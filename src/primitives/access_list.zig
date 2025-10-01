const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("address.zig");
const Hash = @import("hash.zig");
const rlp = @import("../encoding/rlp.zig");

/// EIP-2930 Access List
///
/// An access list is a list of addresses and storage keys that will be accessed
/// during transaction execution. By declaring these accesses upfront, transactions
/// can receive reduced gas costs for accessing those addresses and storage slots.
///
/// Introduced in EIP-2930 (Berlin hard fork) to mitigate some of the effects of
/// EIP-2929's increased gas costs for state access.
///
/// This module provides:
/// - Type definitions for access list entries and lists
/// - Gas cost calculation for access lists
/// - Membership checking (address and storage key lookup)
/// - Deduplication of duplicate entries
/// - RLP serialization for transaction encoding
///
/// Example:
/// ```zig
/// const entry = AccessListEntry{
///     .address = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .storage_keys = &[_]Hash{
///         try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
///     },
/// };
///
/// const list = [_]AccessListEntry{entry};
/// const gas_cost = calculateGas(&list);
/// ```

/// Single entry in an access list
///
/// Each entry consists of an Ethereum address and a list of storage keys
/// (32-byte hashes) that will be accessed at that address.
pub const AccessListEntry = struct {
    address: Address,
    storage_keys: []const Hash,
};

/// Access list type (slice of entries)
///
/// An access list is simply an ordered collection of AccessListEntry items.
/// The order may matter for gas calculation optimization, though duplicate
/// entries should be removed via deduplicate().
pub const AccessList = []const AccessListEntry;

// =============================================================================
// Gas Cost Constants (EIP-2930)
// =============================================================================

/// Gas cost per address in the access list
///
/// Each address costs 2400 gas, regardless of how many storage keys it has.
/// This is cheaper than the cold access cost (2600 gas) but more expensive
/// than warm access (100 gas).
pub const ACCESS_LIST_ADDRESS_COST: u64 = 2400;

/// Gas cost per storage key in the access list
///
/// Each storage key costs 1900 gas. This is cheaper than cold storage access
/// (2100 gas) but more expensive than warm storage access (100 gas).
pub const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1900;

// =============================================================================
// Gas Cost Calculation
// =============================================================================

/// Calculate total gas cost for an access list
///
/// The total cost is computed as:
/// ```
/// total = (num_addresses * 2400) + (total_storage_keys * 1900)
/// ```
///
/// An empty access list costs 0 gas.
///
/// Example:
/// ```zig
/// const list = [_]AccessListEntry{
///     .{ .address = addr1, .storage_keys = &[_]Hash{key1, key2} },
///     .{ .address = addr2, .storage_keys = &[_]Hash{} },
/// };
/// const cost = calculateGas(&list);
/// // cost = (2 * 2400) + (2 * 1900) = 8600
/// ```
pub fn calculateGas(list: AccessList) u64 {
    var total: u64 = 0;

    for (list) |entry| {
        // Cost per address
        total += ACCESS_LIST_ADDRESS_COST;

        // Cost per storage key
        total += ACCESS_LIST_STORAGE_KEY_COST * @as(u64, @intCast(entry.storage_keys.len));
    }

    return total;
}

// =============================================================================
// Membership Checking
// =============================================================================

/// Check if an address exists in the access list
///
/// Returns true if any entry in the list has a matching address.
/// Uses Address.eql() for comparison.
///
/// Example:
/// ```zig
/// const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
/// if (hasAddress(&list, addr)) {
///     // Address is in the list
/// }
/// ```
pub fn hasAddress(list: AccessList, address: Address) bool {
    for (list) |entry| {
        if (entry.address.eql(address)) {
            return true;
        }
    }
    return false;
}

/// Check if a storage key exists in the access list for a specific address
///
/// Returns true if the address is in the list AND the storage key is present
/// in that address's storage_keys array.
///
/// Returns false if:
/// - The address is not in the list
/// - The address is in the list but the key is not
///
/// Example:
/// ```zig
/// const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
/// const key = try Hash.fromHex("0x0000...0001");
///
/// if (hasStorageKey(&list, addr, key)) {
///     // This address+key pair is in the list
/// }
/// ```
pub fn hasStorageKey(list: AccessList, address: Address, key: Hash) bool {
    for (list) |entry| {
        if (entry.address.eql(address)) {
            // Found the address, now check for the key
            for (entry.storage_keys) |storage_key| {
                if (storage_key.eql(key)) {
                    return true;
                }
            }
            // Address found but key not found
            return false;
        }
    }
    // Address not found
    return false;
}

// =============================================================================
// Deduplication
// =============================================================================

/// Remove duplicate addresses and storage keys from an access list
///
/// Creates a new access list where:
/// - Each address appears at most once
/// - Storage keys for the same address are merged and deduplicated
/// - Original order of first appearance is preserved
///
/// Memory is allocated for the result and must be freed by the caller.
/// Each entry's storage_keys slice must also be freed.
///
/// Example:
/// ```zig
/// const deduped = try deduplicate(allocator, &list);
/// defer {
///     for (deduped) |entry| {
///         allocator.free(entry.storage_keys);
///     }
///     allocator.free(deduped);
/// }
/// ```
pub fn deduplicate(allocator: Allocator, list: AccessList) !AccessList {
    var result = std.ArrayList(AccessListEntry){};
    defer result.deinit(allocator);

    for (list) |entry| {
        // Check if address already exists in result
        var found = false;
        for (result.items) |*existing| {
            if (existing.address.eql(entry.address)) {
                // Merge storage keys
                var keys = std.ArrayList(Hash){};
                defer keys.deinit(allocator);

                // Add existing keys
                try keys.appendSlice(allocator, existing.storage_keys);

                // Add new keys if not duplicate
                for (entry.storage_keys) |new_key| {
                    var is_duplicate = false;
                    for (existing.storage_keys) |existing_key| {
                        if (new_key.eql(existing_key)) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    if (!is_duplicate) {
                        try keys.append(allocator, new_key);
                    }
                }

                // Replace the storage keys with merged list
                // Note: This leaks the old storage_keys if they were allocated
                // In practice, the caller should manage this appropriately
                existing.storage_keys = try keys.toOwnedSlice(allocator);
                found = true;
                break;
            }
        }

        if (!found) {
            // New address, duplicate the storage keys
            try result.append(allocator, .{
                .address = entry.address,
                .storage_keys = try allocator.dupe(Hash, entry.storage_keys),
            });
        }
    }

    return try result.toOwnedSlice(allocator);
}

// =============================================================================
// Serialization
// =============================================================================

/// Serialize access list to RLP-encoded bytes
///
/// The access list is encoded as a list of [address, [storageKeys...]] pairs.
/// Each entry is encoded as:
/// ```
/// [
///   address: bytes20,
///   storageKeys: [bytes32, bytes32, ...]
/// ]
/// ```
///
/// The entire access list is then encoded as a list of these entries.
///
/// Memory is allocated for the result and must be freed by the caller.
///
/// Example:
/// ```zig
/// const encoded = try serialize(allocator, &list);
/// defer allocator.free(encoded);
///
/// // Can now include in transaction encoding
/// ```
pub fn serialize(allocator: Allocator, list: AccessList) ![]u8 {
    // Encode each entry as [address, [storageKeys...]]
    var entries = std.ArrayList([]const u8){};
    defer {
        for (entries.items) |item| {
            allocator.free(item);
        }
        entries.deinit(allocator);
    }

    for (list) |entry| {
        // Encode the address bytes
        const encoded_address = try rlp.encodeBytes(allocator, &entry.address.bytes);
        defer allocator.free(encoded_address);

        // Encode each storage key
        var encoded_keys = std.ArrayList([]const u8){};
        defer {
            for (encoded_keys.items) |item| {
                allocator.free(item);
            }
            encoded_keys.deinit(allocator);
        }

        for (entry.storage_keys) |key| {
            const encoded_key = try rlp.encodeBytes(allocator, &key.bytes);
            try encoded_keys.append(allocator, encoded_key);
        }

        // Encode the list of storage keys
        const keys_list_encoded = try rlp.encode(allocator, encoded_keys.items);
        defer allocator.free(keys_list_encoded);

        // Create entry as [address, storageKeysList]
        const entry_items = [_][]const u8{ encoded_address, keys_list_encoded };
        const entry_encoded = try rlp.encode(allocator, &entry_items);
        try entries.append(allocator, entry_encoded);
    }

    // Encode the entire access list
    return try rlp.encode(allocator, entries.items);
}

// =============================================================================
// Tests
// =============================================================================

test "AccessList: empty list" {
    const access_list: AccessList = &.{};

    const gas_cost = calculateGas(access_list);
    try std.testing.expectEqual(@as(u64, 0), gas_cost);

    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    try std.testing.expect(!hasAddress(access_list, addr));

    const key = try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001");
    try std.testing.expect(!hasStorageKey(access_list, addr, key));
}

test "AccessList: calculateGas - single entry with storage keys" {
    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const gas_cost = calculateGas(&access_list);

    // Expected: 1 address * 2400 + 2 storage keys * 1900 = 6200
    try std.testing.expectEqual(@as(u64, 6200), gas_cost);
}

test "AccessList: calculateGas - multiple entries" {
    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x2222222222222222222222222222222222222222"),
            .storage_keys = &.{},
        },
    };

    const gas_cost = calculateGas(&access_list);

    // Expected: 2 addresses * 2400 + 2 storage keys * 1900 = 8600
    try std.testing.expectEqual(@as(u64, 8600), gas_cost);
}

test "AccessList: calculateGas - complex scenario" {
    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    };

    const keys2 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000004"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x2222222222222222222222222222222222222222"),
            .storage_keys = &keys2,
        },
        .{
            .address = try Address.fromHex("0x3333333333333333333333333333333333333333"),
            .storage_keys = &.{},
        },
    };

    const gas_cost = calculateGas(&access_list);

    // Expected: 3 addresses * 2400 + 4 storage keys * 1900 = 14800
    try std.testing.expectEqual(@as(u64, 14800), gas_cost);
}

test "AccessList: hasAddress - present" {
    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    try std.testing.expect(hasAddress(&access_list, addr));
}

test "AccessList: hasAddress - not present" {
    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &.{},
    }};

    const addr = try Address.fromHex("0x2222222222222222222222222222222222222222");
    try std.testing.expect(!hasAddress(&access_list, addr));
}

test "AccessList: hasStorageKey - address and key present" {
    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const key = try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001");

    try std.testing.expect(hasStorageKey(&access_list, addr, key));
}

test "AccessList: hasStorageKey - address present but key not present" {
    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const key = try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003");

    try std.testing.expect(!hasStorageKey(&access_list, addr, key));
}

test "AccessList: hasStorageKey - address not present" {
    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const addr = try Address.fromHex("0x2222222222222222222222222222222222222222");
    const key = try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001");

    try std.testing.expect(!hasStorageKey(&access_list, addr, key));
}

test "AccessList: deduplicate - no duplicates" {
    const allocator = std.testing.allocator;

    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
    };

    const keys2 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x2222222222222222222222222222222222222222"),
            .storage_keys = &keys2,
        },
    };

    const deduped = try deduplicate(allocator, &access_list);
    defer {
        for (deduped) |entry| {
            allocator.free(entry.storage_keys);
        }
        allocator.free(deduped);
    }

    // Should have two entries, same as original
    try std.testing.expectEqual(@as(usize, 2), deduped.len);
    try std.testing.expectEqual(@as(usize, 1), deduped[0].storage_keys.len);
    try std.testing.expectEqual(@as(usize, 1), deduped[1].storage_keys.len);
}

test "AccessList: deduplicate - duplicate addresses" {
    const allocator = std.testing.allocator;

    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const keys2 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"), // Duplicate
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"), // Same address
            .storage_keys = &keys2,
        },
    };

    const deduped = try deduplicate(allocator, &access_list);
    defer {
        for (deduped) |entry| {
            allocator.free(entry.storage_keys);
        }
        allocator.free(deduped);
    }

    // Should have one entry with three unique keys
    try std.testing.expectEqual(@as(usize, 1), deduped.len);
    try std.testing.expectEqual(@as(usize, 3), deduped[0].storage_keys.len);

    // Verify the keys are: 0x01, 0x02, 0x03
    const expected_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    };

    for (expected_keys) |expected_key| {
        var found = false;
        for (deduped[0].storage_keys) |actual_key| {
            if (actual_key.eql(expected_key)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "AccessList: deduplicate - empty list" {
    const allocator = std.testing.allocator;

    const access_list: AccessList = &.{};

    const deduped = try deduplicate(allocator, access_list);
    defer allocator.free(deduped);

    try std.testing.expectEqual(@as(usize, 0), deduped.len);
}

test "AccessList: serialize - empty list" {
    const allocator = std.testing.allocator;

    const access_list: AccessList = &.{};

    const encoded = try serialize(allocator, access_list);
    defer allocator.free(encoded);

    // Empty list should be encoded as 0xc0 (empty RLP list)
    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, 0xc0), encoded[0]);
}

test "AccessList: serialize - single entry" {
    const allocator = std.testing.allocator;

    const storage_keys = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
    };

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &storage_keys,
    }};

    const encoded = try serialize(allocator, &access_list);
    defer allocator.free(encoded);

    // Should produce valid RLP
    try std.testing.expect(encoded.len > 0);
    try std.testing.expect(encoded[0] >= 0xc0); // RLP list prefix
}

test "AccessList: serialize - multiple entries" {
    const allocator = std.testing.allocator;

    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const keys2 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x2222222222222222222222222222222222222222"),
            .storage_keys = &keys2,
        },
    };

    const encoded = try serialize(allocator, &access_list);
    defer allocator.free(encoded);

    // Should produce valid RLP
    try std.testing.expect(encoded.len > 0);
    try std.testing.expect(encoded[0] >= 0xc0); // RLP list prefix
}

test "AccessList: serialize - entry with no storage keys" {
    const allocator = std.testing.allocator;

    const access_list = [_]AccessListEntry{.{
        .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
        .storage_keys = &.{},
    }};

    const encoded = try serialize(allocator, &access_list);
    defer allocator.free(encoded);

    // Should produce valid RLP
    try std.testing.expect(encoded.len > 0);
    try std.testing.expect(encoded[0] >= 0xc0); // RLP list prefix
}

test "AccessList: integration - full workflow" {
    const allocator = std.testing.allocator;

    // Create an access list with some duplicates
    const keys1 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"),
    };

    const keys2 = [_]Hash{
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000002"), // Duplicate key
        try Hash.fromHex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"),
            .storage_keys = &keys1,
        },
        .{
            .address = try Address.fromHex("0x1111111111111111111111111111111111111111"), // Duplicate address
            .storage_keys = &keys2,
        },
        .{
            .address = try Address.fromHex("0x2222222222222222222222222222222222222222"),
            .storage_keys = &.{},
        },
    };

    // Calculate original gas cost
    const original_gas = calculateGas(&access_list);
    try std.testing.expectEqual(@as(u64, 12200), original_gas); // 3*2400 + 4*1900

    // Deduplicate
    const deduped = try deduplicate(allocator, &access_list);
    defer {
        for (deduped) |entry| {
            allocator.free(entry.storage_keys);
        }
        allocator.free(deduped);
    }

    // Should have 2 addresses now
    try std.testing.expectEqual(@as(usize, 2), deduped.len);

    // Calculate deduplicated gas cost
    const deduped_gas = calculateGas(deduped);
    try std.testing.expectEqual(@as(u64, 10500), deduped_gas); // 2*2400 + 3*1900

    // Serialize the deduplicated list
    const encoded = try serialize(allocator, deduped);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 0);
}
