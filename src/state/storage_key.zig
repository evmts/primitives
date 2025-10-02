const std = @import("std");
const Address = @import("../primitives/address.zig");
const constants = @import("constants.zig");

/// Composite key for EVM storage lookups
///
/// Ethereum's storage is organized as a two-level map:
/// 1. First level: contract address (20 bytes)
/// 2. Second level: storage slot (256-bit integer)
///
/// StorageKey combines these two components into a single composite key,
/// enabling efficient HashMap lookups for account storage state.
///
/// This type provides:
/// - Hash function integration with std.AutoHashMap
/// - Equality comparison for key matching
/// - Format support for debugging and logging
///
/// Example:
/// ```zig
/// var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
/// defer storage.deinit();
///
/// const key = StorageKey{
///     .address = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .slot = 0,
/// };
///
/// try storage.put(key, 42);
/// const value = storage.get(key);
/// ```
pub const StorageKey = @This();

/// Contract address (20 bytes)
///
/// Identifies which smart contract's storage is being accessed.
address: Address,

/// Storage slot number (256-bit unsigned integer)
///
/// Each contract has 2^256 possible storage slots (though most use far fewer).
/// Slot 0 is typically the first declared state variable, slot 1 is the second, etc.
/// Dynamic arrays and mappings use computed slot numbers via keccak256.
slot: u256,

// =============================================================================
// State Constants (re-exported for convenience)
// =============================================================================

/// Keccak256 hash of empty bytes: keccak256([])
///
/// This is the code hash for accounts with no code (i.e., EOAs and empty contracts).
/// Used extensively in state management to identify accounts without deployed code.
///
/// Value: 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
pub const EMPTY_CODE_HASH: [32]u8 = constants.EMPTY_CODE_HASH;

/// Root hash of an empty Merkle Patricia trie
///
/// This is the root hash when a trie contains no entries.
/// Used as the storage root for accounts with no storage, and as the
/// transaction root for blocks with no transactions.
///
/// Value: 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub const EMPTY_TRIE_ROOT: [32]u8 = constants.EMPTY_TRIE_ROOT;

// =============================================================================
// Hash Function for HashMap Integration
// =============================================================================

/// Hash function for use with std.AutoHashMap
///
/// Computes a hash combining both the address and slot components.
/// This enables StorageKey to be used as a HashMap key.
///
/// The hash function uses Zig's standard hash mechanism:
/// 1. Hash the 20-byte address
/// 2. Hash the 32-byte slot (as big-endian bytes)
///
/// Example:
/// ```zig
/// var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
/// defer storage.deinit();
///
/// const key = StorageKey{ .address = addr, .slot = 5 };
/// try storage.put(key, value); // Uses hash() internally
/// ```
pub fn hash(self: StorageKey, hasher: anytype) void {
    // Hash the address bytes (20 bytes)
    hasher.update(&self.address.bytes);

    // Hash the slot as big-endian bytes (32 bytes)
    var slot_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &slot_bytes, self.slot, .big);
    hasher.update(&slot_bytes);
}

// =============================================================================
// Comparison Methods
// =============================================================================

/// Check if two StorageKeys are equal
///
/// Two keys are equal if both their address and slot match.
/// Used by HashMap for key matching during lookups.
///
/// Example:
/// ```zig
/// const key1 = StorageKey{ .address = addr1, .slot = 0 };
/// const key2 = StorageKey{ .address = addr1, .slot = 0 };
/// const key3 = StorageKey{ .address = addr1, .slot = 1 };
///
/// try std.testing.expect(key1.eql(key2)); // true - same address and slot
/// try std.testing.expect(!key1.eql(key3)); // false - different slots
/// ```
pub fn eql(a: StorageKey, b: StorageKey) bool {
    return a.address.eql(b.address) and a.slot == b.slot;
}

// =============================================================================
// Formatting for std.fmt
// =============================================================================

/// Format StorageKey for std.fmt output
///
/// Output format: "StorageKey{ .address = 0x..., .slot = 0x... }"
///
/// Integrates with Zig's standard formatting system for debugging and logging.
///
/// Example:
/// ```zig
/// const key = StorageKey{ .address = addr, .slot = 42 };
/// std.debug.print("Key: {}\n", .{key});
/// // Output: Key: StorageKey{ .address = 0x742d35Cc..., .slot = 0x2a }
/// ```
pub fn format(
    self: StorageKey,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeAll("StorageKey{ .address = ");
    try self.address.format("", .{}, writer);
    try writer.writeAll(", .slot = 0x");
    try writer.print("{x}", .{self.slot});
    try writer.writeAll(" }");
}

// =============================================================================
// Tests
// =============================================================================

test "StorageKey: basic construction" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key = StorageKey{
        .address = addr,
        .slot = 0,
    };

    try std.testing.expect(key.address.eql(addr));
    try std.testing.expectEqual(@as(u256, 0), key.slot);
}

test "StorageKey: eql - equal keys" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key1 = StorageKey{ .address = addr, .slot = 42 };
    const key2 = StorageKey{ .address = addr, .slot = 42 };

    try std.testing.expect(key1.eql(key2));
}

test "StorageKey: eql - different addresses" {
    const addr1 = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const addr2 = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const key1 = StorageKey{ .address = addr1, .slot = 0 };
    const key2 = StorageKey{ .address = addr2, .slot = 0 };

    try std.testing.expect(!key1.eql(key2));
}

test "StorageKey: eql - different slots" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key1 = StorageKey{ .address = addr, .slot = 0 };
    const key2 = StorageKey{ .address = addr, .slot = 1 };

    try std.testing.expect(!key1.eql(key2));
}

test "StorageKey: eql - different address and slot" {
    const addr1 = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const addr2 = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const key1 = StorageKey{ .address = addr1, .slot = 0 };
    const key2 = StorageKey{ .address = addr2, .slot = 1 };

    try std.testing.expect(!key1.eql(key2));
}

test "StorageKey: hash - same keys produce same hash" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key1 = StorageKey{ .address = addr, .slot = 42 };
    const key2 = StorageKey{ .address = addr, .slot = 42 };

    var hasher1 = std.hash.Wyhash.init(0);
    var hasher2 = std.hash.Wyhash.init(0);

    key1.hash(&hasher1);
    key2.hash(&hasher2);

    const hash1 = hasher1.final();
    const hash2 = hasher2.final();

    try std.testing.expectEqual(hash1, hash2);
}

test "StorageKey: hash - different slots produce different hashes" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key1 = StorageKey{ .address = addr, .slot = 0 };
    const key2 = StorageKey{ .address = addr, .slot = 1 };

    var hasher1 = std.hash.Wyhash.init(0);
    var hasher2 = std.hash.Wyhash.init(0);

    key1.hash(&hasher1);
    key2.hash(&hasher2);

    const hash1 = hasher1.final();
    const hash2 = hasher2.final();

    try std.testing.expect(hash1 != hash2);
}

test "StorageKey: hash - different addresses produce different hashes" {
    const addr1 = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const addr2 = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const key1 = StorageKey{ .address = addr1, .slot = 0 };
    const key2 = StorageKey{ .address = addr2, .slot = 0 };

    var hasher1 = std.hash.Wyhash.init(0);
    var hasher2 = std.hash.Wyhash.init(0);

    key1.hash(&hasher1);
    key2.hash(&hasher2);

    const hash1 = hasher1.final();
    const hash2 = hasher2.final();

    try std.testing.expect(hash1 != hash2);
}

test "StorageKey: HashMap integration - basic operations" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key = StorageKey{ .address = addr, .slot = 0 };

    // Insert a value
    try storage.put(key, 42);

    // Retrieve the value
    const value = storage.get(key);
    try std.testing.expect(value != null);
    try std.testing.expectEqual(@as(u256, 42), value.?);
}

test "StorageKey: HashMap integration - multiple keys" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");

    // Insert multiple values at different slots
    try storage.put(StorageKey{ .address = addr, .slot = 0 }, 10);
    try storage.put(StorageKey{ .address = addr, .slot = 1 }, 20);
    try storage.put(StorageKey{ .address = addr, .slot = 2 }, 30);

    // Verify all values
    try std.testing.expectEqual(@as(u256, 10), storage.get(StorageKey{ .address = addr, .slot = 0 }).?);
    try std.testing.expectEqual(@as(u256, 20), storage.get(StorageKey{ .address = addr, .slot = 1 }).?);
    try std.testing.expectEqual(@as(u256, 30), storage.get(StorageKey{ .address = addr, .slot = 2 }).?);
}

test "StorageKey: HashMap integration - different addresses" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr1 = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const addr2 = try Address.fromHex("0x1111111111111111111111111111111111111111");

    // Insert values for different addresses at the same slot
    try storage.put(StorageKey{ .address = addr1, .slot = 0 }, 100);
    try storage.put(StorageKey{ .address = addr2, .slot = 0 }, 200);

    // Verify both values are stored separately
    try std.testing.expectEqual(@as(u256, 100), storage.get(StorageKey{ .address = addr1, .slot = 0 }).?);
    try std.testing.expectEqual(@as(u256, 200), storage.get(StorageKey{ .address = addr2, .slot = 0 }).?);
}

test "StorageKey: HashMap integration - update value" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key = StorageKey{ .address = addr, .slot = 0 };

    // Insert initial value
    try storage.put(key, 100);
    try std.testing.expectEqual(@as(u256, 100), storage.get(key).?);

    // Update value
    try storage.put(key, 200);
    try std.testing.expectEqual(@as(u256, 200), storage.get(key).?);

    // Verify only one entry exists
    try std.testing.expectEqual(@as(usize, 1), storage.count());
}

test "StorageKey: HashMap integration - remove value" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key = StorageKey{ .address = addr, .slot = 0 };

    // Insert and verify
    try storage.put(key, 42);
    try std.testing.expect(storage.contains(key));

    // Remove and verify
    _ = storage.remove(key);
    try std.testing.expect(!storage.contains(key));
    try std.testing.expectEqual(@as(usize, 0), storage.count());
}

test "StorageKey: HashMap integration - large slot numbers" {
    const allocator = std.testing.allocator;

    var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
    defer storage.deinit();

    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");

    // Use large slot numbers (common in dynamic arrays/mappings)
    const large_slot = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    const key = StorageKey{ .address = addr, .slot = large_slot };

    try storage.put(key, 999);
    try std.testing.expectEqual(@as(u256, 999), storage.get(key).?);
}

test "StorageKey: format integration with std.fmt" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    const key = StorageKey{ .address = addr, .slot = 42 };

    var buf: [200]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try key.format("", .{}, fbs.writer());

    const result = fbs.getWritten();

    // Should contain both address and slot
    try std.testing.expect(std.mem.indexOf(u8, result, "StorageKey") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "address") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "0x") != null);
}

test "StorageKey: EMPTY_CODE_HASH constant" {
    // Verify the constant is exactly 32 bytes
    try std.testing.expectEqual(@as(usize, 32), EMPTY_CODE_HASH.len);

    // Verify first and last bytes match expected values
    try std.testing.expectEqual(@as(u8, 0xc5), EMPTY_CODE_HASH[0]);
    try std.testing.expectEqual(@as(u8, 0x70), EMPTY_CODE_HASH[31]);
}

test "StorageKey: EMPTY_TRIE_ROOT constant" {
    // Verify the constant is exactly 32 bytes
    try std.testing.expectEqual(@as(usize, 32), EMPTY_TRIE_ROOT.len);

    // Verify first and last bytes match expected values
    try std.testing.expectEqual(@as(u8, 0x56), EMPTY_TRIE_ROOT[0]);
    try std.testing.expectEqual(@as(u8, 0x21), EMPTY_TRIE_ROOT[31]);
}

test "StorageKey: constants are different" {
    // EMPTY_CODE_HASH and EMPTY_TRIE_ROOT should be different values
    try std.testing.expect(!std.mem.eql(u8, &EMPTY_CODE_HASH, &EMPTY_TRIE_ROOT));
}
