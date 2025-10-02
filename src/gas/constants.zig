const std = @import("std");
const AccessList = @import("../primitives/access_list.zig").AccessList;

pub const Gas = struct {
    // Transaction costs
    pub const TX: u64 = 21_000;
    pub const TX_CREATE: u64 = 32_000;
    pub const TX_DATA_ZERO: u64 = 4;
    pub const TX_DATA_NONZERO: u64 = 16;

    // Account access costs
    pub const COLD_ACCOUNT_ACCESS: u64 = 2_600;
    pub const COLD_SLOAD: u64 = 2_100;
    pub const WARM_STORAGE_READ: u64 = 100;

    // Storage costs
    pub const SSTORE_SET: u64 = 20_000;
    pub const SSTORE_RESET: u64 = 5_000;
    pub const SSTORE_CLEAR_REFUND: u64 = 15_000;

    // Call costs
    pub const CALL: u64 = 700;
    pub const CALL_VALUE: u64 = 9_000;
    pub const CALL_STIPEND: u64 = 2_300;
    pub const NEW_ACCOUNT: u64 = 25_000;

    // Precompile costs
    pub const ECRECOVER: u64 = 3_000;
    pub const SHA256_BASE: u64 = 60;
    pub const SHA256_WORD: u64 = 12;
    pub const RIPEMD160_BASE: u64 = 600;
    pub const RIPEMD160_WORD: u64 = 120;
    pub const IDENTITY_BASE: u64 = 15;
    pub const IDENTITY_WORD: u64 = 3;

    // =============================================================================
    // Gas Calculation Functions
    // =============================================================================

    /// Calculate memory expansion cost for EVM operations
    ///
    /// Memory expansion cost is calculated using a quadratic formula to prevent
    /// excessive memory usage. The cost is polynomial, being linear up to 724B
    /// and substantially more expensive after that.
    ///
    /// Formula:
    /// - memory_size_word = (byte_size + 31) / 32
    /// - cost = (memory_size_word^2 / 512) + (3 * memory_size_word)
    ///
    /// This function computes the total cost for the given memory size.
    /// To get expansion cost, subtract the previous memory cost from this result.
    ///
    /// Example:
    /// ```zig
    /// const cost = Gas.memoryExpansion(1024);
    /// // cost = 105 gas (for 1024 bytes = 32 words)
    /// ```
    pub fn memoryExpansion(byte_size: u64) u64 {
        if (byte_size == 0) return 0;

        // Calculate memory size in 32-byte words (round up)
        const memory_size_word = (byte_size + 31) / 32;

        // Calculate quadratic cost: (memory_size_word^2 / 512) + (3 * memory_size_word)
        const quadratic_cost = (memory_size_word * memory_size_word) / 512;
        const linear_cost = 3 * memory_size_word;

        return quadratic_cost + linear_cost;
    }

    /// Calculate intrinsic gas cost for a transaction
    ///
    /// Intrinsic gas is the minimum gas required before execution begins:
    /// - 21,000 base cost for all transactions (TX)
    /// - +32,000 if creating a contract (TX_CREATE)
    /// - +4 gas per zero byte in calldata (TX_DATA_ZERO)
    /// - +16 gas per non-zero byte in calldata (TX_DATA_NONZERO)
    /// - +2,400 per address in access list (ACCESS_LIST_ADDRESS_COST)
    /// - +1,900 per storage key in access list (ACCESS_LIST_STORAGE_KEY_COST)
    ///
    /// This represents the minimum gas that must be available before the
    /// transaction can be executed. If the gas limit is less than this amount,
    /// the transaction is invalid.
    ///
    /// Example:
    /// ```zig
    /// const cost = Gas.intrinsic(.{
    ///     .data = &[_]u8{0, 0, 1, 2},
    ///     .is_creation = false,
    ///     .access_list = null,
    /// });
    /// // cost = 21_000 + (2 * 4) + (2 * 16) = 21_040 gas
    /// ```
    pub fn intrinsic(params: struct {
        data: []const u8,
        is_creation: bool,
        access_list: ?AccessList,
    }) u64 {
        var gas: u64 = TX; // Base transaction cost

        // Contract creation cost
        if (params.is_creation) {
            gas += TX_CREATE;
        }

        // Data gas cost
        for (params.data) |byte| {
            if (byte == 0) {
                gas += TX_DATA_ZERO; // Zero byte cost
            } else {
                gas += TX_DATA_NONZERO; // Non-zero byte cost
            }
        }

        // Access list cost (EIP-2930)
        if (params.access_list) |access_list| {
            for (access_list) |entry| {
                gas += 2_400; // Per address (ACCESS_LIST_ADDRESS_COST)
                gas += @as(u64, @intCast(entry.storage_keys.len)) * 1_900; // Per storage key (ACCESS_LIST_STORAGE_KEY_COST)
            }
        }

        return gas;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "Gas: transaction constants" {
    try testing.expectEqual(@as(u64, 21_000), Gas.TX);
    try testing.expectEqual(@as(u64, 32_000), Gas.TX_CREATE);
    try testing.expectEqual(@as(u64, 4), Gas.TX_DATA_ZERO);
    try testing.expectEqual(@as(u64, 16), Gas.TX_DATA_NONZERO);
}

test "Gas: account access constants" {
    try testing.expectEqual(@as(u64, 2_600), Gas.COLD_ACCOUNT_ACCESS);
    try testing.expectEqual(@as(u64, 2_100), Gas.COLD_SLOAD);
    try testing.expectEqual(@as(u64, 100), Gas.WARM_STORAGE_READ);
}

test "Gas: storage constants" {
    try testing.expectEqual(@as(u64, 20_000), Gas.SSTORE_SET);
    try testing.expectEqual(@as(u64, 5_000), Gas.SSTORE_RESET);
    try testing.expectEqual(@as(u64, 15_000), Gas.SSTORE_CLEAR_REFUND);
}

test "Gas: call constants" {
    try testing.expectEqual(@as(u64, 700), Gas.CALL);
    try testing.expectEqual(@as(u64, 9_000), Gas.CALL_VALUE);
    try testing.expectEqual(@as(u64, 2_300), Gas.CALL_STIPEND);
    try testing.expectEqual(@as(u64, 25_000), Gas.NEW_ACCOUNT);
}

test "Gas: precompile constants" {
    try testing.expectEqual(@as(u64, 3_000), Gas.ECRECOVER);
    try testing.expectEqual(@as(u64, 60), Gas.SHA256_BASE);
    try testing.expectEqual(@as(u64, 12), Gas.SHA256_WORD);
    try testing.expectEqual(@as(u64, 600), Gas.RIPEMD160_BASE);
    try testing.expectEqual(@as(u64, 120), Gas.RIPEMD160_WORD);
    try testing.expectEqual(@as(u64, 15), Gas.IDENTITY_BASE);
    try testing.expectEqual(@as(u64, 3), Gas.IDENTITY_WORD);
}

test "Gas.memoryExpansion: zero bytes" {
    const cost = Gas.memoryExpansion(0);
    try testing.expectEqual(@as(u64, 0), cost);
}

test "Gas.memoryExpansion: single word (32 bytes)" {
    const cost = Gas.memoryExpansion(32);
    // memory_size_word = 1
    // cost = (1^2 / 512) + (3 * 1) = 0 + 3 = 3
    try testing.expectEqual(@as(u64, 3), cost);
}

test "Gas.memoryExpansion: partial word (1 byte)" {
    const cost = Gas.memoryExpansion(1);
    // memory_size_word = (1 + 31) / 32 = 1
    // cost = (1^2 / 512) + (3 * 1) = 0 + 3 = 3
    try testing.expectEqual(@as(u64, 3), cost);
}

test "Gas.memoryExpansion: partial word (31 bytes)" {
    const cost = Gas.memoryExpansion(31);
    // memory_size_word = (31 + 31) / 32 = 1
    // cost = (1^2 / 512) + (3 * 1) = 0 + 3 = 3
    try testing.expectEqual(@as(u64, 3), cost);
}

test "Gas.memoryExpansion: two words (64 bytes)" {
    const cost = Gas.memoryExpansion(64);
    // memory_size_word = 2
    // cost = (2^2 / 512) + (3 * 2) = 0 + 6 = 6
    try testing.expectEqual(@as(u64, 6), cost);
}

test "Gas.memoryExpansion: 1024 bytes (32 words)" {
    const cost = Gas.memoryExpansion(1024);
    // memory_size_word = 32
    // cost = (32^2 / 512) + (3 * 32) = (1024 / 512) + 96 = 2 + 96 = 98
    try testing.expectEqual(@as(u64, 98), cost);
}

test "Gas.memoryExpansion: large memory (10,000 bytes)" {
    const cost = Gas.memoryExpansion(10_000);
    // memory_size_word = (10_000 + 31) / 32 = 313
    // cost = (313^2 / 512) + (3 * 313) = (97969 / 512) + 939 = 191 + 939 = 1130
    try testing.expectEqual(@as(u64, 1130), cost);
}

test "Gas.memoryExpansion: quadratic scaling" {
    // Verify that cost increases quadratically
    const cost_1k = Gas.memoryExpansion(1024);
    const cost_2k = Gas.memoryExpansion(2048);
    const cost_4k = Gas.memoryExpansion(4096);

    // Cost should more than double when size doubles (due to quadratic term)
    try testing.expect(cost_2k > cost_1k * 2);
    try testing.expect(cost_4k > cost_2k * 2);
}

test "Gas.intrinsic: simple transfer (no data)" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{},
        .is_creation = false,
        .access_list = null,
    });
    try testing.expectEqual(@as(u64, 21_000), cost);
}

test "Gas.intrinsic: contract creation (no data)" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{},
        .is_creation = true,
        .access_list = null,
    });
    try testing.expectEqual(@as(u64, 53_000), cost);
}

test "Gas.intrinsic: with zero bytes only" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{ 0, 0, 0, 0 },
        .is_creation = false,
        .access_list = null,
    });
    // 21_000 + (4 * 4) = 21_016
    try testing.expectEqual(@as(u64, 21_016), cost);
}

test "Gas.intrinsic: with non-zero bytes only" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{ 1, 2, 3 },
        .is_creation = false,
        .access_list = null,
    });
    // 21_000 + (3 * 16) = 21_048
    try testing.expectEqual(@as(u64, 21_048), cost);
}

test "Gas.intrinsic: with mixed zero and non-zero bytes" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{ 0, 0, 0, 0, 1, 2 },
        .is_creation = false,
        .access_list = null,
    });
    // 21_000 + (4 * 4) + (2 * 16) = 21_000 + 16 + 32 = 21_048
    try testing.expectEqual(@as(u64, 21_048), cost);
}

test "Gas.intrinsic: contract creation with data" {
    const cost = Gas.intrinsic(.{
        .data = &[_]u8{ 0, 0, 1, 2 },
        .is_creation = true,
        .access_list = null,
    });
    // 21_000 + 32_000 + (2 * 4) + (2 * 16) = 53_000 + 8 + 32 = 53_040
    try testing.expectEqual(@as(u64, 53_040), cost);
}

test "Gas.intrinsic: with access list (single address, no keys)" {
    const Address = @import("../primitives/address.zig").Address;
    const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

    const access_list = [_]AccessListEntry{
        .{
            .address = Address.ZERO,
            .storage_keys = &[_]@import("../primitives/hash.zig").Hash{},
        },
    };

    const cost = Gas.intrinsic(.{
        .data = &[_]u8{},
        .is_creation = false,
        .access_list = &access_list,
    });
    // 21_000 + 2_400 = 23_400
    try testing.expectEqual(@as(u64, 23_400), cost);
}

test "Gas.intrinsic: with access list (address and storage keys)" {
    const Address = @import("../primitives/address.zig").Address;
    const Hash = @import("../primitives/hash.zig").Hash;
    const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

    const storage_keys = [_]Hash{
        Hash.ZERO,
        Hash.ZERO,
    };

    const access_list = [_]AccessListEntry{
        .{
            .address = Address.ZERO,
            .storage_keys = &storage_keys,
        },
    };

    const cost = Gas.intrinsic(.{
        .data = &[_]u8{},
        .is_creation = false,
        .access_list = &access_list,
    });
    // 21_000 + 2_400 + (2 * 1_900) = 21_000 + 2_400 + 3_800 = 27_200
    try testing.expectEqual(@as(u64, 27_200), cost);
}

test "Gas.intrinsic: with multiple access list entries" {
    const Address = @import("../primitives/address.zig").Address;
    const Hash = @import("../primitives/hash.zig").Hash;
    const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

    const storage_keys1 = [_]Hash{Hash.ZERO};
    const storage_keys2 = [_]Hash{ Hash.ZERO, Hash.ZERO, Hash.ZERO };

    const access_list = [_]AccessListEntry{
        .{
            .address = Address.ZERO,
            .storage_keys = &storage_keys1,
        },
        .{
            .address = Address.ZERO,
            .storage_keys = &storage_keys2,
        },
    };

    const cost = Gas.intrinsic(.{
        .data = &[_]u8{},
        .is_creation = false,
        .access_list = &access_list,
    });
    // 21_000 + (2 * 2_400) + (1 * 1_900) + (3 * 1_900)
    // = 21_000 + 4_800 + 1_900 + 5_700 = 33_400
    try testing.expectEqual(@as(u64, 33_400), cost);
}

test "Gas.intrinsic: comprehensive (creation + data + access list)" {
    const Address = @import("../primitives/address.zig").Address;
    const Hash = @import("../primitives/hash.zig").Hash;
    const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

    const storage_keys = [_]Hash{Hash.ZERO};
    const access_list = [_]AccessListEntry{
        .{
            .address = Address.ZERO,
            .storage_keys = &storage_keys,
        },
    };

    const cost = Gas.intrinsic(.{
        .data = &[_]u8{ 0, 1, 2 },
        .is_creation = true,
        .access_list = &access_list,
    });
    // 21_000 (base) + 32_000 (creation) + 4 (zero byte) + 32 (2 non-zero bytes)
    // + 2_400 (address) + 1_900 (storage key)
    // = 21_000 + 32_000 + 4 + 32 + 2_400 + 1_900 = 57_336
    try testing.expectEqual(@as(u64, 57_336), cost);
}
