const std = @import("std");
const AccessList = @import("../transactions/access_list.zig").AccessList;

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

    /// Calculate memory expansion cost
    pub fn memoryExpansion(byte_size: u64) u64 {
        _ = byte_size;
        @panic("TODO: implement memoryExpansion");
    }

    /// Calculate intrinsic gas cost for transaction
    pub fn intrinsic(params: struct {
        data: []const u8,
        is_creation: bool,
        access_list: ?AccessList,
    }) u64 {
        _ = params;
        @panic("TODO: implement intrinsic");
    }
};
