const std = @import("std");
const Hardfork = @import("hardfork.zig").Hardfork;
const Address = @import("../primitives/address.zig").Address;

pub const EipOverride = struct {
    eip: u16,
    enabled: bool,
};

pub const SstoreGasCost = struct {
    gas: u64,
    refund: i64,
};

pub const Eips = struct {
    hardfork: Hardfork,
    overrides: []const EipOverride = &.{},

    const Self = @This();

    /// Check if specific EIP is active
    pub fn is_eip_active(self: Self, eip: u16) bool {
        _ = self;
        _ = eip;
        @panic("TODO: implement is_eip_active");
    }

    /// Get all active EIPs for current configuration
    pub fn get_active_eips(self: Self) []const u16 {
        _ = self;
        @panic("TODO: implement get_active_eips");
    }

    // Opcode availability checks

    /// Check if PUSH0 opcode is enabled (EIP-3855)
    pub fn eip_3855_push0_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_3855_push0_enabled");
    }

    /// Check if BASEFEE opcode is enabled (EIP-3198)
    pub fn eip_3198_basefee_opcode_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_3198_basefee_opcode_enabled");
    }

    /// Check if transient storage opcodes are enabled (EIP-1153)
    pub fn eip_1153_transient_storage_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_1153_transient_storage_enabled");
    }

    /// Check if MCOPY opcode is enabled (EIP-5656)
    pub fn eip_5656_has_mcopy(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_5656_has_mcopy");
    }

    // Transaction type checks

    /// Check if EIP-1559 fee market is enabled
    pub fn eip_1559_is_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_1559_is_enabled");
    }

    /// Check if blob transactions are enabled (EIP-4844)
    pub fn eip_4844_blob_transactions_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_4844_blob_transactions_enabled");
    }

    /// Check if EOA code is enabled (EIP-7702)
    pub fn eip_7702_eoa_code_enabled(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_7702_eoa_code_enabled");
    }

    // Gas cost queries

    /// Get cold SLOAD cost (EIP-2929)
    pub fn eip_2929_cold_sload_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_2929_cold_sload_cost");
    }

    /// Get warm storage read cost (EIP-2929)
    pub fn eip_2929_warm_storage_read_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_2929_warm_storage_read_cost");
    }

    /// Get cold account access cost (EIP-2929)
    pub fn eip_2929_cold_account_access_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_2929_cold_account_access_cost");
    }

    /// Get warm account access cost (EIP-2929)
    pub fn eip_2929_warm_account_access_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_2929_warm_account_access_cost");
    }

    /// Calculate gas refund cap (EIP-3529)
    pub fn eip_3529_gas_refund_cap(self: Self, gas_used: u64, refund_counter: u64) u64 {
        _ = self;
        _ = gas_used;
        _ = refund_counter;
        @panic("TODO: implement eip_3529_gas_refund_cap");
    }

    /// Get calldata gas cost (EIP-2028)
    pub fn eip_2028_calldata_gas_cost(self: Self, is_zero: bool) u64 {
        _ = self;
        _ = is_zero;
        @panic("TODO: implement eip_2028_calldata_gas_cost");
    }

    /// Get EXP byte gas cost (EIP-160)
    pub fn eip_160_exp_byte_gas_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_160_exp_byte_gas_cost");
    }

    /// Calculate SSTORE gas cost
    pub fn sstore_gas_cost(self: Self, current: u256, new: u256, original: u256) SstoreGasCost {
        _ = self;
        _ = current;
        _ = new;
        _ = original;
        @panic("TODO: implement sstore_gas_cost");
    }

    // Code limits

    /// Get max contract code size (EIP-170)
    pub fn eip_170_max_code_size(self: Self) u32 {
        _ = self;
        @panic("TODO: implement eip_170_max_code_size");
    }

    /// Get initcode size limit (EIP-3860)
    pub fn eip_3860_size_limit(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_3860_size_limit");
    }

    /// Get initcode word cost (EIP-3860)
    pub fn eip_3860_word_cost(self: Self) u64 {
        _ = self;
        @panic("TODO: implement eip_3860_word_cost");
    }

    // Behavior changes

    /// Check if SELFDESTRUCT only works in same transaction (EIP-6780)
    pub fn eip_6780_selfdestruct_same_transaction_only(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_6780_selfdestruct_same_transaction_only");
    }

    /// Check if should reject EF bytecode (EIP-3541)
    pub fn eip_3541_should_reject_ef_bytecode(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_3541_should_reject_ef_bytecode");
    }

    /// Check if should use PREVRANDAO instead of DIFFICULTY (EIP-4399)
    pub fn eip_4399_use_prevrandao(self: Self) bool {
        _ = self;
        @panic("TODO: implement eip_4399_use_prevrandao");
    }

    // Warming and access lists

    /// Pre-warm transaction addresses (EIP-2929, EIP-3651)
    pub fn pre_warm_transaction_addresses(
        self: Self,
        access_list: anytype,
        origin: Address,
        target: ?Address,
        coinbase: Address,
    ) !void {
        _ = self;
        _ = access_list;
        _ = origin;
        _ = target;
        _ = coinbase;
        @panic("TODO: implement pre_warm_transaction_addresses");
    }
};
