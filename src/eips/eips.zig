const std = @import("std");
const Hardfork = @import("hardfork.zig").Hardfork;
const Address = @import("../primitives/address.zig").Address;

// =============================================================================
// Type Definitions
// =============================================================================

/// Override configuration for a specific EIP
///
/// Allows enabling or disabling specific EIPs regardless of hardfork.
/// This is useful for testing or custom network configurations.
pub const EipOverride = struct {
    eip: u16,
    enabled: bool,
};

/// Gas cost breakdown for SSTORE operations
///
/// Contains both the gas cost and potential refund for storage operations.
/// Refund can be negative (cost) or positive (refund).
pub const SstoreGasCost = struct {
    gas: u64,
    refund: i64,
};

// =============================================================================
// EIP Configuration
// =============================================================================

/// Ethereum Improvement Proposal (EIP) configuration system
///
/// Consolidates all EIP-specific logic for the EVM. Provides hardfork-based
/// feature detection and gas cost calculations with support for custom EIP overrides.
///
/// Example:
/// ```zig
/// const eips = Eips{ .hardfork = .CANCUN };
/// if (eips.eip_4844_blob_transactions_enabled()) {
///     // Handle blob transactions
/// }
/// ```
pub const Eips = struct {
    hardfork: Hardfork,
    overrides: []const EipOverride = &.{},

    const Self = @This();

    // =============================================================================
    // Feature Detection
    // =============================================================================

    /// Check if specific EIP is active
    ///
    /// Checks both hardfork-based activation and custom overrides.
    ///
    /// Example:
    /// ```zig
    /// if (eips.is_eip_active(1559)) {
    ///     // EIP-1559 fee market is active
    /// }
    /// ```
    pub fn is_eip_active(self: Self, eip: u16) bool {
        // Check overrides first
        for (self.overrides) |override| {
            if (override.eip == eip) {
                return override.enabled;
            }
        }

        // Check hardfork-based activation
        return switch (eip) {
            // Homestead (EIP-2, EIP-7, EIP-8)
            2, 7, 8 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.HOMESTEAD),

            // EIP-160: EXP cost increase (Spurious Dragon)
            160 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.SPURIOUS_DRAGON),

            // EIP-170: Contract code size limit (Spurious Dragon)
            170 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.SPURIOUS_DRAGON),

            // EIP-1559: Fee market (London)
            1559 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.LONDON),

            // EIP-1153: Transient storage (Cancun)
            1153 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.CANCUN),

            // EIP-2028: Transaction data gas cost reduction (Istanbul)
            2028 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.ISTANBUL),

            // EIP-2929: Gas cost increases for state access (Berlin)
            2929 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.BERLIN),

            // EIP-2930: Access lists (Berlin)
            2930 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.BERLIN),

            // EIP-3198: BASEFEE opcode (London)
            3198 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.LONDON),

            // EIP-3529: Reduction in refunds (London)
            3529 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.LONDON),

            // EIP-3541: Reject 0xEF bytecode (London)
            3541 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.LONDON),

            // EIP-3651: Warm COINBASE (Shanghai)
            3651 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.SHANGHAI),

            // EIP-3855: PUSH0 instruction (Shanghai)
            3855 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.SHANGHAI),

            // EIP-3860: Limit and meter initcode (Shanghai)
            3860 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.SHANGHAI),

            // EIP-4399: PREVRANDAO opcode (Merge)
            4399 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.MERGE),

            // EIP-4844: Blob transactions (Cancun)
            4844 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.CANCUN),

            // EIP-5656: MCOPY instruction (Cancun)
            5656 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.CANCUN),

            // EIP-6780: SELFDESTRUCT only in same transaction (Cancun)
            6780 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.CANCUN),

            // EIP-7702: Set EOA account code (Prague)
            7702 => @intFromEnum(self.hardfork) >= @intFromEnum(Hardfork.PRAGUE),

            else => false,
        };
    }

    /// Get all active EIPs for current configuration
    ///
    /// Returns a static list of EIP numbers that are active based on the hardfork.
    /// Does not include custom overrides.
    ///
    /// Example:
    /// ```zig
    /// const active = eips.get_active_eips();
    /// for (active) |eip_num| {
    ///     std.debug.print("EIP-{}: active\n", .{eip_num});
    /// }
    /// ```
    pub fn get_active_eips(self: Self) []const u16 {
        return switch (self.hardfork) {
            .FRONTIER => &[_]u16{},
            .HOMESTEAD => &[_]u16{ 2, 7, 8 },
            .DAO => &[_]u16{ 2, 7, 8 },
            .TANGERINE_WHISTLE => &[_]u16{ 2, 7, 8 },
            .SPURIOUS_DRAGON => &[_]u16{ 2, 7, 8, 160, 170 },
            .BYZANTIUM => &[_]u16{ 2, 7, 8, 160, 170 },
            .CONSTANTINOPLE => &[_]u16{ 2, 7, 8, 160, 170 },
            .PETERSBURG => &[_]u16{ 2, 7, 8, 160, 170 },
            .ISTANBUL => &[_]u16{ 2, 7, 8, 160, 170, 2028 },
            .MUIR_GLACIER => &[_]u16{ 2, 7, 8, 160, 170, 2028 },
            .BERLIN => &[_]u16{ 2, 7, 8, 160, 170, 2028, 2929, 2930 },
            .LONDON => &[_]u16{ 2, 7, 8, 160, 170, 1559, 2028, 2929, 2930, 3198, 3529, 3541 },
            .ARROW_GLACIER => &[_]u16{ 2, 7, 8, 160, 170, 1559, 2028, 2929, 2930, 3198, 3529, 3541 },
            .GRAY_GLACIER => &[_]u16{ 2, 7, 8, 160, 170, 1559, 2028, 2929, 2930, 3198, 3529, 3541 },
            .MERGE => &[_]u16{ 2, 7, 8, 160, 170, 1559, 2028, 2929, 2930, 3198, 3529, 3541, 4399 },
            .SHANGHAI => &[_]u16{ 2, 7, 8, 160, 170, 1559, 2028, 2929, 2930, 3198, 3529, 3541, 3651, 3855, 3860, 4399 },
            .CANCUN => &[_]u16{ 2, 7, 8, 160, 170, 1153, 1559, 2028, 2929, 2930, 3198, 3529, 3541, 3651, 3855, 3860, 4399, 4844, 5656, 6780 },
            .PRAGUE => &[_]u16{ 2, 7, 8, 160, 170, 1153, 1559, 2028, 2929, 2930, 3198, 3529, 3541, 3651, 3855, 3860, 4399, 4844, 5656, 6780, 7702 },
        };
    }

    // =============================================================================
    // Opcode Availability
    // =============================================================================

    /// Check if PUSH0 opcode is enabled (EIP-3855)
    ///
    /// PUSH0 pushes the constant value 0 onto the stack.
    /// Activated in Shanghai hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_3855_push0_enabled()) {
    ///     // PUSH0 (0x5F) is available
    /// }
    /// ```
    pub fn eip_3855_push0_enabled(self: Self) bool {
        return self.is_eip_active(3855);
    }

    /// Check if BASEFEE opcode is enabled (EIP-3198)
    ///
    /// BASEFEE returns the base fee of the current block.
    /// Activated in London hardfork (along with EIP-1559).
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_3198_basefee_opcode_enabled()) {
    ///     // BASEFEE (0x48) is available
    /// }
    /// ```
    pub fn eip_3198_basefee_opcode_enabled(self: Self) bool {
        return self.is_eip_active(3198);
    }

    /// Check if transient storage opcodes are enabled (EIP-1153)
    ///
    /// TLOAD and TSTORE provide transient storage that is cleared at the end
    /// of each transaction. Activated in Cancun hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_1153_transient_storage_enabled()) {
    ///     // TLOAD (0x5C) and TSTORE (0x5D) are available
    /// }
    /// ```
    pub fn eip_1153_transient_storage_enabled(self: Self) bool {
        return self.is_eip_active(1153);
    }

    /// Check if MCOPY opcode is enabled (EIP-5656)
    ///
    /// MCOPY provides efficient memory copying.
    /// Activated in Cancun hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_5656_has_mcopy()) {
    ///     // MCOPY (0x5E) is available
    /// }
    /// ```
    pub fn eip_5656_has_mcopy(self: Self) bool {
        return self.is_eip_active(5656);
    }

    // =============================================================================
    // Transaction Types
    // =============================================================================

    /// Check if EIP-1559 fee market is enabled
    ///
    /// EIP-1559 introduces a new transaction type with base fee and priority fee.
    /// Activated in London hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_1559_is_enabled()) {
    ///     // Type 2 transactions with maxFeePerGas are supported
    /// }
    /// ```
    pub fn eip_1559_is_enabled(self: Self) bool {
        return self.is_eip_active(1559);
    }

    /// Check if blob transactions are enabled (EIP-4844)
    ///
    /// EIP-4844 introduces shard blob transactions for data availability.
    /// Activated in Cancun hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_4844_blob_transactions_enabled()) {
    ///     // Type 3 transactions with blob versioned hashes are supported
    /// }
    /// ```
    pub fn eip_4844_blob_transactions_enabled(self: Self) bool {
        return self.is_eip_active(4844);
    }

    /// Check if EOA code is enabled (EIP-7702)
    ///
    /// EIP-7702 allows setting code for Externally Owned Accounts.
    /// Activated in Prague hardfork.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_7702_eoa_code_enabled()) {
    ///     // EOAs can have code set via authorization lists
    /// }
    /// ```
    pub fn eip_7702_eoa_code_enabled(self: Self) bool {
        return self.is_eip_active(7702);
    }

    // =============================================================================
    // Gas Costs
    // =============================================================================

    /// Get cold SLOAD cost (EIP-2929)
    ///
    /// Returns the gas cost for loading a storage slot that hasn't been accessed yet.
    /// - Pre-Berlin: 200 gas
    /// - Berlin+: 2100 gas
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_2929_cold_sload_cost(); // 2100 for Berlin+
    /// ```
    pub fn eip_2929_cold_sload_cost(self: Self) u64 {
        if (self.is_eip_active(2929)) {
            return 2100; // EIP-2929 cold SLOAD cost
        }
        return 200; // Pre-EIP-2929 SLOAD cost
    }

    /// Get warm storage read cost (EIP-2929)
    ///
    /// Returns the gas cost for accessing a storage slot that has been accessed before.
    /// - Pre-Berlin: 200 gas (same as cold)
    /// - Berlin+: 100 gas
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_2929_warm_storage_read_cost(); // 100 for Berlin+
    /// ```
    pub fn eip_2929_warm_storage_read_cost(self: Self) u64 {
        if (self.is_eip_active(2929)) {
            return 100; // EIP-2929 warm storage read cost
        }
        return 200; // Pre-EIP-2929 cost (same as cold)
    }

    /// Get cold account access cost (EIP-2929)
    ///
    /// Returns the gas cost for accessing an account that hasn't been accessed yet.
    /// - Pre-Berlin: 700 gas
    /// - Berlin+: 2600 gas
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_2929_cold_account_access_cost(); // 2600 for Berlin+
    /// ```
    pub fn eip_2929_cold_account_access_cost(self: Self) u64 {
        if (self.is_eip_active(2929)) {
            return 2600; // EIP-2929 cold account access cost
        }
        return 700; // Pre-EIP-2929 CALL base cost
    }

    /// Get warm account access cost (EIP-2929)
    ///
    /// Returns the gas cost for accessing an account that has been accessed before.
    /// - Pre-Berlin: 700 gas (same as cold)
    /// - Berlin+: 100 gas
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_2929_warm_account_access_cost(); // 100 for Berlin+
    /// ```
    pub fn eip_2929_warm_account_access_cost(self: Self) u64 {
        if (self.is_eip_active(2929)) {
            return 100; // EIP-2929 warm account access cost
        }
        return 700; // Pre-EIP-2929 cost (same as cold)
    }

    /// Calculate gas refund cap (EIP-3529)
    ///
    /// Returns the maximum gas refund allowed for the transaction.
    /// - Pre-London: min(refund_counter, gas_used / 2)
    /// - London+: min(refund_counter, gas_used / 5)
    ///
    /// Example:
    /// ```zig
    /// const refund = eips.eip_3529_gas_refund_cap(100_000, 50_000);
    /// // London: 20_000 (gas_used / 5)
    /// // Pre-London: 50_000 (gas_used / 2)
    /// ```
    pub fn eip_3529_gas_refund_cap(self: Self, gas_used: u64, refund_counter: u64) u64 {
        if (self.is_eip_active(3529)) {
            // EIP-3529: Cap at 1/5 of gas used
            const max_refund = gas_used / 5;
            return @min(refund_counter, max_refund);
        }
        // Pre-EIP-3529: Cap at 1/2 of gas used
        const max_refund = gas_used / 2;
        return @min(refund_counter, max_refund);
    }

    /// Get calldata gas cost (EIP-2028)
    ///
    /// Returns the gas cost per byte of calldata.
    /// - Zero bytes: always 4 gas
    /// - Non-zero bytes:
    ///   - Pre-Istanbul: 68 gas
    ///   - Istanbul+: 16 gas
    ///
    /// Example:
    /// ```zig
    /// const zero_cost = eips.eip_2028_calldata_gas_cost(true); // 4
    /// const nonzero_cost = eips.eip_2028_calldata_gas_cost(false); // 16 for Istanbul+
    /// ```
    pub fn eip_2028_calldata_gas_cost(self: Self, is_zero: bool) u64 {
        if (is_zero) {
            return 4; // Zero byte cost (unchanged)
        }
        if (self.is_eip_active(2028)) {
            return 16; // EIP-2028 reduced non-zero byte cost
        }
        return 68; // Pre-EIP-2028 non-zero byte cost
    }

    /// Get EXP byte gas cost (EIP-160)
    ///
    /// Returns the gas cost per byte for the EXP operation.
    /// - Pre-Spurious Dragon: 10 gas per byte
    /// - Spurious Dragon+: 50 gas per byte
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_160_exp_byte_gas_cost(); // 50 for Spurious Dragon+
    /// ```
    pub fn eip_160_exp_byte_gas_cost(self: Self) u64 {
        if (self.is_eip_active(160)) {
            return 50; // EIP-160 increased EXP byte cost
        }
        return 10; // Pre-EIP-160 EXP byte cost
    }

    /// Calculate SSTORE gas cost
    ///
    /// Calculates the gas cost and refund for a storage operation.
    /// Implements EIP-2200 (Istanbul) gas metering with EIP-3529 (London) refund reduction.
    ///
    /// Parameters:
    /// - current: Current value in storage slot
    /// - new: New value to store
    /// - original: Original value at start of transaction
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.sstore_gas_cost(0, 1, 0);
    /// // Setting from zero: cost.gas = 20000, cost.refund = 0
    ///
    /// const clear = eips.sstore_gas_cost(1, 0, 1);
    /// // Clearing storage: cost.gas = 5000, cost.refund = positive value
    /// ```
    pub fn sstore_gas_cost(self: Self, current: u256, new: u256, original: u256) SstoreGasCost {
        // No-op: setting to same value
        if (current == new) {
            return .{ .gas = 100, .refund = 0 };
        }

        // Setting from zero to non-zero
        if (current == 0 and new != 0) {
            return .{ .gas = 20000, .refund = 0 };
        }

        // Clearing storage (non-zero to zero)
        if (current != 0 and new == 0) {
            const refund: i64 = if (self.is_eip_active(3529))
                4800 // EIP-3529 reduced refund
            else
                15000; // Pre-EIP-3529 refund

            return .{ .gas = 5000, .refund = refund };
        }

        // Modifying non-zero value
        // Check if we're restoring to original value
        if (new == original) {
            const refund: i64 = if (original == 0)
                19900 // Was set from zero, now restoring
            else if (current == 0)
                -15000 // Was cleared, now restoring (negative = additional cost)
            else
                4900; // Modified, now restoring

            return .{ .gas = 5000, .refund = refund };
        }

        // Regular modification
        return .{ .gas = 5000, .refund = 0 };
    }

    // =============================================================================
    // Code Limits
    // =============================================================================

    /// Get max contract code size (EIP-170)
    ///
    /// Returns the maximum size for deployed contract code.
    /// - Pre-Spurious Dragon: No limit
    /// - Spurious Dragon+: 24,576 bytes (0x6000)
    ///
    /// Example:
    /// ```zig
    /// const max_size = eips.eip_170_max_code_size(); // 24576 for Spurious Dragon+
    /// ```
    pub fn eip_170_max_code_size(self: Self) u32 {
        if (self.is_eip_active(170)) {
            return 24576; // EIP-170 code size limit (0x6000)
        }
        return std.math.maxInt(u32); // No limit pre-EIP-170
    }

    /// Get initcode size limit (EIP-3860)
    ///
    /// Returns the maximum size for contract creation code.
    /// - Pre-Shanghai: 24,576 bytes (same as code limit)
    /// - Shanghai+: 49,152 bytes (2 * 24576)
    ///
    /// Example:
    /// ```zig
    /// const limit = eips.eip_3860_size_limit(); // 49152 for Shanghai+
    /// ```
    pub fn eip_3860_size_limit(self: Self) u64 {
        if (self.is_eip_active(3860)) {
            return 49152; // EIP-3860 initcode size limit (48 KB)
        }
        return 24576; // Pre-EIP-3860 uses code size limit
    }

    /// Get initcode word cost (EIP-3860)
    ///
    /// Returns the gas cost per 32-byte word of initcode.
    /// - Pre-Shanghai: 0 gas (no metering)
    /// - Shanghai+: 2 gas per word
    ///
    /// Example:
    /// ```zig
    /// const cost = eips.eip_3860_word_cost(); // 2 for Shanghai+
    /// const total_cost = (initcode_size + 31) / 32 * cost;
    /// ```
    pub fn eip_3860_word_cost(self: Self) u64 {
        if (self.is_eip_active(3860)) {
            return 2; // EIP-3860 initcode word cost
        }
        return 0; // No cost pre-EIP-3860
    }

    // =============================================================================
    // Behavior Changes
    // =============================================================================

    /// Check if SELFDESTRUCT only works in same transaction (EIP-6780)
    ///
    /// EIP-6780 restricts SELFDESTRUCT to only destroy contracts created in the
    /// same transaction. For other contracts, it only sends the balance.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_6780_selfdestruct_same_transaction_only()) {
    ///     // Only destroy if contract created in this transaction
    /// } else {
    ///     // Destroy any contract
    /// }
    /// ```
    pub fn eip_6780_selfdestruct_same_transaction_only(self: Self) bool {
        return self.is_eip_active(6780);
    }

    /// Check if should reject EF bytecode (EIP-3541)
    ///
    /// EIP-3541 rejects contract creation if bytecode starts with 0xEF.
    /// This reserves the 0xEF prefix for future EVM Object Format (EOF).
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_3541_should_reject_ef_bytecode()) {
    ///     if (bytecode[0] == 0xEF) {
    ///         return error.InvalidBytecode;
    ///     }
    /// }
    /// ```
    pub fn eip_3541_should_reject_ef_bytecode(self: Self) bool {
        return self.is_eip_active(3541);
    }

    /// Check if should use PREVRANDAO instead of DIFFICULTY (EIP-4399)
    ///
    /// EIP-4399 replaces the DIFFICULTY opcode with PREVRANDAO after The Merge.
    /// The opcode number (0x44) remains the same, but returns the beacon chain's
    /// randomness value instead of proof-of-work difficulty.
    ///
    /// Example:
    /// ```zig
    /// if (eips.eip_4399_use_prevrandao()) {
    ///     // 0x44 returns PREVRANDAO
    /// } else {
    ///     // 0x44 returns DIFFICULTY
    /// }
    /// ```
    pub fn eip_4399_use_prevrandao(self: Self) bool {
        return self.is_eip_active(4399);
    }

    // =============================================================================
    // Warming and Access Lists
    // =============================================================================

    /// Pre-warm transaction addresses (EIP-2929, EIP-3651)
    ///
    /// Adds addresses to the access list that should be considered "warm" at the
    /// start of transaction execution.
    ///
    /// Always warmed (EIP-2929):
    /// - Transaction origin (from)
    /// - Transaction target (to)
    ///
    /// Additionally warmed (EIP-3651):
    /// - Block coinbase (miner/validator address)
    ///
    /// Example:
    /// ```zig
    /// var access_list = AccessList.init(allocator);
    /// defer access_list.deinit();
    ///
    /// try eips.pre_warm_transaction_addresses(
    ///     &access_list,
    ///     tx.from,
    ///     tx.to,
    ///     block.coinbase,
    /// );
    /// ```
    pub fn pre_warm_transaction_addresses(
        self: Self,
        access_list: anytype,
        origin: Address,
        target: ?Address,
        coinbase: Address,
    ) !void {
        // EIP-2929: Always warm origin and target
        if (self.is_eip_active(2929)) {
            try access_list.addAddress(origin);
            if (target) |t| {
                try access_list.addAddress(t);
            }

            // EIP-3651: Also warm coinbase (Shanghai+)
            if (self.is_eip_active(3651)) {
                try access_list.addAddress(coinbase);
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "Eips: is_eip_active - hardfork-based activation" {
    const frontier = Eips{ .hardfork = .FRONTIER };
    const homestead = Eips{ .hardfork = .HOMESTEAD };
    const london = Eips{ .hardfork = .LONDON };
    const cancun = Eips{ .hardfork = .CANCUN };
    const prague = Eips{ .hardfork = .PRAGUE };

    // Homestead EIPs
    try testing.expect(!frontier.is_eip_active(2));
    try testing.expect(homestead.is_eip_active(2));
    try testing.expect(london.is_eip_active(2));

    // London EIPs
    try testing.expect(!homestead.is_eip_active(1559));
    try testing.expect(london.is_eip_active(1559));
    try testing.expect(london.is_eip_active(3198));
    try testing.expect(london.is_eip_active(3529));

    // Cancun EIPs
    try testing.expect(!london.is_eip_active(4844));
    try testing.expect(cancun.is_eip_active(4844));
    try testing.expect(cancun.is_eip_active(1153));

    // Prague EIPs
    try testing.expect(!cancun.is_eip_active(7702));
    try testing.expect(prague.is_eip_active(7702));
}

test "Eips: is_eip_active - with overrides" {
    const overrides = [_]EipOverride{
        .{ .eip = 3855, .enabled = true }, // Enable PUSH0 on London
        .{ .eip = 1559, .enabled = false }, // Disable EIP-1559 despite London
    };

    const london = Eips{
        .hardfork = .LONDON,
        .overrides = &overrides,
    };

    // Override enables PUSH0 (normally Shanghai+)
    try testing.expect(london.is_eip_active(3855));

    // Override disables EIP-1559 (normally enabled in London)
    try testing.expect(!london.is_eip_active(1559));

    // Other London EIPs still work normally
    try testing.expect(london.is_eip_active(3198));
}

test "Eips: get_active_eips - frontier" {
    const frontier = Eips{ .hardfork = .FRONTIER };
    const active = frontier.get_active_eips();
    try testing.expectEqual(@as(usize, 0), active.len);
}

test "Eips: get_active_eips - london" {
    const london = Eips{ .hardfork = .LONDON };
    const active = london.get_active_eips();

    // Check a few key EIPs are present
    var has_1559 = false;
    var has_3198 = false;
    var has_3529 = false;
    var has_2929 = false;

    for (active) |eip| {
        if (eip == 1559) has_1559 = true;
        if (eip == 3198) has_3198 = true;
        if (eip == 3529) has_3529 = true;
        if (eip == 2929) has_2929 = true;
    }

    try testing.expect(has_1559);
    try testing.expect(has_3198);
    try testing.expect(has_3529);
    try testing.expect(has_2929);
}

test "Eips: get_active_eips - cancun" {
    const cancun = Eips{ .hardfork = .CANCUN };
    const active = cancun.get_active_eips();

    // Check Cancun-specific EIPs
    var has_4844 = false;
    var has_1153 = false;
    var has_5656 = false;

    for (active) |eip| {
        if (eip == 4844) has_4844 = true;
        if (eip == 1153) has_1153 = true;
        if (eip == 5656) has_5656 = true;
    }

    try testing.expect(has_4844);
    try testing.expect(has_1153);
    try testing.expect(has_5656);
}

test "Eips: opcode availability - PUSH0" {
    const london = Eips{ .hardfork = .LONDON };
    const shanghai = Eips{ .hardfork = .SHANGHAI };

    try testing.expect(!london.eip_3855_push0_enabled());
    try testing.expect(shanghai.eip_3855_push0_enabled());
}

test "Eips: opcode availability - BASEFEE" {
    const berlin = Eips{ .hardfork = .BERLIN };
    const london = Eips{ .hardfork = .LONDON };

    try testing.expect(!berlin.eip_3198_basefee_opcode_enabled());
    try testing.expect(london.eip_3198_basefee_opcode_enabled());
}

test "Eips: opcode availability - transient storage" {
    const shanghai = Eips{ .hardfork = .SHANGHAI };
    const cancun = Eips{ .hardfork = .CANCUN };

    try testing.expect(!shanghai.eip_1153_transient_storage_enabled());
    try testing.expect(cancun.eip_1153_transient_storage_enabled());
}

test "Eips: opcode availability - MCOPY" {
    const shanghai = Eips{ .hardfork = .SHANGHAI };
    const cancun = Eips{ .hardfork = .CANCUN };

    try testing.expect(!shanghai.eip_5656_has_mcopy());
    try testing.expect(cancun.eip_5656_has_mcopy());
}

test "Eips: transaction types - EIP-1559" {
    const berlin = Eips{ .hardfork = .BERLIN };
    const london = Eips{ .hardfork = .LONDON };

    try testing.expect(!berlin.eip_1559_is_enabled());
    try testing.expect(london.eip_1559_is_enabled());
}

test "Eips: transaction types - blob transactions" {
    const shanghai = Eips{ .hardfork = .SHANGHAI };
    const cancun = Eips{ .hardfork = .CANCUN };

    try testing.expect(!shanghai.eip_4844_blob_transactions_enabled());
    try testing.expect(cancun.eip_4844_blob_transactions_enabled());
}

test "Eips: transaction types - EOA code" {
    const cancun = Eips{ .hardfork = .CANCUN };
    const prague = Eips{ .hardfork = .PRAGUE };

    try testing.expect(!cancun.eip_7702_eoa_code_enabled());
    try testing.expect(prague.eip_7702_eoa_code_enabled());
}

test "Eips: gas costs - cold SLOAD" {
    const istanbul = Eips{ .hardfork = .ISTANBUL };
    const berlin = Eips{ .hardfork = .BERLIN };

    try testing.expectEqual(@as(u64, 200), istanbul.eip_2929_cold_sload_cost());
    try testing.expectEqual(@as(u64, 2100), berlin.eip_2929_cold_sload_cost());
}

test "Eips: gas costs - warm storage read" {
    const istanbul = Eips{ .hardfork = .ISTANBUL };
    const berlin = Eips{ .hardfork = .BERLIN };

    try testing.expectEqual(@as(u64, 200), istanbul.eip_2929_warm_storage_read_cost());
    try testing.expectEqual(@as(u64, 100), berlin.eip_2929_warm_storage_read_cost());
}

test "Eips: gas costs - cold account access" {
    const istanbul = Eips{ .hardfork = .ISTANBUL };
    const berlin = Eips{ .hardfork = .BERLIN };

    try testing.expectEqual(@as(u64, 700), istanbul.eip_2929_cold_account_access_cost());
    try testing.expectEqual(@as(u64, 2600), berlin.eip_2929_cold_account_access_cost());
}

test "Eips: gas costs - warm account access" {
    const istanbul = Eips{ .hardfork = .ISTANBUL };
    const berlin = Eips{ .hardfork = .BERLIN };

    try testing.expectEqual(@as(u64, 700), istanbul.eip_2929_warm_account_access_cost());
    try testing.expectEqual(@as(u64, 100), berlin.eip_2929_warm_account_access_cost());
}

test "Eips: gas costs - refund cap" {
    const berlin = Eips{ .hardfork = .BERLIN };
    const london = Eips{ .hardfork = .LONDON };

    const gas_used: u64 = 100_000;
    const refund_counter: u64 = 50_000;

    // Pre-London: cap at 1/2
    const berlin_refund = berlin.eip_3529_gas_refund_cap(gas_used, refund_counter);
    try testing.expectEqual(@as(u64, 50_000), berlin_refund);

    // London: cap at 1/5
    const london_refund = london.eip_3529_gas_refund_cap(gas_used, refund_counter);
    try testing.expectEqual(@as(u64, 20_000), london_refund);
}

test "Eips: gas costs - refund cap with smaller counter" {
    const london = Eips{ .hardfork = .LONDON };

    const gas_used: u64 = 100_000;
    const refund_counter: u64 = 10_000;

    // Should return refund_counter since it's smaller than gas_used / 5
    const refund = london.eip_3529_gas_refund_cap(gas_used, refund_counter);
    try testing.expectEqual(@as(u64, 10_000), refund);
}

test "Eips: gas costs - calldata" {
    const byzantium = Eips{ .hardfork = .BYZANTIUM };
    const istanbul = Eips{ .hardfork = .ISTANBUL };

    // Zero bytes always cost 4
    try testing.expectEqual(@as(u64, 4), byzantium.eip_2028_calldata_gas_cost(true));
    try testing.expectEqual(@as(u64, 4), istanbul.eip_2028_calldata_gas_cost(true));

    // Non-zero bytes: 68 pre-Istanbul, 16 post-Istanbul
    try testing.expectEqual(@as(u64, 68), byzantium.eip_2028_calldata_gas_cost(false));
    try testing.expectEqual(@as(u64, 16), istanbul.eip_2028_calldata_gas_cost(false));
}

test "Eips: gas costs - EXP byte cost" {
    const homestead = Eips{ .hardfork = .HOMESTEAD };
    const spurious = Eips{ .hardfork = .SPURIOUS_DRAGON };

    try testing.expectEqual(@as(u64, 10), homestead.eip_160_exp_byte_gas_cost());
    try testing.expectEqual(@as(u64, 50), spurious.eip_160_exp_byte_gas_cost());
}

test "Eips: SSTORE gas cost - no-op" {
    const london = Eips{ .hardfork = .LONDON };

    const cost = london.sstore_gas_cost(100, 100, 100);
    try testing.expectEqual(@as(u64, 100), cost.gas);
    try testing.expectEqual(@as(i64, 0), cost.refund);
}

test "Eips: SSTORE gas cost - set from zero" {
    const london = Eips{ .hardfork = .LONDON };

    const cost = london.sstore_gas_cost(0, 1, 0);
    try testing.expectEqual(@as(u64, 20000), cost.gas);
    try testing.expectEqual(@as(i64, 0), cost.refund);
}

test "Eips: SSTORE gas cost - clear storage (London)" {
    const london = Eips{ .hardfork = .LONDON };

    const cost = london.sstore_gas_cost(1, 0, 1);
    try testing.expectEqual(@as(u64, 5000), cost.gas);
    try testing.expectEqual(@as(i64, 4800), cost.refund); // EIP-3529 reduced refund
}

test "Eips: SSTORE gas cost - clear storage (pre-London)" {
    const berlin = Eips{ .hardfork = .BERLIN };

    const cost = berlin.sstore_gas_cost(1, 0, 1);
    try testing.expectEqual(@as(u64, 5000), cost.gas);
    try testing.expectEqual(@as(i64, 15000), cost.refund); // Pre-EIP-3529 refund
}

test "Eips: SSTORE gas cost - modify non-zero" {
    const london = Eips{ .hardfork = .LONDON };

    const cost = london.sstore_gas_cost(1, 2, 1);
    try testing.expectEqual(@as(u64, 5000), cost.gas);
    try testing.expectEqual(@as(i64, 0), cost.refund);
}

test "Eips: SSTORE gas cost - restore to original" {
    const london = Eips{ .hardfork = .LONDON };

    const cost = london.sstore_gas_cost(2, 1, 1);
    try testing.expectEqual(@as(u64, 5000), cost.gas);
    try testing.expectEqual(@as(i64, 4900), cost.refund);
}

test "Eips: code limits - max code size" {
    const homestead = Eips{ .hardfork = .HOMESTEAD };
    const spurious = Eips{ .hardfork = .SPURIOUS_DRAGON };

    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), homestead.eip_170_max_code_size());
    try testing.expectEqual(@as(u32, 24576), spurious.eip_170_max_code_size());
}

test "Eips: code limits - initcode size limit" {
    const london = Eips{ .hardfork = .LONDON };
    const shanghai = Eips{ .hardfork = .SHANGHAI };

    try testing.expectEqual(@as(u64, 24576), london.eip_3860_size_limit());
    try testing.expectEqual(@as(u64, 49152), shanghai.eip_3860_size_limit());
}

test "Eips: code limits - initcode word cost" {
    const london = Eips{ .hardfork = .LONDON };
    const shanghai = Eips{ .hardfork = .SHANGHAI };

    try testing.expectEqual(@as(u64, 0), london.eip_3860_word_cost());
    try testing.expectEqual(@as(u64, 2), shanghai.eip_3860_word_cost());
}

test "Eips: behavior - SELFDESTRUCT restriction" {
    const shanghai = Eips{ .hardfork = .SHANGHAI };
    const cancun = Eips{ .hardfork = .CANCUN };

    try testing.expect(!shanghai.eip_6780_selfdestruct_same_transaction_only());
    try testing.expect(cancun.eip_6780_selfdestruct_same_transaction_only());
}

test "Eips: behavior - reject EF bytecode" {
    const berlin = Eips{ .hardfork = .BERLIN };
    const london = Eips{ .hardfork = .LONDON };

    try testing.expect(!berlin.eip_3541_should_reject_ef_bytecode());
    try testing.expect(london.eip_3541_should_reject_ef_bytecode());
}

test "Eips: behavior - PREVRANDAO vs DIFFICULTY" {
    const london = Eips{ .hardfork = .LONDON };
    const merge = Eips{ .hardfork = .MERGE };

    try testing.expect(!london.eip_4399_use_prevrandao());
    try testing.expect(merge.eip_4399_use_prevrandao());
}

test "Eips: comprehensive - hardfork progression" {
    // Test that newer hardforks include all older EIPs
    const prague = Eips{ .hardfork = .PRAGUE };

    // Should have all major EIPs
    try testing.expect(prague.is_eip_active(2)); // Homestead
    try testing.expect(prague.is_eip_active(160)); // Spurious Dragon
    try testing.expect(prague.is_eip_active(170)); // Spurious Dragon
    try testing.expect(prague.is_eip_active(2028)); // Istanbul
    try testing.expect(prague.is_eip_active(2929)); // Berlin
    try testing.expect(prague.is_eip_active(1559)); // London
    try testing.expect(prague.is_eip_active(3855)); // Shanghai
    try testing.expect(prague.is_eip_active(4844)); // Cancun
    try testing.expect(prague.is_eip_active(7702)); // Prague
}

test "Eips: comprehensive - gas cost evolution" {
    const frontier = Eips{ .hardfork = .FRONTIER };
    const istanbul = Eips{ .hardfork = .ISTANBUL };
    const berlin = Eips{ .hardfork = .BERLIN };
    const london = Eips{ .hardfork = .LONDON };

    // SLOAD cost evolution
    try testing.expectEqual(@as(u64, 200), frontier.eip_2929_cold_sload_cost());
    try testing.expectEqual(@as(u64, 200), istanbul.eip_2929_cold_sload_cost());
    try testing.expectEqual(@as(u64, 2100), berlin.eip_2929_cold_sload_cost());
    try testing.expectEqual(@as(u64, 2100), london.eip_2929_cold_sload_cost());

    // Refund cap evolution
    const gas_used: u64 = 100_000;
    const refund: u64 = 60_000;

    try testing.expectEqual(@as(u64, 50_000), berlin.eip_3529_gas_refund_cap(gas_used, refund));
    try testing.expectEqual(@as(u64, 20_000), london.eip_3529_gas_refund_cap(gas_used, refund));
}
