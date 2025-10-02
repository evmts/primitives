const std = @import("std");

/// Represents an EVM opcode with categorization and utility methods
///
/// This enumeration contains all EVM opcodes from the Ethereum Yellow Paper,
/// including the latest EIPs (transient storage, memory copy, and auth operations).
///
/// Provides utility methods for:
/// - PUSH operations: size calculation and detection
/// - DUP operations: stack position calculation
/// - SWAP operations: stack position calculation
/// - LOG operations: topic count calculation
/// - Opcode categorization: terminating, state-modifying, arithmetic, etc.
///
/// Example:
/// ```zig
/// const opcode = Opcode.PUSH1;
/// if (opcode.isPush()) {
///     const bytes_to_read = opcode.pushSize();
///     // Read bytes_to_read bytes following the opcode
/// }
/// ```
pub const Opcode = enum(u8) {
    // =============================================================================
    // 0x0 range - Arithmetic Operations
    // =============================================================================
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,

    // =============================================================================
    // 0x10 range - Comparison & Bitwise Operations
    // =============================================================================
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b,
    SHR = 0x1c,
    SAR = 0x1d,

    // =============================================================================
    // 0x20 range - Cryptographic Operations
    // =============================================================================
    KECCAK256 = 0x20,

    // =============================================================================
    // 0x30 range - Environmental Information
    // =============================================================================
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3a,
    EXTCODESIZE = 0x3b,
    EXTCODECOPY = 0x3c,
    RETURNDATASIZE = 0x3d,
    RETURNDATACOPY = 0x3e,
    EXTCODEHASH = 0x3f,

    // =============================================================================
    // 0x40 range - Block Information
    // =============================================================================
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    PREVRANDAO = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,
    BLOBHASH = 0x49,
    BLOBBASEFEE = 0x4a,

    // =============================================================================
    // 0x50 range - Stack, Memory, Storage and Flow Operations
    // =============================================================================
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5a,
    JUMPDEST = 0x5b,
    TLOAD = 0x5c,
    TSTORE = 0x5d,
    MCOPY = 0x5e,
    PUSH0 = 0x5f,

    // =============================================================================
    // 0x60-0x7f range - PUSH Operations
    // =============================================================================
    PUSH1 = 0x60,
    PUSH2 = 0x61,
    PUSH3 = 0x62,
    PUSH4 = 0x63,
    PUSH5 = 0x64,
    PUSH6 = 0x65,
    PUSH7 = 0x66,
    PUSH8 = 0x67,
    PUSH9 = 0x68,
    PUSH10 = 0x69,
    PUSH11 = 0x6a,
    PUSH12 = 0x6b,
    PUSH13 = 0x6c,
    PUSH14 = 0x6d,
    PUSH15 = 0x6e,
    PUSH16 = 0x6f,
    PUSH17 = 0x70,
    PUSH18 = 0x71,
    PUSH19 = 0x72,
    PUSH20 = 0x73,
    PUSH21 = 0x74,
    PUSH22 = 0x75,
    PUSH23 = 0x76,
    PUSH24 = 0x77,
    PUSH25 = 0x78,
    PUSH26 = 0x79,
    PUSH27 = 0x7a,
    PUSH28 = 0x7b,
    PUSH29 = 0x7c,
    PUSH30 = 0x7d,
    PUSH31 = 0x7e,
    PUSH32 = 0x7f,

    // =============================================================================
    // 0x80-0x8f range - DUP Operations
    // =============================================================================
    DUP1 = 0x80,
    DUP2 = 0x81,
    DUP3 = 0x82,
    DUP4 = 0x83,
    DUP5 = 0x84,
    DUP6 = 0x85,
    DUP7 = 0x86,
    DUP8 = 0x87,
    DUP9 = 0x88,
    DUP10 = 0x89,
    DUP11 = 0x8a,
    DUP12 = 0x8b,
    DUP13 = 0x8c,
    DUP14 = 0x8d,
    DUP15 = 0x8e,
    DUP16 = 0x8f,

    // =============================================================================
    // 0x90-0x9f range - SWAP Operations
    // =============================================================================
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    SWAP3 = 0x92,
    SWAP4 = 0x93,
    SWAP5 = 0x94,
    SWAP6 = 0x95,
    SWAP7 = 0x96,
    SWAP8 = 0x97,
    SWAP9 = 0x98,
    SWAP10 = 0x99,
    SWAP11 = 0x9a,
    SWAP12 = 0x9b,
    SWAP13 = 0x9c,
    SWAP14 = 0x9d,
    SWAP15 = 0x9e,
    SWAP16 = 0x9f,

    // =============================================================================
    // 0xa0-0xa4 range - LOG Operations
    // =============================================================================
    LOG0 = 0xa0,
    LOG1 = 0xa1,
    LOG2 = 0xa2,
    LOG3 = 0xa3,
    LOG4 = 0xa4,

    // =============================================================================
    // 0xf0 range - System Operations (Calls, Creates, Halts)
    // =============================================================================
    CREATE = 0xf0,
    CALL = 0xf1,
    CALLCODE = 0xf2,
    RETURN = 0xf3,
    DELEGATECALL = 0xf4,
    CREATE2 = 0xf5,
    AUTH = 0xf6,
    AUTHCALL = 0xf7,
    STATICCALL = 0xfa,
    REVERT = 0xfd,
    INVALID = 0xfe,
    SELFDESTRUCT = 0xff,

    // =============================================================================
    // PUSH Operations Helpers
    // =============================================================================

    /// Check if opcode is a PUSH instruction (PUSH0-PUSH32)
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isPush()) {
    ///     const size = opcode.pushSize();
    /// }
    /// ```
    pub fn isPush(self: Opcode) bool {
        const val = @intFromEnum(self);
        return val >= 0x5f and val <= 0x7f;
    }

    /// Get number of bytes pushed by PUSH instruction
    ///
    /// Returns 0 for PUSH0, 1 for PUSH1, ..., 32 for PUSH32
    /// Returns 0 for non-PUSH opcodes
    ///
    /// Example:
    /// ```zig
    /// const opcode = Opcode.PUSH1;
    /// const bytes_to_read = opcode.pushSize(); // Returns 1
    /// ```
    pub fn pushSize(self: Opcode) u8 {
        const val = @intFromEnum(self);
        if (val >= 0x5f and val <= 0x7f) {
            return val - 0x5f; // PUSH0=0, PUSH1=1, ..., PUSH32=32
        }
        return 0;
    }

    // =============================================================================
    // DUP Operations Helpers
    // =============================================================================

    /// Check if opcode is a DUP instruction (DUP1-DUP16)
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isDup()) {
    ///     const position = opcode.dupPosition();
    /// }
    /// ```
    pub fn isDup(self: Opcode) bool {
        const val = @intFromEnum(self);
        return val >= 0x80 and val <= 0x8f;
    }

    /// Get stack position for DUP instruction
    ///
    /// Returns 1 for DUP1, 2 for DUP2, ..., 16 for DUP16
    /// Returns 0 for non-DUP opcodes
    ///
    /// Example:
    /// ```zig
    /// const opcode = Opcode.DUP1;
    /// const position = opcode.dupPosition(); // Returns 1
    /// ```
    pub fn dupPosition(self: Opcode) u8 {
        const val = @intFromEnum(self);
        if (val >= 0x80 and val <= 0x8f) {
            return val - 0x80 + 1; // DUP1=1, DUP2=2, ..., DUP16=16
        }
        return 0;
    }

    // =============================================================================
    // SWAP Operations Helpers
    // =============================================================================

    /// Check if opcode is a SWAP instruction (SWAP1-SWAP16)
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isSwap()) {
    ///     const position = opcode.swapPosition();
    /// }
    /// ```
    pub fn isSwap(self: Opcode) bool {
        const val = @intFromEnum(self);
        return val >= 0x90 and val <= 0x9f;
    }

    /// Get stack position for SWAP instruction
    ///
    /// Returns 1 for SWAP1, 2 for SWAP2, ..., 16 for SWAP16
    /// Returns 0 for non-SWAP opcodes
    ///
    /// Example:
    /// ```zig
    /// const opcode = Opcode.SWAP1;
    /// const position = opcode.swapPosition(); // Returns 1
    /// ```
    pub fn swapPosition(self: Opcode) u8 {
        const val = @intFromEnum(self);
        if (val >= 0x90 and val <= 0x9f) {
            return val - 0x90 + 1; // SWAP1=1, SWAP2=2, ..., SWAP16=16
        }
        return 0;
    }

    // =============================================================================
    // LOG Operations Helpers
    // =============================================================================

    /// Check if opcode is a LOG instruction (LOG0-LOG4)
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isLog()) {
    ///     const topics = opcode.logTopics();
    /// }
    /// ```
    pub fn isLog(self: Opcode) bool {
        const val = @intFromEnum(self);
        return val >= 0xa0 and val <= 0xa4;
    }

    /// Get number of topics for LOG instruction
    ///
    /// Returns 0 for LOG0, 1 for LOG1, ..., 4 for LOG4
    /// Returns 0 for non-LOG opcodes
    ///
    /// Example:
    /// ```zig
    /// const opcode = Opcode.LOG2;
    /// const topics = opcode.logTopics(); // Returns 2
    /// ```
    pub fn logTopics(self: Opcode) u8 {
        const val = @intFromEnum(self);
        if (val >= 0xa0 and val <= 0xa4) {
            return val - 0xa0; // LOG0=0, LOG1=1, ..., LOG4=4
        }
        return 0;
    }

    // =============================================================================
    // Opcode Classification
    // =============================================================================

    /// Check if opcode terminates execution
    ///
    /// Terminating opcodes: STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isTerminating()) {
    ///     // End execution
    /// }
    /// ```
    pub fn isTerminating(self: Opcode) bool {
        return switch (self) {
            .STOP, .RETURN, .REVERT, .INVALID, .SELFDESTRUCT => true,
            else => false,
        };
    }

    /// Check if opcode modifies blockchain state
    ///
    /// State-modifying opcodes: SSTORE, TSTORE, LOG*, CREATE*, CALL (non-static), SELFDESTRUCT
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isStateModifying()) {
    ///     // Handle state modification
    /// }
    /// ```
    pub fn isStateModifying(self: Opcode) bool {
        return switch (self) {
            .SSTORE,
            .TSTORE,
            .LOG0,
            .LOG1,
            .LOG2,
            .LOG3,
            .LOG4,
            .CREATE,
            .CALL,
            .CALLCODE,
            .DELEGATECALL,
            .CREATE2,
            .AUTH,
            .AUTHCALL,
            .SELFDESTRUCT,
            => true,
            else => false,
        };
    }

    /// Check if opcode is an arithmetic operation
    ///
    /// Arithmetic opcodes: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isArithmetic()) {
    ///     // Handle arithmetic operation
    /// }
    /// ```
    pub fn isArithmetic(self: Opcode) bool {
        return switch (self) {
            .ADD,
            .MUL,
            .SUB,
            .DIV,
            .SDIV,
            .MOD,
            .SMOD,
            .ADDMOD,
            .MULMOD,
            .EXP,
            .SIGNEXTEND,
            => true,
            else => false,
        };
    }

    /// Check if opcode is a comparison operation
    ///
    /// Comparison opcodes: LT, GT, SLT, SGT, EQ, ISZERO
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isComparison()) {
    ///     // Handle comparison operation
    /// }
    /// ```
    pub fn isComparison(self: Opcode) bool {
        return switch (self) {
            .LT, .GT, .SLT, .SGT, .EQ, .ISZERO => true,
            else => false,
        };
    }

    /// Check if opcode is a bitwise operation
    ///
    /// Bitwise opcodes: AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
    ///
    /// Example:
    /// ```zig
    /// if (opcode.isBitwise()) {
    ///     // Handle bitwise operation
    /// }
    /// ```
    pub fn isBitwise(self: Opcode) bool {
        return switch (self) {
            .AND, .OR, .XOR, .NOT, .BYTE, .SHL, .SHR, .SAR => true,
            else => false,
        };
    }

    /// Get the string name of the opcode
    ///
    /// Returns the uppercase opcode name (e.g., "PUSH1", "ADD", "SSTORE")
    ///
    /// Example:
    /// ```zig
    /// const opcode = Opcode.PUSH1;
    /// const name = opcode.name(); // Returns "PUSH1"
    /// ```
    pub fn name(self: Opcode) []const u8 {
        return @tagName(self);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Opcode: isPush - detects all PUSH opcodes" {
    try std.testing.expect(Opcode.PUSH0.isPush());
    try std.testing.expect(Opcode.PUSH1.isPush());
    try std.testing.expect(Opcode.PUSH2.isPush());
    try std.testing.expect(Opcode.PUSH16.isPush());
    try std.testing.expect(Opcode.PUSH32.isPush());
}

test "Opcode: isPush - rejects non-PUSH opcodes" {
    try std.testing.expect(!Opcode.ADD.isPush());
    try std.testing.expect(!Opcode.DUP1.isPush());
    try std.testing.expect(!Opcode.SWAP1.isPush());
    try std.testing.expect(!Opcode.LOG0.isPush());
    try std.testing.expect(!Opcode.MSTORE.isPush());
}

test "Opcode: pushSize - returns correct sizes" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH0.pushSize());
    try std.testing.expectEqual(@as(u8, 1), Opcode.PUSH1.pushSize());
    try std.testing.expectEqual(@as(u8, 2), Opcode.PUSH2.pushSize());
    try std.testing.expectEqual(@as(u8, 16), Opcode.PUSH16.pushSize());
    try std.testing.expectEqual(@as(u8, 32), Opcode.PUSH32.pushSize());
}

test "Opcode: pushSize - returns 0 for non-PUSH opcodes" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.ADD.pushSize());
    try std.testing.expectEqual(@as(u8, 0), Opcode.DUP1.pushSize());
    try std.testing.expectEqual(@as(u8, 0), Opcode.SWAP1.pushSize());
}

test "Opcode: isDup - detects all DUP opcodes" {
    try std.testing.expect(Opcode.DUP1.isDup());
    try std.testing.expect(Opcode.DUP2.isDup());
    try std.testing.expect(Opcode.DUP8.isDup());
    try std.testing.expect(Opcode.DUP16.isDup());
}

test "Opcode: isDup - rejects non-DUP opcodes" {
    try std.testing.expect(!Opcode.PUSH1.isDup());
    try std.testing.expect(!Opcode.SWAP1.isDup());
    try std.testing.expect(!Opcode.ADD.isDup());
    try std.testing.expect(!Opcode.LOG0.isDup());
}

test "Opcode: dupPosition - returns correct positions" {
    try std.testing.expectEqual(@as(u8, 1), Opcode.DUP1.dupPosition());
    try std.testing.expectEqual(@as(u8, 2), Opcode.DUP2.dupPosition());
    try std.testing.expectEqual(@as(u8, 8), Opcode.DUP8.dupPosition());
    try std.testing.expectEqual(@as(u8, 16), Opcode.DUP16.dupPosition());
}

test "Opcode: dupPosition - returns 0 for non-DUP opcodes" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH1.dupPosition());
    try std.testing.expectEqual(@as(u8, 0), Opcode.SWAP1.dupPosition());
    try std.testing.expectEqual(@as(u8, 0), Opcode.ADD.dupPosition());
}

test "Opcode: isSwap - detects all SWAP opcodes" {
    try std.testing.expect(Opcode.SWAP1.isSwap());
    try std.testing.expect(Opcode.SWAP2.isSwap());
    try std.testing.expect(Opcode.SWAP8.isSwap());
    try std.testing.expect(Opcode.SWAP16.isSwap());
}

test "Opcode: isSwap - rejects non-SWAP opcodes" {
    try std.testing.expect(!Opcode.PUSH1.isSwap());
    try std.testing.expect(!Opcode.DUP1.isSwap());
    try std.testing.expect(!Opcode.ADD.isSwap());
    try std.testing.expect(!Opcode.LOG0.isSwap());
}

test "Opcode: swapPosition - returns correct positions" {
    try std.testing.expectEqual(@as(u8, 1), Opcode.SWAP1.swapPosition());
    try std.testing.expectEqual(@as(u8, 2), Opcode.SWAP2.swapPosition());
    try std.testing.expectEqual(@as(u8, 8), Opcode.SWAP8.swapPosition());
    try std.testing.expectEqual(@as(u8, 16), Opcode.SWAP16.swapPosition());
}

test "Opcode: swapPosition - returns 0 for non-SWAP opcodes" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH1.swapPosition());
    try std.testing.expectEqual(@as(u8, 0), Opcode.DUP1.swapPosition());
    try std.testing.expectEqual(@as(u8, 0), Opcode.ADD.swapPosition());
}

test "Opcode: isLog - detects all LOG opcodes" {
    try std.testing.expect(Opcode.LOG0.isLog());
    try std.testing.expect(Opcode.LOG1.isLog());
    try std.testing.expect(Opcode.LOG2.isLog());
    try std.testing.expect(Opcode.LOG3.isLog());
    try std.testing.expect(Opcode.LOG4.isLog());
}

test "Opcode: isLog - rejects non-LOG opcodes" {
    try std.testing.expect(!Opcode.PUSH1.isLog());
    try std.testing.expect(!Opcode.DUP1.isLog());
    try std.testing.expect(!Opcode.SWAP1.isLog());
    try std.testing.expect(!Opcode.SSTORE.isLog());
}

test "Opcode: logTopics - returns correct topic counts" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.LOG0.logTopics());
    try std.testing.expectEqual(@as(u8, 1), Opcode.LOG1.logTopics());
    try std.testing.expectEqual(@as(u8, 2), Opcode.LOG2.logTopics());
    try std.testing.expectEqual(@as(u8, 3), Opcode.LOG3.logTopics());
    try std.testing.expectEqual(@as(u8, 4), Opcode.LOG4.logTopics());
}

test "Opcode: logTopics - returns 0 for non-LOG opcodes" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH1.logTopics());
    try std.testing.expectEqual(@as(u8, 0), Opcode.SSTORE.logTopics());
    try std.testing.expectEqual(@as(u8, 0), Opcode.ADD.logTopics());
}

test "Opcode: isTerminating - detects terminating opcodes" {
    try std.testing.expect(Opcode.STOP.isTerminating());
    try std.testing.expect(Opcode.RETURN.isTerminating());
    try std.testing.expect(Opcode.REVERT.isTerminating());
    try std.testing.expect(Opcode.INVALID.isTerminating());
    try std.testing.expect(Opcode.SELFDESTRUCT.isTerminating());
}

test "Opcode: isTerminating - rejects non-terminating opcodes" {
    try std.testing.expect(!Opcode.ADD.isTerminating());
    try std.testing.expect(!Opcode.SSTORE.isTerminating());
    try std.testing.expect(!Opcode.JUMP.isTerminating());
    try std.testing.expect(!Opcode.CALL.isTerminating());
}

test "Opcode: isStateModifying - detects state-modifying opcodes" {
    try std.testing.expect(Opcode.SSTORE.isStateModifying());
    try std.testing.expect(Opcode.TSTORE.isStateModifying());
    try std.testing.expect(Opcode.LOG0.isStateModifying());
    try std.testing.expect(Opcode.LOG1.isStateModifying());
    try std.testing.expect(Opcode.LOG2.isStateModifying());
    try std.testing.expect(Opcode.LOG3.isStateModifying());
    try std.testing.expect(Opcode.LOG4.isStateModifying());
    try std.testing.expect(Opcode.CREATE.isStateModifying());
    try std.testing.expect(Opcode.CREATE2.isStateModifying());
    try std.testing.expect(Opcode.CALL.isStateModifying());
    try std.testing.expect(Opcode.CALLCODE.isStateModifying());
    try std.testing.expect(Opcode.DELEGATECALL.isStateModifying());
    try std.testing.expect(Opcode.AUTH.isStateModifying());
    try std.testing.expect(Opcode.AUTHCALL.isStateModifying());
    try std.testing.expect(Opcode.SELFDESTRUCT.isStateModifying());
}

test "Opcode: isStateModifying - rejects non-state-modifying opcodes" {
    try std.testing.expect(!Opcode.ADD.isStateModifying());
    try std.testing.expect(!Opcode.SLOAD.isStateModifying());
    try std.testing.expect(!Opcode.TLOAD.isStateModifying());
    try std.testing.expect(!Opcode.STATICCALL.isStateModifying());
    try std.testing.expect(!Opcode.MSTORE.isStateModifying());
    try std.testing.expect(!Opcode.PUSH1.isStateModifying());
}

test "Opcode: isArithmetic - detects arithmetic opcodes" {
    try std.testing.expect(Opcode.ADD.isArithmetic());
    try std.testing.expect(Opcode.MUL.isArithmetic());
    try std.testing.expect(Opcode.SUB.isArithmetic());
    try std.testing.expect(Opcode.DIV.isArithmetic());
    try std.testing.expect(Opcode.SDIV.isArithmetic());
    try std.testing.expect(Opcode.MOD.isArithmetic());
    try std.testing.expect(Opcode.SMOD.isArithmetic());
    try std.testing.expect(Opcode.ADDMOD.isArithmetic());
    try std.testing.expect(Opcode.MULMOD.isArithmetic());
    try std.testing.expect(Opcode.EXP.isArithmetic());
    try std.testing.expect(Opcode.SIGNEXTEND.isArithmetic());
}

test "Opcode: isArithmetic - rejects non-arithmetic opcodes" {
    try std.testing.expect(!Opcode.LT.isArithmetic());
    try std.testing.expect(!Opcode.AND.isArithmetic());
    try std.testing.expect(!Opcode.PUSH1.isArithmetic());
    try std.testing.expect(!Opcode.SSTORE.isArithmetic());
}

test "Opcode: isComparison - detects comparison opcodes" {
    try std.testing.expect(Opcode.LT.isComparison());
    try std.testing.expect(Opcode.GT.isComparison());
    try std.testing.expect(Opcode.SLT.isComparison());
    try std.testing.expect(Opcode.SGT.isComparison());
    try std.testing.expect(Opcode.EQ.isComparison());
    try std.testing.expect(Opcode.ISZERO.isComparison());
}

test "Opcode: isComparison - rejects non-comparison opcodes" {
    try std.testing.expect(!Opcode.ADD.isComparison());
    try std.testing.expect(!Opcode.AND.isComparison());
    try std.testing.expect(!Opcode.PUSH1.isComparison());
    try std.testing.expect(!Opcode.SSTORE.isComparison());
}

test "Opcode: isBitwise - detects bitwise opcodes" {
    try std.testing.expect(Opcode.AND.isBitwise());
    try std.testing.expect(Opcode.OR.isBitwise());
    try std.testing.expect(Opcode.XOR.isBitwise());
    try std.testing.expect(Opcode.NOT.isBitwise());
    try std.testing.expect(Opcode.BYTE.isBitwise());
    try std.testing.expect(Opcode.SHL.isBitwise());
    try std.testing.expect(Opcode.SHR.isBitwise());
    try std.testing.expect(Opcode.SAR.isBitwise());
}

test "Opcode: isBitwise - rejects non-bitwise opcodes" {
    try std.testing.expect(!Opcode.ADD.isBitwise());
    try std.testing.expect(!Opcode.LT.isBitwise());
    try std.testing.expect(!Opcode.PUSH1.isBitwise());
    try std.testing.expect(!Opcode.SSTORE.isBitwise());
}

test "Opcode: name - returns correct opcode names" {
    try std.testing.expectEqualStrings("STOP", Opcode.STOP.name());
    try std.testing.expectEqualStrings("ADD", Opcode.ADD.name());
    try std.testing.expectEqualStrings("PUSH1", Opcode.PUSH1.name());
    try std.testing.expectEqualStrings("PUSH32", Opcode.PUSH32.name());
    try std.testing.expectEqualStrings("DUP1", Opcode.DUP1.name());
    try std.testing.expectEqualStrings("SWAP1", Opcode.SWAP1.name());
    try std.testing.expectEqualStrings("LOG0", Opcode.LOG0.name());
    try std.testing.expectEqualStrings("SSTORE", Opcode.SSTORE.name());
    try std.testing.expectEqualStrings("CREATE", Opcode.CREATE.name());
    try std.testing.expectEqualStrings("SELFDESTRUCT", Opcode.SELFDESTRUCT.name());
}

test "Opcode: enum values - verify correct opcode bytes" {
    try std.testing.expectEqual(@as(u8, 0x00), @intFromEnum(Opcode.STOP));
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(Opcode.ADD));
    try std.testing.expectEqual(@as(u8, 0x20), @intFromEnum(Opcode.KECCAK256));
    try std.testing.expectEqual(@as(u8, 0x5f), @intFromEnum(Opcode.PUSH0));
    try std.testing.expectEqual(@as(u8, 0x60), @intFromEnum(Opcode.PUSH1));
    try std.testing.expectEqual(@as(u8, 0x7f), @intFromEnum(Opcode.PUSH32));
    try std.testing.expectEqual(@as(u8, 0x80), @intFromEnum(Opcode.DUP1));
    try std.testing.expectEqual(@as(u8, 0x8f), @intFromEnum(Opcode.DUP16));
    try std.testing.expectEqual(@as(u8, 0x90), @intFromEnum(Opcode.SWAP1));
    try std.testing.expectEqual(@as(u8, 0x9f), @intFromEnum(Opcode.SWAP16));
    try std.testing.expectEqual(@as(u8, 0xa0), @intFromEnum(Opcode.LOG0));
    try std.testing.expectEqual(@as(u8, 0xa4), @intFromEnum(Opcode.LOG4));
    try std.testing.expectEqual(@as(u8, 0xf0), @intFromEnum(Opcode.CREATE));
    try std.testing.expectEqual(@as(u8, 0xff), @intFromEnum(Opcode.SELFDESTRUCT));
}

test "Opcode: new opcodes - verify transient storage and other new opcodes" {
    try std.testing.expectEqual(@as(u8, 0x5c), @intFromEnum(Opcode.TLOAD));
    try std.testing.expectEqual(@as(u8, 0x5d), @intFromEnum(Opcode.TSTORE));
    try std.testing.expectEqual(@as(u8, 0x5e), @intFromEnum(Opcode.MCOPY));
    try std.testing.expectEqual(@as(u8, 0xf6), @intFromEnum(Opcode.AUTH));
    try std.testing.expectEqual(@as(u8, 0xf7), @intFromEnum(Opcode.AUTHCALL));
}

test "Opcode: combined operations - PUSH detection and size calculation" {
    const opcode = Opcode.PUSH20; // Address size
    try std.testing.expect(opcode.isPush());
    try std.testing.expectEqual(@as(u8, 20), opcode.pushSize());
    try std.testing.expectEqualStrings("PUSH20", opcode.name());
}

test "Opcode: combined operations - categorization of SSTORE" {
    const opcode = Opcode.SSTORE;
    try std.testing.expect(opcode.isStateModifying());
    try std.testing.expect(!opcode.isArithmetic());
    try std.testing.expect(!opcode.isComparison());
    try std.testing.expect(!opcode.isBitwise());
    try std.testing.expect(!opcode.isTerminating());
    try std.testing.expectEqualStrings("SSTORE", opcode.name());
}

test "Opcode: combined operations - categorization of RETURN" {
    const opcode = Opcode.RETURN;
    try std.testing.expect(opcode.isTerminating());
    try std.testing.expect(!opcode.isStateModifying());
    try std.testing.expect(!opcode.isArithmetic());
    try std.testing.expectEqualStrings("RETURN", opcode.name());
}
