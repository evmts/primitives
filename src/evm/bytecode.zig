/// DEPRECATED: Use bytecode4.zig instead
/// EVM bytecode representation and validation
///
/// Provides safe bytecode handling with:
/// - Size validation (max 24576 bytes per EIP-170)
/// - Format validation and parsing
/// - Security-conscious design preventing buffer overflows
/// - Integration with the Planner system for analysis
/// - Support for both raw bytecode and analyzed instruction streams
///
/// All bytecode operations are bounds-checked and memory-safe.
const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayListAligned;
const Opcode = @import("opcode.zig").Opcode;
const bytecode_config = @import("bytecode_config.zig");
const BytecodeConfig = bytecode_config.BytecodeConfig;

// SECURITY MODEL: Untrusted Bytecode Validation
// ==============================================
// This module implements a two-phase security model for handling untrusted EVM bytecode:
//
// NOTE: This implementation does not support EOF (Ethereum Object Format) EIPs including:
// - EIP-3540: EOF - EVM Object Format v1
// - EIP-3670: EOF - Code Validation
// - EIP-4750: EOF - Functions
// - EIP-5450: EOF - Stack Validation
//
// Phase 1 - Validation (in init/buildBitmapsAndValidate):
// - Treat ALL bytecode as untrusted and potentially malicious
// - Use safe std library functions (e.g., std.meta.intToEnum) that perform runtime checks
// - Validate ALL assumptions about bytecode structure
// - Check for invalid opcodes, truncated PUSH instructions, invalid jump destinations
// - Build validated bitmaps that mark safe regions of code
//
// Phase 2 - Execution (after successful validation):
// - Once bytecode passes validation, we can use unsafe builtins for performance
// - @intFromEnum and @enumFromInt have no safety checks in release mode
// - We can use these because we've already validated all opcodes are valid
// - Bitmap lookups ensure we only execute at valid positions
//
// CRITICAL: Never use unsafe builtins during validation phase!
// CRITICAL: Never trust bytecode indices without checking bitmaps first!

// Constants for magic numbers used throughout the bytecode module
// These constants replace magic numbers to improve code readability and maintainability
const BITS_PER_BYTE = 8;
const BITMAP_SHIFT = 3; // log2(BITS_PER_BYTE) for efficient division by 8
const BITMAP_MASK = 7; // BITS_PER_BYTE - 1 for modulo 8
const INITCODE_GAS_PER_WORD = 2; // EIP-3860: 2 gas per 32-byte word
const BYTES_PER_WORD = 32; // EVM word size in bytes
const MAX_PUSH_BYTES = 32; // Maximum bytes for PUSH32
const OPCODE_TABLE_SIZE = 256; // Total possible opcode values (0x00-0xFF)
const CACHE_LINE_SIZE = 64; // Common cache line size for x86-64 and ARM64
const PREFETCH_DISTANCE = 256; // How far ahead to prefetch in bytes

/// Factory function to create a Bytecode type with the given configuration
/// @deprecated Use bytecode4.zig instead
pub fn Bytecode(comptime cfg: BytecodeConfig) type {
    comptime cfg.validate();

    return struct {
        pub const fusions_enabled = cfg.fusions_enabled;
        pub const ValidationError = error{
            InvalidOpcode,
            TruncatedPush,
            InvalidJumpDestination,
            OutOfMemory,
            InitcodeTooLarge,
            BytecodeTooLarge,
        };

        pub const Stats = @import("bytecode_stats.zig").BytecodeStats;
        pub const PcType = cfg.PcType();

        const Self = @This();

        // Packed 4-bit data per bytecode byte
        const PackedBits = packed struct(u4) {
            is_push_data: bool, // This byte is PUSH operand data
            is_op_start: bool, // This byte starts an instruction
            is_jumpdest: bool, // This byte is a valid JUMPDEST
            is_fusion_candidate: bool, // This byte can be part of fusion
        };

        // Iterator for efficient bytecode traversal
        pub const Iterator = struct {
            bytecode: *const Self,
            pc: PcType,

            pub fn next(iterator: *Iterator) ?OpcodeData {
                if (iterator.pc >= iterator.bytecode.len()) return null;

                const opcode = iterator.bytecode.get_unsafe(iterator.pc);
                const packed_bits = iterator.bytecode.packed_bitmap[iterator.pc];

                // Handle fusion opcodes first
                if (packed_bits.is_fusion_candidate) {
                    const fusion_data = iterator.bytecode.getFusionData(iterator.pc);
                    // Advance PC properly for fusion opcodes (PUSH + data + op)
                    switch (fusion_data) {
                        .push_add_fusion, .push_mul_fusion, .push_sub_fusion, .push_div_fusion, .push_and_fusion, .push_or_fusion, .push_xor_fusion, .push_jump_fusion, .push_jumpi_fusion => {
                            const push_size = opcode - 0x5F;
                            iterator.pc += 1 + push_size + 1;
                        },
                        .push => |push_data| {
                            iterator.pc += 1 + push_data.size;
                        },
                        else => {
                            iterator.pc += 1;
                        },
                    }
                    return fusion_data;
                }

                // push

                // Handle regular opcodes
                switch (opcode) {
                    0x60...0x7F => { // PUSH1-PUSH32
                        const push_size = opcode - 0x5F;
                        var value: u256 = 0;

                        // Read push value using proper endianness
                        const end_pc = @min(iterator.pc + 1 + push_size, @as(PcType, @intCast(iterator.bytecode.len())));
                        for (iterator.pc + 1..end_pc) |i| {
                            value = (value << 8) | iterator.bytecode.get_unsafe(@intCast(i));
                        }

                        iterator.pc = end_pc;
                        return OpcodeData{ .push = .{ .value = value, .size = push_size } };
                    },
                    0x5B => { // JUMPDEST
                        iterator.pc += 1;
                        return OpcodeData{ .jumpdest = .{ .gas_cost = 1 } };
                    },
                    0x00 => { // STOP
                        iterator.pc += 1;
                        return OpcodeData{ .stop = {} };
                    },
                    0xFE, 0xFF => { // INVALID
                        iterator.pc += 1;
                        return OpcodeData{ .invalid = {} };
                    },
                    else => {
                        iterator.pc += 1;
                        return OpcodeData{ .regular = .{ .opcode = opcode } };
                    },
                }
            }
        };

        // Tagged union for opcode data returned by iterator
        pub const OpcodeData = union(enum) {
            regular: struct { opcode: u8 },
            push: struct { value: u256, size: u8 },
            jumpdest: struct { gas_cost: u16 },
            push_add_fusion: struct { value: u256 },
            push_mul_fusion: struct { value: u256 },
            push_sub_fusion: struct { value: u256 },
            push_div_fusion: struct { value: u256 },
            push_and_fusion: struct { value: u256 },
            push_or_fusion: struct { value: u256 },
            push_xor_fusion: struct { value: u256 },
            push_jump_fusion: struct { value: u256 },
            push_jumpi_fusion: struct { value: u256 },
            stop: void,
            invalid: void,
        };

        // Full bytecode including any metadata
        full_code: []const u8,
        // Runtime bytecode (excludes trailing metadata)
        runtime_code: []const u8,
        // Optional metadata if found
        metadata: ?SolidityMetadata,
        allocator: std.mem.Allocator,
        // Original bitmaps (kept for backward compatibility)
        is_push_data: []u8,
        is_op_start: []u8,
        is_jumpdest: []u8,
        // NEW: SIMD-optimized packed bitmap (4 bits per byte position)
        packed_bitmap: []PackedBits,

        /// @deprecated Use bytecode4.zig instead
        pub fn init(allocator: std.mem.Allocator, code: []const u8) ValidationError!Self {
            // First, try to parse metadata to separate runtime code
            const metadata = parseSolidityMetadataFromBytes(code);
            const runtime_code = if (metadata) |m|
                code[0 .. code.len - m.metadata_length]
            else
                code;

            // Enforce EIP-170: maximum runtime bytecode size
            if (runtime_code.len > cfg.max_bytecode_size) {
                return error.BytecodeTooLarge;
            }

            var self = Self{
                .full_code = code,
                .runtime_code = runtime_code,
                .metadata = metadata,
                .allocator = allocator,
                .is_push_data = &.{},
                .is_op_start = &.{},
                .is_jumpdest = &.{},
                .packed_bitmap = &.{},
            };
            // Build bitmaps and validate only the runtime code
            try self.buildBitmapsAndValidate();
            // Validate immediate JUMP/JUMPI targets; deinit on failure to avoid leaks
            self.validateImmediateJumps() catch |e| {
                self.deinit();
                return e;
            };
            return self;
        }

        /// Initialize bytecode from initcode (EIP-3860)
        /// Validates that initcode size doesn't exceed the maximum allowed
        /// @deprecated Use bytecode4.zig instead
        pub fn initFromInitcode(allocator: std.mem.Allocator, initcode: []const u8) ValidationError!Self {
            if (initcode.len > cfg.max_initcode_size) {
                return error.InitcodeTooLarge;
            }
            var self = Self{
                .full_code = initcode,
                .runtime_code = initcode, // initcode has no Solidity metadata suffix
                .metadata = null,
                .allocator = allocator,
                .is_push_data = &.{},
                .is_op_start = &.{},
                .is_jumpdest = &.{},
                .packed_bitmap = &.{},
            };
            try self.buildBitmapsAndValidate();
            self.validateImmediateJumps() catch |e| {
                self.deinit();
                return e;
            };
            return self;
        }

        /// Calculate the gas cost for initcode (EIP-3860)
        /// Returns 2 gas per 32-byte word of initcode
        pub fn calculateInitcodeGas(initcode_len: usize) u64 {
            // Gas cost is 2 per 32-byte word, rounding up
            const words = (initcode_len + BYTES_PER_WORD - 1) / BYTES_PER_WORD;
            return words * INITCODE_GAS_PER_WORD;
        }

        /// @deprecated Use bytecode4.zig instead
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.is_push_data);
            self.allocator.free(self.is_op_start);
            self.allocator.free(self.is_jumpdest);
            self.allocator.free(self.packed_bitmap);
            self.* = undefined;
        }

        /// Create an iterator for efficient bytecode traversal
        /// @deprecated Use bytecode4.zig instead
        pub fn createIterator(self: *const Self) Iterator {
            return Iterator{
                .bytecode = self,
                .pc = 0,
            };
        }

        /// Get fusion data for a bytecode position marked as fusion candidate
        /// This method uses the pre-computed packed bitmap instead of re-analyzing
        /// @deprecated Use bytecode4.zig instead
        pub fn getFusionData(self: *const Self, pc: PcType) OpcodeData {
            if (pc >= self.len()) return OpcodeData{ .regular = .{ .opcode = 0x00 } }; // STOP fallback

            const first_op = self.get_unsafe(pc);
            const second_op = if (pc + 1 < self.len()) self.get_unsafe(pc + 1) else 0x00;

            // Read PUSH value first (since all fusions start with PUSH)
            if (first_op < 0x60 or first_op > 0x7F) {
                // Not a PUSH opcode, shouldn't be marked as fusion candidate
                return OpcodeData{ .regular = .{ .opcode = first_op } };
            }

            const push_size = first_op - 0x5F;
            var value: u256 = 0;
            const end_pc = @min(pc + 1 + push_size, self.len());
            for (pc + 1..end_pc) |i| {
                value = (value << 8) | self.get_unsafe(@intCast(i));
            }

            // Return appropriate fusion type based on second opcode
            switch (second_op) {
                0x01 => return OpcodeData{ .push_add_fusion = .{ .value = value } }, // ADD
                0x02 => return OpcodeData{ .push_mul_fusion = .{ .value = value } }, // MUL
                0x03 => return OpcodeData{ .push_sub_fusion = .{ .value = value } }, // SUB
                0x04 => return OpcodeData{ .push_div_fusion = .{ .value = value } }, // DIV
                0x16 => return OpcodeData{ .push_and_fusion = .{ .value = value } }, // AND
                0x17 => return OpcodeData{ .push_or_fusion = .{ .value = value } }, // OR
                0x18 => return OpcodeData{ .push_xor_fusion = .{ .value = value } }, // XOR
                0x56 => return OpcodeData{ .push_jump_fusion = .{ .value = value } }, // JUMP
                0x57 => return OpcodeData{ .push_jumpi_fusion = .{ .value = value } }, // JUMPI
                else => {
                    // Fallback to regular PUSH if fusion pattern not recognized
                    // TODO: Add more fusion types to OpcodeData union as needed
                    return OpcodeData{ .push = .{ .value = value, .size = push_size } };
                },
            }
        }

        /// Get the length of the bytecode
        pub inline fn len(self: Self) PcType {
            // Guaranteed by config that runtime_code.len fits in PcType
            std.debug.assert(self.runtime_code.len <= std.math.maxInt(PcType));
            return @intCast(self.runtime_code.len);
        }

        /// Get the raw bytecode slice
        pub inline fn raw(self: Self) []const u8 {
            return self.runtime_code;
        }

        /// Get bytecode without Solidity metadata
        /// Returns a slice excluding the metadata at the end, or the full bytecode if no metadata found
        pub fn rawWithoutMetadata(self: Self) []const u8 {
            // Since we already separated metadata during init, just return runtime_code
            return self.runtime_code;
        }

        /// Get byte at index
        pub inline fn get(self: Self, index: PcType) ?u8 {
            if (index >= self.runtime_code.len) return null;
            return self.runtime_code[index];
        }
        /// Get byte at index
        pub inline fn get_unsafe(self: Self, index: PcType) u8 {
            return self.runtime_code[index];
        }

        /// Get opcode at position (doesn't check if it's actually an opcode start)
        pub inline fn getOpcode(self: Self, pc: PcType) ?u8 {
            return self.get(pc);
        }
        /// Get opcode at position (doesn't check if it's actually an opcode start)
        pub inline fn getOpcodeUnsafe(self: Self, pc: PcType) u8 {
            return self.get_unsafe(pc);
        }

        /// Check if a position is a valid jump destination
        /// Uses precomputed bitmap for O(1) lookup
        /// @deprecated Use bytecode4.zig instead
        pub fn isValidJumpDest(self: Self, pc: PcType) bool {
            if (pc >= self.len()) return false;
            // https://ziglang.org/documentation/master/#as
            // @as performs type coercion, ensuring the value fits the target type
            return (self.is_jumpdest[pc >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(pc & BITMAP_MASK))) != 0;
        }

        /// Count the number of set bits in a byte range of a bitmap
        /// Uses hardware popcount instruction when available
        pub fn countBitsInRange(bitmap: []const u8, start_bit: usize, end_bit: usize) usize {
            if (start_bit >= end_bit) return 0;
            const start_byte = start_bit >> BITMAP_SHIFT;
            const end_byte_inclusive = (end_bit - 1) >> BITMAP_SHIFT;
            const start_offset: u3 = @intCast(start_bit & BITMAP_MASK);
            const end_offset: u3 = @intCast((end_bit - 1) & BITMAP_MASK);

            var count: usize = 0;
            if (start_byte >= bitmap.len) return 0;

            if (start_byte == end_byte_inclusive) {
                const mask = (@as(u8, 0xFF) << start_offset) & (@as(u8, 0xFF) >> (7 - end_offset));
                return @popCount(bitmap[start_byte] & mask);
            }

            // First partial byte
            count += @popCount(bitmap[start_byte] & (@as(u8, 0xFF) << start_offset));

            // Middle full bytes
            var i = start_byte + 1;
            while (i < end_byte_inclusive and i < bitmap.len) : (i += 1) {
                count += @popCount(bitmap[i]);
            }

            // Last partial byte
            if (i < bitmap.len) {
                const mask_last = @as(u8, 0xFF) >> (7 - end_offset);
                count += @popCount(bitmap[i] & mask_last);
            }

            return count;
        }

        /// Find the next set bit in a bitmap starting from a given position
        /// Uses hardware ctz (count trailing zeros) when available
        pub fn findNextSetBit(bitmap: []const u8, start_bit: usize) ?usize {
            const start_byte = start_bit >> BITMAP_SHIFT;
            if (start_byte >= bitmap.len) return null;

            // Check the starting byte (with offset)
            const start_offset = start_bit & BITMAP_MASK;
            const first_byte = bitmap[start_byte] & (@as(u8, 0xFF) << @as(u3, @intCast(start_offset)));
            if (first_byte != 0) {
                const bit_pos = @ctz(first_byte);
                return (start_byte << BITMAP_SHIFT) + bit_pos;
            }

            // Check subsequent bytes
            var i = start_byte + 1;
            while (i < bitmap.len) : (i += 1) {
                if (bitmap[i] != 0) {
                    const bit_pos = @ctz(bitmap[i]);
                    return (i << BITMAP_SHIFT) + bit_pos;
                }
            }

            return null;
        }

        /// Analyze bytecode and call callbacks for jump destinations
        /// This allows callers to build their own data structures
        pub fn analyzeJumpDests(
            self: Self,
            context: anytype,
            callback: fn (@TypeOf(context), pc: PcType) void,
        ) void {
            var i: PcType = 0;
            while (i < self.runtime_code.len) {
                @branchHint(.likely);
                const op = self.runtime_code[i];
                // https://ziglang.org/documentation/master/#intFromEnum
                // @intFromEnum converts an enum value to its integer representation
                if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                    const n = op - (@intFromEnum(Opcode.PUSH1) - 1);
                    i += 1 + n;
                } else {
                    if (op == @intFromEnum(Opcode.JUMPDEST)) {
                        callback(context, i);
                    }
                    i += 1;
                }
            }
        }

        // NOTE: Opcode validation occurs during bitmap construction via safe enum conversion.
        // A separate SIMD pre-pass was removed to avoid redundant and incomplete checks.

        // (removed unused setBitmapBitsSimd)

        // (removed SIMD fusion detection; scalar detection in getStats)

        /// Build bitmaps and validate bytecode
        fn buildBitmapsAndValidate(self: *Self) ValidationError!void {
            const N = self.runtime_code.len;
            // Empty bytecode is valid, allocate minimal bitmaps
            if (N == 0) {
                self.is_push_data = try self.allocator.alloc(u8, 1);
                self.is_op_start = try self.allocator.alloc(u8, 1);
                self.is_jumpdest = try self.allocator.alloc(u8, 1);
                self.is_push_data[0] = 0;
                self.is_op_start[0] = 0;
                self.is_jumpdest[0] = 0;
                // NEW: Also allocate packed bitmap for empty bytecode
                self.packed_bitmap = try self.allocator.alloc(PackedBits, 1);
                self.packed_bitmap[0] = PackedBits{ .is_push_data = false, .is_op_start = false, .is_jumpdest = false, .is_fusion_candidate = false };
                return;
            }

            // Phase A: validate opcodes and PUSH bounds without allocating
            var i: PcType = 0;
            while (i < N) {
                const op = self.runtime_code[i];
                // Validate opcode value
                _ = std.meta.intToEnum(Opcode, op) catch return error.InvalidOpcode;
                // If PUSH, ensure data fits
                if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                    const n: PcType = op - (@intFromEnum(Opcode.PUSH1) - 1);
                    if (i + n >= N) return error.TruncatedPush;
                    i += n + 1;
                } else {
                    i += 1;
                }
            }

            const bitmap_bytes = (N + BITMAP_MASK) >> BITMAP_SHIFT;

            // Phase B: allocate bitmaps and populate
            const use_aligned = comptime !builtin.is_test;
            if (use_aligned) {
                const aligned_bitmap_bytes = (bitmap_bytes + CACHE_LINE_SIZE - 1) & ~@as(usize, CACHE_LINE_SIZE - 1);
                self.is_push_data = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_push_data);
                self.is_op_start = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_op_start);
                self.is_jumpdest = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_jumpdest);
            } else {
                self.is_push_data = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_push_data);
                self.is_op_start = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_op_start);
                self.is_jumpdest = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                errdefer self.allocator.free(self.is_jumpdest);
            }
            @memset(self.is_push_data, 0);
            @memset(self.is_op_start, 0);
            @memset(self.is_jumpdest, 0);

            // NEW: Allocate packed bitmap (4 bits per byte, so N packed bits)
            self.packed_bitmap = self.allocator.alloc(PackedBits, N) catch return error.OutOfMemory;
            errdefer self.allocator.free(self.packed_bitmap);
            // Initialize all packed bits to false
            for (self.packed_bitmap) |*packed_bits| {
                packed_bits.* = PackedBits{ .is_push_data = false, .is_op_start = false, .is_jumpdest = false, .is_fusion_candidate = false };
            }

            i = 0;
            while (i < N) {
                @branchHint(.likely);

                // Prefetch ahead for better cache performance on large bytecode
                if (@as(usize, i) + PREFETCH_DISTANCE < N) {
                    @prefetch(&self.runtime_code[@as(usize, i) + PREFETCH_DISTANCE], .{
                        .rw = .read,
                        .locality = 3, // Low temporal locality
                        .cache = .data,
                    });
                }

                self.is_op_start[i >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(i & BITMAP_MASK);
                // NEW: Also set packed bitmap
                self.packed_bitmap[i].is_op_start = true;
                const op = self.runtime_code[i];

                // Opcodes are validated above; now mark bitmaps
                const opcode_enum = @as(Opcode, @enumFromInt(op));
                // Check if it's a PUSH opcode
                if (@intFromEnum(opcode_enum) >= @intFromEnum(Opcode.PUSH1) and
                    @intFromEnum(opcode_enum) <= @intFromEnum(Opcode.PUSH32))
                {
                    const n: PcType = op - (@intFromEnum(Opcode.PUSH1) - 1);
                    if (i + n >= N) return error.TruncatedPush;
                    var j: PcType = 0;
                    while (j < n) : (j += 1) {
                        const idx = i + 1 + j;
                        self.is_push_data[idx >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(idx & BITMAP_MASK);
                        // NEW: Also set packed bitmap
                        self.packed_bitmap[idx].is_push_data = true;
                    }
                    i += n + 1;
                } else {
                    i += 1;
                }
            }
            if (comptime cfg.vector_length > 0) {
                self.markJumpdestSimd(cfg.vector_length);
            } else {
                self.markJumpdestScalar();
            }
            if (comptime fusions_enabled) self.markFusionCandidates();
        }

        /// Validate immediate JUMP/JUMPI targets encoded via preceding PUSH
        fn validateImmediateJumps(self: *Self) ValidationError!void {
            var i: PcType = 0;
            const N = self.runtime_code.len;
            while (i < N) {
                if ((self.is_op_start[i >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(i & BITMAP_MASK))) == 0) {
                    i += 1;
                    continue;
                }
                const op = self.runtime_code[i];
                if (op == @intFromEnum(Opcode.JUMP) and i > 0) {
                    // Validate immediate JUMP target (single preceding PUSH)
                    const dest = self.readImmediateJumpTarget(i) orelse null;
                    if (dest) |target_pc| {
                        if (target_pc >= self.len()) return error.InvalidJumpDestination;
                        if ((self.is_jumpdest[target_pc >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(target_pc & BITMAP_MASK))) == 0) {
                            return error.InvalidJumpDestination;
                        }
                    }
                } else if (op == @intFromEnum(Opcode.JUMPI) and i > 0) {
                    // Validate JUMPI only when it is PUSH(dest) + PUSH(cond) + JUMPI
                    const dest = self.readImmediateJumpiTarget(i) orelse null;
                    if (dest) |target_pc| {
                        if (target_pc >= self.len()) return error.InvalidJumpDestination;
                        if ((self.is_jumpdest[target_pc >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(target_pc & BITMAP_MASK))) == 0) {
                            return error.InvalidJumpDestination;
                        }
                    }
                }
                i += self.getInstructionSize(i);
            }
        }

        fn readImmediateJumpTarget(self: *Self, i: PcType) ?PcType {
            var j: PcType = 0;
            while (j < i) {
                if ((self.is_op_start[j >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(j & BITMAP_MASK))) != 0) {
                    const prev_op = self.runtime_code[j];
                    if (prev_op >= @intFromEnum(Opcode.PUSH1) and prev_op <= @intFromEnum(Opcode.PUSH32)) {
                        const size = self.getInstructionSize(j);
                        if (j + size == i) {
                            const n = prev_op - (@intFromEnum(Opcode.PUSH1) - 1);
                            const target = self.readPushValueN(j, @intCast(n)) orelse return null;
                            return @as(PcType, @intCast(target));
                        }
                    }
                }
                j += 1;
            }
            return null;
        }

        fn readImmediateJumpiTarget(self: *Self, i: PcType) ?PcType {
            // Expect pattern: PUSH(dest) PUSH(cond) JUMPI
            const second_push_end = i;
            // Find the second push
            var j: PcType = 0;
            var second_push_start: ?PcType = null;
            while (j < i) : (j += 1) {
                if ((self.is_op_start[j >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(j & BITMAP_MASK))) != 0) {
                    const op = self.runtime_code[j];
                    if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                        if (j + self.getInstructionSize(j) == second_push_end) {
                            second_push_start = j;
                            break;
                        }
                    }
                }
            }
            if (second_push_start == null) return null;
            const second_start = second_push_start.?;
            // Now check the first push immediately before the second
            var k: PcType = 0;
            var first_push_start: ?PcType = null;
            while (k < second_start) : (k += 1) {
                if ((self.is_op_start[k >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(k & BITMAP_MASK))) != 0) {
                    const op = self.runtime_code[k];
                    if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                        if (k + self.getInstructionSize(k) == second_start) {
                            first_push_start = k;
                            break;
                        }
                    }
                }
            }
            if (first_push_start == null) return null;
            const op = self.runtime_code[first_push_start.?];
            const n = op - (@intFromEnum(Opcode.PUSH1) - 1);
            const target = self.readPushValueN(first_push_start.?, @intCast(n)) orelse return null;
            return @as(PcType, @intCast(target));
        }

        /// Read a PUSH value at the given PC
        /// Based on plan_minimal.zig's getMetadata implementation
        // https://ziglang.org/documentation/master/std/#std.meta.Int
        pub fn readPushValue(self: Self, pc: PcType, comptime n: u8) ?std.meta.Int(.unsigned, n * 8) {
            if (pc >= self.runtime_code.len) return null;
            const op = self.runtime_code[pc];
            if (op != @intFromEnum(Opcode.PUSH1) + n - 1) return null; // Not the right PUSH opcode
            const start = pc + 1;
            if (start + n > self.runtime_code.len) return null; // Not enough bytes
            // https://ziglang.org/documentation/master/std/#std.meta.Int
            // Creates an unsigned integer type with n*8 bits (e.g., n=1 -> u8, n=2 -> u16)
            const T = std.meta.Int(.unsigned, n * BITS_PER_BYTE);
            var value: T = 0;
            var i: u8 = 0;
            // https://ziglang.org/documentation/master/std/#std.math.shl
            while (i < n) : (i += 1) value = std.math.shl(T, value, BITS_PER_BYTE) | @as(T, self.runtime_code[start + i]);
            return value;
        }

        /// Read a variable-sized PUSH value (returns u256)
        pub fn readPushValueN(self: Self, pc: PcType, n: u8) ?u256 {
            if (pc >= self.runtime_code.len or n == 0 or n > MAX_PUSH_BYTES) return null;
            const op = self.runtime_code[pc];
            if (op < @intFromEnum(Opcode.PUSH1) or op > @intFromEnum(Opcode.PUSH32)) return null;
            const expected_n = op - (@intFromEnum(Opcode.PUSH1) - 1);
            if (expected_n != n) return null;
            const start = pc + 1;
            const available = @min(n, self.runtime_code.len -| start);
            var value: u256 = 0;
            for (0..n) |i| value = if (i < available) (value << BITS_PER_BYTE) | self.runtime_code[start + i] else value << BITS_PER_BYTE;
            return value;
        }

        /// Get the size of bytecode at PC (1 for most opcodes, 1+n for PUSH)
        pub fn getInstructionSize(self: Self, pc: PcType) PcType {
            if (pc >= self.runtime_code.len) return 0;
            const op = self.runtime_code[pc];
            if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) return 1 + (op - (@intFromEnum(Opcode.PUSH1) - 1));
            return 1;
        }

        /// Get the next PC after the instruction at the given PC
        pub fn getNextPc(self: Self, pc: PcType) ?PcType {
            const size = self.getInstructionSize(pc);
            if (size == 0) return null;
            const next = pc + size;
            if (next > self.runtime_code.len) return null;
            return next;
        }

        /// Metadata information extracted from Solidity compiler metadata
        pub const SolidityMetadata = struct {
            // 34-byte IPFS multihash (0x12 0x20 prefix + 32-byte digest)
            ipfs_hash: [34]u8,
            solc_version: [3]u8, // major, minor, patch
            metadata_length: usize,
        };

        /// Parse Solidity metadata from raw bytecode bytes (static function)
        fn parseSolidityMetadataFromBytes(code: []const u8) ?SolidityMetadata {
            // Minimum metadata size: 2 (length) + 4 (ipfs) + 32 (hash) + 4 (solc) + 3 (version) = 45 bytes
            if (code.len < 45) return null;

            // Get the last 2 bytes which encode the metadata length
            const len_offset = code.len - 2;
            const metadata_len = (@as(u16, code[len_offset]) << 8) | code[len_offset + 1];

            // Verify metadata length is reasonable
            if (metadata_len < 43 or metadata_len > code.len) return null;

            // Calculate where metadata starts
            const metadata_start = code.len - 2 - metadata_len;
            const metadata = code[metadata_start .. code.len - 2];

            // Parse CBOR-encoded metadata
            var pos: usize = 0;

            // Check CBOR map header (0xa2 = map with 2 items)
            if (pos >= metadata.len or metadata[pos] != 0xa2) return null;
            pos += 1;

            // First entry should be "ipfs"
            if (pos + 5 >= metadata.len) return null;
            if (metadata[pos] != 0x64) return null; // 4-byte string
            pos += 1;

            if (!std.mem.eql(u8, metadata[pos .. pos + 4], "ipfs")) return null;
            pos += 4;

            // IPFS hash (0x58 = byte string, 0x22 = 34 bytes following)
            if (pos + 2 >= metadata.len) return null;
            if (metadata[pos] != 0x58 or metadata[pos + 1] != 0x22) return null;
            pos += 2;

            if (pos + 34 > metadata.len) return null;
            var ipfs_hash: [34]u8 = undefined;
            @memcpy(&ipfs_hash, metadata[pos .. pos + 34]);
            pos += 34;

            // Second entry should be "solc"
            if (pos + 5 >= metadata.len) return null;
            if (metadata[pos] != 0x64) return null; // 4-byte string
            pos += 1;

            if (!std.mem.eql(u8, metadata[pos .. pos + 4], "solc")) return null;
            pos += 4;

            // Solc version (3 bytes: major, minor, patch)
            if (pos + 3 > metadata.len) return null;
            const major = metadata[pos];
            const minor = metadata[pos + 1];
            const patch = metadata[pos + 2];

            return SolidityMetadata{
                .ipfs_hash = ipfs_hash,
                .solc_version = .{ major, minor, patch },
                .metadata_length = metadata_len + 2, // Include the length bytes
            };
        }

        /// Get the parsed Solidity metadata if it exists
        pub fn getSolidityMetadata(self: Self) ?SolidityMetadata {
            return self.metadata;
        }

        /// Parse Solidity metadata from the end of bytecode (for backwards compatibility)
        /// Returns null if no valid metadata is found
        pub fn parseSolidityMetadata(self: Self) ?SolidityMetadata {
            return parseSolidityMetadataFromBytes(self.full_code);
        }

        /// Simple bytecode analysis for Schedule generation
        /// This replaces complex planner logic with straightforward analysis
        pub const Analysis = struct {
            jump_destinations: std.ArrayList(JumpDestInfo),
            push_data: std.ArrayList(PushInfo),

            pub fn deinit(self: *@This()) void {
                self.jump_destinations.deinit();
                self.push_data.deinit();
            }
        };

        pub const JumpDestInfo = struct {
            pc: PcType,
            gas_cost: u32 = 1, // Static gas cost for JUMPDEST
        };

        pub const PushInfo = struct {
            pc: PcType,
            size: u8, // 1-32 bytes
            value: u256, // The actual pushed value
            is_inline: bool, // true if <= 8 bytes (can inline)
        };

        /// Analyze bytecode to extract information needed for Schedule generation
        /// This moves the complex analysis logic from planner.zig here
        pub fn analyze(self: Self, allocator: std.mem.Allocator) !Analysis {
            var analysis = Analysis{
                .jump_destinations = std.ArrayList(JumpDestInfo).init(allocator),
                .push_data = std.ArrayList(PushInfo).init(allocator),
            };
            errdefer analysis.deinit();

            var pc: PcType = 0;
            while (pc < self.runtime_code.len) {
                // Skip if not an opcode start
                if ((self.is_op_start[pc >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(pc & BITMAP_MASK))) == 0) {
                    pc += 1;
                    continue;
                }

                const opcode_byte = self.runtime_code[pc];
                const opcode = std.meta.intToEnum(Opcode, opcode_byte) catch {
                    pc += 1;
                    continue;
                };

                switch (opcode) {
                    .JUMPDEST => {
                        try analysis.jump_destinations.append(.{
                            .pc = pc,
                            .gas_cost = 1,
                        });
                        pc += 1;
                    },
                    .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8, .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16, .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24, .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => {
                        const push_size = @intFromEnum(opcode) - @intFromEnum(Opcode.PUSH1) + 1;

                        // Extract the push value
                        var value: u256 = 0;
                        const data_start = pc + 1;
                        const data_end = @min(data_start + push_size, @as(PcType, @intCast(self.runtime_code.len)));

                        for (data_start..data_end) |byte_pc| {
                            if (byte_pc < self.runtime_code.len) {
                                value = (value << 8) | self.runtime_code[byte_pc];
                            }
                        }

                        try analysis.push_data.append(.{
                            .pc = pc,
                            .size = push_size,
                            .value = value,
                            .is_inline = push_size <= 8,
                        });

                        pc += 1 + push_size;
                    },
                    else => {
                        pc += 1;
                    },
                }
            }

            return analysis;
        }

        /// Get statistics about the bytecode
        pub fn getStats(self: Self) !Stats {
            var stats = Stats{
                .opcode_counts = [_]u32{0} ** OPCODE_TABLE_SIZE,
                .push_values = &.{},
                .potential_fusions = &.{},
                .jumpdests = &.{},
                .jumps = &.{},
                .backwards_jumps = 0,
                .is_create_code = false,
            };
            // https://ziglang.org/documentation/master/std/#std.array_list.Aligned
            var push_values = std.ArrayList(Stats.PushValue){};
            defer push_values.deinit(self.allocator);
            // Fusion detection: use scalar approach (simple and robust)

            // https://ziglang.org/documentation/master/std/#std.array_list.Aligned
            var fusions = std.ArrayList(Stats.Fusion){};
            defer fusions.deinit(self.allocator);
            // https://ziglang.org/documentation/master/std/#std.array_list.Aligned
            var jumpdests = std.ArrayList(PcType){};
            defer jumpdests.deinit(self.allocator);
            // https://ziglang.org/documentation/master/std/#std.array_list.Aligned
            var jumps = std.ArrayList(Stats.Jump){};
            defer jumps.deinit(self.allocator);
            var i: PcType = 0;
            while (i < self.runtime_code.len) {
                // Prefetch ahead for stats collection
                if (@as(usize, i) + PREFETCH_DISTANCE < self.runtime_code.len) {
                    @prefetch(&self.runtime_code[@as(usize, i) + PREFETCH_DISTANCE], .{
                        .rw = .read,
                        .locality = 3,
                        .cache = .data,
                    });
                }

                if ((self.is_op_start[i >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(i & BITMAP_MASK))) == 0) {
                    i += 1;
                    continue;
                }
                const op = self.runtime_code[i];
                stats.opcode_counts[op] += 1;
                if (op == @intFromEnum(Opcode.JUMPDEST)) try jumpdests.append(self.allocator, i);
                if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                    const n = op - (@intFromEnum(Opcode.PUSH1) - 1);
                    if (self.readPushValueN(i, @intCast(n))) |value| {
                        try push_values.append(self.allocator, .{ .pc = i, .value = value });
                        const next_pc = i + 1 + n;

                        // Detect simple PUSH+OP fusion opportunities
                        if (next_pc < self.runtime_code.len) {
                            const next_op = self.runtime_code[next_pc];
                            if (next_op == @intFromEnum(Opcode.JUMP) or
                                next_op == @intFromEnum(Opcode.JUMPI) or
                                next_op == @intFromEnum(Opcode.ADD) or
                                next_op == @intFromEnum(Opcode.MUL) or
                                next_op == @intFromEnum(Opcode.SUB) or
                                next_op == @intFromEnum(Opcode.DIV))
                            {
                                try fusions.append(self.allocator, .{ .pc = i, .second_opcode = @as(Opcode, @enumFromInt(next_op)) });
                            }
                        }
                        if (next_pc < self.runtime_code.len and
                            (self.runtime_code[next_pc] == @intFromEnum(Opcode.JUMP) or
                                self.runtime_code[next_pc] == @intFromEnum(Opcode.JUMPI)))
                        {
                            try jumps.append(self.allocator, .{ .pc = next_pc, .target = value });
                            if (value < i) {
                                stats.backwards_jumps += 1;
                            }
                        }
                    }
                }
                if (op == @intFromEnum(Opcode.CODECOPY)) {
                    stats.is_create_code = true;
                }
                i += self.getInstructionSize(i);
            }

            stats.push_values = try self.allocator.dupe(Stats.PushValue, push_values.items);

            // Use scalar-detected fusions
            stats.potential_fusions = try self.allocator.dupe(Stats.Fusion, fusions.items);
            const jumpdests_usize = try self.allocator.alloc(usize, jumpdests.items.len);
            for (jumpdests.items, 0..) |pc, idx| {
                jumpdests_usize[idx] = @intCast(pc);
            }
            stats.jumpdests = jumpdests_usize;
            stats.jumps = try self.allocator.dupe(Stats.Jump, jumps.items);
            return stats;
        }

        /// Linear scan: set jumpdest bit at i when bytecode[i]==0x5b and the push-data bit is not set.
        fn markJumpdestScalar(self: Self) void {
            var i: usize = 0;
            while (i < self.len()) : (i += 1) {
                // Prefetch for sequential access
                if (@as(usize, i) + PREFETCH_DISTANCE < self.len()) {
                    @prefetch(&self.runtime_code[@as(usize, i) + PREFETCH_DISTANCE], .{
                        .rw = .read,
                        .locality = 3,
                        .cache = .data,
                    });
                }

                const test_push = (self.is_push_data[i >> BITMAP_SHIFT] & (@as(u8, 1) << @intCast(i & BITMAP_MASK))) != 0;
                if (self.runtime_code[i] == @intFromEnum(Opcode.JUMPDEST) and !test_push) {
                    self.is_jumpdest[i >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(i & BITMAP_MASK);
                    // NEW: Also set packed bitmap
                    self.packed_bitmap[i].is_jumpdest = true;
                }
            }
        }

        /// SIMD-accelerated jump destination marking with prefetching optimization
        ///
        /// Combines vector processing with cache prefetching for optimal performance on large bytecode.
        /// Prefetching hides memory latency by loading future data while processing current chunks.
        fn markJumpdestSimd(self: Self, comptime L: comptime_int) void {
            // Skip SIMD on WASM targets that don't support it
            if (comptime (builtin.target.cpu.arch == .wasm32 and !builtin.target.cpu.features.isEnabled(.simd128))) {
                // Fall back to scalar implementation for WASM without SIMD
                return self.markJumpdestScalar();
            }
            var i: usize = 0;
            const code_len = self.runtime_code.len;

            // Vector containing L copies of JUMPDEST opcode for parallel comparison
            const splat_5b: @Vector(L, u8) = @splat(@as(u8, @intFromEnum(Opcode.JUMPDEST)));

            // Process bytecode in L-byte chunks with prefetching
            while (i + L <= code_len) : (i += L) {
                // Prefetch future data to hide memory latency
                if (@as(usize, i + L) + PREFETCH_DISTANCE < code_len) {
                    // Prefetch next bytecode chunk for future iterations
                    @prefetch(&self.runtime_code[@as(usize, i + L) + PREFETCH_DISTANCE], .{
                        .rw = .read,
                        .locality = 3,
                        .cache = .data,
                    });

                    // Prefetch corresponding push_data bitmap entries
                    @prefetch(&self.is_push_data[(@as(usize, i + L) + PREFETCH_DISTANCE) >> BITMAP_SHIFT], .{
                        .rw = .read,
                        .locality = 3,
                        .cache = .data,
                    });
                }

                // Load L consecutive bytes into vector for parallel processing
                var arr: [L]u8 = undefined;
                inline for (0..L) |k| arr[k] = self.runtime_code[i + k];
                const v: @Vector(L, u8) = arr;

                // Compare all L bytes against JUMPDEST simultaneously
                const eq: @Vector(L, bool) = v == splat_5b;
                const eq_arr: [L]bool = eq;

                // Process comparison results and update jump destination bitmap
                inline for (0..L) |j| {
                    const idx = i + j;
                    const byte_idx = idx >> BITMAP_SHIFT;
                    const bit_mask = @as(u8, 1) << @intCast(idx & BITMAP_MASK);

                    // Check if it's a JUMPDEST and not push data
                    if (eq_arr[j]) {
                        const test_push = (self.is_push_data[byte_idx] & bit_mask) != 0;
                        if (!test_push) {
                            self.is_jumpdest[byte_idx] |= bit_mask;
                            // NEW: Also set packed bitmap - idx is the actual byte position in bytecode
                            self.packed_bitmap[idx].is_jumpdest = true;
                        }
                    }
                }
            }

            // Handle remaining bytes
            var t: usize = i;
            while (t < code_len) : (t += 1) {
                const byte_idx = t >> BITMAP_SHIFT;
                const bit_mask = @as(u8, 1) << @intCast(t & BITMAP_MASK);
                const test_push = (self.is_push_data[byte_idx] & bit_mask) != 0;
                if (self.runtime_code[t] == @intFromEnum(Opcode.JUMPDEST) and !test_push) {
                    self.is_jumpdest[byte_idx] |= bit_mask;
                    // NEW: Also set packed bitmap
                    self.packed_bitmap[t].is_jumpdest = true;
                }
            }
        }

        /// Detect fusion candidates (PUSH+ADD, PUSH+MUL patterns) for opcode optimization
        /// Marks patterns that can be fused into synthetic opcodes for better performance
        fn markFusionCandidates(self: Self) void {
            var i: PcType = 0;
            const code_len = self.len();

            while (i + 1 < code_len) {
                // Only check actual operation starts, not push data
                if (!self.packed_bitmap[i].is_op_start or self.packed_bitmap[i].is_push_data) {
                    i += 1;
                    continue;
                }

                const op1 = self.runtime_code[i];

                // Check for PUSH opcode
                if (op1 >= @intFromEnum(Opcode.PUSH1) and op1 <= @intFromEnum(Opcode.PUSH32)) {
                    const push_size: PcType = op1 - (@intFromEnum(Opcode.PUSH1) - 1);
                    const next_op_idx = i + 1 + push_size;

                    // Ensure the next instruction is within bounds and is an operation start
                    if (next_op_idx < code_len and
                        self.packed_bitmap[next_op_idx].is_op_start and
                        !self.packed_bitmap[next_op_idx].is_push_data)
                    {
                        const op2 = self.runtime_code[next_op_idx];

                        // Check for fusable patterns:
                        // PUSH + ADD, PUSH + MUL, PUSH + SUB, PUSH + DIV
                        // PUSH + AND, PUSH + OR, PUSH + XOR
                        // PUSH + JUMP, PUSH + JUMPI
                        const is_fusable = switch (op2) {
                            @intFromEnum(Opcode.ADD), @intFromEnum(Opcode.MUL), @intFromEnum(Opcode.SUB), @intFromEnum(Opcode.DIV), @intFromEnum(Opcode.AND), @intFromEnum(Opcode.OR), @intFromEnum(Opcode.XOR), @intFromEnum(Opcode.JUMP), @intFromEnum(Opcode.JUMPI) => true,
                            else => false,
                        };

                        if (is_fusable) {
                            // Mark the PUSH as a fusion candidate
                            self.packed_bitmap[i].is_fusion_candidate = true;
                        }
                    }
                }

                i += self.getInstructionSize(i);
            }
        }
    };
}

const default_config = BytecodeConfig{};
pub const BytecodeDefault = Bytecode(default_config);
pub const BytecodeValidationError = BytecodeDefault.ValidationError;

// Export the factory function for creating Bytecode types
pub const createBytecode = Bytecode;

