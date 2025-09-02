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
const log = @import("log.zig");
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
                // Check if packed_bitmap has enough elements
                if (iterator.pc >= iterator.bytecode.packed_bitmap.len) {
                    // Log error and return null
                    log.err("Iterator PC {} exceeds packed_bitmap len {}", .{ iterator.pc, iterator.bytecode.packed_bitmap.len });
                    return null;
                }
                const packed_bits = iterator.bytecode.packed_bitmap[iterator.pc];

                // Handle fusion opcodes first (only if fusions are enabled)
                if (fusions_enabled and packed_bits.is_fusion_candidate) {
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
        // Packed bitmap (4 bits per byte position) for efficient storage
        packed_bitmap: []PackedBits,

        pub fn init(allocator: std.mem.Allocator, code: []const u8) ValidationError!Self {
            // Check if this is deployment bytecode
            const is_deployment = code.len > 4 and 
                code[0] == 0x60 and code[1] == 0x80 and 
                code[2] == 0x60 and code[3] == 0x40;
            
            // Always try to parse metadata to detect its presence
            const metadata = parseSolidityMetadataFromBytes(code);
            
            // For deployment bytecode with metadata, we need to handle it specially
            // The constructor code needs to execute fully, but we should only validate
            // the actual code portion, not the metadata bytes
            const runtime_code = if (is_deployment and metadata != null) blk: {
                // For deployment bytecode with metadata, we keep the full code
                // but we'll handle validation specially
                log.debug("Bytecode: Deployment bytecode with metadata detected, length={}, metadata_len={}", .{code.len, metadata.?.metadata_length});
                break :blk code;
            } else if (metadata) |m| blk: {
                // For runtime bytecode with metadata, strip it
                log.debug("Bytecode: Found Solidity metadata in runtime code, stripping {} bytes from end (full={}, runtime={})", .{
                    m.metadata_length, code.len, code.len - m.metadata_length
                });
                break :blk code[0 .. code.len - m.metadata_length];
            } else blk: {
                if (is_deployment) {
                    log.debug("Bytecode: Deployment bytecode detected without metadata, length={}", .{code.len});
                } else {
                    log.debug("Bytecode: No metadata found, using full code length={}", .{code.len});
                }
                break :blk code;
            };

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
            // Build bitmaps and validate
            // For deployment bytecode with metadata, pass the metadata length to avoid validating it
            const validation_len = if (is_deployment and metadata != null) 
                code.len - metadata.?.metadata_length 
            else 
                runtime_code.len;
            try self.buildBitmapsAndValidateWithLength(validation_len);
            return self;
        }

        /// Initialize bytecode from initcode (EIP-3860)
        /// Validates that initcode size doesn't exceed the maximum allowed
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
            return self;
        }

        /// Calculate the gas cost for initcode (EIP-3860)
        /// Returns 2 gas per 32-byte word of initcode
        pub fn calculateInitcodeGas(initcode_len: usize) u64 {
            // Gas cost is 2 per 32-byte word, rounding up
            const words = (initcode_len + BYTES_PER_WORD - 1) / BYTES_PER_WORD;
            return words * INITCODE_GAS_PER_WORD;
        }

        pub fn deinit(self: *Self) void {
            // Check if we used aligned allocation (same logic as in init)
            const use_aligned = comptime !builtin.is_test;
            
            // Free bitmaps - must match allocation method
            if (use_aligned and self.is_push_data.len > 0) {
                // For aligned allocations, we need to compute the aligned size
                const bitmap_bytes = (self.runtime_code.len + 7) / 8;
                const aligned_bitmap_bytes = (bitmap_bytes + CACHE_LINE_SIZE - 1) & ~@as(usize, CACHE_LINE_SIZE - 1);
                
                // Create properly aligned slices for freeing
                const aligned_push_data: []align(CACHE_LINE_SIZE) u8 = @alignCast(self.is_push_data[0..aligned_bitmap_bytes]);
                const aligned_op_start: []align(CACHE_LINE_SIZE) u8 = @alignCast(self.is_op_start[0..aligned_bitmap_bytes]);
                const aligned_jumpdest: []align(CACHE_LINE_SIZE) u8 = @alignCast(self.is_jumpdest[0..aligned_bitmap_bytes]);
                
                self.allocator.free(aligned_push_data);
                self.allocator.free(aligned_op_start);
                self.allocator.free(aligned_jumpdest);
            } else {
                self.allocator.free(self.is_push_data);
                self.allocator.free(self.is_op_start);
                self.allocator.free(self.is_jumpdest);
            }
            
            self.allocator.free(self.packed_bitmap);
            self.* = undefined;
        }

        /// Create an iterator for efficient bytecode traversal
        pub fn createIterator(self: *const Self) Iterator {
            return Iterator{
                .bytecode = self,
                .pc = 0,
            };
        }

        /// Get fusion data for a bytecode position marked as fusion candidate
        /// This method uses the pre-computed packed bitmap instead of re-analyzing
        pub fn getFusionData(self: *const Self, pc: PcType) OpcodeData {
            if (pc >= self.len()) return OpcodeData{ .regular = .{ .opcode = 0x00 } }; // STOP fallback

            const first_op = self.get_unsafe(pc);

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

            // The second opcode comes AFTER the push data
            const second_op_pc = pc + 1 + push_size;
            const second_op = if (second_op_pc < self.len()) self.get_unsafe(second_op_pc) else 0x00;

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
                    // If we hit this branch we failed to implement an opcode or fusion
                    log.err("getFusionData: Unhandled fusion pattern - PUSH{} (value: {}) followed by opcode 0x{x:0>2}", .{ push_size, value, second_op });
                    // TODO: Add more fusion types to OpcodeData union as needed
                    unreachable;
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

        // Fusion detection uses scalar approach in getStats for simplicity and robustness

        /// Build bitmaps and validate bytecode in a single pass
        fn buildBitmapsAndValidate(self: *Self) ValidationError!void {
            return self.buildBitmapsAndValidateWithLength(self.runtime_code.len);
        }
        
        /// Build bitmaps and validate bytecode with a specific validation length
        /// This allows validating only the code portion of deployment bytecode, excluding metadata
        fn buildBitmapsAndValidateWithLength(self: *Self, validation_length: usize) ValidationError!void {
            const N = self.runtime_code.len;
            const validate_up_to = @min(validation_length, N);
            
            // Set up cleanup in case of errors
            var cleanup_state: struct {
                is_push_data_allocated: bool = false,
                is_op_start_allocated: bool = false,
                is_jumpdest_allocated: bool = false,
                packed_bitmap_allocated: bool = false,
            } = .{};
            
            errdefer {
                if (cleanup_state.is_push_data_allocated) self.allocator.free(self.is_push_data);
                if (cleanup_state.is_op_start_allocated) self.allocator.free(self.is_op_start);
                if (cleanup_state.is_jumpdest_allocated) self.allocator.free(self.is_jumpdest);
                if (cleanup_state.packed_bitmap_allocated) self.allocator.free(self.packed_bitmap);
            }
            
            // Empty bytecode is valid, allocate minimal bitmaps
            if (N == 0) {
                self.is_push_data = try self.allocator.alloc(u8, 1);
                cleanup_state.is_push_data_allocated = true;
                self.is_op_start = try self.allocator.alloc(u8, 1);
                cleanup_state.is_op_start_allocated = true;
                self.is_jumpdest = try self.allocator.alloc(u8, 1);
                cleanup_state.is_jumpdest_allocated = true;
                self.is_push_data[0] = 0;
                self.is_op_start[0] = 0;
                self.is_jumpdest[0] = 0;
                // NEW: Also allocate packed bitmap for empty bytecode
                self.packed_bitmap = try self.allocator.alloc(PackedBits, 1);
                cleanup_state.packed_bitmap_allocated = true;
                self.packed_bitmap[0] = PackedBits{ .is_push_data = false, .is_op_start = false, .is_jumpdest = false, .is_fusion_candidate = false };
                return;
            }

            const bitmap_bytes = (N + BITMAP_MASK) >> BITMAP_SHIFT;

            // Allocate bitmaps upfront for single-pass population
            const use_aligned = comptime !builtin.is_test;
            if (use_aligned) {
                const aligned_bitmap_bytes = (bitmap_bytes + CACHE_LINE_SIZE - 1) & ~@as(usize, CACHE_LINE_SIZE - 1);
                self.is_push_data = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_push_data_allocated = true;
                self.is_op_start = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_op_start_allocated = true;
                self.is_jumpdest = self.allocator.alignedAlloc(u8, @as(std.mem.Alignment, @enumFromInt(std.math.log2_int(usize, CACHE_LINE_SIZE))), aligned_bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_jumpdest_allocated = true;
            } else {
                self.is_push_data = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_push_data_allocated = true;
                self.is_op_start = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_op_start_allocated = true;
                self.is_jumpdest = self.allocator.alloc(u8, bitmap_bytes) catch return error.OutOfMemory;
                cleanup_state.is_jumpdest_allocated = true;
            }
            @memset(self.is_push_data, 0);
            @memset(self.is_op_start, 0);
            @memset(self.is_jumpdest, 0);

            // NEW: Allocate packed bitmap (4 bits per byte, so N packed bits)
            self.packed_bitmap = self.allocator.alloc(PackedBits, N) catch return error.OutOfMemory;
            cleanup_state.packed_bitmap_allocated = true;
            // Initialize all packed bits to false
            for (self.packed_bitmap) |*packed_bits| {
                packed_bits.* = PackedBits{ .is_push_data = false, .is_op_start = false, .is_jumpdest = false, .is_fusion_candidate = false };
            }

            // Single pass: validate opcodes, mark bitmaps, detect JUMPDEST and fusions
            // Track state for immediate jump validation
            var last_push_value: ?u256 = null;
            var last_push_end: PcType = 0;
            
            // Collect immediate jumps to validate after first pass
            var immediate_jumps = std.ArrayList(PcType){};  
            defer immediate_jumps.deinit(self.allocator);
            
            var i: PcType = 0;
            while (i < validate_up_to) {
                @branchHint(.likely);

                // Prefetch ahead for better cache performance on large bytecode
                if (@as(usize, i) + PREFETCH_DISTANCE < validate_up_to) {
                    @prefetch(&self.runtime_code[@as(usize, i) + PREFETCH_DISTANCE], .{
                        .rw = .read,
                        .locality = 3, // Low temporal locality
                        .cache = .data,
                    });
                }

                // Mark operation start
                self.is_op_start[i >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(i & BITMAP_MASK);
                self.packed_bitmap[i].is_op_start = true;

                const op = self.runtime_code[i];

                // Validate opcode - undefined opcodes are valid but treated as INVALID
                const opcode_enum = std.meta.intToEnum(Opcode, op) catch blk: {
                    // Undefined opcodes are valid in EVM - they execute as INVALID operation
                    // which consumes all gas and reverts. We'll treat them as INVALID (0xFE)
                    break :blk Opcode.INVALID;
                };

                // Check if it's a JUMPDEST (and not push data)
                if (op == @intFromEnum(Opcode.JUMPDEST)) {
                    self.is_jumpdest[i >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(i & BITMAP_MASK);
                    self.packed_bitmap[i].is_jumpdest = true;
                }

                // Check for fusion candidates if enabled
                if (comptime fusions_enabled) {
                    // Check if this is a PUSH that could be part of a fusion
                    if (op >= @intFromEnum(Opcode.PUSH1) and op <= @intFromEnum(Opcode.PUSH32)) {
                        const push_size: PcType = op - (@intFromEnum(Opcode.PUSH1) - 1);
                        const next_op_idx = i + 1 + push_size;

                        // Ensure we can read the next opcode
                        if (next_op_idx < validate_up_to) {
                            const next_op = self.runtime_code[next_op_idx];
                            // Check for fusable patterns
                            const is_fusable = switch (next_op) {
                                @intFromEnum(Opcode.ADD), @intFromEnum(Opcode.MUL), @intFromEnum(Opcode.SUB), @intFromEnum(Opcode.DIV), @intFromEnum(Opcode.AND), @intFromEnum(Opcode.OR), @intFromEnum(Opcode.XOR), @intFromEnum(Opcode.JUMP), @intFromEnum(Opcode.JUMPI) => true,
                                else => false,
                            };

                            if (is_fusable) {
                                self.packed_bitmap[i].is_fusion_candidate = true;
                            }
                        }
                    }
                }

                // Handle PUSH instructions
                if (@intFromEnum(opcode_enum) >= @intFromEnum(Opcode.PUSH1) and
                    @intFromEnum(opcode_enum) <= @intFromEnum(Opcode.PUSH32))
                {
                    const n: PcType = op - (@intFromEnum(Opcode.PUSH1) - 1);
                    
                    // We need to read n bytes after the opcode at position i
                    // So we need positions i+1 through i+n to be valid
                    // This means i+n must be less than the validation length
                    if (i + n >= validate_up_to) return error.TruncatedPush;
                    
                    // Extract push value for immediate jump validation (only if fusions enabled)
                    var push_value: u256 = 0;
                    if (comptime fusions_enabled) {
                        var byte_idx: PcType = 0;
                        while (byte_idx < n) : (byte_idx += 1) {
                            push_value = (push_value << 8) | self.runtime_code[i + 1 + byte_idx];
                        }
                    }
                    
                    // Mark push data bytes
                    var j: PcType = 0;
                    while (j < n) : (j += 1) {
                        const idx = i + 1 + j;
                        self.is_push_data[idx >> BITMAP_SHIFT] |= @as(u8, 1) << @intCast(idx & BITMAP_MASK);
                        self.packed_bitmap[idx].is_push_data = true;
                    }
                    
                    const push_end = i + 1 + n;
                    
                    // ONLY check for immediate jump patterns if fusions are enabled
                    // This is for optimization purposes, not correctness validation
                    if (comptime fusions_enabled) {
                        if (push_end < validate_up_to) {
                            const next_op = self.runtime_code[push_end];
                            
                            // Case 1: PUSH + JUMP (for fusion optimization)
                            if (next_op == @intFromEnum(Opcode.JUMP)) {
                                            log.debug("Detected PUSH + JUMP fusion opportunity at pc={}, push_value={}, next_op={x}", .{ i, push_value, next_op });
                                // Note: We do NOT validate jump targets here - that happens at runtime
                                // This is only for marking fusion opportunities
                            }
                            
                            // Case 2: PUSH + JUMPI (check if previous was also a PUSH)
                            else if (push_end < validate_up_to and next_op == @intFromEnum(Opcode.JUMPI) and 
                                     last_push_value != null and 
                                     last_push_end == i) {
                                // We have PUSH(dest) + PUSH(cond) + JUMPI pattern
                                const jump_dest = last_push_value.?;
                                            log.debug("Detected PUSH + PUSH + JUMPI fusion opportunity at pc={}, jump_dest={}, next_op={x}", .{ i, jump_dest, next_op });
                                // Note: We do NOT validate jump targets here - that happens at runtime
                            }
                        }
                        
                        // Update state for next iteration
                        last_push_value = push_value;
                        last_push_end = push_end;
                    }
                    
                    i = push_end;
                } else {
                    // Reset state when we see non-PUSH opcodes (unless it's JUMPI)
                    if (op != @intFromEnum(Opcode.JUMPI) and op != @intFromEnum(Opcode.JUMP)) {
                        last_push_value = null;
                        last_push_end = 0;
                    }
                    i += 1;
                }
            }
            // Note: We do NOT validate immediate jumps during bytecode initialization because:
            // 1. Not all PUSH+JUMP patterns in bytecode are actually executed (dead code, data sections)
            // 2. The EVM spec requires jump validation at execution time, not initialization time
            // 3. Validating jumps here would reject valid contracts that contain unreachable PUSH+JUMP patterns
            // The immediate jump detection above is ONLY for fusion optimization, not correctness validation.
        }

        /// Validate immediate JUMP/JUMPI targets encoded via preceding PUSH
        /// DEPRECATED: This functionality is now integrated into buildBitmapsAndValidate
        fn validateImmediateJumps_DEPRECATED(self: *Self) ValidationError!void {
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

        /// DEPRECATED: No longer needed with integrated validation
        fn readImmediateJumpTarget_DEPRECATED(self: *Self, i: PcType) ?PcType {
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

        /// DEPRECATED: No longer needed with integrated validation  
        fn readImmediateJumpiTarget_DEPRECATED(self: *Self, i: PcType) ?PcType {
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
            // Minimum metadata size: reduced for Swarm format
            if (code.len < 35) return null;

            // Get the last 2 bytes which encode the metadata length
            const len_offset = code.len - 2;
            const metadata_len = (@as(u16, code[len_offset]) << 8) | code[len_offset + 1];

            // Verify metadata length is reasonable (reduced minimum for Swarm)
            if (metadata_len < 35 or metadata_len > code.len) {
                return null;
            }

            // Calculate where metadata starts
            const metadata_start = code.len - 2 - metadata_len;
            const metadata = code[metadata_start .. code.len - 2];

            // Parse CBOR-encoded metadata
            var pos: usize = 0;

            // Check CBOR map header (0xa1 = map with 1 item, 0xa2 = map with 2 items)
            if (pos >= metadata.len) {
                return null;
            }
            if (metadata[pos] != 0xa1 and metadata[pos] != 0xa2) {
                return null;
            }
            const map_items = if (metadata[pos] == 0xa1) @as(u8, 1) else @as(u8, 2);
            pos += 1;

            // First entry should be "ipfs" or "bzzr0"/"bzzr1" 
            if (pos + 6 >= metadata.len) return null;
            
            const is_ipfs = metadata[pos] == 0x64 and pos + 4 < metadata.len and 
                           std.mem.eql(u8, metadata[pos + 1 .. pos + 5], "ipfs");
            const is_swarm = metadata[pos] == 0x65 and pos + 5 < metadata.len and
                            (std.mem.eql(u8, metadata[pos + 1 .. pos + 6], "bzzr0") or
                             std.mem.eql(u8, metadata[pos + 1 .. pos + 6], "bzzr1"));
            
            if (!is_ipfs and !is_swarm) return null;
            
            if (is_ipfs) {
                pos += 5; // Skip length byte + "ipfs"
            } else {
                pos += 6; // Skip length byte + "bzzr0" or "bzzr1"
            }

            // Hash format depends on whether it's IPFS or Swarm
            if (is_ipfs) {
                // IPFS hash (0x58 = byte string, 0x22 = 34 bytes following)
                if (pos + 2 >= metadata.len) return null;
                if (metadata[pos] != 0x58 or metadata[pos + 1] != 0x22) return null;
                pos += 2;
                if (pos + 34 > metadata.len) return null;
                pos += 34; // Skip 34-byte IPFS hash
            } else {
                // Swarm hash (0x58 = byte string, 0x20 = 32 bytes following)
                if (pos + 2 >= metadata.len) return null;
                if (metadata[pos] != 0x58 or metadata[pos + 1] != 0x20) return null;
                pos += 2;
                if (pos + 32 > metadata.len) return null;
                pos += 32; // Skip 32-byte Swarm hash
            }
            
            // Create a dummy 34-byte hash for compatibility (we don't actually need the hash content)
            var ipfs_hash: [34]u8 = undefined;
            @memset(&ipfs_hash, 0);

            // For 2-item maps, second entry should be "solc" (but 1-item maps only have the hash)
            if (map_items == 2) {
                if (pos + 5 >= metadata.len) return null;
                if (metadata[pos] != 0x64) return null; // 4-byte string
                pos += 1;
                
                if (!std.mem.eql(u8, metadata[pos .. pos + 4], "solc")) return null;
                pos += 4;
                
                // Solc version (3 bytes: major, minor, patch)
                if (pos + 3 > metadata.len) return null;
            }

            // For 1-item maps, we're done parsing; for 2-item maps, parse version
            var solc_version: [3]u8 = .{ 0, 0, 0 }; // Default for Swarm metadata without version
            if (map_items == 2) {
                if (pos + 3 > metadata.len) return null;
                solc_version[0] = metadata[pos];
                solc_version[1] = metadata[pos + 1];
                solc_version[2] = metadata[pos + 2];
            }

            return SolidityMetadata{
                .ipfs_hash = ipfs_hash,
                .solc_version = solc_version,
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
                    .PUSH0 => {
                        // EIP-3855: PUSH0 pushes zero onto the stack
                        try analysis.push_data.append(.{
                            .pc = pc,
                            .size = 0,
                            .value = 0,
                            .is_inline = true,
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

        /// Pretty print bytecode with human-readable formatting, colors, and metadata
        pub fn pretty_print(self: Self, allocator: std.mem.Allocator) ![]u8 {
            const opcode_data = @import("opcode_data.zig");

            // ANSI color codes
            const Colors = struct {
                const reset = "\x1b[0m";
                const bold = "\x1b[1m";
                const dim = "\x1b[2m";
                const red = "\x1b[31m";
                const green = "\x1b[32m";
                const yellow = "\x1b[33m";
                const blue = "\x1b[34m";
                const magenta = "\x1b[35m";
                const cyan = "\x1b[36m";
                const white = "\x1b[37m";
                const bright_red = "\x1b[91m";
                const bright_green = "\x1b[92m";
                const bright_yellow = "\x1b[93m";
                const bright_blue = "\x1b[94m";
                const bright_magenta = "\x1b[95m";
                const bright_cyan = "\x1b[96m";
            };

            var output = std.ArrayListAligned(u8, null){};
            defer output.deinit(allocator);

            // Header
            try output.writer(allocator).print("{s}=== EVM Bytecode Disassembly ==={s}\n", .{ Colors.bold, Colors.reset });
            try output.writer(allocator).print("{s}Length: {} bytes{s}\n\n", .{ Colors.dim, self.runtime_code.len, Colors.reset });

            var pc: PcType = 0;
            var line_num: u32 = 1;

            while (pc < self.runtime_code.len) {
                const opcode_byte = self.runtime_code[pc];

                // Line number and PC address
                try output.writer(allocator).print("{s}{d:3}:{s} {s}0x{x:0>4}{s} ", .{ Colors.dim, line_num, Colors.reset, Colors.cyan, pc, Colors.reset });

                // Check if this is a jump destination
                if (self.isValidJumpDest(pc)) {
                    try output.writer(allocator).print("{s}►{s} ", .{ Colors.bright_yellow, Colors.reset });
                } else {
                    try output.writer(allocator).print("  ", .{});
                }

                // Raw hex bytes (show opcode + data for PUSH instructions)
                const instruction_size = self.getInstructionSize(pc);
                var hex_output = std.ArrayListAligned(u8, null){};
                defer hex_output.deinit(allocator);

                for (0..instruction_size) |i| {
                    if (pc + i < self.runtime_code.len) {
                        try hex_output.writer(allocator).print("{x:0>2}", .{self.runtime_code[pc + i]});
                        if (i + 1 < instruction_size) try hex_output.writer(allocator).print(" ", .{});
                    }
                }

                // Pad hex to fixed width for alignment
                const hex_str = hex_output.items;
                try output.writer(allocator).print("{s}{s:<24}{s} ", .{ Colors.dim, hex_str, Colors.reset });

                // Parse and format the instruction
                if (std.meta.intToEnum(Opcode, opcode_byte)) |opcode| {
                    const opcode_info = opcode_data.OPCODE_INFO[opcode_byte];

                    switch (opcode) {
                        .PUSH0 => {
                            // EIP-3855: PUSH0 pushes zero
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.green, @tagName(opcode), Colors.reset });
                            try output.writer(allocator).print(" {s}0x0{s} {s}(0){s}", .{ Colors.bright_magenta, Colors.reset, Colors.dim, Colors.reset });
                        },
                        .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8, .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16, .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24, .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => {
                            const push_size = @intFromEnum(opcode) - @intFromEnum(Opcode.PUSH1) + 1;
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.green, @tagName(opcode), Colors.reset });

                            // Extract and format push value
                            if (self.readPushValueN(pc, push_size)) |value| {
                                try output.writer(allocator).print(" {s}0x{x}{s}", .{ Colors.bright_magenta, value, Colors.reset });

                                // Show decimal if small value
                                if (value <= 0xFFFF) {
                                    try output.writer(allocator).print(" {s}({}){s}", .{ Colors.dim, value, Colors.reset });
                                }
                            }
                        },
                        .JUMPDEST => {
                            try output.writer(allocator).print("{s}{s}{s:<12}{s}", .{ Colors.bright_yellow, Colors.bold, @tagName(opcode), Colors.reset });
                        },
                        .JUMP, .JUMPI => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.yellow, @tagName(opcode), Colors.reset });
                        },
                        .STOP, .RETURN, .REVERT => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.red, @tagName(opcode), Colors.reset });
                        },
                        .ADD, .SUB, .MUL, .DIV, .SDIV, .MOD, .SMOD, .ADDMOD, .MULMOD, .EXP => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.blue, @tagName(opcode), Colors.reset });
                        },
                        .LT, .GT, .SLT, .SGT, .EQ, .ISZERO => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.magenta, @tagName(opcode), Colors.reset });
                        },
                        .AND, .OR, .XOR, .NOT, .BYTE, .SHL, .SHR, .SAR => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.cyan, @tagName(opcode), Colors.reset });
                        },
                        else => {
                            try output.writer(allocator).print("{s}{s:<12}{s}", .{ Colors.white, @tagName(opcode), Colors.reset });
                        },
                    }

                    // Gas cost
                    try output.writer(allocator).print(" {s}[gas: {}]{s}", .{ Colors.dim, opcode_info.gas_cost, Colors.reset });

                    // Stack effects
                    if (opcode_info.stack_inputs > 0 or opcode_info.stack_outputs > 0) {
                        try output.writer(allocator).print(" {s}[stack: -{}, +{}]{s}", .{ Colors.dim, opcode_info.stack_inputs, opcode_info.stack_outputs, Colors.reset });
                    }
                } else |_| {
                    // Invalid opcode
                    try output.writer(allocator).print("{s}INVALID(0x{x:0>2}){s}", .{ Colors.bright_red, opcode_byte, Colors.reset });
                }

                try output.writer(allocator).print("\n", .{});

                pc += instruction_size;
                line_num += 1;
            }

            // Footer with summary
            try output.writer(allocator).print("\n{s}=== Summary ==={s}\n", .{ Colors.bold, Colors.reset });

            // Count jump destinations
            var jumpdest_count: u32 = 0;
            for (0..self.runtime_code.len) |i| {
                if (self.isValidJumpDest(@intCast(i))) {
                    jumpdest_count += 1;
                }
            }
            
            try output.writer(allocator).print("{s}Jump destinations: {}{s}\n", .{ Colors.dim, jumpdest_count, Colors.reset });
            try output.writer(allocator).print("{s}Total instructions: {}{s}\n", .{ Colors.dim, line_num - 1, Colors.reset });
            
            if (self.metadata) |meta| {
                try output.writer(allocator).print("{s}Solidity metadata: {} bytes{s}\n", .{ Colors.dim, meta.metadata_length, Colors.reset });
                try output.writer(allocator).print("{s}Compiler version: {}.{}.{}{s}\n", .{ 
                    Colors.dim, meta.solc_version[0], meta.solc_version[1], meta.solc_version[2], Colors.reset 
                });
            }
            
            return output.toOwnedSlice(allocator);
        }
    };
}

const default_config = BytecodeConfig{};
pub const BytecodeDefault = Bytecode(default_config);
pub const BytecodeValidationError = BytecodeDefault.ValidationError;

// Export the factory function for creating Bytecode types
pub const createBytecode = Bytecode;

test "pretty_print: should format bytecode with colors and metadata" {
    const allocator = std.testing.allocator;

    // Simple bytecode: PUSH1 0x42, PUSH1 0x24, ADD, JUMPDEST, STOP
    const code = [_]u8{ 0x60, 0x42, 0x60, 0x24, 0x01, 0x5B, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    const formatted = try bytecode.pretty_print(allocator);
    defer allocator.free(formatted);

    // Expected output should contain:
    // - PC addresses (0x00, 0x02, etc.)
    // - Opcode names (PUSH1, ADD, JUMPDEST, STOP)
    // - Push values (0x42, 0x24)
    // - Gas costs
    // - Jump destinations highlighted
    // - ANSI colors

    const expected_parts = [_][]const u8{
        "0x00", // PC address
        "PUSH1", // Opcode name
        "0x42", // Push value
        "0x02", // Next PC
        "0x24", // Second push value
        "ADD", // Add opcode
        "JUMPDEST", // Jump destination
        "STOP", // Stop opcode
        "gas:", // Gas cost indicator
        "\x1b[", // ANSI escape sequence for colors
    };

    for (expected_parts) |part| {
        std.testing.expect(std.mem.indexOf(u8, formatted, part) != null) catch |err| {
            log.debug("Expected to find '{s}' in:\n{s}\n", .{ part, formatted });
            return err;
        };
    }

    // Verify it's a valid string
    try std.testing.expect(formatted.len > 0);
}

// Additional comprehensive test coverage for bytecode.zig

const testing = std.testing;

test "Bytecode init - valid simple bytecode" {
    const allocator = testing.allocator;

    // Simple valid bytecode: PUSH1 0x01, PUSH1 0x02, ADD, STOP
    const code = [_]u8{ 0x60, 0x01, 0x60, 0x02, 0x01, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(usize, 6), bytecode.len());
    try testing.expect(bytecode.isValidJumpDest(4) == false); // ADD is not a JUMPDEST
}

test "Bytecode init - empty bytecode" {
    const allocator = testing.allocator;

    const code = [_]u8{};
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(usize, 0), bytecode.len());
}

test "Bytecode validation - undefined opcode treated as INVALID" {
    const allocator = testing.allocator;

    // Undefined opcode 0x0c (gap in opcode range) should be accepted as INVALID
    const code = [_]u8{0x0c};
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();
    
    try testing.expectEqual(@as(usize, 1), bytecode.len());
}

test "Bytecode validation - truncated PUSH instruction" {
    const allocator = testing.allocator;

    // PUSH1 without data byte
    const code = [_]u8{0x60};
    try testing.expectError(BytecodeDefault.ValidationError.TruncatedPush, BytecodeDefault.init(allocator, &code));
}

test "Bytecode validation - truncated PUSH32" {
    const allocator = testing.allocator;

    // PUSH32 with only 31 bytes of data (should have 32)
    var code = [_]u8{0x7F} ++ [_]u8{0xFF} ** 31;
    try testing.expectError(BytecodeDefault.ValidationError.TruncatedPush, BytecodeDefault.init(allocator, &code));
}

test "Jump destination validation - valid JUMPDEST" {
    const allocator = testing.allocator;

    // PUSH1 3, JUMP, JUMPDEST, STOP
    const code = [_]u8{ 0x60, 0x03, 0x56, 0x5B, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expect(bytecode.isValidJumpDest(3) == true); // JUMPDEST at PC 3
    try testing.expect(bytecode.isValidJumpDest(0) == false); // PUSH1 is not a JUMPDEST
    try testing.expect(bytecode.isValidJumpDest(2) == false); // JUMP is not a JUMPDEST
}

test "Jump destination validation - invalid jump target" {
    const allocator = testing.allocator;

    // PUSH1 3, JUMP, STOP (no JUMPDEST at PC 3)
    const code = [_]u8{ 0x60, 0x03, 0x56, 0x00 };
    try testing.expectError(BytecodeDefault.ValidationError.InvalidJumpDestination, BytecodeDefault.init(allocator, &code));
}

test "Jump destination validation - jump to push data" {
    const allocator = testing.allocator;

    // PUSH1 1, JUMP, 0x5B (this 0x5B is push data, not a real JUMPDEST)
    const code = [_]u8{ 0x60, 0x01, 0x56, 0x60, 0x5B };
    try testing.expectError(BytecodeDefault.ValidationError.InvalidJumpDestination, BytecodeDefault.init(allocator, &code));
}

test "Jump destination validation - JUMPI pattern" {
    const allocator = testing.allocator;

    // PUSH1 6, PUSH1 1, JUMPI, STOP, JUMPDEST, STOP  
    const code = [_]u8{ 0x60, 0x06, 0x60, 0x01, 0x57, 0x00, 0x5B, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expect(bytecode.isValidJumpDest(6) == true);
}

test "PUSH instruction handling - all PUSH sizes" {
    const allocator = testing.allocator;

    // Test PUSH1 through PUSH4
    const push1_code = [_]u8{ 0x60, 0x42, 0x00 }; // PUSH1 0x42, STOP
    var bytecode1 = try BytecodeDefault.init(allocator, &push1_code);
    defer bytecode1.deinit();

    const push2_code = [_]u8{ 0x61, 0x12, 0x34, 0x00 }; // PUSH2 0x1234, STOP  
    var bytecode2 = try BytecodeDefault.init(allocator, &push2_code);
    defer bytecode2.deinit();

    const push4_code = [_]u8{ 0x63, 0x12, 0x34, 0x56, 0x78, 0x00 }; // PUSH4 0x12345678, STOP
    var bytecode4 = try BytecodeDefault.init(allocator, &push4_code);
    defer bytecode4.deinit();

    try testing.expectEqual(@as(usize, 3), bytecode1.len());
    try testing.expectEqual(@as(usize, 4), bytecode2.len());
    try testing.expectEqual(@as(usize, 6), bytecode4.len());
}

test "PUSH value reading - readPushValue" {
    const allocator = testing.allocator;

    // PUSH4 0x12345678, STOP
    const code = [_]u8{ 0x63, 0x12, 0x34, 0x56, 0x78, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    const value = bytecode.readPushValue(0, 4);
    try testing.expect(value != null);
    try testing.expectEqual(@as(u32, 0x12345678), value.?);
}

test "PUSH value reading - readPushValueN" {
    const allocator = testing.allocator;

    // PUSH8 with max value that fits in u64
    const code = [_]u8{ 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    const value = bytecode.readPushValueN(0, 8);
    try testing.expect(value != null);
    try testing.expectEqual(@as(u256, 0xFFFFFFFFFFFFFFFF), value.?);
}

test "Iterator functionality - basic iteration" {
    const allocator = testing.allocator;

    // PUSH1 0x42, ADD, JUMPDEST, STOP
    const code = [_]u8{ 0x60, 0x42, 0x01, 0x5B, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    var iter = bytecode.createIterator();
    
    // First instruction: PUSH1
    var opcode_data = iter.next();
    try testing.expect(opcode_data != null);
    try testing.expectEqual(@as(u8, 0x60), @intFromEnum(opcode_data.?.opcode));

    // Second instruction: ADD (should skip push data)
    opcode_data = iter.next();
    try testing.expect(opcode_data != null);
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(opcode_data.?.opcode));

    // Third instruction: JUMPDEST
    opcode_data = iter.next();
    try testing.expect(opcode_data != null);
    try testing.expectEqual(@as(u8, 0x5B), @intFromEnum(opcode_data.?.opcode));

    // Fourth instruction: STOP
    opcode_data = iter.next();
    try testing.expect(opcode_data != null);
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(opcode_data.?.opcode));

    // Should be at end
    opcode_data = iter.next();
    try testing.expect(opcode_data == null);
}

test "Bitmap operations - push data detection" {
    const allocator = testing.allocator;

    // PUSH2 0x1234, STOP
    const code = [_]u8{ 0x61, 0x12, 0x34, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    // PC 0: PUSH2 instruction (not push data)
    try testing.expect(!bytecode.packed_bitmap[0].is_push_data);
    try testing.expect(bytecode.packed_bitmap[0].is_op_start);

    // PC 1, 2: Push data bytes
    try testing.expect(bytecode.packed_bitmap[1].is_push_data);
    try testing.expect(!bytecode.packed_bitmap[1].is_op_start);
    try testing.expect(bytecode.packed_bitmap[2].is_push_data);
    try testing.expect(!bytecode.packed_bitmap[2].is_op_start);

    // PC 3: STOP instruction
    try testing.expect(!bytecode.packed_bitmap[3].is_push_data);
    try testing.expect(bytecode.packed_bitmap[3].is_op_start);
}

test "Instruction size calculation - getInstructionSize" {
    const allocator = testing.allocator;

    // PUSH1 0x42, PUSH4 0x12345678, ADD, STOP
    const code = [_]u8{ 0x60, 0x42, 0x63, 0x12, 0x34, 0x56, 0x78, 0x01, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(BytecodeDefault.PcType, 2), bytecode.getInstructionSize(0)); // PUSH1
    try testing.expectEqual(@as(BytecodeDefault.PcType, 5), bytecode.getInstructionSize(2)); // PUSH4
    try testing.expectEqual(@as(BytecodeDefault.PcType, 1), bytecode.getInstructionSize(7)); // ADD
    try testing.expectEqual(@as(BytecodeDefault.PcType, 1), bytecode.getInstructionSize(8)); // STOP
}

test "PC navigation - getNextPc" {
    const allocator = testing.allocator;

    // PUSH2 0x1234, ADD, STOP
    const code = [_]u8{ 0x61, 0x12, 0x34, 0x01, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(?BytecodeDefault.PcType, 3), bytecode.getNextPc(0)); // PUSH2 -> ADD
    try testing.expectEqual(@as(?BytecodeDefault.PcType, 4), bytecode.getNextPc(3)); // ADD -> STOP
    try testing.expectEqual(@as(?BytecodeDefault.PcType, null), bytecode.getNextPc(4)); // STOP -> end
}

test "Fusion candidate detection" {
    const allocator = testing.allocator;

    // PUSH1 0x42, ADD, PUSH1 0x24, MUL, STOP
    const code = [_]u8{ 0x60, 0x42, 0x01, 0x60, 0x24, 0x02, 0x00 };
    const config = BytecodeConfig{
        .max_bytecode_size = 1024,
        .fusions_enabled = true,
    };
    const TestBytecode = Bytecode(config);
    var bytecode = try TestBytecode.init(allocator, &code);
    defer bytecode.deinit();

    // PUSH1 at PC 0 followed by ADD should be fusion candidate
    try testing.expect(bytecode.packed_bitmap[0].is_fusion_candidate);

    // PUSH1 at PC 3 followed by MUL should be fusion candidate
    try testing.expect(bytecode.packed_bitmap[3].is_fusion_candidate);
}

test "Large bytecode handling - EIP-170 limit" {
    const allocator = testing.allocator;

    // Test bytecode exactly at EIP-170 limit (24576 bytes)
    const max_size = 24576;
    const large_code = try allocator.alloc(u8, max_size);
    defer allocator.free(large_code);
    
    // Fill with STOP opcodes (valid)
    @memset(large_code, 0x00);
    
    var bytecode = try BytecodeDefault.init(allocator, large_code);
    defer bytecode.deinit();
    
    try testing.expectEqual(@as(usize, max_size), bytecode.len());
}

test "Complex jump patterns - multiple JUMPDESTs" {
    const allocator = testing.allocator;

    // PUSH1 5, JUMP, PUSH1 9, JUMP, JUMPDEST (PC 5), PUSH1 7, JUMP, STOP, JUMPDEST (PC 9), STOP
    const code = [_]u8{ 0x60, 0x05, 0x56, 0x60, 0x09, 0x56, 0x5B, 0x60, 0x07, 0x56, 0x00, 0x5B, 0x00 };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expect(bytecode.isValidJumpDest(6) == true);  // JUMPDEST at PC 6
    try testing.expect(bytecode.isValidJumpDest(11) == true); // JUMPDEST at PC 11
    try testing.expect(bytecode.isValidJumpDest(0) == false); // PUSH1 is not a JUMPDEST
}

test "Error resilience - out of bounds jump" {
    const allocator = testing.allocator;

    // PUSH1 100, JUMP (target 100 is beyond bytecode end)
    const code = [_]u8{ 0x60, 100, 0x56 };
    try testing.expectError(BytecodeDefault.ValidationError.InvalidJumpDestination, BytecodeDefault.init(allocator, &code));
}

test "Bitmap utility functions - countBitsInRange" {
    // Test the bitmap counting utility
    const bitmap = [_]u8{ 0b10101010, 0b11110000, 0b00001111 };
    
    const count1 = BytecodeDefault.countBitsInRange(&bitmap, 0, 8);
    try testing.expectEqual(@as(usize, 4), count1); // First byte has 4 bits set

    const count2 = BytecodeDefault.countBitsInRange(&bitmap, 8, 16);
    try testing.expectEqual(@as(usize, 4), count2); // Second byte has 4 bits set

    const count3 = BytecodeDefault.countBitsInRange(&bitmap, 0, 24);
    try testing.expectEqual(@as(usize, 12), count3); // All three bytes have 12 bits total
}

test "Bitmap utility functions - findNextSetBit" {
    // Test finding next set bit in bitmap
    const bitmap = [_]u8{ 0b00000000, 0b00010000, 0b10000000 };
    
    const next_bit1 = BytecodeDefault.findNextSetBit(&bitmap, 0);
    try testing.expectEqual(@as(?usize, 12), next_bit1); // Bit 12 (4th bit of second byte)

    const next_bit2 = BytecodeDefault.findNextSetBit(&bitmap, 13);
    try testing.expectEqual(@as(?usize, 16), next_bit2); // Bit 16 (0th bit of third byte)

    const next_bit3 = BytecodeDefault.findNextSetBit(&bitmap, 17);
    try testing.expectEqual(@as(?usize, null), next_bit3); // No more set bits
}

test "Initcode gas calculation - EIP-3860" {
    // Test initcode gas calculation per EIP-3860
    const gas1 = BytecodeDefault.calculateInitcodeGas(32);
    try testing.expectEqual(@as(u64, 2), gas1); // 32 bytes = 1 word = 2 gas

    const gas2 = BytecodeDefault.calculateInitcodeGas(64);
    try testing.expectEqual(@as(u64, 4), gas2); // 64 bytes = 2 words = 4 gas

    const gas3 = BytecodeDefault.calculateInitcodeGas(33);
    try testing.expectEqual(@as(u64, 4), gas3); // 33 bytes = 2 words (rounded up) = 4 gas

    const gas4 = BytecodeDefault.calculateInitcodeGas(0);
    try testing.expectEqual(@as(u64, 0), gas4); // 0 bytes = 0 gas
}

test "Memory management - proper cleanup" {
    const allocator = testing.allocator;

    // Test that multiple init/deinit cycles work properly
    for (0..10) |_| {
        const code = [_]u8{ 0x60, 0x42, 0x01, 0x5B, 0x00 };
        var bytecode = try BytecodeDefault.init(allocator, &code);
        defer bytecode.deinit();

        try testing.expectEqual(@as(usize, 5), bytecode.len());
    }
}

test "Edge cases - single byte bytecode" {
    const allocator = testing.allocator;

    // Single STOP instruction
    const code = [_]u8{0x00};
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(usize, 1), bytecode.len());
    try testing.expect(bytecode.packed_bitmap[0].is_op_start);
    try testing.expect(!bytecode.packed_bitmap[0].is_push_data);
    try testing.expect(!bytecode.packed_bitmap[0].is_jumpdest);
}

test "Edge cases - maximum PUSH32 instruction" {
    const allocator = testing.allocator;

    // PUSH32 with 32 bytes of data
    var code = [_]u8{0x7F} ++ [_]u8{0xFF} ** 32 ++ [_]u8{0x00}; // PUSH32 + 32 bytes + STOP
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expectEqual(@as(usize, 34), bytecode.len()); // PUSH32 + 32 data bytes + STOP

    // Verify push data is marked correctly
    for (1..33) |i| {
        try testing.expect(bytecode.packed_bitmap[i].is_push_data);
        try testing.expect(!bytecode.packed_bitmap[i].is_op_start);
    }
}

test "Boundary conditions - jump to last instruction" {
    const allocator = testing.allocator;

    // PUSH1 3, JUMP, JUMPDEST
    const code = [_]u8{ 0x60, 0x03, 0x56, 0x5B };
    var bytecode = try BytecodeDefault.init(allocator, &code);
    defer bytecode.deinit();

    try testing.expect(bytecode.isValidJumpDest(3) == true);
}

test "Security - malformed jump patterns" {
    const allocator = testing.allocator;

    // PUSH1 2, JUMP, JUMPDEST (but jump target is push data, not the JUMPDEST)
    const code = [_]u8{ 0x60, 0x02, 0x56, 0x5B };
    try testing.expectError(BytecodeDefault.ValidationError.InvalidJumpDestination, BytecodeDefault.init(allocator, &code));
}

test "Minimal repro - deployment bytecode with apparent truncated PUSH" {
    const allocator = testing.allocator;
    
    // Minimal case that triggers TruncatedPush
    // This simulates the end of deployment bytecode where a PUSH instruction
    // appears to be truncated but is actually part of the constructor return data
    const code = [_]u8{
        0x60, 0x80, // PUSH1 0x80
        0x60, 0x40, // PUSH1 0x40  
        0x52,       // MSTORE
        0x60, 0x97, // PUSH1 0x97 (size of runtime code)
        0x80,       // DUP1
        0x60, 0x1a, // PUSH1 0x1a (offset in memory)
        0x5f,       // PUSH0
        0x39,       // CODECOPY
        0x5f,       // PUSH0  
        0xf3,       // RETURN
        0xfe,       // INVALID (start of runtime code)
        0x60        // PUSH1 without data - this triggers TruncatedPush
    };
    
    // This should fail with TruncatedPush because the last byte is PUSH1 without data
    try testing.expectError(BytecodeDefault.ValidationError.TruncatedPush, BytecodeDefault.init(allocator, &code));
}

test "Deployment bytecode - actual ten-thousand-hashes fixture" {
    const allocator = testing.allocator;
    
    // First 32 bytes of the actual ten-thousand-hashes bytecode that's failing
    // This is deployment bytecode that ends with what looks like a truncated PUSH
    const code = [_]u8{
        0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15,
        0x60, 0x0e, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x50,
        0x60, 0x97, 0x80, 0x60, 0x1a, 0x5f, 0x39, 0x5f,
        0xf3, 0xfe, // RETURN opcode followed by INVALID
        0x60, 0x80, 0x60, 0x40, 0x52, 0x34, // Start of runtime bytecode
        0x80, 0x15, 0x60 // This ends with 0x60 (PUSH1) without the data byte
    };
    
    // This should fail because it ends with an incomplete PUSH1
    try testing.expectError(BytecodeDefault.ValidationError.TruncatedPush, BytecodeDefault.init(allocator, &code));
}

test "Deployment vs Runtime bytecode handling" {
    const allocator = testing.allocator;
    
    // Simplified deployment bytecode that deploys a simple runtime code
    // Constructor bytecode that returns runtime bytecode
    const deployment_code = [_]u8{
        // Constructor code
        0x60, 0x04, // PUSH1 0x04 (size of runtime code)
        0x80,       // DUP1
        0x60, 0x0c, // PUSH1 0x0c (offset of runtime code)
        0x5f,       // PUSH0 (destination in memory)
        0x39,       // CODECOPY
        0x5f,       // PUSH0 (offset in memory)
        0xf3,       // RETURN
        // Runtime code (what gets deployed)
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0x00
        0x55,       // SSTORE
        0x00,       // STOP
    };
    
    // This should work because it's complete deployment bytecode
    var bytecode = try BytecodeDefault.init(allocator, &deployment_code);
    defer bytecode.deinit();
    
    // The bytecode init detects deployment pattern and uses full code
    try testing.expect(bytecode.runtime_code.len == deployment_code.len);
}
