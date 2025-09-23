const std = @import("std");
const builtin = @import("builtin");
const memory_mod = @import("../memory/memory.zig");
const stack_mod = @import("../stack/stack.zig");
const opcode_data = @import("../opcodes/opcode_data.zig");
const Opcode = opcode_data.Opcode;
const OpcodeSynthetic = @import("../opcodes/opcode_synthetic.zig").OpcodeSynthetic;
pub const FrameConfig = @import("frame_config.zig").FrameConfig;
const Database = @import("../storage/database.zig").Database;
const Account = @import("../storage/database.zig").Account;
const MemoryDatabase = @import("../storage/memory_database.zig").MemoryDatabase;
const bytecode_mod = @import("../bytecode/bytecode.zig");
const BytecodeConfig = @import("../bytecode/bytecode_config.zig").BytecodeConfig;
const primitives = @import("primitives");
const GasConstants = primitives.GasConstants;
const Address = primitives.Address.Address;
const to_u256 = primitives.Address.to_u256;
const from_u256 = primitives.Address.from_u256;
const frame_handlers = @import("frame_handlers.zig");
const SelfDestruct = @import("../storage/self_destruct.zig").SelfDestruct;
const DefaultEvm = @import("../evm.zig").Evm(.{});
const call_params_mod = @import("call_params.zig");
const call_result_mod = @import("call_result.zig");
const dispatch_mod = @import("../preprocessor/dispatch.zig");
const dispatch_cache = @import("dispatch_cache.zig");

/// The core most important datastructure of the entire EVM
/// Holds the StackFrame state along with an `interpret` method for executing a stack frame
pub fn Frame(comptime _config: FrameConfig) type {
    comptime _config.validate();

    return struct {
        const Self = @This();

        /// The config passed into Frame(_config)
        pub const config = _config;

        pub const Error = error{
            StackOverflow,
            StackUnderflow,
            REVERT,
            BytecodeTooLarge,
            AllocationError,
            InvalidJump,
            InvalidOpcode,
            OutOfBounds,
            OutOfGas,
            GasOverflow,
            InvalidAmount,
            WriteProtection,
            // Success termination cases (not actually errors)
            // We treat every exit as errors in the low level interpreter while evm.zig catches them and returns them as success
            // This is a perf optimization
            Stop,
            Return,
            SelfDestruct,
        };

        /// Output data from frame execution (for RETURN and REVERT)
        /// This is stored separately from the frame and returned via thread-local storage
        /// to avoid storing it on the frame struct
        pub threadlocal var frame_output: []const u8 = &.{};

        /// Opcode handlers are expected to recursively dispatch the next opcode if they themselves don't error or return
        /// Takes cursor pointer with jump table available through dispatch metadata when needed
        pub const OpcodeHandler = *const fn (frame: *Self, cursor: [*]const Dispatch.Item) Error!noreturn;

        /// The struct in charge of efficiently dispatching opcode handlers and providing them metadata
        pub const Dispatch = dispatch_mod.Preprocessor(Self);

        /// The "word" type used by the evm. Defaults to u256. "Word" is the type used by Stack and throughout the Evm
        /// If set to something else the EVM will update to that new word size. e.g. run kekkak128 instead of kekkak256
        /// Lowering the word size can improve perf and bundle size
        pub const WordType = config.WordType;
        /// Generic Uint type based on WordType for optimized arithmetic operations
        /// Automatically determines the bit width and limb count from WordType
        pub const UintN = blk: {
            const Uint = @import("primitives").Uint;
            const bits = @bitSizeOf(WordType);
            const limbs = if (bits <= 64) 1 else (bits + 63) / 64;
            break :blk Uint(bits, limbs);
        };
        /// The type used to measure gas. Unsigned integer for perf reasons
        pub const GasType = config.GasType();
        /// The type used to index into bytecode or instructions. Determined by config.max_bytecode_size
        pub const PcType = config.PcType();

        // Compile-time check: PcType must be at least u8 for dispatch cache optimization
        comptime {
            if (@bitSizeOf(PcType) < 8) @compileError("PcType must be at least u8 (8 bits). Current max_bytecode_size is too small.");
        }

        /// The struct in charge of managing Evm memory
        pub const Memory = memory_mod.Memory(.{
            .initial_capacity = config.memory_initial_capacity,
            .memory_limit = config.memory_limit,
            .owned = true,
            .vector_length = config.vector_length,
        });
        /// The struct in charge of managing Evm Word stack
        pub const Stack = stack_mod.Stack(.{
            .stack_size = config.stack_size,
            .WordType = config.WordType,
        });
        /// The type used to validate and analyze bytecode
        /// Bytecode in a single pass validates the bytecode and produces an iterator
        /// Dispatch can use to produce the Dispatch stream
        /// Note: Now used internally in interpret_with_tracer, not stored on frame
        const Bytecode = bytecode_mod.Bytecode(.{
            .max_bytecode_size = config.max_bytecode_size,
            .max_initcode_size = config.max_initcode_size,
            .fusions_enabled = true,
        });

        /// A fixed size array of opcode handlers indexed by opcode number
        /// Note: Tracer is now part of EVM struct, not config - always use non-traced handlers
        pub const opcode_handlers: [256]OpcodeHandler = frame_handlers.getOpcodeHandlers(Self, &.{});

        // Individual handler groups for testing and direct access
        pub const ArithmeticHandlers = @import("../instructions/handlers_arithmetic.zig").Handlers(Self);
        pub const BitwiseHandlers = @import("../instructions/handlers_bitwise.zig").Handlers(Self);
        pub const ComparisonHandlers = @import("../instructions/handlers_comparison.zig").Handlers(Self);
        pub const ContextHandlers = @import("../instructions/handlers_context.zig").Handlers(Self);
        pub const JumpHandlers = @import("../instructions/handlers_jump.zig").Handlers(Self);
        pub const KeccakHandlers = @import("../instructions/handlers_keccak.zig").Handlers(Self);
        pub const LogHandlers = @import("../instructions/handlers_log.zig").Handlers(Self);
        pub const MemoryHandlers = @import("../instructions/handlers_memory.zig").Handlers(Self);
        pub const StackHandlers = @import("../instructions/handlers_stack.zig").Handlers(Self);
        pub const StorageHandlers = @import("../instructions/handlers_storage.zig").Handlers(Self);
        pub const SystemHandlers = @import("../instructions/handlers_system.zig").Handlers(Self);

        // Synthetic handler groups for optimized opcode fusion
        pub const ArithmeticSyntheticHandlers = @import("../instructions/handlers_arithmetic_synthetic.zig").Handlers(Self);
        pub const BitwiseSyntheticHandlers = @import("../instructions/handlers_bitwise_synthetic.zig").Handlers(Self);
        pub const MemorySyntheticHandlers = @import("../instructions/handlers_memory_synthetic.zig").Handlers(Self);
        pub const JumpSyntheticHandlers = @import("../instructions/handlers_jump_synthetic.zig").Handlers(Self);

        // CACHE LINE 1
        stack: Stack, // 16B
        gas_remaining: GasType, // 8B
        /// Inner calls are handled by recursively calling back into the EVM which will execute that call in a new StackFrame
        evm_ptr: *anyopaque, // 8B
        memory: Memory, // 16B -
        contract_address: Address, // 20B
        caller: Address, // 20B

        // These fields are rarely accessed (specific opcodes only)
        // Note: database moved to EVM struct - access via evm_ptr for better cache locality
        value: WordType, // 32B - Only for CALLVALUE opcode (per-call, cannot cache)
        calldata_slice: []const u8, // 16B - Only for CALLDATALOAD/COPY (per-call, cannot cache)
        // TODO: We should be able to remove this in favor of storing pointer as metadata
        code: []const u8 = &[_]u8{}, // 16B - Only for CODESIZE/CODECOPY
        authorized_address: ?Address = null, // 21B - EIP-3074 (per-call auth, cannot cache)
        // TODO: We should be able to remove this in favor of storing pointer as metadata
        jump_table: *const Dispatch.JumpTable, // 8B - Jump table for JUMP/JUMPI
        dispatch: Dispatch, // 16B
        // When enabled (by default only in Debug and Safe mode) we track how many instructions we executed and limit it
        instruction_counter: config.createLoopSafetyCounter(),

        pub fn init(allocator: std.mem.Allocator, gas_remaining: GasType, caller: Address, value: WordType, calldata_input: []const u8, evm_ptr: *anyopaque) Error!Self {
            var stack = Stack.init(allocator, null) catch return Error.AllocationError;
            errdefer stack.deinit(allocator);
            var memory = Memory.init(allocator) catch return Error.AllocationError;
            errdefer memory.deinit(allocator);
            return Self{
                .stack = stack,
                .gas_remaining = std.math.cast(GasType, @max(gas_remaining, 0)) orelse return Error.InvalidAmount,
                .dispatch = Dispatch{ .cursor = undefined }, // Will be set during interpret
                .memory = memory,
                .evm_ptr = evm_ptr,
                .contract_address = Address.ZERO_ADDRESS,
                .jump_table = &Dispatch.JumpTable{ .entries = &[_]Dispatch.JumpTable.JumpTableEntry{} }, // Pointer to empty jump table
                .caller = caller,
                .value = value,
                .calldata_slice = calldata_input,
                .code = &[_]u8{}, // Will be set during interpret
                .authorized_address = null,
                .instruction_counter = config.createLoopSafetyCounter().init(config.loop_quota orelse 0),
            };
        }

        /// Clean up all frame resources.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            (&self.getEvm().tracer).debug("Frame.deinit: Starting cleanup", .{});
            self.stack.deinit(allocator);
            self.memory.deinit(allocator);
            (&self.getEvm().tracer).debug("Frame.deinit: Cleanup complete", .{});
        }

        pub fn interpret(self: *Self, bytecode_raw: []const u8) Error!void {
            @branchHint(.likely);
            (&self.getEvm().tracer).onInterpret(self, bytecode_raw, @as(i64, @intCast(self.gas_remaining)));

            if (bytecode_raw.len > config.max_bytecode_size) {
                @branchHint(.cold);
                (&self.getEvm().tracer).onFrameBytecodeInit(bytecode_raw.len, false, error.BytecodeTooLarge);
                return Error.BytecodeTooLarge;
            }
            (&self.getEvm().tracer).onFrameBytecodeInit(bytecode_raw.len, true, null);
            self.code = bytecode_raw;

            (&self.getEvm().tracer).initPcTracker(bytecode_raw);

            const allocator = self.getEvm().getCallArenaAllocator();

            var schedule: []const Dispatch.Item = undefined;
            var jump_table_ptr: *Dispatch.JumpTable = undefined;
            var owned_schedule: ?Dispatch.DispatchSchedule = null;
            var owned_jump_table: ?*Dispatch.JumpTable = null;

            // TODO: this is AI slop code that is way too tested way too complex and could be simplified
            // TODO: Why is global_dispatch_cache optional? I don't remember if this is intentional or not
            if (dispatch_cache.global_dispatch_cache) |*cache| {
                if (cache.lookup(bytecode_raw)) |cached_data| {
                    (&self.getEvm().tracer).debug("Frame: Using cached dispatch schedule", .{});
                    schedule = @as([*]const Dispatch.Item, @ptrCast(@alignCast(cached_data.schedule.ptr)))[0 .. cached_data.schedule.len / @sizeOf(Dispatch.Item)];
                    const jump_table_entries = @as([*]const Dispatch.JumpTable.JumpTableEntry, @ptrCast(@alignCast(cached_data.jump_table.ptr)))[0 .. cached_data.jump_table.len / @sizeOf(Dispatch.JumpTable.JumpTableEntry)];
                    const cached_jump_table = allocator.create(Dispatch.JumpTable) catch return Error.AllocationError;
                    cached_jump_table.* = .{ .entries = jump_table_entries };
                    jump_table_ptr = cached_jump_table;
                    owned_jump_table = cached_jump_table;

                    defer cache.release(bytecode_raw);
                } else {
                    (&self.getEvm().tracer).debug("Frame: Cache miss, creating new dispatch", .{});
                    const bytecode = Bytecode.initWithTracer(allocator, bytecode_raw, @as(?@TypeOf(&self.getEvm().tracer), &self.getEvm().tracer)) catch |e| {
                        @branchHint(.cold);
                        (&self.getEvm().tracer).onFrameBytecodeInit(bytecode_raw.len, false, e);
                        return switch (e) {
                            error.BytecodeTooLarge => Error.BytecodeTooLarge,
                            error.InvalidOpcode => Error.InvalidOpcode,
                            error.InvalidJumpDestination => Error.InvalidJump,
                            error.TruncatedPush => Error.InvalidOpcode,
                            error.OutOfMemory => Error.AllocationError,
                            else => Error.AllocationError,
                        };
                    };
                    const handlers = &Self.opcode_handlers;
                    owned_schedule = Dispatch.DispatchSchedule.init(allocator, bytecode, handlers, @as(?@TypeOf(&self.getEvm().tracer), &self.getEvm().tracer)) catch {
                        return Error.AllocationError;
                    };
                    schedule = owned_schedule.?.items;

                    if (comptime (@import("builtin").mode == .Debug or @import("builtin").mode == .ReleaseSafe)) {
                        const dispatch_pretty_print = @import("../preprocessor/dispatch_pretty_print.zig");
                        const pretty_output = dispatch_pretty_print.pretty_print(
                            allocator,
                            schedule,
                            bytecode,
                            Self,
                            Dispatch.Item,
                        ) catch null;
                        if (pretty_output) |output| {
                            defer allocator.free(output);
                            (&self.getEvm().tracer).debug("\n{s}", .{output});
                        }
                    }

                    const jt = Dispatch.createJumpTable(allocator, schedule, bytecode) catch return Error.AllocationError;
                    const heap_jump_table = allocator.create(Dispatch.JumpTable) catch return Error.AllocationError;
                    heap_jump_table.* = jt;
                    jump_table_ptr = heap_jump_table;
                    owned_jump_table = heap_jump_table;

                    const schedule_bytes = std.mem.sliceAsBytes(schedule);
                    const jump_table_bytes = std.mem.sliceAsBytes(jump_table_ptr.entries);
                    cache.insert(bytecode_raw, schedule_bytes, jump_table_bytes) catch {
                        @branchHint(.cold);
                        // Failed to cache - not a fatal error, just continue
                        // TODO: we should be tracer.warn logging here
                    };
                }
            } else {
                @branchHint(.unlikely);
                const bytecode = Bytecode.init(allocator, bytecode_raw) catch |e| {
                    @branchHint(.unlikely);
                    return switch (e) {
                        error.BytecodeTooLarge => Error.BytecodeTooLarge,
                        error.InvalidOpcode => Error.InvalidOpcode,
                        error.InvalidJumpDestination => Error.InvalidJump,
                        error.TruncatedPush => Error.InvalidOpcode,
                        error.OutOfMemory => Error.AllocationError,
                        else => Error.AllocationError,
                    };
                };

                const handlers = &Self.opcode_handlers;

                owned_schedule = Dispatch.DispatchSchedule.init(allocator, bytecode, handlers, null) catch {
                    return Error.AllocationError;
                };
                schedule = owned_schedule.?.items;

                if (comptime (@import("builtin").mode == .Debug or @import("builtin").mode == .ReleaseSafe)) {
                    const dispatch_pretty_print = @import("../preprocessor/dispatch_pretty_print.zig");
                    const pretty_output = dispatch_pretty_print.pretty_print(
                        allocator,
                        schedule,
                        bytecode,
                        Self,
                        Dispatch.Item,
                    ) catch null;
                    if (pretty_output) |output| {
                        defer allocator.free(output);
                        (&self.getEvm().tracer).debug("\n{s}", .{output});
                    }
                }

                const jt = Dispatch.createJumpTable(allocator, schedule, bytecode) catch return Error.AllocationError;
                const heap_jump_table = allocator.create(Dispatch.JumpTable) catch return Error.AllocationError;
                heap_jump_table.* = jt;
                jump_table_ptr = heap_jump_table;
                owned_jump_table = heap_jump_table;
            }

            defer {
                if (owned_schedule) |*s| s.deinit();
                if (owned_jump_table) |jt| {
                    if (jt.entries.len > 0) allocator.free(jt.entries);
                    allocator.destroy(jt);
                }
            }

            self.jump_table = jump_table_ptr;

            var start_index: usize = 0;
            var first_block_gas_amount: u32 = 0;

            (&self.getEvm().tracer).assert(schedule.len > 0, "Fatal unexpected error: the opcode execution schedule is length 0 which should be impossible");
            const stop_handler = Self.opcode_handlers[@intFromEnum(Opcode.STOP)];
            (&self.getEvm().tracer).assert(schedule.len >= 2 or schedule[schedule.len - 1].opcode_handler != stop_handler or schedule[schedule.len - 2].opcode_handler != stop_handler, "Frame.interpret: Bytecode stream does not end with 2 stop handlers");

            // Validate the schedule structure if we have an owned schedule (for better error reporting)
            if (owned_schedule) |*s| {
                (&self.getEvm().tracer).assert(s.validate(), "Frame.interpret: Invalid dispatch schedule structure");
            }

            switch (schedule[0]) {
                .first_block_gas => |meta| {
                    if (meta.gas > 0) {
                        first_block_gas_amount = meta.gas;
                        try self.consumeGasChecked(@intCast(meta.gas));
                    }
                    start_index = 1;
                },
                else => {
                    (&self.getEvm().tracer).assert(false, "Schedule doesn't start with .first_block_gas which is completely unexpected");
                },
            }

            self.dispatch = Dispatch{
                .cursor = schedule.ptr + start_index,
            };

            try self.dispatch.cursor[0].opcode_handler(self, self.dispatch.cursor);

            (&self.getEvm().tracer).assert(false, "Handlers should never return normally");
        }

        /// Create a deep copy of the frame.
        /// This is used by DebugPlan to create a sidecar frame for validation.
        pub fn copy(self: *const Self, allocator: std.mem.Allocator) Error!Self {
            (&self.getEvm().tracer).debug("Frame.copy: Creating deep copy, stack_size={}, memory_size={}", .{ self.stack.get_slice().len, self.memory.size() });
            var new_stack = Stack.init(allocator, @as(?*anyopaque, @ptrCast(&self.getEvm().tracer))) catch return Error.AllocationError;
            errdefer new_stack.deinit(allocator);
            const src_stack_slice = self.stack.get_slice();
            if (src_stack_slice.len > 0) {
                var i: usize = src_stack_slice.len;
                while (i > 0) {
                    i -= 1;
                    try new_stack.push(src_stack_slice[i]);
                }
            }

            var new_memory = Memory.init(allocator) catch return Error.AllocationError;
            errdefer new_memory.deinit(allocator);
            const mem_size = self.memory.size();
            if (mem_size > 0) {
                const bytes = self.memory.get_slice(0, mem_size) catch unreachable;
                try new_memory.set_data(0, bytes);
            }

            (&self.getEvm().tracer).debug("Frame.copy: Deep copy complete", .{});
            return Self{
                .stack = new_stack,
                .gas_remaining = self.gas_remaining,
                .dispatch = self.dispatch,
                .memory = new_memory,
                .evm_ptr = self.evm_ptr,
                .contract_address = self.contract_address,
                .jump_table = self.jump_table,
                .caller = self.caller,
                .value = self.value,
                .calldata_slice = self.calldata_slice,
                .code = self.code,
                .authorized_address = self.authorized_address,
                .instruction_counter = self.instruction_counter,
            };
        }

        /// Consume gas with bounds checking and safe casting
        /// Returns GasOverflow if amount doesn't fit in GasType (extremely rare)
        /// Returns OutOfGas if insufficient gas remaining
        pub fn consumeGasChecked(self: *Self, amount: u32) Error!void {
            // Skip gas checks if disabled in config
            if (comptime config.disable_gas_checks) return;

            const amt = std.math.cast(GasType, amount) orelse {
                (&self.getEvm().tracer).panic("Frame.consumeGasChecked: Gas overflow, amount={} doesn't fit in GasType", .{amount});
                return Error.GasOverflow;
            };

            // Check if we have enough gas
            if (amt > self.gas_remaining) {
                (&self.getEvm().tracer).debug("Frame.consumeGasChecked: Out of gas, required={}, remaining={}", .{ amt, self.gas_remaining });
                return Error.OutOfGas;
            }

            self.gas_remaining -= amt;
        }

        // TODO: DefaultEvm should not exist! This is a bug and a relic from an old version of this.
        // What we should do instead here is pass in the Evm type on the config as a require param and then cast to it instead of DefaultEvm
        // Which is literally the wrong type unless the EVM is configured with defaults
        /// Get the EVM instance from the opaque pointer
        pub inline fn getEvm(self: *const Self) *DefaultEvm {
            return @as(*DefaultEvm, @ptrCast(@alignCast(self.evm_ptr)));
        }

        /// Validate that the current dispatch cursor points to the expected handler and metadata.
        /// This provides extra validation that cursor logic is working as expected.
        /// Only runs in Debug and ReleaseSafe modes, no-op in ReleaseSmall/ReleaseFast.
        pub inline fn validateOpcodeHandler(
            self: *Self,
            comptime opcode: Dispatch.UnifiedOpcode,
            cursor: [*]const Dispatch.Item,
        ) void {
            if (comptime (builtin.mode != .Debug and builtin.mode != .ReleaseSafe)) return;
            const dispatch = Dispatch{ .cursor = cursor };
            dispatch.validateOpcodeHandler(opcode, self);
        }

        /// Unified method to handle pre-instruction operations
        /// Combines tracer's before_instruction and opcode validation
        pub inline fn beforeInstruction(
            self: *Self,
            comptime opcode: Dispatch.UnifiedOpcode,
            cursor: [*]const Dispatch.Item,
        ) void {
            if (comptime (builtin.mode != .Debug and builtin.mode != .ReleaseSafe)) return;
            (&self.getEvm().tracer).before_instruction(self, opcode, cursor);
            self.validateOpcodeHandler(opcode, cursor);
        }

        /// Unified method to handle post-instruction operations
        /// Called right before the tail call to the next instruction (normal flow)
        pub inline fn afterInstruction(
            self: *Self,
            comptime opcode: Dispatch.UnifiedOpcode,
            next_handler: OpcodeHandler,
            next_cursor: [*]const Dispatch.Item,
        ) void {
            (&self.getEvm().tracer).after_instruction(self, opcode, next_handler, next_cursor);
        }

        /// Called when an instruction completes with a terminal state
        /// (Error, Return, Stop, etc.) rather than continuing to next instruction
        pub inline fn afterComplete(
            self: *Self,
            comptime opcode: Dispatch.UnifiedOpcode,
        ) void {
            (&self.getEvm().tracer).after_complete(self, opcode);
        }

        /// Pretty print the frame state for debugging and visualization.
        /// Shows stack, memory, gas, and other key state information with ANSI colors.
        pub fn pretty_print(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
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
            };

            var output = std.ArrayList(u8).initCapacity(allocator, 4096) catch return Error.AllocationError;
            const writer = output.writer(allocator);

            // Header
            try writer.print("{s}{s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ Colors.bold, Colors.cyan, Colors.reset });
            try writer.print("{s}{s}║                       FRAME STATE                               ║{s}\n", .{ Colors.bold, Colors.cyan, Colors.reset });
            try writer.print("{s}{s}╚══════════════════════════════════════════════════════════════╝{s}\n", .{ Colors.bold, Colors.cyan, Colors.reset });

            // Gas information
            try writer.print("\n{s}⛽ Gas:{s} ", .{ Colors.yellow, Colors.reset });
            if (self.gas_remaining > 1_000_000) {
                try writer.print("{s}{d:.2}M{s}", .{ Colors.green, @as(f64, @floatFromInt(self.gas_remaining)) / 1_000_000.0, Colors.reset });
            } else if (self.gas_remaining > 1_000) {
                try writer.print("{s}{d:.2}K{s}", .{ Colors.green, @as(f64, @floatFromInt(self.gas_remaining)) / 1_000.0, Colors.reset });
            } else if (self.gas_remaining > 100) {
                try writer.print("{s}{d}{s}", .{ Colors.green, self.gas_remaining, Colors.reset });
            } else {
                try writer.print("{s}{d}{s}", .{ Colors.red, self.gas_remaining, Colors.reset });
            }
            try writer.print("\n", .{});

            // Contract and caller addresses
            try writer.print("\n{s}📍 Contract:{s} {s}0x{s}{s}\n", .{ Colors.blue, Colors.reset, Colors.dim, std.fmt.bytesToHex(&self.contract_address.bytes, .lower), Colors.reset });
            try writer.print("{s}📞 Caller:{s}   {s}0x{s}{s}\n", .{ Colors.blue, Colors.reset, Colors.dim, std.fmt.bytesToHex(&self.caller.bytes, .lower), Colors.reset });

            // Value (if non-zero)
            if (self.value != 0) {
                try writer.print("{s}💰 Value:{s}    {s}{d}{s}\n", .{ Colors.magenta, Colors.reset, Colors.bold, self.value, Colors.reset });
            }

            // Stack visualization (simplified for now)
            try writer.print("\n{s}📚 Stack: (details available in debug mode){s}\n", .{ Colors.cyan, Colors.reset });

            // Memory visualization
            const mem_size = self.memory.size();
            try writer.print("\n{s}💾 Memory [{d} bytes]:{s}\n", .{ Colors.magenta, mem_size, Colors.reset });

            if (mem_size > 0) {
                const bytes_to_show = @min(mem_size, 64);
                const mem_slice = self.memory.get_slice(0, @intCast(bytes_to_show)) catch &[_]u8{};

                // Show memory in hex with ASCII representation
                var offset: usize = 0;
                while (offset < bytes_to_show) : (offset += 16) {
                    const end = @min(offset + 16, bytes_to_show);
                    const line = mem_slice[offset..end];

                    try writer.print("  {s}0x{x:0>4}:{s} ", .{ Colors.dim, offset, Colors.reset });

                    // Hex bytes
                    for (line) |byte| {
                        if (byte == 0) {
                            try writer.print("{s}00{s} ", .{ Colors.dim, Colors.reset });
                        } else {
                            try writer.print("{s}{x:0>2}{s} ", .{ Colors.white, byte, Colors.reset });
                        }
                    }

                    // Padding if line is short
                    var padding_needed = 16 - line.len;
                    while (padding_needed > 0) : (padding_needed -= 1) {
                        try writer.print("   ");
                    }

                    // ASCII representation
                    try writer.print(" {s}│{s}", .{ Colors.dim, Colors.reset });
                    for (line) |byte| {
                        if (byte >= 32 and byte < 127) {
                            try writer.print("{s}{c}{s}", .{ Colors.green, byte, Colors.reset });
                        } else if (byte == 0) {
                            try writer.print("{s}.{s}", .{ Colors.dim, Colors.reset });
                        } else {
                            try writer.print("{s}·{s}", .{ Colors.yellow, Colors.reset });
                        }
                    }
                    try writer.print("\n", .{});
                }

                if (mem_size > bytes_to_show) {
                    try writer.print("  {s}... {d} more bytes{s}\n", .{ Colors.dim, mem_size - bytes_to_show, Colors.reset });
                }
            } else {
                try writer.print("  {s}(empty){s}\n", .{ Colors.dim, Colors.reset });
            }

            const calldata_slice = self.calldata_slice;
            if (calldata_slice.len > 0) {
                try writer.print("\n{s}📥 Calldata [{d} bytes]:{s} ", .{ Colors.yellow, calldata_slice.len, Colors.reset });

                const calldata_preview_len = @min(calldata_slice.len, 32);
                for (calldata_slice[0..calldata_preview_len]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                if (calldata_slice.len > 32) {
                    try writer.print("...");
                }
                try writer.print("\n", .{});
            }

            try writer.print("\n{s}{s}════════════════════════════════════════════════════════════════{s}\n", .{ Colors.dim, Colors.cyan, Colors.reset });

            return try output.toOwnedSlice(allocator);
        }
    };
}
