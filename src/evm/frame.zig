//! Lightweight execution context for EVM operations.
//!
//! Frame handles direct opcode execution including stack manipulation,
//! arithmetic, memory access, and storage operations. It does NOT handle:
//! - PC tracking and jumps (managed by Plan)
//! - CALL/CREATE operations (managed by Host/EVM)
//! - Environment queries (provided by Host)
//!
//! The Frame is designed for efficient opcode dispatch with configurable
//! components for stack size, memory limits, and gas tracking.
const std = @import("std");
const builtin = @import("builtin");
const log = @import("../log.zig");
const memory_mod = @import("../memory/memory.zig");
const stack_mod = @import("../stack/stack.zig");
const opcode_data = @import("../opcodes/opcode_data.zig");
const Opcode = opcode_data.Opcode;
const OpcodeSynthetic = @import("../opcodes/opcode_synthetic.zig").OpcodeSynthetic;
pub const FrameConfig = @import("frame_config.zig").FrameConfig;
const Database = @import("database.zig").Database;
const Account = @import("database.zig").Account;
const MemoryDatabase = @import("memory_database.zig").MemoryDatabase;
const bytecode_mod = @import("../bytecode/bytecode.zig");
const BytecodeConfig = @import("../bytecode/bytecode_config.zig").BytecodeConfig;
const primitives = @import("primitives");
const GasConstants = primitives.GasConstants;
const Address = primitives.Address.Address;
const to_u256 = primitives.Address.to_u256;
const from_u256 = primitives.Address.from_u256;
const keccak_asm = @import("keccak_asm.zig");
const frame_handlers = @import("frame_handlers.zig");
const SelfDestruct = @import("self_destruct.zig").SelfDestruct;
const DefaultEvm = @import("evm.zig").DefaultEvm;
const call_params_mod = @import("call_params.zig");
const call_result_mod = @import("call_result.zig");
const logs = @import("logs.zig");
const Log = logs.Log;
// LogList functionality is inlined into Frame for optimal packing
const dispatch_mod = @import("dispatch.zig");
const keccak256 = @import("keccak_asm.zig").keccak256;

/// LRU cache for dispatch schedules to avoid recompiling bytecode
const DispatchCacheEntry = struct {
    /// Hash of the bytecode (first 32 bytes of keccak256)
    bytecode_hash: [32]u8,
    /// Cached dispatch schedule (owned by cache)
    schedule: []const u8,  // Store as raw bytes
    /// Cached jump table (owned by cache)  
    jump_table_entries: []const u8,  // Store as raw bytes
    /// Last access timestamp for LRU eviction
    last_access: u64,
    /// Reference count for concurrent usage
    ref_count: u32,
};

const DispatchCache = struct {
    const CACHE_SIZE = 256; // Number of cached contracts
    
    entries: [CACHE_SIZE]?DispatchCacheEntry = [_]?DispatchCacheEntry{null} ** CACHE_SIZE,
    allocator: std.mem.Allocator,
    access_counter: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    
    fn init(allocator: std.mem.Allocator) DispatchCache {
        return .{
            .allocator = allocator,
        };
    }
    
    fn deinit(self: *DispatchCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (&self.entries) |*entry_opt| {
            if (entry_opt.*) |*entry| {
                self.allocator.free(entry.schedule);
                self.allocator.free(entry.jump_table_entries);
                entry_opt.* = null;
            }
        }
    }
    
    fn computeHash(bytecode: []const u8) [32]u8 {
        var hash: [32]u8 = undefined;
        keccak256(bytecode, &hash) catch {
            // On error, return zero hash
            return [_]u8{0} ** 32;
        };
        return hash;
    }
    
    fn lookup(self: *DispatchCache, bytecode: []const u8) ?struct { schedule: []const u8, jump_table: []const u8 } {
        const hash = computeHash(bytecode);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.access_counter += 1;
        
        // Search for matching entry
        for (&self.entries) |*entry_opt| {
            if (entry_opt.*) |*entry| {
                if (std.mem.eql(u8, &entry.bytecode_hash, &hash)) {
                    // Found a hit
                    self.hits += 1;
                    entry.last_access = self.access_counter;
                    entry.ref_count += 1;
                    return .{
                        .schedule = entry.schedule,
                        .jump_table = entry.jump_table_entries,
                    };
                }
            }
        }
        
        self.misses += 1;
        return null;
    }
    
    fn insert(self: *DispatchCache, bytecode: []const u8, schedule: []const u8, jump_table: []const u8) !void {
        const hash = computeHash(bytecode);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Find slot to insert (either empty or LRU)
        var lru_idx: usize = 0;
        var lru_access: u64 = std.math.maxInt(u64);
        var empty_idx: ?usize = null;
        
        for (&self.entries, 0..) |*entry_opt, i| {
            if (entry_opt.* == null) {
                empty_idx = i;
                break;
            } else if (entry_opt.*.?.ref_count == 0 and entry_opt.*.?.last_access < lru_access) {
                lru_idx = i;
                lru_access = entry_opt.*.?.last_access;
            }
        }
        
        const target_idx = empty_idx orelse lru_idx;
        
        // Free old entry if replacing
        if (self.entries[target_idx]) |*old_entry| {
            if (old_entry.ref_count > 0) {
                // Skip if still in use
                return;
            }
            self.allocator.free(old_entry.schedule);
            self.allocator.free(old_entry.jump_table_entries);
        }
        
        // Copy schedule and jump table
        const schedule_copy = try self.allocator.dupe(u8, schedule);
        errdefer self.allocator.free(schedule_copy);
        
        const jump_table_copy = try self.allocator.dupe(u8, jump_table);
        
        // Insert new entry
        self.entries[target_idx] = DispatchCacheEntry{
            .bytecode_hash = hash,
            .schedule = schedule_copy,
            .jump_table_entries = jump_table_copy,
            .last_access = self.access_counter,
            .ref_count = 0,
        };
    }
    
    fn release(self: *DispatchCache, bytecode: []const u8) void {
        const hash = computeHash(bytecode);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (&self.entries) |*entry_opt| {
            if (entry_opt.*) |*entry| {
                if (std.mem.eql(u8, &entry.bytecode_hash, &hash)) {
                    if (entry.ref_count > 0) {
                        entry.ref_count -= 1;
                    }
                    return;
                }
            }
        }
    }
    
    fn getStatistics(self: *const DispatchCache) struct { hits: u64, misses: u64, hit_rate: f64 } {
        const total = self.hits + self.misses;
        const hit_rate = if (total > 0) @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total)) else 0.0;
        return .{
            .hits = self.hits,
            .misses = self.misses,
            .hit_rate = hit_rate,
        };
    }
    
    fn clear(self: *DispatchCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (&self.entries) |*entry_opt| {
            if (entry_opt.*) |*entry| {
                if (entry.ref_count == 0) {
                    self.allocator.free(entry.schedule);
                    self.allocator.free(entry.jump_table_entries);
                    entry_opt.* = null;
                }
            }
        }
        
        self.hits = 0;
        self.misses = 0;
        self.access_counter = 0;
    }
};

/// Global dispatch cache instance
var global_dispatch_cache: ?DispatchCache = null;
var cache_mutex: std.Thread.Mutex = .{};

/// Initialize the global dispatch cache
pub fn initGlobalCache(allocator: std.mem.Allocator) void {
    cache_mutex.lock();
    defer cache_mutex.unlock();
    
    if (global_dispatch_cache == null) {
        global_dispatch_cache = DispatchCache.init(allocator);
    }
}

/// Deinitialize the global dispatch cache
pub fn deinitGlobalCache() void {
    cache_mutex.lock();
    defer cache_mutex.unlock();
    
    if (global_dispatch_cache) |*cache| {
        cache.deinit();
        global_dispatch_cache = null;
    }
}

/// Get cache statistics
pub fn getCacheStatistics() ?struct { hits: u64, misses: u64, hit_rate: f64 } {
    cache_mutex.lock();
    defer cache_mutex.unlock();
    
    if (global_dispatch_cache) |*cache| {
        return cache.getStatistics();
    }
    return null;
}

/// Clear the cache (useful for testing or memory pressure)
pub fn clearGlobalCache() void {
    cache_mutex.lock();
    defer cache_mutex.unlock();
    
    if (global_dispatch_cache) |*cache| {
        cache.clear();
    }
}

/// Creates a configured Frame type for EVM execution.
///
/// The Frame is parameterized by compile-time configuration to enable
/// optimal code generation and platform-specific optimizations.
pub fn Frame(comptime config: FrameConfig) type {
    comptime config.validate();

    return struct {
        /// Error code type returned by Frame.interpret - includes both error and success termination cases
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
            Stop,
            Return,
            SelfDestruct,
        };
        const Self = @This();
        /// The type all opcode handlers return.
        /// Opcode handlers are expected to recursively dispatch the next opcode if they themselves don't error or return
        /// Takes cursor pointer with jump table available through dispatch metadata when needed
        pub const OpcodeHandler = *const fn (frame: *Self, cursor: [*]const Dispatch.Item) Error!noreturn;
        /// The struct in charge of efficiently dispatching opcode handlers and providing them metadata
        pub const Dispatch = dispatch_mod.Dispatch(Self);
        /// The config passed into Frame(config)
        pub const frame_config = config;

        /// Returns the appropriate tail call modifier based on the target architecture.
        /// WebAssembly doesn't support tail calls by default, so we use .auto for wasm targets.
        pub inline fn getTailCallModifier() std.builtin.CallModifier {
            return if (builtin.target.cpu.arch == .wasm32 or builtin.target.cpu.arch == .wasm64)
                .auto
            else
                .always_tail; // Must use always_tail for performance
        }
        /// The "word" type used by the evm. Defaults to u256. "Word" is the type used by Stack and throughout the Evm
        /// If set to something else the EVM will update to that new word size. e.g. run kekkak128 instead of kekkak256
        /// Lowering the word size can improve perf and bundle size
        pub const WordType = config.WordType;
        /// The type used to measure gas. Unsigned integer for perf reasons
        pub const GasType = config.GasType();
        /// The type used to index into bytecode or instructions. Determined by config.max_bytecode_size
        pub const PcType = config.PcType();
        /// The struct in charge of managing Evm memory
        pub const Memory = memory_mod.Memory(.{
            .initial_capacity = config.memory_initial_capacity,
            .memory_limit = config.memory_limit,
            .owned = true,
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
        pub const opcode_handlers: [256]OpcodeHandler = if (config.TracerType) |TracerType|
            frame_handlers.getTracedOpcodeHandlers(Self, TracerType)
        else
            frame_handlers.getOpcodeHandlers(Self);

        // Individual handler groups for testing and direct access
        pub const ArithmeticHandlers = @import("handlers_arithmetic.zig").Handlers(Self);
        pub const BitwiseHandlers = @import("handlers_bitwise.zig").Handlers(Self);
        pub const ComparisonHandlers = @import("handlers_comparison.zig").Handlers(Self);
        pub const ContextHandlers = @import("handlers_context.zig").Handlers(Self);
        pub const JumpHandlers = @import("handlers_jump.zig").Handlers(Self);
        pub const KeccakHandlers = @import("handlers_keccak.zig").Handlers(Self);
        pub const LogHandlers = @import("handlers_log.zig").Handlers(Self);
        pub const MemoryHandlers = @import("handlers_memory.zig").Handlers(Self);
        pub const StackHandlers = @import("handlers_stack.zig").Handlers(Self);
        pub const StorageHandlers = @import("handlers_storage.zig").Handlers(Self);
        pub const SystemHandlers = @import("handlers_system.zig").Handlers(Self);

        // Synthetic handler groups for optimized opcode fusion
        pub const ArithmeticSyntheticHandlers = @import("handlers_arithmetic_synthetic.zig").Handlers(Self);
        pub const BitwiseSyntheticHandlers = @import("handlers_bitwise_synthetic.zig").Handlers(Self);
        pub const MemorySyntheticHandlers = @import("handlers_memory_synthetic.zig").Handlers(Self);
        pub const JumpSyntheticHandlers = @import("handlers_jump_synthetic.zig").Handlers(Self);

        // CACHE LINE 1 (0-63 bytes) - ULTRA HOT PATH
        stack: Stack, // 16B - Stack operations
        gas_remaining: GasType, // 8B - Gas tracking (i64)
        memory: Memory, // 16B - Memory operations
        database: config.DatabaseType, // 8B - Storage access
        length_prefixed_calldata: ?[*]const u8, // 8B - Length-prefixed calldata pointer (first 8 bytes = length)
        evm_ptr: *anyopaque, // 8B - EVM instance pointer
        // CACHE LINE 2 (64-124 bytes) - WARM PATH
        value: *const WordType, // 8B - Call value (pointer)
        logs: std.ArrayListUnmanaged(Log), // 16B - Log array list (unmanaged)
        contract_address: Address = Address.ZERO_ADDRESS, // 20B - Current contract
        caller: Address, // 20B - Calling address
        // CACHE LINE 3+ (128+ bytes) - COLD PATH
        output: []u8, // 16B - Output data slice (only for RETURN/REVERT)
        code: []const u8 = &[_]u8{}, // Contract code (for CODESIZE/CODECOPY)
        authorized_address: ?Address = null, // 20B - EIP-3074 authorized address
        jump_table: Dispatch.JumpTable, // 24B - Jump table for JUMP/JUMPI validation (entries slice)

        //
        /// Initialize a new execution frame.
        ///
        /// Creates stack, memory, and other execution components. Allocates
        /// resources with proper cleanup on failure. Bytecode validation
        /// and analysis is now handled separately by dispatch initialization.
        ///
        /// Initialize a new execution frame.
        pub fn init(allocator: std.mem.Allocator, gas_remaining: GasType, database: config.DatabaseType, caller: Address, value: *const WordType, calldata_input: []const u8, evm_ptr: *anyopaque) Error!Self {
            // log.debug("Frame.init: gas={}, caller={any}, value={}, calldata_len={}, self_destruct={}", .{ gas_remaining, caller, value.*, calldata_input.len, self_destruct != null });
            var stack = Stack.init(allocator) catch {
                @branchHint(.cold);
                log.err("Frame.init: Failed to initialize stack", .{});
                return Error.AllocationError;
            };
            errdefer stack.deinit(allocator);
            var memory = Memory.init(allocator) catch {
                @branchHint(.cold);
                log.err("Frame.init: Failed to initialize memory", .{});
                return Error.AllocationError;
            };
            errdefer memory.deinit(allocator);

            // Create length-prefixed calldata
            const length_prefixed = if (calldata_input.len > 0) blk: {
                // Allocate space for length (8 bytes) + data
                const total_size = 8 + calldata_input.len;
                const buffer = allocator.alloc(u8, total_size) catch {
                    @branchHint(.cold);
                    log.err("Frame.init: Failed to allocate length-prefixed calldata", .{});
                    return Error.AllocationError;
                };
                errdefer allocator.free(buffer);

                // Write length as 8 bytes (little-endian)
                std.mem.writeInt(u64, buffer[0..8], calldata_input.len, .little);
                // Copy calldata
                @memcpy(buffer[8..], calldata_input);
                break :blk buffer.ptr;
            } else null;
            errdefer if (length_prefixed) |ptr| {
                const len = std.mem.readInt(u64, ptr[0..8], .little);
                allocator.free(ptr[0 .. 8 + len]);
            };

            // log.debug("Frame.init: Successfully initialized frame components", .{});
            return Self{
                // Cache line 1
                .stack = stack,
                .gas_remaining = std.math.cast(GasType, @max(gas_remaining, 0)) orelse return Error.InvalidAmount,
                .memory = memory,
                .database = database,
                .length_prefixed_calldata = length_prefixed,
                // Cache line 2
                .value = value,
                .contract_address = Address.ZERO_ADDRESS,
                .caller = caller,
                .logs = .{},
                .evm_ptr = evm_ptr,
                // Cache line 3+
                .output = &[_]u8{}, // Start with empty output
                .jump_table = .{ .entries = &[_]Dispatch.JumpTable.JumpTableEntry{} }, // Empty jump table
                .authorized_address = null,
            };
        }
        /// Clean up all frame resources.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            log.debug("Frame.deinit: Starting cleanup, logs_count={}, output_len={}", .{ self.logs.items.len, self.output.len });
            self.stack.deinit(allocator);
            self.memory.deinit(allocator);
            // No need to free any arena-allocated data (logs, output, calldata)
            // The arena allocator will be reset after the call completes
            log.debug("Frame.deinit: Cleanup complete", .{});
        }

        /// Execute this frame without tracing (backward compatibility method).
        /// Simply delegates to interpret_with_tracer with no tracer.
        /// @param bytecode_raw: Raw bytecode to execute
        pub fn interpret(self: *Self, bytecode_raw: []const u8) Error!void {
            return self.interpret_with_tracer(bytecode_raw, null, {});
        }

        /// Execute this frame by building a dispatch schedule and jumping to the first handler.
        /// Performs a one-time static gas charge for the first basic block before execution.
        ///
        /// @param bytecode_raw: Raw bytecode to execute
        /// @param TracerType: Optional comptime tracer type for zero-cost tracing abstraction
        /// @param tracer_instance: Instance of the tracer (ignored if TracerType is null)
        pub fn interpret_with_tracer(self: *Self, bytecode_raw: []const u8, comptime TracerType: ?type, tracer_instance: if (TracerType) |T| *T else void) Error!void {
            // log.debug("Frame.interpret_with_tracer: Starting execution, bytecode_len={}, gas={}", .{ bytecode_raw.len, self.gas_remaining });

            if (bytecode_raw.len > config.max_bytecode_size) {
                @branchHint(.unlikely);
                log.err("Frame.interpret_with_tracer: Bytecode too large: {} > max {}", .{ bytecode_raw.len, config.max_bytecode_size });
                return Error.BytecodeTooLarge;
            }

            // Store the raw code in the frame
            self.code = bytecode_raw;

            const allocator = self.getAllocator();
            
            // Either get from cache or create new dispatch
            var schedule: []const Dispatch.Item = undefined;
            var jump_table: Dispatch.JumpTable = undefined;
            var owned_schedule: ?Dispatch.DispatchSchedule = null;
            var owned_jump_table_entries: ?[]const Dispatch.JumpTable.JumpTableEntry = null;
            
            // Check cache first
            if (global_dispatch_cache) |*cache| {
                if (cache.lookup(bytecode_raw)) |cached_data| {
                    // Use cached data
                    schedule = @as([*]const Dispatch.Item, @ptrCast(@alignCast(cached_data.schedule.ptr)))[0..cached_data.schedule.len / @sizeOf(Dispatch.Item)];
                    const jump_table_entries = @as([*]const Dispatch.JumpTable.JumpTableEntry, @ptrCast(@alignCast(cached_data.jump_table.ptr)))[0..cached_data.jump_table.len / @sizeOf(Dispatch.JumpTable.JumpTableEntry)];
                    jump_table = .{ .entries = jump_table_entries };
                    
                    // Release cache entry when done
                    defer cache.release(bytecode_raw);
                } else {
                    // Cache miss - create new dispatch
                    var bytecode = Bytecode.init(allocator, bytecode_raw) catch |e| {
                        @branchHint(.unlikely);
                        log.err("Frame.interpret_with_tracer: Bytecode init failed: {}", .{e});
                        return switch (e) {
                            error.BytecodeTooLarge => Error.BytecodeTooLarge,
                            error.InvalidOpcode => Error.InvalidOpcode,
                            error.InvalidJumpDestination => Error.InvalidJump,
                            error.TruncatedPush => Error.InvalidOpcode,
                            error.OutOfMemory => Error.AllocationError,
                            else => Error.AllocationError,
                        };
                    };
                    defer bytecode.deinit();
                    
                    const handlers = &Self.opcode_handlers;
                    
                    // Create dispatch schedule
                    owned_schedule = Dispatch.DispatchSchedule.init(allocator, &bytecode, handlers) catch |e| {
                        log.err("Frame.interpret_with_tracer: Failed to create dispatch schedule: {}", .{e});
                        return Error.AllocationError;
                    };
                    schedule = owned_schedule.?.items;
                    
                    // Create jump table
                    const jt = Dispatch.createJumpTable(allocator, schedule, &bytecode) catch return Error.AllocationError;
                    owned_jump_table_entries = jt.entries;
                    jump_table = jt;
                    
                    // Try to cache it
                    const schedule_bytes = std.mem.sliceAsBytes(schedule);
                    const jump_table_bytes = std.mem.sliceAsBytes(jump_table.entries);
                    cache.insert(bytecode_raw, schedule_bytes, jump_table_bytes) catch {
                        // Cache insertion failed, continue without caching
                        log.debug("Failed to cache dispatch schedule for bytecode", .{});
                    };
                }
            } else {
                // No cache available - create new dispatch
                var bytecode = Bytecode.init(allocator, bytecode_raw) catch |e| {
                    @branchHint(.unlikely);
                    log.err("Frame.interpret_with_tracer: Bytecode init failed: {}", .{e});
                    return switch (e) {
                        error.BytecodeTooLarge => Error.BytecodeTooLarge,
                        error.InvalidOpcode => Error.InvalidOpcode,
                        error.InvalidJumpDestination => Error.InvalidJump,
                        error.TruncatedPush => Error.InvalidOpcode,
                        error.OutOfMemory => Error.AllocationError,
                        else => Error.AllocationError,
                    };
                };
                defer bytecode.deinit();
                
                const handlers = &Self.opcode_handlers;
                
                // Create dispatch schedule
                owned_schedule = Dispatch.DispatchSchedule.init(allocator, &bytecode, handlers) catch |e| {
                    log.err("Frame.interpret_with_tracer: Failed to create dispatch schedule: {}", .{e});
                    return Error.AllocationError;
                };
                schedule = owned_schedule.?.items;
                
                // Create jump table
                const jt = Dispatch.createJumpTable(allocator, schedule, &bytecode) catch return Error.AllocationError;
                owned_jump_table_entries = jt.entries;
                jump_table = jt;
            }
            
            // Clean up owned resources when done
            defer {
                if (owned_schedule) |*s| s.deinit();
                if (owned_jump_table_entries) |entries| allocator.free(entries);
            }
            
            // Setup tracer if needed
            if (TracerType) |_| {
                frame_handlers.setTracerInstance(tracer_instance);
            }
            defer {
                if (TracerType != null) {
                    frame_handlers.clearTracerInstance();
                }
            }

            // Store jump table in frame for JUMP/JUMPI handlers
            self.jump_table = jump_table;

            // Handle first_block_gas
            var start_index: usize = 0;
            if (schedule.len > 0) {
                switch (schedule[0]) {
                    .first_block_gas => |meta| {
                        if (meta.gas > 0) {
                            try self.consumeGasChecked(@intCast(meta.gas));
                        }
                        start_index = 1;
                    },
                    else => {},
                }
            }

            const cursor = Dispatch{ .cursor = schedule.ptr + start_index };

            // Verify bytecode stream ends with 2 stop handlers (debug builds only)
            if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
                if (schedule.len >= 2) {
                    const last_item = schedule[schedule.len - 1];
                    const second_last_item = schedule[schedule.len - 2];

                    // With traced handlers we can't directly compare, so skip this check when tracing
                    if (TracerType == null) {
                        const stop_handler = Self.opcode_handlers[@intFromEnum(Opcode.STOP)];
                        if (last_item.opcode_handler != stop_handler or second_last_item.opcode_handler != stop_handler) {
                            log.err("Frame.interpret_with_tracer: Bytecode stream does not end with 2 stop handlers", .{});
                            return Error.InvalidOpcode;
                        }
                    }
                } else {
                    log.err("Frame.interpret_with_tracer: Bytecode stream too short", .{});
                    return Error.InvalidOpcode;
                }
            }

            // log.debug("Frame.interpret_with_tracer: Starting execution, gas={}", .{self.gas_remaining});

            try cursor.cursor[0].opcode_handler(self, cursor.cursor);
            unreachable; // Handlers never return normally
        }

        /// Create a deep copy of the frame.
        /// This is used by DebugPlan to create a sidecar frame for validation.
        pub fn copy(self: *const Self, allocator: std.mem.Allocator) Error!Self {
            log.debug("Frame.copy: Creating deep copy, stack_size={}, memory_size={}, logs_count={}", .{ self.stack.get_slice().len, self.memory.size(), self.logs.items.len });
            var new_stack = Stack.init(allocator) catch return Error.AllocationError;
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

            var new_logs = std.ArrayListUnmanaged(Log){};
            errdefer new_logs.deinit(allocator);

            for (self.logs.items) |log_entry| {
                const topics_copy = allocator.dupe(u256, log_entry.topics) catch return Error.AllocationError;
                errdefer allocator.free(topics_copy);

                const data_copy = allocator.dupe(u8, log_entry.data) catch return Error.AllocationError;
                errdefer allocator.free(data_copy);

                try new_logs.append(allocator, Log{
                    .address = log_entry.address,
                    .topics = topics_copy,
                    .data = data_copy,
                });
            }

            const new_output = if (self.output.len > 0) blk: {
                const output_copy = allocator.alloc(u8, self.output.len) catch return Error.AllocationError;
                @memcpy(output_copy, self.output);
                break :blk output_copy;
            } else &[_]u8{};

            log.debug("Frame.copy: Deep copy complete", .{});
            return Self{
                .stack = new_stack,
                .gas_remaining = self.gas_remaining,
                .memory = new_memory,
                .database = self.database,
                .logs = new_logs,
                .evm_ptr = self.evm_ptr,
                .caller = self.caller,
                .value = self.value,
                .contract_address = self.contract_address,
                .output = new_output,
                .length_prefixed_calldata = self.length_prefixed_calldata,
                .jump_table = self.jump_table,
                .authorized_address = self.authorized_address,
            };
        }

        /// Consume gas without checking (for use after static analysis)
        ///
        /// Safety: This function clamps the amount to fit in GasType, but in practice
        /// this should never happen because:
        /// 1. Block gas limits are typically 30M (well below i32 max of ~2.1B)
        /// 2. You would run out of gas (gas_remaining < 0) long before hitting the clamp
        /// 3. Gas costs are designed to fit in u32, making clamping unnecessary
        pub fn consumeGasUnchecked(self: *Self, amount: u32) void {
            // Compile-time verification that clamping is practically unnecessary
            comptime {
                // With typical block gas limit of 30M and i32, we have plenty of headroom
                if (frame_config.block_gas_limit <= std.math.maxInt(i32)) {
                    // Ensure no single gas cost exceeds what i32 can hold
                    // This is a sanity check - all EVM gas costs are well below this
                    std.debug.assert(std.math.maxInt(u32) < std.math.maxInt(i32));
                }
            }

            // In practice, amount should always fit in GasType since we use u32
            // The clamp is defensive programming for edge cases
            const clamped_amount = @min(amount, std.math.maxInt(GasType));
            self.gas_remaining -= @as(GasType, @intCast(clamped_amount));
        }

        /// Consume gas with bounds checking and safe casting
        /// Returns GasOverflow if amount doesn't fit in GasType (extremely rare)
        /// Returns OutOfGas if insufficient gas remaining
        pub fn consumeGasChecked(self: *Self, amount: u32) Error!void {
            // Cast to GasType - should always succeed with u32 input
            // Only fails if GasType is smaller than u32 (impossible with current config)
            const amt = std.math.cast(GasType, amount) orelse {
                log.err("Frame.consumeGasChecked: Gas overflow, amount={} doesn't fit in GasType", .{amount});
                return Error.GasOverflow;
            };

            // Check if we have enough gas
            if (amt > self.gas_remaining) {
                log.debug("Frame.consumeGasChecked: Out of gas, required={}, remaining={}", .{ amt, self.gas_remaining });
                return Error.OutOfGas;
            }

            self.gas_remaining -= amt;
        }

        /// Get calldata as a slice from the length-prefixed pointer.
        /// Returns empty slice if no calldata is present.
        pub inline fn calldata(self: *const Self) []const u8 {
            const ptr = self.length_prefixed_calldata orelse return &[_]u8{};
            // Read length from first 8 bytes
            const len = std.mem.readInt(u64, ptr[0..8], .little);
            // Return slice starting after length prefix
            return ptr[8 .. 8 + len];
        }

        /// Get the EVM instance from the opaque pointer
        pub inline fn getEvm(self: *const Self) *DefaultEvm {
            return @as(*DefaultEvm, @ptrCast(@alignCast(self.evm_ptr)));
        }

        /// Get the arena allocator for temporary allocations during execution
        pub inline fn getAllocator(self: *const Self) std.mem.Allocator {
            return self.getEvm().getCallArenaAllocator();
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
            if (self.value.* != 0) {
                try writer.print("{s}💰 Value:{s}    {s}{d}{s}\n", .{ Colors.magenta, Colors.reset, Colors.bold, self.value.*, Colors.reset });
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

            // Calldata preview (if present)
            const calldata_slice = self.calldata();
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

            // Logs count
            if (self.logs.items.len > 0) {
                try writer.print("\n{s}📝 Logs:{s} {d} events\n", .{ Colors.cyan, Colors.reset, self.logs.items.len });
            }

            // Output data (if any)
            if (self.output.len > 0) {
                try writer.print("\n{s}📤 Output [{d} bytes]:{s} ", .{ Colors.green, self.output.len, Colors.reset });

                const output_preview_len = @min(self.output.len, 32);
                for (self.output[0..output_preview_len]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                if (self.output.len > 32) {
                    try writer.print("...");
                }
                try writer.print("\n", .{});
            }

            // Footer
            try writer.print("\n{s}{s}════════════════════════════════════════════════════════════════{s}\n", .{ Colors.dim, Colors.cyan, Colors.reset });

            return try output.toOwnedSlice(allocator);
        }
    };
}
