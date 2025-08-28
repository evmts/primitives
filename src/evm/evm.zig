//! Transaction-level EVM execution and state management.
//!
//! The EVM orchestrates contract execution, managing:
//! - Call depth tracking and nested execution contexts
//! - State journaling for transaction reverts
//! - Gas accounting and metering
//! - Contract creation (CREATE/CREATE2)
//! - Cross-contract calls (CALL/DELEGATECALL/STATICCALL)
//! - Integration with Host interface for environment queries
//!
//! This module provides the entry point for all EVM operations,
//! coordinating between Frames, the Planner, and state storage.
//!
//! The EVM utilizes Planners to analyze bytecode and produce optimized execution data structures
//! The EVM utilizes the Frame struct to track the evm state and implement all low level execution details
//! EVM passes itself as a host to the Frame so Frame can get data from EVM that is not on frame and execute inner calls
const std = @import("std");
const primitives = @import("primitives");
const BlockInfo = @import("block_info.zig").DefaultBlockInfo; // Default for backward compatibility
const DatabaseInterface = @import("database_interface.zig").DatabaseInterface;
const Account = @import("database_interface_account.zig").Account;
const SelfDestruct = @import("self_destruct.zig").SelfDestruct;
const CreatedContracts = @import("created_contracts.zig").CreatedContracts;
const MemoryDatabase = @import("memory_database.zig").MemoryDatabase;
const AccessList = @import("access_list.zig").AccessList;
const Hardfork = @import("hardfork.zig").Hardfork;
const precompiles = @import("precompiles.zig");
const EvmConfig = @import("evm_config.zig").EvmConfig;
const TransactionContext = @import("transaction_context.zig").TransactionContext;
const Opcode = @import("opcode.zig").Opcode;
pub const CallResult: type = @import("call_result.zig").CallResult;
pub const CallParams: type = @import("call_params.zig").CallParams;

/// Creates a configured EVM instance type.
///
/// The EVM is parameterized by compile-time configuration for optimal
/// performance and minimal runtime overhead. Configuration controls
/// stack size, memory limits, call depth, and optimization strategies.
pub fn Evm(comptime config: EvmConfig) type {
    return struct {
        const Self = @This();

        /// StackFrame type for the evm
        pub const Frame = @import("frame.zig").Frame(config.frame_config);
        /// Bytecode type for bytecode analysis
        pub const BytecodeFactory = @import("bytecode.zig").Bytecode;
        pub const Bytecode = BytecodeFactory(.{
            .max_bytecode_size = config.frame_config.max_bytecode_size,
            .fusions_enabled = false, // Disable fusions for now
        });
        /// Journal handles reverting state when state needs to be reverted
        pub const Journal: type = @import("journal.zig").Journal(.{
            .SnapshotIdType = if (config.max_call_depth <= 255) u8 else u16,
            .WordType = config.frame_config.WordType,
            .NonceType = u64,
            .initial_capacity = 128,
        });

        /// Call stack entry to track caller and value for DELEGATECALL
        const CallStackEntry = struct {
            caller: primitives.Address,
            value: config.frame_config.WordType,
        };

        pub const Success = enum {
            Stop,
            Return,
            SelfDestruct,
            Jump, // Added for fusion support
        };

        pub const Error = error{
            InvalidJump,
            OutOfGas,
            StackUnderflow,
            StackOverflow,
            ContractNotFound,
            PrecompileError,
            MemoryError,
            StorageError,
            CallDepthExceeded,
            InsufficientBalance,
            ContractCollision,
            InvalidBytecode,
            StaticCallViolation,
            InvalidOpcode,
            RevertExecution,
            OutOfMemory,
            // Removed Stop error - it's a success case
            AllocationError,
            AccountNotFound,
            InvalidJumpDestination,
            MissingJumpDestMetadata,
            InitcodeTooLarge,
            TruncatedPush,
            OutOfBounds,
            WriteProtection,
            BytecodeTooLarge,
        };

        // CACHE LINE 1 - HOT PATH (frequently accessed during execution)
        /// Current call depth (0 = root call)
        depth: config.get_depth_type(),
        /// Current snapshot ID for the active call frame
        current_snapshot_id: Journal.SnapshotIdType,
        /// Database interface for state storage
        database: DatabaseInterface,
        /// Journal for tracking state changes and snapshots
        journal: Journal,
        /// Allocator for dynamic memory
        allocator: std.mem.Allocator,

        // CACHE LINE 2 - TRANSACTION EXECUTION STATE
        /// Access list for tracking warm/cold access (EIP-2929)
        access_list: AccessList,
        /// Tracks contracts created in current transaction (EIP-6780)
        created_contracts: CreatedContracts,
        /// Contracts marked for self-destruction
        self_destruct: SelfDestruct,
        /// Current call input data
        current_input: []const u8,
        /// Current return data
        return_data: []const u8,

        // CACHE LINE 3 - TRANSACTION CONTEXT
        /// Block information
        block_info: BlockInfo,
        /// Transaction context
        context: TransactionContext,
        /// Gas price for the transaction
        gas_price: u256,
        /// Origin address (sender of the transaction)
        origin: primitives.Address,
        /// Hardfork configuration
        hardfork_config: Hardfork,

        // CACHE LINE 4+ - COLD PATH (less frequently accessed)
        /// Logs emitted during the current call
        logs: std.ArrayList(@import("call_result.zig").Log),
        /// Static context stack - tracks if each call depth is static
        static_stack: [config.max_call_depth]bool,
        /// Call stack - tracks caller and value for each call depth
        call_stack: [config.max_call_depth]CallStackEntry,
        /// Arena allocator for per-call temporary allocations
        internal_arena: std.heap.ArenaAllocator,
        /// Small reusable buffer for fixed-size outputs (e.g., 32-byte address)
        small_output_buf: [64]u8 = undefined,

        /// Initialize a new EVM instance.
        ///
        /// Sets up the execution environment with state storage, block context,
        /// and transaction parameters. The planner cache is initialized with
        /// a default size for bytecode optimization.
        pub fn init(allocator: std.mem.Allocator, database: DatabaseInterface, block_info: BlockInfo, context: TransactionContext, gas_price: u256, origin: primitives.Address, hardfork_config: Hardfork) !Self {
            var access_list = AccessList.init(allocator);
            errdefer access_list.deinit();
            return Self{
                .depth = 0,
                .static_stack = [_]bool{false} ** config.max_call_depth,
                .call_stack = [_]CallStackEntry{CallStackEntry{ .caller = primitives.Address.ZERO_ADDRESS, .value = 0 }} ** config.max_call_depth,
                .allocator = allocator,
                .database = database,
                .journal = Journal.init(allocator),
                .created_contracts = CreatedContracts.init(allocator),
                .self_destruct = SelfDestruct.init(allocator),
                .access_list = access_list,
                .block_info = block_info,
                .context = context,
                .current_input = &.{},
                .return_data = &.{},
                .gas_price = gas_price,
                .origin = origin,
                .hardfork_config = hardfork_config,
                .current_snapshot_id = 0,
                .logs = std.ArrayList(@import("call_result.zig").Log){},
                .internal_arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        /// Clean up all resources.
        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.created_contracts.deinit();
            self.self_destruct.deinit();
            self.access_list.deinit();
            self.logs.deinit(self.allocator);
            self.internal_arena.deinit();
        }

        /// Get the arena allocator for temporary allocations during the current call.
        /// This allocator is reset after each root call completes.
        pub fn getCallArenaAllocator(self: *Self) std.mem.Allocator {
            return self.internal_arena.allocator();
        }

        /// Transfer value between accounts with proper balance checks and error handling
        fn doTransfer(self: *Self, from: primitives.Address, to: primitives.Address, value: u256, snapshot_id: Journal.SnapshotIdType) !void {
            var from_account = try self.database.get_account(from.bytes) orelse Account.zero();
            if (from_account.balance < value) return error.InsufficientBalance;
            var to_account = try self.database.get_account(to.bytes) orelse Account.zero();
            try self.journal.record_balance_change(snapshot_id, from, from_account.balance);
            try self.journal.record_balance_change(snapshot_id, to, to_account.balance);
            from_account.balance -= value;
            to_account.balance += value;
            try self.database.set_account(from.bytes, from_account);
            try self.database.set_account(to.bytes, to_account);
        }

        /// Execute an EVM operation.
        ///
        /// This is the main entry point that routes to specific handlers based
        /// on the operation type (CALL, CREATE, etc). Manages transaction-level
        /// state including logs and ensures proper cleanup.
        pub fn call(self: *Self, params: CallParams) CallResult {
            params.validate() catch return CallResult.failure(0);
            defer self.depth = 0;
            defer _ = self.internal_arena.reset(.retain_capacity);
            defer self.logs.clearRetainingCapacity();
            const gas = switch (params) {
                inline else => |p| p.gas,
            };
            if (gas == 0) return CallResult.failure(0);
            if (self.depth >= config.max_call_depth) return CallResult.failure(0);
            var result = switch (params) {
                .call => |p| self.call_handler(p) catch |err| return self.handle_call_error(err, 0),
                .callcode => |p| self.callcode_handler(p) catch |err| return self.handle_call_error(err, 0),
                .delegatecall => |p| self.delegatecall_handler(p) catch |err| return self.handle_call_error(err, 0),
                .staticcall => |p| self.staticcall_handler(p) catch |err| return self.handle_call_error(err, 0),
                .create => |p| self.create_handler(p) catch |err| return self.handle_call_error(err, 0),
                .create2 => |p| self.create2_handler(p) catch |err| return self.handle_call_error(err, 0),
            };
            result.logs = self.takeLogs();
            return result;
        }

        /// Helper method to convert errors to CallResult failures
        fn handle_call_error(self: *Self, err: anyerror, gas_left: u64) CallResult {
            _ = self;
            // Log the error if needed, but return a simple failure
            std.debug.print("Call failed with error: {}\n", .{err});
            return CallResult.failure(gas_left);
        }

        // TODO: this shouldn't be pub
        // TODO: params should be CallParams.call
        /// CALL operation
        ///
        /// Transfers value from caller to target and executes target contract code.
        /// Creates a new execution context with the target's storage. Supports
        /// precompiled contracts and handles state reverts on failure.
        pub fn call_handler(self: *Self, params: anytype) Error!CallResult {
            // TODO we can move the snapshot_id value check and trasnfer to call
            const snapshot_id = self.journal.create_snapshot();
            if (params.value > 0) {
                self.doTransfer(params.caller, params.to, params.value, snapshot_id) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
            }

            if (config.enable_precompiles and precompiles.is_precompile(params.to)) {
                if (params.value > 0) {}
                const result = self.execute_precompile_call(params.to, params.input, params.gas, false) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
                if (!result.success) {
                    @branchHint(.unlikely);
                    self.journal.revert_to_snapshot(snapshot_id);
                }
                return result;
            }
            const code = self.database.get_code_by_address(params.to.bytes) catch &.{};
            // TODO: CallResult should have an enum success case for this so we can tell and we should debug log
            if (code.len == 0) return CallResult.success_empty(params.gas);
            const result = self.execute_frame(
                code,
                params.input,
                params.gas,
                params.to,
                params.caller,
                params.value,
                false, // is_static
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            };
            if (!result.success) self.journal.revert_to_snapshot(snapshot_id);
            return result;
        }

        /// Execute a CALLCODE operation.
        ///
        /// Executes target contract code in the caller's storage context.
        /// Unlike DELEGATECALL, msg.sender remains the direct caller.
        /// Deprecated in favor of DELEGATECALL but maintained for compatibility.
        pub fn callcode_handler(self: *Self, params: anytype) Error!CallResult {
            // TODO we can move the snapshot_id value check and trasnfer to call
            const snapshot_id = self.journal.create_snapshot();
            if (params.value > 0) {
                const caller_account = self.database.get_account(params.caller.bytes) catch |err| {
                    @branchHint(.cold);
                    return self.revert_and_fail(snapshot_id, err);
                };

                if (caller_account == null or caller_account.?.balance < params.value) {
                    @branchHint(.unlikely);
                    self.journal.revert_to_snapshot(snapshot_id);
                    return CallResult.failure(0);
                }
            }

            const code = self.database.get_code_by_address(params.to.bytes) catch &.{};

            // If no code, it's a simple value transfer to self
            if (code.len == 0) {
                @branchHint(.unlikely);
                return CallResult.success_empty(params.gas);
            }

            // CALLCODE executes the target's code in the caller's context (storage/address)
            // This is different from DELEGATECALL which also preserves msg.sender
            const result = self.execute_frame(
                code,
                params.input,
                params.gas,
                params.caller, // Execute in caller's context, not target
                params.caller, // msg.sender is still the caller
                params.value,
                false, // is_static
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            };

            if (!result.success) {
                @branchHint(.unlikely);
                self.journal.revert_to_snapshot(snapshot_id);
            }

            return result;
        }

        // TODO every one of these handlers can just be inlined in call
        /// DELEGATECALL operation
        pub fn delegatecall_handler(self: *Self, params: anytype) Error!CallResult {
            // Create snapshot for state reversion
            const snapshot_id = self.journal.create_snapshot();

            // Check if it's a precompile
            if (config.enable_precompiles and precompiles.is_precompile(params.to)) {
                // For precompiles in delegatecall, we still execute with preserved context
                const result = self.execute_precompile_call(params.to, params.input, params.gas, false) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };

                if (!result.success) {
                    self.journal.revert_to_snapshot(snapshot_id);
                }

                return result;
            }

            // Get contract code
            const code = self.database.get_code_by_address(params.to.bytes) catch &.{};

            // If no code, it's an empty call
            if (code.len == 0) {
                return CallResult.success_empty(params.gas);
            }

            // DELEGATECALL preserves the original caller and value from parent context
            // This is the key difference from CALL - the called code executes with caller's context
            // Get the current call's value to preserve it
            const current_value = if (self.depth > 0) self.call_stack[self.depth - 1].value else 0;
            const result = self.execute_frame(
                code,
                params.input,
                params.gas,
                params.to,
                params.caller, // Preserve original caller
                current_value, // Preserve value from parent context
                false, // is_static
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            };

            if (!result.success) {
                self.journal.revert_to_snapshot(snapshot_id);
            }

            return result;
        }

        /// STATICCALL operation
        pub fn staticcall_handler(self: *Self, params: anytype) Error!CallResult {

            // Create snapshot for state reversion
            const snapshot_id = self.journal.create_snapshot();

            // Check if it's a precompile
            if (config.enable_precompiles and precompiles.is_precompile(params.to)) {
                const result = self.execute_precompile_call(params.to, params.input, params.gas, true) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };

                if (!result.success) {
                    self.journal.revert_to_snapshot(snapshot_id);
                }

                return result;
            }

            // Get contract code
            const code = self.database.get_code_by_address(params.to.bytes) catch &.{};

            // If no code, it's an empty call (no value transfer in static)
            if (code.len == 0) {
                return CallResult.success_empty(params.gas);
            }

            // Execute contract code in static mode
            const result = self.execute_frame(
                code,
                params.input,
                params.gas,
                params.to,
                params.caller,
                0, // No value in static call
                true, // is_static = true
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                // In static context, any error is a failure
                return CallResult.failure(0);
            };

            if (!result.success) {
                self.journal.revert_to_snapshot(snapshot_id);
            }

            return result;
        }

        /// CREATE operation
        pub fn create_handler(self: *Self, params: anytype) Error!CallResult {
            // Create snapshot for state reversion
            const snapshot_id = self.journal.create_snapshot();

            // Get caller account
            var caller_account = self.database.get_account(params.caller.bytes) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            } orelse Account.zero();

            // Check if caller has sufficient balance
            if (caller_account.balance < params.value) {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            }

            // Calculate contract address from sender and nonce
            const contract_address = primitives.Address.get_contract_address(params.caller, caller_account.nonce);

            // Check if address already has code (collision)
            const existed_before = self.database.account_exists(contract_address.bytes);
            if (existed_before) {
                const existing = self.database.get_account(contract_address.bytes) catch null;
                if (existing != null and !std.mem.eql(u8, &existing.?.code_hash, &[_]u8{0} ** 32)) {
                    self.journal.revert_to_snapshot(snapshot_id);
                    return CallResult.failure(0);
                }
            }

            // Record and increment caller's nonce
            try self.journal.record_nonce_change(snapshot_id, params.caller, caller_account.nonce);
            caller_account.nonce += 1;
            self.database.set_account(params.caller.bytes, caller_account) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            };

            // Track created contract for EIP-6780
            try self.created_contracts.mark_created(contract_address);

            // Gas cost for CREATE
            const GasConstants = primitives.GasConstants;
            const create_gas = GasConstants.CreateGas; // 32000

            if (params.gas < create_gas) {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            }

            const remaining_gas = params.gas - create_gas;

            // Transfer value to the new contract before executing init code (per spec)
            if (params.value > 0) {
                self.doTransfer(params.caller, contract_address, params.value, snapshot_id) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
            }

            // Execute initialization code via IR interpreter for robustness
            const result = self.execute_init_code(
                params.init_code,
                remaining_gas,
                contract_address,
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            };

            if (!result.success) {
                self.journal.revert_to_snapshot(snapshot_id);
                return result;
            }

            // Ensure contract account exists and set nonce to 1
            var contract_account = self.database.get_account(contract_address.bytes) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            } orelse Account.zero();
            // For a new account, record creation
            if (!existed_before) {
                try self.journal.record_account_created(snapshot_id, contract_address);
            }
            // Set nonce to 1 for contract accounts
            if (contract_account.nonce != 1) {
                try self.journal.record_nonce_change(snapshot_id, contract_address, contract_account.nonce);
                contract_account.nonce = 1;
            }
            // Store the deployed code (empty code is allowed)
            if (result.output.len > 0) {
                const code_hash_bytes = self.database.set_code(result.output) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
                // Journal code change
                try self.journal.record_code_change(snapshot_id, contract_address, contract_account.code_hash);
                contract_account.code_hash = code_hash_bytes;
            }
            self.database.set_account(contract_address.bytes, contract_account) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            };

            // Return the contract address as 32 bytes (12 zero padding + 20-byte address)
            const out32 = self.small_output_buf[0..32];
            @memset(out32[0..12], 0);
            @memcpy(out32[12..32], &contract_address.bytes);
            return CallResult.success_with_output(result.gas_left, out32);
        }

        /// CREATE2 operation
        pub fn create2_handler(self: *Self, params: anytype) Error!CallResult {
            // Check depth
            if (self.depth >= config.max_call_depth) {
                return CallResult.failure(0);
            }

            // Create snapshot for state reversion
            const snapshot_id = self.journal.create_snapshot();

            // Get caller account
            const caller_account = self.database.get_account(params.caller.bytes) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            } orelse Account.zero();

            // Check if caller has sufficient balance
            if (caller_account.balance < params.value) {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            }

            // Calculate contract address from sender, salt, and init code hash
            const keccak_asm = @import("keccak_asm.zig");
            var init_code_hash_bytes: [32]u8 = undefined;
            try keccak_asm.keccak256(params.init_code, &init_code_hash_bytes);
            const salt_bytes = @as([32]u8, @bitCast(params.salt));
            const contract_address = primitives.Address.get_create2_address(params.caller, salt_bytes, init_code_hash_bytes);

            // Check if address already has code (collision)
            const existed_before2 = self.database.account_exists(contract_address.bytes);
            if (existed_before2) {
                const existing = self.database.get_account(contract_address.bytes) catch null;
                if (existing != null and !std.mem.eql(u8, &existing.?.code_hash, &[_]u8{0} ** 32)) {
                    self.journal.revert_to_snapshot(snapshot_id);
                    return CallResult.failure(0);
                }
            }

            // Track created contract for EIP-6780
            try self.created_contracts.mark_created(contract_address);

            // Gas cost for CREATE2
            const GasConstants = primitives.GasConstants;
            const create_gas = GasConstants.CreateGas; // 32000
            const hash_cost = @as(u64, @intCast(params.init_code.len)) * GasConstants.Keccak256WordGas / 32;
            const total_gas = create_gas + hash_cost;

            if (params.gas < total_gas) {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            }

            const remaining_gas = params.gas - total_gas;

            // Transfer value to the new contract before executing init code
            if (params.value > 0) {
                self.doTransfer(params.caller, contract_address, params.value, snapshot_id) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
            }

            // Execute initialization code via IR interpreter for robustness
            const result = self.execute_init_code(
                params.init_code,
                remaining_gas,
                contract_address,
                snapshot_id,
            ) catch {
                self.journal.revert_to_snapshot(snapshot_id);
                return CallResult.failure(0);
            };

            if (!result.success) {
                self.journal.revert_to_snapshot(snapshot_id);
                return result;
            }

            // Ensure contract account exists and set nonce/code
            var contract_account2 = self.database.get_account(contract_address.bytes) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            } orelse Account.zero();
            // Record creation for new accounts
            if (!existed_before2) {
                try self.journal.record_account_created(snapshot_id, contract_address);
            }
            // Set nonce to 1 for contracts
            if (contract_account2.nonce != 1) {
                try self.journal.record_nonce_change(snapshot_id, contract_address, contract_account2.nonce);
                contract_account2.nonce = 1;
            }
            if (result.output.len > 0) {
                const stored_hash = self.database.set_code(result.output) catch |err| {
                    return self.revert_and_fail(snapshot_id, err);
                };
                try self.journal.record_code_change(snapshot_id, contract_address, contract_account2.code_hash);
                contract_account2.code_hash = stored_hash;
            }
            self.database.set_account(contract_address.bytes, contract_account2) catch |err| {
                return self.revert_and_fail(snapshot_id, err);
            };

            // Return the contract address as 32 bytes (12 zero padding + 20-byte address)
            const out32 = self.small_output_buf[0..32];
            @memset(out32[0..12], 0);
            @memcpy(out32[12..32], &contract_address.bytes);
            return CallResult.success_with_output(result.gas_left, out32);
        }

        /// Execute frame using bytecode iterator-based execution
        ///
        /// This function orchestrates the execution of EVM bytecode within a frame context,
        /// managing the flow of host operations, static mode enforcement, and state journaling.
        ///
        /// The new implementation uses a bytecode iterator to traverse and execute opcodes
        /// directly, building handler arrays and constants on demand instead of pre-planning.
        fn execute_frame(
            self: *Self,
            code: []const u8,
            input: []const u8,
            gas: u64,
            address: primitives.Address,
            caller: primitives.Address,
            value: u256,
            is_static: bool,
            snapshot_id: Journal.SnapshotIdType,
        ) !CallResult {
            // Bind snapshot and call input for this frame duration
            const prev_snapshot = self.current_snapshot_id;
            self.current_snapshot_id = snapshot_id;
            defer self.current_snapshot_id = prev_snapshot;

            const prev_input = self.current_input;
            self.current_input = input;
            defer self.current_input = prev_input;

            // Increment depth and track static context
            self.depth += 1;
            defer self.depth -= 1;

            // Store caller and value in call stack for this depth
            self.call_stack[self.depth - 1] = CallStackEntry{ .caller = caller, .value = value };

            // Track static context for this frame
            self.static_stack[self.depth - 1] = is_static;

            // Convert gas to appropriate type
            const gas_i32 = @as(i32, @intCast(@min(gas, std.math.maxInt(i32))));

            // Create host interface for the frame
            const host = self.to_host();

            // Create frame directly
            var frame = try Frame.init(
                self.allocator,
                code,
                gas_i32,
                self.database,
                host,
            );
            frame.contract_address = address;
            defer frame.deinit(self.allocator);

            // Create bytecode instance for iteration
            const bytecode = try Bytecode.init(self.allocator, code);
            defer bytecode.deinit();

            // Create simple handler lookup table
            const handler_table = try self.createHandlerTable();
            defer self.allocator.free(handler_table);

            // Execute using bytecode iterator
            var iterator = bytecode.createIterator();
            
            while (iterator.next()) |opcode_data| {
                // Check gas
                if (frame.gas_remaining <= 0) {
                    return CallResult.failure(0);
                }

                switch (opcode_data) {
                    .stop => {
                        // STOP opcode - successful termination
                        const gas_left = @as(u64, @intCast(@max(frame.gas_remaining, 0)));
                        var out_slice: []const u8 = &.{};
                        if (frame.output_data.items.len > 0) {
                            const buf = try self.allocator.alloc(u8, frame.output_data.items.len);
                            @memcpy(buf, frame.output_data.items);
                            out_slice = buf;
                        }
                        self.return_data = out_slice;
                        return CallResult.success_with_output(gas_left, out_slice);
                    },
                    .invalid => {
                        // INVALID opcode
                        return CallResult.failure(0);
                    },
                    .push => |push_info| {
                        // PUSH opcodes
                        frame.gas_remaining -= 3; // Base gas cost
                        try frame.stack.push(push_info.value);
                    },
                    .jumpdest => {
                        // JUMPDEST - just consume gas
                        frame.gas_remaining -= 1;
                    },
                    .regular => |regular_info| {
                        // Regular opcodes - execute through frame
                        const opcode_enum = std.meta.intToEnum(Opcode, regular_info.opcode) catch {
                            return CallResult.failure(0);
                        };
                        
                        // Special handling for control flow opcodes
                        switch (opcode_enum) {
                            .JUMP => {
                                _ = try frame.stack.pop(); // jump_dest
                                // Jump handling would go here
                                // For now, just continue
                                frame.gas_remaining -= 8;
                            },
                            .JUMPI => {
                                _ = try frame.stack.pop(); // jump_dest
                                _ = try frame.stack.pop(); // condition
                                // Conditional jump handling would go here
                                frame.gas_remaining -= 10;
                            },
                            .RETURN => {
                                const offset = try frame.stack.pop();
                                const length = try frame.stack.pop();
                                
                                // Get return data from memory
                                const mem_offset = std.math.cast(usize, offset) orelse return CallResult.failure(0);
                                const mem_length = std.math.cast(usize, length) orelse return CallResult.failure(0);
                                
                                const return_data = try frame.memory.get_slice(mem_offset, mem_length);
                                const buf = try self.allocator.alloc(u8, return_data.len);
                                @memcpy(buf, return_data);
                                
                                const gas_left = @as(u64, @intCast(@max(frame.gas_remaining, 0)));
                                self.return_data = buf;
                                return CallResult.success_with_output(gas_left, buf);
                            },
                            .REVERT => {
                                const offset = try frame.stack.pop();
                                const length = try frame.stack.pop();
                                
                                // Get revert data from memory
                                const mem_offset = std.math.cast(usize, offset) orelse return CallResult.failure(0);
                                const mem_length = std.math.cast(usize, length) orelse return CallResult.failure(0);
                                
                                const revert_data = try frame.memory.get_slice(mem_offset, mem_length);
                                const buf = try self.allocator.alloc(u8, revert_data.len);
                                @memcpy(buf, revert_data);
                                
                                const gas_left = @as(u64, @intCast(@max(frame.gas_remaining, 0)));
                                self.return_data = buf;
                                return CallResult.revert_with_data(gas_left, buf);
                            },
                            else => {
                                // Execute regular opcode through frame
                                frame.execute_opcode(opcode_enum) catch |err| {
                                    return switch (err) {
                                        error.OutOfGas => CallResult.failure(0),
                                        error.StackUnderflow => CallResult.failure(0),
                                        error.StackOverflow => CallResult.failure(0),
                                        error.InvalidOpcode => CallResult.failure(0),
                                        error.OutOfBounds => CallResult.failure(0),
                                        error.WriteProtection => CallResult.failure(0),
                                        else => CallResult.failure(0),
                                    };
                                };
                            }
                        }
                    },
                    .push_add_fusion,
                    .push_mul_fusion => {
                        // Handle fusion opcodes if enabled
                        // For now, just fail
                        return CallResult.failure(0);
                    },
                }
            }

            // If we get here, we ran out of code (implicit STOP)
            const gas_left = @as(u64, @intCast(@max(frame.gas_remaining, 0)));
            var out_slice: []const u8 = &.{};
            if (frame.output_data.items.len > 0) {
                const buf = try self.allocator.alloc(u8, frame.output_data.items.len);
                @memcpy(buf, frame.output_data.items);
                out_slice = buf;
            }
            self.return_data = out_slice;
            return CallResult.success_with_output(gas_left, out_slice);
        }

        /// Create a handler lookup table for opcodes
        fn createHandlerTable(self: *Self) ![]const ?*const fn (*Frame) Frame.Error!void {
            // For now, return empty table as we handle opcodes directly
            return try self.allocator.alloc(?*const fn (*Frame) Frame.Error!void, 256);
        }

        /// Execute initialization code using bytecode iterator
        fn execute_init_code(
            self: *Self,
            code: []const u8,
            gas: u64,
            address: primitives.Address,
            snapshot_id: Journal.SnapshotIdType,
        ) !CallResult {
            // Simply delegate to execute_frame with no input
            // Init code execution is the same as regular execution
            // but the output becomes the deployed contract code
            return try self.execute_frame(
                code,
                &.{}, // No input for init code
                gas,
                address,
                address, // Contract is its own caller during init
                0, // No value during init
                false, // Not static during init
                snapshot_id,
            );
        }

        /// Execute nested EVM call - used for calls from within the EVM
        pub fn inner_call(self: *Self, params: CallParams) !CallResult {
            // Don't reset depth to 0 for inner calls - just use call handlers
            const result = switch (params) {
                .call => |p| try self.call_handler(p),
                .callcode => |p| try self.callcode_handler(p),
                .delegatecall => |p| try self.delegatecall_handler(p),
                .staticcall => |p| try self.staticcall_handler(p),
                .create => |p| try self.create_handler(p),
                .create2 => |p| try self.create2_handler(p),
            };
            // Update return data buffer for parent frame semantics
            self.return_data = result.output;
            return result;
        }

        // TODO just inline into call/inner_call
        /// Execute a precompile call using the full legacy precompile system
        /// This implementation supports all standard Ethereum precompiles (0x01-0x0A)
        fn execute_precompile_call(self: *Self, address: primitives.Address, input: []const u8, gas: u64, is_static: bool) !CallResult {
            _ = is_static; // Precompiles are inherently stateless, so static flag doesn't matter

            if (!precompiles.is_precompile(address)) {
                return CallResult{ .success = false, .gas_left = gas, .output = &.{} };
            }

            const precompile_id = address.bytes[19]; // Last byte is the precompile ID
            if (precompile_id < 1 or precompile_id > 10) {
                return CallResult{ .success = false, .gas_left = gas, .output = &.{} };
            }

            // Execute precompile using main allocator so tests can free outputs
            const result = precompiles.execute_precompile(self.allocator, address, input, gas) catch {
                return CallResult{
                    .success = false,
                    .gas_left = 0,
                    .output = &.{},
                };
            };

            // Handle precompile result
            // Copy output into owned buffer and free original to avoid leaks
            var out_slice: []const u8 = &.{};
            if (result.output.len > 0) {
                const buf = try self.allocator.dupe(u8, result.output);
                // Original was allocated with self.allocator in precompile
                self.allocator.free(result.output);
                out_slice = buf;
            }
            if (result.success) {
                return CallResult{ .success = true, .gas_left = gas - result.gas_used, .output = out_slice };
            } else {
                return CallResult{ .success = false, .gas_left = 0, .output = out_slice };
            }
        }

        // ===== Host Interface Implementation =====

        /// Get account balance
        pub fn get_balance(self: *Self, address: primitives.Address) u256 {
            return self.database.get_balance(address.bytes) catch 0;
        }

        /// Check if account exists
        pub fn account_exists(self: *Self, address: primitives.Address) bool {
            return self.database.account_exists(address.bytes);
        }

        /// Get account code
        pub fn get_code(self: *Self, address: primitives.Address) []const u8 {
            return self.database.get_code_by_address(address.bytes) catch &.{};
        }

        /// Get block information
        pub fn get_block_info(self: *Self) BlockInfo {
            return self.block_info;
        }

        /// Emit log event
        pub fn emit_log(self: *Self, contract_address: primitives.Address, topics: []const u256, data: []const u8) void {
            // Allocate copies with the main allocator so tests can free via evm.allocator
            const topics_copy = self.allocator.dupe(u256, topics) catch return;
            const data_copy = self.allocator.dupe(u8, data) catch return;

            self.logs.append(self.allocator, @import("call_result.zig").Log{
                .address = contract_address,
                .topics = topics_copy,
                .data = data_copy,
            }) catch return;
        }

        /// Execute nested EVM call - for Host interface
        pub fn host_inner_call(self: *Self, params: CallParams) !CallResult {
            return self.inner_call(params);
        }

        /// Register a contract as created in the current transaction
        pub fn register_created_contract(self: *Self, address: primitives.Address) !void {
            try self.created_contracts.mark_created(address);
        }

        /// Check if a contract was created in the current transaction
        pub fn was_created_in_tx(self: *Self, address: primitives.Address) bool {
            return self.created_contracts.was_created_in_tx(address);
        }

        /// Create a new journal snapshot
        pub fn create_snapshot(self: *Self) Journal.SnapshotIdType {
            return self.journal.create_snapshot();
        }

        /// Revert state changes to a previous snapshot
        pub fn revert_to_snapshot(self: *Self, snapshot_id: Journal.SnapshotIdType) void {
            // Get the journal entries that need to be reverted before removing them
            var entries_to_revert = std.ArrayList(Journal.EntryType){};
            defer entries_to_revert.deinit(self.allocator);

            // Collect entries that belong to snapshots newer than or equal to the target snapshot
            for (self.journal.entries.items) |entry| {
                if (entry.snapshot_id >= snapshot_id) {
                    entries_to_revert.append(self.allocator, entry) catch {
                        // If we can't allocate memory for reverting, we're in a bad state
                        // But we should still remove the journal entries to maintain consistency
                        break;
                    };
                }
            }

            // Remove the journal entries first
            self.journal.revert_to_snapshot(snapshot_id);

            // Apply the changes in reverse order to revert the database state
            var i = entries_to_revert.items.len;
            while (i > 0) : (i -= 1) {
                const entry = entries_to_revert.items[i - 1];
                self.apply_journal_entry_revert(entry) catch |err| {
                    // Log the error but continue reverting other entries
                    const log = @import("log.zig");
                    log.err("Failed to revert journal entry: {}", .{err});
                };
            }
        }

        /// Apply a single journal entry to revert database state
        fn apply_journal_entry_revert(self: *Self, entry: Journal.EntryType) !void {
            switch (entry.data) {
                .storage_change => |sc| {
                    // Revert storage to original value
                    try self.database.set_storage(sc.address.bytes, sc.key, sc.original_value);
                },
                .balance_change => |bc| {
                    // Revert balance to original value
                    var account = (try self.database.get_account(bc.address.bytes)) orelse {
                        // If account doesn't exist, create it with the original balance
                        const reverted_account = Account{
                            .balance = bc.original_balance,
                            .nonce = 0,
                            .code_hash = [_]u8{0} ** 32,
                            .storage_root = [_]u8{0} ** 32,
                        };
                        return self.database.set_account(bc.address.bytes, reverted_account);
                    };
                    account.balance = bc.original_balance;
                    try self.database.set_account(bc.address.bytes, account);
                },
                .nonce_change => |nc| {
                    // Revert nonce to original value
                    var account = (try self.database.get_account(nc.address.bytes)) orelse return;
                    account.nonce = nc.original_nonce;
                    try self.database.set_account(nc.address.bytes, account);
                },
                .code_change => |cc| {
                    // Revert code to original value
                    var account = (try self.database.get_account(cc.address.bytes)) orelse return;
                    account.code_hash = cc.original_code_hash;
                    try self.database.set_account(cc.address.bytes, account);
                },
                .account_created => |ac| {
                    // Remove created account
                    try self.database.delete_account(ac.address.bytes);
                },
                .account_destroyed => |ad| {
                    // Restore destroyed account
                    // Note: This is a simplified restoration - in practice we'd need full account state
                    const restored_account = Account{
                        .balance = ad.balance,
                        .nonce = 0,
                        .code_hash = [_]u8{0} ** 32,
                        .storage_root = [_]u8{0} ** 32,
                    };
                    try self.database.set_account(ad.address.bytes, restored_account);
                },
            }
        }

        /// Record a storage change in the journal
        pub fn record_storage_change(self: *Self, address: primitives.Address, slot: u256, original_value: u256) !void {
            try self.journal.record_storage_change(self.current_snapshot_id, address, slot, original_value);
        }

        /// Get the original storage value from the journal
        pub fn get_original_storage(self: *Self, address: primitives.Address, slot: u256) ?u256 {
            // Use journal's built-in method to get original storage
            return self.journal.get_original_storage(address, slot);
        }

        /// Access an address and return the gas cost (EIP-2929)
        pub fn access_address(self: *Self, address: primitives.Address) !u64 {
            return try self.access_list.access_address(address);
        }

        /// Access a storage slot and return the gas cost (EIP-2929)
        pub fn access_storage_slot(self: *Self, contract_address: primitives.Address, slot: u256) !u64 {
            return try self.access_list.access_storage_slot(contract_address, slot);
        }

        /// Mark a contract for destruction
        pub fn mark_for_destruction(self: *Self, contract_address: primitives.Address, recipient: primitives.Address) !void {
            try self.self_destruct.mark_for_destruction(contract_address, recipient);
        }

        /// Get current call input/calldata
        pub fn get_input(self: *Self) []const u8 {
            return self.current_input;
        }

        /// Check if hardfork is at least the target
        pub fn is_hardfork_at_least(self: *Self, target: Hardfork) bool {
            return @intFromEnum(self.hardfork_config) >= @intFromEnum(target);
        }

        /// Get current hardfork
        pub fn get_hardfork(self: *Self) Hardfork {
            return self.hardfork_config;
        }

        /// Get whether the current frame is static
        pub fn get_is_static(self: *Self) bool {
            if (self.depth == 0) return false;
            return self.static_stack[self.depth - 1];
        }

        /// Get the call depth for the current frame
        pub fn get_depth(self: *Self) u11 {
            return @intCast(self.depth);
        }

        /// Get transaction origin (original sender)
        pub fn get_tx_origin(self: *Self) primitives.Address {
            return self.origin;
        }

        /// Get current caller address
        pub fn get_caller(self: *Self) primitives.Address {
            if (self.depth == 0) return self.origin;
            return self.call_stack[self.depth - 1].caller;
        }

        /// Get current call value
        pub fn get_call_value(self: *Self) u256 {
            if (self.depth == 0) return 0;
            return self.call_stack[self.depth - 1].value;
        }

        /// Get storage value
        pub fn get_storage(self: *Self, address: primitives.Address, slot: u256) u256 {
            return self.database.get_storage(address.bytes, slot) catch 0;
        }

        /// Set storage value
        pub fn set_storage(self: *Self, address: primitives.Address, slot: u256, value: u256) !void {
            // Record original value for journal
            const original_value = self.get_storage(address, slot);
            try self.record_storage_change(address, slot, original_value);
            try self.database.set_storage(address.bytes, slot, value);
        }

        /// Get transaction gas price
        pub fn get_gas_price(self: *Self) u256 {
            return self.gas_price;
        }

        /// Get return data from last call
        pub fn get_return_data(self: *Self) []const u8 {
            return self.return_data;
        }

        /// Get chain ID
        pub fn get_chain_id(self: *Self) u16 {
            return self.context.chain_id;
        }

        /// Get block hash by number
        pub fn get_block_hash(self: *Self, block_number: u64) ?[32]u8 {
            const current_block = self.block_info.number;

            // EVM BLOCKHASH rules:
            // - Return 0 for current block and future blocks
            // - Return 0 for blocks older than 256 blocks
            // - Return 0 for block 0 (genesis)
            if (block_number >= current_block or
                current_block > block_number + 256 or
                block_number == 0)
            {
                return null;
            }

            // For testing/simulation purposes, generate a deterministic hash
            // In a real implementation, this would look up the actual block hash
            // from the blockchain state or a block hash ring buffer
            var hash: [32]u8 = undefined;
            hash[0..8].* = std.mem.toBytes(block_number);
            hash[8..16].* = std.mem.toBytes(current_block);

            // Fill rest with deterministic pattern based on block number
            var i: usize = 16;
            while (i < 32) : (i += 1) {
                hash[i] = @as(u8, @truncate(block_number +% i));
            }

            return hash;
        }

        /// Get blob hash for the given index (EIP-4844)
        pub fn get_blob_hash(self: *Self, index: u256) ?[32]u8 {
            // Convert index to usize, return null if out of bounds
            if (index >= self.context.blob_versioned_hashes.len) {
                return null;
            }
            const idx = @as(usize, @intCast(index));
            return self.context.blob_versioned_hashes[idx];
        }

        /// Get blob base fee (EIP-4844)
        pub fn get_blob_base_fee(self: *Self) u256 {
            return self.context.blob_base_fee;
        }

        // TODO: remove this this is a duplciate and this version is unused
        /// Transfer value between accounts with proper journaling
        /// This method ensures balance changes are recorded in the journal for potential reverts
        pub fn transfer_value(self: *Self, from: primitives.Address, to: primitives.Address, value: u256) !void {
            // Don't transfer if value is zero
            if (value == 0) return;

            // Get accounts
            var from_account = (try self.database.get_account(from.bytes)) orelse return error.AccountNotFound;
            var to_account = (try self.database.get_account(to.bytes)) orelse Account{
                .balance = 0,
                .nonce = 0,
                .code_hash = [_]u8{0} ** 32,
                .storage_root = [_]u8{0} ** 32,
            };

            // Check sufficient balance
            if (from_account.balance < value) return error.InsufficientBalance;

            // Record original balances in journal before modification
            try self.journal.record_balance_change(self.current_snapshot_id, from, from_account.balance);
            try self.journal.record_balance_change(self.current_snapshot_id, to, to_account.balance);

            // Update balances
            from_account.balance -= value;
            to_account.balance += value;

            // Write to database
            try self.database.set_account(from.bytes, from_account);
            try self.database.set_account(to.bytes, to_account);
        }

        // TODO: remove useless helper function and just inline this
        /// Convert to Host interface
        pub fn to_host(self: *Self) @import("host.zig").Host {
            return @import("host.zig").Host.init(self);
        }

        // TODO: remove useless helper function and just inline this
        /// Helper function to handle database errors by reverting snapshot and returning failure
        fn revert_and_fail(self: *Self, snapshot_id: Journal.SnapshotIdType, err: anyerror) CallResult {
            _ = err catch {};
            self.journal.revert_to_snapshot(snapshot_id);
            return CallResult.failure(0);
        }

        // TODO: remove useless helper function and just inline this
        /// Take all logs and clear the log list
        fn takeLogs(self: *Self) []const @import("call_result.zig").Log {
            const logs = self.logs.toOwnedSlice(self.allocator) catch &.{};
            self.logs = std.ArrayList(@import("call_result.zig").Log){};
            return logs;
        }
    };
}

// TODO: remove DefaultEvm
pub const DefaultEvm = Evm(.{});

