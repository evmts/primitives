const std = @import("std");
const FrameConfig = @import("../frame/frame_config.zig").FrameConfig;
const log = @import("../log.zig");
const primitives = @import("primitives");
const Address = primitives.Address;
const GasConstants = primitives.GasConstants;
// u256 is a built-in type in Zig 0.14+
const keccak_asm = @import("crypto").keccak_asm;
const memory_mod = @import("../memory/memory.zig");
const Opcode = @import("../opcodes/opcode_data.zig").Opcode;

/// Context opcode handlers for the EVM stack frame.
/// These handle execution context queries (caller, value, gas, etc).
pub fn Handlers(comptime FrameType: type) type {
    return struct {
        pub const Error = FrameType.Error;
        pub const Dispatch = FrameType.Dispatch;
        pub const WordType = FrameType.WordType;
        const config = FrameType.frame_config;
        const dispatch_opcode_data = @import("../preprocessor/dispatch_opcode_data.zig");

        /// Continue to next instruction with afterInstruction tracking
        pub inline fn next_instruction(self: *FrameType, cursor: [*]const Dispatch.Item, comptime opcode: Dispatch.UnifiedOpcode) Error!noreturn {
            const op_data = dispatch_opcode_data.getOpData(opcode, Dispatch, Dispatch.Item, cursor);
            self.afterInstruction(opcode, op_data.next_handler, op_data.next_cursor.cursor);
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// Helper to convert Address to WordType
        fn to_u256(addr: Address) WordType {
            const bytes = addr.bytes;
            var value: u256 = 0;
            for (bytes) |byte| {
                value = (value << 8) | @as(u256, byte);
            }
            return @as(WordType, @truncate(value));
        }

        /// Helper to convert WordType to Address
        fn from_u256(value: WordType) Address {
            // If WordType is smaller than u256, just zero-extend
            const value_u256: u256 = if (@bitSizeOf(WordType) < 256) @as(u256, value) else value;
            // Take the lower 160 bits (20 bytes)
            const addr_value = @as(u160, @truncate(value_u256));
            var addr_bytes: [20]u8 = undefined;
            std.mem.writeInt(u160, &addr_bytes, addr_value, .big);
            return Address{ .bytes = addr_bytes };
        }

        /// ADDRESS opcode (0x30) - Get address of currently executing account.
        /// Stack: [] → [address]
        pub fn address(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.ADDRESS, cursor);
            const addr_u256 = to_u256(self.contract_address);
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "ADDRESS requires stack space");
            }
            self.stack.push_unsafe(addr_u256);
            return next_instruction(self, cursor, .ADDRESS);
        }

        /// BALANCE opcode (0x31) - Get balance of the given account.
        /// Stack: [address] → [balance]
        pub fn balance(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.BALANCE, cursor);
            {
                self.getTracer().assert(self.stack.size() >= 1, "BALANCE requires 1 stack item");
            }
            const address_u256 = self.stack.peek_unsafe();
            const addr = from_u256(address_u256);

            // Access the address for warm/cold accounting (EIP-2929)
            const evm = self.getEvm();
            const access_cost = evm.access_address(addr) catch |err| switch (err) {
                else => {
                    self.afterComplete(.BALANCE);
                    return Error.AllocationError;
                },
            };

            // Charge gas for address access
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(access_cost);
            if (self.gas_remaining < 0) {
                self.afterComplete(.BALANCE);
                return Error.OutOfGas;
            }

            const bal = evm.get_balance(addr);
            const balance_word = @as(WordType, @truncate(bal));
            self.stack.set_top_unsafe(balance_word);
            return next_instruction(self, cursor, .BALANCE);
        }

        /// ORIGIN opcode (0x32) - Get execution origination address.
        /// Stack: [] → [origin]
        pub fn origin(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.ORIGIN, cursor);
            const tx_origin = self.getEvm().get_tx_origin();
            const origin_u256 = to_u256(tx_origin);
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "ORIGIN requires stack space");
            }
            self.stack.push_unsafe(origin_u256);
            return next_instruction(self, cursor, .ORIGIN);
        }

        /// CALLER opcode (0x33) - Get caller address.
        /// Stack: [] → [caller]
        pub fn caller(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CALLER, cursor);
            const caller_u256 = to_u256(self.caller);
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "CALLER requires stack space");
            }
            self.stack.push_unsafe(caller_u256);
            return next_instruction(self, cursor, .CALLER);
        }

        /// CALLVALUE opcode (0x34) - Get deposited value by the instruction/transaction responsible for this execution.
        /// Stack: [] → [value]
        pub fn callvalue(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CALLVALUE, cursor);
            const value = self.value;
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "CALLVALUE requires stack space");
            }
            self.stack.push_unsafe(value);
            return next_instruction(self, cursor, .CALLVALUE);
        }

        /// CALLDATALOAD opcode (0x35) - Get input data of current environment.
        /// Stack: [offset] → [data]
        pub fn calldataload(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CALLDATALOAD, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 1, "CALLDATALOAD requires 1 stack item");
            }
            const offset = self.stack.peek_unsafe();
            // Convert u256 to usize, checking for overflow
            if (offset > std.math.maxInt(usize)) {
                self.stack.set_top_unsafe(0);
                const op_data = dispatch.getOpData(.CALLDATALOAD); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }
            const offset_usize = @as(usize, @intCast(offset));

            const calldata = self.calldata();
            // Load 32 bytes from calldata, zero-padding if needed
            var word: u256 = 0;
            for (0..32) |i| {
                const byte_index = offset_usize + i;
                if (byte_index < calldata.len) {
                    const byte_val = calldata[byte_index];
                    word = (word << 8) | @as(u256, byte_val);
                } else {
                    word = word << 8; // Zero padding
                }
            }
            // Convert to WordType (truncate if necessary for smaller word types)
            const word_typed = @as(WordType, @truncate(word));
            self.stack.set_top_unsafe(word_typed);
            const op_data = dispatch.getOpData(.CALLDATALOAD); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// CALLDATASIZE opcode (0x36) - Get size of input data in current environment.
        /// Stack: [] → [size]
        pub fn calldatasize(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CALLDATASIZE, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            const calldata = self.calldata();
            const calldata_len = @as(WordType, @truncate(@as(u256, @intCast(calldata.len))));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "CALLDATASIZE requires stack space");
            }
            self.stack.push_unsafe(calldata_len);
            const op_data = dispatch.getOpData(.CALLDATASIZE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// CALLDATACOPY opcode (0x37) - Copy input data in current environment to memory.
        /// Stack: [destOffset, offset, length] → []
        pub fn calldatacopy(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CALLDATACOPY, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 3, "CALLDATACOPY requires 3 stack items");
            }
            const length = self.stack.pop_unsafe(); // Top of stack
            const offset = self.stack.pop_unsafe(); // Second from top
            const dest_offset = self.stack.pop_unsafe(); // Third from top

            // Check for overflow
            if (dest_offset > std.math.maxInt(usize) or
                offset > std.math.maxInt(usize) or
                length > std.math.maxInt(usize))
            {
                return Error.OutOfBounds;
            }

            const dest_offset_usize = @as(usize, @intCast(dest_offset));
            const offset_usize = @as(usize, @intCast(offset));
            const length_usize = @as(usize, @intCast(length));

            if (length_usize == 0) {
                const op_data = dispatch.getOpData(.CALLDATACOPY); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            // Calculate gas cost for memory expansion and copy operation
            const new_size = dest_offset_usize + length_usize;
            const memory_expansion_cost = self.memory.get_expansion_cost(@as(u24, @intCast(new_size)));

            // Dynamic gas cost: 3 gas per word (32 bytes) copied
            const copy_cost = (length_usize + 31) / 32 * 3;
            const total_gas = memory_expansion_cost + copy_cost;

            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(total_gas);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            // Ensure memory capacity
            self.memory.ensure_capacity(self.getAllocator(), @as(u24, @intCast(new_size))) catch |err| switch (err) {
                memory_mod.MemoryError.MemoryOverflow => return Error.OutOfBounds,
                else => return Error.AllocationError,
            };

            const calldata = self.calldata();

            // Copy calldata to memory with proper zero-padding
            var i: usize = 0;
            while (i < length_usize) : (i += 1) {
                const src_index = offset_usize + i;
                const byte_val = if (src_index < calldata.len) calldata[src_index] else 0;
                self.memory.set_byte(self.getAllocator(), @as(u24, @intCast(dest_offset_usize + i)), byte_val) catch return Error.OutOfBounds;
            }

            const op_data = dispatch.getOpData(.CALLDATACOPY); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// CODESIZE opcode (0x38) - Get size of code running in current environment.
        /// Stack: [] → [size]
        pub fn codesize(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CODESIZE, cursor);
            // Get codesize from frame's code
            const bytecode_len = @as(WordType, @intCast(self.code.len));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "CODESIZE requires stack space");
            }
            self.stack.push_unsafe(bytecode_len);
            const op_data = dispatch_opcode_data.getOpData(.CODESIZE, Dispatch, Dispatch.Item, cursor);
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// CODECOPY opcode (0x39) - Copy code running in current environment to memory.
        /// Stack: [destOffset, offset, length] → []
        pub fn codecopy(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CODECOPY, cursor);
            // EVM stack order: [destOffset, offset, length] with dest on top
            {
                self.getTracer().assert(self.stack.size() >= 3, "CODECOPY requires 3 stack items");
            }
            const dest_offset = self.stack.pop_unsafe(); // Top of stack
            const offset = self.stack.pop_unsafe(); // Next
            const length = self.stack.pop_unsafe(); // Next

            // Check for overflow
            if (dest_offset > std.math.maxInt(usize) or
                offset > std.math.maxInt(usize) or
                length > std.math.maxInt(usize))
            {
                return Error.OutOfBounds;
            }

            const dest_offset_usize = @as(usize, @intCast(dest_offset));
            const offset_usize = @as(usize, @intCast(offset));
            const length_usize = @as(usize, @intCast(length));

            if (length_usize == 0) {
                const op_data = dispatch_opcode_data.getOpData(.CODECOPY, Dispatch, Dispatch.Item, cursor);
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            // Calculate gas cost for memory expansion and copy operation
            const new_size = dest_offset_usize + length_usize;
            const memory_expansion_cost = self.memory.get_expansion_cost(@as(u24, @intCast(new_size)));

            // Dynamic gas cost: 3 gas per word (32 bytes) copied
            const copy_cost = (length_usize + 31) / 32 * 3;
            const total_gas = memory_expansion_cost + copy_cost;

            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(total_gas);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            // Ensure memory capacity
            self.memory.ensure_capacity(self.getAllocator(), @as(u24, @intCast(new_size))) catch |err| switch (err) {
                memory_mod.MemoryError.MemoryOverflow => return Error.OutOfBounds,
                else => return Error.AllocationError,
            };

            // Get bytecode from frame
            const code_data = self.code;

            // Copy code to memory with proper zero-padding
            var i: usize = 0;
            while (i < length_usize) : (i += 1) {
                const src_index = offset_usize + i;
                const byte_val = if (src_index < code_data.len) code_data[src_index] else 0;
                self.memory.set_byte(self.getAllocator(), @as(u24, @intCast(dest_offset_usize + i)), byte_val) catch return Error.OutOfBounds;
            }

            const op_data = dispatch_opcode_data.getOpData(.CODECOPY, Dispatch, Dispatch.Item, cursor);
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// GASPRICE opcode (0x3A) - Get price of gas in current environment.
        /// Stack: [] → [gas_price]
        pub fn gasprice(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .GASPRICE);
            const dispatch = Dispatch{ .cursor = cursor };
            const gas_price = self.getEvm().get_gas_price();
            const gas_price_truncated = @as(WordType, @truncate(gas_price));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "GASPRICE requires stack space");
            }
            self.stack.push_unsafe(gas_price_truncated);
            const op_data = dispatch.getOpData(.GASPRICE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// EXTCODESIZE opcode (0x3B) - Get size of an account's code.
        /// Stack: [address] → [size]
        pub fn extcodesize(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .EXTCODESIZE);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 1, "EXTCODESIZE requires 1 stack item");
            }
            const address_u256 = self.stack.peek_unsafe();
            const addr = from_u256(address_u256);

            // Access the address for warm/cold accounting (EIP-2929)
            const evm = self.getEvm();
            const access_cost = evm.access_address(addr) catch |err| switch (err) {
                else => return Error.AllocationError,
            };

            // Charge gas for address access
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(access_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const code = evm.get_code(addr);
            const code_len = @as(WordType, @truncate(@as(u256, @intCast(code.len))));
            self.stack.set_top_unsafe(code_len);
            const op_data = dispatch.getOpData(.EXTCODESIZE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// EXTCODECOPY opcode (0x3C) - Copy an account's code to memory.
        /// Stack: [address, destOffset, offset, length] → []
        pub fn extcodecopy(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .EXTCODECOPY);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 4, "EXTCODECOPY requires 4 stack items");
            }
            const length = self.stack.pop_unsafe(); // Top of stack
            const offset = self.stack.pop_unsafe(); // Second from top
            const dest_offset = self.stack.pop_unsafe(); // Third from top
            const address_u256 = self.stack.pop_unsafe(); // Fourth from top

            // Check for overflow
            if (dest_offset > std.math.maxInt(usize) or
                offset > std.math.maxInt(usize) or
                length > std.math.maxInt(usize))
            {
                return Error.OutOfBounds;
            }

            const addr = from_u256(address_u256);

            // Access the address for warm/cold accounting (EIP-2929)
            const evm = self.getEvm();
            const access_cost = evm.access_address(addr) catch |err| switch (err) {
                else => return Error.AllocationError,
            };

            // Charge gas for address access
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(access_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }
            const dest_offset_usize = @as(usize, @intCast(dest_offset));
            const offset_usize = @as(usize, @intCast(offset));
            const length_usize = @as(usize, @intCast(length));

            if (length_usize == 0) {
                const op_data = dispatch.getOpData(.EXTCODECOPY); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            // Calculate gas cost for memory expansion and copy operation
            const new_size = dest_offset_usize + length_usize;
            const memory_expansion_cost = self.memory.get_expansion_cost(@as(u24, @intCast(new_size)));

            // Dynamic gas cost: 3 gas per word (32 bytes) copied
            const copy_cost = (length_usize + 31) / 32 * 3;
            const total_gas = memory_expansion_cost + copy_cost;

            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(total_gas);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            // Ensure memory capacity
            self.memory.ensure_capacity(self.getAllocator(), @as(u24, @intCast(new_size))) catch |err| switch (err) {
                memory_mod.MemoryError.MemoryOverflow => return Error.OutOfBounds,
                else => return Error.AllocationError,
            };

            const code = self.getEvm().get_code(addr);

            // Copy external code to memory with proper zero-padding
            var i: usize = 0;
            while (i < length_usize) : (i += 1) {
                const src_index = offset_usize + i;
                const byte_val = if (src_index < code.len) code[src_index] else 0;
                self.memory.set_byte(self.getAllocator(), @as(u24, @intCast(dest_offset_usize + i)), byte_val) catch return Error.OutOfBounds;
            }

            const op_data = dispatch.getOpData(.EXTCODECOPY); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// EXTCODEHASH opcode (0x3F) - Get hash of account's code.
        /// Stack: [address] → [hash]
        pub fn extcodehash(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .EXTCODEHASH);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 1, "EXTCODEHASH requires 1 stack item");
            }
            const address_u256 = self.stack.peek_unsafe();
            const addr = from_u256(address_u256);

            // Access the address for warm/cold accounting (EIP-2929)
            const evm = self.getEvm();
            const access_cost = evm.access_address(addr) catch |err| switch (err) {
                else => return Error.AllocationError,
            };

            // Charge gas for address access
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(access_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            if (!evm.account_exists(addr)) {
                // Non-existent account returns 0 per EIP-1052
                self.stack.set_top_unsafe(0);
                const op_data = dispatch.getOpData(.EXTCODEHASH); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            const code = self.getEvm().get_code(addr);
            if (code.len == 0) {
                // Existing account with empty code returns keccak256("") constant
                const empty_hash_u256: u256 = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
                const empty_hash_word = @as(WordType, @truncate(empty_hash_u256));
                self.stack.set_top_unsafe(empty_hash_word);
                const op_data = dispatch.getOpData(.EXTCODEHASH); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            // Compute keccak256 hash of the code
            var hash: [32]u8 = undefined;
            keccak_asm.keccak256(code, &hash) catch return Error.OutOfBounds;

            // Convert hash to u256 (big-endian)
            var hash_u256: u256 = 0;
            for (hash) |b| {
                hash_u256 = (hash_u256 << 8) | @as(u256, b);
            }
            const hash_word = @as(WordType, @truncate(hash_u256));
            self.stack.set_top_unsafe(hash_word);

            const op_data = dispatch.getOpData(.EXTCODEHASH); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// RETURNDATASIZE opcode (0x3D) - Get size of output data from the previous call.
        /// Stack: [] → [size]
        pub fn returndatasize(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .RETURNDATASIZE);
            const dispatch = Dispatch{ .cursor = cursor };
            // Return data is stored in the frame's output field after a call
            const return_data_len = @as(WordType, @truncate(@as(u256, @intCast(self.output.len))));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "RETURNDATASIZE requires stack space");
            }
            self.stack.push_unsafe(return_data_len);
            const op_data = dispatch.getOpData(.RETURNDATASIZE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// RETURNDATACOPY opcode (0x3E) - Copy output data from the previous call to memory.
        /// Stack: [destOffset, offset, length] → []
        pub fn returndatacopy(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .RETURNDATACOPY);
            const dispatch = Dispatch{ .cursor = cursor };
            // EVM stack order: [destOffset, offset, length] with dest on top
            {
                self.getTracer().assert(self.stack.size() >= 3, "RETURNDATACOPY requires 3 stack items");
            }
            const dest_offset = self.stack.pop_unsafe();
            const offset = self.stack.pop_unsafe();
            const length = self.stack.pop_unsafe();

            // Check for overflow
            if (dest_offset > std.math.maxInt(usize) or
                offset > std.math.maxInt(usize) or
                length > std.math.maxInt(usize))
            {
                return Error.OutOfBounds;
            }

            const dest_offset_usize = @as(usize, @intCast(dest_offset));
            const offset_usize = @as(usize, @intCast(offset));
            const length_usize = @as(usize, @intCast(length));

            // Return data is stored in the frame's output field after a call
            const return_data = self.output;

            // Check if we're trying to read past the end of return data
            if (offset_usize > return_data.len or
                (length_usize > 0 and offset_usize + length_usize > return_data.len))
            {
                return Error.OutOfBounds;
            }

            if (length_usize == 0) {
                const op_data = dispatch.getOpData(.RETURNDATACOPY); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }

            // Calculate gas cost for memory expansion and copy operation
            const new_size = dest_offset_usize + length_usize;
            const memory_expansion_cost = self.memory.get_expansion_cost(@as(u24, @intCast(new_size)));

            // Dynamic gas cost: 3 gas per word (32 bytes) copied
            const copy_cost = (length_usize + 31) / 32 * 3;
            const total_gas = memory_expansion_cost + copy_cost;

            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(total_gas);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            // Ensure memory capacity
            self.memory.ensure_capacity(self.getAllocator(), @as(u24, @intCast(new_size))) catch |err| switch (err) {
                memory_mod.MemoryError.MemoryOverflow => return Error.OutOfBounds,
                else => return Error.AllocationError,
            };

            // Copy return data to memory (no zero-padding needed since bounds are checked)
            const src_slice = return_data[offset_usize..][0..length_usize];
            self.memory.set_data(self.getAllocator(), @as(u24, @intCast(dest_offset_usize)), src_slice) catch return Error.OutOfBounds;

            const op_data = dispatch.getOpData(.RETURNDATACOPY); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// BLOCKHASH opcode (0x40) - Get the hash of one of the 256 most recent complete blocks.
        /// Stack: [block_number] → [hash]
        pub fn blockhash(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.BLOCKHASH, cursor);
            // BLOCKHASH costs 20 gas
            const gas_cost = 20;
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(gas_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 1, "BLOCKHASH requires 1 stack item");
            }
            const block_number = self.stack.peek_unsafe();
            // Cast to u64 - EVM spec says only last 256 blocks are accessible
            const block_number_u64 = @as(u64, @truncate(block_number));
            const block_hash_opt = self.getEvm().get_block_hash(block_number_u64);

            // Push hash or zero if not available
            if (block_hash_opt) |hash| {
                // Convert [32]u8 to u256
                var hash_value: u256 = 0;
                for (hash) |byte| {
                    hash_value = (hash_value << 8) | @as(u256, byte);
                }
                const hash_word = @as(WordType, @truncate(hash_value));
                self.stack.set_top_unsafe(hash_word);
            } else {
                self.stack.set_top_unsafe(0);
            }

            const op_data = dispatch.getOpData(.BLOCKHASH); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// COINBASE opcode (0x41) - Get the current block's beneficiary address.
        /// Stack: [] → [coinbase]
        pub fn coinbase(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.COINBASE, cursor);
            // COINBASE costs 2 gas
            const gas_cost = GasConstants.GasQuickStep;
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(gas_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const coinbase_u256 = to_u256(block_info.coinbase);
            const coinbase_word = @as(WordType, @truncate(coinbase_u256));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "COINBASE requires stack space");
            }
            self.stack.push_unsafe(coinbase_word);
            const op_data = dispatch.getOpData(.COINBASE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// TIMESTAMP opcode (0x42) - Get the current block's timestamp.
        /// Stack: [] → [timestamp]
        pub fn timestamp(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .TIMESTAMP);
            // TIMESTAMP costs 2 gas
            const gas_cost = GasConstants.GasQuickStep;
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(gas_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const timestamp_word = @as(WordType, @truncate(@as(u256, @intCast(block_info.timestamp))));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "TIMESTAMP requires stack space");
            }
            self.stack.push_unsafe(timestamp_word);
            const op_data = dispatch.getOpData(.TIMESTAMP); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// NUMBER opcode (0x43) - Get the current block's number.
        /// Stack: [] → [number]
        pub fn number(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .NUMBER);
            // NUMBER costs 2 gas
            const gas_cost = GasConstants.GasQuickStep;
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(gas_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const block_number_word = @as(WordType, @truncate(@as(u256, @intCast(block_info.number))));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "NUMBER requires stack space");
            }
            self.stack.push_unsafe(block_number_word);
            const op_data = dispatch.getOpData(.NUMBER); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// DIFFICULTY opcode (0x44) - Get the current block's difficulty.
        /// Stack: [] → [difficulty]
        pub fn difficulty(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.PREVRANDAO, cursor);
            // DIFFICULTY costs 2 gas
            const gas_cost = GasConstants.GasQuickStep;
            // Use negative gas pattern for single-branch out-of-gas detection
            self.gas_remaining -= @intCast(gas_cost);
            if (self.gas_remaining < 0) {
                return Error.OutOfGas;
            }

            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const difficulty_word = @as(WordType, @truncate(block_info.difficulty));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "DIFFICULTY requires stack space");
            }
            self.stack.push_unsafe(difficulty_word);
            const op_data = dispatch.getOpData(.PREVRANDAO); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// PREVRANDAO opcode - Alias for DIFFICULTY post-merge.
        /// Stack: [] → [prevrandao]
        pub fn prevrandao(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.PREVRANDAO, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            return difficulty(self, dispatch);
        }

        /// GASLIMIT opcode (0x45) - Get the current block's gas limit.
        /// Stack: [] → [gas_limit]
        pub fn gaslimit(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .GASLIMIT);
            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const gas_limit_word = @as(WordType, @truncate(@as(u256, @intCast(block_info.gas_limit))));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "GASLIMIT requires stack space");
            }
            self.stack.push_unsafe(gas_limit_word);
            const op_data = dispatch.getOpData(.GASLIMIT); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// CHAINID opcode (0x46) - Get the chain ID.
        /// Stack: [] → [chain_id]
        pub fn chainid(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.CHAINID, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            const chain_id = self.getEvm().get_chain_id();
            const chain_id_word = @as(WordType, @truncate(@as(u256, chain_id)));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "CHAINID requires stack space");
            }
            self.stack.push_unsafe(chain_id_word);
            const op_data = dispatch.getOpData(.CHAINID); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// SELFBALANCE opcode (0x47) - Get balance of currently executing account.
        /// Stack: [] → [balance]
        pub fn selfbalance(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .SELFBALANCE);
            const dispatch = Dispatch{ .cursor = cursor };
            const bal = self.getEvm().get_balance(self.contract_address);
            const balance_word = @as(WordType, @truncate(bal));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "SELFBALANCE requires stack space");
            }
            self.stack.push_unsafe(balance_word);
            const op_data = dispatch.getOpData(.SELFBALANCE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// BASEFEE opcode (0x48) - Get the current block's base fee.
        /// Stack: [] → [base_fee]
        pub fn basefee(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .BASEFEE);
            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const base_fee_word = @as(WordType, @truncate(block_info.base_fee));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "BASEFEE requires stack space");
            }
            self.stack.push_unsafe(base_fee_word);
            const op_data = dispatch.getOpData(.BASEFEE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// BLOBHASH opcode (0x49) - Get versioned hashes of blob transactions.
        /// Stack: [index] → [hash]
        pub fn blobhash(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.BLOBHASH, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            {
                self.getTracer().assert(self.stack.size() >= 1, "BLOBHASH requires 1 stack item");
            }
            const index = self.stack.peek_unsafe();
            // Convert u256 to usize for array access
            if (index > std.math.maxInt(usize)) {
                self.stack.set_top_unsafe(0);
                const op_data = dispatch.getOpData(.BLOBHASH); // Use op_data.next_handler and op_data.next_cursor directly
                return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
            }
            const index_usize = @as(usize, @intCast(index));
            // Check if index is within bounds of versioned hashes
            const block_info = self.getEvm().get_block_info();
            if (index_usize < block_info.blob_versioned_hashes.len) {
                const hash = block_info.blob_versioned_hashes[index_usize];
                // Convert [32]u8 to u256
                var hash_value: u256 = 0;
                for (hash) |byte| {
                    hash_value = (hash_value << 8) | @as(u256, byte);
                }
                const hash_word = @as(WordType, @truncate(hash_value));
                self.stack.set_top_unsafe(hash_word);
            } else {
                // Index out of bounds - push zero
                self.stack.set_top_unsafe(0);
            }
            const op_data = dispatch.getOpData(.BLOBHASH); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// BLOBBASEFEE opcode (0x4a) - Get the current block's blob base fee.
        /// Stack: [] → [blob_base_fee]
        pub fn blobbasefee(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.BLOBBASEFEE, cursor);
            const dispatch = Dispatch{ .cursor = cursor };
            const block_info = self.getEvm().get_block_info();
            const blob_base_fee = block_info.blob_base_fee;
            const blob_base_fee_word = @as(WordType, @truncate(blob_base_fee));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "BLOBBASEFEE requires stack space");
            }
            self.stack.push_unsafe(blob_base_fee_word);
            const op_data = dispatch.getOpData(.BLOBBASEFEE); // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// GAS opcode (0x5A) - Get the amount of available gas.
        /// Stack: [] → [gas]
        pub fn gas(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .GAS);
            const dispatch = Dispatch{ .cursor = cursor };
            // Note: The gas value pushed should be after the gas for this instruction is consumed
            // The dispatch system handles the gas consumption before calling this handler
            const gas_value = @as(WordType, @max(self.gas_remaining, 0));
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "GAS requires stack space");
            }
            self.stack.push_unsafe(gas_value);
            const op_data = dispatch.getOpData(.GAS);
            // Use op_data.next_handler and op_data.next_cursor directly
            return @call(FrameType.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// PC opcode (0x58) - Get the value of the program counter prior to the increment.
        /// Stack: [] → [pc]
        pub fn pc(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            log.before_instruction(self, .PC);
            const dispatch = Dispatch{ .cursor = cursor };
            // Get PC value from metadata
            const op_data = dispatch.getOpData(.PC);
            {
                self.getTracer().assert(self.stack.size() < @TypeOf(self.stack).stack_capacity, "PC requires stack space");
            }
            self.stack.push_unsafe(op_data.metadata.value);
            return @call(FrameType.getTailCallModifier(), op_data.op_data.next_handler, .{ self, op_data.op_data.next_cursor.cursor });
        }
    };
}

// ====== TESTS ======

const testing = std.testing;
const Frame = @import("../frame/frame.zig").Frame;
const dispatch_mod = @import("../preprocessor/dispatch.zig");
const DefaultTracer = @import("../tracer/tracer.zig").DefaultTracer;
const block_info_mod = @import("../block/block_info.zig");

// Test configuration
const test_config = FrameConfig{
    .stack_size = 1024,
    .WordType = u256,
    .max_bytecode_size = 1024,
    .block_gas_limit = 30_000_000,
    .DatabaseType = @import("../storage/memory_database.zig").MemoryDatabase,
    .memory_initial_capacity = 4096,
    .memory_limit = 0xFFFFFF,
};

const TestFrame = Frame(test_config);
const MemoryDatabase = @import("../storage/memory_database.zig").MemoryDatabase;

// Mock host for testing
const MockEvm = struct {
    allocator: std.mem.Allocator,
    contract_address: Address,
    caller_address: Address,
    origin_address: Address,
    call_value: u256,
    gas_price: u256,
    chain_id: u64,
    input_data: []const u8,
    return_data: []const u8,
    block_info: block_info_mod.BlockInfo,
    code_map: std.AutoHashMap(Address, []const u8),

    pub fn init(allocator: std.mem.Allocator) MockEvm {
        return .{
            .allocator = allocator,
            .contract_address = Address.zero(),
            .caller_address = Address.zero(),
            .origin_address = Address.zero(),
            .call_value = 0,
            .gas_price = 20_000_000_000, // 20 gwei
            .chain_id = 1,
            .input_data = &.{},
            .return_data = &.{},
            .block_info = .{
                .coinbase = Address.zero(),
                .timestamp = 1625097600,
                .number = 12345678,
                .difficulty = 1000000,
                .gas_limit = 30_000_000,
                .base_fee = 1_000_000_000,
            },
            .code_map = std.AutoHashMap(Address, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MockEvm) void {
        self.code_map.deinit();
    }

    pub fn get_tx_origin(self: *const MockEvm) Address {
        return self.origin_address;
    }

    pub fn get_caller(self: *const MockEvm) Address {
        return self.caller_address;
    }

    pub fn get_call_value(self: *const MockEvm) u256 {
        return self.call_value;
    }

    pub fn get_input(self: *const MockEvm) []const u8 {
        return self.input_data;
    }

    pub fn get_gas_price(self: *const MockEvm) u256 {
        return self.gas_price;
    }

    pub fn get_balance(self: *const MockEvm, address: Address) u256 {
        _ = self;
        _ = address;
        return 1_000_000_000_000_000_000; // 1 ETH
    }

    pub fn access_address(self: *const MockEvm, _: Address) !u64 {
        _ = self;
        return 100; // Mock gas cost
    }

    pub fn get_code(self: *const MockEvm, address: Address) []const u8 {
        return self.code_map.get(address) orelse &.{};
    }

    pub fn account_exists(self: *const MockEvm, address: Address) bool {
        _ = self;
        // Mock: all addresses exist except 0xFFFF...
        const all_f = Address.fromBytes([_]u8{0xFF} ** 20) catch unreachable;
        return !address.eql(all_f);
    }

    pub fn get_return_data(self: *const MockEvm) []const u8 {
        return self.return_data;
    }

    pub fn get_block_hash(self: *const MockEvm, block_number: u256) ?[32]u8 {
        _ = self;
        // Mock: return a hash for blocks within 256 of current
        const current_block = 12345678;
        if (block_number < current_block and current_block - block_number <= 256) {
            var hash: [32]u8 = undefined;
            @memset(&hash, @intCast(block_number & 0xFF));
            return hash;
        }
        return null;
    }

    pub fn get_block_info(self: *const MockEvm) block_info_mod.BlockInfo {
        return self.block_info;
    }

    pub fn get_chain_id(self: *const MockEvm) u64 {
        return self.chain_id;
    }

    pub fn get_blob_hash(self: *const MockEvm, index: u256) ?[32]u8 {
        _ = self;
        // Mock: return hash for first 3 blob indices
        if (index < 3) {
            var hash: [32]u8 = undefined;
            @memset(&hash, @intCast(0xAA + index));
            return hash;
        }
        return null;
    }

    pub fn get_blob_base_fee(self: *const MockEvm) u256 {
        _ = self;
        return 1; // Mock blob base fee
    }
};

fn createTestFrame(allocator: std.mem.Allocator, evm: ?*MockEvm) !TestFrame {
    const evm_ptr = if (evm) |e| @as(*anyopaque, @ptrCast(e)) else @as(*anyopaque, @ptrFromInt(0x1000)); // Use a dummy pointer for tests without EVM
    const database = MemoryDatabase.init(allocator);
    const value = try allocator.create(u256);
    value.* = 0;
    var frame = try TestFrame.init(allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, evm_ptr);
    frame.code = &[_]u8{}; // Empty code by default
    return frame;
}

// Mock dispatch that simulates successful execution flow
fn createMockDispatch() TestFrame.Dispatch {
    const mock_handler = struct {
        fn handler(frame: TestFrame, dispatch: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = frame;
            _ = dispatch;
            return TestFrame.Success.stop;
        }
    }.handler;

    var cursor: [1]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    cursor[0] = .{ .opcode_handler = &mock_handler };

    return TestFrame.Dispatch{
        .cursor = &cursor,
        .bytecode_length = 0,
    };
}

// Mock dispatch with PC metadata for PC opcode
fn createMockDispatchWithPc(pc_value: u256) TestFrame.Dispatch {
    const mock_handler = struct {
        fn handler(frame: TestFrame, dispatch: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = frame;
            _ = dispatch;
            return TestFrame.Success.stop;
        }
    }.handler;

    var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    cursor[0] = .{ .metadata = .{ .pc = .{ .value = pc_value } } };
    cursor[1] = .{ .opcode_handler = &mock_handler };

    return TestFrame.Dispatch{
        .cursor = &cursor,
        .bytecode_length = 0,
    };
}

test "ADDRESS opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_address = Address.fromBytes([_]u8{0x12} ++ [_]u8{0} ** 19) catch unreachable;
    evm.contract_address = test_address;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);
    frame.contract_address = test_address;

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.address(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0x12), result);
}

test "BALANCE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test: get balance of address 0x1234
    try frame.stack.push(0x1234);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.balance(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), result);
}

test "ORIGIN opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const origin = Address.fromBytes([_]u8{0xAB} ++ [_]u8{0} ** 19) catch unreachable;
    evm.origin_address = origin;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.origin(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0xAB), result);
}

test "CALLER opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const caller = Address.fromBytes([_]u8{0xCD} ++ [_]u8{0} ** 19) catch unreachable;
    evm.caller_address = caller;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.caller(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0xCD), result);
}

test "CALLVALUE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.call_value = 123456789;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.callvalue(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 123456789), result);
}

test "CALLDATALOAD opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const calldata = [_]u8{ 0xFF, 0xEE, 0xDD, 0xCC } ++ [_]u8{0} ** 28;
    evm.input_data = &calldata;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Load from offset 0
    try frame.stack.push(0);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.calldataload(frame, dispatch);

    const result = try frame.stack.pop();
    // First 4 bytes: 0xFFEEDDCC followed by 28 zeros
    const expected = @as(u256, 0xFFEEDDCC) << (28 * 8);
    try testing.expectEqual(expected, result);
}

test "CALLDATASIZE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const calldata = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    evm.input_data = &calldata;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.calldatasize(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 8), result);
}

test "CALLDATACOPY opcode" {
    var mock_evm = MockEvm.init(testing.allocator);
    defer mock_evm.deinit();

    const calldata = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    mock_evm.input_data = &calldata;

    var frame = try createTestFrame(testing.allocator, &mock_evm);
    defer frame.deinit(testing.allocator);

    // Copy 4 bytes from offset 1 to memory offset 0
    try frame.stack.push(0); // destOffset
    try frame.stack.push(1); // offset
    try frame.stack.push(4); // length

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.calldatacopy(frame, dispatch);

    // Check memory contents
    const mem_slice = try frame.memory.get_slice(0, 4);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBB, 0xCC, 0xDD, 0xEE }, mem_slice);
}

test "CODESIZE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Create frame with code
    const code_data = [_]u8{ 0x60, 0x00, 0x60, 0x00 };
    const evm_ptr = @as(*anyopaque, @ptrCast(&evm));
    const database = try MemoryDatabase.init(testing.allocator);
    const value = try testing.allocator.create(u256);
    value.* = 0;
    var frame = try TestFrame.init(testing.allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, evm_ptr);
    defer frame.deinit(testing.allocator);
    defer testing.allocator.destroy(value);
    frame.code = &code_data;

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.codesize(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 4), result);
}

test "CODECOPY opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Create frame with code
    const code_data = [_]u8{ 0x60, 0x40, 0x60, 0x80 };
    const evm_ptr = @as(*anyopaque, @ptrCast(&evm));
    const database = try MemoryDatabase.init(testing.allocator);
    const value = try testing.allocator.create(u256);
    value.* = 0;
    var frame = try TestFrame.init(testing.allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, evm_ptr);
    defer frame.deinit(testing.allocator);
    defer testing.allocator.destroy(value);
    frame.code = &code_data;

    // Copy all 4 bytes to memory offset 0
    try frame.stack.push(0); // destOffset
    try frame.stack.push(0); // offset
    try frame.stack.push(4); // length

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.codecopy(frame, dispatch);

    // Check memory contents
    const mem_slice = try frame.memory.get_slice(0, 4);
    try testing.expectEqualSlices(u8, &code_data, mem_slice);
}

test "GASPRICE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.gas_price = 25_000_000_000; // 25 gwei

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gasprice(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 25_000_000_000), result);
}

test "EXTCODESIZE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0x50 };
    const test_address = Address.fromBytes([_]u8{0x99} ++ [_]u8{0} ** 19) catch unreachable;
    try evm.code_map.put(test_address, &test_code);

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Get code size of test address
    try frame.stack.push(0x99);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.extcodesize(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 5), result);
}

test "EXTCODECOPY opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_code = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    const test_address = Address.fromBytes([_]u8{0x88} ++ [_]u8{0} ** 19) catch unreachable;
    try evm.code_map.put(test_address, &test_code);

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Copy 4 bytes from offset 1 of external code to memory offset 0
    try frame.stack.push(0x88); // address
    try frame.stack.push(0); // destOffset
    try frame.stack.push(1); // offset
    try frame.stack.push(4); // length

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.extcodecopy(frame, dispatch);

    // Check memory contents
    const mem_slice = try frame.memory.get_slice(0, 4);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAD, 0xBE, 0xEF, 0xCA }, mem_slice);
}

test "EXTCODEHASH opcode - existing account with code" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_code = [_]u8{ 0x60, 0x00 }; // PUSH1 0x00
    const test_address = Address.fromBytes([_]u8{0x77} ++ [_]u8{0} ** 19) catch unreachable;
    try evm.code_map.put(test_address, &test_code);

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Get code hash of test address
    try frame.stack.push(0x77);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.extcodehash(frame, dispatch);

    // Calculate expected hash of test_code
    var expected_hash: [32]u8 = undefined;
    keccak_asm.keccak256(&test_code, &expected_hash) catch unreachable;
    var expected_u256: u256 = 0;
    for (expected_hash) |b| {
        expected_u256 = (expected_u256 << 8) | @as(u256, b);
    }

    const result = try frame.stack.pop();
    try testing.expectEqual(expected_u256, result);
}

test "EXTCODEHASH opcode - existing account without code" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Get code hash of account without code (EOA)
    try frame.stack.push(0x66);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.extcodehash(frame, dispatch);

    // Expected hash is keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const expected = @as(u256, 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);
    const result = try frame.stack.pop();
    try testing.expectEqual(expected, result);
}

test "EXTCODEHASH opcode - non-existent account" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Get code hash of non-existent account (mocked as 0xFFFF...)
    const non_existent = std.math.maxInt(u256);
    try frame.stack.push(non_existent);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.extcodehash(frame, dispatch);

    // Non-existent account should return 0
    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);
}

test "RETURNDATASIZE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const return_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    evm.return_data = &return_data;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.returndatasize(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 10), result);
}

test "RETURNDATACOPY opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const return_data = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    evm.return_data = &return_data;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Copy 3 bytes from offset 2 to memory offset 0
    try frame.stack.push(0); // destOffset
    try frame.stack.push(2); // offset
    try frame.stack.push(3); // length

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

    // Check memory contents
    const mem_slice = try frame.memory.get_slice(0, 3);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x33, 0x44, 0x55 }, mem_slice);
}

test "BLOCKHASH opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test: get hash of recent block
    try frame.stack.push(12345677); // Current block - 1

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blockhash(frame, dispatch);

    const result = try frame.stack.pop();
    // Mock returns hash filled with (block_number & 0xFF)
    const expected_byte = @as(u8, @intCast(12345677 & 0xFF));
    var expected: u256 = 0;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        expected = (expected << 8) | expected_byte;
    }
    try testing.expectEqual(expected, result);
}

test "COINBASE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const coinbase = Address.fromBytes([_]u8{0xF0} ++ [_]u8{0} ** 19) catch unreachable;
    evm.block_info.coinbase = coinbase;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.coinbase(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0xF0), result);
}

test "TIMESTAMP opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.block_info.timestamp = 1234567890;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.timestamp(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 1234567890), result);
}

test "NUMBER opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.number(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 12345678), result);
}

test "DIFFICULTY opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.block_info.difficulty = 999999999;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.difficulty(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 999999999), result);
}

test "GASLIMIT opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gaslimit(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 30_000_000), result);
}

test "CHAINID opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.chain_id = 56; // BSC mainnet

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.chainid(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 56), result);
}

test "SELFBALANCE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.selfbalance(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), result);
}

test "BASEFEE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    evm.block_info.base_fee = 15_000_000_000; // 15 gwei

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.basefee(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 15_000_000_000), result);
}

test "BLOBHASH opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test: get blob hash at index 1
    try frame.stack.push(1);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blobhash(frame, dispatch);

    const result = try frame.stack.pop();
    // Mock returns hash filled with (0xAA + index)
    const expected_byte = 0xAB; // 0xAA + 1
    var expected: u256 = 0;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        expected = (expected << 8) | expected_byte;
    }
    try testing.expectEqual(expected, result);
}

test "BLOBBASEFEE opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blobbasefee(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 1), result);
}

test "GAS opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    frame.gas_remaining = 500000;

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gas(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 500000), result);
}

test "PC opcode" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatchWithPc(42);
    _ = try TestFrame.ContextHandlers.pc(frame, dispatch);

    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 42), result);
}

// ====== COMPREHENSIVE TESTS ======

test "Address conversion helpers - boundary values" {
    // Test to_u256 and from_u256 roundtrip
    const test_addresses = [_]Address{
        Address.zero(),
        Address.fromBytes([_]u8{0xFF} ** 20) catch unreachable,
        Address.fromBytes([_]u8{ 0x12, 0x34 } ++ [_]u8{0} ** 18) catch unreachable,
        Address.fromBytes([_]u8{0} ** 19 ++ [_]u8{0xFF}) catch unreachable,
        Address.fromBytes([_]u8{0x80} ++ [_]u8{0} ** 19) catch unreachable,
    };

    for (test_addresses) |addr| {
        const u256_val = TestFrame.ContextHandlers.to_u256(addr);
        const addr_back = TestFrame.ContextHandlers.from_u256(u256_val);
        try testing.expect(addr.eql(addr_back));
    }
}

test "ADDRESS opcode - various contract addresses" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_cases = [_]Address{
        Address.zero(),
        Address.fromBytes([_]u8{0xFF} ** 20) catch unreachable,
        Address.fromBytes([_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }) catch unreachable,
        Address.fromBytes([_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ [_]u8{0} ** 16) catch unreachable,
    };

    const host = evm.to_host();

    for (test_cases) |test_addr| {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        frame.contract_address = test_addr;

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.address(frame, dispatch);

        const result = try frame.stack.pop();
        const expected = TestFrame.ContextHandlers.to_u256(test_addr);
        try testing.expectEqual(expected, result);
    }
}

test "BALANCE opcode - address overflow handling" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test with maximum u256 value (should truncate to valid address)
    try frame.stack.push(std.math.maxInt(u256));

    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.balance(frame, dispatch);

    const result = try frame.stack.pop();
    // Should return the mock balance
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), result);
}

test "CALLDATALOAD opcode - edge cases" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const calldata = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    evm.input_data = &calldata;

    const host = evm.to_host();

    // Test cases: offset, expected result description
    const test_cases = [_]struct { offset: u256, check: fn (u256) anyerror!void }{
        // Offset 0: should load first 32 bytes with zero padding
        .{
            .offset = 0,
            .check = struct {
                fn check(result: u256) !void {
                    const expected = (@as(u256, 0x0102030405) << 216); // 27 bytes of zeros
                    try testing.expectEqual(expected, result);
                }
            }.check,
        },
        // Offset at end: should load all zeros
        .{ .offset = 5, .check = struct {
            fn check(result: u256) !void {
                try testing.expectEqual(@as(u256, 0), result);
            }
        }.check },
        // Offset past end: should load all zeros
        .{ .offset = 100, .check = struct {
            fn check(result: u256) !void {
                try testing.expectEqual(@as(u256, 0), result);
            }
        }.check },
        // Offset at max u256: should load all zeros (overflow check)
        .{ .offset = std.math.maxInt(u256), .check = struct {
            fn check(result: u256) !void {
                try testing.expectEqual(@as(u256, 0), result);
            }
        }.check },
        // Offset 3: partial load
        .{
            .offset = 3,
            .check = struct {
                fn check(result: u256) !void {
                    const expected = (@as(u256, 0x0405) << 240); // 30 bytes of zeros
                    try testing.expectEqual(expected, result);
                }
            }.check,
        },
    };

    for (test_cases) |tc| {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(tc.offset);

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.calldataload(frame, dispatch);

        const result = try frame.stack.pop();
        try tc.check(result);
    }
}

test "CALLDATACOPY opcode - boundary conditions" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const calldata = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    evm.input_data = &calldata;

    const host = evm.to_host();

    // Test zero length copy
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(0); // offset
        try frame.stack.push(0); // length

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.calldatacopy(frame, dispatch);

        // Should succeed without modifying memory
        try testing.expectEqual(@as(usize, 0), frame.memory.size());
    }

    // Test copy beyond calldata length (should zero-pad)
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(3); // offset (start at 0xDD)
        try frame.stack.push(5); // length (need 3 bytes of padding)

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.calldatacopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 5);
        try testing.expectEqualSlices(u8, &[_]u8{ 0xDD, 0xEE, 0x00, 0x00, 0x00 }, result);
    }

    // Test overflow protection
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(std.math.maxInt(u256)); // destOffset (overflow)
        try frame.stack.push(0); // offset
        try frame.stack.push(1); // length

        const dispatch = createMockDispatch();
        const result = TestFrame.ContextHandlers.calldatacopy(frame, dispatch);

        try testing.expectError(TestFrame.Error.OutOfBounds, result);
    }
}

test "CODECOPY opcode - edge cases" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    const host = evm.to_host();

    // Create code data
    const code_data = [_]u8{ 0x60, 0x40, 0x60, 0x80, 0x50 };

    // Test copy beyond code length (should zero-pad)
    {
        const database = try MemoryDatabase.init(testing.allocator);
        const value = try testing.allocator.create(u256);
        value.* = 0;
        var frame = try TestFrame.init(testing.allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, host);
        defer frame.deinit(testing.allocator);
        defer testing.allocator.destroy(value);
        frame.code = &code_data;

        try frame.stack.push(0); // destOffset
        try frame.stack.push(3); // offset
        try frame.stack.push(5); // length (need 3 bytes of padding)

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.codecopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 5);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x50, 0x00, 0x00, 0x00 }, result);
    }

    // Test large offset (past code end)
    {
        const database = try MemoryDatabase.init(testing.allocator);
        const value = try testing.allocator.create(u256);
        value.* = 0;
        var frame = try TestFrame.init(testing.allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, host);
        defer frame.deinit(testing.allocator);
        defer testing.allocator.destroy(value);
        frame.code = &code_data;

        try frame.stack.push(0); // destOffset
        try frame.stack.push(1000); // offset (way past code end)
        try frame.stack.push(32); // length

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.codecopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 32);
        // Should be all zeros
        for (result) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }
}

test "EXTCODECOPY opcode - boundary conditions" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_code = [_]u8{ 0x11, 0x22, 0x33 };
    const test_address = Address.fromBytes([_]u8{0x99} ++ [_]u8{0} ** 19) catch unreachable;
    try evm.code_map.put(test_address, &test_code);

    const host = evm.to_host();

    // Test copy with zero-padding
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0x99); // address
        try frame.stack.push(0); // destOffset
        try frame.stack.push(1); // offset
        try frame.stack.push(5); // length (need padding)

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.extcodecopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 5);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x22, 0x33, 0x00, 0x00, 0x00 }, result);
    }

    // Test non-existent contract (empty code)
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0x77); // address with no code
        try frame.stack.push(0); // destOffset
        try frame.stack.push(0); // offset
        try frame.stack.push(4); // length

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.extcodecopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 4);
        // Should be all zeros
        try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00 }, result);
    }
}

test "RETURNDATACOPY opcode - strict bounds checking" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const return_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    evm.return_data = &return_data;

    const host = evm.to_host();

    // Test exact boundary read
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(0); // offset
        try frame.stack.push(4); // length (exact size)

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        const result = try frame.memory.get_slice(0, 4);
        try testing.expectEqualSlices(u8, &return_data, result);
    }

    // Test read past end (should fail, unlike CALLDATACOPY)
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(2); // offset
        try frame.stack.push(3); // length (would need 1 byte past end)

        const dispatch = createMockDispatch();
        const result = TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        try testing.expectError(TestFrame.Error.OutOfBounds, result);
    }

    // Test offset past end
    {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(5); // offset (past end)
        try frame.stack.push(1); // length

        const dispatch = createMockDispatch();
        const result = TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        try testing.expectError(TestFrame.Error.OutOfBounds, result);
    }
}

test "RETURNDATASIZE - comprehensive tests" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Test with empty return data
    {
        evm.return_data = &.{};
        var frame = try createTestFrame(testing.allocator, &evm);
        defer frame.deinit(testing.allocator);

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatasize(frame, dispatch);

        const result = try frame.stack.pop();
        try testing.expectEqual(@as(u256, 0), result);
    }

    // Test with various sizes
    const test_sizes = [_]usize{ 1, 32, 64, 128, 256, 1024, 4096 };
    for (test_sizes) |size| {
        const data = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(data);
        @memset(data, 0xAB);

        evm.return_data = data;
        var frame = try createTestFrame(testing.allocator, &evm);
        defer frame.deinit(testing.allocator);

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatasize(frame, dispatch);

        const result = try frame.stack.pop();
        try testing.expectEqual(@as(u256, size), result);
    }
}

test "RETURNDATACOPY - comprehensive tests" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Test copying entire return data
    {
        const return_data = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        evm.return_data = &return_data;

        var frame = try createTestFrame(testing.allocator, &evm);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(0); // offset
        try frame.stack.push(8); // length

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        const mem_slice = try frame.memory.get_slice(0, 8);
        try testing.expectEqualSlices(u8, &return_data, mem_slice);
    }

    // Test partial copy with offset
    {
        const return_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        evm.return_data = &return_data;

        var frame = try createTestFrame(testing.allocator, &evm);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(10); // destOffset
        try frame.stack.push(2); // offset (skip first 2 bytes)
        try frame.stack.push(3); // length

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        const mem_slice = try frame.memory.get_slice(10, 3);
        try testing.expectEqualSlices(u8, &[_]u8{ 0xCC, 0xDD, 0xEE }, mem_slice);
    }

    // Test zero-length copy (should succeed)
    {
        const return_data = [_]u8{0x42};
        evm.return_data = &return_data;

        var frame = try createTestFrame(testing.allocator, &evm);
        defer frame.deinit(testing.allocator);

        try frame.stack.push(0); // destOffset
        try frame.stack.push(0); // offset
        try frame.stack.push(0); // length = 0

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.returndatacopy(frame, dispatch);

        // Should not error
    }
}

test "BLOCKHASH opcode - edge cases" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Current block number is 12345678 in mock

    // Test: block too old (more than 256 blocks ago)
    try frame.stack.push(12345678 - 257);
    var dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blockhash(frame, dispatch);
    var result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);

    // Test: future block
    try frame.stack.push(12345678 + 1);
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blockhash(frame, dispatch);
    result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);

    // Test: current block (should return 0)
    try frame.stack.push(12345678);
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blockhash(frame, dispatch);
    result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);

    // Test: valid recent block (256 blocks ago exactly)
    try frame.stack.push(12345678 - 256);
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blockhash(frame, dispatch);
    result = try frame.stack.pop();
    // Should get a valid hash
    const expected_byte = @as(u8, @intCast((12345678 - 256) & 0xFF));
    var expected: u256 = 0;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        expected = (expected << 8) | expected_byte;
    }
    try testing.expectEqual(expected, result);
}

test "Block info opcodes - various values" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Set extreme values
    evm.block_info = .{
        .coinbase = Address.fromBytes([_]u8{0xFF} ** 20) catch unreachable,
        .timestamp = std.math.maxInt(u64),
        .number = std.math.maxInt(u64),
        .difficulty = std.math.maxInt(u256),
        .gas_limit = std.math.maxInt(u64),
        .base_fee = std.math.maxInt(u256),
    };

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test COINBASE with max address
    var dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.coinbase(frame, dispatch);
    const coinbase = try frame.stack.pop();
    const expected_coinbase = (@as(u256, 1) << 160) - 1; // Max 160-bit value
    try testing.expectEqual(expected_coinbase, coinbase);

    // Test TIMESTAMP with max value
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.timestamp(frame, dispatch);
    const timestamp = try frame.stack.pop();
    try testing.expectEqual(@as(u256, std.math.maxInt(u64)), timestamp);

    // Test DIFFICULTY with max value
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.difficulty(frame, dispatch);
    const difficulty = try frame.stack.pop();
    try testing.expectEqual(std.math.maxInt(u256), difficulty);

    // Test PREVRANDAO (alias for DIFFICULTY)
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.prevrandao(frame, dispatch);
    const prevrandao = try frame.stack.pop();
    try testing.expectEqual(std.math.maxInt(u256), prevrandao);
}

test "BLOBHASH opcode - index boundaries" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test valid indices (0, 1, 2)
    const valid_indices = [_]u256{ 0, 1, 2 };
    for (valid_indices) |idx| {
        try frame.stack.push(idx);
        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.blobhash(frame, dispatch);
        const result = try frame.stack.pop();

        // Mock returns hash filled with (0xAA + index)
        const expected_byte = @as(u8, @intCast(0xAA + idx));
        var expected: u256 = 0;
        var i: u32 = 0;
        while (i < 32) : (i += 1) {
            expected = (expected << 8) | expected_byte;
        }
        try testing.expectEqual(expected, result);
    }

    // Test invalid index
    try frame.stack.push(3); // Beyond valid range
    var dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blobhash(frame, dispatch);
    const result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);

    // Test max u256 index
    try frame.stack.push(std.math.maxInt(u256));
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.blobhash(frame, dispatch);
    const result_max = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result_max);
}

test "GAS opcode - negative gas handling" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test with positive gas
    frame.gas_remaining = 123456;
    var dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gas(frame, dispatch);
    var result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 123456), result);

    // Test with zero gas
    frame.gas_remaining = 0;
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gas(frame, dispatch);
    result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);

    // Test with negative gas (should return 0)
    frame.gas_remaining = -100;
    dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.gas(frame, dispatch);
    result = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), result);
}

test "PC opcode - various program counter values" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    const host = evm.to_host();

    const pc_values = [_]u256{
        0, // Start of code
        1, // First instruction
        255, // End of typical basic block
        256, // Start of next page
        65535, // Max 16-bit
        65536, // Beyond 16-bit
        16777215, // Max 24-bit (typical max contract size)
        std.math.maxInt(u32), // Max 32-bit
        std.math.maxInt(u256), // Max possible
    };

    for (pc_values) |pc_val| {
        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        const dispatch = createMockDispatchWithPc(pc_val);
        _ = try TestFrame.ContextHandlers.pc(frame, dispatch);

        const result = try frame.stack.pop();
        try testing.expectEqual(pc_val, result);
    }
}

test "Context opcodes - stack underflow" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Opcodes that require stack items
    const dispatch = createMockDispatch();

    // BALANCE requires 1 stack item
    var result = TestFrame.ContextHandlers.balance(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackUnderflow, result);

    // CALLDATALOAD requires 1 stack item
    result = TestFrame.ContextHandlers.calldataload(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackUnderflow, result);

    // CALLDATACOPY requires 3 stack items
    result = TestFrame.ContextHandlers.calldatacopy(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackUnderflow, result);

    try frame.stack.push(0);
    result = TestFrame.ContextHandlers.calldatacopy(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackUnderflow, result);

    try frame.stack.push(0);
    result = TestFrame.ContextHandlers.calldatacopy(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackUnderflow, result);
}

test "Context opcodes - stack overflow" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Fill stack to maximum
    const max_stack = 1024;
    for (0..max_stack) |_| {
        try frame.stack.push(0);
    }

    // Any opcode that pushes should fail
    const dispatch = createMockDispatch();

    // ADDRESS pushes 1 value
    const result = TestFrame.ContextHandlers.address(frame, dispatch);
    try testing.expectError(TestFrame.Error.StackOverflow, result);
}

test "Memory copy operations - large offsets" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    const test_data = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    evm.input_data = &test_data;

    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Test memory limit with CALLDATACOPY
    const large_offset = @as(u256, test_config.memory_limit - 10);
    try frame.stack.push(large_offset); // destOffset (near memory limit)
    try frame.stack.push(0); // offset
    try frame.stack.push(32); // length (would exceed limit)

    const dispatch = createMockDispatch();
    const result = TestFrame.ContextHandlers.calldatacopy(frame, dispatch);

    try testing.expectError(TestFrame.Error.AllocationError, result);
}

test "EXTCODEHASH opcode - empty code hash constant" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();
    var frame = try createTestFrame(testing.allocator, &evm);
    defer frame.deinit(testing.allocator);

    // Verify the empty code hash constant is correct
    const empty_code: []const u8 = &.{};
    var expected_hash_bytes: [32]u8 = undefined;
    keccak_asm.keccak256(empty_code, &expected_hash_bytes) catch unreachable;

    var expected_hash_computed: u256 = 0;
    for (expected_hash_bytes) |b| {
        expected_hash_computed = (expected_hash_computed << 8) | @as(u256, b);
    }

    // The hardcoded constant in the code
    const hardcoded_empty_hash = @as(u256, 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);

    // Verify they match
    try testing.expectEqual(expected_hash_computed, hardcoded_empty_hash);
}

test "Chain ID values" {
    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Test various chain IDs
    const chain_ids = [_]u64{
        1, // Ethereum mainnet
        56, // BSC
        137, // Polygon
        42161, // Arbitrum One
        std.math.maxInt(u64), // Maximum chain ID
    };

    const host = evm.to_host();

    for (chain_ids) |chain_id| {
        evm.chain_id = chain_id;

        var frame = try createTestFrame(testing.allocator, host);
        defer frame.deinit(testing.allocator);

        const dispatch = createMockDispatch();
        _ = try TestFrame.ContextHandlers.chainid(frame, dispatch);

        const result = try frame.stack.pop();
        try testing.expectEqual(@as(u256, chain_id), result);
    }
}

test "WordType truncation behavior" {
    // Test when WordType is smaller than u256
    const SmallWordConfig = FrameConfig{
        .stack_size = 1024,
        .WordType = u64, // Smaller than u256
        .max_bytecode_size = 1024,
        .block_gas_limit = 30_000_000,
        .DatabaseType = @import("../storage/memory_database.zig").MemoryDatabase,
        .memory_initial_capacity = 4096,
        .memory_limit = 0xFFFFFF,
    };

    const SmallFrame = Frame(SmallWordConfig);

    var evm = MockEvm.init(testing.allocator);
    defer evm.deinit();

    // Set values that exceed u64
    evm.block_info.difficulty = std.math.maxInt(u256);
    evm.block_info.base_fee = std.math.maxInt(u256);

    const host = evm.to_host();
    const database = try @import("../storage/memory_database.zig").MemoryDatabase.init(testing.allocator);
    const value = try testing.allocator.create(u64);
    value.* = 0;
    var frame = try SmallFrame.init(testing.allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, host);
    defer frame.deinit(testing.allocator);
    defer testing.allocator.destroy(value);
    frame.code = &[_]u8{};

    // Mock dispatch for SmallFrame
    const mock_handler = struct {
        fn handler(f: SmallFrame, d: SmallFrame.Dispatch) SmallFrame.Error!SmallFrame.Success {
            _ = f;
            _ = d;
            return SmallFrame.Success.stop;
        }
    }.handler;

    var cursor: [1]dispatch_mod.ScheduleElement(SmallFrame) = undefined;
    cursor[0] = .{ .opcode_handler = &mock_handler };

    const dispatch = SmallFrame.Dispatch{
        .cursor = &cursor,
        .bytecode_length = 0,
    };

    // Test DIFFICULTY with value larger than u64
    _ = try SmallFrame.ContextHandlers.difficulty(frame, dispatch);
    const difficulty = try frame.stack.pop();
    // Should be truncated to u64 max
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), difficulty);

    // Test BASEFEE with value larger than u64
    _ = try SmallFrame.ContextHandlers.basefee(frame, dispatch);
    const base_fee = try frame.stack.pop();
    // Should be truncated to u64 max
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), base_fee);
}

test "RETURNDATASIZE and RETURNDATACOPY basic functionality" {
    const allocator = testing.allocator;

    // Create frame with test config
    var frame = try createTestFrame(allocator);
    defer frame.deinit(allocator);

    // Initially, return data should be empty
    try testing.expectEqual(@as(usize, 0), frame.output.len);

    // Test RETURNDATASIZE with empty data
    const dispatch = createMockDispatch();
    _ = try TestFrame.ContextHandlers.returndatasize(&frame, dispatch);
    const empty_size = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 0), empty_size);

    // Set some return data - inline setOutput logic
    const test_data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    // Free existing output if any
    if (frame.output.len > 0) {
        allocator.free(frame.output);
    }
    // Set new output
    const new_output = try allocator.alloc(u8, test_data.len);
    @memcpy(new_output, &test_data);
    frame.output = new_output;

    // Test RETURNDATASIZE with data
    _ = try TestFrame.ContextHandlers.returndatasize(&frame, dispatch);
    const data_size = try frame.stack.pop();
    try testing.expectEqual(@as(u256, 8), data_size);

    // Test RETURNDATACOPY
    try frame.stack.push(0); // destOffset
    try frame.stack.push(0); // offset
    try frame.stack.push(8); // length

    _ = try TestFrame.ContextHandlers.returndatacopy(&frame, dispatch);

    // Verify data was copied to memory
    const memory_data = frame.memory.get_slice(0, 8) catch unreachable;
    try testing.expectEqualSlices(u8, &test_data, memory_data);
}

test "RETURNDATACOPY out of bounds" {
    const allocator = testing.allocator;

    var frame = try createTestFrame(allocator);
    defer frame.deinit(allocator);

    // Set small return data - inline setOutput logic
    const test_data = [_]u8{ 0xAA, 0xBB };
    // Free existing output if any
    if (frame.output.len > 0) {
        allocator.free(frame.output);
    }
    // Set new output
    const new_output = try allocator.alloc(u8, test_data.len);
    @memcpy(new_output, &test_data);
    frame.output = new_output;

    // Try to copy more data than available
    try frame.stack.push(0); // destOffset
    try frame.stack.push(0); // offset
    try frame.stack.push(4); // length (more than available)

    const dispatch = createMockDispatch();
    const result = TestFrame.ContextHandlers.returndatacopy(&frame, dispatch);

    // Should return OutOfBounds error
    try testing.expectError(TestFrame.Error.OutOfBounds, result);
}
