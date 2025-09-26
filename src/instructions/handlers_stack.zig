const std = @import("std");
const FrameConfig = @import("../frame/frame_config.zig").FrameConfig;
const log = @import("../log.zig");

/// Stack manipulation opcode handlers for the EVM stack frame.
/// These are generic structs that return static handlers for a given FrameType.
pub fn Handlers(FrameType: type) type {
    return struct {
        pub const Error = FrameType.Error;
        pub const Dispatch = FrameType.Dispatch;
        pub const WordType = FrameType.WordType;
        const dispatch_opcode_data = @import("../preprocessor/dispatch_opcode_data.zig");

        /// Continue to next instruction with afterInstruction tracking
        pub inline fn next_instruction(self: *FrameType, cursor: [*]const Dispatch.Item, comptime opcode: Dispatch.UnifiedOpcode) Error!noreturn {
            const op_data = dispatch_opcode_data.getOpData(opcode, Dispatch, Dispatch.Item, cursor);
            self.afterInstruction(opcode, op_data.next_handler, op_data.next_cursor.cursor);
            return @call(FrameType.Dispatch.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
        }

        /// POP opcode (0x50) - Remove item from stack.
        pub fn pop(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.POP, cursor);
            _ = self.stack.pop_unsafe();
            return next_instruction(self, cursor, .POP);
        }

        /// PUSH0 opcode (0x5f) - Push 0 onto stack.
        pub fn push0(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
            self.beforeInstruction(.PUSH0, cursor);
            self.stack.push_unsafe(0);
            return next_instruction(self, cursor, .PUSH0);
        }

        /// Generate a push handler for PUSH1-PUSH32
        pub fn generatePushHandler(comptime push_n: u8) FrameType.OpcodeHandler {
            std.debug.assert(push_n <= 32); // Only PUSH1 to PUSH32 is supported
            std.debug.assert(push_n != 0); // PUSH0 is handled as its own opcode
            return &struct {
                pub fn pushHandler(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
                    const opcode = switch (push_n) {
                        1 => @import("../opcodes/opcode.zig").UnifiedOpcode.PUSH1,
                        2 => .PUSH2,
                        3 => .PUSH3,
                        4 => .PUSH4,
                        5 => .PUSH5,
                        6 => .PUSH6,
                        7 => .PUSH7,
                        8 => .PUSH8,
                        9 => .PUSH9,
                        10 => .PUSH10,
                        11 => .PUSH11,
                        12 => .PUSH12,
                        13 => .PUSH13,
                        14 => .PUSH14,
                        15 => .PUSH15,
                        16 => .PUSH16,
                        17 => .PUSH17,
                        18 => .PUSH18,
                        19 => .PUSH19,
                        20 => .PUSH20,
                        21 => .PUSH21,
                        22 => .PUSH22,
                        23 => .PUSH23,
                        24 => .PUSH24,
                        25 => .PUSH25,
                        26 => .PUSH26,
                        27 => .PUSH27,
                        28 => .PUSH28,
                        29 => .PUSH29,
                        30 => .PUSH30,
                        31 => .PUSH31,
                        32 => .PUSH32,
                        else => unreachable,
                    };
                    self.beforeInstruction(opcode, cursor);
                    const dispatch = Dispatch{ .cursor = cursor };

                    // For PUSH1-PUSH8, we get push_inline metadata with u64 value
                    // For PUSH9-PUSH32, we get push_pointer metadata with *u256 value
                    const op_data = switch (push_n) {
                        1 => dispatch.getOpData(.PUSH1),
                        2 => dispatch.getOpData(.PUSH2),
                        3 => dispatch.getOpData(.PUSH3),
                        4 => dispatch.getOpData(.PUSH4),
                        5 => dispatch.getOpData(.PUSH5),
                        6 => dispatch.getOpData(.PUSH6),
                        7 => dispatch.getOpData(.PUSH7),
                        8 => dispatch.getOpData(.PUSH8),
                        9 => dispatch.getOpData(.PUSH9),
                        10 => dispatch.getOpData(.PUSH10),
                        11 => dispatch.getOpData(.PUSH11),
                        12 => dispatch.getOpData(.PUSH12),
                        13 => dispatch.getOpData(.PUSH13),
                        14 => dispatch.getOpData(.PUSH14),
                        15 => dispatch.getOpData(.PUSH15),
                        16 => dispatch.getOpData(.PUSH16),
                        17 => dispatch.getOpData(.PUSH17),
                        18 => dispatch.getOpData(.PUSH18),
                        19 => dispatch.getOpData(.PUSH19),
                        20 => dispatch.getOpData(.PUSH20),
                        21 => dispatch.getOpData(.PUSH21),
                        22 => dispatch.getOpData(.PUSH22),
                        23 => dispatch.getOpData(.PUSH23),
                        24 => dispatch.getOpData(.PUSH24),
                        25 => dispatch.getOpData(.PUSH25),
                        26 => dispatch.getOpData(.PUSH26),
                        27 => dispatch.getOpData(.PUSH27),
                        28 => dispatch.getOpData(.PUSH28),
                        29 => dispatch.getOpData(.PUSH29),
                        30 => dispatch.getOpData(.PUSH30),
                        31 => dispatch.getOpData(.PUSH31),
                        32 => dispatch.getOpData(.PUSH32),
                        else => unreachable,
                    };

                    if (comptime push_n <= 8) {
                        const value = op_data.metadata.value;
                        log.debug("[PUSH{d}] Pushing inline value: 0x{x:0>16}", .{ push_n, value });
                        self.stack.push_unsafe(value);
                    } else {
                        const value = op_data.metadata.value_ptr.*;
                        log.debug("[PUSH{d}] Pushing pointer value: 0x{x:0>64}", .{ push_n, value });
                        self.stack.push_unsafe(value);
                    }
                    self.afterInstruction(opcode, op_data.next_handler, op_data.next_cursor.cursor);
                    return @call(FrameType.Dispatch.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
                }
            }.pushHandler;
        }

        /// Generate a dup handler for DUP1-DUP16
        pub fn generateDupHandler(comptime dup_n: u8) FrameType.OpcodeHandler {
            std.debug.assert(dup_n > 0 and dup_n <= 16); // Only DUP1 to DUP16 is supported
            return &struct {
                pub fn dupHandler(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
                    const opcode = switch (dup_n) {
                        1 => @import("../opcodes/opcode.zig").UnifiedOpcode.DUP1,
                        2 => .DUP2,
                        3 => .DUP3,
                        4 => .DUP4,
                        5 => .DUP5,
                        6 => .DUP6,
                        7 => .DUP7,
                        8 => .DUP8,
                        9 => .DUP9,
                        10 => .DUP10,
                        11 => .DUP11,
                        12 => .DUP12,
                        13 => .DUP13,
                        14 => .DUP14,
                        15 => .DUP15,
                        16 => .DUP16,
                        else => unreachable,
                    };
                    self.beforeInstruction(opcode, cursor);
                    self.stack.dup_n_unsafe(dup_n);
                    const dispatch = Dispatch{ .cursor = cursor };
                    // DUP operations don't have metadata, just get next
                    const op_data = switch (dup_n) {
                        1 => dispatch.getOpData(.DUP1),
                        2 => dispatch.getOpData(.DUP2),
                        3 => dispatch.getOpData(.DUP3),
                        4 => dispatch.getOpData(.DUP4),
                        5 => dispatch.getOpData(.DUP5),
                        6 => dispatch.getOpData(.DUP6),
                        7 => dispatch.getOpData(.DUP7),
                        8 => dispatch.getOpData(.DUP8),
                        9 => dispatch.getOpData(.DUP9),
                        10 => dispatch.getOpData(.DUP10),
                        11 => dispatch.getOpData(.DUP11),
                        12 => dispatch.getOpData(.DUP12),
                        13 => dispatch.getOpData(.DUP13),
                        14 => dispatch.getOpData(.DUP14),
                        15 => dispatch.getOpData(.DUP15),
                        16 => dispatch.getOpData(.DUP16),
                        else => unreachable,
                    };
                    self.afterInstruction(opcode, op_data.next_handler, op_data.next_cursor.cursor);
                    return @call(FrameType.Dispatch.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
                }
            }.dupHandler;
        }

        /// Generate a swap handler for SWAP1-SWAP16
        pub fn generateSwapHandler(comptime swap_n: u8) FrameType.OpcodeHandler {
            std.debug.assert(swap_n > 0 and swap_n <= 16); // Only SWAP1 to SWAP16 is supported
            return &struct {
                pub fn swapHandler(self: *FrameType, cursor: [*]const Dispatch.Item) Error!noreturn {
                    const opcode = switch (swap_n) {
                        1 => @import("../opcodes/opcode.zig").UnifiedOpcode.SWAP1,
                        2 => .SWAP2,
                        3 => .SWAP3,
                        4 => .SWAP4,
                        5 => .SWAP5,
                        6 => .SWAP6,
                        7 => .SWAP7,
                        8 => .SWAP8,
                        9 => .SWAP9,
                        10 => .SWAP10,
                        11 => .SWAP11,
                        12 => .SWAP12,
                        13 => .SWAP13,
                        14 => .SWAP14,
                        15 => .SWAP15,
                        16 => .SWAP16,
                        else => unreachable,
                    };
                    self.beforeInstruction(opcode, cursor);
                    self.stack.swap_n_unsafe(swap_n);
                    const dispatch = Dispatch{ .cursor = cursor };
                    // SWAP operations don't have metadata, just get next
                    const op_data = switch (swap_n) {
                        1 => dispatch.getOpData(.SWAP1),
                        2 => dispatch.getOpData(.SWAP2),
                        3 => dispatch.getOpData(.SWAP3),
                        4 => dispatch.getOpData(.SWAP4),
                        5 => dispatch.getOpData(.SWAP5),
                        6 => dispatch.getOpData(.SWAP6),
                        7 => dispatch.getOpData(.SWAP7),
                        8 => dispatch.getOpData(.SWAP8),
                        9 => dispatch.getOpData(.SWAP9),
                        10 => dispatch.getOpData(.SWAP10),
                        11 => dispatch.getOpData(.SWAP11),
                        12 => dispatch.getOpData(.SWAP12),
                        13 => dispatch.getOpData(.SWAP13),
                        14 => dispatch.getOpData(.SWAP14),
                        15 => dispatch.getOpData(.SWAP15),
                        16 => dispatch.getOpData(.SWAP16),
                        else => unreachable,
                    };
                    self.afterInstruction(opcode, op_data.next_handler, op_data.next_cursor.cursor);
                    return @call(FrameType.Dispatch.getTailCallModifier(), op_data.next_handler, .{ self, op_data.next_cursor.cursor });
                }
            }.swapHandler;
        }
    };
}

// ====== TESTS ======

const testing = std.testing;
const Frame = @import("../frame/frame.zig").Frame;
const dispatch_mod = @import("../preprocessor/dispatch.zig");
const DefaultTracer = @import("../tracer/tracer.zig").DefaultTracer;
const MemoryDatabase = @import("../storage/memory_database.zig").MemoryDatabase;
const Address = @import("primitives").Address;

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

fn createTestFrame(allocator: std.mem.Allocator) !TestFrame {
    const database = MemoryDatabase.init(allocator);
    const value = try allocator.create(u256);
    value.* = 0;
    const evm_ptr = @as(*anyopaque, @ptrFromInt(0x1000)); // Use a dummy pointer for tests
    var frame = try TestFrame.init(allocator, 1_000_000, database, Address.ZERO_ADDRESS, value, &[_]u8{}, evm_ptr);
    frame.code = &[_]u8{}; // Empty code by default
    return frame;
}

// Mock dispatch that simulates successful execution flow
fn createMockDispatch() TestFrame.Dispatch {
    const mock_handler = struct {
        fn handler(frame: *TestFrame, dispatch: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = frame;
            _ = dispatch;
            return TestFrame.Success.Stop;
        }
    }.handler;

    const schedule_item = dispatch_mod.ScheduleItem{
        .opcode_handler = &mock_handler,
        .metadata = undefined,
    };
    const schedule_ptr = &schedule_item;

    return TestFrame.Dispatch{
        .cursor = schedule_ptr,
        .jump_table = null,
    };
}

test "POP opcode - basic pop" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push value then pop it
    try frame.stack.push(42);

    const dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.pop(frame, dispatch);

    try testing.expectEqual(@as(usize, 0), frame.stack.len());
}

test "POP opcode - stack underflow" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Try to pop from empty stack
    const dispatch = createMockDispatch();
    const result = TestFrame.StackHandlers.pop(frame, dispatch);

    try testing.expectError(TestFrame.Error.StackUnderflow, result);
}

test "PUSH0 opcode - push zero" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    const dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.push0(frame, dispatch);

    try testing.expectEqual(@as(u256, 0), try frame.stack.pop());
    try testing.expectEqual(@as(usize, 0), frame.stack.len());
}

test "DUP1 opcode - duplicate top" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    try frame.stack.push(42);

    const DupHandler = TestFrame.StackHandlers.generateDupHandler(1);
    const dispatch = createMockDispatch();
    _ = try DupHandler(frame, dispatch);

    try testing.expectEqual(@as(usize, 2), frame.stack.len());
    try testing.expectEqual(@as(u256, 42), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 42), try frame.stack.pop());
}

test "DUP16 opcode - duplicate 16th item" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push 16 different values
    for (1..17) |i| {
        try frame.stack.push(@as(u256, i));
    }

    const DupHandler = TestFrame.StackHandlers.generateDupHandler(16);
    const dispatch = createMockDispatch();
    _ = try DupHandler(frame, dispatch);

    try testing.expectEqual(@as(usize, 17), frame.stack.len());
    try testing.expectEqual(@as(u256, 1), try frame.stack.pop()); // Duplicated value from bottom
}

test "SWAP1 opcode - swap top two" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    try frame.stack.push(1);
    try frame.stack.push(2);

    const SwapHandler = TestFrame.StackHandlers.generateSwapHandler(1);
    const dispatch = createMockDispatch();
    _ = try SwapHandler(frame, dispatch);

    try testing.expectEqual(@as(u256, 1), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 2), try frame.stack.pop());
}

test "SWAP16 opcode - swap with 16th item" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push 17 values: 1 to 17
    for (1..18) |i| {
        try frame.stack.push(@as(u256, i));
    }

    const SwapHandler = TestFrame.StackHandlers.generateSwapHandler(16);
    const dispatch = createMockDispatch();
    _ = try SwapHandler(frame, dispatch);

    // Top should now be 1, and 17th position should be 17
    try testing.expectEqual(@as(u256, 1), try frame.stack.pop());

    // Pop 15 more to get to what was the 17th position
    for (0..15) |_| {
        _ = try frame.stack.pop();
    }
    try testing.expectEqual(@as(u256, 17), try frame.stack.pop());
}

test "PUSH handler - inline metadata" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test PUSH1 with inline value
    const PushHandler = TestFrame.StackHandlers.generatePushHandler(1);

    // Create dispatch with inline metadata
    const mock_handler = struct {
        fn handler(frame_inner: TestFrame, dispatch_inner: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = frame_inner;
            _ = dispatch_inner;
            return TestFrame.Success.stop;
        }
    }.handler;

    var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    cursor[0] = .{ .opcode_handler = &mock_handler };
    cursor[1] = .{ .opcode_handler = &mock_handler };

    const dispatch = TestFrame.Dispatch{
        .cursor = &cursor,
        .bytecode_length = 0,
    };

    // Set inline metadata
    dispatch.*.cursor[0].metadata = .{ .inline_value = 42 };

    _ = try PushHandler(frame, dispatch);

    try testing.expectEqual(@as(u256, 42), try frame.stack.pop());
}

test "PUSH handler - pointer metadata" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test PUSH32 with pointer value
    const PushHandler = TestFrame.StackHandlers.generatePushHandler(32);

    const value: u256 = std.math.maxInt(u256);

    // Create dispatch with pointer metadata
    const mock_handler = struct {
        fn handler(frame_inner: TestFrame, dispatch_inner: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = frame_inner;
            _ = dispatch_inner;
            return TestFrame.Success.stop;
        }
    }.handler;

    var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    cursor[0] = .{ .opcode_handler = &mock_handler };
    cursor[1] = .{ .opcode_handler = &mock_handler };

    const dispatch = TestFrame.Dispatch{
        .cursor = &cursor,
        .bytecode_length = 0,
    };

    // Set pointer metadata
    dispatch.*.cursor[0].metadata = .{ .pointer_value = &value };

    _ = try PushHandler(frame, dispatch);

    try testing.expectEqual(std.math.maxInt(u256), try frame.stack.pop());
}

// Additional comprehensive tests

test "POP opcode - multiple pops" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push multiple values
    for (1..11) |i| {
        try frame.stack.push(@as(u256, i));
    }

    // Pop 5 times
    for (0..5) |_| {
        const dispatch = createMockDispatch();
        _ = try TestFrame.StackHandlers.pop(frame, dispatch);
    }

    try testing.expectEqual(@as(usize, 5), frame.stack.len());
    try testing.expectEqual(@as(u256, 5), try frame.stack.peek());
}

test "POP opcode - pop all elements" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push and pop 100 elements
    const count = 100;
    for (0..count) |i| {
        try frame.stack.push(@as(u256, i));
    }

    for (0..count) |_| {
        const dispatch = createMockDispatch();
        _ = try TestFrame.StackHandlers.pop(frame, dispatch);
    }

    try testing.expectEqual(@as(usize, 0), frame.stack.len());
}

test "PUSH0 opcode - multiple push0s" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push zero 10 times
    for (0..10) |_| {
        const dispatch = createMockDispatch();
        _ = try TestFrame.StackHandlers.push0(frame, dispatch);
    }

    try testing.expectEqual(@as(usize, 10), frame.stack.len());

    // Verify all are zeros
    for (0..10) |_| {
        try testing.expectEqual(@as(u256, 0), try frame.stack.pop());
    }
}

test "DUP opcodes - all DUP1 to DUP16" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test each DUP operation
    inline for (1..17) |dup_n| {
        // Clear stack
        while (frame.stack.len() > 0) {
            _ = try frame.stack.pop();
        }

        // Push exactly dup_n values
        for (1..dup_n + 1) |i| {
            try frame.stack.push(@as(u256, i * 10));
        }

        const DupHandler = TestFrame.StackHandlers.generateDupHandler(dup_n);
        const dispatch = createMockDispatch();
        _ = try DupHandler(frame, dispatch);

        // Should have dup_n + 1 items now
        try testing.expectEqual(@as(usize, dup_n + 1), frame.stack.len());

        // Top should be the duplicated value
        const expected = @as(u256, 10); // The bottom value that was duplicated
        try testing.expectEqual(expected, try frame.stack.pop());
    }
}

test "SWAP opcodes - all SWAP1 to SWAP16" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test each SWAP operation
    inline for (1..17) |swap_n| {
        // Clear stack
        while (frame.stack.len() > 0) {
            _ = try frame.stack.pop();
        }

        // Push swap_n + 1 values
        for (0..swap_n + 1) |i| {
            try frame.stack.push(@as(u256, i));
        }

        const SwapHandler = TestFrame.StackHandlers.generateSwapHandler(swap_n);
        const dispatch = createMockDispatch();
        _ = try SwapHandler(frame, dispatch);

        // Top should now be what was at position swap_n
        try testing.expectEqual(@as(u256, 0), try frame.stack.pop());

        // And at position swap_n-1 should be what was on top
        for (0..swap_n - 1) |_| {
            _ = try frame.stack.pop();
        }
        try testing.expectEqual(@as(u256, swap_n), try frame.stack.pop());
    }
}

test "Stack operations - complex sequence" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push some initial values
    try frame.stack.push(10);
    try frame.stack.push(20);
    try frame.stack.push(30);

    // DUP2 - duplicate 20
    const Dup2 = TestFrame.StackHandlers.generateDupHandler(2);
    var dispatch = createMockDispatch();
    _ = try Dup2(frame, dispatch);

    // Stack: [10, 20, 30, 20]
    try testing.expectEqual(@as(u256, 20), try frame.stack.peek());

    // SWAP1 - swap top two
    const Swap1 = TestFrame.StackHandlers.generateSwapHandler(1);
    dispatch = createMockDispatch();
    _ = try Swap1(frame, dispatch);

    // Stack: [10, 20, 20, 30]
    try testing.expectEqual(@as(u256, 30), try frame.stack.peek());

    // POP
    dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.pop(frame, dispatch);

    // Stack: [10, 20, 20]
    try testing.expectEqual(@as(usize, 3), frame.stack.len());

    // PUSH0
    dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.push0(frame, dispatch);

    // Stack: [10, 20, 20, 0]
    try testing.expectEqual(@as(u256, 0), try frame.stack.peek());
}

test "PUSH handlers - all sizes inline" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test PUSH1 through PUSH8 (inline values)
    inline for (1..9) |push_n| {
        const PushHandler = TestFrame.StackHandlers.generatePushHandler(push_n);

        const value = @as(u256, (1 << (push_n * 8)) - 1); // Max value for n bytes

        var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
        const mock_handler = struct {
            fn handler(f: TestFrame, d: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
                _ = f;
                _ = d;
                return TestFrame.Success.stop;
            }
        }.handler;

        cursor[0] = .{ .opcode_handler = &mock_handler };
        cursor[1] = .{ .opcode_handler = &mock_handler };

        const dispatch = TestFrame.Dispatch{
            .cursor = &cursor,
            .bytecode_length = 0,
        };

        dispatch.*.cursor[0].metadata = .{ .inline_value = value };

        _ = try PushHandler(frame, dispatch);

        try testing.expectEqual(value, try frame.stack.pop());
    }
}

test "PUSH handlers - all sizes pointer" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test PUSH9 through PUSH32 (pointer values)
    inline for (9..33) |push_n| {
        const PushHandler = TestFrame.StackHandlers.generatePushHandler(push_n);

        const value = @as(u256, push_n * 0x0102030405060708090A0B0C0D0E0F10);

        var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
        const mock_handler = struct {
            fn handler(f: TestFrame, d: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
                _ = f;
                _ = d;
                return TestFrame.Success.stop;
            }
        }.handler;

        cursor[0] = .{ .opcode_handler = &mock_handler };
        cursor[1] = .{ .opcode_handler = &mock_handler };

        const dispatch = TestFrame.Dispatch{
            .cursor = &cursor,
            .bytecode_length = 0,
        };

        dispatch.*.cursor[0].metadata = .{ .pointer_value = &value };

        _ = try PushHandler(frame, dispatch);

        try testing.expectEqual(value, try frame.stack.pop());
    }
}

test "Stack operations - maximum depth" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Fill stack to maximum (1024)
    const max_stack = 1024;
    for (0..max_stack) |i| {
        try frame.stack.push(@as(u256, i));
    }

    // Stack should be full
    try testing.expectEqual(@as(usize, max_stack), frame.stack.len());

    // Pop one to make room
    const dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.pop(frame, dispatch);

    // Now push should succeed
    _ = try TestFrame.StackHandlers.push0(frame, dispatch);
    try testing.expectEqual(@as(usize, max_stack), frame.stack.len());
}

test "DUP and SWAP - pattern verification" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Create a recognizable pattern
    for (1..9) |i| {
        try frame.stack.push(@as(u256, i * 11)); // 11, 22, 33, 44, 55, 66, 77, 88
    }

    // DUP4 - should duplicate 55
    const Dup4 = TestFrame.StackHandlers.generateDupHandler(4);
    var dispatch = createMockDispatch();
    _ = try Dup4(frame, dispatch);

    try testing.expectEqual(@as(u256, 55), try frame.stack.peek());

    // SWAP3 - swap top (55) with 4th item (66)
    const Swap3 = TestFrame.StackHandlers.generateSwapHandler(3);
    dispatch = createMockDispatch();
    _ = try Swap3(frame, dispatch);

    // Now top is 66, and 4th position is 55
    try testing.expectEqual(@as(u256, 66), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 77), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 66), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 55), try frame.stack.pop());
}

test "Stack operations - preservation test" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push unique values
    const test_values = [_]u256{
        0xDEADBEEF,
        0xCAFEBABE,
        0x12345678,
        0x9ABCDEF0,
        0xFEEDFACE,
    };

    for (test_values) |val| {
        try frame.stack.push(val);
    }

    // DUP5 - duplicate bottom value
    const Dup5 = TestFrame.StackHandlers.generateDupHandler(5);
    const dispatch = createMockDispatch();
    _ = try Dup5(frame, dispatch);

    try testing.expectEqual(test_values[0], try frame.stack.peek());

    // Verify all values are still there in correct order
    try testing.expectEqual(test_values[0], try frame.stack.pop()); // Duplicated
    try testing.expectEqual(test_values[4], try frame.stack.pop());
    try testing.expectEqual(test_values[3], try frame.stack.pop());
    try testing.expectEqual(test_values[2], try frame.stack.pop());
    try testing.expectEqual(test_values[1], try frame.stack.pop());
    try testing.expectEqual(test_values[0], try frame.stack.pop()); // Original
}

test "SWAP operations - circular swaps" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push 4 distinct values
    try frame.stack.push(100);
    try frame.stack.push(200);
    try frame.stack.push(300);
    try frame.stack.push(400);

    // SWAP3 twice should restore original order
    const Swap3 = TestFrame.StackHandlers.generateSwapHandler(3);
    var dispatch = createMockDispatch();
    _ = try Swap3(frame, dispatch);

    dispatch = createMockDispatch();
    _ = try Swap3(frame, dispatch);

    // Should be back to original order
    try testing.expectEqual(@as(u256, 400), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 300), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 200), try frame.stack.pop());
    try testing.expectEqual(@as(u256, 100), try frame.stack.pop());
}

test "PUSH0 opcode - edge case" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Fill stack almost to maximum
    for (0..1023) |i| {
        try frame.stack.push(@as(u256, i + 1));
    }

    // PUSH0 should succeed
    const dispatch = createMockDispatch();
    _ = try TestFrame.StackHandlers.push0(frame, dispatch);

    try testing.expectEqual(@as(usize, 1024), frame.stack.len());
    try testing.expectEqual(@as(u256, 0), try frame.stack.peek());
}

test "DUP operations - boundary conditions" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test DUP with exactly required elements
    for (1..17) |i| {
        try frame.stack.push(@as(u256, i * 100));
    }

    // DUP16 with exactly 16 elements
    const Dup16 = TestFrame.StackHandlers.generateDupHandler(16);
    const dispatch = createMockDispatch();
    _ = try Dup16(frame, dispatch);

    // Should have duplicated the bottom element
    try testing.expectEqual(@as(u256, 100), try frame.stack.peek());
    try testing.expectEqual(@as(usize, 17), frame.stack.len());
}

test "SWAP operations - identity swaps" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Push values
    const values = [_]u256{ 10, 20, 30, 40, 50 };
    for (values) |val| {
        try frame.stack.push(val);
    }

    // SWAP1 twice should restore original
    const Swap1 = TestFrame.StackHandlers.generateSwapHandler(1);
    const dispatch = createMockDispatch();
    _ = try Swap1(frame, dispatch);
    _ = try Swap1(frame, dispatch);

    // Verify original order
    var i: usize = values.len;
    while (i > 0) : (i -= 1) {
        try testing.expectEqual(values[i - 1], try frame.stack.pop());
    }
}

test "PUSH handlers - edge values" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test PUSH with various edge values
    const test_cases = [_]struct { push_n: u8, value: u256 }{
        .{ .push_n = 1, .value = 0 },
        .{ .push_n = 1, .value = 0xFF },
        .{ .push_n = 2, .value = 0xFFFF },
        .{ .push_n = 4, .value = 0xFFFFFFFF },
        .{ .push_n = 8, .value = 0xFFFFFFFFFFFFFFFF },
        .{ .push_n = 16, .value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF },
        .{ .push_n = 32, .value = std.math.maxInt(u256) },
    };

    inline for (test_cases) |tc| {
        const PushHandler = TestFrame.StackHandlers.generatePushHandler(tc.push_n);

        var cursor: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
        const mock_handler = struct {
            fn handler(f: TestFrame, d: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
                _ = f;
                _ = d;
                return TestFrame.Success.stop;
            }
        }.handler;

        cursor[0] = .{ .opcode_handler = &mock_handler };
        cursor[1] = .{ .opcode_handler = &mock_handler };

        const dispatch = TestFrame.Dispatch{
            .cursor = &cursor,
            .bytecode_length = 0,
        };

        if (tc.push_n <= 8) {
            dispatch.*.cursor[0].metadata = .{ .inline_value = tc.value };
        } else {
            dispatch.*.cursor[0].metadata = .{ .pointer_value = &tc.value };
        }

        _ = try PushHandler(frame, dispatch);

        try testing.expectEqual(tc.value, try frame.stack.pop());
    }
}

test "Stack operations - stress test with alternating operations" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Stress test: alternating PUSH0, DUP1, SWAP1, POP operations
    const operations = 100;

    for (0..operations) |i| {
        const dispatch = createMockDispatch();
        switch (i % 4) {
            0 => {
                // PUSH0
                _ = try TestFrame.StackHandlers.push0(frame, dispatch);
            },
            1 => {
                // DUP1 (if stack has items)
                if (frame.stack.len() > 0) {
                    const Dup1 = TestFrame.StackHandlers.generateDupHandler(1);
                    _ = try Dup1(frame, dispatch);
                }
            },
            2 => {
                // SWAP1 (if stack has at least 2 items)
                if (frame.stack.len() >= 2) {
                    const Swap1 = TestFrame.StackHandlers.generateSwapHandler(1);
                    _ = try Swap1(frame, dispatch);
                }
            },
            3 => {
                // POP (if stack has items)
                if (frame.stack.len() > 0) {
                    _ = try TestFrame.StackHandlers.pop(frame, dispatch);
                }
            },
            else => unreachable,
        }
    }

    // Stack should have some items (not empty, not overflow)
    try testing.expect(frame.stack.len() > 0);
    try testing.expect(frame.stack.len() <= 1024);
}

test "DUP operations - maximum stack utilization" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Fill stack to 1023 (leave room for 1 more)
    for (0..1023) |i| {
        try frame.stack.push(@as(u256, i));
    }

    // DUP1 should succeed (bringing stack to maximum of 1024)
    const Dup1 = TestFrame.StackHandlers.generateDupHandler(1);
    const dispatch = createMockDispatch();
    _ = try Dup1(frame, dispatch);

    try testing.expectEqual(@as(usize, 1024), frame.stack.len());
    try testing.expectEqual(@as(u256, 1022), try frame.stack.peek()); // Duplicated top value
}

test "SWAP operations - adjacent element preservation" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Create a distinctive pattern to verify adjacent elements aren't corrupted
    const pattern = [_]u256{ 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 };

    for (pattern) |val| {
        try frame.stack.push(val);
    }

    // SWAP4 - swap positions 0 and 4
    const Swap4 = TestFrame.StackHandlers.generateSwapHandler(4);
    const dispatch = createMockDispatch();
    _ = try Swap4(frame, dispatch);

    // Verify the swap happened correctly and adjacent elements preserved
    try testing.expectEqual(@as(u256, 0x4444), try frame.stack.pop()); // Was at position 4
    try testing.expectEqual(@as(u256, 0x7777), try frame.stack.pop()); // Position 1 unchanged
    try testing.expectEqual(@as(u256, 0x6666), try frame.stack.pop()); // Position 2 unchanged
    try testing.expectEqual(@as(u256, 0x5555), try frame.stack.pop()); // Position 3 unchanged
    try testing.expectEqual(@as(u256, 0x8888), try frame.stack.pop()); // Was at position 0
    try testing.expectEqual(@as(u256, 0x3333), try frame.stack.pop()); // Position 5 unchanged
    try testing.expectEqual(@as(u256, 0x2222), try frame.stack.pop()); // Position 6 unchanged
    try testing.expectEqual(@as(u256, 0x1111), try frame.stack.pop()); // Position 7 unchanged
}

test "PUSH handlers - inline vs pointer threshold" {
    var frame = try createTestFrame(testing.allocator);
    defer frame.deinit(testing.allocator);

    // Test the exact threshold where inline becomes pointer (PUSH8 vs PUSH9)

    // PUSH8 should use inline
    const Push8 = TestFrame.StackHandlers.generatePushHandler(8);
    const value8: u256 = 0xFFFFFFFFFFFFFFFF;

    var cursor8: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    const mock_handler8 = struct {
        fn handler(f: TestFrame, d: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = f;
            _ = d;
            return TestFrame.Success.stop;
        }
    }.handler;
    cursor8[0] = .{ .opcode_handler = &mock_handler8 };
    cursor8[1] = .{ .opcode_handler = &mock_handler8 };

    const dispatch8 = TestFrame.Dispatch{ .cursor = &cursor8, .bytecode_length = 0 };
    dispatch8.*.cursor[0].metadata = .{ .inline_value = value8 };
    _ = try Push8(frame, dispatch8);
    try testing.expectEqual(value8, try frame.stack.pop());

    // PUSH9 should use pointer
    const Push9 = TestFrame.StackHandlers.generatePushHandler(9);
    const value9: u256 = 0xFFFFFFFFFFFFFFFFFF;

    var cursor9: [2]dispatch_mod.ScheduleElement(TestFrame) = undefined;
    const mock_handler9 = struct {
        fn handler(f: TestFrame, d: TestFrame.Dispatch) TestFrame.Error!TestFrame.Success {
            _ = f;
            _ = d;
            return TestFrame.Success.stop;
        }
    }.handler;
    cursor9[0] = .{ .opcode_handler = &mock_handler9 };
    cursor9[1] = .{ .opcode_handler = &mock_handler9 };

    const dispatch9 = TestFrame.Dispatch{ .cursor = &cursor9, .bytecode_length = 0 };
    dispatch9.*.cursor[0].metadata = .{ .pointer_value = &value9 };
    _ = try Push9(frame, dispatch9);
    try testing.expectEqual(value9, try frame.stack.pop());
}
