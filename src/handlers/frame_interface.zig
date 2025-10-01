const std = @import("std");

/// Generic handler pattern documentation
///
/// EVM opcode handlers operate on any Frame type meeting these requirements:
///
/// Required types:
/// - Error: error set for frame operations
/// - WordType: stack word type (typically u256)
/// - UintN: arbitrary precision type
/// - Dispatch: dispatch table type with Item and UnifiedOpcode
///
/// Required fields:
/// - stack: Stack implementation
/// - gas_remaining: i64
/// - code: []const u8
///
/// Required methods:
/// - beforeInstruction(opcode, cursor)
/// - afterInstruction(opcode, next_handler, next_cursor)
/// - afterComplete(opcode)
///
/// Example:
/// ```zig
/// const MyFrame = struct {
///     pub const Error = error { OutOfGas, StackUnderflow };
///     pub const WordType = u256;
///     // ... implement required interface
/// };
///
/// const MyHandlers = Handlers(MyFrame);
/// ```

pub const FrameConfig = struct {
    stack_size: usize = 1024,
    WordType: type = u256,
    max_bytecode_size: usize = 24576,
    block_gas_limit: u64 = 30_000_000,
    DatabaseType: type,
    memory_initial_capacity: usize = 4096,
    memory_limit: usize = 0xFFFFFF,
};

/// Generic handler generator
pub fn Handlers(comptime FrameType: type) type {
    return struct {
        pub const Error = FrameType.Error;
        pub const WordType = FrameType.WordType;

        // Arithmetic handlers
        pub fn add(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement add handler");
        }

        pub fn mul(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement mul handler");
        }

        pub fn sub(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement sub handler");
        }

        pub fn div(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement div handler");
        }

        pub fn sdiv(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement sdiv handler");
        }

        pub fn mod(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement mod handler");
        }

        pub fn smod(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement smod handler");
        }

        pub fn addmod(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement addmod handler");
        }

        pub fn mulmod(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement mulmod handler");
        }

        pub fn exp(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement exp handler");
        }

        pub fn signextend(frame: *FrameType, cursor: anytype) Error!noreturn {
            _ = frame;
            _ = cursor;
            @panic("TODO: implement signextend handler");
        }

        // TODO: Add remaining handlers for all opcodes
    };
}
