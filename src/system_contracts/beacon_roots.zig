const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;

pub const BEACON_ROOTS_ADDRESS: Address = .{
    .bytes = [_]u8{
        0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
        0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
        0xd0, 0xBe, 0xac, 0x02,
    },
};

pub const SYSTEM_ADDRESS: Address = .{
    .bytes = [_]u8{0xff} ** 18 ++ [_]u8{ 0xff, 0xfe },
};

pub const HISTORY_BUFFER_LENGTH: u64 = 8191;
pub const BEACON_ROOT_READ_GAS: u64 = 4200;
pub const BEACON_ROOT_WRITE_GAS: u64 = 20000;

pub const BeaconRootsContract = struct {
    database: *anyopaque, // Generic database pointer
    allocator: Allocator,

    const Self = @This();

    pub const Error = error{
        OutOfGas,
        InvalidInput,
    } || Allocator.Error;

    /// Execute beacon roots contract call
    pub fn execute(
        self: *Self,
        caller: Address,
        input: []const u8,
        gas_limit: u64,
    ) Error!struct { output: []const u8, gas_used: u64 } {
        _ = self;
        _ = caller;
        _ = input;
        _ = gas_limit;
        @panic("TODO: implement execute");
    }

    /// Process beacon root update at block start
    pub fn processBeaconRootUpdate(
        database: *anyopaque,
        block_info: anytype,
    ) Error!void {
        _ = database;
        _ = block_info;
        @panic("TODO: implement processBeaconRootUpdate");
    }
};

/// Compute ring buffer slots for timestamp
pub fn computeSlots(timestamp: u64) struct {
    timestamp_slot: u64,
    root_slot: u64,
} {
    _ = timestamp;
    @panic("TODO: implement computeSlots");
}
