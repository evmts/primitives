const std = @import("std");
const Address = @import("../primitives/address.zig").Address;

pub const StorageKey = struct {
    address: Address,
    slot: u256,

    /// Hash function for use in hash maps
    pub fn hash(self: StorageKey, hasher: anytype) void {
        _ = self;
        _ = hasher;
        @panic("TODO: implement hash");
    }

    /// Equality check
    pub fn eql(a: StorageKey, b: StorageKey) bool {
        _ = a;
        _ = b;
        @panic("TODO: implement eql");
    }
};
