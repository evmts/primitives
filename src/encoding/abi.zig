const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;

pub const ABI = @This();

// Error types
pub const Error = error{
    InvalidSelector,
    InvalidType,
    InvalidData,
    DataTooSmall,
    OutOfBounds,
    InvalidAddress,
} || Allocator.Error;

pub const Type = enum {
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
    uint256,
    int8,
    int16,
    int32,
    int64,
    int128,
    int256,
    address,
    bool,
    bytes1,
    bytes2,
    bytes3,
    bytes4,
    bytes8,
    bytes16,
    bytes32,
    bytes,
    string,
    uint256_array,
    bytes32_array,
    address_array,
    string_array,

    /// Check if type is dynamic
    pub fn isDynamic(self: Type) bool {
        _ = self;
        @panic("TODO: implement isDynamic");
    }

    /// Get fixed size of type (null if dynamic)
    pub fn size(self: Type) ?usize {
        _ = self;
        @panic("TODO: implement size");
    }

    /// Get type string representation
    pub fn getType(self: Type) []const u8 {
        _ = self;
        @panic("TODO: implement getType");
    }
};

pub const Value = union(Type) {
    uint8: u8,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    uint128: u128,
    uint256: u256,
    int8: i8,
    int16: i16,
    int32: i32,
    int64: i64,
    int128: i128,
    int256: i256,
    address: Address,
    bool: bool,
    bytes1: [1]u8,
    bytes2: [2]u8,
    bytes3: [3]u8,
    bytes4: [4]u8,
    bytes8: [8]u8,
    bytes16: [16]u8,
    bytes32: [32]u8,
    bytes: []const u8,
    string: []const u8,
    uint256_array: []const u256,
    bytes32_array: []const [32]u8,
    address_array: []const Address,
    string_array: []const []const u8,

    /// Get type of value
    pub fn getType(self: Value) Type {
        _ = self;
        @panic("TODO: implement getType");
    }
};

pub const Selector = [4]u8;

/// Compute function selector from signature
pub fn computeSelector(signature: []const u8) Selector {
    _ = signature;
    @panic("TODO: implement computeSelector");
}

/// Create function signature from name and types
pub fn createSignature(allocator: Allocator, name: []const u8, types: []const Type) Error![]u8 {
    _ = allocator;
    _ = name;
    _ = types;
    @panic("TODO: implement createSignature");
}

/// Encode parameters to ABI format
pub fn encodeParameters(allocator: Allocator, values: []const Value) Error![]u8 {
    _ = allocator;
    _ = values;
    @panic("TODO: implement encodeParameters");
}

/// Decode parameters from ABI format
pub fn decodeParameters(allocator: Allocator, data: []const u8, types: []const Type) Error![]Value {
    _ = allocator;
    _ = data;
    _ = types;
    @panic("TODO: implement decodeParameters");
}

/// Encode function call with selector and parameters
pub fn encodeFunctionCall(allocator: Allocator, signature: []const u8, values: []const Value) Error![]u8 {
    _ = allocator;
    _ = signature;
    _ = values;
    @panic("TODO: implement encodeFunctionCall");
}

/// Encode event topic from signature
pub fn encodeEventTopic(signature: []const u8) Hash {
    _ = signature;
    @panic("TODO: implement encodeEventTopic");
}
