const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RLP = @This();

// Error types
pub const Error = error{
    InputTooShort,
    InputTooLong,
    InvalidLength,
    NonCanonical,
    InvalidRemainder,
    LeadingZeros,
} || Allocator.Error;

pub const Data = union(enum) {
    String: []const u8,
    List: []Data,

    /// Free allocated memory
    pub fn deinit(self: Data, allocator: Allocator) void {
        _ = self;
        _ = allocator;
        @panic("TODO: implement deinit");
    }
};

pub const Decoded = struct {
    data: Data,
    remainder: []const u8,
};

/// Encode any value to RLP
pub fn encode(allocator: Allocator, input: anytype) Error![]u8 {
    _ = allocator;
    _ = input;
    @panic("TODO: implement encode");
}

/// Encode bytes to RLP
pub fn encodeBytes(allocator: Allocator, bytes: []const u8) Error![]u8 {
    _ = allocator;
    _ = bytes;
    @panic("TODO: implement encodeBytes");
}

/// Encode list of byte arrays to RLP
pub fn encodeList(allocator: Allocator, items: []const []const u8) Error![]u8 {
    _ = allocator;
    _ = items;
    @panic("TODO: implement encodeList");
}

/// Decode RLP data
pub fn decode(allocator: Allocator, input: []const u8, stream: bool) Error!Decoded {
    _ = allocator;
    _ = input;
    _ = stream;
    @panic("TODO: implement decode");
}

/// Get encoded length without encoding
pub fn encodedLength(input: anytype) usize {
    _ = input;
    @panic("TODO: implement encodedLength");
}

/// Check if data represents a list
pub fn isList(data: []const u8) bool {
    _ = data;
    @panic("TODO: implement isList");
}
