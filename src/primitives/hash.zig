const std = @import("std");

pub const Hash = @This();

bytes: [32]u8,

pub const ZERO: Hash = .{ .bytes = [_]u8{0} ** 32 };

pub const EMPTY_CODE_HASH: Hash = .{ .bytes = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
} };

pub const EMPTY_TRIE_ROOT: Hash = .{ .bytes = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
} };

// Error types
pub const Error = error{
    InvalidFormat,
    InvalidLength,
};

/// Construct a Hash from a hex string (with or without 0x prefix)
pub fn fromHex(hex: []const u8) Error!Hash {
    _ = hex;
    @panic("TODO: implement fromHex");
}

/// Construct a Hash from raw bytes
pub fn fromBytes(bytes: []const u8) Error!Hash {
    _ = bytes;
    @panic("TODO: implement fromBytes");
}

/// Compute Keccak256 hash of data
pub fn keccak256(data: []const u8) Hash {
    _ = data;
    @panic("TODO: implement keccak256");
}

/// Convert hash to hex string (with 0x prefix)
pub fn toHex(self: Hash) [66]u8 {
    _ = self;
    @panic("TODO: implement toHex");
}

/// Convert hash to u256
pub fn toU256(self: Hash) u256 {
    _ = self;
    @panic("TODO: implement toU256");
}

/// Check if two hashes are equal
pub fn eql(self: Hash, other: Hash) bool {
    _ = self;
    _ = other;
    @panic("TODO: implement eql");
}

/// Format hash for std.fmt output
pub fn format(
    self: Hash,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = fmt;
    _ = options;
    _ = writer;
    @panic("TODO: implement format");
}
