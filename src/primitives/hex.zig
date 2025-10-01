const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Hex = @This();

// Error types
pub const Error = error{
    InvalidFormat,
    InvalidLength,
    InvalidCharacter,
    OddLength,
    ValueTooLarge,
} || Allocator.Error;

/// Encode bytes to lowercase hex string with 0x prefix (allocates)
pub fn encode(allocator: Allocator, bytes: []const u8) Error![]u8 {
    _ = allocator;
    _ = bytes;
    @panic("TODO: implement encode");
}

/// Encode bytes to uppercase hex string with 0x prefix (allocates)
pub fn encodeUpper(allocator: Allocator, bytes: []const u8) Error![]u8 {
    _ = allocator;
    _ = bytes;
    @panic("TODO: implement encodeUpper");
}

/// Encode fixed-size bytes to hex string (no allocation)
pub fn encodeFixed(comptime N: usize, bytes: [N]u8) [2 + N * 2]u8 {
    _ = bytes;
    @panic("TODO: implement encodeFixed");
}

/// Decode hex string to bytes (allocates)
pub fn decode(allocator: Allocator, hex: []const u8) Error![]u8 {
    _ = allocator;
    _ = hex;
    @panic("TODO: implement decode");
}

/// Decode hex string to fixed-size bytes (no allocation)
pub fn decodeFixed(comptime N: usize, hex: []const u8) Error![N]u8 {
    _ = hex;
    @panic("TODO: implement decodeFixed");
}

/// Parse hex string to u256
pub fn toU256(hex: []const u8) Error!u256 {
    _ = hex;
    @panic("TODO: implement toU256");
}

/// Parse hex string to u64
pub fn toU64(hex: []const u8) Error!u64 {
    _ = hex;
    @panic("TODO: implement toU64");
}

/// Convert u256 to hex string (allocates)
pub fn fromU256(allocator: Allocator, value: u256) Error![]u8 {
    _ = allocator;
    _ = value;
    @panic("TODO: implement fromU256");
}

/// Convert u64 to hex string (allocates)
pub fn fromU64(allocator: Allocator, value: u64) Error![]u8 {
    _ = allocator;
    _ = value;
    @panic("TODO: implement fromU64");
}

/// Validate hex string format
pub fn isValid(str: []const u8) bool {
    _ = str;
    @panic("TODO: implement isValid");
}

/// Get byte length of hex string
pub fn byteLength(hex: []const u8) usize {
    _ = hex;
    @panic("TODO: implement byteLength");
}

/// Pad bytes to the left with zeros
pub fn padLeft(allocator: Allocator, bytes: []const u8, target_length: usize) Error![]u8 {
    _ = allocator;
    _ = bytes;
    _ = target_length;
    @panic("TODO: implement padLeft");
}

/// Pad bytes to the right with zeros
pub fn padRight(allocator: Allocator, bytes: []const u8, target_length: usize) Error![]u8 {
    _ = allocator;
    _ = bytes;
    _ = target_length;
    @panic("TODO: implement padRight");
}

/// Trim leading zero bytes
pub fn trimLeft(bytes: []const u8) []const u8 {
    _ = bytes;
    @panic("TODO: implement trimLeft");
}

/// Trim trailing zero bytes
pub fn trimRight(bytes: []const u8) []const u8 {
    _ = bytes;
    @panic("TODO: implement trimRight");
}

/// Concatenate multiple byte arrays
pub fn concat(allocator: Allocator, arrays: []const []const u8) Error![]u8 {
    _ = allocator;
    _ = arrays;
    @panic("TODO: implement concat");
}

/// Slice bytes from start to end
pub fn slice(bytes: []const u8, start: usize, end: usize) []const u8 {
    _ = bytes;
    _ = start;
    _ = end;
    @panic("TODO: implement slice");
}
