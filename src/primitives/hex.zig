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
    const result = try allocator.alloc(u8, 2 + bytes.len * 2);
    result[0] = '0';
    result[1] = 'x';

    const lowercase = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        result[2 + i * 2] = lowercase[b >> 4];
        result[2 + i * 2 + 1] = lowercase[b & 0x0F];
    }

    return result;
}

/// Encode bytes to uppercase hex string with 0x prefix (allocates)
pub fn encodeUpper(allocator: Allocator, bytes: []const u8) Error![]u8 {
    const result = try allocator.alloc(u8, 2 + bytes.len * 2);
    result[0] = '0';
    result[1] = 'x';

    const uppercase = "0123456789ABCDEF";
    for (bytes, 0..) |b, i| {
        result[2 + i * 2] = uppercase[b >> 4];
        result[2 + i * 2 + 1] = uppercase[b & 0x0F];
    }

    return result;
}

/// Encode fixed-size bytes to hex string (no allocation)
pub fn encodeFixed(comptime N: usize, bytes: [N]u8) [2 + N * 2]u8 {
    var result: [2 + N * 2]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex = std.fmt.bytesToHex(&bytes, .lower);
    @memcpy(result[2..], &hex);
    return result;
}

/// Decode hex string to bytes (allocates)
pub fn decode(allocator: Allocator, hex: []const u8) Error![]u8 {
    const hex_str = stripPrefix(hex);

    // Validate format
    if (hex_str.len % 2 != 0) return error.OddLength;
    if (!isValid(hex)) return error.InvalidFormat;

    const result = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(result);

    _ = std.fmt.hexToBytes(result, hex_str) catch return error.InvalidCharacter;
    return result;
}

/// Decode hex string to fixed-size bytes (no allocation)
pub fn decodeFixed(comptime N: usize, hex: []const u8) Error![N]u8 {
    const hex_str = stripPrefix(hex);

    // Validate length
    if (hex_str.len != N * 2) return error.InvalidLength;
    if (!isValid(hex)) return error.InvalidFormat;

    var result: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex_str) catch return error.InvalidCharacter;
    return result;
}

/// Parse hex string to u256
pub fn toU256(hex: []const u8) Error!u256 {
    const hex_str = stripPrefix(hex);

    // u256 can have max 64 hex characters (32 bytes)
    if (hex_str.len > 64) return error.ValueTooLarge;
    if (!isValid(hex)) return error.InvalidFormat;

    var result: u256 = 0;
    for (hex_str) |c| {
        const nibble = try hexCharToNibble(c);
        result = (result << 4) | nibble;
    }
    return result;
}

/// Parse hex string to u64
pub fn toU64(hex: []const u8) Error!u64 {
    const hex_str = stripPrefix(hex);

    // u64 can have max 16 hex characters (8 bytes)
    if (hex_str.len > 16) return error.ValueTooLarge;
    if (!isValid(hex)) return error.InvalidFormat;

    var result: u64 = 0;
    for (hex_str) |c| {
        const nibble = try hexCharToNibble(c);
        result = (result << 4) | nibble;
    }
    return result;
}

/// Convert u256 to hex string (allocates)
pub fn fromU256(allocator: Allocator, value: u256) Error![]u8 {
    // Convert to bytes (big-endian)
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);

    // Find first non-zero byte to avoid leading zeros
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) : (start += 1) {}

    // If all zeros, return "0x0"
    if (start == bytes.len) {
        const result = try allocator.alloc(u8, 3);
        @memcpy(result, "0x0");
        return result;
    }

    return encode(allocator, bytes[start..]);
}

/// Convert u64 to hex string (allocates)
pub fn fromU64(allocator: Allocator, value: u64) Error![]u8 {
    // Convert to bytes (big-endian)
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);

    // Find first non-zero byte to avoid leading zeros
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) : (start += 1) {}

    // If all zeros, return "0x0"
    if (start == bytes.len) {
        const result = try allocator.alloc(u8, 3);
        @memcpy(result, "0x0");
        return result;
    }

    return encode(allocator, bytes[start..]);
}

/// Validate hex string format
pub fn isValid(str: []const u8) bool {
    if (str.len < 2) return false;
    if (!std.mem.startsWith(u8, str, "0x")) return false;

    const hex_str = str[2..];
    if (hex_str.len == 0) return false;

    for (hex_str) |c| {
        if (!std.ascii.isHex(c)) return false;
    }

    return true;
}

/// Get byte length of hex string
pub fn byteLength(hex: []const u8) usize {
    const hex_str = stripPrefix(hex);
    return (hex_str.len + 1) / 2; // Round up for odd lengths
}

/// Pad bytes to the left with zeros
pub fn padLeft(allocator: Allocator, bytes: []const u8, target_length: usize) Error![]u8 {
    if (bytes.len >= target_length) {
        // Already at or exceeds target length, return copy
        const result = try allocator.alloc(u8, bytes.len);
        @memcpy(result, bytes);
        return result;
    }

    const result = try allocator.alloc(u8, target_length);
    const padding = target_length - bytes.len;

    // Fill with zeros
    @memset(result[0..padding], 0);
    // Copy original bytes
    @memcpy(result[padding..], bytes);

    return result;
}

/// Pad bytes to the right with zeros
pub fn padRight(allocator: Allocator, bytes: []const u8, target_length: usize) Error![]u8 {
    if (bytes.len >= target_length) {
        // Already at or exceeds target length, return copy
        const result = try allocator.alloc(u8, bytes.len);
        @memcpy(result, bytes);
        return result;
    }

    const result = try allocator.alloc(u8, target_length);

    // Copy original bytes
    @memcpy(result[0..bytes.len], bytes);
    // Fill rest with zeros
    @memset(result[bytes.len..], 0);

    return result;
}

/// Trim leading zero bytes
pub fn trimLeft(bytes: []const u8) []const u8 {
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) : (start += 1) {}

    // If all zeros, return single zero byte
    if (start == bytes.len) {
        return bytes[bytes.len - 1 ..];
    }

    return bytes[start..];
}

/// Trim trailing zero bytes
pub fn trimRight(bytes: []const u8) []const u8 {
    var end: usize = bytes.len;
    while (end > 0 and bytes[end - 1] == 0) : (end -= 1) {}

    // If all zeros, return single zero byte
    if (end == 0) {
        return bytes[0..1];
    }

    return bytes[0..end];
}

/// Concatenate multiple byte arrays
pub fn concat(allocator: Allocator, arrays: []const []const u8) Error![]u8 {
    // Calculate total length
    var total_len: usize = 0;
    for (arrays) |arr| {
        total_len += arr.len;
    }

    const result = try allocator.alloc(u8, total_len);

    // Copy all arrays
    var offset: usize = 0;
    for (arrays) |arr| {
        @memcpy(result[offset .. offset + arr.len], arr);
        offset += arr.len;
    }

    return result;
}

/// Slice bytes from start to end
pub fn slice(bytes: []const u8, start: usize, end: usize) []const u8 {
    const safe_start = @min(start, bytes.len);
    const safe_end = @min(end, bytes.len);

    if (safe_start >= safe_end) {
        return bytes[0..0]; // Empty slice
    }

    return bytes[safe_start..safe_end];
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Strip "0x" or "0X" prefix if present
fn stripPrefix(hex: []const u8) []const u8 {
    if (hex.len >= 2 and hex[0] == '0' and (hex[1] == 'x' or hex[1] == 'X')) {
        return hex[2..];
    }
    return hex;
}

/// Convert hex character to nibble (0-15)
fn hexCharToNibble(c: u8) Error!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidCharacter,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "Hex: encode - basic" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const hex = try encode(allocator, &bytes);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x1234abcd", hex);
}

test "Hex: encodeUpper - basic" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const hex = try encodeUpper(allocator, &bytes);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x1234ABCD", hex);
}

test "Hex: encodeFixed - basic" {
    const bytes = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const hex = encodeFixed(4, bytes);

    try std.testing.expectEqualStrings("0x1234abcd", &hex);
}

test "Hex: decode - basic" {
    const allocator = std.testing.allocator;

    const bytes = try decode(allocator, "0x1234abcd");
    defer allocator.free(bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0xab, 0xcd }, bytes);
}

test "Hex: decode - uppercase" {
    const allocator = std.testing.allocator;

    const bytes = try decode(allocator, "0x1234ABCD");
    defer allocator.free(bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0xab, 0xcd }, bytes);
}

test "Hex: decode - odd length error" {
    const allocator = std.testing.allocator;

    const result = decode(allocator, "0x123");
    try std.testing.expectError(error.OddLength, result);
}

test "Hex: decodeFixed - basic" {
    const bytes = try decodeFixed(4, "0x1234abcd");

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0xab, 0xcd }, &bytes);
}

test "Hex: decodeFixed - length mismatch" {
    const result = decodeFixed(4, "0x1234ab");
    try std.testing.expectError(error.InvalidLength, result);
}

test "Hex: toU256 - basic" {
    const value = try toU256("0x1234");
    try std.testing.expectEqual(@as(u256, 0x1234), value);
}

test "Hex: toU256 - large value" {
    const value = try toU256("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    try std.testing.expectEqual(@as(u256, std.math.maxInt(u256)), value);
}

test "Hex: toU64 - basic" {
    const value = try toU64("0x1234");
    try std.testing.expectEqual(@as(u64, 0x1234), value);
}

test "Hex: toU64 - max value" {
    const value = try toU64("0xffffffffffffffff");
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), value);
}

test "Hex: toU64 - too large" {
    const result = toU64("0x1ffffffffffffffff");
    try std.testing.expectError(error.ValueTooLarge, result);
}

test "Hex: fromU256 - basic" {
    const allocator = std.testing.allocator;

    const hex = try fromU256(allocator, 0x1234);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x1234", hex);
}

test "Hex: fromU256 - zero" {
    const allocator = std.testing.allocator;

    const hex = try fromU256(allocator, 0);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x0", hex);
}

test "Hex: fromU64 - basic" {
    const allocator = std.testing.allocator;

    const hex = try fromU64(allocator, 0x1234);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x1234", hex);
}

test "Hex: fromU64 - zero" {
    const allocator = std.testing.allocator;

    const hex = try fromU64(allocator, 0);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("0x0", hex);
}

test "Hex: isValid - valid strings" {
    try std.testing.expect(isValid("0x1234"));
    try std.testing.expect(isValid("0xabcd"));
    try std.testing.expect(isValid("0xABCD"));
    try std.testing.expect(isValid("0x0"));
}

test "Hex: isValid - invalid strings" {
    try std.testing.expect(!isValid("1234"));
    try std.testing.expect(!isValid("0x"));
    try std.testing.expect(!isValid("0xzzzz"));
    try std.testing.expect(!isValid(""));
}

test "Hex: byteLength - basic" {
    try std.testing.expectEqual(@as(usize, 2), byteLength("0x1234"));
    try std.testing.expectEqual(@as(usize, 4), byteLength("0x12345678"));
    try std.testing.expectEqual(@as(usize, 1), byteLength("0x12"));
}

test "Hex: byteLength - odd length" {
    try std.testing.expectEqual(@as(usize, 2), byteLength("0x123"));
}

test "Hex: padLeft - basic" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0x12, 0x34 };
    const padded = try padLeft(allocator, &bytes, 4);
    defer allocator.free(padded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x12, 0x34 }, padded);
}

test "Hex: padLeft - no padding needed" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0x12, 0x34 };
    const padded = try padLeft(allocator, &bytes, 2);
    defer allocator.free(padded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34 }, padded);
}

test "Hex: padRight - basic" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0x12, 0x34 };
    const padded = try padRight(allocator, &bytes, 4);
    defer allocator.free(padded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x00, 0x00 }, padded);
}

test "Hex: trimLeft - basic" {
    const bytes = [_]u8{ 0x00, 0x00, 0x12, 0x34 };
    const trimmed = trimLeft(&bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34 }, trimmed);
}

test "Hex: trimLeft - all zeros" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00 };
    const trimmed = trimLeft(&bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, trimmed);
}

test "Hex: trimRight - basic" {
    const bytes = [_]u8{ 0x12, 0x34, 0x00, 0x00 };
    const trimmed = trimRight(&bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34 }, trimmed);
}

test "Hex: trimRight - all zeros" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00 };
    const trimmed = trimRight(&bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, trimmed);
}

test "Hex: concat - basic" {
    const allocator = std.testing.allocator;

    const arr1 = [_]u8{ 0x12, 0x34 };
    const arr2 = [_]u8{ 0xab, 0xcd };
    const arrays = [_][]const u8{ &arr1, &arr2 };

    const result = try concat(allocator, &arrays);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0xab, 0xcd }, result);
}

test "Hex: concat - multiple arrays" {
    const allocator = std.testing.allocator;

    const arr1 = [_]u8{0x01};
    const arr2 = [_]u8{ 0x02, 0x03 };
    const arr3 = [_]u8{ 0x04, 0x05, 0x06 };
    const arrays = [_][]const u8{ &arr1, &arr2, &arr3 };

    const result = try concat(allocator, &arrays);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, result);
}

test "Hex: slice - basic" {
    const bytes = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const sliced = slice(&bytes, 1, 3);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x34, 0xab }, sliced);
}

test "Hex: slice - out of bounds" {
    const bytes = [_]u8{ 0x12, 0x34 };
    const sliced = slice(&bytes, 0, 10);

    try std.testing.expectEqualSlices(u8, &bytes, sliced);
}

test "Hex: slice - start >= end" {
    const bytes = [_]u8{ 0x12, 0x34 };
    const sliced = slice(&bytes, 2, 1);

    try std.testing.expectEqual(@as(usize, 0), sliced.len);
}
