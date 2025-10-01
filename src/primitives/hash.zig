const std = @import("std");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// Represents a 32-byte cryptographic hash (typically Keccak256)
///
/// Hash is used throughout Ethereum for:
/// - Transaction hashes
/// - Block hashes
/// - State roots and storage roots
/// - Code hashes
/// - Merkle Patricia Trie node hashes
///
/// This type provides:
/// - Parsing from hex strings and raw bytes
/// - Keccak256 computation
/// - Conversion to hex and u256
/// - Equality comparison and formatting
pub const Hash = @This();

bytes: [32]u8,

/// Zero hash constant (0x0000...0000)
pub const ZERO: Hash = .{ .bytes = [_]u8{0} ** 32 };

/// Hash of empty bytecode (keccak256(""))
/// Used to identify accounts with no code
pub const EMPTY_CODE_HASH: Hash = .{ .bytes = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
} };

/// Root hash of empty Merkle Patricia Trie
/// Used for empty state and storage roots
pub const EMPTY_TRIE_ROOT: Hash = .{ .bytes = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
} };

// Error types
pub const Error = error{
    /// Hex string is not in format "0x" + 64 hex characters
    InvalidFormat,
    /// Byte slice is not exactly 32 bytes
    InvalidLength,
    /// Invalid hex characters in string
    InvalidHexString,
};

// =============================================================================
// Construction Methods
// =============================================================================

/// Construct a Hash from a hex string (with or without 0x prefix)
///
/// Accepts both lowercase and uppercase hex.
///
/// Examples:
/// ```zig
/// const hash = try Hash.fromHex("0x1234...");
/// const hash2 = try Hash.fromHex("1234..."); // also accepts without 0x
/// ```
pub fn fromHex(hex: []const u8) Error!Hash {
    // Accept both with and without 0x prefix
    const hex_digits = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;

    if (hex_digits.len != 64) {
        return error.InvalidFormat;
    }

    var hash: Hash = undefined;
    _ = std.fmt.hexToBytes(&hash.bytes, hex_digits) catch return error.InvalidHexString;
    return hash;
}

/// Construct a Hash from exactly 32 raw bytes
///
/// Example:
/// ```zig
/// const bytes: [32]u8 = ...;
/// const hash = try Hash.fromBytes(&bytes);
/// ```
pub fn fromBytes(bytes: []const u8) Error!Hash {
    if (bytes.len != 32) return error.InvalidLength;
    var hash: Hash = undefined;
    @memcpy(&hash.bytes, bytes[0..32]);
    return hash;
}

/// Compute Keccak256 hash of data
///
/// This is the primary hash function used in Ethereum.
/// Cannot fail - always returns a valid hash.
///
/// Example:
/// ```zig
/// const hash = Hash.keccak256("hello");
/// const tx_hash = Hash.keccak256(&serialized_tx);
/// ```
pub fn keccak256(data: []const u8) Hash {
    var hash: Hash = undefined;
    Keccak256.hash(data, &hash.bytes, .{});
    return hash;
}

// =============================================================================
// Conversion Methods
// =============================================================================

/// Convert hash to lowercase hex string with 0x prefix
///
/// Returns a fixed-size array (no allocation needed).
/// Format: "0x" + 64 lowercase hex chars = 66 bytes total
///
/// Example:
/// ```zig
/// const hex = hash.toHex();
/// // hex = "0x1234...abcd"
/// ```
pub fn toHex(self: Hash) [66]u8 {
    var result: [66]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex = std.fmt.bytesToHex(&self.bytes, .lower);
    @memcpy(result[2..], &hex);
    return result;
}

/// Convert hash to u256 (big-endian)
///
/// The 32 bytes are interpreted as a big-endian integer.
/// Useful for arithmetic operations on hashes.
///
/// Example:
/// ```zig
/// const value = hash.toU256();
/// ```
pub fn toU256(self: Hash) u256 {
    var result: u256 = 0;
    for (self.bytes) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

// =============================================================================
// Comparison Methods
// =============================================================================

/// Check if two hashes are equal
///
/// Example:
/// ```zig
/// if (hash1.eql(hash2)) {
///     // Same hash
/// }
/// ```
pub fn eql(self: Hash, other: Hash) bool {
    return std.mem.eql(u8, &self.bytes, &other.bytes);
}

/// Check if hash is zero (0x0000...0000)
///
/// Example:
/// ```zig
/// if (hash.isZero()) {
///     // Handle empty/null hash
/// }
/// ```
pub fn isZero(self: Hash) bool {
    return std.mem.eql(u8, &self.bytes, &ZERO.bytes);
}

// =============================================================================
// Formatting for std.fmt
// =============================================================================

/// Format hash for std.fmt output (uses lowercase hex format)
///
/// Integrates with Zig's standard formatting system.
/// Default output is lowercase hex with 0x prefix.
///
/// Example:
/// ```zig
/// std.debug.print("Hash: {}", .{hash});
/// std.debug.print("Hash: {x}", .{hash}); // also works
/// ```
pub fn format(
    self: Hash,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    const hex = self.toHex();
    try writer.writeAll(&hex);
}

// =============================================================================
// Tests
// =============================================================================

test "Hash: ZERO constant" {
    const expected = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &expected, &ZERO.bytes);
}

test "Hash: EMPTY_CODE_HASH constant" {
    // Verify EMPTY_CODE_HASH is keccak256("")
    const computed = Hash.keccak256("");
    try std.testing.expectEqualSlices(u8, &EMPTY_CODE_HASH.bytes, &computed.bytes);
}

test "Hash: EMPTY_TRIE_ROOT constant" {
    const expected = [_]u8{
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
        0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
        0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
        0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
    };
    try std.testing.expectEqualSlices(u8, &expected, &EMPTY_TRIE_ROOT.bytes);
}

test "Hash: fromHex - valid with 0x prefix" {
    const hash = try Hash.fromHex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    try std.testing.expectEqual(@as(u8, 0x01), hash.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x23), hash.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0xef), hash.bytes[31]);
}

test "Hash: fromHex - valid without 0x prefix" {
    const hash = try Hash.fromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    try std.testing.expectEqual(@as(u8, 0x01), hash.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xef), hash.bytes[31]);
}

test "Hash: fromHex - invalid format (too short)" {
    const result = Hash.fromHex("0x0123456789abcdef");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "Hash: fromHex - invalid format (too long)" {
    const result = Hash.fromHex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "Hash: fromHex - invalid hex characters" {
    const result = Hash.fromHex("0x0123456789abcdez0123456789abcdef0123456789abcdef0123456789abcdef");
    try std.testing.expectError(error.InvalidHexString, result);
}

test "Hash: fromBytes - valid 32 bytes" {
    const bytes = [_]u8{0x01, 0x23, 0x45} ++ [_]u8{0} ** 29;
    const hash = try Hash.fromBytes(&bytes);
    try std.testing.expectEqual(@as(u8, 0x01), hash.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x23), hash.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x45), hash.bytes[2]);
}

test "Hash: fromBytes - invalid length (too short)" {
    const bytes = [_]u8{0x01, 0x23};
    const result = Hash.fromBytes(&bytes);
    try std.testing.expectError(error.InvalidLength, result);
}

test "Hash: fromBytes - invalid length (too long)" {
    const bytes = [_]u8{0} ** 33;
    const result = Hash.fromBytes(&bytes);
    try std.testing.expectError(error.InvalidLength, result);
}

test "Hash: keccak256 - empty string" {
    const hash = Hash.keccak256("");
    try std.testing.expectEqualSlices(u8, &EMPTY_CODE_HASH.bytes, &hash.bytes);
}

test "Hash: keccak256 - hello world" {
    const hash = Hash.keccak256("hello world");
    // Verify it's not zero
    try std.testing.expect(!hash.isZero());
    // Should produce deterministic result
    const hash2 = Hash.keccak256("hello world");
    try std.testing.expect(hash.eql(hash2));
}

test "Hash: keccak256 - different inputs produce different hashes" {
    const hash1 = Hash.keccak256("hello");
    const hash2 = Hash.keccak256("world");
    try std.testing.expect(!hash1.eql(hash2));
}

test "Hash: toHex - lowercase format" {
    const bytes = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef} ++ [_]u8{0xff} ** 24;
    const hash = try Hash.fromBytes(&bytes);
    const hex = hash.toHex();
    try std.testing.expectEqualStrings("0x0123456789abcdefffffffffffffffffffffffffffffffffffffffffffffffff", &hex);
}

test "Hash: toU256 - converts to integer" {
    const bytes = [_]u8{0} ** 31 ++ [_]u8{0xff};
    const hash = try Hash.fromBytes(&bytes);
    const value = hash.toU256();
    try std.testing.expectEqual(@as(u256, 0xff), value);
}

test "Hash: toU256 - big endian conversion" {
    const bytes = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const hash = try Hash.fromBytes(&bytes);
    const value = hash.toU256();
    // 0x01 in first byte should be highest bits
    const expected: u256 = @as(u256, 0x01) << 248;
    try std.testing.expectEqual(expected, value);
}

test "Hash: eql - equal hashes" {
    const bytes = [_]u8{0x12} ** 32;
    const hash1 = try Hash.fromBytes(&bytes);
    const hash2 = try Hash.fromBytes(&bytes);
    try std.testing.expect(hash1.eql(hash2));
}

test "Hash: eql - different hashes" {
    const bytes1 = [_]u8{0x12} ** 32;
    const bytes2 = [_]u8{0x34} ** 32;
    const hash1 = try Hash.fromBytes(&bytes1);
    const hash2 = try Hash.fromBytes(&bytes2);
    try std.testing.expect(!hash1.eql(hash2));
}

test "Hash: isZero - zero hash" {
    try std.testing.expect(ZERO.isZero());
    const hash = try Hash.fromBytes(&([_]u8{0} ** 32));
    try std.testing.expect(hash.isZero());
}

test "Hash: isZero - non-zero hash" {
    const hash = Hash.keccak256("hello");
    try std.testing.expect(!hash.isZero());
}

test "Hash: format integration with std.fmt" {
    const bytes = [_]u8{0xab} ** 32;
    const hash = try Hash.fromBytes(&bytes);

    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try hash.format("", .{}, fbs.writer());

    const result = fbs.getWritten();

    // Should format as lowercase hex string with 0x prefix
    try std.testing.expect(std.mem.startsWith(u8, result, "0x"));
    try std.testing.expectEqual(@as(usize, 66), result.len);
    try std.testing.expectEqualStrings("0xabababababababababababababababababababababababababababababababab", result);
}

test "Hash: fromHex and toHex roundtrip" {
    const original = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const hash = try Hash.fromHex(original);
    const hex = hash.toHex();
    try std.testing.expectEqualStrings(original, &hex);
}

test "Hash: comprehensive keccak256 test vectors" {
    // Test vector 1: Empty string
    const empty = Hash.keccak256("");
    const empty_expected = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const empty_hex = empty.toHex();
    try std.testing.expectEqualStrings(empty_expected, &empty_hex);

    // Test vector 2: "hello"
    const hello = Hash.keccak256("hello");
    const hello_expected = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
    const hello_hex = hello.toHex();
    try std.testing.expectEqualStrings(hello_expected, &hello_hex);
}

test "Hash: constants are correct" {
    // Verify EMPTY_CODE_HASH
    try std.testing.expect(EMPTY_CODE_HASH.eql(Hash.keccak256("")));

    // Verify ZERO is all zeros
    for (ZERO.bytes) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
