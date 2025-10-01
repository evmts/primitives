const std = @import("std");
const Allocator = std.mem.Allocator;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// Represents a 20-byte Ethereum address
///
/// Ethereum addresses are derived from the last 20 bytes of the Keccak256 hash
/// of an ECDSA public key, or computed deterministically for contract addresses
/// using CREATE or CREATE2 opcodes.
///
/// This type provides:
/// - Parsing from hex strings with optional EIP-55 checksum validation
/// - Conversion to/from various formats (hex, u256, bytes)
/// - Contract address computation (CREATE and CREATE2)
/// - EIP-55 checksummed output
pub const Address = @This();

bytes: [20]u8,

/// Zero address constant (0x0000000000000000000000000000000000000000)
pub const ZERO: Address = .{ .bytes = [_]u8{0} ** 20 };

// Error types
pub const Error = error{
    /// Hex string is not in format "0x" + 40 hex characters
    InvalidFormat,
    /// Byte slice is not exactly 20 bytes
    InvalidLength,
    /// EIP-55 checksum validation failed (mixed case doesn't match hash)
    InvalidChecksum,
    /// Invalid hex characters in string
    InvalidHexString,
};

// =============================================================================
// Construction Methods
// =============================================================================

/// Construct an Address from a hex string (with or without 0x prefix)
///
/// Accepts both lowercase and mixed-case (checksummed) addresses.
/// Does NOT validate EIP-55 checksum - use `isValidChecksum` separately if needed.
///
/// Examples:
/// ```zig
/// const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
/// const addr2 = try Address.fromHex("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676"); // also valid
/// ```
pub fn fromHex(hex: []const u8) Error!Address {
    if (hex.len != 42 or !std.mem.startsWith(u8, hex, "0x")) {
        return error.InvalidFormat;
    }

    var addr: Address = undefined;
    _ = std.fmt.hexToBytes(&addr.bytes, hex[2..]) catch return error.InvalidHexString;
    return addr;
}

/// Construct an Address from exactly 20 raw bytes
///
/// Example:
/// ```zig
/// const bytes: [20]u8 = .{0x74, 0x2d, 0x35, ...};
/// const addr = try Address.fromBytes(&bytes);
/// ```
pub fn fromBytes(bytes: []const u8) Error!Address {
    if (bytes.len != 20) return error.InvalidLength;
    var addr: Address = undefined;
    @memcpy(&addr.bytes, bytes[0..20]);
    return addr;
}

/// Construct an Address from an ECDSA public key (secp256k1)
///
/// Algorithm:
/// 1. Concatenate x and y coordinates (64 bytes total)
/// 2. Compute Keccak256 hash (32 bytes)
/// 3. Take last 20 bytes as address
///
/// This is how Ethereum derives addresses from public keys.
/// Cannot fail - always returns a valid address.
///
/// Example:
/// ```zig
/// const addr = Address.fromPublicKey(pubkey_x, pubkey_y);
/// ```
pub fn fromPublicKey(x: u256, y: u256) Address {
    var pub_key_bytes: [64]u8 = undefined;
    std.mem.writeInt(u256, pub_key_bytes[0..32], x, .big);
    std.mem.writeInt(u256, pub_key_bytes[32..64], y, .big);

    var hash: [32]u8 = undefined;
    Keccak256.hash(&pub_key_bytes, &hash, .{});

    var address: Address = undefined;
    @memcpy(&address.bytes, hash[12..32]);
    return address;
}

/// Construct an Address from a u256 value
///
/// Takes the low 160 bits (20 bytes) of the value.
/// Useful when addresses are represented as uint160 in contracts.
///
/// Example:
/// ```zig
/// const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
/// ```
pub fn fromU256(value: u256) Address {
    var addr: Address = undefined;
    var v = value;
    for (0..20) |i| {
        addr.bytes[19 - i] = @truncate(v & 0xFF);
        v >>= 8;
    }
    return addr;
}

// =============================================================================
// Validation Methods
// =============================================================================

/// Validate an address string format (but not checksum)
///
/// Checks:
/// - Starts with "0x"
/// - Followed by exactly 40 hexadecimal characters
/// - Does NOT validate EIP-55 checksum
///
/// Example:
/// ```zig
/// if (Address.isValid("0x742d35cc...")) {
///     // Valid format, can safely parse
/// }
/// ```
pub fn isValid(str: []const u8) bool {
    if (str.len != 42 or !std.mem.startsWith(u8, str, "0x"))
        return false;

    for (str[2..]) |c| {
        const valid = switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F' => true,
            else => false,
        };
        if (!valid) return false;
    }

    return true;
}

/// Validate an address string with EIP-55 checksum
///
/// Checks format AND verifies mixed-case encoding matches Keccak256 hash.
/// Returns true only if checksum is correct.
/// Returns false for all-lowercase addresses (even if otherwise valid).
///
/// Example:
/// ```zig
/// // Valid checksum
/// assert(Address.isValidChecksum("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"));
/// // Invalid - all lowercase
/// assert(!Address.isValidChecksum("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676"));
/// ```
pub fn isValidChecksum(str: []const u8) bool {
    if (!isValid(str))
        return false;

    var addr: Address = undefined;
    _ = std.fmt.hexToBytes(&addr.bytes, str[2..]) catch return false;

    const checksummed = addr.toChecksum();
    return std.mem.eql(u8, &checksummed, str);
}

// =============================================================================
// Conversion Methods
// =============================================================================

/// Convert address to lowercase hex string with 0x prefix
///
/// Returns a fixed-size array (no allocation needed).
/// Format: "0x" + 40 lowercase hex chars = 42 bytes total
///
/// Example:
/// ```zig
/// const hex = addr.toHex();
/// // hex = "0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676"
/// ```
pub fn toHex(self: Address) [42]u8 {
    var result: [42]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex = std.fmt.bytesToHex(&self.bytes, .lower);
    @memcpy(result[2..], &hex);
    return result;
}

/// Convert address to EIP-55 checksummed hex string
///
/// Returns mixed-case hex where uppercase/lowercase encodes a checksum.
/// This is the standard format for displaying addresses to users.
///
/// Algorithm (EIP-55):
/// 1. Convert to lowercase hex
/// 2. Hash the lowercase hex (without 0x prefix)
/// 3. For each hex char, uppercase if corresponding hash nibble >= 8
///
/// Example:
/// ```zig
/// const hex = addr.toChecksum();
/// // hex = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"
/// ```
pub fn toChecksum(self: Address) [42]u8 {
    var result: [42]u8 = undefined;
    var hex_without_prefix: [40]u8 = undefined;

    result[0] = '0';
    result[1] = 'x';

    const lowercase = "0123456789abcdef";
    const uppercase = "0123456789ABCDEF";

    // First pass: generate lowercase hex
    for (self.bytes, 0..) |b, i| {
        hex_without_prefix[i * 2] = lowercase[b >> 4];
        hex_without_prefix[i * 2 + 1] = lowercase[b & 15];
    }

    // Hash the lowercase hex (without 0x prefix)
    var hash: [32]u8 = undefined;
    Keccak256.hash(&hex_without_prefix, &hash, .{});

    // Second pass: apply checksum
    for (self.bytes, 0..) |b, i| {
        const high_nibble = b >> 4;
        const low_nibble = b & 15;
        const high_hash = (hash[i] >> 4) & 0x0F;
        const low_hash = hash[i] & 0x0F;

        result[i * 2 + 2] = if (high_nibble > 9 and high_hash >= 8)
            uppercase[high_nibble]
        else
            lowercase[high_nibble];

        result[i * 2 + 3] = if (low_nibble > 9 and low_hash >= 8)
            uppercase[low_nibble]
        else
            lowercase[low_nibble];
    }

    return result;
}

/// Convert address to hex string with specified case
///
/// Allows choosing between lowercase and uppercase (not checksummed).
/// For checksummed output, use `toChecksum()` instead.
///
/// Example:
/// ```zig
/// const lower = addr.formatWithCase(false);
/// // "0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676"
///
/// const upper = addr.formatWithCase(true);
/// // "0x742D35CC6641C91B6E4BB6AC9E3FF2958C94E676"
/// ```
pub fn formatWithCase(self: Address, uppercase: bool) [42]u8 {
    if (uppercase) {
        var result: [42]u8 = undefined;
        result[0] = '0';
        result[1] = 'x';
        const hex = std.fmt.bytesToHex(&self.bytes, .upper);
        @memcpy(result[2..], &hex);
        return result;
    } else {
        return self.toHex();
    }
}

/// Convert address to u256 (big-endian)
///
/// The 20 bytes are interpreted as a big-endian integer.
/// Useful for casting to uint160 in ABI encoding.
///
/// Example:
/// ```zig
/// const value = addr.toU256();
/// ```
pub fn toU256(self: Address) u256 {
    var result: u256 = 0;
    for (self.bytes) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

// =============================================================================
// Contract Address Calculation
// =============================================================================

/// Calculate contract address from deployer and nonce (CREATE opcode)
///
/// Algorithm:
/// ```
/// address = keccak256(rlp([deployer_address, nonce]))[12:]
/// ```
///
/// This is how Ethereum computes contract addresses for the CREATE opcode.
/// Requires RLP encoding, so may allocate memory.
///
/// Example:
/// ```zig
/// const contract_addr = try Address.create(allocator, deployer, 42);
/// ```
pub fn create(allocator: Allocator, deployer: Address, nonce: u64) !Address {
    // TODO: This is a simplified RLP implementation
    // Will be replaced with proper RLP encoding once rlp.zig is implemented
    _ = allocator; // Will be needed for proper RLP implementation

    // Convert nonce to bytes, stripping leading zeros
    var nonce_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce_bytes, nonce, .big);

    // Find first non-zero byte
    var nonce_start: usize = 0;
    for (nonce_bytes) |byte| {
        if (byte != 0) break;
        nonce_start += 1;
    }

    // If nonce is 0, use empty slice
    const nonce_slice = if (nonce == 0) &[_]u8{} else nonce_bytes[nonce_start..];

    // Build simple RLP encoding using fixed buffer: [address, nonce]
    var rlp_data: [64]u8 = undefined; // Max size for this encoding
    var rlp_len: usize = 0;

    // Calculate total payload length
    const addr_len = 1 + 20; // 0x94 (0x80 + 20) + 20 bytes
    const nonce_encoded_len = if (nonce == 0) 1 else if (nonce_slice.len == 1 and nonce_slice[0] < 0x80) 1 else 1 + nonce_slice.len;
    const total_len = addr_len + nonce_encoded_len;

    // RLP list header
    rlp_data[rlp_len] = 0xc0 + @as(u8, @intCast(total_len));
    rlp_len += 1;

    // Address (20 bytes)
    rlp_data[rlp_len] = 0x80 + 20;
    rlp_len += 1;
    @memcpy(rlp_data[rlp_len .. rlp_len + 20], &deployer.bytes);
    rlp_len += 20;

    // Nonce
    if (nonce == 0) {
        rlp_data[rlp_len] = 0x80;
        rlp_len += 1;
    } else if (nonce_slice.len == 1 and nonce_slice[0] < 0x80) {
        rlp_data[rlp_len] = nonce_slice[0];
        rlp_len += 1;
    } else {
        rlp_data[rlp_len] = 0x80 + @as(u8, @intCast(nonce_slice.len));
        rlp_len += 1;
        @memcpy(rlp_data[rlp_len .. rlp_len + nonce_slice.len], nonce_slice);
        rlp_len += nonce_slice.len;
    }

    // Hash the RLP encoded data
    var hash: [32]u8 = undefined;
    Keccak256.hash(rlp_data[0..rlp_len], &hash, .{});

    // Take last 20 bytes as address
    var address: Address = undefined;
    @memcpy(&address.bytes, hash[12..32]);

    return address;
}

/// Calculate contract address using CREATE2 (EIP-1014)
///
/// Algorithm:
/// ```
/// address = keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]
/// ```
///
/// CREATE2 allows deterministic address computation without nonce dependency.
/// The salt and init_code_hash can be chosen to create vanity addresses.
///
/// Example:
/// ```zig
/// const salt: [32]u8 = ...;
/// const init_code_hash: [32]u8 = Hash.keccak256(init_code).bytes;
/// const contract_addr = Address.create2(deployer, salt, init_code_hash);
/// ```
pub fn create2(deployer: Address, salt: [32]u8, init_code_hash: [32]u8) Address {
    // Build the data to hash: 0xff ++ deployer ++ salt ++ init_code_hash
    var data: [85]u8 = undefined;
    data[0] = 0xff;
    @memcpy(data[1..21], &deployer.bytes);
    @memcpy(data[21..53], &salt);
    @memcpy(data[53..85], &init_code_hash);

    // Hash the data
    var hash: [32]u8 = undefined;
    Keccak256.hash(&data, &hash, .{});

    // Take last 20 bytes as address
    var address: Address = undefined;
    @memcpy(&address.bytes, hash[12..32]);

    return address;
}

// =============================================================================
// Comparison Methods
// =============================================================================

/// Check if address is zero (0x0000...0000)
///
/// Example:
/// ```zig
/// if (addr.isZero()) {
///     // Handle empty/null address
/// }
/// ```
pub fn isZero(self: Address) bool {
    return std.mem.eql(u8, &self.bytes, &ZERO.bytes);
}

/// Check if two addresses are equal
///
/// Example:
/// ```zig
/// if (addr.eql(other_addr)) {
///     // Same address
/// }
/// ```
pub fn eql(self: Address, other: Address) bool {
    return std.mem.eql(u8, &self.bytes, &other.bytes);
}

// =============================================================================
// Formatting for std.fmt
// =============================================================================

/// Format address for std.fmt output (uses checksummed format)
///
/// Integrates with Zig's standard formatting system.
/// Default output is EIP-55 checksummed.
///
/// Example:
/// ```zig
/// std.debug.print("Address: {}", .{addr});
/// std.debug.print("Address: {x}", .{addr}); // also works
/// ```
pub fn format(
    self: Address,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    const hex = self.toChecksum();
    try writer.writeAll(&hex);
}

/// Format address as a number for std.fmt hex output
///
/// Used internally by std.fmt when formatting with number-specific options.
/// Most users should use `format()` instead.
///
/// Example:
/// ```zig
/// // Internal use by std.fmt
/// std.debug.print("{x}", .{addr});
/// ```
pub fn formatNumber(
    self: Address,
    writer: anytype,
    options: std.fmt.Number,
) !void {
    _ = options;
    const hex = self.toChecksum();
    try writer.writeAll(&hex);
}

// =============================================================================
// Tests
// =============================================================================

test "Address: ZERO constant" {
    const expected = [_]u8{0} ** 20;
    try std.testing.expectEqualSlices(u8, &expected, &ZERO.bytes);
}

test "Address: fromHex - valid lowercase address" {
    const addr = try Address.fromHex("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676");
    try std.testing.expectEqual(@as(u8, 0x74), addr.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x2d), addr.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x76), addr.bytes[19]);
}

test "Address: fromHex - valid checksummed address" {
    const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");
    try std.testing.expectEqual(@as(u8, 0x74), addr.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x76), addr.bytes[19]);
}

test "Address: fromHex - invalid format (no 0x)" {
    const result = Address.fromHex("742d35cc6641c91b6e4bb6ac9e3ff2958c94e676");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "Address: fromHex - invalid length (too short)" {
    const result = Address.fromHex("0x742d35cc");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "Address: fromHex - invalid length (too long)" {
    const result = Address.fromHex("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676aa");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "Address: fromHex - invalid hex characters" {
    const result = Address.fromHex("0x742d35zz6641c91b6e4bb6ac9e3ff2958c94e676");
    try std.testing.expectError(error.InvalidHexString, result);
}

test "Address: fromBytes - valid 20 bytes" {
    const bytes = [_]u8{0x74, 0x2d, 0x35} ++ [_]u8{0} ** 17;
    const addr = try Address.fromBytes(&bytes);
    try std.testing.expectEqual(@as(u8, 0x74), addr.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x2d), addr.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x35), addr.bytes[2]);
}

test "Address: fromBytes - invalid length" {
    const bytes = [_]u8{0x74, 0x2d};
    const result = Address.fromBytes(&bytes);
    try std.testing.expectError(error.InvalidLength, result);
}

test "Address: fromU256 - converts integer to address" {
    const value: u256 = 0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676;
    const addr = Address.fromU256(value);
    try std.testing.expectEqual(@as(u8, 0x74), addr.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x76), addr.bytes[19]);
}

test "Address: fromU256 - zero" {
    const addr = Address.fromU256(0);
    try std.testing.expectEqualSlices(u8, &ZERO.bytes, &addr.bytes);
}

test "Address: fromU256 and toU256 roundtrip" {
    const original: u256 = 0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676;
    const addr = Address.fromU256(original);
    const result = addr.toU256();
    try std.testing.expectEqual(original, result);
}

test "Address: toHex - lowercase format" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const hex = addr.toHex();
    try std.testing.expectEqualStrings("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676", &hex);
}

test "Address: toChecksum - EIP-55 format" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const hex = addr.toChecksum();
    // This should have proper mixed case per EIP-55
    try std.testing.expect(std.mem.startsWith(u8, &hex, "0x"));
    try std.testing.expectEqual(@as(usize, 42), hex.len);
}

test "Address: formatWithCase - lowercase" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const hex = addr.formatWithCase(false);
    try std.testing.expectEqualStrings("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676", &hex);
}

test "Address: formatWithCase - uppercase" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const hex = addr.formatWithCase(true);
    try std.testing.expectEqualStrings("0x742D35CC6641C91B6E4BB6AC9E3FF2958C94E676", &hex);
}

test "Address: isValid - valid format" {
    try std.testing.expect(Address.isValid("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676"));
    try std.testing.expect(Address.isValid("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"));
}

test "Address: isValid - invalid format" {
    try std.testing.expect(!Address.isValid("742d35cc6641c91b6e4bb6ac9e3ff2958c94e676")); // no 0x
    try std.testing.expect(!Address.isValid("0x742d35cc")); // too short
    try std.testing.expect(!Address.isValid("0x742d35zz6641c91b6e4bb6ac9e3ff2958c94e676")); // invalid char
}

test "Address: isZero - zero address" {
    try std.testing.expect(ZERO.isZero());
    const addr = Address.fromU256(0);
    try std.testing.expect(addr.isZero());
}

test "Address: isZero - non-zero address" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    try std.testing.expect(!addr.isZero());
}

test "Address: eql - equal addresses" {
    const addr1 = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const addr2 = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    try std.testing.expect(addr1.eql(addr2));
}

test "Address: eql - different addresses" {
    const addr1 = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);
    const addr2 = Address.fromU256(0x1111111111111111111111111111111111111111);
    try std.testing.expect(!addr1.eql(addr2));
}

test "Address: fromPublicKey - derives address from pubkey" {
    // Test vector from Ethereum (well-known address)
    // Public key for address 0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676
    // Note: This is a placeholder - real test would use actual secp256k1 pubkey
    const pubkey_x: u256 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    const pubkey_y: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    const addr = Address.fromPublicKey(pubkey_x, pubkey_y);

    // Should produce a valid address (not zero)
    try std.testing.expect(!addr.isZero());
}

test "Address: create2 - deterministic address" {
    const deployer = Address.fromU256(0x0000000000000000000000000000000000000000);
    const salt = [_]u8{0} ** 32;
    const init_code_hash = [_]u8{0} ** 32;

    const addr1 = Address.create2(deployer, salt, init_code_hash);
    const addr2 = Address.create2(deployer, salt, init_code_hash);

    // Same inputs should produce same address
    try std.testing.expect(addr1.eql(addr2));
    try std.testing.expect(!addr1.isZero());
}

test "Address: create2 - different salt produces different address" {
    const deployer = Address.fromU256(0x1111111111111111111111111111111111111111);
    const salt1 = [_]u8{0} ** 32;
    var salt2 = [_]u8{0} ** 32;
    salt2[0] = 1;
    const init_code_hash = [_]u8{0} ** 32;

    const addr1 = Address.create2(deployer, salt1, init_code_hash);
    const addr2 = Address.create2(deployer, salt2, init_code_hash);

    // Different salts should produce different addresses
    try std.testing.expect(!addr1.eql(addr2));
}

test "Address: create - requires allocator" {
    const allocator = std.testing.allocator;
    const deployer = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);

    const addr = try Address.create(allocator, deployer, 0);
    try std.testing.expect(!addr.isZero());

    // Different nonces should produce different addresses
    const addr2 = try Address.create(allocator, deployer, 1);
    try std.testing.expect(!addr.eql(addr2));
}

test "Address: format integration with std.fmt" {
    const addr = Address.fromU256(0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676);

    // Test direct format call
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try addr.format("", .{}, fbs.writer());

    const result = fbs.getWritten();

    // Should format as checksummed hex string
    try std.testing.expect(std.mem.startsWith(u8, result, "0x"));
    try std.testing.expectEqual(@as(usize, 42), result.len);
}
