const std = @import("std");
const primitives = @import("root.zig");

// C-compatible error codes
pub const ErrorCode = enum(c_int) {
    OK = 0,
    InvalidFormat = 1,
    InvalidLength = 2,
    InvalidChecksum = 3,
    InvalidCharacter = 4,
    OddLength = 5,
    ValueTooLarge = 6,
    OutOfMemory = 7,
    InvalidSignature = 8,
    InvalidChainId = 9,
    Unknown = 999,
};

// Opaque pointer types for C compatibility
pub const CAddress = opaque {};
pub const CHash = opaque {};
pub const CTransaction = opaque {};

// ============================================================================
// Address C API
// ============================================================================

/// Create address from hex string
/// Returns null on error, sets error_code
export fn primitives_address_from_hex(
    hex_str: [*:0]const u8,
    error_code: *ErrorCode,
) ?*CAddress {
    const hex_slice = std.mem.span(hex_str);
    const addr = primitives.Address.fromHex(hex_slice) catch |err| {
        error_code.* = switch (err) {
            error.InvalidFormat => .InvalidFormat,
            error.InvalidHexString => .InvalidCharacter,
            else => .Unknown,
        };
        return null;
    };

    const c_addr = std.heap.c_allocator.create(primitives.Address) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    c_addr.* = addr;
    error_code.* = .OK;
    return @ptrCast(c_addr);
}

/// Free address memory
export fn primitives_address_free(addr: *CAddress) void {
    const real_addr: *primitives.Address = @ptrCast(@alignCast(addr));
    std.heap.c_allocator.destroy(real_addr);
}

/// Convert address to hex string (caller must free)
export fn primitives_address_to_hex(
    addr: *const CAddress,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    const real_addr: *const primitives.Address = @ptrCast(@alignCast(addr));
    const hex = real_addr.toHex();

    // Allocate null-terminated C string
    const c_str = std.heap.c_allocator.allocSentinel(u8, hex.len, 0) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    @memcpy(c_str[0..hex.len], &hex);
    error_code.* = .OK;
    return c_str.ptr;
}

/// Convert address to checksummed hex (caller must free)
export fn primitives_address_to_checksum(
    addr: *const CAddress,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    const real_addr: *const primitives.Address = @ptrCast(@alignCast(addr));
    const hex = real_addr.toChecksum();

    // Allocate null-terminated C string
    const c_str = std.heap.c_allocator.allocSentinel(u8, hex.len, 0) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    @memcpy(c_str[0..hex.len], &hex);
    error_code.* = .OK;
    return c_str.ptr;
}

/// Check if address is zero
export fn primitives_address_is_zero(addr: *const CAddress) bool {
    const real_addr: *const primitives.Address = @ptrCast(@alignCast(addr));
    return real_addr.isZero();
}

/// Check if two addresses are equal
export fn primitives_address_equal(a: *const CAddress, b: *const CAddress) bool {
    const addr_a: *const primitives.Address = @ptrCast(@alignCast(a));
    const addr_b: *const primitives.Address = @ptrCast(@alignCast(b));
    return addr_a.eql(addr_b.*);
}

/// Calculate CREATE address
export fn primitives_address_create(
    deployer: *const CAddress,
    nonce: u64,
    error_code: *ErrorCode,
) ?*CAddress {
    const real_deployer: *const primitives.Address = @ptrCast(@alignCast(deployer));
    const addr = primitives.Address.create(std.heap.c_allocator, real_deployer.*, nonce) catch {
        error_code.* = .OutOfMemory;
        return null;
    };

    const c_addr = std.heap.c_allocator.create(primitives.Address) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    c_addr.* = addr;
    error_code.* = .OK;
    return @ptrCast(c_addr);
}

/// Calculate CREATE2 address
export fn primitives_address_create2(
    deployer: *const CAddress,
    salt: [*]const u8,
    salt_len: usize,
    init_code_hash: [*]const u8,
    hash_len: usize,
    error_code: *ErrorCode,
) ?*CAddress {
    if (salt_len != 32 or hash_len != 32) {
        error_code.* = .InvalidLength;
        return null;
    }

    const real_deployer: *const primitives.Address = @ptrCast(@alignCast(deployer));
    var salt_array: [32]u8 = undefined;
    var hash_array: [32]u8 = undefined;
    @memcpy(&salt_array, salt[0..32]);
    @memcpy(&hash_array, init_code_hash[0..32]);

    const addr = primitives.Address.create2(real_deployer.*, salt_array, hash_array);

    const c_addr = std.heap.c_allocator.create(primitives.Address) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    c_addr.* = addr;
    error_code.* = .OK;
    return @ptrCast(c_addr);
}

// ============================================================================
// Hash C API
// ============================================================================

/// Create hash from hex string
export fn primitives_hash_from_hex(
    hex_str: [*:0]const u8,
    error_code: *ErrorCode,
) ?*CHash {
    const hex_slice = std.mem.span(hex_str);
    const hash = primitives.Hash.fromHex(hex_slice) catch |err| {
        error_code.* = switch (err) {
            error.InvalidFormat => .InvalidFormat,
            error.InvalidLength => .InvalidLength,
            error.InvalidHexString => .InvalidCharacter,
        };
        return null;
    };

    const c_hash = std.heap.c_allocator.create(primitives.Hash) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    c_hash.* = hash;
    error_code.* = .OK;
    return @ptrCast(c_hash);
}

/// Free hash memory
export fn primitives_hash_free(hash: *CHash) void {
    const real_hash: *primitives.Hash = @ptrCast(@alignCast(hash));
    std.heap.c_allocator.destroy(real_hash);
}

/// Compute Keccak256 hash
export fn primitives_hash_keccak256(
    data: [*]const u8,
    len: usize,
    error_code: *ErrorCode,
) ?*CHash {
    const data_slice = data[0..len];
    const hash = primitives.Hash.keccak256(data_slice);

    const c_hash = std.heap.c_allocator.create(primitives.Hash) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    c_hash.* = hash;
    error_code.* = .OK;
    return @ptrCast(c_hash);
}

/// Convert hash to hex string (caller must free)
export fn primitives_hash_to_hex(
    hash: *const CHash,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    const real_hash: *const primitives.Hash = @ptrCast(@alignCast(hash));
    const hex = real_hash.toHex();

    const c_str = std.heap.c_allocator.allocSentinel(u8, hex.len, 0) catch {
        error_code.* = .OutOfMemory;
        return null;
    };
    @memcpy(c_str[0..hex.len], &hex);
    error_code.* = .OK;
    return c_str.ptr;
}

/// Check if two hashes are equal
export fn primitives_hash_equal(a: *const CHash, b: *const CHash) bool {
    const hash_a: *const primitives.Hash = @ptrCast(@alignCast(a));
    const hash_b: *const primitives.Hash = @ptrCast(@alignCast(b));
    return hash_a.eql(hash_b.*);
}

// ============================================================================
// Hex Encoding C API
// ============================================================================

/// Encode bytes to hex string (caller must free)
export fn primitives_hex_encode(
    bytes: [*]const u8,
    len: usize,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    const bytes_slice = bytes[0..len];
    const hex = primitives.Hex.encode(std.heap.c_allocator, bytes_slice) catch {
        error_code.* = .OutOfMemory;
        return null;
    };

    const c_str = std.heap.c_allocator.allocSentinel(u8, hex.len, 0) catch {
        std.heap.c_allocator.free(hex);
        error_code.* = .OutOfMemory;
        return null;
    };
    @memcpy(c_str[0..hex.len], hex);
    std.heap.c_allocator.free(hex);
    error_code.* = .OK;
    return c_str.ptr;
}

/// Decode hex string to bytes (caller must free, out_len set to decoded length)
export fn primitives_hex_decode(
    hex_str: [*:0]const u8,
    out_len: *usize,
    error_code: *ErrorCode,
) ?[*]u8 {
    const hex_slice = std.mem.span(hex_str);
    const bytes = primitives.Hex.decode(std.heap.c_allocator, hex_slice) catch |err| {
        error_code.* = switch (err) {
            error.InvalidFormat => .InvalidFormat,
            error.OddLength => .OddLength,
            error.InvalidCharacter => .InvalidCharacter,
            else => .Unknown,
        };
        return null;
    };

    out_len.* = bytes.len;
    error_code.* = .OK;
    return bytes.ptr;
}

/// Validate hex string
export fn primitives_hex_is_valid(hex_str: [*:0]const u8) bool {
    const hex_slice = std.mem.span(hex_str);
    return primitives.Hex.isValid(hex_slice);
}

/// Free hex-allocated memory
export fn primitives_hex_free(ptr: [*]u8) void {
    // Can't safely free without length, caller should use allocator directly
    // This is a design limitation - we need the length to free
    // For now, document that caller must track allocation size
    _ = ptr;
}

// ============================================================================
// Numeric C API
// ============================================================================

/// Parse ether string to wei (returns pointer to u256 bytes, 32 bytes, caller must free)
export fn primitives_numeric_parse_ether(
    ether_str: [*:0]const u8,
    error_code: *ErrorCode,
) ?[*]u8 {
    _ = ether_str;
    _ = error_code;
    @panic("TODO: implement primitives_numeric_parse_ether");
}

/// Parse gwei string to wei (returns pointer to u256 bytes, 32 bytes, caller must free)
export fn primitives_numeric_parse_gwei(
    gwei_str: [*:0]const u8,
    error_code: *ErrorCode,
) ?[*]u8 {
    _ = gwei_str;
    _ = error_code;
    @panic("TODO: implement primitives_numeric_parse_gwei");
}

/// Format wei to ether string (caller must free)
export fn primitives_numeric_format_ether(
    wei_bytes: [*]const u8,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    _ = wei_bytes;
    _ = error_code;
    @panic("TODO: implement primitives_numeric_format_ether");
}

/// Format wei to gwei string (caller must free)
export fn primitives_numeric_format_gwei(
    wei_bytes: [*]const u8,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    _ = wei_bytes;
    _ = error_code;
    @panic("TODO: implement primitives_numeric_format_gwei");
}

// ============================================================================
// RLP C API
// ============================================================================

/// Encode bytes to RLP (caller must free, out_len set to encoded length)
export fn primitives_rlp_encode_bytes(
    bytes: [*]const u8,
    len: usize,
    out_len: *usize,
    error_code: *ErrorCode,
) ?[*]u8 {
    _ = bytes;
    _ = len;
    _ = out_len;
    _ = error_code;
    @panic("TODO: implement primitives_rlp_encode_bytes");
}

// ============================================================================
// ABI C API
// ============================================================================

/// Compute function selector from signature
export fn primitives_abi_compute_selector(
    signature: [*:0]const u8,
    out_selector: *[4]u8,
    error_code: *ErrorCode,
) bool {
    _ = signature;
    _ = out_selector;
    _ = error_code;
    @panic("TODO: implement primitives_abi_compute_selector");
}

// ============================================================================
// Transaction C API
// ============================================================================

/// Create legacy transaction
export fn primitives_tx_legacy_new() ?*CTransaction {
    @panic("TODO: implement primitives_tx_legacy_new");
}

/// Free transaction
export fn primitives_tx_free(tx: *CTransaction) void {
    _ = tx;
    @panic("TODO: implement primitives_tx_free");
}

/// Sign transaction
export fn primitives_tx_sign(
    tx: *CTransaction,
    private_key: [*]const u8,
    chain_id: u64,
    error_code: *ErrorCode,
) bool {
    _ = tx;
    _ = private_key;
    _ = chain_id;
    _ = error_code;
    @panic("TODO: implement primitives_tx_sign");
}

/// Serialize transaction (caller must free, out_len set to serialized length)
export fn primitives_tx_serialize(
    tx: *const CTransaction,
    out_len: *usize,
    error_code: *ErrorCode,
) ?[*]u8 {
    _ = tx;
    _ = out_len;
    _ = error_code;
    @panic("TODO: implement primitives_tx_serialize");
}

// ============================================================================
// Gas C API
// ============================================================================

/// Calculate memory expansion cost
export fn primitives_gas_memory_expansion(byte_size: u64) u64 {
    _ = byte_size;
    @panic("TODO: implement primitives_gas_memory_expansion");
}

/// Calculate intrinsic gas cost
export fn primitives_gas_intrinsic(
    data: [*]const u8,
    data_len: usize,
    is_creation: bool,
) u64 {
    _ = data;
    _ = data_len;
    _ = is_creation;
    @panic("TODO: implement primitives_gas_intrinsic");
}

// ============================================================================
// Opcode C API
// ============================================================================

/// Check if opcode is PUSH
export fn primitives_opcode_is_push(opcode: u8) bool {
    _ = opcode;
    @panic("TODO: implement primitives_opcode_is_push");
}

/// Get PUSH size
export fn primitives_opcode_push_size(opcode: u8) u8 {
    _ = opcode;
    @panic("TODO: implement primitives_opcode_push_size");
}

/// Get opcode name (returns static string, do not free)
export fn primitives_opcode_name(opcode: u8) [*:0]const u8 {
    _ = opcode;
    @panic("TODO: implement primitives_opcode_name");
}

// ============================================================================
// EIPs C API
// ============================================================================

/// Create EIPs configuration for hardfork
export fn primitives_eips_new(hardfork: c_int) ?*anyopaque {
    _ = hardfork;
    @panic("TODO: implement primitives_eips_new");
}

/// Free EIPs configuration
export fn primitives_eips_free(eips: *anyopaque) void {
    _ = eips;
    @panic("TODO: implement primitives_eips_free");
}

/// Check if EIP is active
export fn primitives_eips_is_active(eips: *const anyopaque, eip: u16) bool {
    _ = eips;
    _ = eip;
    @panic("TODO: implement primitives_eips_is_active");
}
