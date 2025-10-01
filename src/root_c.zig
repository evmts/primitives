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
    _ = hex_str;
    _ = error_code;
    @panic("TODO: implement primitives_address_from_hex");
}

/// Free address memory
export fn primitives_address_free(addr: *CAddress) void {
    _ = addr;
    @panic("TODO: implement primitives_address_free");
}

/// Convert address to hex string (caller must free)
export fn primitives_address_to_hex(
    addr: *const CAddress,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    _ = addr;
    _ = error_code;
    @panic("TODO: implement primitives_address_to_hex");
}

/// Convert address to checksummed hex (caller must free)
export fn primitives_address_to_checksum(
    addr: *const CAddress,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    _ = addr;
    _ = error_code;
    @panic("TODO: implement primitives_address_to_checksum");
}

/// Check if address is zero
export fn primitives_address_is_zero(addr: *const CAddress) bool {
    _ = addr;
    @panic("TODO: implement primitives_address_is_zero");
}

/// Check if two addresses are equal
export fn primitives_address_equal(a: *const CAddress, b: *const CAddress) bool {
    _ = a;
    _ = b;
    @panic("TODO: implement primitives_address_equal");
}

/// Calculate CREATE address
export fn primitives_address_create(
    deployer: *const CAddress,
    nonce: u64,
    error_code: *ErrorCode,
) ?*CAddress {
    _ = deployer;
    _ = nonce;
    _ = error_code;
    @panic("TODO: implement primitives_address_create");
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
    _ = deployer;
    _ = salt;
    _ = salt_len;
    _ = init_code_hash;
    _ = hash_len;
    _ = error_code;
    @panic("TODO: implement primitives_address_create2");
}

// ============================================================================
// Hash C API
// ============================================================================

/// Create hash from hex string
export fn primitives_hash_from_hex(
    hex_str: [*:0]const u8,
    error_code: *ErrorCode,
) ?*CHash {
    _ = hex_str;
    _ = error_code;
    @panic("TODO: implement primitives_hash_from_hex");
}

/// Free hash memory
export fn primitives_hash_free(hash: *CHash) void {
    _ = hash;
    @panic("TODO: implement primitives_hash_free");
}

/// Compute Keccak256 hash
export fn primitives_hash_keccak256(
    data: [*]const u8,
    len: usize,
    error_code: *ErrorCode,
) ?*CHash {
    _ = data;
    _ = len;
    _ = error_code;
    @panic("TODO: implement primitives_hash_keccak256");
}

/// Convert hash to hex string (caller must free)
export fn primitives_hash_to_hex(
    hash: *const CHash,
    error_code: *ErrorCode,
) ?[*:0]u8 {
    _ = hash;
    _ = error_code;
    @panic("TODO: implement primitives_hash_to_hex");
}

/// Check if two hashes are equal
export fn primitives_hash_equal(a: *const CHash, b: *const CHash) bool {
    _ = a;
    _ = b;
    @panic("TODO: implement primitives_hash_equal");
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
    _ = bytes;
    _ = len;
    _ = error_code;
    @panic("TODO: implement primitives_hex_encode");
}

/// Decode hex string to bytes (caller must free, out_len set to decoded length)
export fn primitives_hex_decode(
    hex_str: [*:0]const u8,
    out_len: *usize,
    error_code: *ErrorCode,
) ?[*]u8 {
    _ = hex_str;
    _ = out_len;
    _ = error_code;
    @panic("TODO: implement primitives_hex_decode");
}

/// Validate hex string
export fn primitives_hex_is_valid(hex_str: [*:0]const u8) bool {
    _ = hex_str;
    @panic("TODO: implement primitives_hex_is_valid");
}

/// Free hex-allocated memory
export fn primitives_hex_free(ptr: [*]u8) void {
    _ = ptr;
    @panic("TODO: implement primitives_hex_free");
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
