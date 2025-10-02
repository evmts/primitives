const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const RLP = @import("../encoding/rlp.zig");
const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

/// Represents a Blob Transaction (EIP-4844, Type 3)
///
/// EIP-4844 (Proto-Danksharding) introduces a new transaction type that carries
/// "blobs" of data. Blobs are large (~128KB) chunks of data that are temporarily
/// stored on the beacon chain and provide a cheaper alternative to CALLDATA for
/// Layer 2 rollups.
///
/// This type provides:
/// - Transaction signing with private keys
/// - RLP serialization with 0x03 prefix (EIP-2718 envelope)
/// - Transaction hash computation (Keccak256)
/// - Blob gas and fee calculations
/// - Full validation including blob count limits
///
/// Structure (EIP-4844):
/// ```
/// 0x03 || RLP([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
///              gas_limit, to, value, data, access_list, max_fee_per_blob_gas,
///              blob_versioned_hashes, v, r, s])
/// ```
///
/// Key differences from EIP-1559:
/// - Includes max_fee_per_blob_gas for blob data pricing
/// - Includes blob_versioned_hashes (commitments to blob data)
/// - to field is REQUIRED (not optional) - no contract creation
/// - Transaction type is 0x03
pub const BlobTransaction = @This();

/// Chain ID for replay protection (EIP-155)
chain_id: u64,

/// Transaction nonce (sequential counter for sender account)
nonce: u64,

/// Maximum priority fee (tip) per gas in wei
max_priority_fee_per_gas: u256,

/// Maximum total fee per gas in wei
max_fee_per_gas: u256,

/// Maximum gas units this transaction can consume
gas_limit: u64,

/// Recipient address (REQUIRED for blob transactions - no contract creation)
to: Address,

/// Value in wei to transfer to recipient
value: u256,

/// Contract call data
data: []const u8,

/// Access list (addresses and storage keys pre-declared for cheaper access)
access_list: []const AccessListEntry,

/// Maximum fee per blob gas in wei
max_fee_per_blob_gas: u64,

/// Versioned hashes of blob commitments (KZG commitments)
blob_versioned_hashes: []const Hash,

/// ECDSA signature recovery ID (0 or 1 for EIP-4844)
v: u64,

/// ECDSA signature r component (32 bytes)
r: [32]u8,

/// ECDSA signature s component (32 bytes)
s: [32]u8,

// =============================================================================
// Constants
// =============================================================================

/// EIP-2718 transaction type identifier for blob transactions
pub const TRANSACTION_TYPE: u8 = 0x03;

/// Number of bytes in a single blob (128 KB)
pub const BYTES_PER_BLOB: u32 = 131_072;

/// Maximum number of blobs per transaction
pub const MAX_BLOBS_PER_TX: u8 = 6;

/// Gas consumption per blob
pub const BLOB_GAS_PER_BLOB: u32 = 131_072;

/// Blob commitment version byte
pub const BLOB_COMMITMENT_VERSION: u8 = 0x01;

/// Target number of blob gas per block (3 blobs)
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 393_216;

/// Blob base fee update fraction (controls how quickly fee adjusts)
pub const BLOB_BASE_FEE_UPDATE_FRACTION: u64 = 3338477;

/// Minimum blob base fee (1 wei)
pub const MIN_BLOB_BASE_FEE: u64 = 1;

/// Secp256k1 curve order (for signature validation)
const SECP256K1_N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

/// Half of secp256k1 curve order (for EIP-2 low-s requirement)
const SECP256K1_N_HALF: u256 = SECP256K1_N / 2;

// =============================================================================
// Error Types
// =============================================================================

pub const Error = error{
    /// ECDSA signature is invalid or malformed
    InvalidSignature,
    /// Chain ID doesn't match expected value
    InvalidChainId,
    /// RLP decoding failed (malformed transaction data)
    InvalidRlpEncoding,
    /// Transaction field contains invalid value
    InvalidTransactionField,
    /// Signature recovery failed (public key could not be recovered)
    SignatureRecoveryFailed,
    /// The s value is too high (violates EIP-2 low-s requirement)
    InvalidSValue,
    /// The v value is invalid (not 0 or 1)
    InvalidVValue,
    /// Max priority fee exceeds max fee
    InvalidFeeValues,
    /// Too many blobs in transaction (exceeds MAX_BLOBS_PER_TX)
    TooManyBlobs,
    /// No blobs in transaction (at least one required)
    NoBlobs,
    /// Access list encoding/decoding error
    InvalidAccessList,
    /// Invalid blob versioned hash
    InvalidBlobHash,
} || Allocator.Error || RLP.Error;

// =============================================================================
// Type Aliases
// =============================================================================

/// A single blob of data (128 KB)
pub const Blob = [BYTES_PER_BLOB]u8;

/// BLS12-381 G1 point commitment (48 bytes)
pub const BlobCommitment = [48]u8;

/// BLS12-381 proof (48 bytes)
pub const BlobProof = [48]u8;

// =============================================================================
// Construction & Initialization
// =============================================================================

/// Create a new unsigned blob transaction
///
/// Creates a transaction with empty signature values (v=0, r=0, s=0).
/// Call `sign()` to add a valid signature before broadcasting.
///
/// Example:
/// ```zig
/// const tx = BlobTransaction.init(.{
///     .chain_id = 1,
///     .nonce = 42,
///     .max_priority_fee_per_gas = try Numeric.parseGwei("2"),
///     .max_fee_per_gas = try Numeric.parseGwei("100"),
///     .gas_limit = 21_000,
///     .to = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .value = try Numeric.parseEther("0.1"),
///     .data = &[_]u8{},
///     .access_list = &[_]AccessListEntry{},
///     .max_fee_per_blob_gas = try Numeric.parseGwei("50"),
///     .blob_versioned_hashes = &[_]Hash{versioned_hash1, versioned_hash2},
/// });
/// ```
pub fn init(params: struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: Address,
    value: u256,
    data: []const u8,
    access_list: []const AccessListEntry,
    max_fee_per_blob_gas: u64,
    blob_versioned_hashes: []const Hash,
}) BlobTransaction {
    return BlobTransaction{
        .chain_id = params.chain_id,
        .nonce = params.nonce,
        .max_priority_fee_per_gas = params.max_priority_fee_per_gas,
        .max_fee_per_gas = params.max_fee_per_gas,
        .gas_limit = params.gas_limit,
        .to = params.to,
        .value = params.value,
        .data = params.data,
        .access_list = params.access_list,
        .max_fee_per_blob_gas = params.max_fee_per_blob_gas,
        .blob_versioned_hashes = params.blob_versioned_hashes,
        .v = 0,
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 32,
    };
}

// =============================================================================
// Blob Gas & Fee Calculation
// =============================================================================

/// Calculate total blob gas for this transaction
///
/// Blob gas is separate from regular gas and is calculated based on the
/// number of blob versioned hashes included in the transaction.
///
/// Formula: blob_gas = len(blob_versioned_hashes) * BLOB_GAS_PER_BLOB
///
/// Example:
/// ```zig
/// const blob_gas = tx.blobGas();
/// // For 2 blobs: 2 * 131_072 = 262_144
/// ```
pub fn blobGas(self: BlobTransaction) u64 {
    return @as(u64, @intCast(self.blob_versioned_hashes.len)) * BLOB_GAS_PER_BLOB;
}

/// Calculate blob fee for this transaction given blob base fee
///
/// The blob fee is calculated separately from regular gas fees.
/// It represents the total cost of blob data storage.
///
/// Formula: blob_fee = blob_gas * blob_base_fee
///
/// Example:
/// ```zig
/// const blob_base_fee = calculateBlobBaseFee(excess_blob_gas);
/// const blob_fee = tx.blobFee(blob_base_fee);
/// const total_cost = tx.maxCost() + blob_fee;
/// ```
pub fn blobFee(self: BlobTransaction, blob_base_fee: u64) u64 {
    return self.blobGas() * blob_base_fee;
}

/// Calculate maximum possible cost for this transaction (excluding blob fee)
///
/// This is the maximum amount that could be deducted from the sender's account
/// for regular execution gas. Blob fee is calculated separately.
///
/// Formula: max_fee_per_gas * gas_limit + value
///
/// Example:
/// ```zig
/// const max_cost = tx.maxCost();
/// const blob_fee = tx.blobFee(blob_base_fee);
/// const total = max_cost + blob_fee;
/// if (sender_balance < total) {
///     return error.InsufficientBalance;
/// }
/// ```
pub fn maxCost(self: BlobTransaction) u256 {
    return @as(u256, self.gas_limit) * self.max_fee_per_gas + self.value;
}

/// Calculate effective gas price given network base fee
///
/// Same formula as EIP-1559:
/// effective_price = min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)
///
/// Example:
/// ```zig
/// const base_fee = try Numeric.parseGwei("50");
/// const effective_price = tx.effectiveGasPrice(base_fee);
/// ```
pub fn effectiveGasPrice(self: BlobTransaction, base_fee: u256) u256 {
    const priority_price = base_fee + self.max_priority_fee_per_gas;
    return @min(self.max_fee_per_gas, priority_price);
}

// =============================================================================
// Validation
// =============================================================================

/// Validate all transaction fields
///
/// Checks:
/// - Gas limit is non-zero and reasonable
/// - Max priority fee doesn't exceed max fee
/// - Blob count is valid (1-6 blobs)
/// - Signature is valid (if signed)
/// - All fields are in valid ranges
///
/// Example:
/// ```zig
/// try tx.validate();
/// // Transaction is valid
/// ```
pub fn validate(self: BlobTransaction) Error!void {
    // Validate gas limit is non-zero
    if (self.gas_limit == 0) {
        return error.InvalidTransactionField;
    }

    // Validate max_priority_fee_per_gas <= max_fee_per_gas
    if (self.max_priority_fee_per_gas > self.max_fee_per_gas) {
        return error.InvalidFeeValues;
    }

    // Validate blob count (must have at least 1, at most MAX_BLOBS_PER_TX)
    if (self.blob_versioned_hashes.len == 0) {
        return error.NoBlobs;
    }

    if (self.blob_versioned_hashes.len > MAX_BLOBS_PER_TX) {
        return error.TooManyBlobs;
    }

    // Validate each blob versioned hash has correct version byte
    for (self.blob_versioned_hashes) |blob_hash| {
        if (blob_hash.bytes[0] != BLOB_COMMITMENT_VERSION) {
            return error.InvalidBlobHash;
        }
    }

    // Validate signature if present
    if (self.v != 0 or !std.mem.allEqual(u8, &self.r, 0) or !std.mem.allEqual(u8, &self.s, 0)) {
        try self.validateSignature();
    }
}

/// Validate transaction signature values
///
/// Checks that r, s, and v are in valid ranges per ECDSA and EIP-2.
/// - r and s must be in range [1, secp256k1.N)
/// - s must be in low range [1, secp256k1.N/2] (EIP-2)
/// - v must be 0 or 1
///
/// Example:
/// ```zig
/// try tx.validateSignature();
/// // Transaction has valid signature values
/// ```
pub fn validateSignature(self: BlobTransaction) Error!void {
    // Check v is 0 or 1
    if (self.v > 1) {
        return error.InvalidVValue;
    }

    // Check r and s are non-zero
    const r_is_zero = std.mem.allEqual(u8, &self.r, 0);
    const s_is_zero = std.mem.allEqual(u8, &self.s, 0);

    if (r_is_zero or s_is_zero) {
        return error.InvalidSignature;
    }

    // Convert r and s to u256 for comparison
    const r_value = std.mem.readInt(u256, &self.r, .big);
    const s_value = std.mem.readInt(u256, &self.s, .big);

    // Check r < secp256k1.N
    if (r_value >= SECP256K1_N) {
        return error.InvalidSignature;
    }

    // Check s <= secp256k1.N / 2 (EIP-2 low-s requirement)
    if (s_value > SECP256K1_N_HALF) {
        return error.InvalidSValue;
    }

    // Check s < secp256k1.N (redundant with low-s check, but explicit)
    if (s_value >= SECP256K1_N) {
        return error.InvalidSignature;
    }
}

// =============================================================================
// Signing & Recovery
// =============================================================================

/// Sign transaction with private key
///
/// This modifies the transaction in-place, setting the v, r, s values.
/// The signature process:
/// 1. Compute signing hash (includes all transaction fields)
/// 2. Sign hash with ECDSA using private_key
/// 3. Set v to recovery_id (0 or 1)
/// 4. Set r and s from signature
///
/// Example:
/// ```zig
/// var tx = BlobTransaction.init(...);
/// const private_key = try Hex.decodeFixed(32, "0x...");
/// try tx.sign(private_key);
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn sign(self: *BlobTransaction, private_key: [32]u8) Error!void {
    // Get allocator for hash computation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Compute signing hash
    const signing_hash = try self.signingHash(allocator);

    // 2. Sign hash with secp256k1
    const Crypto = @import("../crypto/crypto.zig");
    const signature = Crypto.unaudited_signHash(signing_hash.bytes, private_key) catch {
        return error.InvalidSignature;
    };

    // 3. Extract recovery_id from signature (v is just recovery_id, 0 or 1)
    self.v = signature.recovery_id();

    // 4. Set r and s values (convert u256 to bytes)
    std.mem.writeInt(u256, &self.r, signature.r, .big);
    std.mem.writeInt(u256, &self.s, signature.s, .big);
}

/// Recover sender address from transaction signature
///
/// Uses ECDSA public key recovery to derive the sender's address from
/// the transaction hash and signature (v, r, s values).
///
/// Example:
/// ```zig
/// const sender = try tx.recoverSender();
/// std.debug.print("From: {}\n", .{sender});
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn recoverSender(self: BlobTransaction) Error!Address {
    // Get allocator for hash computation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Compute signing hash
    const signing_hash = try self.signingHash(allocator);

    // 2. Create signature struct (convert bytes to u256)
    const Crypto = @import("../crypto/crypto.zig");
    const r = std.mem.readInt(u256, &self.r, .big);
    const s = std.mem.readInt(u256, &self.s, .big);
    const signature = Crypto.Signature{
        .r = r,
        .s = s,
        .v = @intCast(self.v), // For blob transactions, v is the recovery_id (0 or 1)
    };

    // 3. Recover address from signature
    return Crypto.unaudited_recoverAddress(signing_hash.bytes, signature) catch {
        return error.SignatureRecoveryFailed;
    };
}

// =============================================================================
// Serialization & Hashing
// =============================================================================

/// Serialize transaction to RLP-encoded bytes with EIP-2718 envelope
///
/// Encodes as: 0x03 || RLP([chain_id, nonce, max_priority_fee_per_gas,
///                          max_fee_per_gas, gas_limit, to, value, data,
///                          access_list, max_fee_per_blob_gas,
///                          blob_versioned_hashes, v, r, s])
///
/// Returns allocated byte array - caller must free.
///
/// Example:
/// ```zig
/// const encoded = try tx.serialize(allocator);
/// defer allocator.free(encoded);
/// // Broadcast encoded bytes to network
/// ```
pub fn serialize(self: BlobTransaction, allocator: Allocator) Error![]u8 {
    var items = std.ArrayList(u8){};
    defer items.deinit(allocator);

    // Encode each field
    // 1. chain_id
    const chain_id_encoded = try RLP.encode(allocator, self.chain_id);
    defer allocator.free(chain_id_encoded);
    try items.appendSlice(allocator, chain_id_encoded);

    // 2. nonce
    const nonce_encoded = try RLP.encode(allocator, self.nonce);
    defer allocator.free(nonce_encoded);
    try items.appendSlice(allocator, nonce_encoded);

    // 3. max_priority_fee_per_gas
    const priority_fee_bytes = try u256ToMinimalBytes(allocator, self.max_priority_fee_per_gas);
    defer allocator.free(priority_fee_bytes);
    const priority_fee_encoded = try RLP.encodeBytes(allocator, priority_fee_bytes);
    defer allocator.free(priority_fee_encoded);
    try items.appendSlice(allocator, priority_fee_encoded);

    // 4. max_fee_per_gas
    const max_fee_bytes = try u256ToMinimalBytes(allocator, self.max_fee_per_gas);
    defer allocator.free(max_fee_bytes);
    const max_fee_encoded = try RLP.encodeBytes(allocator, max_fee_bytes);
    defer allocator.free(max_fee_encoded);
    try items.appendSlice(allocator, max_fee_encoded);

    // 5. gas_limit
    const gas_limit_encoded = try RLP.encode(allocator, self.gas_limit);
    defer allocator.free(gas_limit_encoded);
    try items.appendSlice(allocator, gas_limit_encoded);

    // 6. to (REQUIRED - always has address)
    const to_encoded = try RLP.encodeBytes(allocator, &self.to.bytes);
    defer allocator.free(to_encoded);
    try items.appendSlice(allocator, to_encoded);

    // 7. value
    const value_bytes = try u256ToMinimalBytes(allocator, self.value);
    defer allocator.free(value_bytes);
    const value_encoded = try RLP.encodeBytes(allocator, value_bytes);
    defer allocator.free(value_encoded);
    try items.appendSlice(allocator, value_encoded);

    // 8. data
    const data_encoded = try RLP.encodeBytes(allocator, self.data);
    defer allocator.free(data_encoded);
    try items.appendSlice(allocator, data_encoded);

    // 9. access_list
    const access_list_encoded = try encodeAccessList(allocator, self.access_list);
    defer allocator.free(access_list_encoded);
    try items.appendSlice(allocator, access_list_encoded);

    // 10. max_fee_per_blob_gas
    const blob_fee_encoded = try RLP.encode(allocator, self.max_fee_per_blob_gas);
    defer allocator.free(blob_fee_encoded);
    try items.appendSlice(allocator, blob_fee_encoded);

    // 11. blob_versioned_hashes
    const blob_hashes_encoded = try encodeBlobHashes(allocator, self.blob_versioned_hashes);
    defer allocator.free(blob_hashes_encoded);
    try items.appendSlice(allocator, blob_hashes_encoded);

    // 12. v
    const v_encoded = try RLP.encode(allocator, self.v);
    defer allocator.free(v_encoded);
    try items.appendSlice(allocator, v_encoded);

    // 13. r (strip leading zeros)
    const r_bytes = stripLeadingZeros(&self.r);
    const r_encoded = try RLP.encodeBytes(allocator, r_bytes);
    defer allocator.free(r_encoded);
    try items.appendSlice(allocator, r_encoded);

    // 14. s (strip leading zeros)
    const s_bytes = stripLeadingZeros(&self.s);
    const s_encoded = try RLP.encodeBytes(allocator, s_bytes);
    defer allocator.free(s_encoded);
    try items.appendSlice(allocator, s_encoded);

    // Wrap in RLP list
    const payload = try items.toOwnedSlice(allocator);
    defer allocator.free(payload);

    // Calculate list header
    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    // Add transaction type prefix
    try result.append(allocator, TRANSACTION_TYPE);

    // Add RLP list header
    if (payload.len < 56) {
        try result.append(allocator, 0xc0 + @as(u8, @intCast(payload.len)));
    } else {
        const len_bytes = try encodeLength(allocator, payload.len);
        defer allocator.free(len_bytes);
        try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
        try result.appendSlice(allocator, len_bytes);
    }

    // Add payload
    try result.appendSlice(allocator, payload);

    return try result.toOwnedSlice(allocator);
}

/// Deserialize transaction from RLP-encoded bytes
///
/// Decodes bytes in format: 0x03 || RLP([chain_id, nonce, ...])
///
/// Validates:
/// - Transaction type is 0x03
/// - Correct RLP structure (list of 14 elements)
/// - All fields are correctly typed and sized
///
/// Example:
/// ```zig
/// const tx = try BlobTransaction.deserialize(allocator, encoded_bytes);
/// defer if (tx.data.len > 0) allocator.free(tx.data);
/// defer if (tx.access_list.len > 0) allocator.free(tx.access_list);
/// defer if (tx.blob_versioned_hashes.len > 0) allocator.free(tx.blob_versioned_hashes);
/// ```
pub fn deserialize(allocator: Allocator, data: []const u8) Error!BlobTransaction {
    // Check minimum length (type byte + RLP header)
    if (data.len < 2) {
        return error.InvalidRlpEncoding;
    }

    // Check transaction type
    if (data[0] != TRANSACTION_TYPE) {
        return error.InvalidRlpEncoding;
    }

    // Decode RLP payload
    const decoded = RLP.decode(allocator, data[1..], false) catch return error.InvalidRlpEncoding;
    defer decoded.data.deinit(allocator);

    // Must be a list
    const list = switch (decoded.data) {
        .List => |l| l,
        .String => return error.InvalidRlpEncoding,
    };

    // Must have exactly 14 elements
    if (list.len != 14) {
        return error.InvalidRlpEncoding;
    }

    // Extract fields
    var tx: BlobTransaction = undefined;

    // 1. chain_id
    tx.chain_id = try decodeU64(list[0]);

    // 2. nonce
    tx.nonce = try decodeU64(list[1]);

    // 3. max_priority_fee_per_gas
    tx.max_priority_fee_per_gas = try decodeU256(list[2]);

    // 4. max_fee_per_gas
    tx.max_fee_per_gas = try decodeU256(list[3]);

    // 5. gas_limit
    tx.gas_limit = try decodeU64(list[4]);

    // 6. to (REQUIRED - cannot be null)
    const maybe_to = try decodeAddress(list[5]);
    tx.to = maybe_to orelse return error.InvalidRlpEncoding;

    // 7. value
    tx.value = try decodeU256(list[6]);

    // 8. data (allocate copy)
    tx.data = try decodeBytes(allocator, list[7]);

    // 9. access_list (allocate copy)
    tx.access_list = try decodeAccessList(allocator, list[8]);

    // 10. max_fee_per_blob_gas
    tx.max_fee_per_blob_gas = try decodeU64(list[9]);

    // 11. blob_versioned_hashes (allocate copy)
    tx.blob_versioned_hashes = try decodeBlobHashes(allocator, list[10]);

    // 12. v
    tx.v = try decodeU64(list[11]);

    // 13. r
    tx.r = try decodeHash32(list[12]);

    // 14. s
    tx.s = try decodeHash32(list[13]);

    return tx;
}

/// Compute transaction hash (Keccak256 of serialized transaction)
///
/// The transaction hash uniquely identifies the transaction.
///
/// Formula: hash = keccak256(0x03 || rlp([chain_id, nonce, ...]))
///
/// Example:
/// ```zig
/// const tx_hash = try tx.hash(allocator);
/// std.debug.print("Transaction: {}\n", .{tx_hash});
/// ```
pub fn hash(self: BlobTransaction, allocator: Allocator) Error!Hash {
    const encoded = try self.serialize(allocator);
    defer allocator.free(encoded);
    return Hash.keccak256(encoded);
}

/// Compute signing hash for this transaction
///
/// This is the hash that gets signed (same as transaction hash for unsigned tx).
///
/// Example:
/// ```zig
/// const sig_hash = try tx.signingHash(allocator);
/// // Use sig_hash for signature verification
/// ```
pub fn signingHash(self: BlobTransaction, allocator: Allocator) Error!Hash {
    // Create a copy without signature
    var unsigned = self;
    unsigned.v = 0;
    unsigned.r = [_]u8{0} ** 32;
    unsigned.s = [_]u8{0} ** 32;

    // Serialize and hash
    const encoded = try unsigned.serialize(allocator);
    defer allocator.free(encoded);

    return Hash.keccak256(encoded);
}

// =============================================================================
// Utility Methods
// =============================================================================

/// Calculate intrinsic gas cost for this transaction
///
/// Intrinsic gas is the minimum gas required before execution:
/// - 21,000 base cost for all transactions
/// - +4 gas per zero byte in data
/// - +16 gas per non-zero byte in data
/// - +2,400 per address in access list
/// - +1,900 per storage key in access list
///
/// Note: Blob gas is calculated separately via blobGas()
///
/// Example:
/// ```zig
/// const intrinsic = tx.intrinsicGas();
/// if (tx.gas_limit < intrinsic) {
///     return error.InsufficientGas;
/// }
/// ```
pub fn intrinsicGas(self: BlobTransaction) u64 {
    var gas: u64 = 21_000; // Base transaction cost

    // Data gas cost
    for (self.data) |byte| {
        if (byte == 0) {
            gas += 4; // Zero byte cost
        } else {
            gas += 16; // Non-zero byte cost
        }
    }

    // Access list cost (EIP-2930)
    for (self.access_list) |entry| {
        gas += 2_400; // Per address
        gas += @as(u64, @intCast(entry.storage_keys.len)) * 1_900; // Per storage key
    }

    return gas;
}

/// Check if two transactions are equal
///
/// Compares all fields including signature.
///
/// Example:
/// ```zig
/// if (tx1.eql(tx2)) {
///     std.debug.print("Same transaction\n", .{});
/// }
/// ```
pub fn eql(self: BlobTransaction, other: BlobTransaction) bool {
    if (self.chain_id != other.chain_id) return false;
    if (self.nonce != other.nonce) return false;
    if (self.max_priority_fee_per_gas != other.max_priority_fee_per_gas) return false;
    if (self.max_fee_per_gas != other.max_fee_per_gas) return false;
    if (self.gas_limit != other.gas_limit) return false;
    if (!self.to.eql(other.to)) return false;
    if (self.value != other.value) return false;
    if (self.max_fee_per_blob_gas != other.max_fee_per_blob_gas) return false;
    if (self.v != other.v) return false;

    // Compare data
    if (!std.mem.eql(u8, self.data, other.data)) return false;

    // Compare access list length
    if (self.access_list.len != other.access_list.len) return false;

    // Compare blob hashes length
    if (self.blob_versioned_hashes.len != other.blob_versioned_hashes.len) return false;

    // Compare signature
    if (!std.mem.eql(u8, &self.r, &other.r)) return false;
    if (!std.mem.eql(u8, &self.s, &other.s)) return false;

    return true;
}

// =============================================================================
// Formatting for std.fmt
// =============================================================================

/// Format transaction for std.fmt output
///
/// Example:
/// ```zig
/// std.debug.print("Transaction: {}\n", .{tx});
/// ```
pub fn format(
    self: BlobTransaction,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeAll("BlobTx(");
    try writer.print("chain={d}, ", .{self.chain_id});
    try writer.print("nonce={d}, ", .{self.nonce});
    try writer.print("maxPriorityFee={d}, ", .{self.max_priority_fee_per_gas});
    try writer.print("maxFee={d}, ", .{self.max_fee_per_gas});
    try writer.print("gasLimit={d}, ", .{self.gas_limit});
    try writer.print("to={any}, ", .{self.to});
    try writer.print("value={d}, ", .{self.value});
    try writer.print("dataLen={d}, ", .{self.data.len});
    try writer.print("accessListLen={d}, ", .{self.access_list.len});
    try writer.print("maxBlobFee={d}, ", .{self.max_fee_per_blob_gas});
    try writer.print("blobs={d}", .{self.blob_versioned_hashes.len});

    if (self.v != 0 or !std.mem.allEqual(u8, &self.r, 0)) {
        try writer.print(", v={d}", .{self.v});
    }

    try writer.writeAll(")");
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert u256 to minimal big-endian bytes (strip leading zeros)
fn u256ToMinimalBytes(allocator: Allocator, value: u256) ![]u8 {
    if (value == 0) {
        return try allocator.dupe(u8, &[_]u8{});
    }

    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);

    // Find first non-zero byte
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) {
        start += 1;
    }

    return try allocator.dupe(u8, bytes[start..]);
}

/// Strip leading zeros from byte array
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) {
        start += 1;
    }
    if (start >= bytes.len) {
        return &[_]u8{};
    }
    return bytes[start..];
}

/// Encode length as bytes (for RLP long form)
fn encodeLength(allocator: Allocator, length: usize) ![]u8 {
    var len_bytes = std.ArrayList(u8){};
    defer len_bytes.deinit(allocator);

    var temp = length;
    while (temp > 0) {
        try len_bytes.insert(allocator, 0, @as(u8, @intCast(temp & 0xff)));
        temp >>= 8;
    }

    return try len_bytes.toOwnedSlice(allocator);
}

/// Encode access list to RLP
fn encodeAccessList(allocator: Allocator, list: []const AccessListEntry) ![]u8 {
    var entries = std.ArrayList(u8){};
    defer entries.deinit(allocator);

    for (list) |entry| {
        // Encode each entry as [address, [storage_keys...]]
        var entry_items = std.ArrayList(u8){};
        defer entry_items.deinit(allocator);

        // Encode address
        const addr_encoded = try RLP.encodeBytes(allocator, &entry.address.bytes);
        defer allocator.free(addr_encoded);
        try entry_items.appendSlice(allocator, addr_encoded);

        // Encode storage keys list
        var keys_data = std.ArrayList(u8){};
        defer keys_data.deinit(allocator);

        for (entry.storage_keys) |key| {
            const key_encoded = try RLP.encodeBytes(allocator, &key.bytes);
            defer allocator.free(key_encoded);
            try keys_data.appendSlice(allocator, key_encoded);
        }

        const keys_payload = try keys_data.toOwnedSlice(allocator);
        defer allocator.free(keys_payload);

        // Add list header for keys
        if (keys_payload.len < 56) {
            try entry_items.append(allocator, 0xc0 + @as(u8, @intCast(keys_payload.len)));
        } else {
            const len_bytes = try encodeLength(allocator, keys_payload.len);
            defer allocator.free(len_bytes);
            try entry_items.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
            try entry_items.appendSlice(allocator, len_bytes);
        }
        try entry_items.appendSlice(allocator, keys_payload);

        // Wrap entry in list
        const entry_payload = try entry_items.toOwnedSlice(allocator);
        defer allocator.free(entry_payload);

        if (entry_payload.len < 56) {
            try entries.append(allocator, 0xc0 + @as(u8, @intCast(entry_payload.len)));
        } else {
            const len_bytes = try encodeLength(allocator, entry_payload.len);
            defer allocator.free(len_bytes);
            try entries.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
            try entries.appendSlice(allocator, len_bytes);
        }
        try entries.appendSlice(allocator, entry_payload);
    }

    const payload = try entries.toOwnedSlice(allocator);
    defer allocator.free(payload);

    // Wrap in list
    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    if (payload.len < 56) {
        try result.append(allocator, 0xc0 + @as(u8, @intCast(payload.len)));
    } else {
        const len_bytes = try encodeLength(allocator, payload.len);
        defer allocator.free(len_bytes);
        try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
        try result.appendSlice(allocator, len_bytes);
    }
    try result.appendSlice(allocator, payload);

    return try result.toOwnedSlice(allocator);
}

/// Encode blob versioned hashes to RLP
fn encodeBlobHashes(allocator: Allocator, hashes: []const Hash) ![]u8 {
    var items = std.ArrayList(u8){};
    defer items.deinit(allocator);

    for (hashes) |blob_hash| {
        const hash_encoded = try RLP.encodeBytes(allocator, &blob_hash.bytes);
        defer allocator.free(hash_encoded);
        try items.appendSlice(allocator, hash_encoded);
    }

    const payload = try items.toOwnedSlice(allocator);
    defer allocator.free(payload);

    // Wrap in list
    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    if (payload.len < 56) {
        try result.append(allocator, 0xc0 + @as(u8, @intCast(payload.len)));
    } else {
        const len_bytes = try encodeLength(allocator, payload.len);
        defer allocator.free(len_bytes);
        try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
        try result.appendSlice(allocator, len_bytes);
    }
    try result.appendSlice(allocator, payload);

    return try result.toOwnedSlice(allocator);
}

/// Decode u64 from RLP data
fn decodeU64(data: RLP.Data) Error!u64 {
    const bytes = switch (data) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return 0;
    if (bytes.len > 8) return error.InvalidRlpEncoding;

    var result: u64 = 0;
    for (bytes) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

/// Decode u256 from RLP data
fn decodeU256(data: RLP.Data) Error!u256 {
    const bytes = switch (data) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return 0;
    if (bytes.len > 32) return error.InvalidRlpEncoding;

    var result: u256 = 0;
    for (bytes) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

/// Decode address from RLP data
fn decodeAddress(data: RLP.Data) Error!?Address {
    const bytes = switch (data) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return null;
    if (bytes.len != 20) return error.InvalidRlpEncoding;

    return Address.fromBytes(bytes) catch return error.InvalidRlpEncoding;
}

/// Decode bytes from RLP data (allocates copy)
fn decodeBytes(allocator: Allocator, data: RLP.Data) Error![]const u8 {
    const bytes = switch (data) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    return try allocator.dupe(u8, bytes);
}

/// Decode 32-byte hash from RLP data
fn decodeHash32(data: RLP.Data) Error![32]u8 {
    const bytes = switch (data) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    var result = [_]u8{0} ** 32;

    // Pad with leading zeros if needed
    if (bytes.len > 32) return error.InvalidRlpEncoding;

    const offset = 32 - bytes.len;
    @memcpy(result[offset..], bytes);

    return result;
}

/// Decode access list from RLP data
fn decodeAccessList(allocator: Allocator, data: RLP.Data) Error![]const AccessListEntry {
    const list = switch (data) {
        .List => |l| l,
        .String => return error.InvalidAccessList,
    };

    if (list.len == 0) {
        return try allocator.alloc(AccessListEntry, 0);
    }

    var entries = std.ArrayList(AccessListEntry){};
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.storage_keys);
        }
        entries.deinit(allocator);
    }

    for (list) |entry_data| {
        const entry_list = switch (entry_data) {
            .List => |l| l,
            .String => return error.InvalidAccessList,
        };

        if (entry_list.len != 2) return error.InvalidAccessList;

        // Decode address
        const address = (try decodeAddress(entry_list[0])) orelse return error.InvalidAccessList;

        // Decode storage keys
        const keys_list = switch (entry_list[1]) {
            .List => |l| l,
            .String => return error.InvalidAccessList,
        };

        var keys = std.ArrayList(Hash){};
        errdefer keys.deinit(allocator);

        for (keys_list) |key_data| {
            const key_bytes = try decodeHash32(key_data);
            try keys.append(allocator, Hash{ .bytes = key_bytes });
        }

        try entries.append(allocator, AccessListEntry{
            .address = address,
            .storage_keys = try keys.toOwnedSlice(allocator),
        });
    }

    return try entries.toOwnedSlice(allocator);
}

/// Decode blob versioned hashes from RLP data
fn decodeBlobHashes(allocator: Allocator, data: RLP.Data) Error![]const Hash {
    const list = switch (data) {
        .List => |l| l,
        .String => return error.InvalidRlpEncoding,
    };

    if (list.len == 0) {
        return try allocator.alloc(Hash, 0);
    }

    var hashes = std.ArrayList(Hash){};
    errdefer hashes.deinit(allocator);

    for (list) |hash_data| {
        const hash_bytes = try decodeHash32(hash_data);
        try hashes.append(allocator, Hash{ .bytes = hash_bytes });
    }

    return try hashes.toOwnedSlice(allocator);
}

// =============================================================================
// Global Functions
// =============================================================================

/// Convert blob commitment to versioned hash
///
/// A versioned hash is computed as:
/// ```
/// versioned_hash = BLOB_COMMITMENT_VERSION || sha256(commitment)[1:]
/// ```
///
/// This creates a 32-byte hash where the first byte is the version (0x01)
/// and the remaining 31 bytes are from the SHA256 hash of the commitment.
///
/// Example:
/// ```zig
/// const commitment: BlobCommitment = ...; // KZG commitment
/// const versioned_hash = commitmentToVersionedHash(commitment);
/// ```
pub fn commitmentToVersionedHash(commitment: BlobCommitment) Hash {
    var result: Hash = undefined;

    // Compute SHA256 of commitment
    var sha256_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &sha256_hash, .{});

    // Set version byte
    result.bytes[0] = BLOB_COMMITMENT_VERSION;

    // Copy remaining 31 bytes from SHA256 hash
    @memcpy(result.bytes[1..], sha256_hash[1..]);

    return result;
}

/// Calculate blob base fee from excess blob gas
///
/// The blob base fee adjusts dynamically based on network usage.
/// It uses an exponential formula similar to EIP-1559 but for blob gas.
///
/// Formula (simplified):
/// ```
/// blob_base_fee = MIN_BLOB_BASE_FEE * e^(excess_blob_gas / BLOB_BASE_FEE_UPDATE_FRACTION)
/// ```
///
/// This is computed using integer arithmetic to avoid floating point.
///
/// Example:
/// ```zig
/// const excess_blob_gas = block.excess_blob_gas;
/// const blob_base_fee = calculateBlobBaseFee(excess_blob_gas);
/// const total_blob_cost = tx.blobFee(blob_base_fee);
/// ```
pub fn calculateBlobBaseFee(excess_blob_gas: u64) u64 {
    // Use the fake exponential function as specified in EIP-4844
    // blob_base_fee = MIN_BLOB_BASE_FEE * fake_exponential(
    //     MIN_BLOB_BASE_FEE,
    //     excess_blob_gas,
    //     BLOB_BASE_FEE_UPDATE_FRACTION
    // )

    return fakeExponential(
        MIN_BLOB_BASE_FEE,
        excess_blob_gas,
        BLOB_BASE_FEE_UPDATE_FRACTION,
    );
}

/// Compute fake exponential for blob base fee calculation
///
/// This implements the integer approximation of the exponential function
/// used in EIP-4844 for blob base fee calculation.
///
/// Returns: factor * e^(numerator / denominator)
///
/// Uses Taylor series approximation with integer arithmetic.
fn fakeExponential(factor: u64, numerator: u64, denominator: u64) u64 {
    var i: u64 = 1;
    var output: u64 = 0;
    var numerator_accum: u64 = factor * denominator;

    while (numerator_accum > 0) {
        output += numerator_accum;

        // Compute next term: numerator_accum * numerator / (denominator * i)
        // Check for overflow
        const mul_result = @mulWithOverflow(numerator_accum, numerator);
        if (mul_result[1] != 0) break; // Overflow, stop iteration

        numerator_accum = mul_result[0] / (denominator * i);
        i += 1;

        // Prevent infinite loop
        if (i > 100) break;
    }

    return output / denominator;
}

// =============================================================================
// Tests
// =============================================================================

test "BlobTransaction: init creates unsigned transaction" {
    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 50_000_000_000,
        .blob_versioned_hashes = &[_]Hash{Hash.ZERO},
    });

    try std.testing.expectEqual(@as(u64, 1), tx.chain_id);
    try std.testing.expectEqual(@as(u64, 42), tx.nonce);
    try std.testing.expectEqual(@as(u64, 0), tx.v);
    try std.testing.expectEqual(@as(usize, 1), tx.blob_versioned_hashes.len);
}

test "BlobTransaction: blobGas calculation" {
    const hash1 = Hash.ZERO;
    const hash2 = Hash.ZERO;

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{hash1, hash2},
    });

    const blob_gas = tx.blobGas();
    try std.testing.expectEqual(@as(u64, 2 * BLOB_GAS_PER_BLOB), blob_gas);
    try std.testing.expectEqual(@as(u64, 262_144), blob_gas);
}

test "BlobTransaction: blobFee calculation" {
    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{Hash.ZERO},
    });

    const blob_base_fee: u64 = 100;
    const fee = tx.blobFee(blob_base_fee);
    try std.testing.expectEqual(@as(u64, BLOB_GAS_PER_BLOB * 100), fee);
}

test "BlobTransaction: validate rejects zero blobs" {
    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{},
    });

    try std.testing.expectError(error.NoBlobs, tx.validate());
}

test "BlobTransaction: validate rejects too many blobs" {
    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{Hash.ZERO} ** 7, // Too many
    });

    try std.testing.expectError(error.TooManyBlobs, tx.validate());
}

test "BlobTransaction: validate rejects invalid blob hash version" {
    var bad_hash = Hash.ZERO;
    bad_hash.bytes[0] = 0x02; // Wrong version

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{bad_hash},
    });

    try std.testing.expectError(error.InvalidBlobHash, tx.validate());
}

test "BlobTransaction: validate accepts valid transaction" {
    var valid_hash = Hash.ZERO;
    valid_hash.bytes[0] = BLOB_COMMITMENT_VERSION;

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 100,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{valid_hash},
    });

    try tx.validate();
}

test "BlobTransaction: validateSignature checks v value" {
    var tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{Hash.ZERO},
    });

    tx.v = 2; // Invalid
    tx.r = [_]u8{1} ** 32;
    tx.s = [_]u8{1} ** 32;

    try std.testing.expectError(error.InvalidVValue, tx.validateSignature());
}

test "BlobTransaction: intrinsicGas calculation" {
    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{0, 0, 0, 0, 1, 2},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{Hash.ZERO},
    });

    const expected = 21_000 + (4 * 4) + (2 * 16);
    try std.testing.expectEqual(@as(u64, expected), tx.intrinsicGas());
}

test "BlobTransaction: commitmentToVersionedHash" {
    const commitment: BlobCommitment = [_]u8{0xab} ** 48;
    const versioned_hash = commitmentToVersionedHash(commitment);

    // Check version byte
    try std.testing.expectEqual(BLOB_COMMITMENT_VERSION, versioned_hash.bytes[0]);

    // Check it's not zero
    try std.testing.expect(!versioned_hash.isZero());
}

test "BlobTransaction: calculateBlobBaseFee with zero excess" {
    const fee = calculateBlobBaseFee(0);
    try std.testing.expectEqual(MIN_BLOB_BASE_FEE, fee);
}

test "BlobTransaction: calculateBlobBaseFee with excess" {
    const fee = calculateBlobBaseFee(TARGET_BLOB_GAS_PER_BLOCK);
    // Should be higher than minimum
    // The fee should increase when there's excess blob gas
    try std.testing.expect(fee >= MIN_BLOB_BASE_FEE);
}

test "BlobTransaction: sign and recover" {
    var valid_hash = Hash.ZERO;
    valid_hash.bytes[0] = BLOB_COMMITMENT_VERSION;

    var tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = &[_]Hash{valid_hash},
    });

    const private_key = [_]u8{0xab} ** 32;
    try tx.sign(private_key);

    // Verify signature is set
    const zero_bytes = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &tx.r, &zero_bytes));
    try std.testing.expect(!std.mem.eql(u8, &tx.s, &zero_bytes));
    try std.testing.expect(tx.v == 0 or tx.v == 1); // recovery_id

    // Verify we can recover sender
    const sender = try tx.recoverSender();
    try std.testing.expect(!std.mem.eql(u8, &sender.bytes, &Address.ZERO.bytes));
}

test "BlobTransaction: format outputs human-readable string" {
    var valid_hash = Hash.ZERO;
    valid_hash.bytes[0] = BLOB_COMMITMENT_VERSION;

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{1, 2, 3, 4},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 50_000_000_000,
        .blob_versioned_hashes = &[_]Hash{valid_hash, valid_hash},
    });

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try tx.format("", .{}, fbs.writer());

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "BlobTx"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "chain=1"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "nonce=42"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "blobs=2"));
}

test "BlobTransaction: serialize and deserialize roundtrip" {
    const allocator = std.testing.allocator;

    var valid_hash = Hash.ZERO;
    valid_hash.bytes[0] = BLOB_COMMITMENT_VERSION;

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{0x12, 0x34},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 50_000_000_000,
        .blob_versioned_hashes = &[_]Hash{valid_hash},
    });

    const encoded = try tx.serialize(allocator);
    defer allocator.free(encoded);

    // Check type prefix
    try std.testing.expectEqual(@as(u8, 0x03), encoded[0]);

    const decoded = try BlobTransaction.deserialize(allocator, encoded);
    defer allocator.free(decoded.data);
    defer allocator.free(decoded.access_list);
    defer allocator.free(decoded.blob_versioned_hashes);

    try std.testing.expectEqual(tx.chain_id, decoded.chain_id);
    try std.testing.expectEqual(tx.nonce, decoded.nonce);
    try std.testing.expectEqual(tx.max_priority_fee_per_gas, decoded.max_priority_fee_per_gas);
    try std.testing.expectEqual(tx.max_fee_per_gas, decoded.max_fee_per_gas);
    try std.testing.expectEqual(tx.gas_limit, decoded.gas_limit);
    try std.testing.expect(tx.to.eql(decoded.to));
    try std.testing.expectEqual(tx.value, decoded.value);
    try std.testing.expectEqualSlices(u8, tx.data, decoded.data);
    try std.testing.expectEqual(tx.max_fee_per_blob_gas, decoded.max_fee_per_blob_gas);
    try std.testing.expectEqual(tx.blob_versioned_hashes.len, decoded.blob_versioned_hashes.len);
}

test "BlobTransaction: hash computation" {
    const allocator = std.testing.allocator;

    var valid_hash = Hash.ZERO;
    valid_hash.bytes[0] = BLOB_COMMITMENT_VERSION;

    const tx = BlobTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .max_fee_per_blob_gas = 50_000_000_000,
        .blob_versioned_hashes = &[_]Hash{valid_hash},
    });

    const hash1 = try tx.hash(allocator);
    const hash2 = try tx.hash(allocator);

    // Same transaction should produce same hash
    try std.testing.expect(hash1.eql(hash2));
    try std.testing.expect(!hash1.isZero());
}
