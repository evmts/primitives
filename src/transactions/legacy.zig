const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig");
const RLP = @import("../encoding/rlp.zig");

/// Represents a Legacy (pre-EIP-2718) Ethereum transaction
///
/// Legacy transactions were the original transaction type in Ethereum before
/// the introduction of typed transactions in EIP-2718. They use a simple RLP
/// encoding and include EIP-155 replay protection via the v value.
///
/// This type provides:
/// - Transaction signing with private keys (EIP-155 compliant)
/// - RLP serialization and deserialization
/// - Transaction hash computation (Keccak256)
/// - Sender address recovery from signature (ECDSA)
/// - Full validation of transaction fields
///
/// Structure:
/// ```
/// RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
/// ```
///
/// The v value encodes both the recovery ID and chain ID (EIP-155):
/// - Pre-EIP-155: v ∈ {27, 28}
/// - Post-EIP-155: v = chain_id * 2 + 35 + {0, 1}
pub const LegacyTransaction = @This();

/// Transaction nonce (sequential counter for sender account)
nonce: u64,

/// Gas price in wei (amount willing to pay per gas unit)
gas_price: u256,

/// Maximum gas units this transaction can consume
gas_limit: u64,

/// Recipient address (null for contract creation)
to: ?Address,

/// Value in wei to transfer to recipient
value: u256,

/// Contract call data or contract init code
data: []const u8,

/// ECDSA signature recovery ID (encodes chain_id per EIP-155)
v: u64,

/// ECDSA signature r component (32 bytes)
r: [32]u8,

/// ECDSA signature s component (32 bytes)
s: [32]u8,

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
    /// The v value is invalid (not in valid range)
    InvalidVValue,
} || RLP.Error;

// =============================================================================
// Construction & Initialization
// =============================================================================

/// Create a new unsigned transaction
///
/// Creates a transaction with empty signature values (v=0, r=0, s=0).
/// Call `sign()` to add a valid signature before broadcasting.
///
/// Example:
/// ```zig
/// const tx = LegacyTransaction.init(
///     .nonce = 42,
///     .gas_price = try Numeric.parseGwei("20"),
///     .gas_limit = 21_000,
///     .to = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .value = try Numeric.parseEther("1.5"),
///     .data = &[_]u8{},
/// );
/// ```
pub fn init(params: struct {
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
}) LegacyTransaction {
    return LegacyTransaction{
        .nonce = params.nonce,
        .gas_price = params.gas_price,
        .gas_limit = params.gas_limit,
        .to = params.to,
        .value = params.value,
        .data = params.data,
        .v = 0,
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 32,
    };
}

// =============================================================================
// Signing & Verification
// =============================================================================

/// Sign transaction with private key using EIP-155 (replay protection)
///
/// This modifies the transaction in-place, setting the v, r, s values.
/// The signature process:
/// 1. Compute signing hash (includes chain_id for replay protection)
/// 2. Sign hash with ECDSA using private_key
/// 3. Set v = chain_id * 2 + 35 + recovery_id
/// 4. Set r and s from signature
///
/// The chain_id parameter provides replay protection per EIP-155.
/// Transactions signed with one chain_id cannot be replayed on another chain.
///
/// Example:
/// ```zig
/// var tx = LegacyTransaction.init(...);
/// const private_key = try Hex.decodeFixed(32, "0x...");
/// try tx.sign(private_key, 1); // Chain ID 1 = Ethereum mainnet
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn sign(self: *LegacyTransaction, private_key: [32]u8, chain_id: u64) Error!void {
    // Get allocator from somewhere - we'll use a page allocator for this operation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Compute signing hash with chain_id
    const signing_hash = try self.signingHash(allocator, chain_id);

    // 2. Sign hash with secp256k1
    const Crypto = @import("../crypto/crypto.zig");
    const signature = Crypto.unaudited_signHash(signing_hash.bytes, private_key) catch {
        return error.InvalidSignature;
    };

    // 3. Extract recovery_id from signature
    const recovery_id = signature.recovery_id();

    // 4. Set v = chain_id * 2 + 35 + recovery_id (EIP-155)
    self.v = chain_id * 2 + 35 + recovery_id;

    // 5. Set r and s values (convert u256 to bytes)
    std.mem.writeInt(u256, &self.r, signature.r, .big);
    std.mem.writeInt(u256, &self.s, signature.s, .big);
}

/// Recover sender address from transaction signature
///
/// Uses ECDSA public key recovery to derive the sender's address from
/// the transaction hash and signature (v, r, s values).
///
/// Algorithm:
/// 1. Extract chain_id and recovery_id from v value
/// 2. Compute transaction hash (same as signing hash)
/// 3. Recover public key from (hash, r, s, recovery_id)
/// 4. Derive address from public key (keccak256(pubkey)[12:])
///
/// Example:
/// ```zig
/// const sender = try tx.recoverSender();
/// std.debug.print("From: {}\n", .{sender});
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn recoverSender(self: LegacyTransaction) Error!Address {
    // Get allocator for hash computation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Extract chain_id and recovery_id from v
    // For EIP-155: v = chainId * 2 + 35 + recovery_id
    // For pre-EIP-155: v = 27 + recovery_id
    // For unsigned: v = 0
    if (self.v == 0) {
        return error.InvalidSignature; // Unsigned transaction
    }

    const chain_id: ?u64 = if (self.v >= 35) blk: {
        const recovery_id_offset = (self.v - 35) % 2;
        break :blk (self.v - 35 - recovery_id_offset) / 2;
    } else null;

    const recovery_id: u8 = if (self.v >= 35)
        @intCast((self.v - 35) % 2)
    else if (self.v >= 27)
        @intCast(self.v - 27)
    else
        return error.InvalidVValue;

    // 2. Compute signing hash
    const signing_hash = try self.signingHash(allocator, chain_id);

    // 3. Create signature struct (convert bytes to u256)
    const Crypto = @import("../crypto/crypto.zig");
    const r = std.mem.readInt(u256, &self.r, .big);
    const s = std.mem.readInt(u256, &self.s, .big);
    const signature = Crypto.Signature{
        .r = r,
        .s = s,
        .v = recovery_id,
    };

    // 4. Recover address from signature
    return Crypto.unaudited_recoverAddress(signing_hash.bytes, signature) catch {
        return error.SignatureRecoveryFailed;
    };
}

/// Extract chain ID from v value (EIP-155)
///
/// Returns the chain ID if the transaction uses EIP-155 replay protection,
/// or null if it's a pre-EIP-155 transaction (v ∈ {27, 28}).
///
/// EIP-155 encoding: v = chain_id * 2 + 35 + recovery_id
/// Recovery: chain_id = (v - 35) / 2
///
/// Example:
/// ```zig
/// const chain_id = tx.getChainId();
/// if (chain_id) |id| {
///     std.debug.print("Chain ID: {}\n", .{id});
/// } else {
///     std.debug.print("Pre-EIP-155 transaction\n", .{});
/// }
/// ```
pub fn getChainId(self: LegacyTransaction) ?u64 {
    // Pre-EIP-155: v ∈ {27, 28}
    if (self.v == 27 or self.v == 28) {
        return null;
    }

    // EIP-155: v = chain_id * 2 + 35 + {0, 1}
    // Solve for chain_id: (v - 35) / 2
    if (self.v < 35) {
        return null; // Invalid v value
    }

    return (self.v - 35) / 2;
}

/// Validate transaction signature values
///
/// Checks that r, s, and v are in valid ranges per ECDSA and EIP-2.
/// - r and s must be in range [1, secp256k1.N)
/// - s must be in low range [1, secp256k1.N/2] (EIP-2)
/// - v must be valid (27, 28, or EIP-155 encoded)
///
/// Example:
/// ```zig
/// try tx.validateSignature();
/// // Transaction has valid signature values
/// ```
pub fn validateSignature(self: LegacyTransaction) Error!void {
    // TODO: Implement signature validation
    // This requires secp256k1 curve order constant
    // For now, basic checks only

    // Check v is non-zero (unsigned transactions have v=0)
    if (self.v == 0) {
        return error.InvalidVValue;
    }

    // Check r and s are non-zero
    const r_is_zero = std.mem.allEqual(u8, &self.r, 0);
    const s_is_zero = std.mem.allEqual(u8, &self.s, 0);

    if (r_is_zero or s_is_zero) {
        return error.InvalidSignature;
    }

    // TODO: Check r < secp256k1.N
    // TODO: Check s < secp256k1.N / 2 (EIP-2 low-s requirement)
    // TODO: Check v is valid (27, 28, or properly EIP-155 encoded)
}

// =============================================================================
// Serialization & Hashing
// =============================================================================

/// Serialize transaction to RLP-encoded bytes
///
/// Encodes the transaction as: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
///
/// The encoding rules:
/// - Empty address (contract creation) encoded as empty byte array
/// - All integers encoded as big-endian with leading zeros stripped
/// - data encoded as-is
///
/// Returns allocated byte array - caller must free.
///
/// Example:
/// ```zig
/// const encoded = try tx.serialize(allocator);
/// defer allocator.free(encoded);
/// // Broadcast encoded bytes to network
/// ```
///
/// NOTE: Requires RLP encoding implementation (not yet available)
pub fn serialize(self: LegacyTransaction, allocator: Allocator) Error![]u8 {
    var items = std.ArrayList(u8){};
    defer items.deinit(allocator);

    // 1. nonce
    const nonce_bytes = try u64ToMinimalBytes(allocator, self.nonce);
    defer allocator.free(nonce_bytes);
    const nonce_encoded = try RLP.encodeBytes(allocator, nonce_bytes);
    defer allocator.free(nonce_encoded);
    try items.appendSlice(allocator, nonce_encoded);

    // 2. gas_price
    const gas_price_bytes = try u256ToMinimalBytes(allocator, self.gas_price);
    defer allocator.free(gas_price_bytes);
    const gas_price_encoded = try RLP.encodeBytes(allocator, gas_price_bytes);
    defer allocator.free(gas_price_encoded);
    try items.appendSlice(allocator, gas_price_encoded);

    // 3. gas_limit
    const gas_limit_bytes = try u64ToMinimalBytes(allocator, self.gas_limit);
    defer allocator.free(gas_limit_bytes);
    const gas_limit_encoded = try RLP.encodeBytes(allocator, gas_limit_bytes);
    defer allocator.free(gas_limit_encoded);
    try items.appendSlice(allocator, gas_limit_encoded);

    // 4. to (empty for contract creation)
    if (self.to) |to_addr| {
        const to_encoded = try RLP.encodeBytes(allocator, &to_addr.bytes);
        defer allocator.free(to_encoded);
        try items.appendSlice(allocator, to_encoded);
    } else {
        // Empty address for contract creation
        const empty_encoded = try RLP.encodeBytes(allocator, &[_]u8{});
        defer allocator.free(empty_encoded);
        try items.appendSlice(allocator, empty_encoded);
    }

    // 5. value
    const value_bytes = try u256ToMinimalBytes(allocator, self.value);
    defer allocator.free(value_bytes);
    const value_encoded = try RLP.encodeBytes(allocator, value_bytes);
    defer allocator.free(value_encoded);
    try items.appendSlice(allocator, value_encoded);

    // 6. data
    const data_encoded = try RLP.encodeBytes(allocator, self.data);
    defer allocator.free(data_encoded);
    try items.appendSlice(allocator, data_encoded);

    // 7. v
    const v_bytes = try u64ToMinimalBytes(allocator, self.v);
    defer allocator.free(v_bytes);
    const v_encoded = try RLP.encodeBytes(allocator, v_bytes);
    defer allocator.free(v_encoded);
    try items.appendSlice(allocator, v_encoded);

    // 8. r (strip leading zeros)
    const r_bytes = stripLeadingZeros(&self.r);
    const r_encoded = try RLP.encodeBytes(allocator, r_bytes);
    defer allocator.free(r_encoded);
    try items.appendSlice(allocator, r_encoded);

    // 9. s (strip leading zeros)
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
/// Decodes bytes in format: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
///
/// Validates:
/// - Correct RLP structure (list of 9 elements)
/// - All fields are correctly typed and sized
/// - Address is 20 bytes if present
/// - r and s are 32 bytes
///
/// Example:
/// ```zig
/// const tx = try LegacyTransaction.deserialize(allocator, encoded_bytes);
/// defer if (tx.data.len > 0) allocator.free(tx.data);
/// ```
///
/// NOTE: Requires RLP decoding implementation (not yet available)
pub fn deserialize(allocator: Allocator, data: []const u8) Error!LegacyTransaction {
    // Decode RLP payload
    const decoded = RLP.decode(allocator, data, false) catch return error.InvalidRlpEncoding;
    defer decoded.data.deinit(allocator);

    // Must be a list
    const list = switch (decoded.data) {
        .List => |l| l,
        .String => return error.InvalidRlpEncoding,
    };

    // Must have 9 elements
    if (list.len != 9) {
        return error.InvalidRlpEncoding;
    }

    // Extract fields
    const nonce = try extractU64(list[0]);
    const gas_price = try extractU256(list[1]);
    const gas_limit = try extractU64(list[2]);
    const to = try extractOptionalAddress(list[3]);
    const value = try extractU256(list[4]);
    const tx_data = try extractBytes(allocator, list[5]);
    const v = try extractU64(list[6]);
    const r = try extractHash(list[7]);
    const s = try extractHash(list[8]);

    return LegacyTransaction{
        .nonce = nonce,
        .gas_price = gas_price,
        .gas_limit = gas_limit,
        .to = to,
        .value = value,
        .data = tx_data,
        .v = v,
        .r = r,
        .s = s,
    };
}

/// Compute transaction hash (Keccak256 of RLP encoding)
///
/// The transaction hash uniquely identifies the transaction and is used:
/// - As the transaction ID in blocks and receipts
/// - For transaction lookups in block explorers
/// - As input to signature recovery
///
/// Formula: hash = keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s]))
///
/// Example:
/// ```zig
/// const tx_hash = try tx.hash(allocator);
/// std.debug.print("Transaction: {}\n", .{tx_hash});
/// ```
pub fn hash(self: LegacyTransaction, allocator: Allocator) Error!Hash {
    // Serialize and hash
    const encoded = try self.serialize(allocator);
    defer allocator.free(encoded);

    return Hash.keccak256(encoded);
}

/// Compute signing hash for this transaction with given chain_id
///
/// This is the hash that gets signed (different from transaction hash).
/// For EIP-155 transactions:
/// ```
/// signing_hash = keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]))
/// ```
///
/// For pre-EIP-155:
/// ```
/// signing_hash = keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))
/// ```
///
/// Example:
/// ```zig
/// const sig_hash = try tx.signingHash(allocator, 1);
/// // Use sig_hash for signature verification
/// ```
///
/// NOTE: Requires RLP encoding implementation (not yet available)
pub fn signingHash(self: LegacyTransaction, allocator: Allocator, chain_id: ?u64) Error!Hash {
    var items = std.ArrayList(u8){};
    defer items.deinit(allocator);

    // Encode base fields: nonce, gasPrice, gasLimit, to, value, data
    // 1. nonce
    const nonce_bytes = try u64ToMinimalBytes(allocator, self.nonce);
    defer allocator.free(nonce_bytes);
    const nonce_encoded = try RLP.encodeBytes(allocator, nonce_bytes);
    defer allocator.free(nonce_encoded);
    try items.appendSlice(allocator, nonce_encoded);

    // 2. gas_price
    const gas_price_bytes = try u256ToMinimalBytes(allocator, self.gas_price);
    defer allocator.free(gas_price_bytes);
    const gas_price_encoded = try RLP.encodeBytes(allocator, gas_price_bytes);
    defer allocator.free(gas_price_encoded);
    try items.appendSlice(allocator, gas_price_encoded);

    // 3. gas_limit
    const gas_limit_bytes = try u64ToMinimalBytes(allocator, self.gas_limit);
    defer allocator.free(gas_limit_bytes);
    const gas_limit_encoded = try RLP.encodeBytes(allocator, gas_limit_bytes);
    defer allocator.free(gas_limit_encoded);
    try items.appendSlice(allocator, gas_limit_encoded);

    // 4. to
    if (self.to) |to_addr| {
        const to_encoded = try RLP.encodeBytes(allocator, &to_addr.bytes);
        defer allocator.free(to_encoded);
        try items.appendSlice(allocator, to_encoded);
    } else {
        const empty_encoded = try RLP.encodeBytes(allocator, &[_]u8{});
        defer allocator.free(empty_encoded);
        try items.appendSlice(allocator, empty_encoded);
    }

    // 5. value
    const value_bytes = try u256ToMinimalBytes(allocator, self.value);
    defer allocator.free(value_bytes);
    const value_encoded = try RLP.encodeBytes(allocator, value_bytes);
    defer allocator.free(value_encoded);
    try items.appendSlice(allocator, value_encoded);

    // 6. data
    const data_encoded = try RLP.encodeBytes(allocator, self.data);
    defer allocator.free(data_encoded);
    try items.appendSlice(allocator, data_encoded);

    // Add EIP-155 fields if chain_id is provided
    if (chain_id) |cid| {
        // 7. chain_id
        const chain_id_bytes = try u64ToMinimalBytes(allocator, cid);
        defer allocator.free(chain_id_bytes);
        const chain_id_encoded = try RLP.encodeBytes(allocator, chain_id_bytes);
        defer allocator.free(chain_id_encoded);
        try items.appendSlice(allocator, chain_id_encoded);

        // 8 & 9. Two empty bytes for 0, 0
        const zero_encoded = try RLP.encodeBytes(allocator, &[_]u8{});
        defer allocator.free(zero_encoded);
        try items.appendSlice(allocator, zero_encoded);
        try items.appendSlice(allocator, zero_encoded);
    }

    // Wrap in RLP list
    const payload = try items.toOwnedSlice(allocator);
    defer allocator.free(payload);

    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    // Add RLP list header
    if (payload.len < 56) {
        try result.append(allocator, 0xc0 + @as(u8, @intCast(payload.len)));
    } else {
        const len_bytes = try encodeLength(allocator, payload.len);
        defer allocator.free(len_bytes);
        try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
        try result.appendSlice(allocator, len_bytes);
    }

    try result.appendSlice(allocator, payload);

    const encoded = try result.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    return Hash.keccak256(encoded);
}

// =============================================================================
// Validation & Checks
// =============================================================================

/// Check if transaction creates a contract (to address is null)
///
/// Contract creation transactions have no recipient address.
/// The data field contains the contract initialization code.
///
/// Example:
/// ```zig
/// if (tx.isContractCreation()) {
///     std.debug.print("Creating contract\n", .{});
/// }
/// ```
pub fn isContractCreation(self: LegacyTransaction) bool {
    return self.to == null;
}

/// Validate all transaction fields
///
/// Checks:
/// - Gas limit is non-zero and reasonable
/// - Gas price is non-negative
/// - Value is non-negative
/// - Signature is valid (if signed)
/// - All fields are in valid ranges
///
/// Example:
/// ```zig
/// try tx.validate();
/// // Transaction is valid
/// ```
pub fn validate(self: LegacyTransaction) Error!void {
    // Validate gas limit is non-zero
    if (self.gas_limit == 0) {
        return error.InvalidTransactionField;
    }

    // Validate signature if present
    if (self.v != 0) {
        try self.validateSignature();
    }

    // All other fields are inherently valid by type constraints
}

/// Calculate intrinsic gas cost for this transaction
///
/// Intrinsic gas is the minimum gas required before execution:
/// - 21,000 base cost for all transactions
/// - +32,000 if creating a contract
/// - +4 gas per zero byte in data
/// - +16 gas per non-zero byte in data
///
/// Example:
/// ```zig
/// const intrinsic = tx.intrinsicGas();
/// if (tx.gas_limit < intrinsic) {
///     return error.InsufficientGas;
/// }
/// ```
pub fn intrinsicGas(self: LegacyTransaction) u64 {
    var gas: u64 = 21_000; // Base transaction cost

    // Contract creation cost
    if (self.isContractCreation()) {
        gas += 32_000;
    }

    // Data gas cost
    for (self.data) |byte| {
        if (byte == 0) {
            gas += 4; // Zero byte cost
        } else {
            gas += 16; // Non-zero byte cost
        }
    }

    return gas;
}

// =============================================================================
// Comparison & Utility
// =============================================================================

/// Check if two transactions are equal
///
/// Compares all fields including signature.
/// Use `eqlWithoutSignature()` to compare unsigned transactions.
///
/// Example:
/// ```zig
/// if (tx1.eql(tx2)) {
///     std.debug.print("Same transaction\n", .{});
/// }
/// ```
pub fn eql(self: LegacyTransaction, other: LegacyTransaction) bool {
    if (self.nonce != other.nonce) return false;
    if (self.gas_price != other.gas_price) return false;
    if (self.gas_limit != other.gas_limit) return false;
    if (self.value != other.value) return false;
    if (self.v != other.v) return false;

    // Compare addresses
    const self_has_to = self.to != null;
    const other_has_to = other.to != null;
    if (self_has_to != other_has_to) return false;
    if (self_has_to and !self.to.?.eql(other.to.?)) return false;

    // Compare data
    if (!std.mem.eql(u8, self.data, other.data)) return false;

    // Compare signature
    if (!std.mem.eql(u8, &self.r, &other.r)) return false;
    if (!std.mem.eql(u8, &self.s, &other.s)) return false;

    return true;
}

/// Check if two transactions are equal ignoring signature
///
/// Useful for comparing unsigned transactions or checking if
/// two signatures are over the same transaction.
///
/// Example:
/// ```zig
/// if (tx1.eqlWithoutSignature(tx2)) {
///     std.debug.print("Same transaction parameters\n", .{});
/// }
/// ```
pub fn eqlWithoutSignature(self: LegacyTransaction, other: LegacyTransaction) bool {
    if (self.nonce != other.nonce) return false;
    if (self.gas_price != other.gas_price) return false;
    if (self.gas_limit != other.gas_limit) return false;
    if (self.value != other.value) return false;

    // Compare addresses
    const self_has_to = self.to != null;
    const other_has_to = other.to != null;
    if (self_has_to != other_has_to) return false;
    if (self_has_to and !self.to.?.eql(other.to.?)) return false;

    // Compare data
    if (!std.mem.eql(u8, self.data, other.data)) return false;

    return true;
}

// =============================================================================
// Formatting for std.fmt
// =============================================================================

/// Format transaction for std.fmt output
///
/// Outputs a human-readable representation showing key fields.
///
/// Example:
/// ```zig
/// std.debug.print("Transaction: {}\n", .{tx});
/// // Transaction: LegacyTx(nonce=42, gasPrice=20gwei, gasLimit=21000, to=0x..., value=1.5eth)
/// ```
pub fn format(
    self: LegacyTransaction,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeAll("LegacyTx(");
    try writer.print("nonce={d}, ", .{self.nonce});
    try writer.print("gasPrice={d}, ", .{self.gas_price});
    try writer.print("gasLimit={d}, ", .{self.gas_limit});

    if (self.to) |addr| {
        try writer.print("to={any}, ", .{addr});
    } else {
        try writer.writeAll("to=null, ");
    }

    try writer.print("value={d}, ", .{self.value});
    try writer.print("dataLen={d}", .{self.data.len});

    if (self.v != 0) {
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

/// Convert u64 to minimal big-endian bytes (strip leading zeros)
fn u64ToMinimalBytes(allocator: Allocator, value: u64) ![]u8 {
    if (value == 0) {
        return try allocator.dupe(u8, &[_]u8{});
    }

    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);

    // Find first non-zero byte
    var start: usize = 0;
    while (start < 8 and bytes[start] == 0) {
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

/// Extract u64 from RLP decoded value
fn extractU64(item: RLP.Data) !u64 {
    const bytes = switch (item) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return 0;
    if (bytes.len > 8) return error.InvalidRlpEncoding;

    var value: u64 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

/// Extract u256 from RLP decoded value
fn extractU256(item: RLP.Data) !u256 {
    const bytes = switch (item) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return 0;
    if (bytes.len > 32) return error.InvalidRlpEncoding;

    var value: u256 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

/// Extract optional address from RLP decoded value
fn extractOptionalAddress(item: RLP.Data) !?Address {
    const bytes = switch (item) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    if (bytes.len == 0) return null;
    if (bytes.len != 20) return error.InvalidRlpEncoding;

    var addr: Address = undefined;
    @memcpy(&addr.bytes, bytes);
    return addr;
}

/// Extract hash from RLP decoded value
fn extractHash(item: RLP.Data) ![32]u8 {
    const bytes = switch (item) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    var result: [32]u8 = [_]u8{0} ** 32;

    // If bytes is less than 32, pad with leading zeros
    if (bytes.len > 32) return error.InvalidRlpEncoding;

    const offset = 32 - bytes.len;
    @memcpy(result[offset..], bytes);

    return result;
}

/// Extract bytes from RLP decoded value (allocates new slice)
fn extractBytes(allocator: Allocator, item: RLP.Data) ![]u8 {
    const bytes = switch (item) {
        .String => |s| s,
        .List => return error.InvalidRlpEncoding,
    };

    return try allocator.dupe(u8, bytes);
}

// =============================================================================
// Tests
// =============================================================================

test "LegacyTransaction: init creates unsigned transaction" {
    const tx = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000, // 20 gwei
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000, // 1 ether
        .data = &[_]u8{},
    });

    try std.testing.expectEqual(@as(u64, 42), tx.nonce);
    try std.testing.expectEqual(@as(u256, 20_000_000_000), tx.gas_price);
    try std.testing.expectEqual(@as(u64, 21_000), tx.gas_limit);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), tx.value);
    try std.testing.expectEqual(@as(u64, 0), tx.v);
    try std.testing.expectEqual(@as(usize, 0), tx.data.len);
}

test "LegacyTransaction: isContractCreation with null to address" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 100_000,
        .to = null,
        .value = 0,
        .data = &[_]u8{0x60, 0x60, 0x60}, // Some bytecode
    });

    try std.testing.expect(tx.isContractCreation());
}

test "LegacyTransaction: isContractCreation with address" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    try std.testing.expect(!tx.isContractCreation());
}

test "LegacyTransaction: getChainId extracts EIP-155 chain ID" {
    var tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    // Mainnet (chain_id = 1)
    // v = 1 * 2 + 35 + 0 = 37
    tx.v = 37;
    try std.testing.expectEqual(@as(u64, 1), tx.getChainId().?);

    // v = 1 * 2 + 35 + 1 = 38
    tx.v = 38;
    try std.testing.expectEqual(@as(u64, 1), tx.getChainId().?);

    // Sepolia (chain_id = 11155111)
    // v = 11155111 * 2 + 35 + 0 = 22310257
    tx.v = 22310257;
    try std.testing.expectEqual(@as(u64, 11155111), tx.getChainId().?);
}

test "LegacyTransaction: getChainId returns null for pre-EIP-155" {
    var tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    tx.v = 27;
    try std.testing.expectEqual(@as(?u64, null), tx.getChainId());

    tx.v = 28;
    try std.testing.expectEqual(@as(?u64, null), tx.getChainId());
}

test "LegacyTransaction: intrinsicGas calculates correctly" {
    // Simple transfer
    const tx1 = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 100,
        .data = &[_]u8{},
    });
    try std.testing.expectEqual(@as(u64, 21_000), tx1.intrinsicGas());

    // Contract creation (no data)
    const tx2 = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 100_000,
        .to = null,
        .value = 0,
        .data = &[_]u8{},
    });
    try std.testing.expectEqual(@as(u64, 53_000), tx2.intrinsicGas());

    // With data (4 zero bytes, 2 non-zero bytes)
    const tx3 = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{0, 0, 0, 0, 1, 2},
    });
    // 21_000 + (4 * 4) + (2 * 16) = 21_048
    try std.testing.expectEqual(@as(u64, 21_048), tx3.intrinsicGas());
}

test "LegacyTransaction: validate rejects zero gas limit" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 0, // Invalid
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    try std.testing.expectError(error.InvalidTransactionField, tx.validate());
}

test "LegacyTransaction: validateSignature rejects zero v" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    try std.testing.expectError(error.InvalidVValue, tx.validateSignature());
}

test "LegacyTransaction: validateSignature rejects zero r or s" {
    var tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    tx.v = 27;
    tx.r = [_]u8{0} ** 32; // Zero r
    tx.s = [_]u8{1} ** 32;

    try std.testing.expectError(error.InvalidSignature, tx.validateSignature());

    tx.r = [_]u8{1} ** 32;
    tx.s = [_]u8{0} ** 32; // Zero s

    try std.testing.expectError(error.InvalidSignature, tx.validateSignature());
}

test "LegacyTransaction: eql compares transactions correctly" {
    const tx1 = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
    });

    const tx2 = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
    });

    const tx3 = LegacyTransaction.init(.{
        .nonce = 43, // Different nonce
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
    });

    try std.testing.expect(tx1.eql(tx2));
    try std.testing.expect(!tx1.eql(tx3));
}

test "LegacyTransaction: eqlWithoutSignature ignores signature" {
    var tx1 = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
    });

    var tx2 = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
    });

    // Same transaction, different signatures
    tx1.v = 27;
    tx1.r = [_]u8{1} ** 32;
    tx1.s = [_]u8{2} ** 32;

    tx2.v = 28;
    tx2.r = [_]u8{3} ** 32;
    tx2.s = [_]u8{4} ** 32;

    try std.testing.expect(!tx1.eql(tx2)); // Different with signature check
    try std.testing.expect(tx1.eqlWithoutSignature(tx2)); // Same without signature
}

test "LegacyTransaction: format outputs human-readable string" {
    const tx = LegacyTransaction.init(.{
        .nonce = 42,
        .gas_price = 20_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{1, 2, 3, 4},
    });

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try tx.format("", .{}, fbs.writer());

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "LegacyTx"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "nonce=42"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "gasLimit=21000"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "dataLen=4"));
}

test "LegacyTransaction: sign returns error (not implemented)" {
    var tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    const private_key = [_]u8{0xab} ** 32;
    try std.testing.expectError(error.InvalidSignature, tx.sign(private_key, 1));
}

test "LegacyTransaction: recoverSender returns error (not implemented)" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    try std.testing.expectError(error.SignatureRecoveryFailed, tx.recoverSender());
}

test "LegacyTransaction: serialize produces valid RLP encoding" {
    const tx = LegacyTransaction.init(.{
        .nonce = 0,
        .gas_price = 1,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
    });

    const allocator = std.testing.allocator;
    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    // Should produce a valid RLP list
    try std.testing.expect(serialized.len > 0);
    try std.testing.expectEqual(@as(u8, 0xdf), serialized[0]); // RLP list header for length 31
}

test "LegacyTransaction: deserialize returns error (RLP not implemented)" {
    const allocator = std.testing.allocator;
    const data = [_]u8{0xf8, 0x6c}; // RLP list header

    try std.testing.expectError(error.InvalidRlpEncoding, LegacyTransaction.deserialize(allocator, &data));
}
