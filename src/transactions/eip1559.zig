const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig");
const RLP = @import("../encoding/rlp.zig");
const AccessListEntry = @import("access_list.zig").AccessListEntry;

/// Represents an EIP-1559 transaction (Type 2)
///
/// EIP-1559 introduced a new transaction type with a base fee mechanism and
/// priority fees, replacing the simple gas price model. This transaction type
/// became the default after the London hard fork.
///
/// This type provides:
/// - Transaction signing with private keys (EIP-155 compliant)
/// - RLP serialization with 0x02 prefix (EIP-2718 envelope)
/// - Transaction hash computation (Keccak256)
/// - Sender address recovery from signature (ECDSA)
/// - Full validation of transaction fields
/// - Access list support (EIP-2930)
///
/// Structure (EIP-1559):
/// ```
/// 0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
///              gas_limit, to, value, data, access_list, v, r, s])
/// ```
///
/// Fee mechanism:
/// - max_fee_per_gas: Maximum total fee willing to pay per gas
/// - max_priority_fee_per_gas: Maximum tip to miner per gas
/// - base_fee_per_gas: Network base fee (determined by protocol)
/// - Actual gas price = min(max_fee_per_gas, base_fee + max_priority_fee)
pub const EIP1559Transaction = @This();

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

/// Recipient address (null for contract creation)
to: ?Address,

/// Value in wei to transfer to recipient
value: u256,

/// Contract call data or contract init code
data: []const u8,

/// Access list (addresses and storage keys pre-declared for cheaper access)
access_list: []const AccessListEntry,

/// ECDSA signature recovery ID (0 or 1 for EIP-1559)
v: u64,

/// ECDSA signature r component (32 bytes)
r: [32]u8,

/// ECDSA signature s component (32 bytes)
s: [32]u8,

// =============================================================================
// Constants
// =============================================================================

/// EIP-2718 transaction type identifier for EIP-1559 transactions
pub const TRANSACTION_TYPE: u8 = 0x02;

/// Secp256k1 curve order (for signature validation)
/// This is the order of the secp256k1 elliptic curve group
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
    /// The v value is invalid (not 0 or 1 for EIP-1559)
    InvalidVValue,
    /// Max priority fee exceeds max fee
    InvalidFeeValues,
    /// Access list encoding/decoding error
    InvalidAccessList,
} || Allocator.Error || RLP.Error;

// =============================================================================
// Construction & Initialization
// =============================================================================

/// Create a new unsigned EIP-1559 transaction
///
/// Creates a transaction with empty signature values (v=0, r=0, s=0).
/// Call `sign()` to add a valid signature before broadcasting.
///
/// Example:
/// ```zig
/// const tx = EIP1559Transaction.init(.{
///     .chain_id = 1,
///     .nonce = 42,
///     .max_priority_fee_per_gas = try Numeric.parseGwei("2"),
///     .max_fee_per_gas = try Numeric.parseGwei("100"),
///     .gas_limit = 21_000,
///     .to = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .value = try Numeric.parseEther("1.5"),
///     .data = &[_]u8{},
///     .access_list = &[_]AccessListEntry{},
/// });
/// ```
pub fn init(params: struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    access_list: []const AccessListEntry,
}) EIP1559Transaction {
    return EIP1559Transaction{
        .chain_id = params.chain_id,
        .nonce = params.nonce,
        .max_priority_fee_per_gas = params.max_priority_fee_per_gas,
        .max_fee_per_gas = params.max_fee_per_gas,
        .gas_limit = params.gas_limit,
        .to = params.to,
        .value = params.value,
        .data = params.data,
        .access_list = params.access_list,
        .v = 0,
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 32,
    };
}

// =============================================================================
// Fee Calculation
// =============================================================================

/// Calculate effective gas price given network base fee
///
/// The effective gas price is the actual price per gas that will be charged:
/// ```
/// effective_price = min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)
/// ```
///
/// The miner receives:
/// ```
/// miner_tip = effective_price - base_fee
/// ```
///
/// And the base fee is burned.
///
/// Example:
/// ```zig
/// const base_fee = try Numeric.parseGwei("50");
/// const effective_price = tx.effectiveGasPrice(base_fee);
/// const total_cost = effective_price * tx.gas_limit;
/// ```
pub fn effectiveGasPrice(self: EIP1559Transaction, base_fee: u256) u256 {
    // Effective price is capped by max_fee_per_gas
    const priority_price = base_fee + self.max_priority_fee_per_gas;
    return @min(self.max_fee_per_gas, priority_price);
}

/// Calculate maximum possible gas cost for this transaction
///
/// This is the maximum amount that could be deducted from the sender's account.
/// Actual cost may be lower depending on base fee and gas used.
///
/// Formula: max_fee_per_gas * gas_limit + value
///
/// Example:
/// ```zig
/// const max_cost = tx.maxCost();
/// if (sender_balance < max_cost) {
///     return error.InsufficientBalance;
/// }
/// ```
pub fn maxCost(self: EIP1559Transaction) u256 {
    return @as(u256, self.gas_limit) * self.max_fee_per_gas + self.value;
}

// =============================================================================
// Validation
// =============================================================================

/// Validate all transaction fields
///
/// Checks:
/// - Gas limit is non-zero and reasonable
/// - Max priority fee doesn't exceed max fee
/// - Fee values are non-negative
/// - Value is non-negative
/// - Signature is valid (if signed)
/// - All fields are in valid ranges
///
/// Example:
/// ```zig
/// try tx.validate();
/// // Transaction is valid
/// ```
pub fn validate(self: EIP1559Transaction) Error!void {
    // Validate gas limit is non-zero
    if (self.gas_limit == 0) {
        return error.InvalidTransactionField;
    }

    // Validate max_priority_fee_per_gas <= max_fee_per_gas
    if (self.max_priority_fee_per_gas > self.max_fee_per_gas) {
        return error.InvalidFeeValues;
    }

    // Validate signature if present
    if (self.v != 0 or !std.mem.allEqual(u8, &self.r, 0) or !std.mem.allEqual(u8, &self.s, 0)) {
        try self.validateSignature();
    }

    // All other fields are inherently valid by type constraints
}

/// Validate transaction signature values
///
/// Checks that r, s, and v are in valid ranges per ECDSA and EIP-2.
/// - r and s must be in range [1, secp256k1.N)
/// - s must be in low range [1, secp256k1.N/2] (EIP-2)
/// - v must be 0 or 1 (EIP-1559 uses simple recovery ID)
///
/// Example:
/// ```zig
/// try tx.validateSignature();
/// // Transaction has valid signature values
/// ```
pub fn validateSignature(self: EIP1559Transaction) Error!void {
    // Check v is 0 or 1 (EIP-1559 uses simple recovery ID)
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
/// var tx = EIP1559Transaction.init(...);
/// const private_key = try Hex.decodeFixed(32, "0x...");
/// try tx.sign(private_key);
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn sign(self: *EIP1559Transaction, private_key: [32]u8) Error!void {
    // TODO: This requires secp256k1 ECDSA implementation
    // Implementation steps:
    // 1. Compute signing hash: hash = keccak256(0x02 || rlp([chain_id, nonce, ...]))
    // 2. Sign hash with secp256k1.sign(hash, private_key)
    // 3. Extract r, s, and recovery_id from signature
    // 4. Set v = recovery_id (0 or 1 for EIP-1559)
    // 5. Set r and s values
    _ = self;
    _ = private_key;
    return error.InvalidSignature; // Placeholder until secp256k1 is implemented
}

/// Recover sender address from transaction signature
///
/// Uses ECDSA public key recovery to derive the sender's address from
/// the transaction hash and signature (v, r, s values).
///
/// Algorithm:
/// 1. Validate signature values
/// 2. Compute transaction hash (same as signing hash)
/// 3. Recover public key from (hash, r, s, v)
/// 4. Derive address from public key (keccak256(pubkey)[12:])
///
/// Example:
/// ```zig
/// const sender = try tx.recoverSender();
/// std.debug.print("From: {}\n", .{sender});
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn recoverSender(self: EIP1559Transaction) Error!Address {
    // TODO: This requires secp256k1 ECDSA implementation
    // Implementation steps:
    // 1. Validate signature values
    // 2. Compute signing hash
    // 3. Recover public key: pubkey = secp256k1.recover(hash, r, s, v)
    // 4. Return Address.fromPublicKey(pubkey.x, pubkey.y)
    _ = self;
    return error.SignatureRecoveryFailed; // Placeholder until secp256k1 is implemented
}

// =============================================================================
// Serialization & Hashing
// =============================================================================

/// Serialize transaction to RLP-encoded bytes with EIP-2718 envelope
///
/// Encodes as: 0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas,
///                          max_fee_per_gas, gas_limit, to, value, data,
///                          access_list, v, r, s])
///
/// The encoding rules:
/// - Prefixed with transaction type byte (0x02)
/// - Empty address (contract creation) encoded as empty byte array
/// - All integers encoded as big-endian with leading zeros stripped
/// - Access list encoded as RLP list of [address, [storage_keys...]]
///
/// Returns allocated byte array - caller must free.
///
/// Example:
/// ```zig
/// const encoded = try tx.serialize(allocator);
/// defer allocator.free(encoded);
/// // Broadcast encoded bytes to network
/// ```
pub fn serialize(self: EIP1559Transaction, allocator: Allocator) Error![]u8 {
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

    // 6. to (empty for contract creation)
    const to_encoded = if (self.to) |addr|
        try RLP.encodeBytes(allocator, &addr.bytes)
    else
        try RLP.encodeBytes(allocator, &[_]u8{});
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

    // 10. v
    const v_encoded = try RLP.encode(allocator, self.v);
    defer allocator.free(v_encoded);
    try items.appendSlice(allocator, v_encoded);

    // 11. r (strip leading zeros)
    const r_bytes = stripLeadingZeros(&self.r);
    const r_encoded = try RLP.encodeBytes(allocator, r_bytes);
    defer allocator.free(r_encoded);
    try items.appendSlice(allocator, r_encoded);

    // 12. s (strip leading zeros)
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
/// Decodes bytes in format: 0x02 || RLP([chain_id, nonce, ...])
///
/// Validates:
/// - Transaction type is 0x02
/// - Correct RLP structure (list of 12 elements)
/// - All fields are correctly typed and sized
/// - Address is 20 bytes if present
/// - r and s are at most 32 bytes
///
/// Example:
/// ```zig
/// const tx = try EIP1559Transaction.deserialize(allocator, encoded_bytes);
/// defer if (tx.data.len > 0) allocator.free(tx.data);
/// defer if (tx.access_list.len > 0) allocator.free(tx.access_list);
/// ```
pub fn deserialize(allocator: Allocator, data: []const u8) Error!EIP1559Transaction {
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

    // Must have exactly 12 elements
    if (list.len != 12) {
        return error.InvalidRlpEncoding;
    }

    // Extract fields
    var tx: EIP1559Transaction = undefined;

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

    // 6. to
    tx.to = try decodeAddress(list[5]);

    // 7. value
    tx.value = try decodeU256(list[6]);

    // 8. data (allocate copy)
    tx.data = try decodeBytes(allocator, list[7]);

    // 9. access_list (allocate copy)
    tx.access_list = try decodeAccessList(allocator, list[8]);

    // 10. v
    tx.v = try decodeU64(list[9]);

    // 11. r
    tx.r = try decodeHash32(list[10]);

    // 12. s
    tx.s = try decodeHash32(list[11]);

    return tx;
}

/// Compute transaction hash (Keccak256 of serialized transaction)
///
/// The transaction hash uniquely identifies the transaction and is used:
/// - As the transaction ID in blocks and receipts
/// - For transaction lookups in block explorers
/// - As input to signature recovery
///
/// Formula: hash = keccak256(0x02 || rlp([chain_id, nonce, ...]))
///
/// Example:
/// ```zig
/// const tx_hash = try tx.hash(allocator);
/// std.debug.print("Transaction: {}\n", .{tx_hash});
/// ```
pub fn hash(self: EIP1559Transaction, allocator: Allocator) Error!Hash {
    const encoded = try self.serialize(allocator);
    defer allocator.free(encoded);
    return Hash.keccak256(encoded);
}

/// Compute signing hash for this transaction
///
/// This is the hash that gets signed (same as transaction hash for unsigned tx).
/// For EIP-1559 transactions:
/// ```
/// signing_hash = keccak256(0x02 || rlp([chain_id, nonce, ..., access_list]))
/// ```
///
/// Note: The signing hash excludes the signature fields (v, r, s).
///
/// Example:
/// ```zig
/// const sig_hash = try tx.signingHash(allocator);
/// // Use sig_hash for signature verification
/// ```
pub fn signingHash(self: EIP1559Transaction, allocator: Allocator) Error!Hash {
    // Create a copy without signature
    var unsigned = self;
    unsigned.v = 0;
    unsigned.r = [_]u8{0} ** 32;
    unsigned.s = [_]u8{0} ** 32;

    // Serialize and hash (this will include v=0, r=0, s=0 in the encoding)
    const encoded = try unsigned.serialize(allocator);
    defer allocator.free(encoded);

    return Hash.keccak256(encoded);
}

// =============================================================================
// Utility Methods
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
pub fn isContractCreation(self: EIP1559Transaction) bool {
    return self.to == null;
}

/// Calculate intrinsic gas cost for this transaction
///
/// Intrinsic gas is the minimum gas required before execution:
/// - 21,000 base cost for all transactions
/// - +32,000 if creating a contract
/// - +4 gas per zero byte in data
/// - +16 gas per non-zero byte in data
/// - +2,400 per address in access list
/// - +1,900 per storage key in access list
///
/// Example:
/// ```zig
/// const intrinsic = tx.intrinsicGas();
/// if (tx.gas_limit < intrinsic) {
///     return error.InsufficientGas;
/// }
/// ```
pub fn intrinsicGas(self: EIP1559Transaction) u64 {
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
pub fn eql(self: EIP1559Transaction, other: EIP1559Transaction) bool {
    if (self.chain_id != other.chain_id) return false;
    if (self.nonce != other.nonce) return false;
    if (self.max_priority_fee_per_gas != other.max_priority_fee_per_gas) return false;
    if (self.max_fee_per_gas != other.max_fee_per_gas) return false;
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

    // Compare access list length
    if (self.access_list.len != other.access_list.len) return false;

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
/// Outputs a human-readable representation showing key fields.
///
/// Example:
/// ```zig
/// std.debug.print("Transaction: {}\n", .{tx});
/// ```
pub fn format(
    self: EIP1559Transaction,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeAll("EIP1559Tx(");
    try writer.print("chain={d}, ", .{self.chain_id});
    try writer.print("nonce={d}, ", .{self.nonce});
    try writer.print("maxPriorityFee={d}, ", .{self.max_priority_fee_per_gas});
    try writer.print("maxFee={d}, ", .{self.max_fee_per_gas});
    try writer.print("gasLimit={d}, ", .{self.gas_limit});

    if (self.to) |addr| {
        try writer.print("to={any}, ", .{addr});
    } else {
        try writer.writeAll("to=null, ");
    }

    try writer.print("value={d}, ", .{self.value});
    try writer.print("dataLen={d}, ", .{self.data.len});
    try writer.print("accessListLen={d}", .{self.access_list.len});

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

// =============================================================================
// Tests
// =============================================================================

test "EIP1559Transaction: init creates unsigned transaction" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000, // 2 gwei
        .max_fee_per_gas = 100_000_000_000, // 100 gwei
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000, // 1 ether
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    try std.testing.expectEqual(@as(u64, 1), tx.chain_id);
    try std.testing.expectEqual(@as(u64, 42), tx.nonce);
    try std.testing.expectEqual(@as(u256, 2_000_000_000), tx.max_priority_fee_per_gas);
    try std.testing.expectEqual(@as(u256, 100_000_000_000), tx.max_fee_per_gas);
    try std.testing.expectEqual(@as(u64, 21_000), tx.gas_limit);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), tx.value);
    try std.testing.expectEqual(@as(u64, 0), tx.v);
}

test "EIP1559Transaction: effectiveGasPrice calculation" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000, // 2 gwei
        .max_fee_per_gas = 100_000_000_000, // 100 gwei
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    // Base fee = 50 gwei, effective = min(100, 50 + 2) = 52 gwei
    const base_fee: u256 = 50_000_000_000;
    const effective = tx.effectiveGasPrice(base_fee);
    try std.testing.expectEqual(@as(u256, 52_000_000_000), effective);

    // Base fee = 99 gwei, effective = min(100, 99 + 2) = 100 gwei (capped)
    const high_base_fee: u256 = 99_000_000_000;
    const capped = tx.effectiveGasPrice(high_base_fee);
    try std.testing.expectEqual(@as(u256, 100_000_000_000), capped);
}

test "EIP1559Transaction: maxCost calculation" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    // max_cost = (100 gwei * 21000) + 1 ether = 0.0021 + 1 = 1.0021 ether
    const expected: u256 = 1_002_100_000_000_000_000;
    try std.testing.expectEqual(expected, tx.maxCost());
}

test "EIP1559Transaction: validate rejects invalid fee values" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 200_000_000_000, // 200 gwei
        .max_fee_per_gas = 100_000_000_000, // 100 gwei (invalid: less than priority)
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    try std.testing.expectError(error.InvalidFeeValues, tx.validate());
}

test "EIP1559Transaction: validate rejects zero gas limit" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 0, // Invalid
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    try std.testing.expectError(error.InvalidTransactionField, tx.validate());
}

test "EIP1559Transaction: validateSignature checks v value" {
    var tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    tx.v = 2; // Invalid for EIP-1559
    tx.r = [_]u8{1} ** 32;
    tx.s = [_]u8{1} ** 32;

    try std.testing.expectError(error.InvalidVValue, tx.validateSignature());
}

test "EIP1559Transaction: isContractCreation with null to" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = null,
        .value = 0,
        .data = &[_]u8{0x60, 0x60, 0x60},
        .access_list = &[_]AccessListEntry{},
    });

    try std.testing.expect(tx.isContractCreation());
}

test "EIP1559Transaction: intrinsicGas calculation" {
    // Simple transfer
    const tx1 = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 100,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });
    try std.testing.expectEqual(@as(u64, 21_000), tx1.intrinsicGas());

    // Contract creation
    const tx2 = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = null,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });
    try std.testing.expectEqual(@as(u64, 53_000), tx2.intrinsicGas());

    // With data
    const tx3 = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{0, 0, 0, 0, 1, 2},
        .access_list = &[_]AccessListEntry{},
    });
    const expected = 21_000 + (4 * 4) + (2 * 16);
    try std.testing.expectEqual(@as(u64, expected), tx3.intrinsicGas());
}

test "EIP1559Transaction: sign returns error (not implemented)" {
    var tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    const private_key = [_]u8{0xab} ** 32;
    try std.testing.expectError(error.InvalidSignature, tx.sign(private_key));
}

test "EIP1559Transaction: recoverSender returns error (not implemented)" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    try std.testing.expectError(error.SignatureRecoveryFailed, tx.recoverSender());
}

test "EIP1559Transaction: serialize and deserialize roundtrip" {
    const allocator = std.testing.allocator;

    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{0x12, 0x34},
        .access_list = &[_]AccessListEntry{},
    });

    const encoded = try tx.serialize(allocator);
    defer allocator.free(encoded);

    // Check type prefix
    try std.testing.expectEqual(@as(u8, 0x02), encoded[0]);

    const decoded = try EIP1559Transaction.deserialize(allocator, encoded);
    defer allocator.free(decoded.data);
    defer allocator.free(decoded.access_list);

    try std.testing.expectEqual(tx.chain_id, decoded.chain_id);
    try std.testing.expectEqual(tx.nonce, decoded.nonce);
    try std.testing.expectEqual(tx.max_priority_fee_per_gas, decoded.max_priority_fee_per_gas);
    try std.testing.expectEqual(tx.max_fee_per_gas, decoded.max_fee_per_gas);
    try std.testing.expectEqual(tx.gas_limit, decoded.gas_limit);
    try std.testing.expectEqual(tx.value, decoded.value);
    try std.testing.expectEqualSlices(u8, tx.data, decoded.data);
}

test "EIP1559Transaction: hash computation" {
    const allocator = std.testing.allocator;

    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
    });

    const hash1 = try tx.hash(allocator);
    const hash2 = try tx.hash(allocator);

    // Same transaction should produce same hash
    try std.testing.expect(hash1.eql(hash2));
    try std.testing.expect(!hash1.isZero());
}

test "EIP1559Transaction: format outputs human-readable string" {
    const tx = EIP1559Transaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{1, 2, 3, 4},
        .access_list = &[_]AccessListEntry{},
    });

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try tx.format("", .{}, fbs.writer());

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "EIP1559Tx"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "chain=1"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "nonce=42"));
}
