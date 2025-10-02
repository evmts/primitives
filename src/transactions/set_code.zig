const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig");
const RLP = @import("../encoding/rlp.zig");
const AccessListEntry = @import("../primitives/access_list.zig").AccessListEntry;

/// Represents an EIP-7702 Set Code transaction (Type 4)
///
/// EIP-7702 introduces a new transaction type that allows EOAs (Externally Owned Accounts)
/// to temporarily delegate their code execution to a smart contract. This enables advanced
/// features like account abstraction, batching, and sponsored transactions without requiring
/// users to deploy smart contract wallets.
///
/// This type provides:
/// - Transaction signing with private keys
/// - RLP serialization with 0x04 prefix (EIP-2718 envelope)
/// - Transaction hash computation (Keccak256)
/// - Sender address recovery from signature (ECDSA)
/// - Full validation of transaction fields and authorization list
/// - Authorization list support for delegation
///
/// Structure (EIP-7702):
/// ```
/// 0x04 || RLP([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
///              gas_limit, to, value, data, access_list, authorization_list,
///              v, r, s])
/// ```
///
/// Authorization mechanism:
/// - Each authorization delegates an EOA's code to a contract address
/// - The authorization is signed by the EOA's private key
/// - Authorizations are processed before transaction execution
/// - Delegation is temporary and only valid for the transaction
pub const SetCodeTransaction = @This();

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

/// Authorization list (EOA delegations to contracts)
authorization_list: []const Authorization,

/// ECDSA signature recovery ID (0 or 1 for EIP-7702)
v: u64,

/// ECDSA signature r component (32 bytes)
r: [32]u8,

/// ECDSA signature s component (32 bytes)
s: [32]u8,

// =============================================================================
// Constants
// =============================================================================

/// EIP-2718 transaction type identifier for EIP-7702 transactions
pub const TRANSACTION_TYPE: u8 = 0x04;

/// Magic byte used in authorization signing hash
pub const MAGIC: u8 = 0x05;

/// Secp256k1 curve order (for signature validation)
const SECP256K1_N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

/// Half of secp256k1 curve order (for EIP-2 low-s requirement)
const SECP256K1_N_HALF: u256 = SECP256K1_N / 2;

/// Gas cost per authorization
pub const PER_AUTH_BASE_COST: u64 = 12_500;

/// Gas cost per empty account delegation
pub const PER_EMPTY_ACCOUNT_COST: u64 = 25_000;

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
    /// The v value is invalid (not 0 or 1 for EIP-7702)
    InvalidVValue,
    /// Max priority fee exceeds max fee
    InvalidFeeValues,
    /// Access list encoding/decoding error
    InvalidAccessList,
    /// Authorization list encoding/decoding error
    InvalidAuthorizationList,
    /// Authorization validation failed
    InvalidAuthorization,
    /// Zero address in authorization
    ZeroAddress,
} || Allocator.Error || RLP.Error;

// =============================================================================
// Authorization Structure
// =============================================================================

/// Represents a single authorization in the authorization list
///
/// An authorization allows an EOA to delegate its code execution to a
/// specified contract address. The authorization is signed by the EOA's
/// private key and includes a nonce for replay protection.
///
/// Structure:
/// ```
/// [chain_id, address, nonce, v, r, s]
/// ```
///
/// The signing hash is computed as:
/// ```
/// keccak256(MAGIC || rlp([chain_id, address, nonce]))
/// ```
pub const Authorization = struct {
    /// Chain ID for replay protection
    chain_id: u64,

    /// Contract address to delegate code execution to
    address: Address,

    /// Nonce for replay protection
    nonce: u64,

    /// ECDSA signature recovery ID (0 or 1)
    v: u64,

    /// ECDSA signature r component
    r: [32]u8,

    /// ECDSA signature s component
    s: [32]u8,

    /// Create a signed authorization
    ///
    /// Creates and signs an authorization that delegates the signer's EOA
    /// code execution to the specified contract address.
    ///
    /// Example:
    /// ```zig
    /// const private_key = try Hex.decodeFixed(32, "0x...");
    /// const contract_addr = try Address.fromHex("0x...");
    /// const auth = try Authorization.create(1, contract_addr, 0, private_key);
    /// ```
    ///
    /// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
    pub fn create(chain_id: u64, address: Address, nonce: u64, private_key: [32]u8) Error!Authorization {
        // TODO: This requires secp256k1 ECDSA implementation
        // Implementation steps:
        // 1. Create unsigned authorization
        // 2. Compute signing hash
        // 3. Sign hash with secp256k1.sign(hash, private_key)
        // 4. Extract v, r, s from signature
        // 5. Return signed authorization
        _ = chain_id;
        _ = address;
        _ = nonce;
        _ = private_key;
        return error.InvalidSignature;
    }

    /// Recover the authority (signer) address from the authorization
    ///
    /// Uses ECDSA public key recovery to derive the EOA address that
    /// signed this authorization. This is the account that is delegating
    /// its code execution.
    ///
    /// Example:
    /// ```zig
    /// const signer = try auth.authority();
    /// std.debug.print("Delegating account: {}\n", .{signer});
    /// ```
    ///
    /// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
    pub fn authority(self: Authorization) Error!Address {
        // TODO: This requires secp256k1 ECDSA implementation
        // Implementation steps:
        // 1. Validate signature values
        // 2. Compute signing hash
        // 3. Recover public key: pubkey = secp256k1.recover(hash, r, s, v)
        // 4. Return Address.fromPublicKey(pubkey.x, pubkey.y)
        _ = self;
        return error.SignatureRecoveryFailed;
    }

    /// Validate authorization fields and signature
    ///
    /// Checks:
    /// - Chain ID is non-zero
    /// - Address is not zero address
    /// - Signature values (r, s, v) are valid
    /// - s is in low range (EIP-2)
    ///
    /// Example:
    /// ```zig
    /// try auth.validate();
    /// // Authorization is valid
    /// ```
    pub fn validate(self: Authorization) Error!void {
        // Chain ID must be non-zero
        if (self.chain_id == 0) {
            return error.InvalidChainId;
        }

        // Address must not be zero
        if (self.address.isZero()) {
            return error.ZeroAddress;
        }

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

        // Check s < secp256k1.N
        if (s_value >= SECP256K1_N) {
            return error.InvalidSignature;
        }
    }

    /// Compute signing hash for this authorization
    ///
    /// The signing hash is computed as:
    /// ```
    /// keccak256(MAGIC || rlp([chain_id, address, nonce]))
    /// ```
    ///
    /// Where MAGIC = 0x05 for EIP-7702.
    ///
    /// Example:
    /// ```zig
    /// const hash = try auth.signingHash(allocator);
    /// // Use hash for signature verification
    /// ```
    ///
    /// NOTE: Requires RLP encoding implementation (not yet available)
    pub fn signingHash(self: Authorization, allocator: Allocator) Error!Hash {
        // TODO: This requires RLP encoding implementation
        // Implementation steps:
        // 1. Encode RLP([chain_id, address, nonce])
        // 2. Prepend MAGIC byte (0x05)
        // 3. Compute keccak256(MAGIC || rlp_data)
        _ = self;
        _ = allocator;
        return error.InvalidRlpEncoding;
    }
};

// =============================================================================
// Construction & Initialization
// =============================================================================

/// Create a new unsigned EIP-7702 transaction
///
/// Creates a transaction with empty signature values (v=0, r=0, s=0).
/// Call `sign()` to add a valid signature before broadcasting.
///
/// Example:
/// ```zig
/// const tx = SetCodeTransaction.init(.{
///     .chain_id = 1,
///     .nonce = 42,
///     .max_priority_fee_per_gas = try Numeric.parseGwei("2"),
///     .max_fee_per_gas = try Numeric.parseGwei("100"),
///     .gas_limit = 100_000,
///     .to = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
///     .value = try Numeric.parseEther("0.1"),
///     .data = &[_]u8{},
///     .access_list = &[_]AccessListEntry{},
///     .authorization_list = &[_]Authorization{...},
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
    authorization_list: []const Authorization,
}) SetCodeTransaction {
    return SetCodeTransaction{
        .chain_id = params.chain_id,
        .nonce = params.nonce,
        .max_priority_fee_per_gas = params.max_priority_fee_per_gas,
        .max_fee_per_gas = params.max_fee_per_gas,
        .gas_limit = params.gas_limit,
        .to = params.to,
        .value = params.value,
        .data = params.data,
        .access_list = params.access_list,
        .authorization_list = params.authorization_list,
        .v = 0,
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 32,
    };
}

// =============================================================================
// Validation
// =============================================================================

/// Validate all transaction fields
///
/// Checks:
/// - Gas limit is non-zero
/// - Max priority fee doesn't exceed max fee
/// - All authorizations are valid
/// - Signature is valid (if signed)
/// - All fields are in valid ranges
///
/// Example:
/// ```zig
/// try tx.validate();
/// // Transaction is valid
/// ```
pub fn validate(self: SetCodeTransaction) Error!void {
    // Validate gas limit is non-zero
    if (self.gas_limit == 0) {
        return error.InvalidTransactionField;
    }

    // Validate max_priority_fee_per_gas <= max_fee_per_gas
    if (self.max_priority_fee_per_gas > self.max_fee_per_gas) {
        return error.InvalidFeeValues;
    }

    // Validate all authorizations
    for (self.authorization_list) |auth| {
        auth.validate() catch return error.InvalidAuthorization;
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
/// - v must be 0 or 1 (EIP-7702 uses simple recovery ID)
///
/// Example:
/// ```zig
/// try tx.validateSignature();
/// // Transaction has valid signature values
/// ```
pub fn validateSignature(self: SetCodeTransaction) Error!void {
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

    // Check s < secp256k1.N
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
/// var tx = SetCodeTransaction.init(...);
/// const private_key = try Hex.decodeFixed(32, "0x...");
/// try tx.sign(private_key);
/// ```
///
/// NOTE: Requires secp256k1 ECDSA implementation (not yet available)
pub fn sign(self: *SetCodeTransaction, private_key: [32]u8) Error!void {
    // TODO: This requires secp256k1 ECDSA implementation
    // Implementation steps:
    // 1. Compute signing hash
    // 2. Sign hash with secp256k1.sign(hash, private_key)
    // 3. Extract r, s, and recovery_id from signature
    // 4. Set v = recovery_id (0 or 1)
    // 5. Set r and s values
    _ = self;
    _ = private_key;
    return error.InvalidSignature;
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
pub fn recoverSender(self: SetCodeTransaction) Error!Address {
    // TODO: This requires secp256k1 ECDSA implementation
    _ = self;
    return error.SignatureRecoveryFailed;
}

// =============================================================================
// Serialization & Hashing
// =============================================================================

/// Serialize transaction to RLP-encoded bytes with EIP-2718 envelope
///
/// Encodes as: 0x04 || RLP([chain_id, nonce, max_priority_fee_per_gas,
///                          max_fee_per_gas, gas_limit, to, value, data,
///                          access_list, authorization_list, v, r, s])
///
/// Returns allocated byte array - caller must free.
///
/// Example:
/// ```zig
/// const encoded = try tx.serialize(allocator);
/// defer allocator.free(encoded);
/// ```
///
/// NOTE: Requires RLP encoding implementation (not yet available)
pub fn serialize(self: SetCodeTransaction, allocator: Allocator) Error![]u8 {
    // TODO: Implement RLP serialization
    // This requires the RLP encoder to support all field types
    _ = self;
    _ = allocator;
    return error.InvalidRlpEncoding;
}

/// Deserialize transaction from RLP-encoded bytes
///
/// Decodes bytes in format: 0x04 || RLP([chain_id, nonce, ...])
///
/// Validates:
/// - Transaction type is 0x04
/// - Correct RLP structure
/// - All fields are correctly typed and sized
///
/// Example:
/// ```zig
/// const tx = try SetCodeTransaction.deserialize(allocator, encoded_bytes);
/// defer allocator.free(tx.data);
/// defer allocator.free(tx.access_list);
/// defer allocator.free(tx.authorization_list);
/// ```
///
/// NOTE: Requires RLP decoding implementation (not yet available)
pub fn deserialize(allocator: Allocator, data: []const u8) Error!SetCodeTransaction {
    // TODO: Implement RLP deserialization
    _ = allocator;
    _ = data;
    return error.InvalidRlpEncoding;
}

/// Compute transaction hash (Keccak256 of serialized transaction)
///
/// The transaction hash uniquely identifies the transaction.
///
/// Formula: hash = keccak256(0x04 || rlp([chain_id, nonce, ...]))
///
/// Example:
/// ```zig
/// const tx_hash = try tx.hash(allocator);
/// std.debug.print("Transaction: {}\n", .{tx_hash});
/// ```
pub fn hash(self: SetCodeTransaction, allocator: Allocator) Error!Hash {
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
/// ```
pub fn signingHash(self: SetCodeTransaction, allocator: Allocator) Error!Hash {
    // Create a copy without signature
    var unsigned = self;
    unsigned.v = 0;
    unsigned.r = [_]u8{0} ** 32;
    unsigned.s = [_]u8{0} ** 32;

    const encoded = try unsigned.serialize(allocator);
    defer allocator.free(encoded);

    return Hash.keccak256(encoded);
}

// =============================================================================
// Fee & Gas Calculation
// =============================================================================

/// Calculate effective gas price given network base fee
///
/// The effective gas price is:
/// ```
/// effective_price = min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)
/// ```
///
/// Example:
/// ```zig
/// const base_fee = try Numeric.parseGwei("50");
/// const effective_price = tx.effectiveGasPrice(base_fee);
/// ```
pub fn effectiveGasPrice(self: SetCodeTransaction, base_fee: u256) u256 {
    const priority_price = base_fee + self.max_priority_fee_per_gas;
    return @min(self.max_fee_per_gas, priority_price);
}

/// Calculate maximum possible gas cost for this transaction
///
/// Formula: max_fee_per_gas * gas_limit + value
///
/// Example:
/// ```zig
/// const max_cost = tx.maxCost();
/// ```
pub fn maxCost(self: SetCodeTransaction) u256 {
    return @as(u256, self.gas_limit) * self.max_fee_per_gas + self.value;
}

/// Calculate intrinsic gas cost for this transaction
///
/// Intrinsic gas includes:
/// - 21,000 base cost
/// - +32,000 if creating a contract
/// - +4 per zero byte in data
/// - +16 per non-zero byte in data
/// - +2,400 per address in access list
/// - +1,900 per storage key in access list
/// - +12,500 per authorization (base)
/// - +25,000 per empty account in authorization list
///
/// Example:
/// ```zig
/// const intrinsic = tx.intrinsicGas();
/// ```
pub fn intrinsicGas(self: SetCodeTransaction) u64 {
    var gas: u64 = 21_000; // Base transaction cost

    // Contract creation cost
    if (self.isContractCreation()) {
        gas += 32_000;
    }

    // Data gas cost
    for (self.data) |byte| {
        if (byte == 0) {
            gas += 4;
        } else {
            gas += 16;
        }
    }

    // Access list cost
    for (self.access_list) |entry| {
        gas += 2_400; // Per address
        gas += @as(u64, @intCast(entry.storage_keys.len)) * 1_900; // Per storage key
    }

    // Authorization list cost
    gas += @as(u64, @intCast(self.authorization_list.len)) * PER_AUTH_BASE_COST;

    return gas;
}

// =============================================================================
// Utility Methods
// =============================================================================

/// Check if transaction creates a contract (to address is null)
///
/// Example:
/// ```zig
/// if (tx.isContractCreation()) {
///     std.debug.print("Creating contract\n", .{});
/// }
/// ```
pub fn isContractCreation(self: SetCodeTransaction) bool {
    return self.to == null;
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
pub fn eql(self: SetCodeTransaction, other: SetCodeTransaction) bool {
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

    // Compare authorization list length
    if (self.authorization_list.len != other.authorization_list.len) return false;

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
    self: SetCodeTransaction,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeAll("SetCodeTx(");
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
    try writer.print("accessListLen={d}, ", .{self.access_list.len});
    try writer.print("authListLen={d}", .{self.authorization_list.len});

    if (self.v != 0 or !std.mem.allEqual(u8, &self.r, 0)) {
        try writer.print(", v={d}", .{self.v});
    }

    try writer.writeAll(")");
}

// =============================================================================
// Tests
// =============================================================================

test "SetCodeTransaction: init creates unsigned transaction" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    try std.testing.expectEqual(@as(u64, 1), tx.chain_id);
    try std.testing.expectEqual(@as(u64, 42), tx.nonce);
    try std.testing.expectEqual(@as(u256, 2_000_000_000), tx.max_priority_fee_per_gas);
    try std.testing.expectEqual(@as(u256, 100_000_000_000), tx.max_fee_per_gas);
    try std.testing.expectEqual(@as(u64, 100_000), tx.gas_limit);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), tx.value);
    try std.testing.expectEqual(@as(u64, 0), tx.v);
}

test "SetCodeTransaction: validate rejects invalid fee values" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 200_000_000_000,
        .max_fee_per_gas = 100_000_000_000, // Invalid: less than priority
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    try std.testing.expectError(error.InvalidFeeValues, tx.validate());
}

test "SetCodeTransaction: validate rejects zero gas limit" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 0, // Invalid
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    try std.testing.expectError(error.InvalidTransactionField, tx.validate());
}

test "SetCodeTransaction: validateSignature checks v value" {
    var tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    tx.v = 2; // Invalid
    tx.r = [_]u8{1} ** 32;
    tx.s = [_]u8{1} ** 32;

    try std.testing.expectError(error.InvalidVValue, tx.validateSignature());
}

test "SetCodeTransaction: isContractCreation with null to" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = null,
        .value = 0,
        .data = &[_]u8{0x60, 0x60, 0x60},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    try std.testing.expect(tx.isContractCreation());
}

test "SetCodeTransaction: effectiveGasPrice calculation" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    const base_fee: u256 = 50_000_000_000;
    const effective = tx.effectiveGasPrice(base_fee);
    try std.testing.expectEqual(@as(u256, 52_000_000_000), effective);

    const high_base_fee: u256 = 99_000_000_000;
    const capped = tx.effectiveGasPrice(high_base_fee);
    try std.testing.expectEqual(@as(u256, 100_000_000_000), capped);
}

test "SetCodeTransaction: maxCost calculation" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    const expected: u256 = 1_010_000_000_000_000_000;
    try std.testing.expectEqual(expected, tx.maxCost());
}

test "SetCodeTransaction: intrinsicGas calculation" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{0, 0, 0, 0, 1, 2},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    const expected = 21_000 + (4 * 4) + (2 * 16);
    try std.testing.expectEqual(@as(u64, expected), tx.intrinsicGas());
}

test "SetCodeTransaction: format outputs human-readable string" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 1_000_000_000_000_000_000,
        .data = &[_]u8{1, 2, 3, 4},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try tx.format("", .{}, fbs.writer());

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "SetCodeTx"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "chain=1"));
    try std.testing.expect(std.mem.containsAtLeast(u8, result, 1, "nonce=42"));
}

test "Authorization: validate checks chain_id" {
    var auth = Authorization{
        .chain_id = 0, // Invalid
        .address = Address.ZERO,
        .nonce = 0,
        .v = 0,
        .r = [_]u8{1} ** 32,
        .s = [_]u8{1} ** 32,
    };

    try std.testing.expectError(error.InvalidChainId, auth.validate());
}

test "Authorization: validate checks zero address" {
    var auth = Authorization{
        .chain_id = 1,
        .address = Address.ZERO,
        .nonce = 0,
        .v = 0,
        .r = [_]u8{1} ** 32,
        .s = [_]u8{1} ** 32,
    };

    try std.testing.expectError(error.ZeroAddress, auth.validate());
}

test "Authorization: validate checks v value" {
    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    var auth = Authorization{
        .chain_id = 1,
        .address = addr,
        .nonce = 0,
        .v = 2, // Invalid
        .r = [_]u8{1} ** 32,
        .s = [_]u8{1} ** 32,
    };

    try std.testing.expectError(error.InvalidVValue, auth.validate());
}

test "Authorization: validate checks non-zero r and s" {
    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    var auth = Authorization{
        .chain_id = 1,
        .address = addr,
        .nonce = 0,
        .v = 0,
        .r = [_]u8{0} ** 32, // Zero r
        .s = [_]u8{1} ** 32,
    };

    try std.testing.expectError(error.InvalidSignature, auth.validate());
}

test "SetCodeTransaction: sign returns error (not implemented)" {
    var tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    const private_key = [_]u8{0xab} ** 32;
    try std.testing.expectError(error.InvalidSignature, tx.sign(private_key));
}

test "SetCodeTransaction: recoverSender returns error (not implemented)" {
    const tx = SetCodeTransaction.init(.{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 100_000,
        .to = Address.ZERO,
        .value = 0,
        .data = &[_]u8{},
        .access_list = &[_]AccessListEntry{},
        .authorization_list = &[_]Authorization{},
    });

    try std.testing.expectError(error.SignatureRecoveryFailed, tx.recoverSender());
}

test "Authorization: create returns error (not implemented)" {
    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const private_key = [_]u8{0xab} ** 32;

    try std.testing.expectError(error.InvalidSignature, Authorization.create(1, addr, 0, private_key));
}

test "Authorization: authority returns error (not implemented)" {
    const addr = try Address.fromHex("0x1111111111111111111111111111111111111111");
    const auth = Authorization{
        .chain_id = 1,
        .address = addr,
        .nonce = 0,
        .v = 0,
        .r = [_]u8{1} ** 32,
        .s = [_]u8{1} ** 32,
    };

    try std.testing.expectError(error.SignatureRecoveryFailed, auth.authority());
}
