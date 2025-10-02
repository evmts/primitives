# Why secp256k1 is Required

## What is secp256k1?

**secp256k1** is an elliptic curve used for digital signatures in cryptocurrency systems. It's the cryptographic foundation of:
- Bitcoin
- Ethereum
- Most blockchain systems

## Why Ethereum Needs It

### 1. **Transaction Signing**
Every Ethereum transaction must be **cryptographically signed** to prove:
- **Authenticity**: The transaction came from the claimed sender
- **Authorization**: The sender approves the transaction
- **Integrity**: The transaction hasn't been tampered with

Without secp256k1, you **cannot create valid transactions** that the network will accept.

### 2. **Address Derivation**
Ethereum addresses are derived from secp256k1 **public keys**:

```
Private Key (256 bits)
    ↓ [secp256k1 point multiplication]
Public Key (512 bits: x, y coordinates)
    ↓ [keccak256 hash]
Ethereum Address (last 160 bits)
```

The address is: `0x` + last 20 bytes of `keccak256(public_key)`

### 3. **Signature Verification**
When a transaction arrives on the network, validators must:
1. Extract the signature (`v`, `r`, `s`)
2. Compute the transaction hash
3. **Recover the public key** from hash + signature (using secp256k1)
4. Derive the address from the public key
5. Verify it matches the sender

This entire process requires secp256k1 ECDSA operations.

## The Signature Process

### Creating a Transaction

```zig
// 1. Create unsigned transaction
var tx = LegacyTransaction{
    .nonce = 0,
    .gas_price = 20_000_000_000,
    .gas_limit = 21_000,
    .to = recipient_address,
    .value = 1_000_000_000_000_000_000, // 1 ETH
    .data = &[_]u8{},
    .v = 0,
    .r = [_]u8{0} ** 32,
    .s = [_]u8{0} ** 32,
};

// 2. Compute signing hash
const signing_hash = tx.signingHash(allocator);
// signing_hash = keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))

// 3. Sign with secp256k1 (THIS IS THE MISSING PIECE)
const signature = secp256k1.sign(signing_hash, private_key);
// ↑ Requires elliptic curve cryptography library

// 4. Update transaction with signature
tx.v = signature.recovery_id;
tx.r = signature.r;
tx.s = signature.s;

// 5. Serialize and broadcast
const raw_tx = try tx.serialize(allocator);
// Now this transaction can be sent to the network
```

### Verifying a Transaction

```zig
// 1. Receive transaction from network
const tx = try LegacyTransaction.deserialize(allocator, raw_tx);

// 2. Compute transaction hash
const tx_hash = try tx.hash(allocator);

// 3. Recover sender (THIS IS THE MISSING PIECE)
const public_key = secp256k1.recover(tx_hash, tx.r, tx.s, tx.v);
// ↑ Requires elliptic curve cryptography library

// 4. Derive address from public key
const sender = publicKeyToAddress(public_key);
// sender = last 20 bytes of keccak256(public_key)

// 5. Verify sender has sufficient balance, correct nonce, etc.
```

## What's Missing in This Codebase

### Currently Blocked Functions (14 TODOs)

All transaction types have stubbed signing/recovery methods:

**LegacyTransaction** (`src/transactions/legacy.zig`)
```zig
pub fn sign(self: *LegacyTransaction, private_key: [32]u8, chain_id: u64) !void {
    // TODO: Requires secp256k1
    return error.InvalidSignature;
}

pub fn recoverSender(self: LegacyTransaction) !Address {
    // TODO: Requires secp256k1
    return error.SignatureRecoveryFailed;
}
```

**EIP1559Transaction** (`src/transactions/eip1559.zig`)
```zig
pub fn sign(self: *EIP1559Transaction, private_key: [32]u8) !void {
    // TODO: Requires secp256k1
    return error.InvalidSignature;
}

pub fn recoverSender(self: EIP1559Transaction) !Address {
    // TODO: Requires secp256k1
    return error.SignatureRecoveryFailed;
}
```

Same for **BlobTransaction** and **SetCodeTransaction**.

**Authorization** (EIP-7702, `src/transactions/set_code.zig`)
```zig
pub fn create(chain_id: u64, address: Address, nonce: u64, private_key: [32]u8) !Authorization {
    // TODO: Requires secp256k1
    return error.InvalidSignature;
}

pub fn authority(self: Authorization) !Address {
    // TODO: Requires secp256k1
    return error.SignatureRecoveryFailed;
}
```

### Why These Can't Be Implemented

These operations require:

1. **Elliptic Curve Point Multiplication**
   - Generate public key from private key: `PublicKey = PrivateKey × G` (where G is the generator point)
   - Computationally intensive, requires specialized math

2. **ECDSA Signing**
   - Generate signature `(r, s)` from message hash and private key
   - Requires modular arithmetic on 256-bit numbers
   - Must use secure random number generation

3. **ECDSA Public Key Recovery**
   - Given signature `(r, s, v)` and message hash, recover public key
   - Only possible with secp256k1 curve properties
   - Complex mathematical operations

These are **cryptographic primitives** that require:
- Specialized mathematical libraries
- Constant-time implementations (timing attack prevention)
- Extensive testing and security audits

## What You Can Do Now (Without secp256k1)

✅ **All of these work perfectly:**
- Create transactions with all fields
- Serialize transactions to RLP
- Deserialize transactions from RLP
- Compute transaction hashes
- Validate transaction structure
- Parse addresses and amounts
- Encode/decode ABI data
- Work with all Ethereum primitives

❌ **What doesn't work:**
- Actually **signing** transactions
- **Verifying** signatures
- **Recovering** sender addresses

## What You Need to Add

### Option 1: Use zig-secp256k1 (Recommended)
```zig
// In build.zig
const secp256k1 = b.dependency("secp256k1", .{
    .target = target,
    .optimize = optimize,
});
```

Then implement the 14 TODO functions using the library.

### Option 2: Link to libsecp256k1 (C library)
Use the well-tested Bitcoin Core library via C FFI.

### Option 3: Wait for Pure Zig Implementation
A pure Zig secp256k1 implementation would need to be:
- Mathematically correct
- Timing-attack resistant
- Extensively tested
- Security audited

This is a **multi-month effort** and not recommended.

## Real-World Impact

**Without secp256k1:**
```zig
// You can build transactions
const tx = LegacyTransaction.init(...);

// You can serialize them
const raw = try tx.serialize(allocator);

// But you CANNOT sign them
try tx.sign(private_key); // ❌ Returns error.InvalidSignature

// Network will REJECT unsigned transactions
// No way to prove ownership without cryptographic signature
```

**With secp256k1:**
```zig
// Full transaction lifecycle works
const tx = LegacyTransaction.init(...);
try tx.sign(private_key); // ✅ Creates valid signature
const raw = try tx.serialize(allocator);
// Network accepts and processes transaction ✅
```

## Summary

### secp256k1 is **absolutely required** for:
1. **Creating valid Ethereum transactions** (signing)
2. **Verifying transaction authenticity** (signature verification)
3. **Determining transaction sender** (public key recovery)
4. **Implementing wallet functionality** (key management)

### This library provides **everything else**:
- All Ethereum primitive types ✅
- Transaction structures ✅
- RLP encoding/decoding ✅
- ABI encoding/decoding ✅
- Gas calculations ✅
- State management ✅

### The 14 missing TODOs are **100% blocked** by secp256k1

They're not "unfinished work" - they're **impossible to implement** without elliptic curve cryptography.

**Bottom line**: To have a **fully functional Ethereum primitives library**, you need secp256k1. Without it, you can build and parse transactions, but not sign or verify them.

See `SECP256K1_INTEGRATION.md` for the complete implementation guide.
