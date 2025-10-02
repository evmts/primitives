# secp256k1 Integration Requirements

## Overview

The primitives package has 14 TODO items blocked by the need for secp256k1 ECDSA cryptography support. These are critical for transaction signing and sender recovery functionality.

## Blocked Functionality

### Transaction Signing (8 TODOs)
All transaction types need signing capability:

1. **LegacyTransaction** (`src/transactions/legacy.zig`)
   - `sign()` - Sign transaction with private key
   - `recoverSender()` - Recover sender address from signature

2. **EIP1559Transaction** (`src/transactions/eip1559.zig`)
   - `sign()` - Sign transaction with private key
   - `recoverSender()` - Recover sender address from signature

3. **BlobTransaction** (`src/transactions/blob.zig`)
   - `sign()` - Sign transaction with private key
   - `recoverSender()` - Recover sender address from signature

4. **SetCodeTransaction** (`src/transactions/set_code.zig`)
   - `sign()` - Sign transaction with private key
   - `recoverSender()` - Recover sender address from signature

### Authorization Signing (2 TODOs)
EIP-7702 authorization requires cryptographic operations:

5. **Authorization** (`src/transactions/set_code.zig`)
   - `create()` - Create signed authorization
   - `authority()` - Recover authority address from authorization signature

### Signature Validation (4 TODOs)
Legacy transaction validation needs curve parameters:

6. **LegacyTransaction.validateSignature()** (`src/transactions/legacy.zig`)
   - Check r < secp256k1.N
   - Check s <= secp256k1.N / 2 (EIP-2 low-s requirement)
   - Check v is valid (27, 28, or EIP-155 encoded)
   - Full signature validation implementation

### C FFI (1 TODO blocked)
Transaction C API signing:

7. **primitives_tx_sign()** (`src/root_c.zig`)
   - C wrapper for transaction signing

## Implementation Options

### Option 1: Use zig-secp256k1 Library (Recommended)
- **Pros**: Battle-tested, maintained, full feature set
- **Cons**: External dependency
- **Action**: Add to `build.zig` dependencies

### Option 2: Create C FFI to libsecp256k1
- **Pros**: Use well-known libsecp256k1 C library
- **Cons**: Requires C interop, platform-specific builds
- **Action**: Create Zig bindings, link library

### Option 3: Pure Zig Implementation
- **Pros**: No external dependencies
- **Cons**: Significant effort, security audit needed
- **Action**: Implement from scratch (not recommended)

## Required secp256k1 Operations

### 1. ECDSA Signing
```zig
// Sign a 32-byte hash with a 32-byte private key
// Returns: signature { r: [32]u8, s: [32]u8, recovery_id: u8 }
fn sign(hash: [32]u8, private_key: [32]u8) !Signature
```

### 2. Public Key Recovery
```zig
// Recover public key from hash and signature
// Returns: public_key { x: [32]u8, y: [32]u8 }
fn recover(hash: [32]u8, r: [32]u8, s: [32]u8, recovery_id: u8) !PublicKey
```

### 3. Address Derivation
```zig
// Convert public key to Ethereum address
// Address = keccak256(public_key)[12..32]
fn publicKeyToAddress(pub_key: PublicKey) Address
```

### 4. Curve Constants
```zig
// secp256k1 curve order
const SECP256K1_N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

// Half of curve order (for EIP-2 low-s validation)
const SECP256K1_N_HALF: u256 = SECP256K1_N / 2;
```

## Implementation Steps

### Step 1: Choose Library
- Evaluate zig-secp256k1 library
- Test compatibility with Zig 0.15.1
- Verify ECDSA recovery support

### Step 2: Add Dependency
Update `build.zig`:
```zig
const secp256k1 = b.dependency("secp256k1", .{
    .target = target,
    .optimize = optimize,
});

primitives_module.addImport("secp256k1", secp256k1.module("secp256k1"));
```

### Step 3: Create Wrapper Module
Create `src/crypto/secp256k1.zig`:
```zig
const std = @import("std");
const secp = @import("secp256k1");

pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,
    recovery_id: u8,
};

pub fn sign(hash: [32]u8, private_key: [32]u8) !Signature {
    // Implement using secp256k1 library
}

pub fn recoverPublicKey(hash: [32]u8, sig: Signature) !PublicKey {
    // Implement using secp256k1 library
}

pub fn publicKeyToAddress(pub_key: PublicKey) Address {
    // keccak256(pub_key)[12..32]
}
```

### Step 4: Implement Transaction Methods

For each transaction type, implement:

```zig
pub fn sign(self: *Transaction, private_key: [32]u8) !void {
    const hash = try self.signingHash(allocator);
    const sig = try secp256k1.sign(hash.bytes, private_key);

    self.v = sig.recovery_id;
    self.r = sig.r;
    self.s = sig.s;
}

pub fn recoverSender(self: Transaction) !Address {
    const hash = try self.hash(allocator);
    const sig = .{ .r = self.r, .s = self.s, .recovery_id = self.v };
    const pub_key = try secp256k1.recoverPublicKey(hash.bytes, sig);
    return secp256k1.publicKeyToAddress(pub_key);
}
```

### Step 5: Implement Validation

```zig
pub fn validateSignature(self: Transaction) !void {
    // Check v is valid
    if (self.v > 1) return error.InvalidVValue;

    // Check r and s are non-zero
    if (std.mem.allEqual(u8, &self.r, 0)) return error.InvalidSignature;
    if (std.mem.allEqual(u8, &self.s, 0)) return error.InvalidSignature;

    // Convert to u256 for range checks
    const r_value = std.mem.readInt(u256, &self.r, .big);
    const s_value = std.mem.readInt(u256, &self.s, .big);

    // Check r < SECP256K1_N
    if (r_value >= secp256k1.SECP256K1_N) return error.InvalidSignature;

    // Check s <= SECP256K1_N / 2 (EIP-2 low-s)
    if (s_value > secp256k1.SECP256K1_N_HALF) return error.InvalidSValue;
}
```

### Step 6: Update Tests

Add comprehensive tests for:
- Transaction signing
- Sender recovery
- Signature validation
- Authorization creation/verification

### Step 7: Update C FFI

Implement `primitives_tx_sign()`:
```zig
pub export fn primitives_tx_sign(
    tx: *CTransaction,
    private_key: [*]const u8,
    chain_id: u64,
    error_code: *ErrorCode,
) bool {
    const key_bytes: [32]u8 = private_key[0..32].*;

    switch (tx.tx_type) {
        0 => {
            var tx_ptr: *LegacyTransaction = @ptrFromInt(tx.data_ptr);
            tx_ptr.sign(key_bytes) catch |err| {
                error_code.* = errorToCode(err);
                return false;
            };
        },
        // ... handle other types
        else => {
            error_code.* = .InvalidInput;
            return false;
        },
    }

    error_code.* = .Success;
    return true;
}
```

## Estimated Effort

- **Option 1 (zig-secp256k1)**: 2-3 days
  - 4 hours: dependency setup and testing
  - 8 hours: implement transaction methods
  - 4 hours: implement Authorization methods
  - 4 hours: tests and validation

- **Option 2 (C FFI to libsecp256k1)**: 3-4 days
  - 8 hours: create Zig bindings
  - 8 hours: implement transaction methods
  - 4 hours: platform-specific build config
  - 4 hours: tests

- **Option 3 (Pure Zig)**: 2-3 weeks
  - Not recommended without security audit

## Testing Requirements

### Unit Tests
- Sign/recover roundtrip for each transaction type
- Signature validation edge cases
- EIP-2 low-s enforcement
- EIP-155 chain ID encoding

### Integration Tests
- Sign transactions with known private keys
- Verify against Ethereum test vectors
- Cross-verify with other implementations

### Security Tests
- Invalid signature rejection
- Malformed signature handling
- Curve parameter validation

## Current Workarounds

All affected functions currently return errors:
- `sign()` returns `error.InvalidSignature`
- `recoverSender()` returns `error.SignatureRecoveryFailed`
- `validateSignature()` returns placeholder error
- `Authorization.create()` returns `error.InvalidSignature`
- `Authorization.authority()` returns `error.SignatureRecoveryFailed`

This allows the codebase to compile and all other functionality to work correctly. Transaction signing/recovery will work once secp256k1 is integrated.

## Production Readiness

**Current Status**: ✅ Production-ready for all non-cryptographic operations

**With secp256k1**: ✅ Full production readiness including:
- Transaction signing
- Sender recovery
- Signature validation
- Authorization support

**Recommendation**: Integrate zig-secp256k1 library for complete functionality.
