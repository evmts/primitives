# TODO: Missing Features

This document tracks features our primitives package does not yet support.

> **Note**: This comparison is based on a thorough analysis of the codebase. Many features previously thought missing are actually already implemented (e.g., CREATE/CREATE2 contract address calculation, value/unit conversion, hash utilities, RLP, basic ABI encoding/decoding, and all major transaction types).

## ✅ Already Implemented

For reference, here's what we **DO** have:

- ✅ **Address** - Full implementation with CREATE, CREATE2, EIP-55 checksums
- ✅ **Hash** - Keccak256, EIP-191 message hashing, selectors
- ✅ **Hex** - Complete encoding/decoding utilities
- ✅ **Numeric** - Unit conversions (wei, gwei, ether, etc.)
- ✅ **RLP** - Full encoding/decoding
- ✅ **ABI** - Basic parameter encoding/decoding, function selectors, event topics
- ✅ **secp256k1** - Signature recovery, validation, curve operations
- ✅ **Transactions** - Legacy, EIP-1559, EIP-4844 (Blob), EIP-7702 (SetCode)
- ✅ **Access Lists** - Full support
- ✅ **Event Logs** - Basic support

---

## High Priority (Missing)

### Mnemonic & HD Wallet Support

- [ ] **Mnemonic** module

  - [ ] Generate random mnemonic
  - [ ] Validate mnemonic
  - [ ] Convert mnemonic to seed
  - [ ] Convert mnemonic to private key
  - [ ] Convert mnemonic to HD key
  - [ ] Path derivation

- [ ] **HdKey** (Hierarchical Deterministic Keys)
  - [ ] Create from extended key
  - [ ] Create from JSON
  - [ ] Create from seed
  - [ ] Path derivation (BIP-32)

### Typed Data (EIP-712)

- [ ] **TypedData** module
  - [ ] Domain separator calculation
  - [ ] Encode typed data
  - [ ] Hash domain
  - [ ] Hash struct
  - [ ] Generate sign payload
  - [ ] Validate typed data
  - [ ] Extract EIP-712 domain types
  - [ ] Serialize typed data

### Account Abstraction (ERC-4337)

- [ ] **UserOperation** module

  - [ ] Create from/to RPC format
  - [ ] Pack/unpack user operations
  - [ ] Get sign payload
  - [ ] Hash user operation
  - [ ] Convert to typed data
  - [ ] Generate init code

- [ ] **UserOperationGas** module

  - [ ] Convert from/to RPC format

- [ ] **UserOperationReceipt** module

  - [ ] Convert from/to RPC format

- [ ] **EntryPoint** utilities

- [ ] **ValidatorData** module
  - [ ] Encode validator data
  - [ ] Get sign payload

### RPC Infrastructure

- [ ] **Provider** (EIP-1193)

  - [ ] Create provider emitter
  - [ ] Parse provider errors
  - [ ] Provider request/response handling

- [ ] **RpcRequest** module

  - [ ] JSON-RPC 2.0 request formatting
  - [ ] Ethereum JSON-RPC method types

- [ ] **RpcResponse** module

  - [ ] JSON-RPC 2.0 response parsing
  - [ ] Error handling

- [ ] **RpcSchema** module

  - [ ] Type definitions for Ethereum JSON-RPC namespaces

- [ ] **RpcTransport** module
  - [ ] HTTP transport
  - [ ] WebSocket transport
  - [ ] Request/response handling

## Medium Priority

### Additional Cryptographic Algorithms

- [ ] **Bls** (BLS12-381)

  - [ ] Aggregate signatures
  - [ ] Create key pair
  - [ ] Get public key
  - [ ] Sign messages
  - [ ] Verify signatures

- [ ] **BlsPoint** utilities

  - [ ] Convert from/to bytes
  - [ ] Convert from/to hex

- [ ] **Ed25519**

  - [ ] Create key pair
  - [ ] Get public key
  - [ ] Generate random private key
  - [ ] Sign messages
  - [ ] Verify signatures

- [ ] **P256** (secp256r1)

  - [ ] Create key pair
  - [ ] Get public key
  - [ ] Get shared secret (ECDH)
  - [ ] Generate random private key
  - [ ] Recover public key
  - [ ] Sign messages
  - [ ] Verify signatures

- [ ] **X25519**

  - [ ] Create key pair
  - [ ] Get public key
  - [ ] Get shared secret (ECDH)
  - [ ] Generate random private key

- [ ] **WebCryptoP256**

  - [ ] Create key pair
  - [ ] Create ECDH key pair
  - [ ] Get shared secret
  - [ ] Sign messages
  - [ ] Verify signatures

- [ ] **WebAuthnP256**
  - [ ] Browser-based authentication support
  - [ ] Sign with WebAuthn
  - [ ] Verify WebAuthn signatures

### Extended secp256k1 Features

- [ ] Get shared secret (ECDH)
- [ ] DER encoding/decoding for signatures
- [ ] Signature tuple format conversions
- [ ] Signature RPC format conversions
- [ ] Public key compression/decompression utilities

### Keystore Encryption

- [ ] **Keystore** module
  - [ ] Encrypt with PBKDF2
  - [ ] Encrypt with Scrypt
  - [ ] Decrypt keystore
  - [ ] Async variants
  - [ ] Convert to key

### Sign-In with Ethereum (EIP-4361)

- [ ] **Siwe** module
  - [ ] Create SIWE message
  - [ ] Generate nonce
  - [ ] Parse SIWE message
  - [ ] Validate SIWE message
  - [ ] URI validation

### ENS Utilities

- [ ] **Ens** module
  - [ ] Label hash calculation
  - [ ] Name hash calculation
  - [ ] Name normalization

### State Proofs & Merkle Trees

- [ ] **AccountProof** structures

  - [ ] Parse account proofs
  - [ ] Verify account proofs

- [ ] **BinaryStateTree** (EIP-7864)

  - [ ] Create binary state tree
  - [ ] Insert nodes
  - [ ] Merkelize tree

- [ ] **StateOverrides**
  - [ ] Convert from/to RPC format

### Complete Blob Support (EIP-4844)

- [ ] Create blobs from data
- [ ] Convert blobs to/from bytes/hex
- [ ] Generate KZG commitments
- [ ] Generate KZG proofs
- [ ] Construct complete blob sidecars
- [ ] Convert sidecars to versioned hashes

## Lower Priority

### ABI Enhancements

- [ ] **Human-readable ABI parsing** (e.g., `AbiFunction.from("function transfer(address,uint256)")`)
- [ ] **AbiConstructor** encoding/decoding
- [ ] **AbiError** encoding/decoding with selectors
- [ ] **AbiEvent** encoding/decoding with indexed parameters (beyond basic topic hashing)
- [ ] **AbiItem** formatting utilities
- [ ] **AbiParameters.encodePacked** (non-standard packed encoding)
- [ ] ABI type validation and assertions
- [ ] Support for tuples and nested structures in ABI
- [ ] Full ABI JSON parsing (from contract artifacts)

### Encoding Formats

- [ ] **Base58** encoding/decoding

  - [ ] Convert from/to bytes
  - [ ] Convert from/to hex
  - [ ] Convert from/to string

- [ ] **Base64** encoding/decoding
  - [ ] Standard encoding
  - [ ] URL-safe encoding
  - [ ] Padding options

### Advanced Signature Standards

- [ ] **PersonalMessage** (EIP-191)

  - [ ] Encode personal messages
  - [ ] Get sign payload

- [ ] **SignatureErc6492** (Contract Signatures)

  - [ ] Wrap signatures
  - [ ] Unwrap signatures
  - [ ] Validate wrapped signatures
  - [ ] Assert signature format

- [ ] **SignatureErc8010**
  - [ ] Wrap signatures
  - [ ] Unwrap signatures
  - [ ] Validate wrapped signatures
  - [ ] Assert signature format

### Block & Transaction Data Structures

- [ ] **Block** RPC conversions

  - [ ] Convert from RPC format
  - [ ] Convert to RPC format

- [ ] **BlockOverrides** RPC conversions

- [ ] **TransactionReceipt** RPC conversions

- [ ] **TransactionRequest** RPC conversions

- [ ] **Withdrawal** RPC conversions

- [ ] **Log** RPC conversion utilities

- [ ] **Filter** RPC conversions

- [ ] **Fee** utilities for gas calculations

### Bloom Filters

- [ ] **Bloom** module
  - [ ] Check if value is in bloom filter
  - [ ] Validate bloom filter

### Encryption

- [ ] **AesGcm** module
  - [ ] Encrypt data
  - [ ] Decrypt data
  - [ ] Generate keys
  - [ ] Generate random salt

### ERC Standards

- [ ] **Calls** module (ERC-7821)

  - [ ] Encode batch calls
  - [ ] Decode batch calls
  - [ ] Get ABI parameters

- [ ] **Execute** module (ERC-7821)
  - [ ] Encode execute data
  - [ ] Decode execute data
  - [ ] Encode batch of batches
  - [ ] Decode batch of batches

### Data Type Utilities

- [ ] **Bytes** advanced utilities

  - [ ] Concat, pad, trim, slice
  - [ ] Size calculations
  - [ ] Advanced conversions

- [ ] **Hex** advanced utilities

  - [ ] Extended manipulation functions
  - [ ] Additional conversion methods

- [ ] **Json** utilities
  - [ ] Parse with bigint support
  - [ ] Stringify with bigint support

### Hash Functions

- [ ] RIPEMD-160
- [ ] SHA-256 (already available via std.crypto, may need wrapper)

### Transaction Enhancements

- [ ] EIP-2930 transaction type (AccessList transactions)
- [ ] Complete RPC conversion utilities for all transaction types (fromRpc/toRpc)
- [ ] Unified TransactionEnvelope wrapper type
- [ ] Transaction validation helpers beyond basic signing

---

## Notes

- Features are grouped by priority based on common use cases
- High priority features are essential for wallet and dApp development
- Medium priority features expand cryptographic capabilities
- Lower priority features provide advanced utilities and edge case support
- **This is a living document** - as features are implemented, they should be moved to the "Already Implemented" section
