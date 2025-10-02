const std = @import("std");

// Core Types
pub const Address = @import("primitives/address.zig").Address;
pub const Hash = @import("primitives/hash.zig").Hash;
pub const Hex = @import("primitives/hex.zig").Hex;
pub const Numeric = @import("primitives/numeric.zig").Numeric;

// Access List (EIP-2930) - now a primitive
pub const AccessListEntry = @import("primitives/access_list.zig").AccessListEntry;
pub const AccessList = @import("primitives/access_list.zig").AccessList;
pub const ACCESS_LIST_ADDRESS_COST = @import("primitives/access_list.zig").ACCESS_LIST_ADDRESS_COST;
pub const ACCESS_LIST_STORAGE_KEY_COST = @import("primitives/access_list.zig").ACCESS_LIST_STORAGE_KEY_COST;
pub const calculateGas = @import("primitives/access_list.zig").calculateGas;
pub const hasAddress = @import("primitives/access_list.zig").hasAddress;
pub const hasStorageKey = @import("primitives/access_list.zig").hasStorageKey;
pub const deduplicate = @import("primitives/access_list.zig").deduplicate;
pub const serializeAccessList = @import("primitives/access_list.zig").serialize;

// Encoding & Serialization
pub const RLP = @import("encoding/rlp.zig").RLP;
pub const ABI = @import("encoding/abi.zig").ABI;

// Transactions
pub const TransactionType = @import("transactions/transaction_type.zig").TransactionType;
pub const LegacyTransaction = @import("transactions/legacy.zig").LegacyTransaction;
pub const EIP1559Transaction = @import("transactions/eip1559.zig").EIP1559Transaction;
pub const BlobTransaction = @import("transactions/blob.zig").BlobTransaction;
pub const SetCodeTransaction = @import("transactions/set_code.zig").SetCodeTransaction;
pub const Authorization = @import("transactions/set_code.zig").Authorization;

// Access Lists (old location - kept for backward compatibility)
// Note: These now re-export from primitives/access_list.zig
// pub const AccessList = @import("transactions/access_list.zig").AccessList;
// pub const AccessListEntry = @import("transactions/access_list.zig").AccessListEntry;
// pub const ACCESS_LIST_ADDRESS_COST = @import("transactions/access_list.zig").ACCESS_LIST_ADDRESS_COST;
// pub const ACCESS_LIST_STORAGE_KEY_COST = @import("transactions/access_list.zig").ACCESS_LIST_STORAGE_KEY_COST;

// Blob-related types
pub const Blob = @import("transactions/blob.zig").Blob;
pub const BlobCommitment = @import("transactions/blob.zig").BlobCommitment;
pub const BlobProof = @import("transactions/blob.zig").BlobProof;
pub const commitmentToVersionedHash = @import("transactions/blob.zig").commitmentToVersionedHash;
pub const calculateBlobBaseFee = @import("transactions/blob.zig").calculateBlobBaseFee;

// Gas
pub const Gas = @import("gas/constants.zig").Gas;

// Opcodes
pub const Opcode = @import("opcodes/opcode.zig").Opcode;

// EIPs and Hardforks
pub const Hardfork = @import("eips/hardfork.zig").Hardfork;
pub const Eips = @import("eips/eips.zig").Eips;
pub const EipOverride = @import("eips/eips.zig").EipOverride;
pub const SstoreGasCost = @import("eips/eips.zig").SstoreGasCost;

// Logs
pub const EventLog = @import("logs/event_log.zig").EventLog;
pub const filterLogs = @import("logs/event_log.zig").filterLogs;

// State Management
pub const StorageKey = @import("state/storage_key.zig").StorageKey;
pub const EMPTY_CODE_HASH = @import("state/constants.zig").EMPTY_CODE_HASH;
pub const EMPTY_TRIE_ROOT = @import("state/constants.zig").EMPTY_TRIE_ROOT;

// System Contracts
pub const BeaconRootsContract = @import("system_contracts/beacon_roots.zig").BeaconRootsContract;
pub const BEACON_ROOTS_ADDRESS = @import("system_contracts/beacon_roots.zig").BEACON_ROOTS_ADDRESS;
pub const SYSTEM_ADDRESS = @import("system_contracts/beacon_roots.zig").SYSTEM_ADDRESS;
pub const HISTORY_BUFFER_LENGTH = @import("system_contracts/beacon_roots.zig").HISTORY_BUFFER_LENGTH;
pub const BEACON_ROOT_READ_GAS = @import("system_contracts/beacon_roots.zig").BEACON_ROOT_READ_GAS;
pub const BEACON_ROOT_WRITE_GAS = @import("system_contracts/beacon_roots.zig").BEACON_ROOT_WRITE_GAS;
pub const computeSlots = @import("system_contracts/beacon_roots.zig").computeSlots;

test "import all modules" {
    std.testing.refAllDecls(@This());
}

// C API tests
test {
    _ = @import("root_c_test.zig");
}
