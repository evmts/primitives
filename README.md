# Ethereum Primitives (Zig)

Modern, type-safe Zig library providing fundamental Ethereum primitives and utilities. Zero external dependencies, comptime-optimized, and designed for high-performance EVM implementations.

## Design Philosophy

1. **Type Safety** - Distinct types prevent mixing addresses, hashes, and raw bytes
2. **Comptime Everything** - Maximum use of compile-time computation and validation
3. **Zero Allocations** - Stack-first design; heap only when necessary
4. **Explicit Errors** - Comprehensive error types with clear semantics
5. **EIP Compliance** - Strict adherence to Ethereum specifications
6. **Performance** - Optimized for EVM hot paths (addressing, hashing, RLP)

---

## Core Types

### `Address`

20-byte Ethereum addresses with checksum validation and contract address computation.

```zig
pub const Address = struct {
    bytes: [20]u8,

    pub const ZERO: Address = .{ .bytes = [_]u8{0} ** 20 };

    pub fn fromHex(hex: []const u8) !Address;
    pub fn fromBytes(bytes: []const u8) !Address;
    pub fn fromPublicKey(x: u256, y: u256) Address;
    pub fn fromU256(value: u256) Address;

    pub fn isValid(str: []const u8) bool;
    pub fn isValidChecksum(str: []const u8) bool;

    pub fn toHex(self: Address) [42]u8;
    pub fn toChecksum(self: Address) [42]u8;
    pub fn toU256(self: Address) u256;

    pub fn create(deployer: Address, nonce: u64) Address;
    pub fn create2(deployer: Address, salt: [32]u8, init_code_hash: [32]u8) Address;

    pub fn isZero(self: Address) bool;
    pub fn eql(self: Address, other: Address) bool;

    pub fn format(
        self: Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void;
};
```

#### Usage

```zig
const addr = try Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676");

const valid = Address.isValid("0x...");
const valid_checksum = Address.isValidChecksum("0x...");

const hex = addr.toChecksum();
const hex_lower = addr.toHex();

const contract = Address.create(deployer, nonce);
const create2_addr = Address.create2(deployer, salt, init_code_hash);

if (addr.isZero()) { ... }
if (addr.eql(other)) { ... }

const value = addr.toU256();
const addr_from_int = Address.fromU256(value);
```

---

### `Hash`

32-byte cryptographic hashes (Keccak256, transaction hashes, storage keys, etc).

```zig
pub const Hash = struct {
    bytes: [32]u8,

    pub const ZERO: Hash = .{ .bytes = [_]u8{0} ** 32 };
    pub const EMPTY_CODE_HASH: Hash = .{ .bytes = .{
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    } };
    pub const EMPTY_TRIE_ROOT: Hash = .{ .bytes = .{
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
        0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
        0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
        0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
    } };

    pub fn fromHex(hex: []const u8) !Hash;
    pub fn fromBytes(bytes: []const u8) !Hash;
    pub fn keccak256(data: []const u8) Hash;

    pub fn toHex(self: Hash) [66]u8;
    pub fn toU256(self: Hash) u256;

    pub fn eql(self: Hash, other: Hash) bool;

    pub fn format(
        self: Hash,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void;
};
```

#### Usage

```zig
const hash = try Hash.fromHex("0x1234...");
const hash_from_data = Hash.keccak256(data);
const hash_from_bytes = Hash.fromBytes(&bytes);

const hex = hash.toHex();
if (hash.eql(other)) { ... }
const value = hash.toU256();
```

---

### `Hex`

Hexadecimal encoding/decoding utilities with validation.

```zig
pub const Hex = struct {
    pub fn encode(allocator: Allocator, bytes: []const u8) ![]u8;
    pub fn encodeUpper(allocator: Allocator, bytes: []const u8) ![]u8;
    pub fn encodeFixed(comptime N: usize, bytes: [N]u8) [2 + N * 2]u8;

    pub fn decode(allocator: Allocator, hex: []const u8) ![]u8;
    pub fn decodeFixed(comptime N: usize, hex: []const u8) ![N]u8;

    pub fn toU256(hex: []const u8) !u256;
    pub fn toU64(hex: []const u8) !u64;

    pub fn fromU256(allocator: Allocator, value: u256) ![]u8;
    pub fn fromU64(allocator: Allocator, value: u64) ![]u8;

    pub fn isValid(str: []const u8) bool;
    pub fn byteLength(hex: []const u8) usize;

    pub fn padLeft(allocator: Allocator, bytes: []const u8, target_length: usize) ![]u8;
    pub fn padRight(allocator: Allocator, bytes: []const u8, target_length: usize) ![]u8;

    pub fn trimLeft(bytes: []const u8) []const u8;
    pub fn trimRight(bytes: []const u8) []const u8;

    pub fn concat(allocator: Allocator, arrays: []const []const u8) ![]u8;
    pub fn slice(bytes: []const u8, start: usize, end: usize) []const u8;
};
```

#### Usage

```zig
const hex = try Hex.encode(allocator, bytes);
defer allocator.free(hex);

const hex_fixed = Hex.encodeFixed(20, bytes);

const bytes = try Hex.decode(allocator, "0x1234");
defer allocator.free(bytes);

const bytes_fixed = try Hex.decodeFixed(20, "0x1234...");

const value = try Hex.toU256("0x1234");

if (Hex.isValid("0x1234")) { ... }
const len = Hex.byteLength("0x1234");

const padded = try Hex.padLeft(allocator, bytes, 32);
const trimmed = Hex.trimLeft(bytes);
const result = try Hex.concat(allocator, &[_][]const u8{ bytes1, bytes2 });
```

---

### `Numeric`

Ethereum unit conversions and number utilities.

```zig
pub const Numeric = struct {
    pub const WEI: u256 = 1;
    pub const KWEI: u256 = 1_000;
    pub const MWEI: u256 = 1_000_000;
    pub const GWEI: u256 = 1_000_000_000;
    pub const SZABO: u256 = 1_000_000_000_000;
    pub const FINNEY: u256 = 1_000_000_000_000_000;
    pub const ETHER: u256 = 1_000_000_000_000_000_000;

    pub const Unit = enum {
        wei,
        kwei,
        mwei,
        gwei,
        szabo,
        finney,
        ether,

        pub fn toMultiplier(self: Unit) u256;
        pub fn fromString(str: []const u8) ?Unit;
        pub fn toString(self: Unit) []const u8;
    };

    pub fn parseEther(ether_str: []const u8) !u256;
    pub fn parseGwei(gwei_str: []const u8) !u256;
    pub fn parseUnits(value_str: []const u8, unit: Unit) !u256;

    pub fn formatEther(allocator: Allocator, wei_value: u256) ![]u8;
    pub fn formatGwei(allocator: Allocator, wei_value: u256) ![]u8;
    pub fn formatUnits(allocator: Allocator, wei_value: u256, unit: Unit, decimals: ?u8) ![]u8;

    pub fn convertUnits(value: u256, from_unit: Unit, to_unit: Unit) !u256;

    pub fn calculateGasCost(gas_used: u64, gas_price_gwei: u256) u256;
    pub fn formatGasCost(allocator: Allocator, gas_used: u64, gas_price_gwei: u256) ![]u8;
};
```

#### Usage

```zig
const wei = try Numeric.parseEther("1.5");
const wei_gwei = try Numeric.parseGwei("20");
const wei_custom = try Numeric.parseUnits("1.5", .ether);

const str = try Numeric.formatEther(allocator, wei_value);
defer allocator.free(str);

const str_gwei = try Numeric.formatGwei(allocator, wei_value);
defer allocator.free(str_gwei);

const converted = try Numeric.convertUnits(1, .ether, .gwei);

const cost = Numeric.calculateGasCost(gas_used, gas_price_gwei);
```

---

## Encoding & Serialization

### `RLP`

Recursive Length Prefix encoding/decoding.

```zig
pub const RLP = struct {
    pub const Data = union(enum) {
        String: []const u8,
        List: []Data,

        pub fn deinit(self: Data, allocator: Allocator) void;
    };

    pub const Decoded = struct {
        data: Data,
        remainder: []const u8,
    };

    pub fn encode(allocator: Allocator, input: anytype) ![]u8;
    pub fn encodeBytes(allocator: Allocator, bytes: []const u8) ![]u8;
    pub fn encodeList(allocator: Allocator, items: []const []const u8) ![]u8;

    pub fn decode(allocator: Allocator, input: []const u8, stream: bool) !Decoded;

    pub fn encodedLength(input: anytype) usize;
    pub fn isList(data: []const u8) bool;
};
```

#### Usage

```zig
const encoded = try RLP.encode(allocator, "hello");
defer allocator.free(encoded);

const list = [_][]const u8{ "cat", "dog" };
const encoded_list = try RLP.encode(allocator, list);
defer allocator.free(encoded_list);

const decoded = try RLP.decode(allocator, data, false);
defer decoded.data.deinit(allocator);

switch (decoded.data) {
    .String => |s| std.debug.print("String: {s}\n", .{s}),
    .List => |l| std.debug.print("List with {} items\n", .{l.len}),
}

const decoded_stream = try RLP.decode(allocator, data, true);
defer decoded_stream.data.deinit(allocator);
```

---

### `ABI`

Application Binary Interface encoding/decoding for smart contracts.

```zig
pub const ABI = struct {
    pub const Type = enum {
        uint8, uint16, uint32, uint64, uint128, uint256,
        int8, int16, int32, int64, int128, int256,
        address,
        bool,
        bytes1, bytes2, bytes3, bytes4, bytes8, bytes16, bytes32,
        bytes,
        string,
        uint256_array,
        bytes32_array,
        address_array,
        string_array,

        pub fn isDynamic(self: Type) bool;
        pub fn size(self: Type) ?usize;
        pub fn getType(self: Type) []const u8;
    };

    pub const Value = union(Type) {
        uint8: u8,
        uint16: u16,
        uint32: u32,
        uint64: u64,
        uint128: u128,
        uint256: u256,
        int8: i8,
        int16: i16,
        int32: i32,
        int64: i64,
        int128: i128,
        int256: i256,
        address: Address,
        bool: bool,
        bytes1: [1]u8,
        bytes2: [2]u8,
        bytes3: [3]u8,
        bytes4: [4]u8,
        bytes8: [8]u8,
        bytes16: [16]u8,
        bytes32: [32]u8,
        bytes: []const u8,
        string: []const u8,
        uint256_array: []const u256,
        bytes32_array: []const [32]u8,
        address_array: []const Address,
        string_array: []const []const u8,

        pub fn getType(self: Value) Type;
    };

    pub const Selector = [4]u8;

    pub fn computeSelector(signature: []const u8) Selector;
    pub fn createSignature(allocator: Allocator, name: []const u8, types: []const Type) ![]u8;

    pub fn encodeParameters(allocator: Allocator, values: []const Value) ![]u8;
    pub fn decodeParameters(allocator: Allocator, data: []const u8, types: []const Type) ![]Value;

    pub fn encodeFunctionCall(allocator: Allocator, signature: []const u8, values: []const Value) ![]u8;
    pub fn encodeEventTopic(signature: []const u8) Hash;
};
```

#### Usage

```zig
const selector = ABI.computeSelector("transfer(address,uint256)");

const sig = try ABI.createSignature(
    allocator,
    "transfer",
    &[_]ABI.Type{ .address, .uint256 }
);
defer allocator.free(sig);

const values = [_]ABI.Value{
    .{ .address = recipient },
    .{ .uint256 = amount },
};

const encoded = try ABI.encodeParameters(allocator, &values);
defer allocator.free(encoded);

const calldata = try ABI.encodeFunctionCall(
    allocator,
    "transfer(address,uint256)",
    &values
);
defer allocator.free(calldata);

const types = [_]ABI.Type{ .address, .uint256 };
const decoded = try ABI.decodeParameters(allocator, data, &types);
defer allocator.free(decoded);

const topic0 = ABI.encodeEventTopic("Transfer(address,address,uint256)");
```

---

## Transactions

### Transaction Types

```zig
pub const TransactionType = enum(u8) {
    legacy = 0x00,
    eip2930 = 0x01,
    eip1559 = 0x02,
    eip4844 = 0x03,
    eip7702 = 0x04,
};
```

### `LegacyTransaction`

```zig
pub const LegacyTransaction = struct {
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub fn sign(self: *LegacyTransaction, private_key: [32]u8, chain_id: u64) !void;
    pub fn serialize(self: LegacyTransaction, allocator: Allocator) ![]u8;
    pub fn deserialize(allocator: Allocator, data: []const u8) !LegacyTransaction;
    pub fn hash(self: LegacyTransaction, allocator: Allocator) !Hash;
    pub fn recoverSender(self: LegacyTransaction) !Address;
};
```

### `EIP1559Transaction`

```zig
pub const EIP1559Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    access_list: []const AccessListEntry,
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub fn effectiveGasPrice(self: EIP1559Transaction, base_fee: u256) u256;
    pub fn validate(self: EIP1559Transaction) !void;
    pub fn sign(self: *EIP1559Transaction, private_key: [32]u8) !void;
    pub fn serialize(self: EIP1559Transaction, allocator: Allocator) ![]u8;
    pub fn deserialize(allocator: Allocator, data: []const u8) !EIP1559Transaction;
    pub fn hash(self: EIP1559Transaction, allocator: Allocator) !Hash;
    pub fn recoverSender(self: EIP1559Transaction) !Address;
};
```

### `BlobTransaction` (EIP-4844)

```zig
pub const BlobTransaction = struct {
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
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub const BYTES_PER_BLOB = 131_072;
    pub const MAX_BLOBS_PER_TX = 6;
    pub const BLOB_GAS_PER_BLOB = 131_072;

    pub fn blobGas(self: BlobTransaction) u64;
    pub fn blobFee(self: BlobTransaction, blob_base_fee: u64) u64;
    pub fn validate(self: BlobTransaction) !void;
    pub fn sign(self: *BlobTransaction, private_key: [32]u8) !void;
    pub fn serialize(self: BlobTransaction, allocator: Allocator) ![]u8;
    pub fn deserialize(allocator: Allocator, data: []const u8) !BlobTransaction;
};

pub const Blob = [131_072]u8;
pub const BlobCommitment = [48]u8;
pub const BlobProof = [48]u8;

pub fn commitmentToVersionedHash(commitment: BlobCommitment) Hash;
pub fn calculateBlobBaseFee(excess_blob_gas: u64) u64;
```

### `SetCodeTransaction` (EIP-7702)

```zig
pub const SetCodeTransaction = struct {
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
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub fn validate(self: SetCodeTransaction) !void;
    pub fn sign(self: *SetCodeTransaction, private_key: [32]u8) !void;
    pub fn serialize(self: SetCodeTransaction, allocator: Allocator) ![]u8;
    pub fn deserialize(allocator: Allocator, data: []const u8) !SetCodeTransaction;
};

pub const Authorization = struct {
    chain_id: u64,
    address: Address,
    nonce: u64,
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub fn create(chain_id: u64, address: Address, nonce: u64, private_key: [32]u8) !Authorization;
    pub fn authority(self: Authorization) !Address;
    pub fn validate(self: Authorization) !void;
    pub fn signingHash(self: Authorization) !Hash;
};
```

---

### `AccessList` (EIP-2930)

```zig
pub const AccessListEntry = struct {
    address: Address,
    storage_keys: []const Hash,
};

pub const AccessList = []const AccessListEntry;

pub const ACCESS_LIST_ADDRESS_COST = 2400;
pub const ACCESS_LIST_STORAGE_KEY_COST = 1900;

pub fn calculateGas(list: AccessList) u64;
pub fn hasAddress(list: AccessList, address: Address) bool;
pub fn hasStorageKey(list: AccessList, address: Address, key: Hash) bool;
pub fn deduplicate(allocator: Allocator, list: AccessList) !AccessList;
pub fn serialize(allocator: Allocator, list: AccessList) ![]u8;
```

#### Usage

```zig
const entry = AccessListEntry{
    .address = addr,
    .storage_keys = &[_]Hash{ key1, key2 },
};

const list = [_]AccessListEntry{ entry };

const gas_cost = calculateGas(&list);
const has_addr = hasAddress(&list, addr);
const has_key = hasStorageKey(&list, addr, key);

const deduped = try deduplicate(allocator, &list);
defer allocator.free(deduped);

const serialized = try serialize(allocator, &list);
defer allocator.free(serialized);
```

---

## System Contracts

### `BeaconRoots` (EIP-4788)

Trust-minimized access to consensus layer (beacon chain) block roots from within the EVM. Beacon roots are stored in a ring buffer for recent block access without unbounded storage growth.

```zig
pub const BEACON_ROOTS_ADDRESS = Address{
    .bytes = [_]u8{
        0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
        0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
        0xd0, 0xBe, 0xac, 0x02,
    },
};

pub const SYSTEM_ADDRESS = Address{
    .bytes = [_]u8{0xff} ** 18 ++ [_]u8{0xff, 0xfe},
};

pub const HISTORY_BUFFER_LENGTH: u64 = 8191;
pub const BEACON_ROOT_READ_GAS: u64 = 4200;
pub const BEACON_ROOT_WRITE_GAS: u64 = 20000;

pub const BeaconRootsContract = struct {
    database: *Database,
    allocator: Allocator,

    pub fn execute(
        self: *Self,
        caller: Address,
        input: []const u8,
        gas_limit: u64,
    ) !struct { output: []const u8, gas_used: u64 };

    pub fn processBeaconRootUpdate(
        database: *Database,
        block_info: *const BlockInfo,
    ) !void;
};

pub fn computeSlots(timestamp: u64) struct {
    timestamp_slot: u64,
    root_slot: u64
};
```

#### Usage

```zig
var contract = BeaconRootsContract{
    .database = &database,
    .allocator = allocator,
};

// System call to store beacon root (called at block start)
const timestamp: u64 = 1710338135;
const beacon_root = [_]u8{0xAB} ** 32;

var input: [64]u8 = undefined;
std.mem.writeInt(u256, input[0..32], timestamp, .big);
@memcpy(input[32..64], &beacon_root);

const write_result = try contract.execute(
    SYSTEM_ADDRESS,
    &input,
    100000,
);
defer allocator.free(write_result.output);

// Read beacon root for a timestamp
var read_input: [32]u8 = undefined;
std.mem.writeInt(u256, &read_input, timestamp, .big);

const read_result = try contract.execute(
    caller_address,
    &read_input,
    10000,
);
defer allocator.free(read_result.output);

if (read_result.output.len == 32) {
    // Root found
    const beacon_root_bytes = read_result.output[0..32];
} else {
    // Root not available (timestamp too old or not found)
}

// Process beacon root update at block start
try BeaconRootsContract.processBeaconRootUpdate(&database, &block_info);

// Compute ring buffer slots for a timestamp
const slots = computeSlots(timestamp);
// slots.timestamp_slot -> location for beacon root
// slots.root_slot -> location for timestamp verification
```

---

## Logs & Events

### `EventLog`

```zig
pub const EventLog = struct {
    address: Address,
    topics: []const Hash,
    data: []const u8,
    block_number: ?u64,
    transaction_hash: ?Hash,
    transaction_index: ?u32,
    log_index: ?u32,
    removed: bool,

    pub fn eventSignature(self: EventLog) ?Hash;
};

pub fn filterLogs(logs: []const EventLog, topics: []const ?Hash) []const EventLog;
```

#### Usage

```zig
const log = EventLog{
    .address = contract_addr,
    .topics = &[_]Hash{ topic0, topic1, topic2 },
    .data = event_data,
    .block_number = 12345,
    .transaction_hash = tx_hash,
    .transaction_index = 0,
    .log_index = 0,
    .removed = false,
};

const sig = log.eventSignature();

const filtered = filterLogs(logs, &[_]?Hash{ topic0, null, null });
```

---

## Gas Constants

```zig
pub const Gas = struct {
    pub const TX = 21_000;
    pub const TX_CREATE = 32_000;
    pub const TX_DATA_ZERO = 4;
    pub const TX_DATA_NONZERO = 16;

    pub const COLD_ACCOUNT_ACCESS = 2_600;
    pub const COLD_SLOAD = 2_100;
    pub const WARM_STORAGE_READ = 100;

    pub const SSTORE_SET = 20_000;
    pub const SSTORE_RESET = 5_000;
    pub const SSTORE_CLEAR_REFUND = 15_000;

    pub const CALL = 700;
    pub const CALL_VALUE = 9_000;
    pub const CALL_STIPEND = 2_300;
    pub const NEW_ACCOUNT = 25_000;

    pub const ECRECOVER = 3_000;
    pub const SHA256_BASE = 60;
    pub const SHA256_WORD = 12;
    pub const RIPEMD160_BASE = 600;
    pub const RIPEMD160_WORD = 120;
    pub const IDENTITY_BASE = 15;
    pub const IDENTITY_WORD = 3;

    pub fn memoryExpansion(byte_size: u64) u64;
    pub fn intrinsic(params: struct {
        data: []const u8,
        is_creation: bool,
        access_list: ?AccessList,
    }) u64;
};
```

#### Usage

```zig
const base_cost = Gas.TX;
const create_cost = Gas.TX_CREATE;

const memory_cost = Gas.memoryExpansion(1024);

const intrinsic_gas = Gas.intrinsic(.{
    .data = calldata,
    .is_creation = false,
    .access_list = null,
});
```

---

## Opcodes

EVM opcode enumeration with categorization and utility methods.

```zig
pub const Opcode = enum(u8) {
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b,
    SHR = 0x1c,
    SAR = 0x1d,
    KECCAK256 = 0x20,
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3a,
    EXTCODESIZE = 0x3b,
    EXTCODECOPY = 0x3c,
    RETURNDATASIZE = 0x3d,
    RETURNDATACOPY = 0x3e,
    EXTCODEHASH = 0x3f,
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    PREVRANDAO = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,
    BLOBHASH = 0x49,
    BLOBBASEFEE = 0x4a,
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5a,
    JUMPDEST = 0x5b,
    TLOAD = 0x5c,
    TSTORE = 0x5d,
    MCOPY = 0x5e,
    PUSH0 = 0x5f,
    PUSH1 = 0x60,
    PUSH2 = 0x61,
    // ... PUSH3-PUSH31
    PUSH32 = 0x7f,
    DUP1 = 0x80,
    DUP2 = 0x81,
    // ... DUP3-DUP15
    DUP16 = 0x8f,
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    // ... SWAP3-SWAP15
    SWAP16 = 0x9f,
    LOG0 = 0xa0,
    LOG1 = 0xa1,
    LOG2 = 0xa2,
    LOG3 = 0xa3,
    LOG4 = 0xa4,
    CREATE = 0xf0,
    CALL = 0xf1,
    CALLCODE = 0xf2,
    RETURN = 0xf3,
    DELEGATECALL = 0xf4,
    CREATE2 = 0xf5,
    AUTH = 0xf6,
    AUTHCALL = 0xf7,
    STATICCALL = 0xfa,
    REVERT = 0xfd,
    INVALID = 0xfe,
    SELFDESTRUCT = 0xff,

    pub fn isPush(self: Opcode) bool;
    pub fn pushSize(self: Opcode) u8;
    pub fn isDup(self: Opcode) bool;
    pub fn dupPosition(self: Opcode) u8;
    pub fn isSwap(self: Opcode) bool;
    pub fn swapPosition(self: Opcode) u8;
    pub fn isLog(self: Opcode) bool;
    pub fn logTopics(self: Opcode) u8;
    pub fn isTerminating(self: Opcode) bool;
    pub fn isStateModifying(self: Opcode) bool;
    pub fn isArithmetic(self: Opcode) bool;
    pub fn isComparison(self: Opcode) bool;
    pub fn isBitwise(self: Opcode) bool;
    pub fn name(self: Opcode) []const u8;
};
```

### Opcode Categories

#### PUSH Operations (0x5f-0x7f)

```zig
if (opcode.isPush()) {
    const size = opcode.pushSize(); // 0-32 bytes
}
```

#### DUP Operations (0x80-0x8f)

```zig
if (opcode.isDup()) {
    const position = opcode.dupPosition(); // 1-16
}
```

#### SWAP Operations (0x90-0x9f)

```zig
if (opcode.isSwap()) {
    const position = opcode.swapPosition(); // 1-16
}
```

#### LOG Operations (0xa0-0xa4)

```zig
if (opcode.isLog()) {
    const topics = opcode.logTopics(); // 0-4
}
```

### Opcode Classification

```zig
// Terminating opcodes
if (opcode.isTerminating()) {
    // STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
}

// State-modifying opcodes
if (opcode.isStateModifying()) {
    // SSTORE, TSTORE, LOG*, CREATE*, CALL*, SELFDESTRUCT
}

// Arithmetic opcodes
if (opcode.isArithmetic()) {
    // ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
}

// Comparison opcodes
if (opcode.isComparison()) {
    // LT, GT, SLT, SGT, EQ, ISZERO
}

// Bitwise opcodes
if (opcode.isBitwise()) {
    // AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
}
```

#### Usage

```zig
const opcode = Opcode.PUSH1;

if (opcode.isPush()) {
    const bytes_to_read = opcode.pushSize();
    // Read bytes_to_read bytes following the opcode
}

const name = opcode.name(); // "PUSH1"

// Check opcode properties
if (Opcode.SSTORE.isStateModifying()) {
    // Handle state modification
}

if (Opcode.RETURN.isTerminating()) {
    // End execution
}

// Categorize opcodes
switch (opcode) {
    .ADD, .MUL, .SUB => {
        // Arithmetic operations
    },
    .PUSH1...PUSH32 => {
        const size = opcode.pushSize();
        // Handle PUSH operations
    },
    .DUP1...DUP16 => {
        const pos = opcode.dupPosition();
        // Handle DUP operations
    },
    else => {},
}
```

---

## EIP Configuration

### `Eips`

Ethereum Improvement Proposal (EIP) configuration system that consolidates all EIP-specific logic for the EVM. Provides hardfork-based feature detection and gas cost calculations with support for custom EIP overrides.

```zig
pub const Hardfork = enum {
    FRONTIER,
    HOMESTEAD,
    DAO,
    TANGERINE_WHISTLE,
    SPURIOUS_DRAGON,
    BYZANTIUM,
    CONSTANTINOPLE,
    PETERSBURG,
    ISTANBUL,
    MUIR_GLACIER,
    BERLIN,
    LONDON,
    ARROW_GLACIER,
    GRAY_GLACIER,
    MERGE,
    SHANGHAI,
    CANCUN,
    PRAGUE,
};

pub const EipOverride = struct {
    eip: u16,
    enabled: bool,
};

pub const Eips = struct {
    hardfork: Hardfork,
    overrides: []const EipOverride = &.{},

    // Feature detection
    pub fn is_eip_active(self: Self, eip: u16) bool;
    pub fn get_active_eips(self: Self) []const u16;

    // Opcode availability
    pub fn eip_3855_push0_enabled(self: Self) bool;
    pub fn eip_3198_basefee_opcode_enabled(self: Self) bool;
    pub fn eip_1153_transient_storage_enabled(self: Self) bool;
    pub fn eip_5656_has_mcopy(self: Self) bool;

    // Transaction types
    pub fn eip_1559_is_enabled(self: Self) bool;
    pub fn eip_4844_blob_transactions_enabled(self: Self) bool;
    pub fn eip_7702_eoa_code_enabled(self: Self) bool;

    // Gas costs
    pub fn eip_2929_cold_sload_cost(self: Self) u64;
    pub fn eip_2929_warm_storage_read_cost(self: Self) u64;
    pub fn eip_2929_cold_account_access_cost(self: Self) u64;
    pub fn eip_2929_warm_account_access_cost(self: Self) u64;
    pub fn eip_3529_gas_refund_cap(self: Self, gas_used: u64, refund_counter: u64) u64;
    pub fn eip_2028_calldata_gas_cost(self: Self, is_zero: bool) u64;
    pub fn eip_160_exp_byte_gas_cost(self: Self) u64;
    pub fn sstore_gas_cost(self: Self, current: u256, new: u256, original: u256) SstoreGasCost;

    // Code limits
    pub fn eip_170_max_code_size(self: Self) u32;
    pub fn eip_3860_size_limit(self: Self) u64;
    pub fn eip_3860_word_cost(self: Self) u64;

    // Behavior changes
    pub fn eip_6780_selfdestruct_same_transaction_only(self: Self) bool;
    pub fn eip_3541_should_reject_ef_bytecode(self: Self) bool;
    pub fn eip_4399_use_prevrandao(self: Self) bool;

    // Warming & access lists
    pub fn pre_warm_transaction_addresses(
        self: Self,
        access_list: *AccessList,
        origin: Address,
        target: ?Address,
        coinbase: Address,
    ) !void;
};
```

### Major EIP Groups by Hardfork

#### Berlin (EIP-2929, EIP-2930)
- **EIP-2929**: Gas cost increases for state access opcodes
- **EIP-2930**: Optional access lists in transactions

#### London (EIP-1559, EIP-3198, EIP-3529, EIP-3541)
- **EIP-1559**: Fee market change with base fee per gas
- **EIP-3198**: BASEFEE opcode
- **EIP-3529**: Reduction in gas refunds (1/5 instead of 1/2)
- **EIP-3541**: Reject contracts starting with 0xEF

#### Shanghai (EIP-3651, EIP-3855, EIP-3860)
- **EIP-3651**: Warm COINBASE address
- **EIP-3855**: PUSH0 instruction
- **EIP-3860**: Limit and meter initcode (48KB limit, 2 gas/word)

#### Cancun (EIP-1153, EIP-4788, EIP-4844, EIP-5656, EIP-6780)
- **EIP-1153**: Transient storage opcodes (TLOAD/TSTORE)
- **EIP-4788**: Beacon block root in the EVM
- **EIP-4844**: Shard blob transactions
- **EIP-5656**: MCOPY instruction
- **EIP-6780**: SELFDESTRUCT only in same transaction

#### Prague (EIP-2537, EIP-2935, EIP-6110, EIP-7002, EIP-7702)
- **EIP-2537**: BLS12-381 precompile operations
- **EIP-2935**: Historical block hashes from state
- **EIP-6110**: Validator deposits on chain
- **EIP-7002**: Execution layer triggerable exits
- **EIP-7702**: Set EOA account code

### Usage

#### Basic Configuration

```zig
const eips = Eips{ .hardfork = .CANCUN };

// Check if specific EIPs are active
if (eips.is_eip_active(1559)) {
    // EIP-1559 fee market is active
}

if (eips.eip_4844_blob_transactions_enabled()) {
    // Handle blob transactions
}

// Get all active EIPs for current hardfork
const active_eips = eips.get_active_eips();
for (active_eips) |eip_num| {
    std.debug.print("EIP-{}: active\n", .{eip_num});
}
```

#### Gas Cost Calculations

```zig
const berlin = Eips{ .hardfork = .BERLIN };
const istanbul = Eips{ .hardfork = .ISTANBUL };

// EIP-2929: Cold storage costs
const cold_sload = berlin.eip_2929_cold_sload_cost(); // 2100
const warm_sload = berlin.eip_2929_warm_storage_read_cost(); // 100

// Pre-Berlin costs
const old_sload = istanbul.eip_2929_cold_sload_cost(); // 200

// EIP-3529: Gas refund cap
const london = Eips{ .hardfork = .LONDON };
const gas_used: u64 = 100_000;
const refund_counter: u64 = 50_000;

// London: refund capped at 1/5 of gas used
const refund = london.eip_3529_gas_refund_cap(gas_used, refund_counter); // 20,000

// Pre-London: capped at 1/2
const old_refund = istanbul.eip_3529_gas_refund_cap(gas_used, refund_counter); // 50,000

// EIP-2028: Calldata gas costs
const zero_byte_cost = london.eip_2028_calldata_gas_cost(true); // 4
const nonzero_byte_cost = london.eip_2028_calldata_gas_cost(false); // 16
```

#### SSTORE Gas Costs

```zig
const eips = Eips{ .hardfork = .LONDON };

const current: u256 = 0;
const new: u256 = 1;
const original: u256 = 0;

const cost = eips.sstore_gas_cost(current, new, original);
// cost.gas = 20000 (setting from zero)
// cost.refund = 0

// Clearing storage
const clear_cost = eips.sstore_gas_cost(1, 0, 1);
// clear_cost.gas = 5000
// clear_cost.refund = 4800 (reduced by EIP-3529 in London)
```

#### Code Size Limits

```zig
const spurious = Eips{ .hardfork = .SPURIOUS_DRAGON };
const shanghai = Eips{ .hardfork = .SHANGHAI };

// EIP-170: Contract code size limit
const max_code = spurious.eip_170_max_code_size(); // 24,576 (0x6000)

// EIP-3860: Initcode size limits
const init_limit_pre = spurious.size_limit(); // 24,576 bytes
const init_limit_post = shanghai.size_limit(); // 49,152 bytes (48KB)

const word_cost = shanghai.word_cost(); // 2 gas per word
```

#### Transaction Address Warming

```zig
const shanghai = Eips{ .hardfork = .SHANGHAI };
var access_list = AccessList.init(allocator);
defer access_list.deinit();

// Pre-warm addresses for transaction execution
// Includes: origin, target, and coinbase (EIP-3651)
try shanghai.pre_warm_transaction_addresses(
    &access_list,
    tx_origin,
    tx_target,
    block_coinbase,
);
```

#### Custom EIP Overrides

```zig
// Enable future EIPs on older hardfork for testing
const custom = Eips{
    .hardfork = .LONDON,
    .overrides = &[_]EipOverride{
        .{ .eip = 3855, .enabled = true }, // Enable PUSH0
        .{ .eip = 3860, .enabled = true }, // Enable initcode metering
    },
};

if (custom.eip_3855_push0_enabled()) {
    // PUSH0 is now available on London
}

// Disable specific EIPs for testing
const restricted = Eips{
    .hardfork = .CANCUN,
    .overrides = &[_]EipOverride{
        .{ .eip = 4844, .enabled = false }, // Disable blob transactions
        .{ .eip = 1153, .enabled = false }, // Disable transient storage
    },
};

if (!restricted.eip_4844_blob_transactions_enabled()) {
    // Blob transactions disabled despite Cancun hardfork
}
```

#### Behavior Checks

```zig
const cancun = Eips{ .hardfork = .CANCUN };
const london = Eips{ .hardfork = .LONDON };
const merge = Eips{ .hardfork = .MERGE };

// EIP-6780: Restrict SELFDESTRUCT behavior
if (cancun.eip_6780_selfdestruct_same_transaction_only()) {
    // Only destroy contracts created in same transaction
}

// EIP-3541: Reject 0xEF bytecode
const bytecode = [_]u8{ 0xEF, 0x00, 0x01 };
if (london.eip_3541_should_reject_ef_bytecode()) {
    if (london.eip_3541_should_reject_create_with_ef_bytecode(&bytecode)) {
        return error.InvalidBytecode; // Reject EIP-3540 magic
    }
}

// EIP-4399: PREVRANDAO vs DIFFICULTY
if (merge.eip_4399_use_prevrandao()) {
    // Use PREVRANDAO opcode instead of DIFFICULTY
}
```

---

## Error Handling

All fallible operations return Zig error unions:

```zig
pub const AddressError = error{
    InvalidFormat,
    InvalidLength,
    InvalidChecksum,
};

pub const HexError = error{
    InvalidFormat,
    InvalidLength,
    InvalidCharacter,
    OddLength,
    ValueTooLarge,
};

pub const NumericError = error{
    InvalidInput,
    InvalidUnit,
    InvalidFormat,
    ValueTooLarge,
};

pub const RLPError = error{
    InputTooShort,
    InputTooLong,
    InvalidLength,
    NonCanonical,
    InvalidRemainder,
    LeadingZeros,
};

pub const ABIError = error{
    InvalidSelector,
    InvalidType,
    InvalidData,
    DataTooSmall,
    OutOfBounds,
    InvalidAddress,
};

pub const TransactionError = error{
    InvalidSignature,
    InvalidChainId,
    InvalidType,
};
```

#### Usage

```zig
const addr = Address.fromHex(hex_str) catch |err| switch (err) {
    error.InvalidFormat => return error.BadInput,
    error.InvalidChecksum => {
        std.log.warn("Checksum failed\n", .{});
        return error.InvalidChecksum;
    },
    else => return err,
};
```

---

## State Management

### `StorageKey`

Composite key for EVM storage (address + slot).

```zig
pub const StorageKey = struct {
    address: Address,
    slot: u256,

    pub fn hash(self: StorageKey, hasher: anytype) void;
    pub fn eql(a: StorageKey, b: StorageKey) bool;
};
```

#### Usage

```zig
var storage = std.AutoHashMap(StorageKey, u256).init(allocator);
defer storage.deinit();

const key = StorageKey{ .address = addr, .slot = 0 };
try storage.put(key, value);

const stored_value = storage.get(key);
```

### State Constants

```zig
pub const EMPTY_CODE_HASH: [32]u8 = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

pub const EMPTY_TRIE_ROOT: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};
```

---

## Module Structure

```zig
const primitives = @import("primitives");

pub const Address = primitives.Address;
pub const Hash = primitives.Hash;

pub const Hex = primitives.Hex;
pub const RLP = primitives.RLP;
pub const ABI = primitives.ABI;

pub const Numeric = primitives.Numeric;
pub const Gas = primitives.Gas;

pub const LegacyTransaction = primitives.LegacyTransaction;
pub const EIP1559Transaction = primitives.EIP1559Transaction;
pub const BlobTransaction = primitives.BlobTransaction;
pub const SetCodeTransaction = primitives.SetCodeTransaction;

pub const AccessList = primitives.AccessList;
pub const AccessListEntry = primitives.AccessListEntry;
pub const EventLog = primitives.EventLog;

pub const StorageKey = primitives.StorageKey;
pub const EMPTY_CODE_HASH = primitives.EMPTY_CODE_HASH;
pub const EMPTY_TRIE_ROOT = primitives.EMPTY_TRIE_ROOT;
```

---

## Examples

### Creating and Signing a Transaction

```zig
const std = @import("std");
const primitives = @import("primitives");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tx = primitives.EIP1559Transaction{
        .chain_id = 1,
        .nonce = 42,
        .max_priority_fee_per_gas = try primitives.Numeric.parseGwei("2"),
        .max_fee_per_gas = try primitives.Numeric.parseGwei("20"),
        .gas_limit = 21_000,
        .to = try primitives.Address.fromHex("0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676"),
        .value = try primitives.Numeric.parseEther("1.5"),
        .data = &[_]u8{},
        .access_list = &[_]primitives.AccessListEntry{},
        .v = 0,
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 32,
    };

    const private_key = try primitives.Hex.decodeFixed(32, "0x...");
    try tx.sign(private_key);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    const tx_hash = try tx.hash(allocator);

    std.debug.print("Transaction hash: {}\n", .{tx_hash});
}
```

### Encoding a Contract Call

```zig
const primitives = @import("primitives");

const recipient = try primitives.Address.fromHex("0x...");
const amount = try primitives.Numeric.parseEther("100");

const values = [_]primitives.ABI.Value{
    .{ .address = recipient },
    .{ .uint256 = amount },
};

const calldata = try primitives.ABI.encodeFunctionCall(
    allocator,
    "transfer(address,uint256)",
    &values
);
defer allocator.free(calldata);
```

### Decoding Event Logs

```zig
const event_signature = primitives.ABI.encodeEventTopic(
    "Transfer(address,address,uint256)"
);

for (logs) |log| {
    if (log.topics.len > 0 and log.topics[0].eql(event_signature)) {
        const from = primitives.Address.fromBytes(log.topics[1].bytes[12..32]);
        const to = primitives.Address.fromBytes(log.topics[2].bytes[12..32]);

        const types = [_]primitives.ABI.Type{.uint256};
        const values = try primitives.ABI.decodeParameters(allocator, log.data, &types);
        defer allocator.free(values);

        const amount = values[0].uint256;

        std.debug.print("Transfer from {} to {}: {}\n", .{ from, to, amount });
    }
}
```

---

## License

MIT
