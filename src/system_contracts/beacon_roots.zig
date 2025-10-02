/// EIP-4788: Beacon block root in the EVM
///
/// This module implements the beacon roots contract that provides trust-minimized
/// access to the consensus layer (beacon chain) from within the EVM.
///
/// The beacon roots are stored in a ring buffer with HISTORY_BUFFER_LENGTH entries.
/// This allows accessing recent beacon block roots without unbounded storage growth.
///
/// ## Overview
///
/// EIP-4788 introduces a system contract at a well-known address that stores recent
/// beacon chain block roots. This enables EVM smart contracts to verify consensus
/// layer state proofs, enabling trustless bridges, liquid staking protocols, and
/// other applications that need to interact with the beacon chain.
///
/// ## Storage Layout
///
/// The contract uses a ring buffer with two mappings:
/// - `timestamp % HISTORY_BUFFER_LENGTH -> beacon_root` (timestamp slot)
/// - `(timestamp % HISTORY_BUFFER_LENGTH) + HISTORY_BUFFER_LENGTH -> timestamp` (root slot)
///
/// The dual mapping ensures that when the ring buffer wraps around, we can detect
/// that a slot has been overwritten by comparing the stored timestamp.
///
/// ## Usage
///
/// ```zig
/// const beacon_roots = @import("beacon_roots.zig");
///
/// // Initialize contract
/// var contract = beacon_roots.BeaconRootsContract{
///     .database = &database,
///     .allocator = allocator,
/// };
///
/// // System call to store beacon root (called at block start)
/// const timestamp: u64 = 1710338135;
/// const beacon_root = [_]u8{0xAB} ** 32;
///
/// var input: [64]u8 = undefined;
/// std.mem.writeInt(u256, input[0..32], timestamp, .big);
/// @memcpy(input[32..64], &beacon_root);
///
/// const write_result = try contract.execute(
///     beacon_roots.SYSTEM_ADDRESS,
///     &input,
///     100000,
/// );
/// defer allocator.free(write_result.output);
///
/// // Read beacon root for a timestamp
/// var read_input: [32]u8 = undefined;
/// std.mem.writeInt(u256, &read_input, timestamp, .big);
///
/// const read_result = try contract.execute(
///     caller_address,
///     &read_input,
///     10000,
/// );
/// defer allocator.free(read_result.output);
///
/// if (read_result.output.len == 32) {
///     // Root found
///     const beacon_root_bytes = read_result.output[0..32];
/// } else {
///     // Root not available (timestamp too old or not found)
/// }
/// ```
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Represents a 20-byte Ethereum address
pub const Address = struct {
    bytes: [20]u8,
};

// =============================================================================
// Constants
// =============================================================================

/// EIP-4788 beacon roots contract address
/// Deployed at 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02
pub const BEACON_ROOTS_ADDRESS: Address = .{
    .bytes = [_]u8{
        0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
        0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
        0xd0, 0xBe, 0xac, 0x02,
    },
};

/// System address that can update beacon roots
/// 0xfffffffffffffffffffffffffffffffffffffffe
pub const SYSTEM_ADDRESS: Address = .{
    .bytes = [_]u8{0xff} ** 18 ++ [_]u8{ 0xff, 0xfe },
};

/// Length of the beacon roots ring buffer
/// This is a prime number to reduce collision probability
pub const HISTORY_BUFFER_LENGTH: u64 = 8191;

/// Gas cost for reading a beacon root
/// Covers storage access (SLOAD) and verification logic
pub const BEACON_ROOT_READ_GAS: u64 = 4200;

/// Gas cost for writing a beacon root (system call only)
/// Covers two storage writes (SSTORE) for dual mapping
pub const BEACON_ROOT_WRITE_GAS: u64 = 20000;

// =============================================================================
// Types
// =============================================================================

/// Block metadata required for beacon root updates
///
/// This struct contains the minimum information needed to process
/// beacon root updates at block start. Implementations may use their
/// own BlockInfo type as long as it has these fields.
pub const BlockInfo = struct {
    /// Block timestamp (Unix time)
    timestamp: u64,

    /// Parent beacon block root (optional, null if pre-Cancun)
    beacon_root: ?[32]u8,
};

/// Database interface for storage operations
///
/// This is a minimal interface that any storage backend can implement.
/// The contract only needs get/set operations on u256 values.
pub const Database = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const DbError = error{
        StorageError,
        DatabaseError,
    };

    pub const VTable = struct {
        get_storage: *const fn (ctx: *anyopaque, address: [20]u8, slot: u64) DbError!u256,
        set_storage: *const fn (ctx: *anyopaque, address: [20]u8, slot: u64, value: u256) DbError!void,
    };

    /// Read a storage slot value
    pub fn get_storage(self: Database, address: [20]u8, slot: u64) DbError!u256 {
        return self.vtable.get_storage(self.ptr, address, slot);
    }

    /// Write a storage slot value
    pub fn set_storage(self: Database, address: [20]u8, slot: u64, value: u256) DbError!void {
        return self.vtable.set_storage(self.ptr, address, slot, value);
    }
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during beacon roots operations
pub const Error = error{
    /// Input data is wrong length for the operation
    InvalidInputLength,

    /// System call input must be exactly 64 bytes
    InvalidSystemCallInput,

    /// Read input must be exactly 32 bytes
    InvalidReadInput,

    /// Not enough gas to complete the operation
    OutOfGas,
} || Allocator.Error || Database.DbError;

// =============================================================================
// Ring Buffer Slot Computation
// =============================================================================

/// Compute storage slots for a given timestamp
///
/// The beacon roots contract uses a ring buffer with dual storage:
/// - timestamp_slot: stores the beacon root for this timestamp
/// - root_slot: stores the timestamp itself for verification
///
/// This dual mapping prevents false positives when the ring buffer wraps around.
///
/// Example:
/// ```zig
/// const slots = computeSlots(1710338135);
/// // slots.timestamp_slot = 1710338135 % 8191 = 5944
/// // slots.root_slot = 5944 + 8191 = 14135
/// ```
pub fn computeSlots(timestamp: u64) struct {
    timestamp_slot: u64,
    root_slot: u64,
} {
    const timestamp_slot = timestamp % HISTORY_BUFFER_LENGTH;
    const root_slot = timestamp_slot + HISTORY_BUFFER_LENGTH;
    return .{
        .timestamp_slot = timestamp_slot,
        .root_slot = root_slot,
    };
}

// =============================================================================
// BeaconRootsContract
// =============================================================================

/// Beacon roots contract implementation
///
/// This contract handles both reading and writing of beacon roots.
/// - Writes are only allowed from SYSTEM_ADDRESS (system calls at block start)
/// - Reads are allowed from any address
pub const BeaconRootsContract = struct {
    database: Database,
    allocator: Allocator,

    const Self = @This();

    /// Execute the beacon roots contract
    ///
    /// This method handles two types of calls:
    ///
    /// 1. System call (from SYSTEM_ADDRESS with 64 bytes input):
    ///    - First 32 bytes: timestamp (big-endian u256)
    ///    - Second 32 bytes: beacon root (32 bytes)
    ///    - Stores the beacon root in the ring buffer
    ///    - Returns empty output, gas_used = BEACON_ROOT_WRITE_GAS
    ///
    /// 2. Read call (from any address with 32 bytes input):
    ///    - Input: timestamp (big-endian u256)
    ///    - Returns beacon root if available (32 bytes)
    ///    - Returns empty output if not found
    ///    - gas_used = BEACON_ROOT_READ_GAS
    ///
    /// Example:
    /// ```zig
    /// // Write (system call)
    /// var input: [64]u8 = undefined;
    /// std.mem.writeInt(u256, input[0..32], timestamp, .big);
    /// @memcpy(input[32..64], &beacon_root);
    /// const result = try contract.execute(SYSTEM_ADDRESS, &input, 100000);
    ///
    /// // Read
    /// var read_input: [32]u8 = undefined;
    /// std.mem.writeInt(u256, &read_input, timestamp, .big);
    /// const result = try contract.execute(caller, &read_input, 10000);
    /// ```
    pub fn execute(
        self: *Self,
        caller: Address,
        input: []const u8,
        gas_limit: u64,
    ) Error!struct { output: []const u8, gas_used: u64 } {
        // System call to update beacon root
        if (std.mem.eql(u8, &caller.bytes, &SYSTEM_ADDRESS.bytes)) {
            if (input.len != 64) {
                return Error.InvalidSystemCallInput;
            }

            if (gas_limit < BEACON_ROOT_WRITE_GAS) {
                return Error.OutOfGas;
            }

            // Parse timestamp and beacon root
            const timestamp = std.mem.readInt(u256, input[0..32], .big);
            var beacon_root: [32]u8 = undefined;
            @memcpy(&beacon_root, input[32..64]);

            // Store in ring buffer
            const slots = computeSlots(@intCast(timestamp));

            // Store timestamp -> beacon_root
            try self.database.set_storage(
                BEACON_ROOTS_ADDRESS.bytes,
                slots.timestamp_slot,
                @bitCast(beacon_root),
            );

            // Store beacon_root -> timestamp (for verification)
            try self.database.set_storage(
                BEACON_ROOTS_ADDRESS.bytes,
                slots.root_slot,
                timestamp,
            );

            return .{ .output = &.{}, .gas_used = BEACON_ROOT_WRITE_GAS };
        }

        // Regular call to read beacon root
        if (input.len != 32) {
            return Error.InvalidReadInput;
        }

        if (gas_limit < BEACON_ROOT_READ_GAS) {
            return Error.OutOfGas;
        }

        // Parse timestamp
        const timestamp = std.mem.readInt(u256, input[0..32], .big);

        // Retrieve from ring buffer
        const slots = computeSlots(@intCast(timestamp));
        const stored_root = try self.database.get_storage(
            BEACON_ROOTS_ADDRESS.bytes,
            slots.timestamp_slot,
        );

        // Check if this is the correct timestamp by verifying reverse mapping
        const stored_timestamp = try self.database.get_storage(
            BEACON_ROOTS_ADDRESS.bytes,
            slots.root_slot,
        );

        if (stored_timestamp != timestamp) {
            // Timestamp doesn't match, root not available
            // Return empty slice (caller must free it)
            const empty_output = try self.allocator.alloc(u8, 0);
            return .{ .output = empty_output, .gas_used = BEACON_ROOT_READ_GAS };
        }

        // Allocate and return the beacon root
        const output = try self.allocator.alloc(u8, 32);
        const root_bytes: [32]u8 = @bitCast(stored_root);
        @memcpy(output, &root_bytes);

        return .{ .output = output, .gas_used = BEACON_ROOT_READ_GAS };
    }

    /// Process a beacon root update at the start of a block
    ///
    /// This is a convenience method that should be called by the EVM
    /// before processing any transactions in a block. It stores the
    /// parent beacon block root if present.
    ///
    /// This is typically called automatically by the block processing
    /// logic and does not go through the normal contract execution path.
    ///
    /// Example:
    /// ```zig
    /// const block_info = BlockInfo{
    ///     .timestamp = 1710338135,
    ///     .beacon_root = [_]u8{0xAB} ** 32,
    /// };
    ///
    /// try BeaconRootsContract.processBeaconRootUpdate(
    ///     database,
    ///     &block_info,
    /// );
    /// ```
    pub fn processBeaconRootUpdate(
        database: Database,
        block_info: *const BlockInfo,
    ) Database.DbError!void {
        if (block_info.beacon_root == null) {
            // No beacon root to update (pre-Cancun block)
            return;
        }

        const beacon_root = block_info.beacon_root.?;
        const timestamp = block_info.timestamp;

        // Store in ring buffer
        const slots = computeSlots(timestamp);

        // Store timestamp -> beacon_root
        try database.set_storage(
            BEACON_ROOTS_ADDRESS.bytes,
            slots.timestamp_slot,
            @bitCast(beacon_root),
        );

        // Store beacon_root -> timestamp (for verification)
        try database.set_storage(
            BEACON_ROOTS_ADDRESS.bytes,
            slots.root_slot,
            timestamp,
        );
    }
};

// =============================================================================
// Tests
// =============================================================================

// Simple in-memory database for testing
const TestDatabase = struct {
    storage: std.AutoHashMap(StorageKey, u256),
    allocator: Allocator,

    const StorageKey = struct {
        address: [20]u8,
        slot: u64,

        pub fn hash(self: StorageKey) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(&self.address);
            hasher.update(std.mem.asBytes(&self.slot));
            return hasher.final();
        }

        pub fn eql(self: StorageKey, other: StorageKey) bool {
            return std.mem.eql(u8, &self.address, &other.address) and self.slot == other.slot;
        }
    };

    pub fn init(allocator: Allocator) TestDatabase {
        return .{
            .storage = std.AutoHashMap(StorageKey, u256).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TestDatabase) void {
        self.storage.deinit();
    }

    pub fn database(self: *TestDatabase) Database {
        return .{
            .ptr = self,
            .vtable = &.{
                .get_storage = getStorage,
                .set_storage = setStorage,
            },
        };
    }

    fn getStorage(ctx: *anyopaque, address: [20]u8, slot: u64) Database.DbError!u256 {
        const self: *TestDatabase = @ptrCast(@alignCast(ctx));
        const key = StorageKey{ .address = address, .slot = slot };
        return self.storage.get(key) orelse 0;
    }

    fn setStorage(ctx: *anyopaque, address: [20]u8, slot: u64, value: u256) Database.DbError!void {
        const self: *TestDatabase = @ptrCast(@alignCast(ctx));
        const key = StorageKey{ .address = address, .slot = slot };
        self.storage.put(key, value) catch return Database.DbError.StorageError;
    }
};

test "computeSlots - basic calculation" {
    const slots = computeSlots(1000);
    try std.testing.expectEqual(@as(u64, 1000), slots.timestamp_slot);
    try std.testing.expectEqual(@as(u64, 1000 + HISTORY_BUFFER_LENGTH), slots.root_slot);
}

test "computeSlots - ring buffer wrap" {
    const timestamp: u64 = HISTORY_BUFFER_LENGTH * 2 + 42;
    const slots = computeSlots(timestamp);
    try std.testing.expectEqual(@as(u64, 42), slots.timestamp_slot);
    try std.testing.expectEqual(@as(u64, 42 + HISTORY_BUFFER_LENGTH), slots.root_slot);
}

test "BeaconRootsContract - system call write" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // Prepare system call input
    const timestamp: u64 = 1710338135;
    const beacon_root = [_]u8{0xAB} ** 32;

    var input: [64]u8 = undefined;
    std.mem.writeInt(u256, input[0..32], timestamp, .big);
    @memcpy(input[32..64], &beacon_root);

    // Execute system call
    const result = try contract.execute(SYSTEM_ADDRESS, &input, 100000);
    defer allocator.free(result.output);

    try testing.expectEqual(BEACON_ROOT_WRITE_GAS, result.gas_used);
    try testing.expectEqual(@as(usize, 0), result.output.len);

    // Verify storage was updated
    const slots = computeSlots(timestamp);
    const stored_root = try db.database().get_storage(BEACON_ROOTS_ADDRESS.bytes, slots.timestamp_slot);
    const stored_timestamp = try db.database().get_storage(BEACON_ROOTS_ADDRESS.bytes, slots.root_slot);

    const root_bytes: [32]u8 = @bitCast(stored_root);
    try testing.expectEqualSlices(u8, &beacon_root, &root_bytes);
    try testing.expectEqual(@as(u256, timestamp), stored_timestamp);
}

test "BeaconRootsContract - read beacon root" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // First, write a beacon root via system call
    const timestamp: u64 = 1710338135;
    const beacon_root = [_]u8{0xAB} ** 32;

    var write_input: [64]u8 = undefined;
    std.mem.writeInt(u256, write_input[0..32], timestamp, .big);
    @memcpy(write_input[32..64], &beacon_root);

    _ = try contract.execute(SYSTEM_ADDRESS, &write_input, 100000);

    // Now read it back
    var read_input: [32]u8 = undefined;
    std.mem.writeInt(u256, &read_input, timestamp, .big);

    const test_caller = Address{ .bytes = [_]u8{0x11} ** 20 };
    const read_result = try contract.execute(test_caller, &read_input, 10000);
    defer allocator.free(read_result.output);

    try testing.expectEqual(BEACON_ROOT_READ_GAS, read_result.gas_used);
    try testing.expectEqual(@as(usize, 32), read_result.output.len);
    try testing.expectEqualSlices(u8, &beacon_root, read_result.output);
}

test "BeaconRootsContract - read not found" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // Try to read a timestamp that was never stored
    var read_input: [32]u8 = undefined;
    std.mem.writeInt(u256, &read_input, 999999, .big);

    const test_caller = Address{ .bytes = [_]u8{0x11} ** 20 };
    const result = try contract.execute(test_caller, &read_input, 10000);
    defer allocator.free(result.output);

    try testing.expectEqual(BEACON_ROOT_READ_GAS, result.gas_used);
    try testing.expectEqual(@as(usize, 0), result.output.len);
}

test "BeaconRootsContract - ring buffer wrap around" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // Store a root at a timestamp
    const timestamp1: u64 = 1000;
    const timestamp2: u64 = timestamp1 + HISTORY_BUFFER_LENGTH; // Will map to same slot
    const root1 = [_]u8{0x11} ** 32;
    const root2 = [_]u8{0x22} ** 32;

    // Store first root
    var input1: [64]u8 = undefined;
    std.mem.writeInt(u256, input1[0..32], timestamp1, .big);
    @memcpy(input1[32..64], &root1);
    _ = try contract.execute(SYSTEM_ADDRESS, &input1, 100000);

    // Store second root (overwrites first)
    var input2: [64]u8 = undefined;
    std.mem.writeInt(u256, input2[0..32], timestamp2, .big);
    @memcpy(input2[32..64], &root2);
    _ = try contract.execute(SYSTEM_ADDRESS, &input2, 100000);

    // Try to read first timestamp - should not be found
    var read_input1: [32]u8 = undefined;
    std.mem.writeInt(u256, &read_input1, timestamp1, .big);

    const test_caller = Address{ .bytes = [_]u8{0x11} ** 20 };
    const result1 = try contract.execute(test_caller, &read_input1, 10000);
    defer allocator.free(result1.output);

    try testing.expectEqual(@as(usize, 0), result1.output.len);

    // Read second timestamp - should be found
    var read_input2: [32]u8 = undefined;
    std.mem.writeInt(u256, &read_input2, timestamp2, .big);

    const result2 = try contract.execute(test_caller, &read_input2, 10000);
    defer allocator.free(result2.output);

    try testing.expectEqual(@as(usize, 32), result2.output.len);
    try testing.expectEqualSlices(u8, &root2, result2.output);
}

test "BeaconRootsContract - invalid input length errors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // Invalid system call input (not 64 bytes)
    const invalid_system_input = [_]u8{0x01} ** 63;
    const result1 = contract.execute(SYSTEM_ADDRESS, &invalid_system_input, 100000);
    try testing.expectError(Error.InvalidSystemCallInput, result1);

    // Invalid read input (not 32 bytes)
    const invalid_read_input = [_]u8{0x01} ** 31;
    const test_caller = Address{ .bytes = [_]u8{0x11} ** 20 };
    const result2 = contract.execute(test_caller, &invalid_read_input, 10000);
    try testing.expectError(Error.InvalidReadInput, result2);
}

test "BeaconRootsContract - out of gas errors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    var contract = BeaconRootsContract{
        .database = db.database(),
        .allocator = allocator,
    };

    // Insufficient gas for write
    var valid_write_input: [64]u8 = undefined;
    std.mem.writeInt(u256, valid_write_input[0..32], 12345, .big);
    @memset(valid_write_input[32..64], 0xCC);

    const result1 = contract.execute(SYSTEM_ADDRESS, &valid_write_input, BEACON_ROOT_WRITE_GAS - 1);
    try testing.expectError(Error.OutOfGas, result1);

    // Insufficient gas for read
    var valid_read_input: [32]u8 = undefined;
    std.mem.writeInt(u256, &valid_read_input, 12345, .big);

    const test_caller = Address{ .bytes = [_]u8{0x11} ** 20 };
    const result2 = contract.execute(test_caller, &valid_read_input, BEACON_ROOT_READ_GAS - 1);
    try testing.expectError(Error.OutOfGas, result2);
}

test "BeaconRootsContract.processBeaconRootUpdate - with beacon root" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    const block_info = BlockInfo{
        .timestamp = 1710338135,
        .beacon_root = [_]u8{0xCD} ** 32,
    };

    try BeaconRootsContract.processBeaconRootUpdate(db.database(), &block_info);

    // Verify storage was updated
    const slots = computeSlots(block_info.timestamp);
    const stored_root = try db.database().get_storage(BEACON_ROOTS_ADDRESS.bytes, slots.timestamp_slot);
    const stored_timestamp = try db.database().get_storage(BEACON_ROOTS_ADDRESS.bytes, slots.root_slot);

    const root_bytes: [32]u8 = @bitCast(stored_root);
    try testing.expectEqualSlices(u8, &block_info.beacon_root.?, &root_bytes);
    try testing.expectEqual(@as(u256, block_info.timestamp), stored_timestamp);
}

test "BeaconRootsContract.processBeaconRootUpdate - without beacon root" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var db = TestDatabase.init(allocator);
    defer db.deinit();

    const block_info = BlockInfo{
        .timestamp = 1710338135,
        .beacon_root = null, // Pre-Cancun block
    };

    // Should not error, just do nothing
    try BeaconRootsContract.processBeaconRootUpdate(db.database(), &block_info);

    // Verify nothing was stored
    const slots = computeSlots(block_info.timestamp);
    const stored_root = try db.database().get_storage(BEACON_ROOTS_ADDRESS.bytes, slots.timestamp_slot);
    try testing.expectEqual(@as(u256, 0), stored_root);
}

test "BEACON_ROOTS_ADDRESS constant" {
    const expected = [_]u8{
        0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
        0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
        0xd0, 0xBe, 0xac, 0x02,
    };
    try std.testing.expectEqualSlices(u8, &expected, &BEACON_ROOTS_ADDRESS.bytes);
}

test "SYSTEM_ADDRESS constant" {
    const expected = [_]u8{0xff} ** 18 ++ [_]u8{ 0xff, 0xfe };
    try std.testing.expectEqualSlices(u8, &expected, &SYSTEM_ADDRESS.bytes);
}

test "constants have correct values" {
    try std.testing.expectEqual(@as(u64, 8191), HISTORY_BUFFER_LENGTH);
    try std.testing.expectEqual(@as(u64, 4200), BEACON_ROOT_READ_GAS);
    try std.testing.expectEqual(@as(u64, 20000), BEACON_ROOT_WRITE_GAS);
}
