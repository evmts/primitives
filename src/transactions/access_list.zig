const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;

pub const AccessListEntry = struct {
    address: Address,
    storage_keys: []const Hash,
};

pub const AccessList = []const AccessListEntry;

// Gas costs for access list items
pub const ACCESS_LIST_ADDRESS_COST: u64 = 2400;
pub const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1900;

/// Calculate gas cost for access list
pub fn calculateGas(list: AccessList) u64 {
    _ = list;
    @panic("TODO: implement calculateGas");
}

/// Check if access list contains an address
pub fn hasAddress(list: AccessList, address: Address) bool {
    _ = list;
    _ = address;
    @panic("TODO: implement hasAddress");
}

/// Check if access list contains a storage key
pub fn hasStorageKey(list: AccessList, address: Address, key: Hash) bool {
    _ = list;
    _ = address;
    _ = key;
    @panic("TODO: implement hasStorageKey");
}

/// Deduplicate access list entries
pub fn deduplicate(allocator: Allocator, list: AccessList) !AccessList {
    _ = allocator;
    _ = list;
    @panic("TODO: implement deduplicate");
}

/// Serialize access list to bytes
pub fn serialize(allocator: Allocator, list: AccessList) ![]u8 {
    _ = allocator;
    _ = list;
    @panic("TODO: implement serialize");
}
