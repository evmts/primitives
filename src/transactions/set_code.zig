const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const AccessListEntry = @import("access_list.zig").AccessListEntry;

pub const Authorization = struct {
    chain_id: u64,
    address: Address,
    nonce: u64,
    v: u64,
    r: [32]u8,
    s: [32]u8,

    pub const Error = error{
        InvalidSignature,
        InvalidChainId,
    } || Allocator.Error;

    /// Create authorization with signature
    pub fn create(chain_id: u64, address: Address, nonce: u64, private_key: [32]u8) Error!Authorization {
        _ = chain_id;
        _ = address;
        _ = nonce;
        _ = private_key;
        @panic("TODO: implement create");
    }

    /// Recover authority address
    pub fn authority(self: Authorization) Error!Address {
        _ = self;
        @panic("TODO: implement authority");
    }

    /// Validate authorization
    pub fn validate(self: Authorization) Error!void {
        _ = self;
        @panic("TODO: implement validate");
    }

    /// Compute signing hash
    pub fn signingHash(self: Authorization) Error!Hash {
        _ = self;
        @panic("TODO: implement signingHash");
    }
};

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

    pub const Error = error{
        InvalidSignature,
        InvalidChainId,
        InvalidFee,
        InvalidAuthorization,
    } || Allocator.Error;

    /// Validate transaction fields
    pub fn validate(self: SetCodeTransaction) Error!void {
        _ = self;
        @panic("TODO: implement validate");
    }

    /// Sign transaction with private key
    pub fn sign(self: *SetCodeTransaction, private_key: [32]u8) Error!void {
        _ = self;
        _ = private_key;
        @panic("TODO: implement sign");
    }

    /// Serialize transaction to bytes
    pub fn serialize(self: SetCodeTransaction, allocator: Allocator) Error![]u8 {
        _ = self;
        _ = allocator;
        @panic("TODO: implement serialize");
    }

    /// Deserialize transaction from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) Error!SetCodeTransaction {
        _ = allocator;
        _ = data;
        @panic("TODO: implement deserialize");
    }
};
