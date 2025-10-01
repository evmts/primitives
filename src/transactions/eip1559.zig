const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const AccessListEntry = @import("access_list.zig").AccessListEntry;

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

    pub const Error = error{
        InvalidSignature,
        InvalidChainId,
        InvalidFee,
    } || Allocator.Error;

    /// Calculate effective gas price
    pub fn effectiveGasPrice(self: EIP1559Transaction, base_fee: u256) u256 {
        _ = self;
        _ = base_fee;
        @panic("TODO: implement effectiveGasPrice");
    }

    /// Validate transaction fields
    pub fn validate(self: EIP1559Transaction) Error!void {
        _ = self;
        @panic("TODO: implement validate");
    }

    /// Sign transaction with private key
    pub fn sign(self: *EIP1559Transaction, private_key: [32]u8) Error!void {
        _ = self;
        _ = private_key;
        @panic("TODO: implement sign");
    }

    /// Serialize transaction to bytes
    pub fn serialize(self: EIP1559Transaction, allocator: Allocator) Error![]u8 {
        _ = self;
        _ = allocator;
        @panic("TODO: implement serialize");
    }

    /// Deserialize transaction from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) Error!EIP1559Transaction {
        _ = allocator;
        _ = data;
        @panic("TODO: implement deserialize");
    }

    /// Compute transaction hash
    pub fn hash(self: EIP1559Transaction, allocator: Allocator) Error!Hash {
        _ = self;
        _ = allocator;
        @panic("TODO: implement hash");
    }

    /// Recover sender address from signature
    pub fn recoverSender(self: EIP1559Transaction) Error!Address {
        _ = self;
        @panic("TODO: implement recoverSender");
    }
};
