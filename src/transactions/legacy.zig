const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;

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

    pub const Error = error{
        InvalidSignature,
        InvalidChainId,
    } || Allocator.Error;

    /// Sign transaction with private key
    pub fn sign(self: *LegacyTransaction, private_key: [32]u8, chain_id: u64) Error!void {
        _ = self;
        _ = private_key;
        _ = chain_id;
        @panic("TODO: implement sign");
    }

    /// Serialize transaction to bytes
    pub fn serialize(self: LegacyTransaction, allocator: Allocator) Error![]u8 {
        _ = self;
        _ = allocator;
        @panic("TODO: implement serialize");
    }

    /// Deserialize transaction from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) Error!LegacyTransaction {
        _ = allocator;
        _ = data;
        @panic("TODO: implement deserialize");
    }

    /// Compute transaction hash
    pub fn hash(self: LegacyTransaction, allocator: Allocator) Error!Hash {
        _ = self;
        _ = allocator;
        @panic("TODO: implement hash");
    }

    /// Recover sender address from signature
    pub fn recoverSender(self: LegacyTransaction) Error!Address {
        _ = self;
        @panic("TODO: implement recoverSender");
    }
};
