const std = @import("std");
const Allocator = std.mem.Allocator;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const AccessListEntry = @import("access_list.zig").AccessListEntry;

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

    pub const BYTES_PER_BLOB: u32 = 131_072;
    pub const MAX_BLOBS_PER_TX: u8 = 6;
    pub const BLOB_GAS_PER_BLOB: u32 = 131_072;

    pub const Error = error{
        InvalidSignature,
        InvalidChainId,
        InvalidFee,
        TooManyBlobs,
    } || Allocator.Error;

    /// Calculate blob gas usage
    pub fn blobGas(self: BlobTransaction) u64 {
        _ = self;
        @panic("TODO: implement blobGas");
    }

    /// Calculate blob fee
    pub fn blobFee(self: BlobTransaction, blob_base_fee: u64) u64 {
        _ = self;
        _ = blob_base_fee;
        @panic("TODO: implement blobFee");
    }

    /// Validate transaction fields
    pub fn validate(self: BlobTransaction) Error!void {
        _ = self;
        @panic("TODO: implement validate");
    }

    /// Sign transaction with private key
    pub fn sign(self: *BlobTransaction, private_key: [32]u8) Error!void {
        _ = self;
        _ = private_key;
        @panic("TODO: implement sign");
    }

    /// Serialize transaction to bytes
    pub fn serialize(self: BlobTransaction, allocator: Allocator) Error![]u8 {
        _ = self;
        _ = allocator;
        @panic("TODO: implement serialize");
    }

    /// Deserialize transaction from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) Error!BlobTransaction {
        _ = allocator;
        _ = data;
        @panic("TODO: implement deserialize");
    }
};

pub const Blob = [131_072]u8;
pub const BlobCommitment = [48]u8;
pub const BlobProof = [48]u8;

/// Convert blob commitment to versioned hash
pub fn commitmentToVersionedHash(commitment: BlobCommitment) Hash {
    _ = commitment;
    @panic("TODO: implement commitmentToVersionedHash");
}

/// Calculate blob base fee from excess blob gas
pub fn calculateBlobBaseFee(excess_blob_gas: u64) u64 {
    _ = excess_blob_gas;
    @panic("TODO: implement calculateBlobBaseFee");
}
