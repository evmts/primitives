const std = @import("std");
const Allocator = std.mem.Allocator;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Address = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig");

/// Application Binary Interface (ABI) encoding and decoding for Ethereum smart contracts
///
/// The ABI is Ethereum's standard for encoding function calls and data structures.
/// It defines how to encode:
/// - Function calls (selector + parameters)
/// - Event topics (signature hash + indexed parameters)
/// - Return values
/// - Errors
///
/// This implementation provides:
/// - Type-safe encoding/decoding of all Solidity types
/// - Function selector computation
/// - Dynamic and static type handling
/// - Comprehensive error handling
///
/// Reference: https://docs.soliditylang.org/en/latest/abi-spec.html
pub const ABI = @This();

// =============================================================================
// Error Types
// =============================================================================

pub const Error = error{
    /// Data buffer is too small for the expected type
    DataTooSmall,
    /// Invalid type for encoding/decoding
    InvalidType,
    /// Data format is invalid
    InvalidData,
    /// Selector format is invalid
    InvalidSelector,
    /// Position exceeds data bounds
    OutOfBounds,
    /// String is not valid UTF-8
    InvalidUtf8,
    /// Attempted to use an unimplemented feature
    NotImplemented,
    /// Memory allocation failed
    OutOfMemory,
};

// =============================================================================
// Type System
// =============================================================================

/// ABI type enumeration covering all Solidity types
///
/// Static types (fixed size, encoded in-place):
/// - Integer types (uint8-256, int8-256)
/// - address, bool
/// - Fixed-size bytes (bytes1-32)
///
/// Dynamic types (variable size, encoded via offset pointers):
/// - bytes, string
/// - Arrays (uint256[], bytes32[], address[], string[])
pub const Type = enum {
    // Unsigned integers
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
    uint256,
    // Signed integers
    int8,
    int16,
    int32,
    int64,
    int128,
    int256,
    // Special types
    address,
    bool,
    // Fixed-size bytes
    bytes1,
    bytes2,
    bytes3,
    bytes4,
    bytes8,
    bytes16,
    bytes32,
    // Dynamic types
    bytes,
    string,
    // Array types
    uint256_array,
    bytes32_array,
    address_array,
    string_array,

    /// Check if this type is dynamically sized
    ///
    /// Dynamic types require offset pointers in the static part and
    /// their actual data is stored in the dynamic part of the encoding.
    ///
    /// Example:
    /// ```zig
    /// assert(Type.string.isDynamic() == true);
    /// assert(Type.uint256.isDynamic() == false);
    /// ```
    pub fn isDynamic(self: Type) bool {
        return switch (self) {
            .bytes, .string, .uint256_array, .bytes32_array, .address_array, .string_array => true,
            else => false,
        };
    }

    /// Get the static size of a type in bytes
    ///
    /// Returns null for dynamic types (which have variable size).
    /// Static types always encode to 32 bytes (1 word).
    ///
    /// Example:
    /// ```zig
    /// assert(Type.uint256.size() == 32);
    /// assert(Type.string.size() == null);
    /// ```
    pub fn size(self: Type) ?usize {
        return switch (self) {
            .uint8, .int8 => 1,
            .uint16, .int16 => 2,
            .uint32, .int32 => 4,
            .uint64, .int64 => 8,
            .uint128, .int128 => 16,
            .uint256, .int256 => 32,
            .address => 20,
            .bool => 1,
            .bytes1 => 1,
            .bytes2 => 2,
            .bytes3 => 3,
            .bytes4 => 4,
            .bytes8 => 8,
            .bytes16 => 16,
            .bytes32 => 32,
            .bytes, .string, .uint256_array, .bytes32_array, .address_array, .string_array => null,
        };
    }

    /// Get the Solidity type string for this type
    ///
    /// Used for signature generation and debugging.
    ///
    /// Example:
    /// ```zig
    /// const type_str = Type.uint256.getType();
    /// // type_str = "uint256"
    /// ```
    pub fn getType(self: Type) []const u8 {
        return switch (self) {
            .uint8 => "uint8",
            .uint16 => "uint16",
            .uint32 => "uint32",
            .uint64 => "uint64",
            .uint128 => "uint128",
            .uint256 => "uint256",
            .int8 => "int8",
            .int16 => "int16",
            .int32 => "int32",
            .int64 => "int64",
            .int128 => "int128",
            .int256 => "int256",
            .address => "address",
            .bool => "bool",
            .bytes1 => "bytes1",
            .bytes2 => "bytes2",
            .bytes3 => "bytes3",
            .bytes4 => "bytes4",
            .bytes8 => "bytes8",
            .bytes16 => "bytes16",
            .bytes32 => "bytes32",
            .bytes => "bytes",
            .string => "string",
            .uint256_array => "uint256[]",
            .bytes32_array => "bytes32[]",
            .address_array => "address[]",
            .string_array => "string[]",
        };
    }
};

/// ABI value union holding actual parameter data
///
/// Each variant corresponds to a Type and holds the appropriate Zig type.
/// The union is tagged with the Type enum for type safety.
///
/// Example:
/// ```zig
/// const value = Value{ .uint256 = 42 };
/// const addr_value = Value{ .address = my_address };
/// ```
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

    /// Get the Type of this value
    ///
    /// Example:
    /// ```zig
    /// const value = Value{ .uint256 = 42 };
    /// assert(value.getType() == Type.uint256);
    /// ```
    pub fn getType(self: Value) Type {
        return @as(Type, self);
    }
};

// =============================================================================
// Function Selector Type
// =============================================================================

/// 4-byte function selector
///
/// Function selectors are the first 4 bytes of the Keccak256 hash of the
/// function signature. They identify which function to call in a contract.
///
/// Example:
/// ```zig
/// const selector = ABI.computeSelector("transfer(address,uint256)");
/// // selector = [0xa9, 0x05, 0x9c, 0xbb]
/// ```
pub const Selector = [4]u8;

// =============================================================================
// Cursor for Reading Encoded Data
// =============================================================================

/// Internal cursor for reading ABI-encoded data
///
/// Maintains a position in a byte slice and provides methods for reading
/// ABI-encoded values at proper word (32-byte) boundaries.
const Cursor = struct {
    data: []const u8,
    position: usize,

    pub fn init(data: []const u8) Cursor {
        return Cursor{
            .data = data,
            .position = 0,
        };
    }

    pub fn setPosition(self: *Cursor, pos: usize) void {
        self.position = pos;
    }

    pub fn readBytes(self: *Cursor, len: usize) Error![]const u8 {
        if (self.position + len > self.data.len) return Error.OutOfBounds;
        const result = self.data[self.position .. self.position + len];
        self.position += len;
        return result;
    }

    pub fn readWord(self: *Cursor) Error![32]u8 {
        const bytes = try self.readBytes(32);
        return bytes[0..32].*;
    }

    pub fn readU256Word(self: *Cursor) Error!u256 {
        const bytes = try self.readBytes(32);
        return std.mem.readInt(u256, bytes[0..32], .big);
    }

    pub fn atPosition(self: *const Cursor, pos: usize) Cursor {
        return Cursor{
            .data = self.data,
            .position = pos,
        };
    }
};

// =============================================================================
// Core Functions - Selector Computation
// =============================================================================

/// Compute the 4-byte function selector from a function signature
///
/// Algorithm:
/// 1. Compute Keccak256 hash of the signature string
/// 2. Take the first 4 bytes
///
/// The signature format is: "functionName(type1,type2,...)"
/// - No spaces
/// - No parameter names
/// - Canonical type names (uint256, not uint)
///
/// Example:
/// ```zig
/// const selector = ABI.computeSelector("transfer(address,uint256)");
/// // selector = [0xa9, 0x05, 0x9c, 0xbb]
/// ```
pub fn computeSelector(signature: []const u8) Selector {
    var hash: [32]u8 = undefined;
    Keccak256.hash(signature, &hash, .{});
    return hash[0..4].*;
}

/// Create a function signature string from name and parameter types
///
/// Allocates and returns a signature in the format "name(type1,type2,...)".
/// Caller must free the returned slice.
///
/// Example:
/// ```zig
/// const sig = try ABI.createSignature(
///     allocator,
///     "transfer",
///     &[_]Type{ .address, .uint256 }
/// );
/// defer allocator.free(sig);
/// // sig = "transfer(address,uint256)"
/// ```
pub fn createSignature(allocator: Allocator, name: []const u8, types: []const Type) ![]u8 {
    var signature = std.array_list.AlignedManaged(u8, null).init(allocator);
    defer signature.deinit();

    try signature.appendSlice(name);
    try signature.append('(');

    for (types, 0..) |param_type, i| {
        if (i > 0) try signature.append(',');
        try signature.appendSlice(param_type.getType());
    }

    try signature.append(')');
    return signature.toOwnedSlice();
}

// =============================================================================
// Encoding Functions - Internal Helpers
// =============================================================================

/// Encode a single static parameter to 32 bytes
fn encodeStaticParameter(allocator: Allocator, value: Value) ![]u8 {
    var result = try allocator.alloc(u8, 32);
    @memset(result, 0);

    switch (value) {
        .uint8 => |val| {
            result[31] = val;
        },
        .uint16 => |val| {
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, val, .big);
            @memcpy(result[30..32], &bytes);
        },
        .uint32 => |val| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, val, .big);
            @memcpy(result[28..32], &bytes);
        },
        .uint64 => |val| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, val, .big);
            @memcpy(result[24..32], &bytes);
        },
        .uint128 => |val| {
            var bytes: [16]u8 = undefined;
            std.mem.writeInt(u128, &bytes, val, .big);
            @memcpy(result[16..32], &bytes);
        },
        .uint256 => |val| {
            var bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &bytes, val, .big);
            @memcpy(result, &bytes);
        },
        .int8 => |val| {
            const unsigned = @as(u8, @bitCast(val));
            result[31] = unsigned;
            if (val < 0) {
                @memset(result[0..31], 0xff);
            }
        },
        .int16 => |val| {
            const unsigned = @as(u16, @bitCast(val));
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, unsigned, .big);
            @memcpy(result[30..32], &bytes);
            if (val < 0) {
                @memset(result[0..30], 0xff);
            }
        },
        .int32 => |val| {
            const unsigned = @as(u32, @bitCast(val));
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, unsigned, .big);
            @memcpy(result[28..32], &bytes);
            if (val < 0) {
                @memset(result[0..28], 0xff);
            }
        },
        .int64 => |val| {
            const unsigned = @as(u64, @bitCast(val));
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, unsigned, .big);
            @memcpy(result[24..32], &bytes);
            if (val < 0) {
                @memset(result[0..24], 0xff);
            }
        },
        .int128 => |val| {
            const unsigned = @as(u128, @bitCast(val));
            var bytes: [16]u8 = undefined;
            std.mem.writeInt(u128, &bytes, unsigned, .big);
            @memcpy(result[16..32], &bytes);
            if (val < 0) {
                @memset(result[0..16], 0xff);
            }
        },
        .int256 => {
            allocator.free(result);
            return Error.NotImplemented;
        },
        .address => |val| {
            // Address is 20 bytes, right-aligned (left-padded with zeros)
            @memcpy(result[12..32], &val.bytes);
        },
        .bool => |val| {
            result[31] = if (val) 1 else 0;
        },
        .bytes1 => |val| {
            @memcpy(result[0..1], &val);
        },
        .bytes2 => |val| {
            @memcpy(result[0..2], &val);
        },
        .bytes3 => |val| {
            @memcpy(result[0..3], &val);
        },
        .bytes4 => |val| {
            @memcpy(result[0..4], &val);
        },
        .bytes8 => |val| {
            @memcpy(result[0..8], &val);
        },
        .bytes16 => |val| {
            @memcpy(result[0..16], &val);
        },
        .bytes32 => |val| {
            @memcpy(result, &val);
        },
        else => {
            allocator.free(result);
            return Error.InvalidType;
        },
    }

    return result;
}

/// Encode a dynamic parameter (bytes, string, arrays)
fn encodeDynamicParameter(allocator: Allocator, value: Value) ![]u8 {
    switch (value) {
        .bytes, .string => |val| {
            const length = val.len;
            const padded_length = ((length + 31) / 32) * 32;

            var result = try allocator.alloc(u8, 32 + padded_length);
            @memset(result, 0);

            // Encode length
            var length_bytes: [32]u8 = undefined;
            @memset(&length_bytes, 0);
            std.mem.writeInt(u64, length_bytes[24..32], @as(u64, @intCast(length)), .big);
            @memcpy(result[0..32], &length_bytes);

            // Encode data
            @memcpy(result[32 .. 32 + length], val);

            return result;
        },
        .uint256_array => |val| {
            const length = val.len;
            var result = try allocator.alloc(u8, 32 + (length * 32));
            @memset(result, 0);

            // Encode length
            var length_bytes: [32]u8 = undefined;
            @memset(&length_bytes, 0);
            std.mem.writeInt(u64, length_bytes[24..32], @as(u64, @intCast(length)), .big);
            @memcpy(result[0..32], &length_bytes);

            // Encode elements
            for (val, 0..) |elem, i| {
                var elem_bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &elem_bytes, elem, .big);
                @memcpy(result[32 + (i * 32) .. 32 + ((i + 1) * 32)], &elem_bytes);
            }

            return result;
        },
        .bytes32_array => |val| {
            const length = val.len;
            var result = try allocator.alloc(u8, 32 + (length * 32));
            @memset(result, 0);

            // Encode length
            var length_bytes: [32]u8 = undefined;
            @memset(&length_bytes, 0);
            std.mem.writeInt(u64, length_bytes[24..32], @as(u64, @intCast(length)), .big);
            @memcpy(result[0..32], &length_bytes);

            // Encode elements
            for (val, 0..) |elem, i| {
                @memcpy(result[32 + (i * 32) .. 32 + ((i + 1) * 32)], &elem);
            }

            return result;
        },
        .address_array => |val| {
            const length = val.len;
            var result = try allocator.alloc(u8, 32 + (length * 32));
            @memset(result, 0);

            // Encode length
            var length_bytes: [32]u8 = undefined;
            @memset(&length_bytes, 0);
            std.mem.writeInt(u64, length_bytes[24..32], @as(u64, @intCast(length)), .big);
            @memcpy(result[0..32], &length_bytes);

            // Encode elements (addresses are 20 bytes, right-aligned)
            for (val, 0..) |elem, i| {
                @memcpy(result[32 + (i * 32) + 12 .. 32 + ((i + 1) * 32)], &elem.bytes);
            }

            return result;
        },
        .string_array => |val| {
            const length = val.len;

            // First pass: calculate total size
            var total_size: usize = 32; // Array length
            total_size += length * 32; // Offset pointers

            var string_sizes = try allocator.alloc(usize, length);
            defer allocator.free(string_sizes);

            for (val, 0..) |str, i| {
                const str_len = str.len;
                const padded_len = ((str_len + 31) / 32) * 32;
                string_sizes[i] = 32 + padded_len; // Length + data
                total_size += string_sizes[i];
            }

            var result = try allocator.alloc(u8, total_size);
            @memset(result, 0);

            // Encode array length
            var length_bytes: [32]u8 = undefined;
            @memset(&length_bytes, 0);
            std.mem.writeInt(u64, length_bytes[24..32], @as(u64, @intCast(length)), .big);
            @memcpy(result[0..32], &length_bytes);

            // Calculate offsets and encode offset pointers
            var current_offset: usize = length * 32;
            for (0..length) |i| {
                var offset_bytes: [32]u8 = undefined;
                @memset(&offset_bytes, 0);
                std.mem.writeInt(u64, offset_bytes[24..32], @as(u64, @intCast(current_offset)), .big);
                @memcpy(result[32 + (i * 32) .. 32 + ((i + 1) * 32)], &offset_bytes);
                current_offset += string_sizes[i];
            }

            // Encode string data
            var data_offset: usize = 32 + (length * 32);
            for (val, 0..) |str, i| {
                const str_len = str.len;

                // String length
                var str_length_bytes: [32]u8 = undefined;
                @memset(&str_length_bytes, 0);
                std.mem.writeInt(u64, str_length_bytes[24..32], @as(u64, @intCast(str_len)), .big);
                @memcpy(result[data_offset .. data_offset + 32], &str_length_bytes);

                // String data
                @memcpy(result[data_offset + 32 .. data_offset + 32 + str_len], str);

                data_offset += string_sizes[i];
            }

            return result;
        },
        else => {
            return Error.InvalidType;
        },
    }
}

// =============================================================================
// Encoding Functions - Public API
// =============================================================================

/// Encode ABI parameters according to the ABI specification
///
/// Encodes an array of values into ABI-encoded format. This includes:
/// - Static part: all parameters encoded in order (dynamic types use offset pointers)
/// - Dynamic part: actual data for dynamic types
///
/// The caller is responsible for freeing the returned slice.
///
/// Example:
/// ```zig
/// const values = [_]Value{
///     .{ .address = recipient },
///     .{ .uint256 = amount },
/// };
/// const encoded = try ABI.encodeParameters(allocator, &values);
/// defer allocator.free(encoded);
/// ```
pub fn encodeParameters(allocator: Allocator, values: []const Value) ![]u8 {
    if (values.len == 0) return try allocator.alloc(u8, 0);

    var static_parts = std.array_list.AlignedManaged([]u8, null).init(allocator);
    defer {
        for (static_parts.items) |part| {
            allocator.free(part);
        }
        static_parts.deinit();
    }

    var dynamic_parts = std.array_list.AlignedManaged([]u8, null).init(allocator);
    defer {
        for (dynamic_parts.items) |part| {
            allocator.free(part);
        }
        dynamic_parts.deinit();
    }

    // First pass: compute sizes and prepare parts
    var static_size: usize = 0;
    var dynamic_size: usize = 0;

    for (values) |value| {
        const value_type = value.getType();

        if (value_type.isDynamic()) {
            // Dynamic type: add offset pointer to static part
            static_size += 32;

            const dynamic_data = try encodeDynamicParameter(allocator, value);
            try dynamic_parts.append(dynamic_data);
            dynamic_size += dynamic_data.len;

            // Create offset pointer (will be filled in second pass)
            const offset_pointer = try allocator.alloc(u8, 32);
            @memset(offset_pointer, 0);
            try static_parts.append(offset_pointer);
        } else {
            // Static type: encode directly
            const static_data = try encodeStaticParameter(allocator, value);
            try static_parts.append(static_data);
            static_size += 32;
        }
    }

    // Second pass: update offset pointers
    var current_dynamic_offset: usize = static_size;
    var dynamic_index: usize = 0;

    for (values, 0..) |value, i| {
        const value_type = value.getType();

        if (value_type.isDynamic()) {
            // Update the offset pointer
            var offset_bytes: [32]u8 = undefined;
            @memset(&offset_bytes, 0);
            std.mem.writeInt(u64, offset_bytes[24..32], @as(u64, @intCast(current_dynamic_offset)), .big);
            @memcpy(static_parts.items[i], &offset_bytes);

            current_dynamic_offset += dynamic_parts.items[dynamic_index].len;
            dynamic_index += 1;
        }
    }

    // Concatenate all parts
    const total_size = static_size + dynamic_size;
    var result = try allocator.alloc(u8, total_size);

    var offset: usize = 0;

    // Copy static parts
    for (static_parts.items) |part| {
        @memcpy(result[offset .. offset + part.len], part);
        offset += part.len;
    }

    // Copy dynamic parts
    for (dynamic_parts.items) |part| {
        @memcpy(result[offset .. offset + part.len], part);
        offset += part.len;
    }

    return result;
}

// =============================================================================
// Decoding Functions - Internal Helpers
// =============================================================================

/// Decode unsigned integer from a 32-byte word
fn decodeUint(cursor: *Cursor, comptime T: type, comptime bits: u16) Error!T {
    if (bits > 256 or bits % 8 != 0) return Error.InvalidType;

    const word = try cursor.readWord();
    const bytes_len = bits / 8;
    const start_offset = 32 - bytes_len;

    if (T == u256) {
        return std.mem.readInt(u256, &word, .big);
    } else {
        return std.mem.readInt(T, word[start_offset..32], .big);
    }
}

/// Decode signed integer from a 32-byte word (two's complement)
fn decodeInt(cursor: *Cursor, comptime T: type, comptime bits: u16) Error!T {
    if (bits > 256 or bits % 8 != 0) return Error.InvalidType;

    const word = try cursor.readWord();
    const bytes_len = bits / 8;
    const start_offset = 32 - bytes_len;

    if (T == i256) {
        return Error.NotImplemented;
    } else {
        const unsigned = std.mem.readInt(std.meta.Int(.unsigned, @bitSizeOf(T)), word[start_offset..32], .big);
        return @bitCast(unsigned);
    }
}

/// Decode address from a 32-byte word
fn decodeAddress(cursor: *Cursor) Error!Address {
    const word = try cursor.readWord();
    var address: Address = undefined;
    @memcpy(&address.bytes, word[12..32]);
    return address;
}

/// Decode boolean from a 32-byte word
fn decodeBool(cursor: *Cursor) Error!bool {
    const word = try cursor.readWord();
    return word[31] != 0;
}

/// Decode fixed-size bytes from a 32-byte word
fn decodeBytesFixed(cursor: *Cursor, comptime size: usize) Error![size]u8 {
    const word = try cursor.readWord();
    var result: [size]u8 = undefined;
    @memcpy(&result, word[0..size]);
    return result;
}

/// Decode dynamic bytes from encoded data
fn decodeBytesDynamic(allocator: Allocator, cursor: *Cursor, static_position: usize) Error![]u8 {
    const offset = try cursor.readU256Word();
    var offset_cursor = cursor.atPosition(static_position + @as(usize, @intCast(offset)));

    const length = try offset_cursor.readU256Word();
    const length_usize = @as(usize, @intCast(length));

    if (length_usize == 0) {
        return try allocator.alloc(u8, 0);
    }

    const padded_length = ((length_usize + 31) / 32) * 32;
    const data = try offset_cursor.readBytes(padded_length);

    const result = try allocator.alloc(u8, length_usize);
    @memcpy(result, data[0..length_usize]);
    return result;
}

/// Decode string from encoded data (validates UTF-8)
fn decodeString(allocator: Allocator, cursor: *Cursor, static_position: usize) Error![]u8 {
    const bytes = try decodeBytesDynamic(allocator, cursor, static_position);
    if (!std.unicode.utf8ValidateSlice(bytes)) {
        allocator.free(bytes);
        return Error.InvalidUtf8;
    }
    return bytes;
}

/// Decode a single parameter
fn decodeParameter(allocator: Allocator, cursor: *Cursor, param_type: Type, static_position: usize) Error!Value {
    return switch (param_type) {
        .uint8 => Value{ .uint8 = try decodeUint(cursor, u8, 8) },
        .uint16 => Value{ .uint16 = try decodeUint(cursor, u16, 16) },
        .uint32 => Value{ .uint32 = try decodeUint(cursor, u32, 32) },
        .uint64 => Value{ .uint64 = try decodeUint(cursor, u64, 64) },
        .uint128 => Value{ .uint128 = try decodeUint(cursor, u128, 128) },
        .uint256 => Value{ .uint256 = try decodeUint(cursor, u256, 256) },
        .int8 => Value{ .int8 = try decodeInt(cursor, i8, 8) },
        .int16 => Value{ .int16 = try decodeInt(cursor, i16, 16) },
        .int32 => Value{ .int32 = try decodeInt(cursor, i32, 32) },
        .int64 => Value{ .int64 = try decodeInt(cursor, i64, 64) },
        .int128 => Value{ .int128 = try decodeInt(cursor, i128, 128) },
        .int256 => return Error.NotImplemented,
        .address => Value{ .address = try decodeAddress(cursor) },
        .bool => Value{ .bool = try decodeBool(cursor) },
        .bytes1 => Value{ .bytes1 = try decodeBytesFixed(cursor, 1) },
        .bytes2 => Value{ .bytes2 = try decodeBytesFixed(cursor, 2) },
        .bytes3 => Value{ .bytes3 = try decodeBytesFixed(cursor, 3) },
        .bytes4 => Value{ .bytes4 = try decodeBytesFixed(cursor, 4) },
        .bytes8 => Value{ .bytes8 = try decodeBytesFixed(cursor, 8) },
        .bytes16 => Value{ .bytes16 = try decodeBytesFixed(cursor, 16) },
        .bytes32 => Value{ .bytes32 = try decodeBytesFixed(cursor, 32) },
        .bytes => Value{ .bytes = try decodeBytesDynamic(allocator, cursor, static_position) },
        .string => Value{ .string = try decodeString(allocator, cursor, static_position) },
        .uint256_array => blk: {
            const offset = try cursor.readU256Word();
            var offset_cursor = cursor.atPosition(static_position + @as(usize, @intCast(offset)));

            const length = try offset_cursor.readU256Word();
            const length_usize = @as(usize, @intCast(length));

            var result = try allocator.alloc(u256, length_usize);
            for (0..length_usize) |i| {
                result[i] = try decodeUint(&offset_cursor, u256, 256);
            }

            break :blk Value{ .uint256_array = result };
        },
        .bytes32_array => blk: {
            const offset = try cursor.readU256Word();
            var offset_cursor = cursor.atPosition(static_position + @as(usize, @intCast(offset)));

            const length = try offset_cursor.readU256Word();
            const length_usize = @as(usize, @intCast(length));

            var result = try allocator.alloc([32]u8, length_usize);
            for (0..length_usize) |i| {
                result[i] = try decodeBytesFixed(&offset_cursor, 32);
            }

            break :blk Value{ .bytes32_array = result };
        },
        .address_array => blk: {
            const offset = try cursor.readU256Word();
            var offset_cursor = cursor.atPosition(static_position + @as(usize, @intCast(offset)));

            const length = try offset_cursor.readU256Word();
            const length_usize = @as(usize, @intCast(length));

            var result = try allocator.alloc(Address, length_usize);
            for (0..length_usize) |i| {
                result[i] = try decodeAddress(&offset_cursor);
            }

            break :blk Value{ .address_array = result };
        },
        .string_array => return Error.NotImplemented, // Complex nested dynamic type
    };
}

// =============================================================================
// Decoding Functions - Public API
// =============================================================================

/// Decode ABI-encoded parameters
///
/// Decodes a byte slice according to the provided type array.
/// The caller is responsible for freeing the returned slice and any
/// dynamically allocated data within the values.
///
/// Example:
/// ```zig
/// const types = [_]Type{ .address, .uint256 };
/// const decoded = try ABI.decodeParameters(allocator, data, &types);
/// defer {
///     // Free any dynamic data in values
///     allocator.free(decoded);
/// }
/// ```
pub fn decodeParameters(allocator: Allocator, data: []const u8, types: []const Type) ![]Value {
    if (data.len == 0 and types.len == 0) {
        return try allocator.alloc(Value, 0);
    }

    if (data.len < types.len * 32) {
        return Error.DataTooSmall;
    }

    var cursor = Cursor.init(data);
    const result = try allocator.alloc(Value, types.len);

    var consumed: usize = 0;
    for (types, 0..) |param_type, i| {
        cursor.setPosition(consumed);
        result[i] = try decodeParameter(allocator, &cursor, param_type, 0);
        consumed += 32; // Each parameter takes 32 bytes in static part
    }

    return result;
}

// =============================================================================
// High-Level Encoding Functions
// =============================================================================

/// Encode a complete function call (selector + parameters)
///
/// Combines the function selector with ABI-encoded parameters.
/// The signature format is: "functionName(type1,type2,...)"
///
/// Example:
/// ```zig
/// const calldata = try ABI.encodeFunctionCall(
///     allocator,
///     "transfer(address,uint256)",
///     &[_]Value{
///         .{ .address = recipient },
///         .{ .uint256 = amount },
///     }
/// );
/// defer allocator.free(calldata);
/// ```
pub fn encodeFunctionCall(allocator: Allocator, signature: []const u8, values: []const Value) ![]u8 {
    const selector = computeSelector(signature);
    const encoded_params = try encodeParameters(allocator, values);
    defer allocator.free(encoded_params);

    const result = try allocator.alloc(u8, 4 + encoded_params.len);
    @memcpy(result[0..4], &selector);
    @memcpy(result[4..], encoded_params);
    return result;
}

/// Encode an event topic (signature hash)
///
/// Events in Ethereum use the Keccak256 hash of the event signature as topic0.
/// The signature format is: "EventName(type1,type2,...)"
///
/// Example:
/// ```zig
/// const topic0 = ABI.encodeEventTopic("Transfer(address,address,uint256)");
/// ```
pub fn encodeEventTopic(signature: []const u8) Hash {
    return Hash.keccak256(signature);
}

// =============================================================================
// Tests
// =============================================================================

test "ABI: computeSelector - ERC20 transfer" {
    const selector = computeSelector("transfer(address,uint256)");
    const expected = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb };
    try std.testing.expectEqualSlices(u8, &expected, &selector);
}

test "ABI: createSignature - simple function" {
    const sig = try createSignature(
        std.testing.allocator,
        "transfer",
        &[_]Type{ .address, .uint256 },
    );
    defer std.testing.allocator.free(sig);

    try std.testing.expectEqualStrings("transfer(address,uint256)", sig);
}

test "ABI: encodeParameters - uint256" {
    const values = [_]Value{
        .{ .uint256 = 69420 },
    };

    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 32), encoded.len);

    const expected = [_]u8{0} ** 28 ++ [_]u8{ 0x00, 0x01, 0x0f, 0x2c };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "ABI: encodeParameters - bool true/false" {
    // Test true
    {
        const values = [_]Value{.{ .bool = true }};
        const encoded = try encodeParameters(std.testing.allocator, &values);
        defer std.testing.allocator.free(encoded);

        const expected = [_]u8{0} ** 31 ++ [_]u8{0x01};
        try std.testing.expectEqualSlices(u8, &expected, encoded);
    }

    // Test false
    {
        const values = [_]Value{.{ .bool = false }};
        const encoded = try encodeParameters(std.testing.allocator, &values);
        defer std.testing.allocator.free(encoded);

        const expected = [_]u8{0} ** 32;
        try std.testing.expectEqualSlices(u8, &expected, encoded);
    }
}

test "ABI: encodeParameters - address" {
    const addr = Address{ .bytes = [_]u8{0x12} ** 20 };
    const values = [_]Value{.{ .address = addr }};

    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    // Address should be right-aligned (left-padded with zeros)
    const expected = [_]u8{0} ** 12 ++ addr.bytes;
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "ABI: encodeParameters - int32 negative" {
    const values = [_]Value{.{ .int32 = -2147483648 }};
    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    // Two's complement representation
    const expected = [_]u8{0xff} ** 28 ++ [_]u8{ 0x80, 0x00, 0x00, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "ABI: encodeParameters - string" {
    const values = [_]Value{.{ .string = "hello" }};
    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    // Offset (32) + length (32) + data (32 padded)
    try std.testing.expectEqual(@as(usize, 96), encoded.len);

    // Check offset
    const offset_expected = [_]u8{0} ** 31 ++ [_]u8{0x20};
    try std.testing.expectEqualSlices(u8, &offset_expected, encoded[0..32]);

    // Check length
    const length_expected = [_]u8{0} ** 31 ++ [_]u8{0x05};
    try std.testing.expectEqualSlices(u8, &length_expected, encoded[32..64]);

    // Check data
    try std.testing.expectEqualStrings("hello", encoded[64..69]);
}

test "ABI: encodeParameters - multiple types" {
    const addr = Address{ .bytes = [_]u8{0xaa} ** 20 };
    const values = [_]Value{
        .{ .uint256 = 420 },
        .{ .bool = true },
        .{ .address = addr },
    };

    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 96), encoded.len); // 3 * 32 bytes
}

test "ABI: decodeParameters - uint256" {
    const data = [_]u8{0} ** 28 ++ [_]u8{ 0x00, 0x01, 0x0f, 0x2c };
    const types = [_]Type{.uint256};

    const decoded = try decodeParameters(std.testing.allocator, &data, &types);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqual(@as(u256, 69420), decoded[0].uint256);
}

test "ABI: decodeParameters - bool" {
    // Test true
    {
        const data = [_]u8{0} ** 31 ++ [_]u8{0x01};
        const types = [_]Type{.bool};

        const decoded = try decodeParameters(std.testing.allocator, &data, &types);
        defer std.testing.allocator.free(decoded);

        try std.testing.expectEqual(true, decoded[0].bool);
    }

    // Test false
    {
        const data = [_]u8{0} ** 32;
        const types = [_]Type{.bool};

        const decoded = try decodeParameters(std.testing.allocator, &data, &types);
        defer std.testing.allocator.free(decoded);

        try std.testing.expectEqual(false, decoded[0].bool);
    }
}

test "ABI: decodeParameters - address" {
    const expected_addr = Address{ .bytes = [_]u8{0x12} ** 20 };
    const data = [_]u8{0} ** 12 ++ expected_addr.bytes;
    const types = [_]Type{.address};

    const decoded = try decodeParameters(std.testing.allocator, &data, &types);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &expected_addr.bytes, &decoded[0].address.bytes);
}

test "ABI: decodeParameters - int32 negative" {
    const data = [_]u8{0xff} ** 28 ++ [_]u8{ 0x80, 0x00, 0x00, 0x00 };
    const types = [_]Type{.int32};

    const decoded = try decodeParameters(std.testing.allocator, &data, &types);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqual(@as(i32, -2147483648), decoded[0].int32);
}

test "ABI: encodeFunctionCall - transfer" {
    const addr = Address{ .bytes = [_]u8{0x12} ** 20 };
    const values = [_]Value{
        .{ .address = addr },
        .{ .uint256 = 1000 },
    };

    const calldata = try encodeFunctionCall(
        std.testing.allocator,
        "transfer(address,uint256)",
        &values,
    );
    defer std.testing.allocator.free(calldata);

    try std.testing.expectEqual(@as(usize, 68), calldata.len); // 4 + 64 bytes

    // Check selector
    const expected_selector = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb };
    try std.testing.expectEqualSlices(u8, &expected_selector, calldata[0..4]);
}

test "ABI: encodeEventTopic - Transfer event" {
    const topic = encodeEventTopic("Transfer(address,address,uint256)");

    // Should produce a valid 32-byte hash
    try std.testing.expect(!topic.isZero());
    try std.testing.expectEqual(@as(usize, 32), topic.bytes.len);
}

test "ABI: Type.isDynamic - static types" {
    try std.testing.expect(!Type.uint256.isDynamic());
    try std.testing.expect(!Type.address.isDynamic());
    try std.testing.expect(!Type.bool.isDynamic());
    try std.testing.expect(!Type.bytes32.isDynamic());
}

test "ABI: Type.isDynamic - dynamic types" {
    try std.testing.expect(Type.string.isDynamic());
    try std.testing.expect(Type.bytes.isDynamic());
    try std.testing.expect(Type.uint256_array.isDynamic());
    try std.testing.expect(Type.address_array.isDynamic());
}

test "ABI: Type.size - various types" {
    try std.testing.expectEqual(@as(?usize, 1), Type.uint8.size());
    try std.testing.expectEqual(@as(?usize, 32), Type.uint256.size());
    try std.testing.expectEqual(@as(?usize, 20), Type.address.size());
    try std.testing.expectEqual(@as(?usize, null), Type.string.size());
}

test "ABI: Type.getType - type strings" {
    try std.testing.expectEqualStrings("uint256", Type.uint256.getType());
    try std.testing.expectEqualStrings("address", Type.address.getType());
    try std.testing.expectEqualStrings("bool", Type.bool.getType());
    try std.testing.expectEqualStrings("string", Type.string.getType());
    try std.testing.expectEqualStrings("uint256[]", Type.uint256_array.getType());
}

test "ABI: roundtrip encode/decode - multiple types" {
    const addr = Address{ .bytes = [_]u8{0xab} ** 20 };
    const original_values = [_]Value{
        .{ .uint256 = 42 },
        .{ .bool = true },
        .{ .address = addr },
    };

    const encoded = try encodeParameters(std.testing.allocator, &original_values);
    defer std.testing.allocator.free(encoded);

    const types = [_]Type{ .uint256, .bool, .address };
    const decoded = try decodeParameters(std.testing.allocator, encoded, &types);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqual(@as(u256, 42), decoded[0].uint256);
    try std.testing.expectEqual(true, decoded[1].bool);
    try std.testing.expectEqualSlices(u8, &addr.bytes, &decoded[2].address.bytes);
}

test "ABI: encodeParameters - uint256 array" {
    const array = [_]u256{ 1, 2, 3 };
    const values = [_]Value{.{ .uint256_array = &array }};

    const encoded = try encodeParameters(std.testing.allocator, &values);
    defer std.testing.allocator.free(encoded);

    // Offset (32) + length (32) + 3 elements (96) = 160 bytes
    try std.testing.expectEqual(@as(usize, 160), encoded.len);
}

test "ABI: decodeParameters - bytes" {
    // Encoded bytes "hello"
    const data = [_]u8{
        // Offset to bytes data (32)
        0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        // Length of bytes (5)
        0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
        // Bytes data "hello" padded to 32 bytes
        'h', 'e', 'l', 'l', 'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };

    const types = [_]Type{.bytes};
    const decoded = try decodeParameters(std.testing.allocator, &data, &types);
    defer {
        std.testing.allocator.free(decoded[0].bytes);
        std.testing.allocator.free(decoded);
    }

    try std.testing.expectEqualStrings("hello", decoded[0].bytes);
}

test "ABI: empty parameters" {
    const encoded = try encodeParameters(std.testing.allocator, &[_]Value{});
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 0), encoded.len);

    const decoded = try decodeParameters(std.testing.allocator, "", &[_]Type{});
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}
