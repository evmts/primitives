//! RLP (Recursive Length Prefix) - Ethereum's serialization format
//!
//! This module provides a complete implementation of RLP encoding and decoding
//! as specified in the Ethereum Yellow Paper. RLP is used throughout Ethereum
//! for serializing transactions, blocks, state, and other data structures.
//!
//! ## RLP Specification Overview
//!
//! RLP is a serialization method that encodes arbitrarily nested arrays of
//! binary data. It defines encoding rules for:
//!
//! ### String Encoding
//! - **Single byte [0x00, 0x7f]**: Encoded as itself
//! - **String [0-55 bytes]**: 0x80 + length, followed by string
//! - **Long string [55+ bytes]**: 0xb7 + length_of_length + length + string
//!
//! ### List Encoding
//! - **Short list [0-55 bytes]**: 0xc0 + length, followed by items
//! - **Long list [55+ bytes]**: 0xf7 + length_of_length + length + items
//!
//! ## Usage Examples
//!
//! ### Encoding Simple Data
//! ```zig
//! const encoded = try RLP.encode(allocator, "hello");
//! defer allocator.free(encoded);
//!
//! const list = [_][]const u8{ "cat", "dog" };
//! const encoded_list = try RLP.encode(allocator, list);
//! defer allocator.free(encoded_list);
//! ```
//!
//! ### Decoding RLP Data
//! ```zig
//! const decoded = try RLP.decode(allocator, encoded_data, false);
//! defer decoded.data.deinit(allocator);
//!
//! switch (decoded.data) {
//!     .String => |str| std.log.info("String: {s}", .{str}),
//!     .List => |items| std.log.info("List with {} items", .{items.len}),
//! }
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RLP = @This();

// Error types
pub const Error = error{
    InputTooShort,
    InputTooLong,
    InvalidLength,
    NonCanonical,
    InvalidRemainder,
    LeadingZeros,
} || Allocator.Error;

pub const Data = union(enum) {
    String: []const u8,
    List: []Data,

    /// Free allocated memory
    pub fn deinit(self: Data, allocator: Allocator) void {
        switch (self) {
            .List => |items| {
                for (items) |item| {
                    item.deinit(allocator);
                }
                allocator.free(items);
            },
            .String => |value| {
                allocator.free(value);
            },
        }
    }
};

pub const Decoded = struct {
    data: Data,
    remainder: []const u8,
};

/// Encode any value to RLP
pub fn encode(allocator: Allocator, input: anytype) Error![]u8 {
    const T = @TypeOf(input);
    const info = @typeInfo(T);

    // Handle byte arrays and slices
    if (info == .array) {
        const child_info = @typeInfo(info.array.child);
        if (child_info == .int and child_info.int.bits == 8) {
            return try encodeBytes(allocator, &input);
        }
    } else if (info == .pointer) {
        const child_info = @typeInfo(info.pointer.child);
        if (child_info == .int and child_info.int.bits == 8) {
            return try encodeBytes(allocator, input);
        } else if (child_info == .array) {
            const elem_info = @typeInfo(child_info.array.child);
            if (elem_info == .int and elem_info.int.bits == 8) {
                // Handle string literals like "a" which are *const [N:0]u8
                return try encodeBytes(allocator, input);
            }
        }
    }

    // Handle lists
    if (info == .array or info == .pointer) {
        var result = std.ArrayList(u8){};
        defer result.deinit(allocator);

        // First encode each element
        var encoded_items = std.ArrayList([]u8){};
        defer {
            for (encoded_items.items) |item| {
                allocator.free(item);
            }
            encoded_items.deinit(allocator);
        }

        var total_len: usize = 0;
        for (input) |item| {
            const encoded_item = try encode(allocator, item);
            try encoded_items.append(allocator, encoded_item);
            total_len += encoded_item.len;
        }

        // Calculate header
        if (total_len < 56) {
            try result.append(allocator, 0xc0 + @as(u8, @intCast(total_len)));
        } else {
            const len_bytes = try encodeLength(allocator, total_len);
            defer allocator.free(len_bytes);
            try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
            try result.appendSlice(allocator, len_bytes);
        }

        // Append encoded items
        for (encoded_items.items) |item| {
            try result.appendSlice(allocator, item);
        }

        return try result.toOwnedSlice(allocator);
    }

    // Handle comptime integers
    if (info == .comptime_int) {
        const value_u64: u64 = input;
        return try encode(allocator, value_u64);
    }

    // Handle integers
    if (info == .int) {
        if (input == 0) {
            // Special case: 0 is encoded as empty string
            const result = try allocator.alloc(u8, 1);
            result[0] = 0x80;
            return result;
        }

        var bytes = std.ArrayList(u8){};
        defer bytes.deinit(allocator);

        var value = input;
        while (value > 0) {
            try bytes.insert(allocator, 0, @as(u8, @intCast(value & 0xff)));
            if (@TypeOf(value) == u8) {
                value = 0;
            } else {
                value = @divTrunc(value, @as(@TypeOf(value), 256));
            }
        }

        return try encodeBytes(allocator, bytes.items);
    }

    @compileError("Unsupported type for RLP encoding: " ++ @typeName(T));
}

/// Encode bytes to RLP
pub fn encodeBytes(allocator: Allocator, bytes: []const u8) Error![]u8 {
    // If a single byte less than 0x80, return as is
    if (bytes.len == 1 and bytes[0] < 0x80) {
        const result = try allocator.alloc(u8, 1);
        result[0] = bytes[0];
        return result;
    }

    // If string is 0-55 bytes long, return [0x80+len, data]
    if (bytes.len < 56) {
        const result = try allocator.alloc(u8, 1 + bytes.len);
        result[0] = 0x80 + @as(u8, @intCast(bytes.len));
        @memcpy(result[1..], bytes);
        return result;
    }

    // If string is >55 bytes long, return [0xb7+len(len(data)), len(data), data]
    const len_bytes = try encodeLength(allocator, bytes.len);
    defer allocator.free(len_bytes);

    const result = try allocator.alloc(u8, 1 + len_bytes.len + bytes.len);
    result[0] = 0xb7 + @as(u8, @intCast(len_bytes.len));
    @memcpy(result[1 .. 1 + len_bytes.len], len_bytes);
    @memcpy(result[1 + len_bytes.len ..], bytes);

    return result;
}

/// Encode list of byte arrays to RLP
pub fn encodeList(allocator: Allocator, items: []const []const u8) Error![]u8 {
    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    // First encode each element
    var encoded_items = std.ArrayList([]u8){};
    defer {
        for (encoded_items.items) |item| {
            allocator.free(item);
        }
        encoded_items.deinit(allocator);
    }

    var total_len: usize = 0;
    for (items) |item| {
        const encoded_item = try encodeBytes(allocator, item);
        try encoded_items.append(allocator, encoded_item);
        total_len += encoded_item.len;
    }

    // Calculate header
    if (total_len < 56) {
        try result.append(allocator, 0xc0 + @as(u8, @intCast(total_len)));
    } else {
        const len_bytes = try encodeLength(allocator, total_len);
        defer allocator.free(len_bytes);
        try result.append(allocator, 0xf7 + @as(u8, @intCast(len_bytes.len)));
        try result.appendSlice(allocator, len_bytes);
    }

    // Append encoded items
    for (encoded_items.items) |item| {
        try result.appendSlice(allocator, item);
    }

    return try result.toOwnedSlice(allocator);
}

/// Encode an integer length as bytes
fn encodeLength(allocator: Allocator, length: usize) ![]u8 {
    var len_bytes = std.ArrayList(u8){};
    defer len_bytes.deinit(allocator);

    var temp = length;
    while (temp > 0) {
        try len_bytes.insert(allocator, 0, @as(u8, @intCast(temp & 0xff)));
        temp >>= 8;
    }

    return try len_bytes.toOwnedSlice(allocator);
}

/// Decode RLP data
pub fn decode(allocator: Allocator, input: []const u8, stream: bool) Error!Decoded {
    if (input.len == 0) {
        return Decoded{
            .data = Data{ .String = try allocator.dupe(u8, &.{}) },
            .remainder = &.{},
        };
    }

    const result = try decodeInternal(allocator, input);

    if (!stream and result.remainder.len > 0) {
        result.data.deinit(allocator);
        return Error.InvalidRemainder;
    }

    return result;
}

fn decodeInternal(allocator: Allocator, input: []const u8) Error!Decoded {
    if (input.len == 0) {
        return Error.InputTooShort;
    }

    const prefix = input[0];

    // Single byte (0x00 - 0x7f)
    if (prefix <= 0x7f) {
        const result = try allocator.alloc(u8, 1);
        result[0] = prefix;
        return Decoded{
            .data = Data{ .String = result },
            .remainder = input[1..],
        };
    }

    // String 0-55 bytes (0x80 - 0xb7)
    if (prefix <= 0xb7) {
        const length = prefix - 0x80;

        if (input.len - 1 < length) {
            return Error.InputTooShort;
        }

        // Empty string
        if (prefix == 0x80) {
            return Decoded{
                .data = Data{ .String = try allocator.dupe(u8, &.{}) },
                .remainder = input[1..],
            };
        }

        // Enforce canonical representation: single byte < 0x80 should be encoded as itself
        if (length == 1 and input[1] < 0x80) {
            return Error.NonCanonical;
        }

        const data = try allocator.alloc(u8, length);
        @memcpy(data, input[1 .. 1 + length]);

        return Decoded{
            .data = Data{ .String = data },
            .remainder = input[1 + length ..],
        };
    }

    // String > 55 bytes (0xb8 - 0xbf)
    if (prefix <= 0xbf) {
        const length_of_length = prefix - 0xb7;

        if (input.len - 1 < length_of_length) {
            return Error.InputTooShort;
        }

        // Check for leading zeros in the length
        if (input[1] == 0) {
            return Error.LeadingZeros;
        }

        var total_length: usize = 0;
        for (input[1 .. 1 + length_of_length]) |byte| {
            total_length = (total_length << 8) + byte;
        }

        // Enforce canonical representation: if length < 56, should use the short form
        if (total_length < 56) {
            return Error.NonCanonical;
        }

        if (input.len - 1 - length_of_length < total_length) {
            return Error.InputTooShort;
        }

        const data = try allocator.alloc(u8, total_length);
        @memcpy(data, input[1 + length_of_length .. 1 + length_of_length + total_length]);

        return Decoded{
            .data = Data{ .String = data },
            .remainder = input[1 + length_of_length + total_length ..],
        };
    }

    // List 0-55 bytes (0xc0 - 0xf7)
    if (prefix <= 0xf7) {
        const length = prefix - 0xc0;

        if (input.len - 1 < length) {
            return Error.InputTooShort;
        }

        if (length == 0) {
            return Decoded{
                .data = Data{ .List = try allocator.alloc(Data, 0) },
                .remainder = input[1..],
            };
        }

        var items = std.ArrayList(Data){};
        errdefer {
            for (items.items) |item| {
                item.deinit(allocator);
            }
            items.deinit(allocator);
        }

        var remaining = input[1 .. 1 + length];
        while (remaining.len > 0) {
            const decoded = try decodeInternal(allocator, remaining);
            try items.append(allocator, decoded.data);
            remaining = decoded.remainder;
        }

        return Decoded{
            .data = Data{ .List = try items.toOwnedSlice(allocator) },
            .remainder = input[1 + length ..],
        };
    }

    // List > 55 bytes (0xf8 - 0xff)
    if (prefix <= 0xff) {
        const length_of_length = prefix - 0xf7;

        if (input.len - 1 < length_of_length) {
            return Error.InputTooShort;
        }

        // Check for leading zeros in the length
        if (input[1] == 0) {
            return Error.LeadingZeros;
        }

        var total_length: usize = 0;
        for (input[1 .. 1 + length_of_length]) |byte| {
            total_length = (total_length << 8) + byte;
        }

        // Enforce canonical representation: if length < 56, should use the short form
        if (total_length < 56) {
            return Error.NonCanonical;
        }

        if (input.len - 1 - length_of_length < total_length) {
            return Error.InputTooShort;
        }

        var items = std.ArrayList(Data){};
        errdefer {
            for (items.items) |item| {
                item.deinit(allocator);
            }
            items.deinit(allocator);
        }

        var remaining = input[1 + length_of_length .. 1 + length_of_length + total_length];
        while (remaining.len > 0) {
            const decoded = try decodeInternal(allocator, remaining);
            try items.append(allocator, decoded.data);
            remaining = decoded.remainder;
        }

        return Decoded{
            .data = Data{ .List = try items.toOwnedSlice(allocator) },
            .remainder = input[1 + length_of_length + total_length ..],
        };
    }

    unreachable;
}

/// Get encoded length without encoding
pub fn encodedLength(input: anytype) usize {
    const T = @TypeOf(input);
    const info = @typeInfo(T);

    // Handle byte arrays and slices
    if (info == .array) {
        const child_info = @typeInfo(info.array.child);
        if (child_info == .int and child_info.int.bits == 8) {
            return encodedBytesLength(input.len);
        }
    } else if (info == .pointer) {
        const child_info = @typeInfo(info.pointer.child);
        if (child_info == .int and child_info.int.bits == 8) {
            return encodedBytesLength(input.len);
        } else if (child_info == .array) {
            const elem_info = @typeInfo(child_info.array.child);
            if (elem_info == .int and elem_info.int.bits == 8) {
                return encodedBytesLength(input.len);
            }
        }
    }

    // Handle lists
    if (info == .array or info == .pointer) {
        var total_len: usize = 0;
        for (input) |item| {
            total_len += encodedLength(item);
        }
        return encodedListLength(total_len);
    }

    // Handle integers
    if (info == .int) {
        if (input == 0) {
            return 1; // Encoded as 0x80
        }
        var byte_len: usize = 0;
        var value = input;
        while (value > 0) {
            byte_len += 1;
            value = @divTrunc(value, 256);
        }
        return encodedBytesLength(byte_len);
    }

    // Handle comptime integers
    if (info == .comptime_int) {
        const value_u64: u64 = input;
        return encodedLength(value_u64);
    }

    @compileError("Unsupported type for RLP encodedLength: " ++ @typeName(T));
}

fn encodedBytesLength(byte_len: usize) usize {
    if (byte_len == 1) {
        return 1; // Could be 1 if < 0x80, but we assume worst case
    }
    if (byte_len < 56) {
        return 1 + byte_len;
    }
    const len_len = lengthOfLength(byte_len);
    return 1 + len_len + byte_len;
}

fn encodedListLength(content_len: usize) usize {
    if (content_len < 56) {
        return 1 + content_len;
    }
    const len_len = lengthOfLength(content_len);
    return 1 + len_len + content_len;
}

fn lengthOfLength(len: usize) usize {
    var count: usize = 0;
    var temp = len;
    while (temp > 0) {
        count += 1;
        temp >>= 8;
    }
    return count;
}

/// Check if data represents a list
pub fn isList(data: []const u8) bool {
    if (data.len == 0) {
        return false;
    }
    return data[0] >= 0xc0;
}

// Tests
test "RLP single byte" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const single_byte = "a";
    const encoded = try encode(allocator, single_byte);
    defer allocator.free(encoded);

    try testing.expectEqualSlices(u8, &[_]u8{'a'}, encoded);

    const decoded = try decode(allocator, encoded, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .String => |str| try testing.expectEqualSlices(u8, &[_]u8{'a'}, str),
        .List => unreachable,
    }
}

test "RLP string 0-55 bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const dog_str = "dog";
    const encoded = try encode(allocator, dog_str);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 4), encoded.len);
    try testing.expectEqual(@as(u8, 131), encoded[0]);
    try testing.expectEqual(@as(u8, 'd'), encoded[1]);
    try testing.expectEqual(@as(u8, 'o'), encoded[2]);
    try testing.expectEqual(@as(u8, 'g'), encoded[3]);

    const decoded = try decode(allocator, encoded, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .String => |str| try testing.expectEqualSlices(u8, dog_str, str),
        .List => unreachable,
    }
}

test "RLP string >55 bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const long_str = "zoo255zoo255zzzzzzzzzzzzssssssssssssssssssssssssssssssssssssssssssssss";
    const encoded = try encode(allocator, long_str);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 72), encoded.len);
    try testing.expectEqual(@as(u8, 184), encoded[0]);
    try testing.expectEqual(@as(u8, 70), encoded[1]);

    const decoded = try decode(allocator, encoded, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .String => |str| try testing.expectEqualSlices(u8, long_str, str),
        .List => unreachable,
    }
}

test "RLP list 0-55 bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const list = [_][]const u8{ "dog", "god", "cat" };

    const encoded_list = try encode(allocator, list[0..]);
    defer allocator.free(encoded_list);

    try testing.expectEqual(@as(usize, 13), encoded_list.len);
    try testing.expectEqual(@as(u8, 204), encoded_list[0]);

    const decoded = try decode(allocator, encoded_list, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .List => |items| {
            try testing.expectEqual(@as(usize, 3), items.len);
            for (items, 0..) |item, i| {
                switch (item) {
                    .String => |str| try testing.expectEqualSlices(u8, list[i], str),
                    .List => unreachable,
                }
            }
        },
        .String => unreachable,
    }
}

test "RLP integers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Single byte integer
    {
        const encoded = try encode(allocator, 15);
        defer allocator.free(encoded);

        try testing.expectEqual(@as(usize, 1), encoded.len);
        try testing.expectEqual(@as(u8, 15), encoded[0]);

        const decoded = try decode(allocator, encoded, false);
        defer decoded.data.deinit(allocator);

        switch (decoded.data) {
            .String => |str| {
                try testing.expectEqual(@as(usize, 1), str.len);
                try testing.expectEqual(@as(u8, 15), str[0]);
            },
            .List => unreachable,
        }
    }

    // Multi-byte integer
    {
        const encoded = try encode(allocator, 1024);
        defer allocator.free(encoded);

        try testing.expectEqual(@as(usize, 3), encoded.len);
        try testing.expectEqual(@as(u8, 130), encoded[0]);
        try testing.expectEqual(@as(u8, 4), encoded[1]);
        try testing.expectEqual(@as(u8, 0), encoded[2]);

        const decoded = try decode(allocator, encoded, false);
        defer decoded.data.deinit(allocator);

        switch (decoded.data) {
            .String => |str| {
                try testing.expectEqual(@as(usize, 2), str.len);
                try testing.expectEqual(@as(u8, 4), str[0]);
                try testing.expectEqual(@as(u8, 0), str[1]);
            },
            .List => unreachable,
        }
    }

    // Zero
    {
        const encoded = try encode(allocator, 0);
        defer allocator.free(encoded);

        try testing.expectEqual(@as(usize, 1), encoded.len);
        try testing.expectEqual(@as(u8, 0x80), encoded[0]);

        const decoded = try decode(allocator, encoded, false);
        defer decoded.data.deinit(allocator);

        switch (decoded.data) {
            .String => |str| try testing.expectEqual(@as(usize, 0), str.len),
            .List => unreachable,
        }
    }
}

test "RLP empty string" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const empty = "";
    const encoded = try encode(allocator, empty);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 1), encoded.len);
    try testing.expectEqual(@as(u8, 0x80), encoded[0]);

    const decoded = try decode(allocator, encoded, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .String => |str| try testing.expectEqual(@as(usize, 0), str.len),
        .List => unreachable,
    }
}

test "RLP empty list" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const list = [_][]const u8{};
    const encoded = try encode(allocator, list[0..]);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 1), encoded.len);
    try testing.expectEqual(@as(u8, 0xc0), encoded[0]);

    const decoded = try decode(allocator, encoded, false);
    defer decoded.data.deinit(allocator);

    switch (decoded.data) {
        .List => |items| try testing.expectEqual(@as(usize, 0), items.len),
        .String => unreachable,
    }
}

test "RLP isList" {
    const testing = std.testing;

    try testing.expect(!isList(&[_]u8{0x7f}));
    try testing.expect(!isList(&[_]u8{0x80}));
    try testing.expect(!isList(&[_]u8{0xb7}));
    try testing.expect(!isList(&[_]u8{0xbf}));
    try testing.expect(isList(&[_]u8{0xc0}));
    try testing.expect(isList(&[_]u8{0xf7}));
    try testing.expect(isList(&[_]u8{0xff}));
}

test "RLP encodeBytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Single byte < 0x80
    {
        const encoded = try encodeBytes(allocator, &[_]u8{0x05});
        defer allocator.free(encoded);
        try testing.expectEqualSlices(u8, &[_]u8{0x05}, encoded);
    }

    // Short string
    {
        const encoded = try encodeBytes(allocator, "hello");
        defer allocator.free(encoded);
        try testing.expectEqual(@as(usize, 6), encoded.len);
        try testing.expectEqual(@as(u8, 0x85), encoded[0]);
    }
}

test "RLP encodeList" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const items = [_][]const u8{ "cat", "dog" };
    const encoded = try encodeList(allocator, &items);
    defer allocator.free(encoded);

    try testing.expect(encoded.len > 0);
    try testing.expect(encoded[0] >= 0xc0);
}

test "RLP stream decoding" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create multiple encoded items
    const encoded1 = try encode(allocator, "cat");
    defer allocator.free(encoded1);

    const encoded2 = try encode(allocator, "dog");
    defer allocator.free(encoded2);

    // Concatenate them
    const stream = try std.mem.concat(allocator, u8, &[_][]const u8{ encoded1, encoded2 });
    defer allocator.free(stream);

    // Decode first item with stream mode
    const decoded1 = try decode(allocator, stream, true);
    defer decoded1.data.deinit(allocator);

    switch (decoded1.data) {
        .String => |str| try testing.expectEqualSlices(u8, "cat", str),
        .List => unreachable,
    }

    // Decode second item
    const decoded2 = try decode(allocator, decoded1.remainder, true);
    defer decoded2.data.deinit(allocator);

    switch (decoded2.data) {
        .String => |str| try testing.expectEqualSlices(u8, "dog", str),
        .List => unreachable,
    }

    try testing.expectEqual(@as(usize, 0), decoded2.remainder.len);
}

test "RLP encodedLength" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test string
    {
        const str = "dog";
        const expected = encodedLength(str);
        const encoded = try encode(allocator, str);
        defer allocator.free(encoded);
        try testing.expectEqual(encoded.len, expected);
    }

    // Test integer
    {
        const val = 1024;
        const expected = encodedLength(val);
        const encoded = try encode(allocator, val);
        defer allocator.free(encoded);
        try testing.expectEqual(encoded.len, expected);
    }

    // Test list
    {
        const list = [_][]const u8{ "cat", "dog" };
        const expected = encodedLength(list[0..]);
        const encoded = try encode(allocator, list[0..]);
        defer allocator.free(encoded);
        try testing.expectEqual(encoded.len, expected);
    }
}
