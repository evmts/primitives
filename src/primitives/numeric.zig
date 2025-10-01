const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Numeric = @This();

// Unit constants
pub const WEI: u256 = 1;
pub const KWEI: u256 = 1_000;
pub const MWEI: u256 = 1_000_000;
pub const GWEI: u256 = 1_000_000_000;
pub const SZABO: u256 = 1_000_000_000_000;
pub const FINNEY: u256 = 1_000_000_000_000_000;
pub const ETHER: u256 = 1_000_000_000_000_000_000;

// Error types
pub const Error = error{
    InvalidInput,
    InvalidUnit,
    InvalidFormat,
    ValueTooLarge,
} || Allocator.Error;

pub const Unit = enum {
    wei,
    kwei,
    mwei,
    gwei,
    szabo,
    finney,
    ether,

    /// Get multiplier for this unit
    pub fn toMultiplier(self: Unit) u256 {
        return switch (self) {
            .wei => WEI,
            .kwei => KWEI,
            .mwei => MWEI,
            .gwei => GWEI,
            .szabo => SZABO,
            .finney => FINNEY,
            .ether => ETHER,
        };
    }

    /// Parse unit from string
    pub fn fromString(str: []const u8) ?Unit {
        if (std.mem.eql(u8, str, "wei")) return .wei;
        if (std.mem.eql(u8, str, "kwei")) return .kwei;
        if (std.mem.eql(u8, str, "mwei")) return .mwei;
        if (std.mem.eql(u8, str, "gwei")) return .gwei;
        if (std.mem.eql(u8, str, "szabo")) return .szabo;
        if (std.mem.eql(u8, str, "finney")) return .finney;
        if (std.mem.eql(u8, str, "ether")) return .ether;
        return null;
    }

    /// Convert unit to string
    pub fn toString(self: Unit) []const u8 {
        return switch (self) {
            .wei => "wei",
            .kwei => "kwei",
            .mwei => "mwei",
            .gwei => "gwei",
            .szabo => "szabo",
            .finney => "finney",
            .ether => "ether",
        };
    }
};

/// Parse ether string to wei (e.g., "1.5" -> 1500000000000000000)
pub fn parseEther(ether_str: []const u8) Error!u256 {
    return parseUnits(ether_str, .ether);
}

/// Parse gwei string to wei
pub fn parseGwei(gwei_str: []const u8) Error!u256 {
    return parseUnits(gwei_str, .gwei);
}

/// Parse value with specified unit to wei
pub fn parseUnits(value_str: []const u8, unit: Unit) Error!u256 {
    const trimmed = std.mem.trim(u8, value_str, " \t\n\r");
    if (trimmed.len == 0) return Error.InvalidInput;

    // Handle decimal point
    if (std.mem.indexOf(u8, trimmed, ".")) |dot_pos| {
        const integer_part = trimmed[0..dot_pos];
        const decimal_part = trimmed[dot_pos + 1 ..];

        // Parse integer part
        var integer_value: u256 = 0;
        if (integer_part.len > 0) {
            integer_value = try parseInteger(integer_part);
        }

        // Parse decimal part
        var decimal_value: u256 = 0;
        if (decimal_part.len > 0) {
            decimal_value = try parseDecimal(decimal_part, unit);
        }

        const multiplier = unit.toMultiplier();
        const integer_wei = integer_value * multiplier;

        return integer_wei + decimal_value;
    } else {
        // No decimal point, just parse as integer
        const integer_value = try parseInteger(trimmed);
        const multiplier = unit.toMultiplier();
        return integer_value * multiplier;
    }
}

/// Format wei value to ether string
pub fn formatEther(allocator: Allocator, wei_value: u256) Error![]u8 {
    return formatUnits(allocator, wei_value, .ether, null);
}

/// Format wei value to gwei string
pub fn formatGwei(allocator: Allocator, wei_value: u256) Error![]u8 {
    return formatUnits(allocator, wei_value, .gwei, null);
}

/// Format wei value to specified unit
pub fn formatUnits(allocator: Allocator, wei_value: u256, unit: Unit, decimals: ?u8) Error![]u8 {
    const multiplier = unit.toMultiplier();
    const unit_name = unit.toString();

    // Calculate integer and fractional parts
    const integer_part = wei_value / multiplier;
    const remainder = wei_value % multiplier;

    if (remainder == 0) {
        // No fractional part
        return std.fmt.allocPrint(allocator, "{} {s}", .{ integer_part, unit_name });
    }

    // Calculate decimal places needed
    const max_decimals = decimals orelse getDefaultDecimals(unit);
    const decimal_str = try formatDecimalPart(allocator, remainder, multiplier, max_decimals);
    defer allocator.free(decimal_str);

    if (std.mem.eql(u8, decimal_str, "0")) {
        return std.fmt.allocPrint(allocator, "{} {s}", .{ integer_part, unit_name });
    }

    return std.fmt.allocPrint(allocator, "{}.{s} {s}", .{ integer_part, decimal_str, unit_name });
}

/// Convert between units
pub fn convertUnits(value: u256, from_unit: Unit, to_unit: Unit) Error!u256 {
    const from_multiplier = from_unit.toMultiplier();
    const to_multiplier = to_unit.toMultiplier();

    // Convert to wei first
    const wei_value = value * from_multiplier;

    // Then convert to target unit
    return wei_value / to_multiplier;
}

/// Calculate gas cost in wei
pub fn calculateGasCost(gas_used: u64, gas_price_gwei: u256) u256 {
    const gas_price_wei = gas_price_gwei * GWEI;
    return @as(u256, gas_used) * gas_price_wei;
}

/// Format gas cost as ether string
pub fn formatGasCost(allocator: Allocator, gas_used: u64, gas_price_gwei: u256) Error![]u8 {
    const cost_wei = calculateGasCost(gas_used, gas_price_gwei);
    return formatEther(allocator, cost_wei);
}

// Helper functions
fn parseInteger(str: []const u8) Error!u256 {
    if (str.len == 0) return 0;

    return std.fmt.parseInt(u256, str, 10) catch |err| switch (err) {
        error.Overflow => Error.ValueTooLarge,
        error.InvalidCharacter => Error.InvalidInput,
    };
}

fn parseDecimal(decimal_str: []const u8, unit: Unit) Error!u256 {
    if (decimal_str.len == 0) return 0;

    const multiplier = unit.toMultiplier();
    var result: u256 = 0;
    var place_value = multiplier / 10;

    for (decimal_str) |c| {
        if (c < '0' or c > '9') return Error.InvalidInput;
        if (place_value == 0) break; // No more precision available

        const digit = c - '0';
        result += @as(u256, digit) * place_value;
        place_value /= 10;
    }

    return result;
}

fn formatDecimalPart(allocator: Allocator, remainder: u256, multiplier: u256, max_decimals: u8) Error![]u8 {
    var decimal_chars: std.ArrayList(u8) = .{};
    defer decimal_chars.deinit(allocator);

    var current_remainder = remainder;
    var current_multiplier = multiplier;
    var decimals_added: u8 = 0;

    while (current_remainder > 0 and decimals_added < max_decimals) {
        current_multiplier /= 10;
        if (current_multiplier == 0) break;

        const digit = current_remainder / current_multiplier;
        try decimal_chars.append(allocator, @as(u8, @intCast(digit)) + '0');
        current_remainder %= current_multiplier;
        decimals_added += 1;
    }

    // Remove trailing zeros
    while (decimal_chars.items.len > 0 and decimal_chars.items[decimal_chars.items.len - 1] == '0') {
        _ = decimal_chars.pop();
    }

    if (decimal_chars.items.len == 0) {
        return allocator.dupe(u8, "0");
    }

    return decimal_chars.toOwnedSlice(allocator);
}

fn getDefaultDecimals(unit: Unit) u8 {
    return switch (unit) {
        .wei => 0,
        .kwei => 3,
        .mwei => 6,
        .gwei => 9,
        .szabo => 12,
        .finney => 15,
        .ether => 18,
    };
}

// Tests
const testing = std.testing;

test "unit constants" {
    try testing.expectEqual(@as(u256, 1), WEI);
    try testing.expectEqual(@as(u256, 1_000), KWEI);
    try testing.expectEqual(@as(u256, 1_000_000), MWEI);
    try testing.expectEqual(@as(u256, 1_000_000_000), GWEI);
    try testing.expectEqual(@as(u256, 1_000_000_000_000), SZABO);
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000), FINNEY);
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), ETHER);
}

test "Unit.toMultiplier" {
    try testing.expectEqual(WEI, Unit.wei.toMultiplier());
    try testing.expectEqual(KWEI, Unit.kwei.toMultiplier());
    try testing.expectEqual(MWEI, Unit.mwei.toMultiplier());
    try testing.expectEqual(GWEI, Unit.gwei.toMultiplier());
    try testing.expectEqual(SZABO, Unit.szabo.toMultiplier());
    try testing.expectEqual(FINNEY, Unit.finney.toMultiplier());
    try testing.expectEqual(ETHER, Unit.ether.toMultiplier());
}

test "Unit.fromString" {
    try testing.expectEqual(Unit.wei, Unit.fromString("wei").?);
    try testing.expectEqual(Unit.kwei, Unit.fromString("kwei").?);
    try testing.expectEqual(Unit.mwei, Unit.fromString("mwei").?);
    try testing.expectEqual(Unit.gwei, Unit.fromString("gwei").?);
    try testing.expectEqual(Unit.szabo, Unit.fromString("szabo").?);
    try testing.expectEqual(Unit.finney, Unit.fromString("finney").?);
    try testing.expectEqual(Unit.ether, Unit.fromString("ether").?);
    try testing.expectEqual(@as(?Unit, null), Unit.fromString("invalid"));
}

test "Unit.toString" {
    try testing.expectEqualStrings("wei", Unit.wei.toString());
    try testing.expectEqualStrings("kwei", Unit.kwei.toString());
    try testing.expectEqualStrings("mwei", Unit.mwei.toString());
    try testing.expectEqualStrings("gwei", Unit.gwei.toString());
    try testing.expectEqualStrings("szabo", Unit.szabo.toString());
    try testing.expectEqualStrings("finney", Unit.finney.toString());
    try testing.expectEqualStrings("ether", Unit.ether.toString());
}

test "parseEther - integer values" {
    const result1 = try parseEther("1");
    try testing.expectEqual(ETHER, result1);

    const result2 = try parseEther("2");
    try testing.expectEqual(2 * ETHER, result2);

    const result3 = try parseEther("100");
    try testing.expectEqual(100 * ETHER, result3);
}

test "parseEther - decimal values" {
    const result1 = try parseEther("1.5");
    try testing.expectEqual(ETHER + ETHER / 2, result1);

    const result2 = try parseEther("0.001");
    try testing.expectEqual(FINNEY, result2);

    const result3 = try parseEther("0.000000001");
    try testing.expectEqual(GWEI, result3);

    const result4 = try parseEther("2.25");
    try testing.expectEqual(2 * ETHER + ETHER / 4, result4);
}

test "parseEther - edge cases" {
    const result1 = try parseEther("0");
    try testing.expectEqual(@as(u256, 0), result1);

    const result2 = try parseEther("0.0");
    try testing.expectEqual(@as(u256, 0), result2);

    const result3 = try parseEther("  1.5  ");
    try testing.expectEqual(ETHER + ETHER / 2, result3);
}

test "parseGwei - integer values" {
    const result1 = try parseGwei("1");
    try testing.expectEqual(GWEI, result1);

    const result2 = try parseGwei("20");
    try testing.expectEqual(20 * GWEI, result2);

    const result3 = try parseGwei("100");
    try testing.expectEqual(100 * GWEI, result3);
}

test "parseGwei - decimal values" {
    const result1 = try parseGwei("0.5");
    try testing.expectEqual(GWEI / 2, result1);

    const result2 = try parseGwei("1.5");
    try testing.expectEqual(GWEI + GWEI / 2, result2);
}

test "parseUnits - various units" {
    const wei_result = try parseUnits("1000", .wei);
    try testing.expectEqual(@as(u256, 1000), wei_result);

    const kwei_result = try parseUnits("1", .kwei);
    try testing.expectEqual(KWEI, kwei_result);

    const mwei_result = try parseUnits("1", .mwei);
    try testing.expectEqual(MWEI, mwei_result);

    const szabo_result = try parseUnits("1", .szabo);
    try testing.expectEqual(SZABO, szabo_result);

    const finney_result = try parseUnits("1", .finney);
    try testing.expectEqual(FINNEY, finney_result);
}

test "parseUnits - error cases" {
    try testing.expectError(Error.InvalidInput, parseUnits("", .ether));
    try testing.expectError(Error.InvalidInput, parseUnits("   ", .ether));
    try testing.expectError(Error.InvalidInput, parseUnits("abc", .ether));
    try testing.expectError(Error.InvalidInput, parseUnits("1.2.3", .ether));
}

test "formatEther - integer values" {
    const allocator = testing.allocator;

    const result1 = try formatEther(allocator, ETHER);
    defer allocator.free(result1);
    try testing.expectEqualStrings("1 ether", result1);

    const result2 = try formatEther(allocator, 2 * ETHER);
    defer allocator.free(result2);
    try testing.expectEqualStrings("2 ether", result2);

    const result3 = try formatEther(allocator, 100 * ETHER);
    defer allocator.free(result3);
    try testing.expectEqualStrings("100 ether", result3);
}

test "formatEther - decimal values" {
    const allocator = testing.allocator;

    const result1 = try formatEther(allocator, ETHER + ETHER / 2);
    defer allocator.free(result1);
    try testing.expectEqualStrings("1.5 ether", result1);

    const result2 = try formatEther(allocator, FINNEY);
    defer allocator.free(result2);
    try testing.expectEqualStrings("0.001 ether", result2);

    const result3 = try formatEther(allocator, GWEI);
    defer allocator.free(result3);
    try testing.expectEqualStrings("0.000000001 ether", result3);
}

test "formatEther - zero value" {
    const allocator = testing.allocator;

    const result = try formatEther(allocator, 0);
    defer allocator.free(result);
    try testing.expectEqualStrings("0 ether", result);
}

test "formatGwei - integer values" {
    const allocator = testing.allocator;

    const result1 = try formatGwei(allocator, GWEI);
    defer allocator.free(result1);
    try testing.expectEqualStrings("1 gwei", result1);

    const result2 = try formatGwei(allocator, 20 * GWEI);
    defer allocator.free(result2);
    try testing.expectEqualStrings("20 gwei", result2);
}

test "formatGwei - decimal values" {
    const allocator = testing.allocator;

    const result1 = try formatGwei(allocator, GWEI / 2);
    defer allocator.free(result1);
    try testing.expectEqualStrings("0.5 gwei", result1);

    const result2 = try formatGwei(allocator, GWEI + GWEI / 2);
    defer allocator.free(result2);
    try testing.expectEqualStrings("1.5 gwei", result2);
}

test "formatUnits - various units" {
    const allocator = testing.allocator;

    const wei_result = try formatUnits(allocator, 1000, .wei, null);
    defer allocator.free(wei_result);
    try testing.expectEqualStrings("1000 wei", wei_result);

    const kwei_result = try formatUnits(allocator, KWEI, .kwei, null);
    defer allocator.free(kwei_result);
    try testing.expectEqualStrings("1 kwei", kwei_result);

    const mwei_result = try formatUnits(allocator, MWEI, .mwei, null);
    defer allocator.free(mwei_result);
    try testing.expectEqualStrings("1 mwei", mwei_result);
}

test "formatUnits - custom decimals" {
    const allocator = testing.allocator;

    // Format with 2 decimal places
    const result1 = try formatUnits(allocator, ETHER + ETHER / 2, .ether, 2);
    defer allocator.free(result1);
    try testing.expectEqualStrings("1.5 ether", result1);

    // Format with 0 decimal places (should show integer only)
    const result2 = try formatUnits(allocator, ETHER + ETHER / 2, .ether, 0);
    defer allocator.free(result2);
    try testing.expectEqualStrings("1 ether", result2);
}

test "convertUnits - ether to gwei" {
    const result = try convertUnits(1, .ether, .gwei);
    try testing.expectEqual(@as(u256, 1_000_000_000), result);
}

test "convertUnits - gwei to ether" {
    const result1 = try convertUnits(1000, .gwei, .ether);
    try testing.expectEqual(@as(u256, 0), result1); // Less than 1 ether

    const result2 = try convertUnits(1_000_000_000, .gwei, .ether);
    try testing.expectEqual(@as(u256, 1), result2);
}

test "convertUnits - wei to ether" {
    const result = try convertUnits(ETHER, .wei, .ether);
    try testing.expectEqual(@as(u256, 1), result);
}

test "convertUnits - same unit" {
    const result = try convertUnits(100, .gwei, .gwei);
    try testing.expectEqual(@as(u256, 100), result);
}

test "calculateGasCost" {
    const gas_used: u64 = 21000;
    const gas_price_gwei: u256 = 20;

    const cost = calculateGasCost(gas_used, gas_price_gwei);
    try testing.expectEqual(@as(u256, 21000) * 20 * GWEI, cost);
}

test "calculateGasCost - high gas price" {
    const gas_used: u64 = 100000;
    const gas_price_gwei: u256 = 100;

    const cost = calculateGasCost(gas_used, gas_price_gwei);
    try testing.expectEqual(@as(u256, 100000) * 100 * GWEI, cost);
}

test "formatGasCost" {
    const allocator = testing.allocator;
    const gas_used: u64 = 21000;
    const gas_price_gwei: u256 = 20;

    const result = try formatGasCost(allocator, gas_used, gas_price_gwei);
    defer allocator.free(result);

    // 21000 * 20 gwei = 420000 gwei = 0.00042 ether
    try testing.expectEqualStrings("0.00042 ether", result);
}

test "parseInteger - helper function" {
    const result1 = try parseInteger("123");
    try testing.expectEqual(@as(u256, 123), result1);

    const result2 = try parseInteger("0");
    try testing.expectEqual(@as(u256, 0), result2);

    const result3 = try parseInteger("");
    try testing.expectEqual(@as(u256, 0), result3);
}

test "parseDecimal - helper function" {
    const result1 = try parseDecimal("5", .ether);
    try testing.expectEqual(ETHER / 2, result1);

    const result2 = try parseDecimal("25", .ether);
    try testing.expectEqual(ETHER / 4, result2);

    const result3 = try parseDecimal("", .ether);
    try testing.expectEqual(@as(u256, 0), result3);
}

test "getDefaultDecimals - helper function" {
    try testing.expectEqual(@as(u8, 0), getDefaultDecimals(.wei));
    try testing.expectEqual(@as(u8, 3), getDefaultDecimals(.kwei));
    try testing.expectEqual(@as(u8, 6), getDefaultDecimals(.mwei));
    try testing.expectEqual(@as(u8, 9), getDefaultDecimals(.gwei));
    try testing.expectEqual(@as(u8, 12), getDefaultDecimals(.szabo));
    try testing.expectEqual(@as(u8, 15), getDefaultDecimals(.finney));
    try testing.expectEqual(@as(u8, 18), getDefaultDecimals(.ether));
}
