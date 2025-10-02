const std = @import("std");
const testing = std.testing;
const c_api = @import("root_c.zig");

// =============================================================================
// Address C API Tests
// =============================================================================

test "C API: Address - from_hex and to_hex" {
    var error_code: c_api.ErrorCode = undefined;

    // Create address from hex string
    const hex_str = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const addr = c_api.primitives_address_from_hex(hex_str, &error_code);
    try testing.expect(addr != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer c_api.primitives_address_free(addr.?);

    // Convert back to hex
    const result_hex = c_api.primitives_address_to_hex(addr.?, &error_code);
    try testing.expect(result_hex != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(result_hex.?));

    // Verify the hex string (should be lowercase)
    const result_slice = std.mem.span(result_hex.?);
    try testing.expectEqualStrings("0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676", result_slice);
}

test "C API: Address - to_checksum" {
    var error_code: c_api.ErrorCode = undefined;

    const hex_str = "0x742d35cc6641c91b6e4bb6ac9e3ff2958c94e676";
    const addr = c_api.primitives_address_from_hex(hex_str, &error_code);
    try testing.expect(addr != null);
    defer c_api.primitives_address_free(addr.?);

    const checksum_hex = c_api.primitives_address_to_checksum(addr.?, &error_code);
    try testing.expect(checksum_hex != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(checksum_hex.?));

    // Verify it contains mixed case (checksummed)
    const checksum_slice = std.mem.span(checksum_hex.?);
    try testing.expect(checksum_slice.len == 42);
    try testing.expect(std.mem.startsWith(u8, checksum_slice, "0x"));
}

test "C API: Address - is_zero" {
    var error_code: c_api.ErrorCode = undefined;

    // Zero address
    const zero_hex = "0x0000000000000000000000000000000000000000";
    const zero_addr = c_api.primitives_address_from_hex(zero_hex, &error_code);
    try testing.expect(zero_addr != null);
    defer c_api.primitives_address_free(zero_addr.?);

    try testing.expect(c_api.primitives_address_is_zero(zero_addr.?));

    // Non-zero address
    const non_zero_hex = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const non_zero_addr = c_api.primitives_address_from_hex(non_zero_hex, &error_code);
    try testing.expect(non_zero_addr != null);
    defer c_api.primitives_address_free(non_zero_addr.?);

    try testing.expect(!c_api.primitives_address_is_zero(non_zero_addr.?));
}

test "C API: Address - equal" {
    var error_code: c_api.ErrorCode = undefined;

    const hex1 = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const hex2 = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const hex3 = "0x1111111111111111111111111111111111111111";

    const addr1 = c_api.primitives_address_from_hex(hex1, &error_code);
    const addr2 = c_api.primitives_address_from_hex(hex2, &error_code);
    const addr3 = c_api.primitives_address_from_hex(hex3, &error_code);

    defer c_api.primitives_address_free(addr1.?);
    defer c_api.primitives_address_free(addr2.?);
    defer c_api.primitives_address_free(addr3.?);

    try testing.expect(c_api.primitives_address_equal(addr1.?, addr2.?));
    try testing.expect(!c_api.primitives_address_equal(addr1.?, addr3.?));
}

test "C API: Address - create" {
    var error_code: c_api.ErrorCode = undefined;

    const deployer_hex = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const deployer = c_api.primitives_address_from_hex(deployer_hex, &error_code);
    try testing.expect(deployer != null);
    defer c_api.primitives_address_free(deployer.?);

    const created = c_api.primitives_address_create(deployer.?, 0, &error_code);
    try testing.expect(created != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer c_api.primitives_address_free(created.?);

    // Should not be zero
    try testing.expect(!c_api.primitives_address_is_zero(created.?));

    // Different nonces should produce different addresses
    const created2 = c_api.primitives_address_create(deployer.?, 1, &error_code);
    try testing.expect(created2 != null);
    defer c_api.primitives_address_free(created2.?);

    try testing.expect(!c_api.primitives_address_equal(created.?, created2.?));
}

test "C API: Address - create2" {
    var error_code: c_api.ErrorCode = undefined;

    const deployer_hex = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const deployer = c_api.primitives_address_from_hex(deployer_hex, &error_code);
    try testing.expect(deployer != null);
    defer c_api.primitives_address_free(deployer.?);

    const salt = [_]u8{0} ** 32;
    const init_code_hash = [_]u8{0} ** 32;

    const created = c_api.primitives_address_create2(deployer.?, &salt, 32, &init_code_hash, 32, &error_code);
    try testing.expect(created != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer c_api.primitives_address_free(created.?);

    // Should be deterministic
    const created2 = c_api.primitives_address_create2(deployer.?, &salt, 32, &init_code_hash, 32, &error_code);
    try testing.expect(created2 != null);
    defer c_api.primitives_address_free(created2.?);

    try testing.expect(c_api.primitives_address_equal(created.?, created2.?));
}

test "C API: Address - invalid hex" {
    var error_code: c_api.ErrorCode = undefined;

    // Invalid format (no 0x)
    const bad_hex1 = "742d35Cc6641C91B6E4bb6ac9e3ff2958c94E676";
    const addr1 = c_api.primitives_address_from_hex(bad_hex1, &error_code);
    try testing.expect(addr1 == null);
    try testing.expectEqual(c_api.ErrorCode.InvalidFormat, error_code);

    // Invalid length
    const bad_hex2 = "0x742d35Cc";
    const addr2 = c_api.primitives_address_from_hex(bad_hex2, &error_code);
    try testing.expect(addr2 == null);
    try testing.expectEqual(c_api.ErrorCode.InvalidFormat, error_code);

    // Invalid characters
    const bad_hex3 = "0x742d35Cc6641C91B6E4bb6ac9e3ff2958c94E6ZZ";
    const addr3 = c_api.primitives_address_from_hex(bad_hex3, &error_code);
    try testing.expect(addr3 == null);
    try testing.expectEqual(c_api.ErrorCode.InvalidCharacter, error_code);
}

// =============================================================================
// Hash C API Tests
// =============================================================================

test "C API: Hash - from_hex and to_hex" {
    var error_code: c_api.ErrorCode = undefined;

    const hex_str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const hash = c_api.primitives_hash_from_hex(hex_str, &error_code);
    try testing.expect(hash != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer c_api.primitives_hash_free(hash.?);

    const result_hex = c_api.primitives_hash_to_hex(hash.?, &error_code);
    try testing.expect(result_hex != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(result_hex.?));

    const result_slice = std.mem.span(result_hex.?);
    try testing.expectEqualStrings(hex_str, result_slice);
}

test "C API: Hash - keccak256" {
    var error_code: c_api.ErrorCode = undefined;

    const data = "hello world";
    const hash = c_api.primitives_hash_keccak256(data.ptr, data.len, &error_code);
    try testing.expect(hash != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer c_api.primitives_hash_free(hash.?);

    // Verify it's deterministic
    const hash2 = c_api.primitives_hash_keccak256(data.ptr, data.len, &error_code);
    try testing.expect(hash2 != null);
    defer c_api.primitives_hash_free(hash2.?);

    try testing.expect(c_api.primitives_hash_equal(hash.?, hash2.?));
}

test "C API: Hash - equal" {
    var error_code: c_api.ErrorCode = undefined;

    const hex1 = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const hex2 = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const hex3 = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    const hash1 = c_api.primitives_hash_from_hex(hex1, &error_code);
    const hash2 = c_api.primitives_hash_from_hex(hex2, &error_code);
    const hash3 = c_api.primitives_hash_from_hex(hex3, &error_code);

    defer c_api.primitives_hash_free(hash1.?);
    defer c_api.primitives_hash_free(hash2.?);
    defer c_api.primitives_hash_free(hash3.?);

    try testing.expect(c_api.primitives_hash_equal(hash1.?, hash2.?));
    try testing.expect(!c_api.primitives_hash_equal(hash1.?, hash3.?));
}

// =============================================================================
// Hex C API Tests
// =============================================================================

test "C API: Hex - encode and decode" {
    var error_code: c_api.ErrorCode = undefined;

    const bytes = [_]u8{ 0x12, 0x34, 0xab, 0xcd };
    const hex = c_api.primitives_hex_encode(&bytes, bytes.len, &error_code);
    try testing.expect(hex != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(hex.?));

    const hex_slice = std.mem.span(hex.?);
    try testing.expectEqualStrings("0x1234abcd", hex_slice);

    // Decode back
    var out_len: usize = undefined;
    const decoded = c_api.primitives_hex_decode(hex.?, &out_len, &error_code);
    try testing.expect(decoded != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(decoded.?[0..out_len]);

    try testing.expectEqual(@as(usize, 4), out_len);
    try testing.expectEqualSlices(u8, &bytes, decoded.?[0..out_len]);
}

test "C API: Hex - is_valid" {
    try testing.expect(c_api.primitives_hex_is_valid("0x1234abcd"));
    try testing.expect(c_api.primitives_hex_is_valid("0xABCDEF"));
    try testing.expect(!c_api.primitives_hex_is_valid("1234abcd")); // no 0x
    try testing.expect(!c_api.primitives_hex_is_valid("0x")); // empty
    try testing.expect(!c_api.primitives_hex_is_valid("0xZZZZ")); // invalid chars
}

// =============================================================================
// Numeric C API Tests
// =============================================================================

test "C API: Numeric - parse_ether" {
    var error_code: c_api.ErrorCode = undefined;

    const ether_str = "1.5";
    const wei_bytes = c_api.primitives_numeric_parse_ether(ether_str, &error_code);
    try testing.expect(wei_bytes != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(wei_bytes.?[0..32]);

    // Verify the value (1.5 ether = 1500000000000000000 wei)
    const wei_value = std.mem.readInt(u256, wei_bytes.?[0..32], .big);
    try testing.expectEqual(@as(u256, 1_500_000_000_000_000_000), wei_value);
}

test "C API: Numeric - parse_gwei" {
    var error_code: c_api.ErrorCode = undefined;

    const gwei_str = "100";
    const wei_bytes = c_api.primitives_numeric_parse_gwei(gwei_str, &error_code);
    try testing.expect(wei_bytes != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(wei_bytes.?[0..32]);

    // Verify the value (100 gwei = 100000000000 wei)
    const wei_value = std.mem.readInt(u256, wei_bytes.?[0..32], .big);
    try testing.expectEqual(@as(u256, 100_000_000_000), wei_value);
}

test "C API: Numeric - format_ether" {
    var error_code: c_api.ErrorCode = undefined;

    // 1 ether in wei
    const wei_value: u256 = 1_000_000_000_000_000_000;
    var wei_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &wei_bytes, wei_value, .big);

    const ether_str = c_api.primitives_numeric_format_ether(&wei_bytes, &error_code);
    try testing.expect(ether_str != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(ether_str.?));

    const ether_slice = std.mem.span(ether_str.?);
    try testing.expectEqualStrings("1 ether", ether_slice);
}

test "C API: Numeric - format_gwei" {
    var error_code: c_api.ErrorCode = undefined;

    // 50 gwei in wei
    const wei_value: u256 = 50_000_000_000;
    var wei_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &wei_bytes, wei_value, .big);

    const gwei_str = c_api.primitives_numeric_format_gwei(&wei_bytes, &error_code);
    try testing.expect(gwei_str != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(std.mem.span(gwei_str.?));

    const gwei_slice = std.mem.span(gwei_str.?);
    try testing.expectEqualStrings("50 gwei", gwei_slice);
}

// =============================================================================
// RLP C API Tests
// =============================================================================

test "C API: RLP - encode_bytes" {
    var error_code: c_api.ErrorCode = undefined;

    const bytes = [_]u8{ 0x12, 0x34 };
    var out_len: usize = undefined;
    const encoded = c_api.primitives_rlp_encode_bytes(&bytes, bytes.len, &out_len, &error_code);
    try testing.expect(encoded != null);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);
    defer std.heap.c_allocator.free(encoded.?[0..out_len]);

    try testing.expect(out_len > 0);
}

// =============================================================================
// ABI C API Tests
// =============================================================================

test "C API: ABI - compute_selector" {
    var error_code: c_api.ErrorCode = undefined;
    var selector: [4]u8 = undefined;

    const signature = "transfer(address,uint256)";
    const success = c_api.primitives_abi_compute_selector(signature, &selector, &error_code);
    try testing.expect(success);
    try testing.expectEqual(c_api.ErrorCode.Success, error_code);

    // Verify selector is non-zero
    var is_zero = true;
    for (selector) |byte| {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    try testing.expect(!is_zero);
}

// =============================================================================
// Gas C API Tests
// =============================================================================

test "C API: Gas - memory_expansion" {
    const cost = c_api.primitives_gas_memory_expansion(1024);
    try testing.expect(cost > 0);

    // Larger size should cost more
    const larger_cost = c_api.primitives_gas_memory_expansion(2048);
    try testing.expect(larger_cost > cost);
}

test "C API: Gas - intrinsic" {
    const data = [_]u8{0} ** 100;

    const cost_non_creation = c_api.primitives_gas_intrinsic(&data, data.len, false);
    try testing.expect(cost_non_creation > 21000); // Base TX cost

    const cost_creation = c_api.primitives_gas_intrinsic(&data, data.len, true);
    try testing.expect(cost_creation > cost_non_creation); // Creation costs more
}

// =============================================================================
// Opcode C API Tests
// =============================================================================

test "C API: Opcode - is_push" {
    try testing.expect(c_api.primitives_opcode_is_push(0x60)); // PUSH1
    try testing.expect(c_api.primitives_opcode_is_push(0x7f)); // PUSH32
    try testing.expect(!c_api.primitives_opcode_is_push(0x01)); // ADD
}

test "C API: Opcode - push_size" {
    try testing.expectEqual(@as(u8, 1), c_api.primitives_opcode_push_size(0x60)); // PUSH1
    try testing.expectEqual(@as(u8, 32), c_api.primitives_opcode_push_size(0x7f)); // PUSH32
    try testing.expectEqual(@as(u8, 0), c_api.primitives_opcode_push_size(0x01)); // ADD (not a push)
}

test "C API: Opcode - name" {
    const name1 = c_api.primitives_opcode_name(0x01);
    const name1_slice = std.mem.span(name1);
    try testing.expectEqualStrings("ADD", name1_slice);

    const name2 = c_api.primitives_opcode_name(0x60);
    const name2_slice = std.mem.span(name2);
    try testing.expectEqualStrings("PUSH1", name2_slice);
}

// =============================================================================
// EIPs C API Tests
// =============================================================================

test "C API: EIPs - new and is_active" {
    // Create EIPs for London hardfork (value 11 - index in Hardfork enum)
    const eips = c_api.primitives_eips_new(11); // London
    try testing.expect(eips != null);
    defer c_api.primitives_eips_free(eips.?);

    // Check if EIP-1559 is active (should be for London)
    const is_1559_active = c_api.primitives_eips_is_active(eips.?, 1559);
    try testing.expect(is_1559_active);
}
