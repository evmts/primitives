const std = @import("std");
const evm = @import("evm");
const primitives = @import("primitives");
const revm = @import("revm");
const common = @import("common.zig");

fn run_slt_test(allocator: std.mem.Allocator, a: u256, b: u256, expected: u256) !void {
    // Build bytecode: PUSH a, PUSH b, SLT
    var bytecode = std.ArrayList(u8).init(allocator);
    defer bytecode.deinit();
    
    // PUSH a
    try bytecode.append(0x7f); // PUSH32
    var a_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &a_bytes, a, .big);
    try bytecode.appendSlice(&a_bytes);
    
    // PUSH b
    try bytecode.append(0x7f); // PUSH32
    var b_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &b_bytes, b, .big);
    try bytecode.appendSlice(&b_bytes);
    
    // SLT
    try bytecode.append(0x12);
    
    // Setup Guillotine EVM
    var database = evm.Database.init(allocator);
    defer database.deinit();
    
    const caller_address = primitives.Address{ .bytes = [_]u8{0x10} ++ [_]u8{0} ** 18 ++ [_]u8{0x01} };
    const contract_address = primitives.Address{ .bytes = [_]u8{0x20} ++ [_]u8{0} ** 18 ++ [_]u8{0x02} };
    
    const code_hash = try database.set_code(bytecode.items);
    
    try database.set_account(contract_address.bytes, .{
        .balance = 0,
        .nonce = 0,
        .code_hash = code_hash,
        .storage_root = [_]u8{0} ** 32,
    });
    
    try database.set_account(caller_address.bytes, .{
        .balance = std.math.maxInt(u256),
        .nonce = 0,
        .code_hash = [_]u8{0} ** 32,
        .storage_root = [_]u8{0} ** 32,
    });
    
    const block_info = evm.BlockInfo{
        .chain_id = 1,
        .number = 20_000_000,
        .timestamp = 1_800_000_000,
        .difficulty = 0,
        .gas_limit = 1_000_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .base_fee = 7,
        .prev_randao = [_]u8{0} ** 32,
        .blob_base_fee = 1000000000,
        .blob_versioned_hashes = &.{},
    };

    const tx_context = evm.TransactionContext{
        .gas_limit = 1_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .chain_id = 1,
    };
    
    var guillotine_evm = try evm.Evm(.{}).init(
        allocator,
        &database,
        block_info,
        tx_context,
        0,
        caller_address,
        .CANCUN
    );
    defer guillotine_evm.deinit();
    
    const call_params = evm.CallParams{
        .call = .{
            .caller = caller_address,
            .to = contract_address,
            .value = 0,
            .input = &.{},
            .gas = 1_000_000,
        },
    };
    
    var guillotine_result = guillotine_evm.call(call_params);
    defer guillotine_result.deinit(allocator);
    
    // Setup REVM
    var revm_vm = try revm.Revm.init(allocator, .{
        .gas_limit = 1_000_000,
        .chain_id = 1,
    });
    defer revm_vm.deinit();
    
    try revm_vm.setBalance(caller_address, std.math.maxInt(u256));
    try revm_vm.setCode(contract_address, bytecode.items);
    
    var revm_result = revm_vm.execute(caller_address, contract_address, 0, &.{}, 1_000_000) catch |err| {
        if (guillotine_result.success) {
            return err;
        }
        return;
    };
    defer revm_result.deinit();
    
    // Compare results
    try std.testing.expectEqual(revm_result.success, guillotine_result.success);
    try std.testing.expectEqual(revm_result.stack.len, 1);
    try std.testing.expectEqual(guillotine_result.stack.len, 1);
    try std.testing.expectEqual(expected, revm_result.stack[0]);
    try std.testing.expectEqual(expected, guillotine_result.stack[0]);
}

fn run_slt_test_with_jump(allocator: std.mem.Allocator, a: u256, b: u256, expected: u256) !void {
    // Build bytecode with JUMP to prevent opcode fusion: PUSH a, PUSH b, PUSH dest, JUMP, JUMPDEST, SLT
    var bytecode = std.ArrayList(u8).init(allocator);
    defer bytecode.deinit();
    
    // PUSH a
    try bytecode.append(0x7f); // PUSH32
    var a_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &a_bytes, a, .big);
    try bytecode.appendSlice(&a_bytes);
    
    // PUSH b
    try bytecode.append(0x7f); // PUSH32
    var b_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &b_bytes, b, .big);
    try bytecode.appendSlice(&b_bytes);
    
    // PUSH destination (position after JUMP: 32 + 1 + 32 + 1 + 1 + 1 + 1 = 69)
    try bytecode.append(0x60); // PUSH1
    try bytecode.append(69);
    
    // JUMP
    try bytecode.append(0x56);
    
    // JUMPDEST
    try bytecode.append(0x5b);
    
    // SLT
    try bytecode.append(0x12);
    
    // Setup and execute (same as regular test)
    var database = evm.Database.init(allocator);
    defer database.deinit();
    
    const caller_address = primitives.Address{ .bytes = [_]u8{0x10} ++ [_]u8{0} ** 18 ++ [_]u8{0x01} };
    const contract_address = primitives.Address{ .bytes = [_]u8{0x20} ++ [_]u8{0} ** 18 ++ [_]u8{0x02} };
    
    const code_hash = try database.set_code(bytecode.items);
    
    try database.set_account(contract_address.bytes, .{
        .balance = 0,
        .nonce = 0,
        .code_hash = code_hash,
        .storage_root = [_]u8{0} ** 32,
    });
    
    try database.set_account(caller_address.bytes, .{
        .balance = std.math.maxInt(u256),
        .nonce = 0,
        .code_hash = [_]u8{0} ** 32,
        .storage_root = [_]u8{0} ** 32,
    });
    
    const block_info = evm.BlockInfo{
        .chain_id = 1,
        .number = 20_000_000,
        .timestamp = 1_800_000_000,
        .difficulty = 0,
        .gas_limit = 1_000_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .base_fee = 7,
        .prev_randao = [_]u8{0} ** 32,
        .blob_base_fee = 1000000000,
        .blob_versioned_hashes = &.{},
    };

    const tx_context = evm.TransactionContext{
        .gas_limit = 1_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .chain_id = 1,
    };
    
    var guillotine_evm = try evm.Evm(.{}).init(
        allocator,
        &database,
        block_info,
        tx_context,
        0,
        caller_address,
        .CANCUN
    );
    defer guillotine_evm.deinit();
    
    const call_params = evm.CallParams{
        .call = .{
            .caller = caller_address,
            .to = contract_address,
            .value = 0,
            .input = &.{},
            .gas = 1_000_000,
        },
    };
    
    var guillotine_result = guillotine_evm.call(call_params);
    defer guillotine_result.deinit(allocator);
    
    // Setup REVM
    var revm_vm = try revm.Revm.init(allocator, .{
        .gas_limit = 1_000_000,
        .chain_id = 1,
    });
    defer revm_vm.deinit();
    
    try revm_vm.setBalance(caller_address, std.math.maxInt(u256));
    try revm_vm.setCode(contract_address, bytecode.items);
    
    var revm_result = revm_vm.execute(caller_address, contract_address, 0, &.{}, 1_000_000) catch |err| {
        if (guillotine_result.success) {
            return err;
        }
        return;
    };
    defer revm_result.deinit();
    
    // Compare results
    try std.testing.expectEqual(revm_result.success, guillotine_result.success);
    try std.testing.expectEqual(revm_result.stack.len, 1);
    try std.testing.expectEqual(guillotine_result.stack.len, 1);
    try std.testing.expectEqual(expected, revm_result.stack[0]);
    try std.testing.expectEqual(expected, guillotine_result.stack[0]);
}

test "SLT: basic positive numbers" {
    const allocator = std.testing.allocator;
    try run_slt_test(allocator, 5, 10, 1); // 5 < 10 (both positive)
    try run_slt_test_with_jump(allocator, 10, 5, 0); // 10 < 5 (both positive)
}

test "SLT: equal values" {
    const allocator = std.testing.allocator;
    try run_slt_test(allocator, 100, 100, 0); // 100 < 100
    try run_slt_test_with_jump(allocator, 0, 0, 0); // 0 < 0
}

test "SLT: zero comparisons" {
    const allocator = std.testing.allocator;
    try run_slt_test(allocator, 0, 1, 1); // 0 < 1
    try run_slt_test_with_jump(allocator, 1, 0, 0); // 1 < 0
}

test "SLT: negative vs positive" {
    const allocator = std.testing.allocator;
    const neg_one = std.math.maxInt(u256); // -1 in two's complement
    try run_slt_test(allocator, neg_one, 1, 1); // -1 < 1
    try run_slt_test_with_jump(allocator, 1, neg_one, 0); // 1 < -1
}

test "SLT: both negative" {
    const allocator = std.testing.allocator;
    const neg_one = std.math.maxInt(u256); // -1
    const neg_two = std.math.maxInt(u256) - 1; // -2
    try run_slt_test(allocator, neg_two, neg_one, 1); // -2 < -1
    try run_slt_test_with_jump(allocator, neg_one, neg_two, 0); // -1 < -2
}

test "SLT: signed MIN and MAX" {
    const allocator = std.testing.allocator;
    const max_signed = (1 << 255) - 1; // 0x7FFF...FFF (MAX positive)
    const min_signed = 1 << 255; // 0x8000...000 (MIN negative)
    try run_slt_test(allocator, min_signed, max_signed, 1); // MIN < MAX
    try run_slt_test_with_jump(allocator, max_signed, min_signed, 0); // MAX < MIN
}

test "SLT: MIN with itself and -1" {
    const allocator = std.testing.allocator;
    const min_signed = 1 << 255; // 0x8000...000 (MIN negative)
    const neg_one = std.math.maxInt(u256); // -1
    try run_slt_test(allocator, min_signed, min_signed, 0); // MIN < MIN
    try run_slt_test_with_jump(allocator, min_signed, neg_one, 1); // MIN < -1
}

test "SLT: MAX with itself and 0" {
    const allocator = std.testing.allocator;
    const max_signed = (1 << 255) - 1; // 0x7FFF...FFF (MAX positive)
    try run_slt_test(allocator, max_signed, max_signed, 0); // MAX < MAX
    try run_slt_test_with_jump(allocator, max_signed, 0, 0); // MAX < 0
}

test "SLT: small negative numbers" {
    const allocator = std.testing.allocator;
    const neg_10 = std.math.maxInt(u256) - 9; // -10
    const neg_5 = std.math.maxInt(u256) - 4; // -5
    try run_slt_test(allocator, neg_10, neg_5, 1); // -10 < -5
    try run_slt_test_with_jump(allocator, neg_5, neg_10, 0); // -5 < -10
}

test "SLT: large negative numbers" {
    const allocator = std.testing.allocator;
    const neg_1000 = std.math.maxInt(u256) - 999; // -1000
    const neg_100 = std.math.maxInt(u256) - 99; // -100
    try run_slt_test(allocator, neg_1000, neg_100, 1); // -1000 < -100
    try run_slt_test_with_jump(allocator, neg_100, neg_1000, 0); // -100 < -1000
}

test "SLT: crossing zero boundary" {
    const allocator = std.testing.allocator;
    const neg_one = std.math.maxInt(u256); // -1
    try run_slt_test(allocator, neg_one, 0, 1); // -1 < 0
    try run_slt_test_with_jump(allocator, 0, neg_one, 0); // 0 < -1
}

test "SLT: large positive vs small negative" {
    const allocator = std.testing.allocator;
    const large_pos = 1000000;
    const neg_one = std.math.maxInt(u256); // -1
    try run_slt_test(allocator, neg_one, large_pos, 1); // -1 < 1000000
    try run_slt_test_with_jump(allocator, large_pos, neg_one, 0); // 1000000 < -1
}

test "SLT: sign bit edge cases" {
    const allocator = std.testing.allocator;
    const just_below_sign = (1 << 255) - 1; // 0x7FFF...FFF
    const just_above_sign = 1 << 255; // 0x8000...000
    try run_slt_test(allocator, just_above_sign, just_below_sign, 1); // negative < positive
    try run_slt_test_with_jump(allocator, just_below_sign, just_above_sign, 0); // positive < negative
}

test "SLT: alternating bit patterns" {
    const allocator = std.testing.allocator;
    const pattern1 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    const pattern2 = 0x5555555555555555555555555555555555555555555555555555555555555555;
    // pattern1 has sign bit set (negative), pattern2 doesn't (positive)
    try run_slt_test(allocator, pattern1, pattern2, 1); // negative < positive
    try run_slt_test_with_jump(allocator, pattern2, pattern1, 0); // positive < negative
}

test "SLT: powers of two near sign boundary" {
    const allocator = std.testing.allocator;
    const pos_power = 1 << 254; // Large positive power of 2
    const neg_power = 1 << 255; // Smallest negative (sign bit only)
    try run_slt_test(allocator, neg_power, pos_power, 1); // negative < positive
    try run_slt_test_with_jump(allocator, pos_power, neg_power, 0); // positive < negative
}

test "opcode 0x12 differential test" {
    const allocator = std.testing.allocator;
    
    // Build bytecode for this opcode
    const bytecode = try common.build_bytecode(allocator, 0x12);
    defer allocator.free(bytecode);
    
    // Setup Guillotine EVM
    var database = evm.Database.init(allocator);
    defer database.deinit();
    
    const caller_address = primitives.Address{ .bytes = [_]u8{0x10} ++ [_]u8{0} ** 18 ++ [_]u8{0x01} };
    const contract_address = primitives.Address{ .bytes = [_]u8{0x20} ++ [_]u8{0} ** 18 ++ [_]u8{0x02} };
    
    // Set the bytecode on the contract account
    const code_hash = try database.set_code(bytecode);
    
    try database.set_account(contract_address.bytes, .{
        .balance = 0,
        .nonce = 0,
        .code_hash = code_hash,
        .storage_root = [_]u8{0} ** 32,
    });
    
    // Set up caller as EOA with balance
    try database.set_account(caller_address.bytes, .{
        .balance = std.math.maxInt(u256),
        .nonce = 0,
        .code_hash = [_]u8{0} ** 32, // Empty code hash for EOA
        .storage_root = [_]u8{0} ** 32,
    });
    
    const block_info = evm.BlockInfo{
        .chain_id = 1,
        .number = 20_000_000,
        .timestamp = 1_800_000_000,
        .difficulty = 0,
        .gas_limit = 1_000_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .base_fee = 7,
        .prev_randao = [_]u8{0} ** 32,
        .blob_base_fee = 1000000000,
        .blob_versioned_hashes = &.{},
    };

    const tx_context = evm.TransactionContext{
        .gas_limit = 1_000_000,
        .coinbase = primitives.ZERO_ADDRESS,
        .chain_id = 1,
    };
    
    var guillotine_evm = try evm.Evm(.{}).init(
        allocator,
        &database,
        block_info,
        tx_context,
        0,
        caller_address,
        .CANCUN
    );
    defer guillotine_evm.deinit();
    
    // Execute with Guillotine using call
    const call_params = evm.CallParams{
        .call = .{
            .caller = caller_address,
            .to = contract_address,
            .value = 0,
            .input = &.{}, // Empty input - code is on the account
            .gas = 1_000_000,
        },
    };
    
    var guillotine_result = guillotine_evm.call(call_params);
    defer guillotine_result.deinit(allocator);
    
    // Setup REVM
    var revm_vm = try revm.Revm.init(allocator, .{
        .gas_limit = 1_000_000,
        .chain_id = 1,
    });
    defer revm_vm.deinit();
    
    try revm_vm.setBalance(caller_address, std.math.maxInt(u256));
    
    // Execute with REVM
    // Deploy the bytecode to the contract_address in REVM (similar to Guillotine setup)
    try revm_vm.setCode(contract_address, bytecode);
    
    // Execute with REVM - now calling the deployed contract
    var revm_result = revm_vm.execute(caller_address, contract_address, 0, &.{}, 1_000_000) catch |err| {
        // If REVM fails, check if Guillotine also failed
        if (guillotine_result.success) {
            return err;
        }
        return; // Both failed, which is expected for some opcodes
    };
    defer revm_result.deinit();
    
    // Compare results
    try std.testing.expectEqual(revm_result.success, guillotine_result.success);
    if (revm_result.success and guillotine_result.success) {
        try std.testing.expectEqualSlices(u8, revm_result.output, guillotine_result.output);
    }
}