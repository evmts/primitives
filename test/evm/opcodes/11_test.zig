const std = @import("std");
const evm = @import("evm");
const primitives = @import("primitives");
const common = @import("common.zig");

test "GT: basic (10 > 5 = 1)" {
    try run_gt_test(std.testing.allocator, 10, 5);
}

fn run_gt_test(allocator: std.mem.Allocator, a: u256, b: u256) !void {
    // Build custom bytecode for GT test
    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    
    // Push a
    if (a == 0) {
        try buf.append(allocator, 0x5f); // PUSH0
    } else {
        var tmp: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &tmp, a, .big);
        const first_non_zero = std.mem.indexOfNonePos(u8, &tmp, 0, &[_]u8{0}) orelse 32;
        const slice = tmp[first_non_zero..];
        if (slice.len > 0 and slice.len <= 32) {
            const op: u8 = 0x60 + @as(u8, @intCast(slice.len - 1));
            try buf.append(allocator, op);
            try buf.appendSlice(allocator, slice);
        }
    }
    
    // Push b
    if (b == 0) {
        try buf.append(allocator, 0x5f); // PUSH0
    } else {
        var tmp: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &tmp, b, .big);
        const first_non_zero = std.mem.indexOfNonePos(u8, &tmp, 0, &[_]u8{0}) orelse 32;
        const slice = tmp[first_non_zero..];
        if (slice.len > 0 and slice.len <= 32) {
            const op: u8 = 0x60 + @as(u8, @intCast(slice.len - 1));
            try buf.append(allocator, op);
            try buf.appendSlice(allocator, slice);
        }
    }
    
    // GT opcode
    try buf.append(allocator, 0x11);
    
    // Store result and return
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x00); // 0 (memory offset)
    try buf.append(allocator, 0x52); // MSTORE
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x20); // 32 (length)
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x00); // 0 (offset)
    try buf.append(allocator, 0xf3); // RETURN
    
    const bytecode = try buf.toOwnedSlice(allocator);
    defer allocator.free(bytecode);
    
    // Setup Guillotine EVM
    var database = evm.Database.init(allocator);
    defer database.deinit();
    
    const caller_address = primitives.Address{ .bytes = [_]u8{0x10} ++ [_]u8{0} ** 18 ++ [_]u8{0x01} };
    const contract_address = primitives.Address{ .bytes = [_]u8{0x20} ++ [_]u8{0} ** 18 ++ [_]u8{0x02} };
    
    const code_hash = try database.set_code(bytecode);
    
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
    try revm_vm.setCode(contract_address, bytecode);
    
    var revm_result = revm_vm.execute(caller_address, contract_address, 0, &.{}, 1_000_000) catch |err| {
        if (guillotine_result.success) {
            return err;
        }
        return;
    };
    defer revm_result.deinit();
    
    // Compare results
    try std.testing.expectEqual(revm_result.success, guillotine_result.success);
    if (revm_result.success and guillotine_result.success) {
        try std.testing.expectEqualSlices(u8, revm_result.output, guillotine_result.output);
    }
}

test "GT: equal values (10 > 10 = 0)" {
    try run_gt_test(std.testing.allocator, 10, 10);
}

test "GT: less than (5 > 10 = 0)" {
    try run_gt_test(std.testing.allocator, 5, 10);
}

test "GT: zero comparison (1 > 0 = 1)" {
    try run_gt_test(std.testing.allocator, 1, 0);
}

test "GT: zero comparison reversed (0 > 1 = 0)" {
    try run_gt_test(std.testing.allocator, 0, 1);
}

test "GT: both zero (0 > 0 = 0)" {
    try run_gt_test(std.testing.allocator, 0, 0);
}

test "GT: large numbers" {
    try run_gt_test(std.testing.allocator, 1000000, 999999);
}

test "GT: near u64 boundary" {
    const u64_max = @as(u256, std.math.maxInt(u64));
    try run_gt_test(std.testing.allocator, u64_max, u64_max - 10);
}

test "GT: exactly u64 max" {
    const u64_max = @as(u256, std.math.maxInt(u64));
    try run_gt_test(std.testing.allocator, u64_max + 1, u64_max);
}

test "GT: large 128-bit numbers" {
    const large_128 = @as(u256, 1) << 120;
    try run_gt_test(std.testing.allocator, large_128 + 1, large_128);
}

test "GT: MAX_U256 comparisons" {
    try run_gt_test(std.testing.allocator, std.math.maxInt(u256), std.math.maxInt(u256) - 1);
}

test "GT: MAX_U256 with self" {
    try run_gt_test(std.testing.allocator, std.math.maxInt(u256), std.math.maxInt(u256));
}

test "GT: MAX and zero" {
    try run_gt_test(std.testing.allocator, std.math.maxInt(u256), 0);
}

test "GT: zero and MAX" {
    try run_gt_test(std.testing.allocator, 0, std.math.maxInt(u256));
}

test "GT: consecutive numbers" {
    try run_gt_test(std.testing.allocator, 12346, 12345);
}

test "GT: powers of 2" {
    try run_gt_test(std.testing.allocator, 512, 256);
}

test "GT: near 256-bit boundary" {
    try run_gt_test(std.testing.allocator, std.math.maxInt(u256), std.math.maxInt(u256) - 1000);
}

test "GT: alternating bit patterns" {
    const pattern1 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    const pattern2 = 0x5555555555555555555555555555555555555555555555555555555555555555;
    try run_gt_test(std.testing.allocator, pattern1, pattern2);
}

test "GT: all ones pattern" {
    const all_ones_128 = (@as(u256, 1) << 128) - 1;
    try run_gt_test(std.testing.allocator, (@as(u256, 1) << 128), all_ones_128);
}

test "GT: fibonacci numbers" {
    try run_gt_test(std.testing.allocator, 21, 13);
}

test "GT: prime numbers" {
    try run_gt_test(std.testing.allocator, 1009, 997);
}

test "GT: edge case near middle" {
    const mid = @as(u256, 1) << 128;
    try run_gt_test(std.testing.allocator, mid, mid - 1);
}

test "GT: very large difference" {
    try run_gt_test(std.testing.allocator, @as(u256, 1) << 255, 1);
}

test "GT: one apart at boundary" {
    const boundary = @as(u256, 1) << 64;
    try run_gt_test(std.testing.allocator, boundary, boundary - 1);
}

fn run_gt_test_with_jump(allocator: std.mem.Allocator, a: u256, b: u256) !void {
    // Build custom bytecode for GT test with jump to prevent fusion
    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    
    // Push a
    if (a == 0) {
        try buf.append(allocator, 0x5f); // PUSH0
    } else {
        var tmp: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &tmp, a, .big);
        const first_non_zero = std.mem.indexOfNonePos(u8, &tmp, 0, &[_]u8{0}) orelse 32;
        const slice = tmp[first_non_zero..];
        if (slice.len > 0 and slice.len <= 32) {
            const op: u8 = 0x60 + @as(u8, @intCast(slice.len - 1));
            try buf.append(allocator, op);
            try buf.appendSlice(allocator, slice);
        }
    }
    
    // Push b
    if (b == 0) {
        try buf.append(allocator, 0x5f); // PUSH0
    } else {
        var tmp: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &tmp, b, .big);
        const first_non_zero = std.mem.indexOfNonePos(u8, &tmp, 0, &[_]u8{0}) orelse 32;
        const slice = tmp[first_non_zero..];
        if (slice.len > 0 and slice.len <= 32) {
            const op: u8 = 0x60 + @as(u8, @intCast(slice.len - 1));
            try buf.append(allocator, op);
            try buf.appendSlice(allocator, slice);
        }
    }
    
    // Calculate jump destination
    const jump_dest = buf.items.len + 3;
    
    // Jump to GT (prevents fusion)
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, @intCast(jump_dest)); // destination
    try buf.append(allocator, 0x56); // JUMP
    
    // JUMPDEST + GT
    try buf.append(allocator, 0x5b); // JUMPDEST
    try buf.append(allocator, 0x11); // GT opcode
    
    // Store result and return
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x00); // 0 (memory offset)
    try buf.append(allocator, 0x52); // MSTORE
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x20); // 32 (length)
    try buf.append(allocator, 0x60); // PUSH1
    try buf.append(allocator, 0x00); // 0 (offset)
    try buf.append(allocator, 0xf3); // RETURN
    
    const bytecode = try buf.toOwnedSlice(allocator);
    defer allocator.free(bytecode);
    
    // Setup Guillotine EVM
    var database = evm.Database.init(allocator);
    defer database.deinit();
    
    const caller_address = primitives.Address{ .bytes = [_]u8{0x10} ++ [_]u8{0} ** 18 ++ [_]u8{0x01} };
    const contract_address = primitives.Address{ .bytes = [_]u8{0x20} ++ [_]u8{0} ** 18 ++ [_]u8{0x02} };
    
    const code_hash = try database.set_code(bytecode);
    
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
    try revm_vm.setCode(contract_address, bytecode);
    
    var revm_result = revm_vm.execute(caller_address, contract_address, 0, &.{}, 1_000_000) catch |err| {
        if (guillotine_result.success) {
            return err;
        }
        return;
    };
    defer revm_result.deinit();
    
    // Compare results
    try std.testing.expectEqual(revm_result.success, guillotine_result.success);
    if (revm_result.success and guillotine_result.success) {
        try std.testing.expectEqualSlices(u8, revm_result.output, guillotine_result.output);
    }
}

test "GT with JUMP: basic (10 > 5 = 1)" {
    try run_gt_test_with_jump(std.testing.allocator, 10, 5);
}

test "GT with JUMP: equal values (100 > 100 = 0)" {
    try run_gt_test_with_jump(std.testing.allocator, 100, 100);
}

test "GT with JUMP: large numbers" {
    try run_gt_test_with_jump(std.testing.allocator, 2000000, 1000000);
}

test "GT with JUMP: MAX comparison" {
    try run_gt_test_with_jump(std.testing.allocator, std.math.maxInt(u256), std.math.maxInt(u256) - 1);
}

test "GT with JUMP: near u64 boundary" {
    const u64_max = @as(u256, std.math.maxInt(u64));
    try run_gt_test_with_jump(std.testing.allocator, u64_max, u64_max - 10);
}