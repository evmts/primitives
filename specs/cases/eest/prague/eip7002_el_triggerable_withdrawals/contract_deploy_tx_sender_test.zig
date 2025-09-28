const std = @import("std");
const testing = std.testing;
const runner = @import("runner");

test "sender" {
    const allocator = testing.allocator;
    
    // Read and parse the JSON test file
    const json_path = "specs/execution-specs/tests/eest/prague/eip7002_el_triggerable_withdrawals/contract_deploy_tx.json";
    const json_content = try std.fs.cwd().readFileAlloc(allocator, json_path, 100 * 1024 * 1024);
    defer allocator.free(json_content);
    
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();
    
    // Get the specific test case
    const test_case = parsed.value.object.get("sender").?;
    
    // Run the test
    try runner.runJsonTest(allocator, test_case);
}
