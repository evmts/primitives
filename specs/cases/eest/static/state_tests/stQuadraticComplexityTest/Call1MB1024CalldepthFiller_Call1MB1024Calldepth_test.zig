const std = @import("std");
const testing = std.testing;
const runner = @import("runner");

test "Call1MB1024Calldepth" {
    const allocator = testing.allocator;
    
    // Read and parse the JSON test file
    const json_path = "specs/execution-specs/tests/eest/static/state_tests/stQuadraticComplexityTest/Call1MB1024CalldepthFiller.json";
    const json_content = try std.fs.cwd().readFileAlloc(allocator, json_path, 100 * 1024 * 1024);
    defer allocator.free(json_content);
    
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();
    
    // Get the specific test case
    const test_case = parsed.value.object.get("Call1MB1024Calldepth").?;
    
    // Run the test
    try runner.runJsonTest(allocator, test_case);
}
