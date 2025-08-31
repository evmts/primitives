// Root file that imports all differential tests

const std = @import("std");

// Enable debug logging for tests
pub const std_options = std.Options{
    .log_level = .debug,
};

test {
    _ = @import("math_operations_test.zig");
    _ = @import("system_handlers_test.zig");
    _ = @import("jump_handlers_test.zig");
    _ = @import("memory_operations_test.zig");
    _ = @import("storage_operations_test.zig");
    _ = @import("stack_operations_test.zig");
    _ = @import("env_operations_test.zig");
    _ = @import("keccak_logs_test.zig");
    _ = @import("fixtures_test.zig");
    _ = @import("synthetic_toggle_test.zig");
    _ = @import("popular_contracts_test.zig");
    _ = @import("fixtures_contract_test.zig");
    _ = @import("usdc_proxy_test.zig");
    _ = @import("comprehensive_contract_tests.zig");
    _ = @import("fixtures_comprehensive_differential_test.zig");
}
