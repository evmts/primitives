const std = @import("std");
const builtin = @import("builtin");

/// Professional isomorphic logger for the EVM2 that works across all target architectures
/// including native platforms, WASI, and WASM environments. Uses the std_options.logFn
/// system for automatic platform adaptation.
///
/// Provides debug, error, and warning logging with EVM2-specific prefixing.
/// Debug logs are optimized away in release builds for performance.
/// Debug log for development and troubleshooting
/// Compile-time no-op in ReleaseFast/ReleaseSmall for performance
pub fn debug(comptime format: []const u8, args: anytype) void {
    if (comptime (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)) {
        if (builtin.target.cpu.arch != .wasm32 or builtin.target.os.tag != .freestanding) {
            std.log.debug("[EVM2] " ++ format, args);
        }
    }
}

/// Error log for critical issues that require attention
pub fn err(comptime format: []const u8, args: anytype) void {
    if (builtin.target.cpu.arch != .wasm32 or builtin.target.os.tag != .freestanding) {
        std.log.err("[EVM2] " ++ format, args);
    }
}

/// Warning log for non-critical issues and unexpected conditions
pub fn warn(comptime format: []const u8, args: anytype) void {
    if (builtin.target.cpu.arch != .wasm32 or builtin.target.os.tag != .freestanding) {
        std.log.warn("[EVM2] " ++ format, args);
    }
}

/// Info log for general information (use sparingly for performance)
pub fn info(comptime format: []const u8, args: anytype) void {
    if (builtin.target.cpu.arch != .wasm32 or builtin.target.os.tag != .freestanding) {
        std.log.info("[EVM2] " ++ format, args);
    }
}

test "log functions compile and execute without error" {
    debug("test debug message: {}", .{42});
    err("test error message: {s}", .{"error"});
    warn("test warning message: {d:.2}", .{3.14});
    info("test info message: {any}", .{true});
}

test "log functions handle different argument types" {
    debug("string: {s}, number: {d}, hex: {x}", .{ "test", 123, 0xABC });
    err("boolean: {}, float: {d:.3}", .{ false, 2.718 });
    warn("array: {any}", .{[_]u32{ 1, 2, 3 }});
    info("no args: {s}", .{""});
}