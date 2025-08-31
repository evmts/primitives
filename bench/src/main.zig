const std = @import("std");
const clap = @import("clap");
const Orchestrator = @import("Orchestrator.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                 Display this help and exit.
        \\-V, --version              Show version information and exit
        \\-e, --evm <NAME>           EVM implementation to benchmark (default: zig)
        \\-n, --num-runs <NUM>       Number of runs per test case (default: 10)
        \\--internal-runs <NUM>      Number of internal runs per hyperfine execution (default: 50)
        \\--snailtracer-internal-runs <NUM>   Number of internal runs for snailtracer (defaults to --internal-runs value)
        \\--export <FORMAT>          Export results (json, markdown, detailed)
        \\--compare                  Compare all available EVM implementations
        \\--all                      Include all test cases (by default only working benchmarks are included)
        \\--next                     Use call_mini for Zig EVM (simplified lazy jumpdest validation)
        \\--call2                    Use call2 for Zig EVM (interpret2 with tailcall dispatch)
        \\--show-output              Show output from hyperfine
        \\--diff <TEST>              Run differential trace comparison between REVM and Zig for a specific test case
        \\--diff-output <DIR>        Output directory for differential traces (default: differential_traces)
        \\--detailed                 Run detailed performance analysis with additional metrics
        \\--perf-output <DIR>        Output directory for performance reports (default: perf-reports)
        \\
    );

    const parsers = comptime .{
        .NAME = clap.parsers.string,
        .NUM = clap.parsers.int(u32, 10),
        .FORMAT = clap.parsers.string,
        .TEST = clap.parsers.string,
        .DIR = clap.parsers.string,
        .NAME2 = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        const stderr = std.fs.File{ .handle = 2 };
        diag.reportToFile(stderr, err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try printHelp();
        return;
    }
    if (res.args.version != 0) {
        const stdout_file = std.fs.File{ .handle = 1 };
        var stdout_buffer: [1024]u8 = undefined;
        var stdout = stdout_file.writer(&stdout_buffer);
        try stdout.interface.print("Guillotine Orchestrator {s}\n", .{version()});
        try stdout.interface.flush();
        return;
    }

    const evm_name = res.args.evm orelse "zig";
    const num_runs = res.args.@"num-runs" orelse 50;
    const internal_runs = res.args.@"internal-runs" orelse 100;
    const snailtracer_internal_runs = res.args.@"snailtracer-internal-runs" orelse internal_runs;
    const export_format = res.args.@"export";
    const compare_mode = res.args.compare != 0;
    const include_all_cases = res.args.all != 0;
    const use_next = res.args.next != 0;
    const use_call2 = res.args.call2 != 0;
    const show_output = res.args.@"show-output" != 0;
    const diff_test = res.args.diff;
    const diff_output_dir = res.args.@"diff-output" orelse "differential_traces";
    const detailed = res.args.detailed != 0;
    const perf_output_dir = res.args.@"perf-output" orelse "perf-reports";

    if (diff_test) |test_name| {
        // Differential trace mode
        var orchestrator = try Orchestrator.init(allocator, "zig", 1, 1, 1, 1, 1, 1, false, use_next, use_call2, show_output, "");
        defer orchestrator.deinit();

        try orchestrator.discoverTestCases();

        // Find the specific test case
        var found_test: ?Orchestrator.TestCase = null;
        for (orchestrator.test_cases) |tc| {
            if (std.mem.eql(u8, tc.name, test_name)) {
                found_test = tc;
                break;
            }
        }

        if (found_test) |test_case| {
            try orchestrator.runDifferentialTrace(test_case, diff_output_dir);
        } else {
            std.debug.print("Error: Test case '{s}' not found\n", .{test_name});
            std.debug.print("Available test cases:\n", .{});
            for (orchestrator.test_cases) |tc| {
                std.debug.print("  - {s}\n", .{tc.name});
            }
            std.process.exit(1);
        }
    } else if (compare_mode) {
        // Compare mode: run benchmarks for all available EVMs
        const evms = [_][]const u8{ "zig-call2", "revm", "geth", "evmone" };

        var all_results = std.ArrayList(Orchestrator.BenchmarkResult).empty;
        defer all_results.deinit(allocator);

        for (evms) |evm| {
            std.debug.print("\n=== Running benchmarks for {s} ===\n", .{evm});

            var orchestrator = try Orchestrator.init(allocator, evm, num_runs, internal_runs, num_runs, internal_runs, snailtracer_internal_runs, internal_runs, include_all_cases, use_next, use_call2, show_output, "");
            defer orchestrator.deinit();

            try orchestrator.discoverTestCases();
            try orchestrator.runBenchmarks();

            // Collect results
            for (orchestrator.results.items) |result| {
                try all_results.append(allocator, .{
                    .test_case = try std.fmt.allocPrint(allocator, "{s} ({s})", .{ result.test_case, evm }),
                    .mean_ms = result.mean_ms,
                    .min_ms = result.min_ms,
                    .max_ms = result.max_ms,
                    .std_dev_ms = result.std_dev_ms,
                    .median_ms = result.median_ms,
                    .runs = result.runs,
                    .internal_runs = result.internal_runs,
                });
            }
        }

        // Export comparison results
        if (export_format) |format| {
            if (std.mem.eql(u8, format, "markdown")) {
                try exportComparisonMarkdown(allocator, all_results.items, num_runs, include_all_cases);
            }
        }

        // Free allocated memory
        for (all_results.items) |result| {
            allocator.free(result.test_case);
        }
    } else {
        // Single EVM mode
        var orchestrator = try Orchestrator.init(allocator, evm_name, num_runs, internal_runs, num_runs, internal_runs, snailtracer_internal_runs, internal_runs, include_all_cases, use_next, use_call2, show_output, "");
        defer orchestrator.deinit();

        // Discover test cases
        try orchestrator.discoverTestCases();

        std.debug.print("Discovered {} test cases\n", .{orchestrator.test_cases.len});

        if (detailed) {
            // Run detailed performance analysis
            try orchestrator.runDetailedBenchmarks(perf_output_dir);
        } else {
            // Run normal benchmarks
            try orchestrator.runBenchmarks();

            // Print summary
            orchestrator.printSummary();
        }

        // Export results if requested
        if (export_format) |format| {
            try orchestrator.exportResults(format);
        }
    }
}

const TimeUnit = enum {
    microseconds,
    milliseconds,
    seconds,
};

const FormattedTime = struct {
    value: f64,
    unit: TimeUnit,

    pub fn format(self: FormattedTime, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        const unit_str = switch (self.unit) {
            .microseconds => "μs",
            .milliseconds => "ms",
            .seconds => "s",
        };
        try writer.print("{d:.2} {s}", .{ self.value, unit_str });
    }
};

fn selectOptimalUnit(time_ms: f64) FormattedTime {
    if (time_ms >= 1000.0) {
        return FormattedTime{ .value = time_ms / 1000.0, .unit = .seconds };
    } else if (time_ms >= 1.0) {
        return FormattedTime{ .value = time_ms, .unit = .milliseconds };
    } else {
        return FormattedTime{ .value = time_ms * 1000.0, .unit = .microseconds };
    }
}

fn formatTimeWithUnit(time_ms: f64) FormattedTime {
    return selectOptimalUnit(time_ms);
}

fn formatTimeString(allocator: std.mem.Allocator, time_ms: f64) ![]const u8 {
    const formatted = formatTimeWithUnit(time_ms);
    const unit_str = switch (formatted.unit) {
        .microseconds => "μs",
        .milliseconds => "ms",
        .seconds => "s",
    };
    return std.fmt.allocPrint(allocator, "{d:.2} {s}", .{ formatted.value, unit_str });
}

fn exportComparisonMarkdown(allocator: std.mem.Allocator, results: []const Orchestrator.BenchmarkResult, num_runs: u32, include_all_cases: bool) !void {
    // Create the file in bench/results.md
    var exe_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExeDirPath(&exe_dir_buf);

    const project_root = try std.fs.path.resolve(allocator, &[_][]const u8{ exe_path, "..", ".." });
    defer allocator.free(project_root);

    const results_path = try std.fs.path.join(allocator, &[_][]const u8{ project_root, "bench", "official", "results.md" });
    defer allocator.free(results_path);

    const file = try std.fs.createFileAbsolute(results_path, .{});
    defer file.close();

    // Get current timestamp
    const timestamp = std.time.timestamp();
    const seconds = @as(u64, @intCast(timestamp));

    // Write header
    var writer_buffer: [1024]u8 = undefined;
    var writer = file.writer(&writer_buffer);
    try writer.interface.print("# EVM Benchmark Comparison Results\n\n", .{});
    try writer.interface.print("## Summary\n\n", .{});
    try writer.interface.print("**Test Runs per Case**: {}\n", .{num_runs});
    try writer.interface.print("**EVMs Compared**: Guillotine Call2 (Zig with tailcall dispatch), REVM (Rust), Geth (Go), evmone (C++)\n", .{});
    try writer.interface.print("**Timestamp**: {} (Unix epoch)\n\n", .{seconds});

    // Determine which test cases to include
    const working_test_cases = [_][]const u8{ "erc20-approval-transfer", "erc20-mint", "erc20-transfer", "ten-thousand-hashes", "snailtracer" };

    const all_test_cases = [_][]const u8{
        "erc20-approval-transfer",
        "erc20-mint",
        "erc20-transfer",
        "ten-thousand-hashes",
        "snailtracer",
        "opcodes-arithmetic",
        "opcodes-arithmetic-advanced",
        "opcodes-bitwise",
        "opcodes-block-1",
        "opcodes-block-2",
        "opcodes-comparison",
        "opcodes-control",
        "opcodes-crypto",
        "opcodes-data",
        "opcodes-dup",
        "opcodes-environmental-1",
        "opcodes-environmental-2",
        "opcodes-jump-basic",
        "opcodes-memory",
        "opcodes-push-pop",
        "opcodes-storage-cold",
        "opcodes-storage-warm",
        "opcodes-swap",
        "precompile-blake2f",
        "precompile-bn256add",
        "precompile-bn256mul",
        "precompile-bn256pairing",
        "precompile-ecrecover",
        "precompile-identity",
        "precompile-modexp",
        "precompile-ripemd160",
        "precompile-sha256",
    };

    const test_cases = if (include_all_cases) all_test_cases[0..] else working_test_cases[0..];

    // Add summary statistics first
    try writer.interface.print("## Overall Performance Summary (Per Run)\n\n", .{});
    try writer.interface.writeAll("| Test Case | Zig-Call2 | REVM | Geth | evmone |\n");
    try writer.interface.writeAll("|-----------|-----------|------|------|--------|\n");

    for (test_cases) |test_case| {
        var zig_call2_mean: f64 = 0;
        var revm_mean: f64 = 0;
        var geth_mean: f64 = 0;
        var evmone_mean: f64 = 0;

        for (results) |result| {
            // Check if result starts with test_case followed by " (" (exact match)
            if (std.mem.startsWith(u8, result.test_case, test_case) and
                result.test_case.len > test_case.len and
                std.mem.eql(u8, result.test_case[test_case.len .. test_case.len + 2], " ("))
            {
                if (std.mem.indexOf(u8, result.test_case, "(zig-call2)") != null) {
                    zig_call2_mean = result.mean_ms;
                } else if (std.mem.indexOf(u8, result.test_case, "(revm)") != null) {
                    revm_mean = result.mean_ms;
                } else if (std.mem.indexOf(u8, result.test_case, "(geth)") != null) {
                    geth_mean = result.mean_ms;
                } else if (std.mem.indexOf(u8, result.test_case, "(evmone)") != null) {
                    evmone_mean = result.mean_ms;
                }
            }
        }

        const zig_call2_str = try formatTimeString(allocator, zig_call2_mean);
        defer allocator.free(zig_call2_str);
        const revm_str = try formatTimeString(allocator, revm_mean);
        defer allocator.free(revm_str);
        const geth_str = try formatTimeString(allocator, geth_mean);
        defer allocator.free(geth_str);
        const evmone_str = try formatTimeString(allocator, evmone_mean);
        defer allocator.free(evmone_str);

        try writer.interface.print("| {s:<25} | {s:>9} | {s:>9} | {s:>9} | {s:>9} |\n", .{
            test_case,
            zig_call2_str,
            revm_str,
            geth_str,
            evmone_str,
        });
    }

    // Group results by test case
    try writer.interface.print("\n## Detailed Performance Comparison\n\n", .{});

    // Write comparison tables for each test case

    for (test_cases) |test_case| {
        try writer.interface.print("### {s}\n\n", .{test_case});
        try writer.interface.writeAll("| EVM | Mean (per run) | Median (per run) | Min (per run) | Max (per run) | Std Dev (per run) | Internal Runs |\n");
        try writer.interface.writeAll("|-----|----------------|------------------|---------------|---------------|-------------------|---------------|\n");

        // Find results for this test case (exact match to avoid duplicates)
        for (results) |result| {
            // Check if result starts with test_case followed by " ("
            if (std.mem.startsWith(u8, result.test_case, test_case) and
                result.test_case.len > test_case.len and
                std.mem.eql(u8, result.test_case[test_case.len .. test_case.len + 2], " ("))
            {
                const evm_name = if (std.mem.indexOf(u8, result.test_case, "(zig-call2)") != null)
                    "Guillotine (Call2)"
                else if (std.mem.indexOf(u8, result.test_case, "(revm)") != null)
                    "REVM"
                else if (std.mem.indexOf(u8, result.test_case, "(geth)") != null)
                    "Geth"
                else
                    "evmone";

                const mean_str = try formatTimeString(allocator, result.mean_ms);
                defer allocator.free(mean_str);
                const median_str = try formatTimeString(allocator, result.median_ms);
                defer allocator.free(median_str);
                const min_str = try formatTimeString(allocator, result.min_ms);
                defer allocator.free(min_str);
                const max_str = try formatTimeString(allocator, result.max_ms);
                defer allocator.free(max_str);
                const stddev_str = try formatTimeString(allocator, result.std_dev_ms);
                defer allocator.free(stddev_str);

                try writer.interface.print("| {s:<11} | {s:>14} | {s:>16} | {s:>13} | {s:>13} | {s:>17} | {d:>13} |\n", .{
                    evm_name,
                    mean_str,
                    median_str,
                    min_str,
                    max_str,
                    stddev_str,
                    result.internal_runs,
                });
            }
        }

        try writer.interface.print("\n", .{});
    }

    // Add notes
    try writer.interface.writeAll("\n## Notes\n\n");
    try writer.interface.writeAll("- **All times are normalized per individual execution run**\n");
    try writer.interface.writeAll("- Times are displayed in the most appropriate unit (μs, ms, or s)\n");
    try writer.interface.writeAll("- All implementations use optimized builds:\n");
    try writer.interface.writeAll("  - Zig (Call2): ReleaseFast with tailcall-based interpreter\n");
    try writer.interface.writeAll("  - Rust (REVM): --release\n");
    try writer.interface.writeAll("  - Go (geth): -O3 optimizations\n");
    try writer.interface.writeAll("  - C++ (evmone): -O3 -march=native\n");
    try writer.interface.writeAll("- Lower values indicate better performance\n");
    try writer.interface.writeAll("- Each hyperfine run executes the contract multiple times internally (see Internal Runs column)\n");
    try writer.interface.writeAll("- These benchmarks measure the full execution time including contract deployment\n\n");

    try writer.interface.writeAll("---\n\n");
    try writer.interface.writeAll("*Generated by Guillotine Benchmark Orchestrator*\n");
    try writer.interface.flush();

    std.debug.print("Comparison results exported to bench/results.md\n", .{});
}

fn printHelp() !void {
    const stdout_file = std.fs.File{ .handle = 1 };
    var stdout_buffer: [1024]u8 = undefined;
    var stdout = stdout_file.writer(&stdout_buffer);
    try stdout.interface.print(
        \\EVM Benchmark Orchestrator
        \\
        \\This tool orchestrates benchmarks across various EVM implementations using hyperfine.
        \\
        \\Usage: orchestrator [OPTIONS]
        \\
        \\Options:
        \\  -h, --help                 Display this help and exit
        \\  -e, --evm <NAME>           EVM implementation to benchmark (default: zig)
        \\  -n, --num-runs <NUM>       Number of runs per test case (default: 50)
        \\  --internal-runs <NUM>      Number of internal runs per hyperfine execution (default: 100)
        \\  --snailtracer-internal-runs <NUM>   Number of internal runs for snailtracer (defaults to --internal-runs)
        \\  --export <FORMAT>          Export results (json, markdown, detailed)
        \\  --next                     Use block-based execution for Zig EVM (new optimized interpreter)
        \\  --detailed                 Run detailed performance analysis with additional metrics
        \\  --perf-output <DIR>        Output directory for performance reports (default: perf-reports)
        \\
        \\Examples:
        \\  orchestrator                    Run benchmarks with Zig EVM
        \\  orchestrator -e zig -n 50       Run 50 iterations per test case
        \\  orchestrator --export json      Export results to JSON
        \\  orchestrator --export markdown  Export results to Markdown
        \\  orchestrator --compare --export markdown  Compare all EVMs and export
        \\  orchestrator --compare --js-runs 1  Compare EVMs with only 1 run for JavaScript
        \\  orchestrator --diff erc20-transfer  Run differential trace comparison
        \\  orchestrator --diff snailtracer --diff-output traces  Custom output directory
        \\  orchestrator --detailed        Run detailed performance analysis with metrics
        \\  orchestrator --detailed --perf-output results  Custom output directory for perf reports
        \\
    , .{});
    try stdout.interface.flush();
}

test "formatTimeWithUnit selects appropriate unit" {
    // Test microseconds
    const micro_time = formatTimeWithUnit(0.5);
    try std.testing.expectEqual(TimeUnit.microseconds, micro_time.unit);
    try std.testing.expectApproxEqRel(@as(f64, 500.0), micro_time.value, 0.001);

    // Test milliseconds
    const milli_time = formatTimeWithUnit(50.0);
    try std.testing.expectEqual(TimeUnit.milliseconds, milli_time.unit);
    try std.testing.expectApproxEqRel(@as(f64, 50.0), milli_time.value, 0.001);

    // Test seconds
    const seconds_time = formatTimeWithUnit(2500.0);
    try std.testing.expectEqual(TimeUnit.seconds, seconds_time.unit);
    try std.testing.expectApproxEqRel(@as(f64, 2.5), seconds_time.value, 0.001);
}

test "selectOptimalUnit returns correct unit and value" {
    // Test edge cases
    const edge_micro = selectOptimalUnit(0.999);
    try std.testing.expectEqual(TimeUnit.microseconds, edge_micro.unit);
    try std.testing.expectApproxEqRel(@as(f64, 999.0), edge_micro.value, 0.001);

    const edge_milli = selectOptimalUnit(999.999);
    try std.testing.expectEqual(TimeUnit.milliseconds, edge_milli.unit);
    try std.testing.expectApproxEqRel(@as(f64, 999.999), edge_milli.value, 0.001);

    const edge_seconds = selectOptimalUnit(1000.0);
    try std.testing.expectEqual(TimeUnit.seconds, edge_seconds.unit);
    try std.testing.expectApproxEqRel(@as(f64, 1.0), edge_seconds.value, 0.001);
}

test "FormattedTime.format outputs correct string" {
    const allocator = std.testing.allocator;

    // Test microseconds formatting
    const micro_time = FormattedTime{ .value = 123.45, .unit = .microseconds };
    var micro_buf = std.ArrayList(u8).empty;
    defer micro_buf.deinit(allocator);
    try micro_time.format("", .{}, micro_buf.writer(allocator));
    try std.testing.expectEqualStrings("123.45 μs", micro_buf.items);

    // Test milliseconds formatting
    const milli_time = FormattedTime{ .value = 87.50, .unit = .milliseconds };
    var milli_buf = std.ArrayList(u8).empty;
    defer milli_buf.deinit(allocator);
    try milli_time.format("", .{}, milli_buf.writer(allocator));
    try std.testing.expectEqualStrings("87.50 ms", milli_buf.items);

    // Test seconds formatting
    const seconds_time = FormattedTime{ .value = 3.14, .unit = .seconds };
    var seconds_buf = std.ArrayList(u8).empty;
    defer seconds_buf.deinit(allocator);
    try seconds_time.format("", .{}, seconds_buf.writer(allocator));
    try std.testing.expectEqualStrings("3.14 s", seconds_buf.items);
}

test "TimeUnit enum has correct values" {
    const micro = TimeUnit.microseconds;
    const milli = TimeUnit.milliseconds;
    const secs = TimeUnit.seconds;

    // Test enum values exist and are distinct
    try std.testing.expect(micro != milli);
    try std.testing.expect(milli != secs);
    try std.testing.expect(micro != secs);
}
fn version() []const u8 {
    return "0.1.0"; // TODO: wire from build options
}
