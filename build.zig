const std = @import("std");
const build_pkg = @import("build/main.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build configuration
    const config = build_pkg.Config.createBuildOptions(b, target);
    const rust_target = build_pkg.Config.getRustTarget(target);

    // Dependencies
    const zbench_dep = b.dependency("zbench", .{ .target = target, .optimize = optimize });
    const clap_dep = b.dependency("clap", .{ .target = target, .optimize = optimize });

    // Libraries
    const blst_lib = build_pkg.BlstLib.createBlstLibrary(b, target, optimize);
    const c_kzg_lib = build_pkg.CKzgLib.createCKzgLibrary(b, target, optimize, blst_lib);

    const rust_build_step = build_pkg.RevmLib.createRustBuildStep(b, optimize, rust_target);
    const bn254_lib = build_pkg.Bn254Lib.createBn254Library(b, target, optimize, config.options, rust_build_step, rust_target);
    const revm_lib = build_pkg.RevmLib.createRevmLibrary(b, target, optimize, rust_build_step, rust_target);

    // Modules
    const modules = build_pkg.Modules.createModules(b, target, optimize, config.options_mod, zbench_dep, c_kzg_lib, blst_lib, bn254_lib, revm_lib);

    // Executables
    const guillotine_exe = build_pkg.GuillotineExe.createExecutable(b, modules.exe_mod);
    _ = build_pkg.GuillotineExe.createRunStep(b, guillotine_exe);

    const evm_runner = build_pkg.EvmRunnerExe.createEvmRunner(b, target, optimize, modules.evm_mod, modules.primitives_mod, c_kzg_lib, blst_lib, bn254_lib, clap_dep);
    const evm_runner_small = build_pkg.EvmRunnerExe.createEvmRunnerSmall(b, target, .ReleaseSmall, modules.evm_mod, modules.primitives_mod, c_kzg_lib, blst_lib, bn254_lib, clap_dep);
    build_pkg.EvmRunnerExe.createRunSteps(b, evm_runner, evm_runner_small);

    // Asset generation for devtool
    const asset_generator = build_pkg.AssetGenerator;
    const npm_check = b.addSystemCommand(&[_][]const u8{ "which", "npm" });
    npm_check.addCheck(.{ .expect_stdout_match = "npm" });

    const npm_install = b.addSystemCommand(&[_][]const u8{ "npm", "install" });
    npm_install.setCwd(b.path("src/devtool"));
    npm_install.step.dependOn(&npm_check.step);

    const npm_build = b.addSystemCommand(&[_][]const u8{ "npm", "run", "build" });
    npm_build.setCwd(b.path("src/devtool"));
    npm_build.step.dependOn(&npm_install.step);

    const generate_assets = asset_generator.GenerateAssetsStep.init(b, "src/devtool/dist", "src/devtool/assets.zig");
    generate_assets.step.dependOn(&npm_build.step);

    const devtool_exe = build_pkg.DevtoolExe.createDevtoolExecutable(b, target, optimize, modules.lib_mod, modules.evm_mod, modules.primitives_mod, modules.provider_mod, &generate_assets.step);
    build_pkg.DevtoolExe.createDevtoolSteps(b, devtool_exe, target);

    // Benchmark executables
    const debug_runner = build_pkg.BenchmarksExe.createDebugRunner(b, target, modules.evm_mod, modules.primitives_mod);
    const crash_debugger = build_pkg.BenchmarksExe.createCrashDebugger(b, target, modules.evm_mod, modules.primitives_mod);
    const simple_crash_test = build_pkg.BenchmarksExe.createSimpleCrashTest(b, target, modules.evm_mod, modules.primitives_mod);

    // Get the build step created by EvmRunnerExe.createRunSteps
    const build_evm_runner_step = b.step("build-evm-runner-manual", "Build the EVM benchmark runner");
    build_evm_runner_step.dependOn(&b.addInstallArtifact(evm_runner, .{}).step);

    _ = build_pkg.BenchmarksExe.createPoopRunner(b, target, build_evm_runner_step);
    _ = build_pkg.BenchmarksExe.createOrchestrator(b, target, clap_dep);
    build_pkg.BenchmarksExe.createBenchmarkSteps(debug_runner, crash_debugger, simple_crash_test, b);

    // Libraries and utilities
    build_pkg.Utils.createLibraries(b, modules.lib_mod, bn254_lib);
    const lib = b.addLibrary(.{ .linkage = .static, .name = "Guillotine", .root_module = modules.lib_mod });
    build_pkg.Utils.createDocsStep(b, lib);
    _ = build_pkg.Utils.createOpcodeTestLib(b, target, optimize, modules.evm_mod, modules.primitives_mod, modules.crypto_mod, config.options_mod, bn254_lib);
    build_pkg.Utils.createExternalBuildSteps(b);

    // Tests
    const tests_pkg = build_pkg.Tests;
    const lib_unit_tests = b.addTest(.{ .root_module = modules.lib_mod });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const integration_tests = tests_pkg.createIntegrationTests(b, target, optimize, modules, revm_lib, bn254_lib, c_kzg_lib, blst_lib, rust_target);
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    
    // ERC20 deployment gas issue test
    const erc20_gas_test = b.addTest(.{
        .name = "test-erc20-gas",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/erc20_deployment_gas_issue.zig"),
            .target = target,
            .optimize = .Debug,  // Debug for better logging
        }),
    });
    erc20_gas_test.root_module.addImport("evm", modules.evm_mod);
    erc20_gas_test.root_module.addImport("primitives", modules.primitives_mod);
    erc20_gas_test.root_module.addImport("crypto", modules.crypto_mod);
    erc20_gas_test.root_module.addImport("build_options", config.options_mod);
    erc20_gas_test.root_module.addImport("log", b.createModule(.{
        .root_source_file = b.path("src/log.zig"),
        .target = target,
        .optimize = .Debug,
    }));
    erc20_gas_test.linkLibrary(c_kzg_lib);
    erc20_gas_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| erc20_gas_test.linkLibrary(bn254);
    erc20_gas_test.linkLibC();
    
    const run_erc20_gas_test = b.addRunArtifact(erc20_gas_test);
    const erc20_gas_test_step = b.step("test-erc20-gas", "Test ERC20 deployment gas issue");
    erc20_gas_test_step.dependOn(&run_erc20_gas_test.step);
    
    // Jump table issue test
    const jump_table_test = b.addTest(.{
        .name = "test-jump-table",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/jump_table_issue.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    jump_table_test.root_module.addImport("evm", modules.evm_mod);
    jump_table_test.root_module.addImport("primitives", modules.primitives_mod);
    jump_table_test.root_module.addImport("crypto", modules.crypto_mod);
    jump_table_test.root_module.addImport("build_options", config.options_mod);
    jump_table_test.root_module.addImport("log", b.createModule(.{
        .root_source_file = b.path("src/log.zig"),
    }));
    jump_table_test.linkLibrary(c_kzg_lib);
    jump_table_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| jump_table_test.linkLibrary(bn254);
    jump_table_test.linkLibC();
    
    const run_jump_table_test = b.addRunArtifact(jump_table_test);
    const jump_table_test_step = b.step("test-jump-table", "Test jump table JUMPDEST recognition");
    jump_table_test_step.dependOn(&run_jump_table_test.step);

    // BN254 benchmarks
    const zbench_module = zbench_dep.module("zbench");
    const zbench_bn254 = b.addExecutable(.{
        .name = "zbench-bn254",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/crypto/bn254/zbench_benchmarks.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    zbench_bn254.root_module.addImport("zbench", zbench_module);

    const run_zbench_bn254 = b.addRunArtifact(zbench_bn254);
    const zbench_bn254_step = b.step("bench-bn254", "Run zbench BN254 benchmarks");
    zbench_bn254_step.dependOn(&run_zbench_bn254.step);

    // EVM benchmarks
    const zbench_evm = b.addExecutable(.{
        .name = "zbench-evm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/evm/evm_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    zbench_evm.root_module.addImport("zbench", zbench_module);
    zbench_evm.root_module.addImport("log", b.createModule(.{
        .root_source_file = b.path("src/log.zig"),
        .target = target,
        .optimize = optimize,
    }));
    zbench_evm.root_module.addImport("primitives", modules.primitives_mod);
    zbench_evm.root_module.addImport("evm", modules.evm_mod);
    zbench_evm.root_module.addImport("crypto", modules.crypto_mod);
    if (modules.revm_mod) |revm_mod| {
        zbench_evm.root_module.addImport("revm", revm_mod);
    }
    if (revm_lib) |revm| zbench_evm.linkLibrary(revm);
    if (bn254_lib) |bn254| zbench_evm.linkLibrary(bn254);
    zbench_evm.linkLibrary(c_kzg_lib);
    zbench_evm.linkLibrary(blst_lib);
    zbench_evm.linkLibC();

    const run_zbench_evm = b.addRunArtifact(zbench_evm);
    const zbench_evm_step = b.step("bench-evm", "Run zbench EVM benchmarks");
    zbench_evm_step.dependOn(&run_zbench_evm.step);

    // ERC20 deployment issue test
    const erc20_deployment_test = b.addTest(.{
        .name = "test-erc20-deployment",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/evm/erc20_deployment_issue.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    erc20_deployment_test.root_module.addImport("evm", modules.evm_mod);
    erc20_deployment_test.root_module.addImport("primitives", modules.primitives_mod);
    erc20_deployment_test.root_module.addImport("crypto", modules.crypto_mod);
    erc20_deployment_test.root_module.addImport("build_options", config.options_mod);
    erc20_deployment_test.root_module.addImport("log", b.createModule(.{
        .root_source_file = b.path("src/log.zig"),
        .target = target,
        .optimize = .Debug,
    }));
    
    // Add REVM module and library for differential testing
    if (modules.revm_mod) |revm_mod| {
        erc20_deployment_test.root_module.addImport("revm", revm_mod);
        if (revm_lib) |revm| {
            erc20_deployment_test.linkLibrary(revm);
            erc20_deployment_test.addIncludePath(b.path("src/revm_wrapper"));
            
            const revm_rust_target_dir_test = if (optimize == .Debug) "debug" else "release";
            const revm_dylib_path_test = if (rust_target) |target_triple|
                b.fmt("target/{s}/{s}/librevm_wrapper.dylib", .{ target_triple, revm_rust_target_dir_test })
            else
                b.fmt("target/{s}/librevm_wrapper.dylib", .{revm_rust_target_dir_test});
            erc20_deployment_test.addObjectFile(b.path(revm_dylib_path_test));
            
            if (target.result.os.tag == .linux) {
                erc20_deployment_test.linkSystemLibrary("m");
                erc20_deployment_test.linkSystemLibrary("pthread");
                erc20_deployment_test.linkSystemLibrary("dl");
            } else if (target.result.os.tag == .macos) {
                erc20_deployment_test.linkSystemLibrary("c++");
                erc20_deployment_test.linkFramework("Security");
                erc20_deployment_test.linkFramework("SystemConfiguration");
                erc20_deployment_test.linkFramework("CoreFoundation");
            }
            
            erc20_deployment_test.step.dependOn(&revm.step);
        }
    }
    
    erc20_deployment_test.linkLibrary(c_kzg_lib);
    erc20_deployment_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| erc20_deployment_test.linkLibrary(bn254);
    erc20_deployment_test.linkLibC();
    
    const run_erc20_deployment_test = b.addRunArtifact(erc20_deployment_test);
    const erc20_deployment_test_step = b.step("test-erc20-deployment", "Test ERC20 deployment issue");
    erc20_deployment_test_step.dependOn(&run_erc20_deployment_test.step);

    // Fixtures comprehensive differential test
    const fixtures_differential_test = b.addTest(.{
        .name = "fixtures-differential-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/differential/fixtures_comprehensive_differential_test.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    fixtures_differential_test.root_module.addImport("evm", modules.evm_mod);
    fixtures_differential_test.root_module.addImport("primitives", modules.primitives_mod);
    fixtures_differential_test.root_module.addImport("crypto", modules.crypto_mod);
    fixtures_differential_test.root_module.addImport("build_options", config.options_mod);
    fixtures_differential_test.root_module.addImport("log", b.createModule(.{ .root_source_file = b.path("src/log.zig"), .target = target, .optimize = .Debug }));
    
    // Add REVM module and library for differential testing
    if (modules.revm_mod) |revm_mod| {
        fixtures_differential_test.root_module.addImport("revm", revm_mod);
        if (revm_lib) |revm| {
            fixtures_differential_test.linkLibrary(revm);
            fixtures_differential_test.addIncludePath(b.path("src/revm_wrapper"));
            
            const revm_rust_target_dir_test = if (optimize == .Debug) "debug" else "release";
            const revm_dylib_path_test = if (rust_target) |target_triple|
                b.fmt("target/{s}/{s}/librevm_wrapper.dylib", .{ target_triple, revm_rust_target_dir_test })
            else
                b.fmt("target/{s}/librevm_wrapper.dylib", .{revm_rust_target_dir_test});
            fixtures_differential_test.addObjectFile(b.path(revm_dylib_path_test));
            
            if (target.result.os.tag == .linux) {
                fixtures_differential_test.linkSystemLibrary("m");
                fixtures_differential_test.linkSystemLibrary("pthread");
                fixtures_differential_test.linkSystemLibrary("dl");
            } else if (target.result.os.tag == .macos) {
                fixtures_differential_test.linkSystemLibrary("c++");
                fixtures_differential_test.linkFramework("Security");
                fixtures_differential_test.linkFramework("SystemConfiguration");
                fixtures_differential_test.linkFramework("CoreFoundation");
            }
            
            fixtures_differential_test.step.dependOn(&revm.step);
        }
    }
    
    fixtures_differential_test.linkLibrary(c_kzg_lib);
    fixtures_differential_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| fixtures_differential_test.linkLibrary(bn254);
    fixtures_differential_test.linkLibC();
    
    const run_fixtures_differential_test = b.addRunArtifact(fixtures_differential_test);
    const fixtures_differential_test_step = b.step("test-fixtures-differential", "Run differential tests for benchmark fixtures (ERC20, snailtracer, etc.)");
    fixtures_differential_test_step.dependOn(&run_fixtures_differential_test.step);

    // Snailtracer differential test
    const snailtracer_test = b.addTest(.{
        .name = "snailtracer-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/evm/snailtracer_test.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    snailtracer_test.root_module.addImport("evm", modules.evm_mod);
    snailtracer_test.root_module.addImport("primitives", modules.primitives_mod);
    snailtracer_test.root_module.addImport("crypto", modules.crypto_mod);
    snailtracer_test.root_module.addImport("build_options", config.options_mod);
    snailtracer_test.root_module.addImport("log", b.createModule(.{ .root_source_file = b.path("src/log.zig"), .target = target, .optimize = .Debug }));
    
    // Add REVM module and library for differential testing
    if (modules.revm_mod) |revm_mod| {
        snailtracer_test.root_module.addImport("revm", revm_mod);
        if (revm_lib) |revm| {
            snailtracer_test.linkLibrary(revm);
            snailtracer_test.addIncludePath(b.path("src/revm_wrapper"));
            
            const revm_rust_target_dir_test = if (optimize == .Debug) "debug" else "release";
            const revm_dylib_path_test = if (rust_target) |target_triple|
                b.fmt("target/{s}/{s}/librevm_wrapper.dylib", .{ target_triple, revm_rust_target_dir_test })
            else
                b.fmt("target/{s}/librevm_wrapper.dylib", .{revm_rust_target_dir_test});
            snailtracer_test.addObjectFile(b.path(revm_dylib_path_test));
            
            if (target.result.os.tag == .linux) {
                snailtracer_test.linkSystemLibrary("m");
                snailtracer_test.linkSystemLibrary("pthread");
                snailtracer_test.linkSystemLibrary("dl");
            } else if (target.result.os.tag == .macos) {
                snailtracer_test.linkSystemLibrary("c++");
                snailtracer_test.linkFramework("Security");
                snailtracer_test.linkFramework("SystemConfiguration");
                snailtracer_test.linkFramework("CoreFoundation");
            }
            
            snailtracer_test.step.dependOn(&revm.step);
        }
    }
    
    snailtracer_test.linkLibrary(c_kzg_lib);
    snailtracer_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| snailtracer_test.linkLibrary(bn254);
    snailtracer_test.linkLibC();
    
    const run_snailtracer_test = b.addRunArtifact(snailtracer_test);
    const snailtracer_test_step = b.step("test-snailtracer", "Run snailtracer differential test");
    snailtracer_test_step.dependOn(&run_snailtracer_test.step);

    // GT opcode bug test
    const gt_bug_test = b.addTest(.{
        .name = "gt-bug-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test_gt_exact.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    gt_bug_test.root_module.addImport("evm", modules.evm_mod);
    gt_bug_test.root_module.addImport("primitives", modules.primitives_mod);
    gt_bug_test.root_module.addImport("crypto", modules.crypto_mod);
    gt_bug_test.root_module.addImport("build_options", config.options_mod);
    gt_bug_test.root_module.addImport("log", b.createModule(.{ .root_source_file = b.path("src/log.zig"), .target = target, .optimize = .Debug }));
    gt_bug_test.linkLibrary(c_kzg_lib);
    gt_bug_test.linkLibrary(blst_lib);
    if (bn254_lib) |bn254| gt_bug_test.linkLibrary(bn254);
    gt_bug_test.linkLibC();
    const test_gt_bug = b.step("test-gt-bug", "Test GT opcode bug");
    test_gt_bug.dependOn(&b.addRunArtifact(gt_bug_test).step);

    // Per-opcode differential tests discovered in test/evm/opcodes
    // We dynamically scan the directory and add a test target for each file matching *_test.zig
    const opcode_tests_step = b.step("test-opcodes", "Run all per-opcode differential tests");
    if (std.fs.cwd().openDir("test/evm/opcodes", .{ .iterate = true }) catch null) |op_dir_val| {
        var op_dir = op_dir_val; // make mutable for close()
        defer op_dir.close();
        var it = op_dir.iterate();
        while (it.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, "_test.zig")) continue;

            const file_path = b.fmt("test/evm/opcodes/{s}", .{entry.name});
            const test_name = b.fmt("opcode-{s}", .{entry.name});
            
            // Extract opcode hex from filename (e.g., "01_test.zig" -> "0x01")
            const opcode_hex = entry.name[0..std.mem.indexOf(u8, entry.name, "_") orelse continue];
            const individual_step_name = b.fmt("test-opcodes-0x{s}", .{opcode_hex});
            const individual_step_desc = b.fmt("Test opcode 0x{s}", .{opcode_hex});

            const t = b.addTest(.{
                .name = test_name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(file_path),
                    .target = target,
                    .optimize = .Debug,
                }),
            });
            // Inject module dependencies used by the differential harness
            t.root_module.addImport("evm", modules.evm_mod);
            t.root_module.addImport("primitives", modules.primitives_mod);
            t.root_module.addImport("crypto", modules.crypto_mod);
            t.root_module.addImport("build_options", config.options_mod);
            t.root_module.addImport("log", b.createModule(.{ .root_source_file = b.path("src/log.zig"), .target = target, .optimize = .Debug }));

            // Link external libs
            t.linkLibrary(c_kzg_lib);
            t.linkLibrary(blst_lib);
            if (bn254_lib) |bn254| t.linkLibrary(bn254);
            t.linkLibC();

            // Add REVM integration for differential tests
            if (modules.revm_mod) |revm_mod| {
                t.root_module.addImport("revm", revm_mod);
                if (revm_lib) |revm| {
                    t.linkLibrary(revm);
                    t.addIncludePath(b.path("src/revm_wrapper"));
                    const revm_rust_target_dir_test = if (optimize == .Debug) "debug" else "release";
                    const revm_dylib_path_test = if (rust_target) |target_triple|
                        b.fmt("target/{s}/{s}/librevm_wrapper.dylib", .{ target_triple, revm_rust_target_dir_test })
                    else
                        b.fmt("target/{s}/librevm_wrapper.dylib", .{revm_rust_target_dir_test});
                    t.addObjectFile(b.path(revm_dylib_path_test));

                    if (target.result.os.tag == .linux) {
                        t.linkSystemLibrary("m");
                        t.linkSystemLibrary("pthread");
                        t.linkSystemLibrary("dl");
                    } else if (target.result.os.tag == .macos) {
                        t.linkSystemLibrary("c++");
                        t.linkFramework("Security");
                        t.linkFramework("SystemConfiguration");
                        t.linkFramework("CoreFoundation");
                    }
                    t.step.dependOn(&revm.step);
                }
            }

            const run_t = b.addRunArtifact(t);
            
            // Add to the "all opcodes" step
            opcode_tests_step.dependOn(&run_t.step);
            
            // Create individual test step for this opcode
            const individual_step = b.step(individual_step_name, individual_step_desc);
            individual_step.dependOn(&run_t.step);
        }
    }

    // ERC20 mint differential test
    {
        const erc20_mint_test = b.addTest(.{
            .name = "erc20_mint_test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/evm/erc20_mint_test.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });

        // Add all the required dependencies
        erc20_mint_test.root_module.addImport("evm", modules.evm_mod);
        erc20_mint_test.root_module.addImport("primitives", modules.primitives_mod);
        erc20_mint_test.root_module.addImport("crypto", modules.crypto_mod);
        
        // Add REVM module and library for differential testing
        if (modules.revm_mod) |revm_mod| {
            erc20_mint_test.root_module.addImport("revm", revm_mod);
            if (revm_lib) |revm| {
                erc20_mint_test.linkLibrary(revm);
                erc20_mint_test.addIncludePath(b.path("src/revm_wrapper"));
                
                const revm_rust_target_dir_test = if (optimize == .Debug) "debug" else "release";
                const revm_dylib_path_test = if (rust_target) |target_triple|
                    b.fmt("target/{s}/{s}/librevm_wrapper.dylib", .{ target_triple, revm_rust_target_dir_test })
                else
                    b.fmt("target/{s}/librevm_wrapper.dylib", .{revm_rust_target_dir_test});
                erc20_mint_test.addObjectFile(b.path(revm_dylib_path_test));
                
                if (target.result.os.tag == .linux) {
                    erc20_mint_test.linkSystemLibrary("m");
                    erc20_mint_test.linkSystemLibrary("pthread");
                    erc20_mint_test.linkSystemLibrary("dl");
                } else if (target.result.os.tag == .macos) {
                    erc20_mint_test.linkSystemLibrary("c++");
                    erc20_mint_test.linkFramework("Security");
                    erc20_mint_test.linkFramework("SystemConfiguration");
                    erc20_mint_test.linkFramework("CoreFoundation");
                }
                
                erc20_mint_test.step.dependOn(&revm.step);
            }
        }
        
        // Link other required libraries
        erc20_mint_test.linkLibrary(c_kzg_lib);
        erc20_mint_test.linkLibrary(blst_lib);
        if (bn254_lib) |bn254| erc20_mint_test.linkLibrary(bn254);
        erc20_mint_test.linkLibC();

        const run_erc20_mint_test = b.addRunArtifact(erc20_mint_test);
        
        const erc20_mint_step = b.step("test-erc20-mint", "Run ERC20 mint differential test");
        erc20_mint_step.dependOn(&run_erc20_mint_test.step);
    }

    // CODECOPY+RETURN test
    {
        const codecopy_test = b.addTest(.{
            .name = "codecopy_return_test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/evm/codecopy_return_test.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        
        codecopy_test.root_module.addImport("evm", modules.evm_mod);
        codecopy_test.root_module.addImport("primitives", modules.primitives_mod);
        codecopy_test.root_module.addImport("crypto", modules.crypto_mod);
        codecopy_test.root_module.addImport("build_options", config.options_mod);
        
        const run_codecopy_test = b.addRunArtifact(codecopy_test);
        const codecopy_step = b.step("test-codecopy-return", "Test CODECOPY and RETURN opcodes");
        codecopy_step.dependOn(&run_codecopy_test.step);
    }

    // Language bindings
    build_pkg.WasmBindings.createWasmSteps(b, optimize, config.options_mod);
    build_pkg.PythonBindings.createPythonSteps(b);
    build_pkg.SwiftBindings.createSwiftSteps(b);
    build_pkg.GoBindings.createGoSteps(b);
    build_pkg.TypeScriptBindings.createTypeScriptSteps(b);
}
