//! High-performance Ethereum Virtual Machine implementation.
//!
//! This module provides a complete EVM with configurable components:
//! - Frame-based execution contexts with stack, memory, and gas tracking
//! - Bytecode analysis and optimization through the Planner system
//! - Pluggable database interfaces for state management
//! - Comprehensive tracing and debugging capabilities
//! - Support for all Ethereum hard forks and EIPs
//!
//! The implementation prioritizes performance through cache-conscious design,
//! compile-time configuration, and platform-specific optimizations.
const std = @import("std");

// Core frame and execution modules
pub const FrameConfig = @import("frame_config.zig").FrameConfig;
pub const Frame = @import("frame.zig").Frame;
pub const FrameInterpreter = @import("frame_interpreter.zig").FrameInterpreter;
pub const createFrameInterpreter = @import("frame_interpreter.zig").createFrameInterpreter;
pub const StackFrame = @import("stack_frame.zig").StackFrame;
pub const Dispatch = @import("dispatch.zig").Dispatch;

// Stack and memory modules
pub const StackConfig = @import("stack_config.zig").StackConfig;
pub const Stack = @import("stack.zig").Stack;
pub const MemoryConfig = @import("memory_config.zig").MemoryConfig;
pub const Memory = @import("memory.zig").Memory;
pub const MemoryError = @import("memory.zig").MemoryError;

// Planner and bytecode analysis
pub const Planner = @import("planner.zig").Planner;
pub const createPlanner = @import("planner.zig").createPlanner;
pub const PlannerConfig = @import("planner_config.zig").PlannerConfig;
pub const Plan = @import("plan.zig").Plan;
pub const createPlan = @import("plan.zig").createPlan;
pub const PlanConfig = @import("plan_config.zig").PlanConfig;
pub const PlanMinimal = @import("plan_minimal.zig").PlanMinimal;
pub const PlanAdvanced = @import("plan_advanced.zig").PlanAdvanced;
pub const PlanDebug = @import("plan_debug.zig").PlanDebug;

// EVM main module and configuration
pub const Evm = @import("evm.zig").Evm;
pub const Evm2 = @import("evm2.zig").Evm2;
pub const EvmConfig = @import("evm_config.zig").EvmConfig;
pub const PlannerStrategy = @import("planner_strategy.zig").PlannerStrategy;

// Default EVM types for backward compatibility
pub const DefaultEvm = Evm(.{});
pub const DefaultEvm2 = Evm2(.{});

// Tracer modules
pub const Tracer = @import("tracer.zig").Tracer;
pub const DetailedStructLog = @import("tracer.zig").DetailedStructLog;
pub const TracerConfig = @import("tracer.zig").TracerConfig;
pub const MemoryCaptureMode = @import("tracer.zig").MemoryCaptureMode;
pub const LoggingTracer = @import("tracer.zig").LoggingTracer;
pub const FileTracer = @import("tracer.zig").FileTracer;
pub const NoOpTracer = @import("tracer.zig").NoOpTracer;
pub const DebuggingTracer = @import("tracer.zig").DebuggingTracer;

// Bytecode modules
pub const BytecodeConfig = @import("bytecode_config.zig").BytecodeConfig;
pub const Bytecode = @import("bytecode.zig").Bytecode;
pub const BytecodeStats = @import("bytecode_stats.zig").BytecodeStats;

// Opcode and instruction data
pub const Opcode = @import("opcode.zig").Opcode;
pub const OpcodeData = @import("opcode_data.zig");
pub const OpcodeSynthetic = @import("opcode_synthetic.zig");
pub const opcode_synthetic = @import("opcode_synthetic.zig");

// Precompiles module
pub const precompiles = @import("precompiles.zig");

// Database and state modules
const block_info_mod = @import("block_info.zig");
pub const BlockInfo = block_info_mod.DefaultBlockInfo;
pub const CompactBlockInfo = block_info_mod.CompactBlockInfo;
pub const BlockInfoConfig = @import("block_info_config.zig").BlockInfoConfig;
pub const CallParams = @import("call_params.zig").CallParams;
pub const CallResult = @import("call_result.zig").CallResult;
pub const CreatedContracts = @import("created_contracts.zig").CreatedContracts;
pub const DatabaseInterface = @import("database_interface.zig").DatabaseInterface;
pub const Account = @import("database_interface_account.zig").Account;
pub const AccessList = @import("access_list.zig").AccessList;
pub const Hardfork = @import("hardfork.zig").Hardfork;
pub const Host = @import("host.zig").Host;
pub const HostMock = @import("host_mock.zig").HostMock;
pub const MemoryDatabase = @import("memory_database.zig").MemoryDatabase;
pub const SelfDestruct = @import("self_destruct.zig").SelfDestruct;
pub const Log = @import("logs.zig").Log;
pub const TransactionContext = @import("transaction_context.zig").TransactionContext;
pub const kzg_setup = @import("kzg_setup.zig");

// Run all tests
test {
    // Test core modules
    _ = FrameConfig;
    _ = Frame;
    _ = FrameInterpreter;
    _ = createFrameInterpreter;
    _ = Dispatch;
    _ = @import("dispatch_tests.zig");
    _ = StackFrame;

    // Test stack and memory
    _ = StackConfig;
    _ = Stack;
    _ = MemoryConfig;
    _ = Memory;
    _ = MemoryError;

    // Test planner and bytecode
    _ = Planner;
    _ = createPlanner;
    _ = PlannerConfig;
    _ = Plan;
    _ = createPlan;
    _ = PlanConfig;
    _ = PlanMinimal;
    _ = PlanAdvanced; // Testing compilation
    _ = PlanDebug; // Testing compilation

    // Test EVM
    _ = Evm;
    _ = Evm2;
    _ = EvmConfig;
    _ = PlannerStrategy;

    // Test tracer modules
    _ = Tracer;
    _ = DetailedStructLog;
    _ = TracerConfig;
    _ = MemoryCaptureMode;
    _ = LoggingTracer;
    _ = FileTracer;
    _ = NoOpTracer;
    _ = DebuggingTracer;

    // Test bytecode modules
    _ = BytecodeConfig;
    _ = Bytecode;
    _ = BytecodeStats;

    // Test opcodes
    _ = Opcode;
    _ = OpcodeData;
    _ = OpcodeSynthetic;
    _ = opcode_synthetic;

    // Test additional modules
    _ = BlockInfo;
    _ = CallParams;
    _ = CallResult;
    _ = CreatedContracts;
    _ = DatabaseInterface;
    _ = Account;
    _ = Hardfork;
    _ = Host;
    _ = MemoryDatabase;
    _ = SelfDestruct;
    _ = AccessList;
}

// Include C API tests via import to ensure they run under `zig build test`
// without modifying the top-level build script. These imports are scoped to
// test-only context and do not affect normal builds.
test "Include C API tests" {
    const frame_c = @import("frame_c.zig");
    const bytecode_c = @import("bytecode_c.zig");
    const memory_c = @import("memory_c.zig");
    const stack_c = @import("stack_c.zig");
    const plan_c = @import("plan_c.zig");
    const planner_c = @import("planner_c.zig");
    const precompiles_c = @import("precompiles_c.zig");
    const hardfork_c = @import("hardfork_c.zig");

    std.testing.refAllDecls(frame_c);
    std.testing.refAllDecls(bytecode_c);
    std.testing.refAllDecls(memory_c);
    std.testing.refAllDecls(stack_c);
    std.testing.refAllDecls(plan_c);
    std.testing.refAllDecls(planner_c);
    std.testing.refAllDecls(precompiles_c);
    std.testing.refAllDecls(hardfork_c);
}

test "Include fusion tests" {
    // TODO: These fusion test files are currently missing
    // _ = @import("test_planner_fusion.zig");
    // _ = @import("test_fusion_e2e.zig");
}

test "Include dedicated test modules" {
    _ = @import("evm_tests.zig");
    _ = @import("bytecode_tests.zig");
    _ = @import("stack_frame_tests.zig");
}
