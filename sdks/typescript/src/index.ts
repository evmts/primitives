// Export all primitives
export { Address } from './primitives/address.js';
export { U256 } from './primitives/u256.js';
export { Hash } from './primitives/hash.js';
export { Bytes } from './primitives/bytes.js';

// Export core components
export { Frame, Stack, Memory } from './core/index.js';
export type { FrameOptions, FrameExecutionResult, StepInfo, FrameState, BytecodeInfo } from './core/index.js';

// Export EVM components
export { GuillotineEVM, ExecutionParams } from './evm/evm.js';
export { ExecutionResult } from './evm/execution-result.js';

// Export errors
export { GuillotineError, GuillotineErrorType } from './errors.js';

// Export WASM utilities
export { initWasm, getWasmLoader } from './wasm/loader.js';

// Re-export everything from primitives, core and evm for convenience
export * from './primitives/index.js';
export * from './core/index.js';
export * from './evm/index.js';