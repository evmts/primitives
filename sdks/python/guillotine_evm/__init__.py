"""
Guillotine EVM Python Bindings

High-performance Python bindings for the Guillotine Ethereum Virtual Machine.
"""

__version__ = "0.1.0"
__author__ = "EVMts Contributors"
__email__ = "noreply@evmts.dev"

from .primitives_enhanced import Address, U256, Hash, Bytes
from .evm_enhanced import EVM, ExecutionResult, DeployResult, Log, HardFork
from .bytecode import Bytecode, Opcode, Instruction, BytecodeStats
from .planner import Planner, Plan, CacheStats
from .precompiles import (
    ECPoint, PrecompileResult,
    ecrecover, sha256, ripemd160, identity, modexp,
    ecadd, ecmul, ecpairing, blake2f, point_evaluation,
    is_precompile_address, get_precompile_id, create_precompile_address,
    get_precompile_name
)
from .exceptions import (
    GuillotineError, ExecutionError, InvalidAddressError, ValidationError,
    OutOfGasError, InvalidBytecodeError, MemoryError
)

__all__ = [
    # Core EVM
    "EVM",
    "ExecutionResult",
    "DeployResult",
    "Log",
    "HardFork",
    
    # Primitives
    "Address",
    "U256", 
    "Hash",
    "Bytes",
    
    # Bytecode Analysis
    "Bytecode",
    "Opcode",
    "Instruction",
    "BytecodeStats",
    
    # Optimization and Planning
    "Planner",
    "Plan",
    "CacheStats",
    
    # Precompiled Contracts
    "ECPoint",
    "PrecompileResult",
    "ecrecover",
    "sha256",
    "ripemd160", 
    "identity",
    "modexp",
    "ecadd",
    "ecmul",
    "ecpairing",
    "blake2f",
    "point_evaluation",
    "is_precompile_address",
    "get_precompile_id",
    "create_precompile_address",
    "get_precompile_name",
    
    # Exceptions
    "GuillotineError",
    "ExecutionError", 
    "InvalidAddressError",
    "ValidationError",
    "OutOfGasError",
    "InvalidBytecodeError",
    "MemoryError",
    
    # Version info
    "__version__",
    "__author__",
    "__email__",
]