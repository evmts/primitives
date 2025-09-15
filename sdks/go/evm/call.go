package evm

import (
	"fmt"
	"math/big"

	guillotine "github.com/evmts/guillotine/sdks/go"
	"github.com/evmts/guillotine/sdks/go/primitives"
)

// ========================
// Call Parameter Interfaces
// ========================

// CallParams is the interface for all call types
type CallParams interface {
	callType() string
}

// Call represents a regular CALL operation
type Call struct {
	Caller primitives.Address
	To     primitives.Address
	Value  *big.Int
	Input  []byte
	Gas    uint64
}
func (c Call) callType() string { return "call" }

// Callcode represents a CALLCODE operation: execute external code with current storage/context
// Executes code at `to`, but uses caller's storage and address context
type Callcode struct {
	Caller primitives.Address
	To     primitives.Address
	Value  *big.Int
	Input  []byte
	Gas    uint64
}
func (c Callcode) callType() string { return "callcode" }

// Delegatecall represents a DELEGATECALL operation (preserves caller context)
type Delegatecall struct {
	Caller primitives.Address // Original caller, not current contract
	To     primitives.Address
	Input  []byte
	Gas    uint64
}
func (d Delegatecall) callType() string { return "delegatecall" }

// Staticcall represents a STATICCALL operation (read-only)
type Staticcall struct {
	Caller primitives.Address
	To     primitives.Address
	Input  []byte
	Gas    uint64
}
func (s Staticcall) callType() string { return "staticcall" }

// Create represents a CREATE operation
type Create struct {
	Caller   primitives.Address
	Value    *big.Int
	InitCode []byte
	Gas      uint64
}
func (c Create) callType() string { return "create" }

// Create2 represents a CREATE2 operation
type Create2 struct {
	Caller   primitives.Address
	Value    *big.Int
	InitCode []byte
	Salt     *big.Int
	Gas      uint64
}
func (c Create2) callType() string { return "create2" }

// ========================
// Call Method
// ========================

// Call executes any type of EVM call using the interface parameter
func (evm *EVM) Call(params CallParams) (*guillotine.CallResult, error) {
	evm.mu.RLock()
	defer evm.mu.RUnlock()
	
	if evm.vm == nil {
		return nil, fmt.Errorf("EVM instance has been closed")
	}
	
	// Convert interface to guillotine.CallParams based on type
	var callParams *guillotine.CallParams
	
	switch p := params.(type) {
	case Call:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeCall,
			Caller:   p.Caller,
			To:       p.To,
			Value:    p.Value,
			Input:    p.Input,
			Gas:      p.Gas,
			Salt:     big.NewInt(0),
		}
	case Callcode:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeCallcode,
			Caller:   p.Caller,
			To:       p.To,
			Value:    p.Value,
			Input:    p.Input,
			Gas:      p.Gas,
			Salt:     big.NewInt(0),
		}
	case Delegatecall:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeDelegatecall,
			Caller:   p.Caller,
			To:       p.To,
			Value:    big.NewInt(0),
			Input:    p.Input,
			Gas:      p.Gas,
			Salt:     big.NewInt(0),
		}
	case Staticcall:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeStaticcall,
			Caller:   p.Caller,
			To:       p.To,
			Value:    big.NewInt(0),
			Input:    p.Input,
			Gas:      p.Gas,
			Salt:     big.NewInt(0),
		}
	case Create:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeCreate,
			Caller:   p.Caller,
			To:       primitives.ZeroAddress(),
			Value:    p.Value,
			Input:    p.InitCode,
			Gas:      p.Gas,
			Salt:     big.NewInt(0),
		}
	case Create2:
		callParams = &guillotine.CallParams{
			CallType: guillotine.CallTypeCreate2,
			Caller:   p.Caller,
			To:       primitives.ZeroAddress(),
			Value:    p.Value,
			Input:    p.InitCode,
			Gas:      p.Gas,
			Salt:     p.Salt,
		}
	default:
		return nil, fmt.Errorf("unknown call type: %T", params)
	}
	
	// Execute through the VMHandle
	return evm.vm.Call(callParams)
}