// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"errors"

	"github.com/ethereum/go-ethereum/params"
)

type (
	ExecutionFunc func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error)
	gasFunc       func(*EVM, *Contract, *Stack, *Memory, uint64) (uint64, error) // last parameter is the requested memory size as a uint64
	// memorySizeFunc returns the required size, and whether the operation overflowed a uint64
	MemorySizeFunc func(*Stack) (size uint64, overflow bool)
)

var errGasUintOverflow = errors.New("gas uint64 overflow")

type Operation struct {
	// execute is the operation function
	Execute     ExecutionFunc
	constantGas uint64
	dynamicGas  gasFunc
	// minStack tells how many stack items are required
	MinStack int
	// maxStack specifies the max length the stack can have for this operation
	// to not overflow the stack.
	MaxStack int

	// memorySize returns the memory size required for the operation
	MemorySize MemorySizeFunc

	halts   bool // indicates whether the operation should halt further execution
	jumps   bool // indicates whether the program counter should not increment
	writes  bool // determines whether this a state modifying operation
	Valid   bool // indication whether the retrieved operation is valid and known
	reverts bool // determines whether the operation reverts state (implicitly halts)
	returns bool // determines whether the operations sets the return data content
}

var (
	frontierInstructionSet         = newFrontierInstructionSet()
	homesteadInstructionSet        = newHomesteadInstructionSet()
	tangerineWhistleInstructionSet = newTangerineWhistleInstructionSet()
	spuriousDragonInstructionSet   = newSpuriousDragonInstructionSet()
	byzantiumInstructionSet        = newByzantiumInstructionSet()
	constantinopleInstructionSet   = NewConstantinopleInstructionSet()
	istanbulInstructionSet         = newIstanbulInstructionSet()
)

// JumpTable contains the EVM opcodes supported at a given fork.
type JumpTable [256]Operation

// newIstanbulInstructionSet returns the frontier, homestead
// byzantium, contantinople and petersburg instructions.
func newIstanbulInstructionSet() JumpTable {
	instructionSet := NewConstantinopleInstructionSet()

	enable1344(&instructionSet) // ChainID opcode - https://eips.ethereum.org/EIPS/eip-1344
	enable1884(&instructionSet) // Reprice reader opcodes - https://eips.ethereum.org/EIPS/eip-1884
	enable2200(&instructionSet) // Net metered SSTORE - https://eips.ethereum.org/EIPS/eip-2200

	return instructionSet
}

// newConstantinopleInstructionSet returns the frontier, homestead
// byzantium and contantinople instructions.
func NewConstantinopleInstructionSet() JumpTable {
	// instructions that can be executed during the byzantium phase.
	instructionSet := newByzantiumInstructionSet()
	instructionSet[SHL] = Operation{
		Execute:     opSHL,
		constantGas: GasFastestStep,
		MinStack:    minStack(2, 1),
		MaxStack:    maxStack(2, 1),
		Valid:       true,
	}
	instructionSet[SHR] = Operation{
		Execute:     opSHR,
		constantGas: GasFastestStep,
		MinStack:    minStack(2, 1),
		MaxStack:    maxStack(2, 1),
		Valid:       true,
	}
	instructionSet[SAR] = Operation{
		Execute:     opSAR,
		constantGas: GasFastestStep,
		MinStack:    minStack(2, 1),
		MaxStack:    maxStack(2, 1),
		Valid:       true,
	}
	instructionSet[EXTCODEHASH] = Operation{
		Execute:     opExtCodeHash,
		constantGas: params.ExtcodeHashGasConstantinople,
		MinStack:    minStack(1, 1),
		MaxStack:    maxStack(1, 1),
		Valid:       true,
	}
	instructionSet[CREATE2] = Operation{
		Execute:     opCreate2,
		constantGas: params.Create2Gas,
		dynamicGas:  gasCreate2,
		MinStack:    minStack(4, 1),
		MaxStack:    maxStack(4, 1),
		MemorySize:  memoryCreate2,
		Valid:       true,
		writes:      true,
		returns:     true,
	}
	return instructionSet
}

// newByzantiumInstructionSet returns the frontier, homestead and
// byzantium instructions.
func newByzantiumInstructionSet() JumpTable {
	instructionSet := newSpuriousDragonInstructionSet()
	instructionSet[STATICCALL] = Operation{
		Execute:     opStaticCall,
		constantGas: params.CallGasEIP150,
		dynamicGas:  gasStaticCall,
		MinStack:    minStack(6, 1),
		MaxStack:    maxStack(6, 1),
		MemorySize:  memoryStaticCall,
		Valid:       true,
		returns:     true,
	}
	instructionSet[RETURNDATASIZE] = Operation{
		Execute:     opReturnDataSize,
		constantGas: GasQuickStep,
		MinStack:    minStack(0, 1),
		MaxStack:    maxStack(0, 1),
		Valid:       true,
	}
	instructionSet[RETURNDATACOPY] = Operation{
		Execute:     opReturnDataCopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasReturnDataCopy,
		MinStack:    minStack(3, 0),
		MaxStack:    maxStack(3, 0),
		MemorySize:  memoryReturnDataCopy,
		Valid:       true,
	}
	instructionSet[REVERT] = Operation{
		Execute:    opRevert,
		dynamicGas: gasRevert,
		MinStack:   minStack(2, 0),
		MaxStack:   maxStack(2, 0),
		MemorySize: memoryRevert,
		Valid:      true,
		reverts:    true,
		returns:    true,
	}
	return instructionSet
}

// EIP 158 a.k.a Spurious Dragon
func newSpuriousDragonInstructionSet() JumpTable {
	instructionSet := newTangerineWhistleInstructionSet()
	instructionSet[EXP].dynamicGas = gasExpEIP158
	return instructionSet

}

// EIP 150 a.k.a Tangerine Whistle
func newTangerineWhistleInstructionSet() JumpTable {
	instructionSet := newHomesteadInstructionSet()
	instructionSet[BALANCE].constantGas = params.BalanceGasEIP150
	instructionSet[EXTCODESIZE].constantGas = params.ExtcodeSizeGasEIP150
	instructionSet[SLOAD].constantGas = params.SloadGasEIP150
	instructionSet[EXTCODECOPY].constantGas = params.ExtcodeCopyBaseEIP150
	instructionSet[CALL].constantGas = params.CallGasEIP150
	instructionSet[CALLCODE].constantGas = params.CallGasEIP150
	instructionSet[DELEGATECALL].constantGas = params.CallGasEIP150
	return instructionSet
}

// newHomesteadInstructionSet returns the frontier and homestead
// instructions that can be executed during the homestead phase.
func newHomesteadInstructionSet() JumpTable {
	instructionSet := newFrontierInstructionSet()
	instructionSet[DELEGATECALL] = Operation{
		Execute:     opDelegateCall,
		dynamicGas:  gasDelegateCall,
		constantGas: params.CallGasFrontier,
		MinStack:    minStack(6, 1),
		MaxStack:    maxStack(6, 1),
		MemorySize:  memoryDelegateCall,
		Valid:       true,
		returns:     true,
	}
	return instructionSet
}

// newFrontierInstructionSet returns the frontier instructions
// that can be executed during the frontier phase.
func newFrontierInstructionSet() JumpTable {
	return JumpTable{
		STOP: {
			Execute:     opStop,
			constantGas: 0,
			MinStack:    minStack(0, 0),
			MaxStack:    maxStack(0, 0),
			halts:       true,
			Valid:       true,
		},
		ADD: {
			Execute:     opAdd,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		MUL: {
			Execute:     opMul,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SUB: {
			Execute:     opSub,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		DIV: {
			Execute:     opDiv,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SDIV: {
			Execute:     opSdiv,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		MOD: {
			Execute:     opMod,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SMOD: {
			Execute:     opSmod,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		ADDMOD: {
			Execute:     opAddmod,
			constantGas: GasMidStep,
			MinStack:    minStack(3, 1),
			MaxStack:    maxStack(3, 1),
			Valid:       true,
		},
		MULMOD: {
			Execute:     opMulmod,
			constantGas: GasMidStep,
			MinStack:    minStack(3, 1),
			MaxStack:    maxStack(3, 1),
			Valid:       true,
		},
		EXP: {
			Execute:    opExp,
			dynamicGas: gasExpFrontier,
			MinStack:   minStack(2, 1),
			MaxStack:   maxStack(2, 1),
			Valid:      true,
		},
		SIGNEXTEND: {
			Execute:     opSignExtend,
			constantGas: GasFastStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		LT: {
			Execute:     opLt,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		GT: {
			Execute:     opGt,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SLT: {
			Execute:     opSlt,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SGT: {
			Execute:     opSgt,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		EQ: {
			Execute:     opEq,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		ISZERO: {
			Execute:     opIszero,
			constantGas: GasFastestStep,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		AND: {
			Execute:     opAnd,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		XOR: {
			Execute:     opXor,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		OR: {
			Execute:     opOr,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		NOT: {
			Execute:     opNot,
			constantGas: GasFastestStep,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		BYTE: {
			Execute:     opByte,
			constantGas: GasFastestStep,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			Valid:       true,
		},
		SHA3: {
			Execute:     opSha3,
			constantGas: params.Sha3Gas,
			dynamicGas:  gasSha3,
			MinStack:    minStack(2, 1),
			MaxStack:    maxStack(2, 1),
			MemorySize:  memorySha3,
			Valid:       true,
		},
		ADDRESS: {
			Execute:     opAddress,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		BALANCE: {
			Execute:     opBalance,
			constantGas: params.BalanceGasFrontier,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		ORIGIN: {
			Execute:     opOrigin,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		CALLER: {
			Execute:     opCaller,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		CALLVALUE: {
			Execute:     opCallValue,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		CALLDATALOAD: {
			Execute:     opCallDataLoad,
			constantGas: GasFastestStep,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		CALLDATASIZE: {
			Execute:     opCallDataSize,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		CALLDATACOPY: {
			Execute:     opCallDataCopy,
			constantGas: GasFastestStep,
			dynamicGas:  gasCallDataCopy,
			MinStack:    minStack(3, 0),
			MaxStack:    maxStack(3, 0),
			MemorySize:  memoryCallDataCopy,
			Valid:       true,
		},
		CODESIZE: {
			Execute:     opCodeSize,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		CODECOPY: {
			Execute:     opCodeCopy,
			constantGas: GasFastestStep,
			dynamicGas:  gasCodeCopy,
			MinStack:    minStack(3, 0),
			MaxStack:    maxStack(3, 0),
			MemorySize:  memoryCodeCopy,
			Valid:       true,
		},
		GASPRICE: {
			Execute:     opGasprice,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		EXTCODESIZE: {
			Execute:     opExtCodeSize,
			constantGas: params.ExtcodeSizeGasFrontier,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		EXTCODECOPY: {
			Execute:     opExtCodeCopy,
			constantGas: params.ExtcodeCopyBaseFrontier,
			dynamicGas:  gasExtCodeCopy,
			MinStack:    minStack(4, 0),
			MaxStack:    maxStack(4, 0),
			MemorySize:  memoryExtCodeCopy,
			Valid:       true,
		},
		BLOCKHASH: {
			Execute:     opBlockhash,
			constantGas: GasExtStep,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		COINBASE: {
			Execute:     opCoinbase,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		TIMESTAMP: {
			Execute:     opTimestamp,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		NUMBER: {
			Execute:     opNumber,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		DIFFICULTY: {
			Execute:     opDifficulty,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		GASLIMIT: {
			Execute:     opGasLimit,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		POP: {
			Execute:     opPop,
			constantGas: GasQuickStep,
			MinStack:    minStack(1, 0),
			MaxStack:    maxStack(1, 0),
			Valid:       true,
		},
		MLOAD: {
			Execute:     opMload,
			constantGas: GasFastestStep,
			dynamicGas:  gasMLoad,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			MemorySize:  memoryMLoad,
			Valid:       true,
		},
		MSTORE: {
			Execute:     opMstore,
			constantGas: GasFastestStep,
			dynamicGas:  gasMStore,
			MinStack:    minStack(2, 0),
			MaxStack:    maxStack(2, 0),
			MemorySize:  memoryMStore,
			Valid:       true,
		},
		MSTORE8: {
			Execute:     opMstore8,
			constantGas: GasFastestStep,
			dynamicGas:  gasMStore8,
			MemorySize:  memoryMStore8,
			MinStack:    minStack(2, 0),
			MaxStack:    maxStack(2, 0),

			Valid: true,
		},
		SLOAD: {
			Execute:     opSload,
			constantGas: params.SloadGasFrontier,
			MinStack:    minStack(1, 1),
			MaxStack:    maxStack(1, 1),
			Valid:       true,
		},
		SSTORE: {
			Execute:    opSstore,
			dynamicGas: gasSStore,
			MinStack:   minStack(2, 0),
			MaxStack:   maxStack(2, 0),
			Valid:      true,
			writes:     true,
		},
		JUMP: {
			Execute:     opJump,
			constantGas: GasMidStep,
			MinStack:    minStack(1, 0),
			MaxStack:    maxStack(1, 0),
			jumps:       true,
			Valid:       true,
		},
		JUMPI: {
			Execute:     opJumpi,
			constantGas: GasSlowStep,
			MinStack:    minStack(2, 0),
			MaxStack:    maxStack(2, 0),
			jumps:       true,
			Valid:       true,
		},
		PC: {
			Execute:     opPc,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		MSIZE: {
			Execute:     opMsize,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		GAS: {
			Execute:     opGas,
			constantGas: GasQuickStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		JUMPDEST: {
			Execute:     opJumpdest,
			constantGas: params.JumpdestGas,
			MinStack:    minStack(0, 0),
			MaxStack:    maxStack(0, 0),
			Valid:       true,
		},
		PUSH1: {
			Execute:     opPush1,
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH2: {
			Execute:     makePush(2, 2),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH3: {
			Execute:     makePush(3, 3),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH4: {
			Execute:     makePush(4, 4),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH5: {
			Execute:     makePush(5, 5),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH6: {
			Execute:     makePush(6, 6),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH7: {
			Execute:     makePush(7, 7),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH8: {
			Execute:     makePush(8, 8),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH9: {
			Execute:     makePush(9, 9),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH10: {
			Execute:     makePush(10, 10),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH11: {
			Execute:     makePush(11, 11),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH12: {
			Execute:     makePush(12, 12),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH13: {
			Execute:     makePush(13, 13),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH14: {
			Execute:     makePush(14, 14),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH15: {
			Execute:     makePush(15, 15),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH16: {
			Execute:     makePush(16, 16),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH17: {
			Execute:     makePush(17, 17),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH18: {
			Execute:     makePush(18, 18),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH19: {
			Execute:     makePush(19, 19),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH20: {
			Execute:     makePush(20, 20),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH21: {
			Execute:     makePush(21, 21),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH22: {
			Execute:     makePush(22, 22),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH23: {
			Execute:     makePush(23, 23),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH24: {
			Execute:     makePush(24, 24),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH25: {
			Execute:     makePush(25, 25),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH26: {
			Execute:     makePush(26, 26),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH27: {
			Execute:     makePush(27, 27),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH28: {
			Execute:     makePush(28, 28),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH29: {
			Execute:     makePush(29, 29),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH30: {
			Execute:     makePush(30, 30),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH31: {
			Execute:     makePush(31, 31),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		PUSH32: {
			Execute:     makePush(32, 32),
			constantGas: GasFastestStep,
			MinStack:    minStack(0, 1),
			MaxStack:    maxStack(0, 1),
			Valid:       true,
		},
		DUP1: {
			Execute:     makeDup(1),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(1),
			MaxStack:    maxDupStack(1),
			Valid:       true,
		},
		DUP2: {
			Execute:     makeDup(2),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(2),
			MaxStack:    maxDupStack(2),
			Valid:       true,
		},
		DUP3: {
			Execute:     makeDup(3),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(3),
			MaxStack:    maxDupStack(3),
			Valid:       true,
		},
		DUP4: {
			Execute:     makeDup(4),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(4),
			MaxStack:    maxDupStack(4),
			Valid:       true,
		},
		DUP5: {
			Execute:     makeDup(5),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(5),
			MaxStack:    maxDupStack(5),
			Valid:       true,
		},
		DUP6: {
			Execute:     makeDup(6),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(6),
			MaxStack:    maxDupStack(6),
			Valid:       true,
		},
		DUP7: {
			Execute:     makeDup(7),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(7),
			MaxStack:    maxDupStack(7),
			Valid:       true,
		},
		DUP8: {
			Execute:     makeDup(8),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(8),
			MaxStack:    maxDupStack(8),
			Valid:       true,
		},
		DUP9: {
			Execute:     makeDup(9),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(9),
			MaxStack:    maxDupStack(9),
			Valid:       true,
		},
		DUP10: {
			Execute:     makeDup(10),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(10),
			MaxStack:    maxDupStack(10),
			Valid:       true,
		},
		DUP11: {
			Execute:     makeDup(11),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(11),
			MaxStack:    maxDupStack(11),
			Valid:       true,
		},
		DUP12: {
			Execute:     makeDup(12),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(12),
			MaxStack:    maxDupStack(12),
			Valid:       true,
		},
		DUP13: {
			Execute:     makeDup(13),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(13),
			MaxStack:    maxDupStack(13),
			Valid:       true,
		},
		DUP14: {
			Execute:     makeDup(14),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(14),
			MaxStack:    maxDupStack(14),
			Valid:       true,
		},
		DUP15: {
			Execute:     makeDup(15),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(15),
			MaxStack:    maxDupStack(15),
			Valid:       true,
		},
		DUP16: {
			Execute:     makeDup(16),
			constantGas: GasFastestStep,
			MinStack:    minDupStack(16),
			MaxStack:    maxDupStack(16),
			Valid:       true,
		},
		SWAP1: {
			Execute:     makeSwap(1),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(2),
			MaxStack:    maxSwapStack(2),
			Valid:       true,
		},
		SWAP2: {
			Execute:     makeSwap(2),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(3),
			MaxStack:    maxSwapStack(3),
			Valid:       true,
		},
		SWAP3: {
			Execute:     makeSwap(3),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(4),
			MaxStack:    maxSwapStack(4),
			Valid:       true,
		},
		SWAP4: {
			Execute:     makeSwap(4),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(5),
			MaxStack:    maxSwapStack(5),
			Valid:       true,
		},
		SWAP5: {
			Execute:     makeSwap(5),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(6),
			MaxStack:    maxSwapStack(6),
			Valid:       true,
		},
		SWAP6: {
			Execute:     makeSwap(6),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(7),
			MaxStack:    maxSwapStack(7),
			Valid:       true,
		},
		SWAP7: {
			Execute:     makeSwap(7),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(8),
			MaxStack:    maxSwapStack(8),
			Valid:       true,
		},
		SWAP8: {
			Execute:     makeSwap(8),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(9),
			MaxStack:    maxSwapStack(9),
			Valid:       true,
		},
		SWAP9: {
			Execute:     makeSwap(9),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(10),
			MaxStack:    maxSwapStack(10),
			Valid:       true,
		},
		SWAP10: {
			Execute:     makeSwap(10),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(11),
			MaxStack:    maxSwapStack(11),
			Valid:       true,
		},
		SWAP11: {
			Execute:     makeSwap(11),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(12),
			MaxStack:    maxSwapStack(12),
			Valid:       true,
		},
		SWAP12: {
			Execute:     makeSwap(12),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(13),
			MaxStack:    maxSwapStack(13),
			Valid:       true,
		},
		SWAP13: {
			Execute:     makeSwap(13),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(14),
			MaxStack:    maxSwapStack(14),
			Valid:       true,
		},
		SWAP14: {
			Execute:     makeSwap(14),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(15),
			MaxStack:    maxSwapStack(15),
			Valid:       true,
		},
		SWAP15: {
			Execute:     makeSwap(15),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(16),
			MaxStack:    maxSwapStack(16),
			Valid:       true,
		},
		SWAP16: {
			Execute:     makeSwap(16),
			constantGas: GasFastestStep,
			MinStack:    minSwapStack(17),
			MaxStack:    maxSwapStack(17),
			Valid:       true,
		},
		LOG0: {
			Execute:    makeLog(0),
			dynamicGas: makeGasLog(0),
			MinStack:   minStack(2, 0),
			MaxStack:   maxStack(2, 0),
			MemorySize: memoryLog,
			Valid:      true,
			writes:     true,
		},
		LOG1: {
			Execute:    makeLog(1),
			dynamicGas: makeGasLog(1),
			MinStack:   minStack(3, 0),
			MaxStack:   maxStack(3, 0),
			MemorySize: memoryLog,
			Valid:      true,
			writes:     true,
		},
		LOG2: {
			Execute:    makeLog(2),
			dynamicGas: makeGasLog(2),
			MinStack:   minStack(4, 0),
			MaxStack:   maxStack(4, 0),
			MemorySize: memoryLog,
			Valid:      true,
			writes:     true,
		},
		LOG3: {
			Execute:    makeLog(3),
			dynamicGas: makeGasLog(3),
			MinStack:   minStack(5, 0),
			MaxStack:   maxStack(5, 0),
			MemorySize: memoryLog,
			Valid:      true,
			writes:     true,
		},
		LOG4: {
			Execute:    makeLog(4),
			dynamicGas: makeGasLog(4),
			MinStack:   minStack(6, 0),
			MaxStack:   maxStack(6, 0),
			MemorySize: memoryLog,
			Valid:      true,
			writes:     true,
		},
		CREATE: {
			Execute:     opCreate,
			constantGas: params.CreateGas,
			dynamicGas:  gasCreate,
			MinStack:    minStack(3, 1),
			MaxStack:    maxStack(3, 1),
			MemorySize:  memoryCreate,
			Valid:       true,
			writes:      true,
			returns:     true,
		},
		CALL: {
			Execute:     opCall,
			constantGas: params.CallGasFrontier,
			dynamicGas:  gasCall,
			MinStack:    minStack(7, 1),
			MaxStack:    maxStack(7, 1),
			MemorySize:  memoryCall,
			Valid:       true,
			returns:     true,
		},
		CALLCODE: {
			Execute:     opCallCode,
			constantGas: params.CallGasFrontier,
			dynamicGas:  gasCallCode,
			MinStack:    minStack(7, 1),
			MaxStack:    maxStack(7, 1),
			MemorySize:  memoryCall,
			Valid:       true,
			returns:     true,
		},
		RETURN: {
			Execute:    opReturn,
			dynamicGas: gasReturn,
			MinStack:   minStack(2, 0),
			MaxStack:   maxStack(2, 0),
			MemorySize: memoryReturn,
			halts:      true,
			Valid:      true,
		},
		SELFDESTRUCT: {
			Execute:    opSuicide,
			dynamicGas: gasSelfdestruct,
			MinStack:   minStack(1, 0),
			MaxStack:   maxStack(1, 0),
			halts:      true,
			Valid:      true,
			writes:     true,
		},
	}
}
