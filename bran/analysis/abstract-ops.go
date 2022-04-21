// Copyright 2018 MPI-SWS, Valentin Wuestholz, and ConsenSys AG

// This file is part of Bran.
//
// Bran is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bran is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bran.  If not, see <https://www.gnu.org/licenses/>.

package analysis

import (
	"math/big"

	"github.com/practical-formal-methods/bran/vm"
)

// pcAndSt is a pair of program counter and state.
type pcAndSt struct {
	pc pcType
	st absState
}

// stepRes represents the result of executing an abstract transformer.
type stepRes struct {
	mayFail      bool
	failureCause string
	postStates   []pcAndSt // list of post states
}

// emptyRes returns a result with no post-states.
func emptyRes() stepRes {
	return stepRes{}
}

// initRes returns the initial program state (i.e., PC is 0 and stack and memory are empty).
func initRes() stepRes {
	return stepRes{
		postStates: []pcAndSt{
			{
				pc: 0,
				st: absState{
					stack: emptyStack(),
					mem: absMem{
						mem: vm.NewMemory(),
					},
				},
			},
		},
	}
}

// falRes returns a result that indicates a possible failure.
func failRes(cause string) stepRes {
	return stepRes{
		mayFail:      true,
		failureCause: cause,
	}
}

// nextPcRes produces a result from the current execution environment for non-jump instructions (i.e., PC incremented).
func nextPcRes(env execEnv) stepRes {
	return stepRes{
		postStates: []pcAndSt{
			{
				pc: *env.pc + 1,
				st: env.st,
			},
		},
	}
}

// absJumpTable represents a jump table for abstract operations.
type absJumpTable [256]absOp

// execFn is the type of functions executing abstract operations.
// It should not modify any part of the environment (except possibly for the integer pool in the EVM object).
type execFn func(env execEnv) (stepRes, error)

// absOp represents an abstract operation.
type absOp struct {
	// valid is true if the operation has been initialized.
	valid bool
	// memSize calculates how much memory the operation needs.
	// If unset, the operation should not access memory.
	memSize memSizeFn
	// exec executes an abstract operation.
	// exec can safely assume that by the time it executes, the following will hold:
	//   1) the state and stack will not be top
	//   2) the stack will have been validated (but top values in it are still possible)
	//   3) the memory will have been resized, but it can also be top
	exec execFn
}

// fromExec creates a valid abstract operation.
func fromExec(exec execFn) absOp {
	return absOp{
		valid: true,
		exec:  exec,
	}
}

// noOpOp is the no-op abstract operation.
var noOpOp = fromExec(func(env execEnv) (stepRes, error) {
	return nextPcRes(env), nil
})

// mayFailOp is the operation that always fails.
var mayFailOp = fromExec(func(env execEnv) (stepRes, error) {
	return failRes(UnsupportedOpcodeFail), nil
})

// emptyResOp is the operation that returns an empty state (used for stopping execution).
var emptyResOp = fromExec(func(env execEnv) (stepRes, error) {
	return emptyRes(), nil
})

// execEnv is the (abstract) execution environment.
type execEnv struct {
	pc          *pcType
	interpreter *vm.EVMInterpreter
	contract    *vm.Contract
	ppcMap      *prevPCMap
	st          absState
	conc        vm.Operation
}

// memSizeFn calculates the new size of the memory.
type memSizeFn func(stack absStack, conc vm.MemorySizeFunc) (uint64, bool, bool, error)

// withSt returns an environment identical to the current one, except for the new state.
func (e execEnv) withSt(newSt absState) execEnv {
	return execEnv{
		pc:          e.pc,
		interpreter: e.interpreter,
		contract:    e.contract,
		ppcMap:      e.ppcMap,
		st:          newSt,
		conc:        e.conc,
	}
}

// withStackCopy returns an execution environment with a clone of the current stack.
func (e execEnv) withStackCopy() execEnv {
	return e.withSt(e.st.withStackCopy())
}

// withMemCopy returns an execution environment with a clone of the current memory.
func (e execEnv) withMemCopy() execEnv {
	return e.withSt(e.st.withMemCopy())
}

// withPcCopy returns an execution environment with a clone of the current PC.
func (e execEnv) withPcCopy() execEnv {
	cpc := *e.pc
	return execEnv{
		pc:          &cpc,
		interpreter: e.interpreter,
		contract:    e.contract,
		ppcMap:      e.ppcMap,
		st:          e.st,
		conc:        e.conc,
	}
}

func (e execEnv) unpack() (*vm.Stack, absMem) {
	return e.st.stack.stack, e.st.mem
}

// execConc executes the concrete operation in the environment.
func execConc(env execEnv) error {
	interpreter := env.interpreter
	if interpreter.IntPool == nil {
		interpreter.IntPool = vm.PoolOfIntPools.Get()
		defer func() {
			vm.PoolOfIntPools.Put(interpreter.IntPool)
			interpreter.IntPool = nil
		}()
	}
	_, err := env.conc.Execute((*uint64)(env.pc), interpreter, env.contract, env.st.mem.mem, env.st.stack.stack)
	return err
}

// makeMemFn returns a function that computes the abstract memory size.
func makeMemFn(indices ...int) memSizeFn {
	return func(stack absStack, conc vm.MemorySizeFunc) (uint64, bool, bool, error) {
		hasTop, err := stack.hasTop(indices...)
		if err != nil {
			return 0, false, false, err
		}
		if hasTop {
			return 0, false, true, nil
		}
		sz, overflow := conc(stack.stack)
		return sz, overflow, false, nil
	}
}

// newAbsJumpTable creates an abstract jump table.
func newAbsJumpTable(forPrefix bool) absJumpTable {
	opCreate := mayFailOp
	opCall := mayFailOp
	opCallCode := mayFailOp
	opDelegateCall := mayFailOp
	opStaticCall := mayFailOp
	opCreate2 := mayFailOp
	if forPrefix {
		opCreate = absOp{
			valid:   true,
			memSize: makeMemFn(1, 2),
			exec:    makePopPushTopFn(3, 1),
		}
		opCall = absOp{
			valid:   true,
			memSize: makeMemFn(3, 4, 5, 6),
			exec:    makePopPushMemTopFn(7, 1, 5, 6),
		}
		opCallCode = absOp{
			valid:   true,
			memSize: makeMemFn(3, 4, 5, 6),
			exec:    makePopPushMemTopFn(7, 1, 5, 6),
		}
		opDelegateCall = absOp{
			valid:   true,
			memSize: makeMemFn(2, 3, 4, 5),
			exec:    makePopPushMemTopFn(6, 1, 4, 5),
		}
		opStaticCall = absOp{
			valid:   true,
			memSize: makeMemFn(2, 3, 4, 5),
			exec:    makePopPushMemTopFn(6, 1, 4, 5),
		}
		opCreate2 = absOp{
			valid:   true,
			memSize: makeMemFn(1, 2),
			exec:    makePopPushTopFn(4, 1),
		}
	}
	return absJumpTable{
		vm.STOP: emptyResOp,

		vm.ADD:        makeStackOp(2, 1),
		vm.MUL:        makeStackOp(2, 1),
		vm.SUB:        makeStackOp(2, 1),
		vm.DIV:        makeStackOp(2, 1),
		vm.SDIV:       makeStackOp(2, 1),
		vm.MOD:        makeStackOp(2, 1),
		vm.SMOD:       makeStackOp(2, 1),
		vm.ADDMOD:     makeStackOp(3, 1),
		vm.MULMOD:     makeStackOp(3, 1),
		vm.EXP:        makeStackOp(2, 1),
		vm.SIGNEXTEND: makeStackOp(2, 1),

		vm.LT:     makeStackOp(2, 1),
		vm.GT:     makeStackOp(2, 1),
		vm.SLT:    makeStackOp(2, 1),
		vm.SGT:    makeStackOp(2, 1),
		vm.EQ:     makeStackOp(2, 1),
		vm.ISZERO: makeStackOp(1, 1),
		vm.AND:    makeStackOp(2, 1),
		vm.XOR:    makeStackOp(2, 1),
		vm.OR:     makeStackOp(2, 1),
		vm.NOT:    makeStackOp(1, 1),
		vm.BYTE:   makeStackOp(2, 1),
		vm.SHA3: absOp{
			valid:   true,
			memSize: makeMemFn(0, 1),
			exec:    opSha3,
		},

		vm.SHL: makeStackOp(2, 1),
		vm.SHR: makeStackOp(2, 1),
		vm.SAR: makeStackOp(2, 1),

		vm.ADDRESS:      makePopPushTopOp(0, 1),
		vm.BALANCE:      makePopPushTopOp(1, 1),
		vm.ORIGIN:       makePopPushTopOp(0, 1),
		vm.CALLER:       makePopPushTopOp(0, 1),
		vm.CALLVALUE:    makePopPushTopOp(0, 1),
		vm.CALLDATALOAD: makePopPushTopOp(1, 1),
		vm.CALLDATASIZE: makePopPushTopOp(0, 1),
		vm.CALLDATACOPY: absOp{
			valid:   true,
			memSize: makeMemFn(0, 2),
			exec:    opCallDataCopy,
		},
		vm.CODESIZE: fromExec(delegateConcStackOp),
		vm.CODECOPY: absOp{
			valid:   true,
			memSize: makeMemFn(0, 2),
			exec:    opCodeCopy,
		},
		vm.GASPRICE:    makePopPushTopOp(0, 1),
		vm.EXTCODESIZE: makePopPushTopOp(1, 1),
		vm.EXTCODECOPY: absOp{
			valid:   true,
			memSize: makeMemFn(1, 3),
			exec:    opExtCodeCopy,
		},

		vm.RETURNDATASIZE: makePopPushTopOp(0, 1),
		vm.RETURNDATACOPY: absOp{
			valid:   true,
			memSize: makeMemFn(0, 2),
			exec:    opReturnDataCopy,
		},
		vm.EXTCODEHASH: makePopPushTopOp(1, 1),

		vm.BLOCKHASH:   makePopPushTopOp(1, 1),
		vm.COINBASE:    makePopPushTopOp(0, 1),
		vm.TIMESTAMP:   makePopPushTopOp(0, 1),
		vm.NUMBER:      makePopPushTopOp(0, 1),
		vm.DIFFICULTY:  makePopPushTopOp(0, 1),
		vm.GASLIMIT:    makePopPushTopOp(0, 1),
		vm.CHAINID:     makePopPushTopOp(0, 1),
		vm.SELFBALANCE: makePopPushTopOp(0, 1),

		vm.POP: makeStackOp(1, 0),

		vm.MLOAD: absOp{
			valid:   true,
			memSize: makeMemFn(0),
			exec:    opMload,
		},
		vm.MSTORE: absOp{
			valid:   true,
			memSize: makeMemFn(0),
			exec:    opMstore,
		},
		vm.MSTORE8: absOp{
			valid:   true,
			memSize: makeMemFn(0),
			exec:    opMstore8,
		},

		vm.SLOAD:  makePopPushTopOp(1, 1),
		vm.SSTORE: makePopPushTopOp(2, 0),

		vm.JUMP:  fromExec(opJump),
		vm.JUMPI: fromExec(opJumpi),

		vm.PC:       fromExec(delegateConcStackOp),
		vm.MSIZE:    fromExec(opMsize),
		vm.GAS:      makePopPushTopOp(0, 1),
		vm.JUMPDEST: noOpOp,

		vm.PUSH1:  fromExec(delegateConcStackOp),
		vm.PUSH2:  fromExec(delegateConcStackOp),
		vm.PUSH3:  fromExec(delegateConcStackOp),
		vm.PUSH4:  fromExec(delegateConcStackOp),
		vm.PUSH5:  fromExec(delegateConcStackOp),
		vm.PUSH6:  fromExec(delegateConcStackOp),
		vm.PUSH7:  fromExec(delegateConcStackOp),
		vm.PUSH8:  fromExec(delegateConcStackOp),
		vm.PUSH9:  fromExec(delegateConcStackOp),
		vm.PUSH10: fromExec(delegateConcStackOp),
		vm.PUSH11: fromExec(delegateConcStackOp),
		vm.PUSH12: fromExec(delegateConcStackOp),
		vm.PUSH13: fromExec(delegateConcStackOp),
		vm.PUSH14: fromExec(delegateConcStackOp),
		vm.PUSH15: fromExec(delegateConcStackOp),
		vm.PUSH16: fromExec(delegateConcStackOp),
		vm.PUSH17: fromExec(delegateConcStackOp),
		vm.PUSH18: fromExec(delegateConcStackOp),
		vm.PUSH19: fromExec(delegateConcStackOp),
		vm.PUSH20: fromExec(delegateConcStackOp),
		vm.PUSH21: fromExec(delegateConcStackOp),
		vm.PUSH22: fromExec(delegateConcStackOp),
		vm.PUSH23: fromExec(delegateConcStackOp),
		vm.PUSH24: fromExec(delegateConcStackOp),
		vm.PUSH25: fromExec(delegateConcStackOp),
		vm.PUSH26: fromExec(delegateConcStackOp),
		vm.PUSH27: fromExec(delegateConcStackOp),
		vm.PUSH28: fromExec(delegateConcStackOp),
		vm.PUSH29: fromExec(delegateConcStackOp),
		vm.PUSH30: fromExec(delegateConcStackOp),
		vm.PUSH31: fromExec(delegateConcStackOp),
		vm.PUSH32: fromExec(delegateConcStackOp),

		vm.DUP1:  fromExec(delegateConcStackOp),
		vm.DUP2:  fromExec(delegateConcStackOp),
		vm.DUP3:  fromExec(delegateConcStackOp),
		vm.DUP4:  fromExec(delegateConcStackOp),
		vm.DUP5:  fromExec(delegateConcStackOp),
		vm.DUP6:  fromExec(delegateConcStackOp),
		vm.DUP7:  fromExec(delegateConcStackOp),
		vm.DUP8:  fromExec(delegateConcStackOp),
		vm.DUP9:  fromExec(delegateConcStackOp),
		vm.DUP10: fromExec(delegateConcStackOp),
		vm.DUP11: fromExec(delegateConcStackOp),
		vm.DUP12: fromExec(delegateConcStackOp),
		vm.DUP13: fromExec(delegateConcStackOp),
		vm.DUP14: fromExec(delegateConcStackOp),
		vm.DUP15: fromExec(delegateConcStackOp),
		vm.DUP16: fromExec(delegateConcStackOp),

		vm.SWAP1:  fromExec(delegateConcStackOp),
		vm.SWAP2:  fromExec(delegateConcStackOp),
		vm.SWAP3:  fromExec(delegateConcStackOp),
		vm.SWAP4:  fromExec(delegateConcStackOp),
		vm.SWAP5:  fromExec(delegateConcStackOp),
		vm.SWAP6:  fromExec(delegateConcStackOp),
		vm.SWAP7:  fromExec(delegateConcStackOp),
		vm.SWAP8:  fromExec(delegateConcStackOp),
		vm.SWAP9:  fromExec(delegateConcStackOp),
		vm.SWAP10: fromExec(delegateConcStackOp),
		vm.SWAP11: fromExec(delegateConcStackOp),
		vm.SWAP12: fromExec(delegateConcStackOp),
		vm.SWAP13: fromExec(delegateConcStackOp),
		vm.SWAP14: fromExec(delegateConcStackOp),
		vm.SWAP15: fromExec(delegateConcStackOp),
		vm.SWAP16: fromExec(delegateConcStackOp),

		vm.LOG0: makeOpLog(0),
		vm.LOG1: makeOpLog(1),
		vm.LOG2: makeOpLog(2),
		vm.LOG3: makeOpLog(3),
		vm.LOG4: makeOpLog(4),

		vm.CREATE: opCreate,
		// TODO(wuestholz): Maybe improve analysis precision for precompiled contracts.
		vm.CALL:         opCall,
		vm.CALLCODE:     opCallCode,
		vm.RETURN:       emptyResOp,
		vm.DELEGATECALL: opDelegateCall,
		vm.CREATE2:      opCreate2,
		vm.STATICCALL:   opStaticCall,
		vm.REVERT:       emptyResOp,
		vm.SELFDESTRUCT: emptyResOp,
	}
}

// delegateConcStackOp is an abstract operation that just delegates to the underlying concrete operation.
// It assumes that the concrete operation does not modify the memory.
func delegateConcStackOp(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withPcCopy()
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}

// makeStackOp returns an abstract operation that mutates the (abstract) stack by popping values and pushing values.
func makeStackOp(pop, push uint) absOp {
	return fromExec(func(env execEnv) (stepRes, error) {
		env2 := env.withStackCopy().withPcCopy()
		stack2, _ := env2.unpack()
		anyTops := false
		for i := 0; uint(i) < pop; i++ {
			if isTop(stack2.Back(i)) {
				anyTops = true
				break
			}
		}
		if anyTops {
			// We pop values from the stack and conservatively push top values.
			for i := 0; uint(i) < pop; i++ {
				stack2.Pop()
			}
			for i := 0; uint(i) < push; i++ {
				stack2.Push(topVal())
			}
			return nextPcRes(env2), nil
		}
		// Just execute the operation concretely (modifying the environment).
		if err := execConc(env2); err != nil {
			return emptyRes(), nil
		}
		return nextPcRes(env2), nil
	})
}

// makePopPushToapOp returns an operation that first pops stack elements and then pushes top values.
func makePopPushTopOp(pop, push int) absOp {
	return fromExec(makePopPushTopFn(pop, push))
}

func makePopPushTopFn(pop, push int) execFn {
	return func(env execEnv) (stepRes, error) {
		env2 := env.withStackCopy().withPcCopy()
		stack2, _ := env2.unpack()
		for i := 0; i < pop; i++ {
			stack2.Pop()
		}
		for i := 0; i < push; i++ {
			stack2.Push(topVal())
		}
		return nextPcRes(env2), nil
	}
}

func makePopPushMemTopFn(pop, push, memOffsetIdx, memSizeArgIdx int) execFn {
	return func(env execEnv) (stepRes, error) {
		env2 := env.withStackCopy().withMemCopy().withPcCopy()
		stack2, _ := env2.unpack()
		memOffset := stack2.Back(memOffsetIdx)
		memSize := stack2.Back(memSizeArgIdx)
		for i := 0; i < pop; i++ {
			stack2.Pop()
		}
		for i := 0; i < push; i++ {
			stack2.Push(topVal())
		}
		if isTop(memOffset) || isTop(memSize) {
			env2.st.mem = topMem()
		} else {
			env2.st.mem.set(memOffset.Uint64(), memSize.Uint64(), topBytes())
		}
		return nextPcRes(env2), nil
	}
}

func makeOpLog(size int) absOp {
	return absOp{
		valid:   true,
		exec:    makePopPushTopFn(2+size, 0),
		memSize: makeMemFn(0, 1),
	}
}

func opSha3(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	offset, size := stack2.Back(0), stack2.Back(1)
	if isTop(offset) || isTop(size) || mem2.get(offset.Int64(), size.Int64()).isTop {
		stack2.Pop()
		stack2.Pop()
		stack2.Push(topVal())
		return nextPcRes(env2), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}

func opMload(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	offset := stack2.Pop()
	if isTop(offset) {
		stack2.Push(topVal())
	} else {
		loadedBytes := mem2.get(offset.Int64(), 32)
		stack2.Push(loadedBytes.toBigInt())
	}
	return nextPcRes(env2), nil
}

func opMstore(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	off, val := stack2.Back(0), stack2.Back(1)
	if mem2.isTop {
		stack2.Pop()
		stack2.Pop()
		return nextPcRes(env2), nil
	}
	if isTop(off) {
		stack2.Pop()
		stack2.Pop()
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	if isTop(val) {
		stack2.Pop()
		stack2.Pop()
		mem2.set(off.Uint64(), 32, topBytes())
		return nextPcRes(env2), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}

func opMstore8(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	off, val := stack2.Back(0), stack2.Back(1)
	if mem2.isTop {
		stack2.Pop()
		stack2.Pop()
		return nextPcRes(env2), nil
	}
	if isTop(off) {
		stack2.Pop()
		stack2.Pop()
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	if isTop(val) {
		stack2.Pop()
		stack2.Pop()
		mem2.set(off.Uint64(), 1, topBytes())
		return nextPcRes(env2), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}

func opJump(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withPcCopy()
	stack2, _ := env2.unpack()
	dest := stack2.Peek()
	if isTop(dest) {
		return failRes(JumpToTopFail), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return stepRes{
		postStates: []pcAndSt{
			{
				pc: *env2.pc, // The PC was already updated by the concrete execution.
				st: env2.st,
			},
		},
	}, nil
}

func opJumpi(env execEnv) (stepRes, error) {
	stack, _ := env.unpack()
	cond := stack.Back(1)
	var alts []absState
	if isTop(cond) {
		ppc, exists := env.ppcMap.getPrevPC(*env.pc)
		if !exists {
			return failRes(InternalFail), nil
		}

		thenSt := env.st.withStackCopy()
		// We check if the condition is boolean based on what opcodes where executed earlier.
		isBooleanCond, _, _ := matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.ISZERO})
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.EQ})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.LT})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.GT})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.SLT})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.SGT})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.CALL})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.STATICCALL})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.DELEGATECALL})
		}
		if !isBooleanCond {
			isBooleanCond, _, _ = matchesBackwards(env.contract, env.ppcMap, ppc, []vm.OpCode{vm.PUSH, vm.CALLCODE})
		}
		if isBooleanCond {
			thenStack := thenSt.stack.stack
			thenCond := thenStack.Back(1)
			thenCond.Set(big.NewInt(1))
			refinedStack := backwardsRefineStack(thenStack, env.contract, env.ppcMap, ppc, MagicInt(16))
			thenSt.stack.stack = refinedStack
		}

		elseSt := env.st.withStackCopy()
		elseStack := elseSt.stack.stack
		elseCond := elseStack.Back(1)
		elseCond.Set(big.NewInt(0))

		refinedStack := backwardsRefineStack(elseStack, env.contract, env.ppcMap, ppc, MagicInt(16))
		elseSt.stack.stack = refinedStack

		alts = []absState{thenSt, elseSt}
	} else {
		alts = []absState{env.st.withStackCopy()}
	}

	var newStates []pcAndSt
	for _, st := range alts {
		altEnv := env.withSt(st).withPcCopy()
		altDest, _ := altEnv.unpack()
		if isTop(altDest.Peek()) {
			return failRes(JumpToTopFail), nil
		}
		if err := execConc(altEnv); err == nil {
			// We ignore states that would lead to an error (e.g., invalid jump destination).
			postJmpSt := pcAndSt{
				pc: *altEnv.pc, // The PC was already updated by the concrete execution.
				st: altEnv.st,
			}
			newStates = append(newStates, postJmpSt)
		}
	}
	return stepRes{postStates: newStates}, nil
}

func opMsize(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	if mem2.isTop {
		stack2.Push(topVal())
		return nextPcRes(env2), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}

func opCallDataCopy(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	memOffset, _, size := stack2.Pop(), stack2.Pop(), stack2.Pop()
	if mem2.isTop {
		return nextPcRes(env2), nil
	}
	if isTop(memOffset) || isTop(size) {
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	// Since we don't track the input to the contract, we have to set
	// all bytes to top.
	mem2.set(memOffset.Uint64(), size.Uint64(), topBytes())
	return nextPcRes(env2), nil
}

func opExtCodeCopy(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	_, memOffset, _, size := stack2.Pop(), stack2.Pop(), stack2.Pop(), stack2.Pop()
	if mem2.isTop {
		return nextPcRes(env2), nil
	}
	if isTop(memOffset) || isTop(size) {
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	mem2.set(memOffset.Uint64(), size.Uint64(), topBytes())
	return nextPcRes(env2), nil
}

func opCodeCopy(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	memOffset, _, size := stack2.Pop(), stack2.Pop(), stack2.Pop()
	if mem2.isTop {
		return nextPcRes(env2), nil
	}
	if isTop(memOffset) || isTop(size) {
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	// We currently just store top values even though we could copy the contract's code.
	mem2.set(memOffset.Uint64(), size.Uint64(), topBytes())
	return nextPcRes(env2), nil
}

func opReturnDataCopy(env execEnv) (stepRes, error) {
	env2 := env.withStackCopy().withMemCopy().withPcCopy()
	stack2, mem2 := env2.unpack()
	memOffset, dataOffset, size := stack2.Pop(), stack2.Pop(), stack2.Pop()
	if isTop(dataOffset) {
		return failRes(TopOffsetFail), nil
	}
	if mem2.isTop {
		return nextPcRes(env2), nil
	}
	if isTop(memOffset) || isTop(size) {
		env2.st.mem = topMem()
		return nextPcRes(env2), nil
	}
	if err := execConc(env2); err != nil {
		return emptyRes(), nil
	}
	return nextPcRes(env2), nil
}
