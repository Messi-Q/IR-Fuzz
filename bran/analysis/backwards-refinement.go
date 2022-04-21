// Copyright 2018 MPI-SWS and Valentin Wuestholz

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

	"github.com/ethereum/go-ethereum/common"

	"github.com/practical-formal-methods/bran/vm"
)

type opcodeArg struct {
	dupIdx  int
	pushArg *big.Int
}

// matchesBackwards determines if the given contract matches the sequence of opcodes backwards from the given PC.
// contract	pc <-, pattent(opcodes) ->
// It returns a boolean indicated whether the match succeeded.
// If it did, the returned array contains additional information (e.g., arguments) for every opcode in the pattern.
// If it did, it returns the final PC.
func matchesBackwards(contract *vm.Contract, ppcMap *prevPCMap, pc pcType, pattern []vm.OpCode) (bool, []opcodeArg, pcType) {
	args := make([]opcodeArg, len(pattern))
	idx := 0
	patLen := len(pattern)
	for idx < patLen {
		actualOp := contract.GetOp(uint64(pc))
		incr := 0
		if actualOp != vm.JUMPDEST {
			// We skip jump destinations since they are no-ops.

			expOp := pattern[idx]
			switch expOp {
			case vm.DUP:
				isDup := actualOp >= vm.DUP1 && actualOp <= vm.DUP16
				if !isDup {
					return false, nil, 0
				}
				index := int(actualOp - vm.DUP1)
				args[idx].dupIdx = index
			case vm.PUSH:
				isPush := actualOp >= vm.PUSH1 && actualOp <= vm.PUSH32
				if !isPush {
					return false, nil, 0
				}
				sz := int(actualOp - vm.PUSH1 + 1)
				codeLen := len(contract.Code)
				startMin := codeLen
				if int(pc+1) < startMin {
					startMin = int(pc + 1)
				}
				endMin := codeLen
				if startMin+sz < endMin {
					endMin = startMin + sz
				}
				b := big.NewInt(0).SetBytes(common.RightPadBytes(contract.Code[startMin:endMin], sz))
				args[idx].pushArg = b
			default:
				if actualOp != expOp {
					return false, nil, 0
				}
			}
			incr = 1
		}

		var exists bool
		pc, exists = ppcMap.getPrevPC(pc)
		if !exists {
			return false, nil, 0
		}
		idx += incr
	}
	return true, args, pc
}

// backwardsRefineStack refines the stack by backwards execution.
func backwardsRefineStack(origStack *vm.Stack, contract *vm.Contract, ppcMap *prevPCMap, pc pcType, maxBackPropSteps int) *vm.Stack {
	suffixMatches := func(pc pcType, pattern []vm.OpCode) (bool, []opcodeArg, pcType) {
		return matchesBackwards(contract, ppcMap, pc, pattern)
	}

	refinedStack := origStack.Clone()
	currStack := refinedStack.Clone()
	refinedStackLen := refinedStack.Len()
	indexInRefinedStack := func(currIdx int) int {
		currStackLen := currStack.Len()
		// We assume that the pattern matching below preserves the invariant currStackLen <= refinedStackLen.
		return refinedStackLen - currStackLen + currIdx
	}

	topEq := func(stack *vm.Stack, v int64) bool {
		return stack.Peek().Cmp(big.NewInt(v)) == 0
	}

	for i := 0; i < maxBackPropSteps; i++ {
		var match bool
		var args []opcodeArg
		var ppc pcType
		if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.PUSH}); match {
			currStack.Pop()
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.JUMPDEST}); match {
			// This is a no-op.
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.ISZERO}); match && topEq(currStack, 0) {
			// If we start with 0 on the stack and call ISZERO twice we end up with 0 again.
			// {[0]} ISZERO; ISZERO; {[0]}
		} else if match, args, _ = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.EQ}); match && topEq(currStack, 0) {
			// EQ; {[1]} ISZERO; {[0])
			currStack.Pop()
			currStack.Push(big.NewInt(1))
			// We just compute the stack before executing ISZERO.
			ppc, _ = ppcMap.getPrevPC(pc)
		} else if match, args, _ = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.LT}); match && topEq(currStack, 0) {
			// LT; {[1]} ISZERO; {[0])
			currStack.Pop()
			currStack.Push(big.NewInt(1))
			// We just compute the stack before executing ISZERO.
			ppc, _ = ppcMap.getPrevPC(pc)
		} else if match, args, _ = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.GT}); match && topEq(currStack, 0) {
			// GT; {[1]} ISZERO; {[0])
			currStack.Pop()
			currStack.Push(big.NewInt(1))
			// We just compute the stack before executing ISZERO.
			ppc, _ = ppcMap.getPrevPC(pc)
		} else if match, args, _ = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.SLT}); match && topEq(currStack, 0) {
			// SLT; {[1]} ISZERO; {[0])
			currStack.Pop()
			currStack.Push(big.NewInt(1))
			// We just compute the stack before executing ISZERO.
			ppc, _ = ppcMap.getPrevPC(pc)
		} else if match, args, _ = suffixMatches(pc, []vm.OpCode{vm.ISZERO, vm.SGT}); match && topEq(currStack, 0) {
			// SGT; {[1]} ISZERO; {[0])
			currStack.Pop()
			currStack.Push(big.NewInt(1))
			// We just compute the stack before executing ISZERO.
			ppc, _ = ppcMap.getPrevPC(pc)
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.ISZERO}); match && topEq(currStack, 1) {
			// {[0]} ISZERO; {[1]}
			currStack.Pop()
			currStack.Push(big.NewInt(0))
		} else if match, args, ppc = matchesBackwards(contract, ppcMap, pc, []vm.OpCode{vm.DUP}); match {
			val := currStack.Pop()
			idx := args[0].dupIdx
			dupVal := currStack.Back(idx)
			meet := meetVals(dupVal, val)
			if meet != nil {
				dupVal.Set(meet)
				refinedStack.Back(indexInRefinedStack(idx)).Set(meet)
			}
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.EQ, vm.DUP, vm.DUP}); match && args[1].dupIdx >= 1 && topEq(currStack, 1) {
			currStack.Pop()
			idx1 := args[1].dupIdx - 1
			val1 := currStack.Back(idx1)
			idx2 := args[2].dupIdx
			val2 := currStack.Back(idx2)
			meet := meetVals(val1, val2)
			if meet != nil {
				val1.Set(meet)
				val2.Set(meet)
				refinedStack.Back(indexInRefinedStack(idx1)).Set(meet)
				refinedStack.Back(indexInRefinedStack(idx2)).Set(meet)
			}
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.EQ, vm.DUP, vm.PUSH}); match && args[1].dupIdx >= 1 && topEq(currStack, 1) {
			currStack.Pop()
			idx1 := args[1].dupIdx - 1
			val1 := currStack.Back(idx1)
			val2 := args[2].pushArg
			meet := meetVals(val1, val2)
			if meet != nil {
				val1.Set(meet)
				refinedStack.Back(indexInRefinedStack(idx1)).Set(meet)
			}
		} else if match, args, ppc = suffixMatches(pc, []vm.OpCode{vm.EQ, vm.PUSH, vm.DUP}); match && topEq(currStack, 1) {
			currStack.Pop()
			val1 := args[1].pushArg
			idx2 := args[2].dupIdx
			val2 := currStack.Back(idx2)
			meet := meetVals(val1, val2)
			if meet != nil {
				val2.Set(meet)
				refinedStack.Back(indexInRefinedStack(idx2)).Set(meet)
			}
		} else {
			break
		}
		pc = ppc
	}
	return refinedStack
}
