// MPI-SWS, Valentin Wuestholz, and ConsenSys AG

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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"

	"github.com/practical-formal-methods/bran/vm"
)

type pcType uint64

type execPrefix map[int]pcType

type concJumpTable [256]vm.Operation // jump_table

type result struct {
	mayFail      bool
	failureCause string
	avoidRetry   bool
}

func noFail() result {
	return result{}
}

func mayFail(cause string) result {
	return result{
		mayFail:      true,
		failureCause: cause,
	}
}

func prefixMayFail(cause string) result {
	return result{
		mayFail:      true,
		failureCause: cause,
		avoidRetry:   true,
	}
}

type prevPCMap struct { // m,
	prevPC        map[pcType]pcType
	multiplePreds map[pcType]bool // default: false
}

func newPrevPCMap() *prevPCMap {
	return &prevPCMap{
		prevPC:        map[pcType]pcType{},
		multiplePreds: map[pcType]bool{},
	}
}

func (m *prevPCMap) addPrevPC(currPc, prevPc pcType) {
	if !m.multiplePreds[currPc] {
		ppc, exists := m.prevPC[currPc]
		if !exists {
			m.prevPC[currPc] = prevPc // no currPc, currPc = prevPc
		} else if ppc != prevPc {
			delete(m.prevPC, currPc) // else ,currPc has a prevPc
			m.multiplePreds[currPc] = true
		}
	}
}

func (m *prevPCMap) getPrevPC(pc pcType) (pcType, bool) {
	ppc, exists := m.prevPC[pc]
	return ppc, exists
}

type constPropAnalyzer struct {
	contract           *vm.Contract
	codeHash           common.Hash
	interpreter        *vm.EVMInterpreter // interpreter
	analyzer           *LookaheadAnalyzer
	maxDisjuncts       int
	failOnTopMemResize bool
	useBoundedJoins    bool
	verbose            bool
}

func newConstPropAnalyzer(contract *vm.Contract, codeHash common.Hash, interpreter *vm.EVMInterpreter, analyzer *LookaheadAnalyzer) *constPropAnalyzer {
	return &constPropAnalyzer{
		contract:           contract,
		codeHash:           codeHash,
		interpreter:        interpreter,
		analyzer:           analyzer,
		failOnTopMemResize: MagicBool(false),
		verbose:            MagicBool(false),
		useBoundedJoins:    MagicBool(false),
		maxDisjuncts:       MagicInt(0),
	}
}

func (a *constPropAnalyzer) Analyze(execPrefix execPrefix) (result, error, error) {
	if a.verbose {
		var pre []uint64
		idx := 0
		for true {
			pc, exists := execPrefix[idx]
			if !exists {
				break
			}
			pre = append(pre, uint64(pc))
			idx++
		} // pre: list of all prefix
		/* test */
		// fmt.Printf("prefix: %#v\n", pre)
		// fmt.Printf("code: %x\n", a.contract.Code)
	}

	concJt := a.interpreter.Cfg.JumpTable // vm/interpreter.go
	// JumpTable: xxxInstrutionSet, vm/jump_table.go
	absJtPrefix := newAbsJumpTable(true)                                          // abstract-ops.go
	prefixRes, preErr := a.calculatePrecondition(concJt, absJtPrefix, execPrefix) //// core (prefix inference)                          ////
	if preErr != nil {
		return prefixMayFail(PrefixComputationFail), preErr, nil
	}
	if prefixRes.mayFail {
		return prefixMayFail(fmt.Sprintf("%v(%v)", PrefixComputationFail, prefixRes.failureCause)), nil, nil
	}

	absJt := newAbsJumpTable(false)
	states := map[string]absState{}
	keys := map[pcType]map[string]bool{}
	ppcMap := newPrevPCMap()
	var worklist []string
	workset := map[string]pcType{}

	addNewStates := func(prevPC pcType, newStates []pcAndSt) {
		for _, st := range newStates {
			pc := st.pc // newStates: suffix list, pc: next suffix
			ppcMap.addPrevPC(pc, prevPC)

			newState := st.st.withStackCopy().withMemCopy()

			stSize := -1
			if !newState.isBot && !newState.stack.isTop && newState.stack.stack != nil {
				stSize = newState.stack.len()
			}
			loc := fmt.Sprintf("%x:%x", pc, stSize) // state pc: len of suffix list		hex format			// loc

			oldState, exists := states[loc]
			ks := keys[pc]
			if ks == nil {
				ks = map[string]bool{}
			}
			numDisjs := len(ks)
			if !exists && a.maxDisjuncts <= numDisjs {
				loc = fmt.Sprintf("%x:%x", pc, -1)
				oldState, exists = states[loc]
			}
			if exists {
				var diff bool
				newState, diff = joinStates(oldState, newState)
				if !diff || a.useBoundedJoins {
					continue
				}
			}

			states[loc] = newState
			ks[loc] = true
			keys[pc] = ks
			if _, ex := workset[loc]; !ex {
				worklist = append(worklist, loc) // list of pc record
				workset[loc] = pc
			}
		}
	}

	popState := func() (absState, pcType) {
		ret := worklist[0]
		worklist = worklist[1:]
		pc := workset[ret]
		delete(workset, ret)
		return states[ret], pc
	}

	prefixLen := len(execPrefix)
	if 0 < prefixLen {
		lastPrefixPC := execPrefix[prefixLen-1]
		addNewStates(lastPrefixPC, prefixRes.postStates) // add a suffix(origianl prefix list len -1),
		// 		worklist -> suffix list loc msg
	}

	for 0 < len(worklist) { //// 		suffix checking                       //
		st, pc := popState() // worklist - 1	(get first suffix)
		if st.isBot {
			continue
		}
		opcode := a.contract.GetOp(uint64(pc))
		res, stepErr := a.step(pc, ppcMap, st, concJt[opcode], opcode, absJt, false) // excute op (ignoreTargets false)
		//		try to find target locations in suffix
		if stepErr != nil {
			return mayFail(StepExecFail), nil, stepErr
		}
		if res.mayFail {
			return mayFail(res.failureCause), nil, nil
		}
		addNewStates(pc, res.postStates) // upgrade suffix list msg (loc)
	}

	return noFail(), nil, nil
}

func (a *constPropAnalyzer) calculatePrecondition(concJt concJumpTable, absJt absJumpTable, execPrefix execPrefix) (stepRes, error) {
	ppcMap := newPrevPCMap()
	currRes := initRes() // 																	abstract-ops.go
	for idx := 0; true; idx++ {
		pc, exists := execPrefix[idx]
		if !exists {
			break
		}

		// Select from the results only the state that matchesBackwards the next pc in the prefix.
		currSt := botState() // 																abstract-state.go
		for _, st := range currRes.postStates {
			if st.pc == pc {
				if 0 < idx {
					ppc := execPrefix[idx-1]
					ppcMap.addPrevPC(pc, ppc) // current pc, pre pc
				}
				currSt, _ = joinStates(currSt, st.st) // abstract-state.go
			}
		} // init ppcMap, currSt

		/* debug prefix */
		// fmt.Printf("%v ", pc) // test
		if currSt.isBot {
			return emptyRes(), fmt.Errorf("expected feasible prefix")
		}
		opcode := a.contract.GetOp(uint64(pc)) // GetOp() : vm/contract return Opcodes of pc'th bytes in bytes array
		var err error
		currRes, err = a.step(pc, ppcMap, currSt, concJt[opcode], opcode, absJt, false)

		if err != nil {
			currRes = emptyRes()
		}
		/* For reach target in prefix case */
		if currRes.mayFail {
			return currRes, nil
		}
	}
	return currRes, nil
}

func (a *constPropAnalyzer) step(pc pcType, ppcMap *prevPCMap, st absState, conc vm.Operation, op vm.OpCode, jt absJumpTable, ignoreTargets bool) (stepRes, error) {
	abstractOp := jt[op]
	if abstractOp.valid != conc.Valid {
		return failRes(InternalFail), nil // abstract-ops.go
	}

	if a.analyzer.IsTargetingAssertionFailed() { // lookahead-analyzer.go, default false
		if op == vm.LOG1 {
			// We look for the following event type:
			// event AssertionFailed(string message);
			isAssertionFailed := true
			if st.isBot {
				isAssertionFailed = false
			} else if !st.stack.isTop && 3 <= st.stack.len() {
				topic := st.stack.stack.Back(2)
				magicTopic, _ := math.ParseBig256("0xb42604cb105a16c8f6db8a41e6b00c0c1b4826465e8bc504b3eb3e88b3e6a4a0")
				if !isTop(topic) && topic.Cmp(magicTopic) != 0 {
					isAssertionFailed = false
				}
			}
			if !ignoreTargets && isAssertionFailed {
				return failRes(ReachedAssertionFailed), nil
			}
		}
		if !abstractOp.valid {
			return emptyRes(), nil
		}
	} else if a.analyzer.HasTargetInstructions() { // length of TargetInstruction > 0, default false, can modified by Add...
		if !ignoreTargets && a.analyzer.IsTargetInstruction(a.codeHash, uint64(pc)) {
			return failRes(ReachedTargetInstructionFail), nil // reached-target-instruction !!
		}
		if !abstractOp.valid {
			return emptyRes(), nil // not target
		}
	} else {
		if !abstractOp.valid {
			switch op {
			case 0xfe:
				if a.analyzer.IsCoveredAssertion(a.codeHash, uint64(pc)) { // assertion check
					// No need to report a failure since the assertion has already been covered.
					return emptyRes(), nil // abstract-ops.go
				}
			}
			if !ignoreTargets {
				return failRes(InvalidOpcodeFail), nil
			}
			return emptyRes(), nil
		}
	}

	if st.stack.isTop { // abstract-stack.go no top in s1 or s2
		return failRes(TopStackFail), nil
	}

	if stLen := st.stack.len(); stLen < conc.MinStack || conc.MaxStack < stLen {
		return failRes(StackValidationFail), nil
	}

	postMem := st.mem              // abstract-memory.go
	if abstractOp.memSize != nil { // ...ops
		if conc.MemorySize == nil {
			return failRes(InternalFail), nil
		}
		msize, overflow, isUnknown, msErr := abstractOp.memSize(st.stack, conc.MemorySize)
		if msErr != nil {
			return failRes(InternalFail), nil
		}

		if isUnknown {
			if a.failOnTopMemResize {
				return failRes(TopMemoryResizeFail), nil
			}
			postMem = topMem()
		} else {
			if overflow {
				return failRes(MemoryOverflowFail), nil
			}

			var msz uint64
			if msz, overflow = math.SafeMul(vm.ToWordSize(msize), 32); overflow {
				return failRes(MemoryOverflowFail), nil
			}

			if 0 < msz {
				postMem = st.mem.clone()
				postMem.resize(msz)
			}
		}
	}

	postSt := absState{
		stack: st.stack,
		mem:   postMem,
	}
	env := execEnv{
		pc:          &pc,
		interpreter: a.interpreter,
		contract:    a.contract,
		ppcMap:      ppcMap,
		st:          postSt,
		conc:        conc,
	}
	return abstractOp.exec(env) // opxxx() , next
}
