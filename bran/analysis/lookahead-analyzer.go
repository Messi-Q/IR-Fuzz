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
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/params"

	"github.com/practical-formal-methods/bran/vm"
)

var ReachedTargetInstructionFail = "reached-target-instruction"
var ReachedAssertionFailed = "reached-assertion-failed"
var InvalidOpcodeFail = "invalid-opcode"
var UnsupportedOpcodeFail = "unsupported-opcode"
var MemoryOverflowFail = "memory-overflow-failure"
var TopMemoryResizeFail = "top-memory-resize-failure"
var TopStackFail = "top-stack"
var StackValidationFail = "invalid-stack"
var JumpToTopFail = "jump-to-top"
var TopOffsetFail = "top-offset-failure"
var PrefixComputationFail = "prefix-computation-failure"
var StepExecFail = "step-execution-failure"
var InternalFail = "internal-failure"

type LookaheadAnalyzer struct {
	callInfos                  map[uint64]*callInfo
	cachedResults              map[prefixHash]result
	isTargetInstruction        map[string]bool
	isCoveredAssertion         map[string]bool
	lids                       map[string]string
	coveredPaths               map[string]uint64
	maxPrefixLen               int
	useDummyAnalysis           bool
	isTargetingAssertionFailed bool

	numSuccess    uint64
	numFail       uint64
	numPrefixFail uint64
	failureCauses map[string]uint64
	numErrors     uint64
	time          time.Duration
	startTime     time.Time
}

type callInfo struct {
	contract    *vm.Contract
	codeHash    common.Hash
	prefix      execPrefix // init in AppendPrefixInstruction, empty at first
	prefixLen   int        // started from 0
	prefixHash  hash.Hash32
	summaryHash hash.Hash32
	analyzer    *constPropAnalyzer
}

type prefixHash uint32

func NewLookaheadAnalyzer() *LookaheadAnalyzer {
	return &LookaheadAnalyzer{
		failureCauses:       map[string]uint64{},
		cachedResults:       map[prefixHash]result{},
		isTargetInstruction: map[string]bool{},
		isCoveredAssertion:  map[string]bool{},
		lids:                map[string]string{},
		coveredPaths:        map[string]uint64{},
		callInfos:           map[uint64]*callInfo{},
		maxPrefixLen:        MagicInt(8192),
		useDummyAnalysis:    MagicBool(false),
	}
}

func (a *LookaheadAnalyzer) Start(callNumber uint64, code, codeHash []byte) {
	a.startTimer()
	defer a.stopTimer()

	if callNumber < 1 {
		a.callInfos = map[uint64]*callInfo{}
	}
	addr := common.HexToAddress(MagicString("0x0123456789abcdef"))
	ch := common.BytesToHash(codeHash) // hash of code, init here
	info := callInfo{
		codeHash:    ch,
		contract:    newDummyContract(addr, code, ch), // only code is provided
		prefix:      map[int]pcType{},                 // pcType : const-prop-analyzer
		prefixHash:  fnv.New32a(),
		summaryHash: fnv.New32a(),
	} // no analyzer
	a.callInfos[callNumber] = &info
}

func (a *LookaheadAnalyzer) AppendPrefixSummary(callNumber, callNumberToSummarize uint64) {
	a.startTimer()
	defer a.stopTimer()

	info := a.callInfos[callNumber]
	if info == nil {
		return
	}
	sumInfo := a.callInfos[callNumberToSummarize]
	if sumInfo == nil {
		return
	}
	prefixSum := sumInfo.prefixHash.Sum32()
	prefixBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefixBytes, prefixSum)
	info.summaryHash.Write(prefixBytes)
	summarySum := sumInfo.summaryHash.Sum32()
	summaryBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(summaryBytes, summarySum)
	info.summaryHash.Write(summaryBytes)
}

func (a *LookaheadAnalyzer) AppendPrefixInstruction(callNumber uint64, pc uint64) {
	a.startTimer()
	defer a.stopTimer()

	info := a.callInfos[callNumber]
	if info == nil {
		return
	}
	prefixLen := info.prefixLen // default 0
	if prefixLen < a.maxPrefixLen {
		// We stop recording if it becomes too long.
		info.prefix[prefixLen] = pcType(pc) // init value of prefix
		// 		equal to  user's given prefix list
	}
	info.prefixLen++
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, pc)
	info.prefixHash.Write(b)
}

func (a *LookaheadAnalyzer) CurrentPathID() string { // 											get pid
	info := a.callInfos[0]
	if info == nil {
		return ""
	}
	pHash := prefixHash(info.prefixHash.Sum32())
	sHash := info.summaryHash.Sum32()
	return fmt.Sprintf("%x+%x", pHash, sHash)
}

func (a *LookaheadAnalyzer) CanIgnoreSuffix(callNumber uint64) (canIgnore, avoidRetry bool, justification, prefixId string, err error) {
	a.startTimer()
	defer a.stopTimer()

	info := a.callInfos[callNumber]
	if info == nil {
		return false, false, "", "", fmt.Errorf("analysis not yet started")
	}

	if a.useDummyAnalysis {
		return false, false, "", "", nil
	}

	if a.maxPrefixLen < info.prefixLen {
		return false, true, "", "", fmt.Errorf("overly long prefix")
	}

	pHash := prefixHash(info.prefixHash.Sum32())
	sHash := info.summaryHash.Sum32()
	pid := fmt.Sprintf("%x:%x", pHash, sHash) //											pathid

	if cachedRes, found := a.cachedResults[pHash]; found { // 								avoid retry
		if cachedRes.mayFail {
			return false, cachedRes.avoidRetry, cachedRes.failureCause, pid, nil
		}
		a.recordSuccess()
		return true, cachedRes.avoidRetry, "", pid, nil
	}

	if info.analyzer == nil {
		evm := newDummyEVM()
		interpreter, ok := evm.Interpreter().(*vm.EVMInterpreter)
		if !ok {
			return false, true, "", pid, fmt.Errorf("expected compatible EVM interpreter")
		}
		info.analyzer = newConstPropAnalyzer(info.contract, info.codeHash, interpreter, a) // default analyzer, const-prop-analyzer
	}

	res, prefixErr, suffixErr := info.analyzer.Analyze(info.prefix) // 						Core

	if prefixErr != nil {
		a.recordError()
		return false, true, "", pid, prefixErr
	}
	if suffixErr != nil {
		a.recordError()
		return false, false, "", pid, suffixErr
	}

	// We cache both kinds of results, but not errors.
	a.cachedResults[pHash] = result{
		mayFail:      res.mayFail,
		failureCause: res.failureCause,
		avoidRetry:   res.avoidRetry,
	}

	if res.mayFail {
		a.recordFailure(res.failureCause, res.avoidRetry)
		return false, res.avoidRetry, res.failureCause, pid, nil
	}

	a.recordSuccess()
	return true, false, "", pid, nil
}

func (a *LookaheadAnalyzer) IsCoveredAssertion(codeHash common.Hash, pc uint64) bool {
	return a.isCoveredAssertion[fmt.Sprintf("%032x:%x", codeHash, pc)]
}

func (a *LookaheadAnalyzer) RecordCoveredAssertion(codeHash []byte, pc uint64) {
	a.isCoveredAssertion[fmt.Sprintf("%032x:%x", codeHash, pc)] = true
}

func (a *LookaheadAnalyzer) AddTargetInstruction(codeHash []byte, pc uint64) { // set Target(pc)
	loc := fmt.Sprintf("%032x:%x", codeHash, pc)
	a.isTargetInstruction[loc] = true
}

func (a *LookaheadAnalyzer) AddTargetLocation(loc string) { // set Target(loc)
	a.isTargetInstruction[loc] = true
}

func (a *LookaheadAnalyzer) HasTargetInstructions() bool {
	return 0 < len(a.isTargetInstruction)
}

func (a *LookaheadAnalyzer) IsTargetingAssertionFailed() bool {
	return a.isTargetingAssertionFailed
}

func (a *LookaheadAnalyzer) TargetAssertionFailed() {
	a.isTargetingAssertionFailed = true
}

func (a *LookaheadAnalyzer) IsTargetInstruction(codeHash common.Hash, pc uint64) bool {
	id := fmt.Sprintf("%032x:%x", codeHash, pc) // hex len > 32(add 0) : pc
	return a.isTargetInstruction[id]
}

func (a *LookaheadAnalyzer) startTimer() {
	a.startTime = time.Now()
}

func (a *LookaheadAnalyzer) stopTimer() {
	a.time += time.Now().Sub(a.startTime)
}

func (a *LookaheadAnalyzer) RecordCoveredPath(pathId, lid string) {
	if _, exists := a.lids[pathId]; !exists {
		a.lids[pathId] = lid
		a.coveredPaths[lid]++
	}
}

func (a *LookaheadAnalyzer) recordSuccess() {
	a.numSuccess++
}

func (a *LookaheadAnalyzer) recordFailure(cause string, inPrefix bool) {
	if inPrefix {
		a.numPrefixFail++
	} else {
		a.numFail++
	}
	a.failureCauses[cause]++
}

func (a *LookaheadAnalyzer) recordError() {
	a.numErrors++
}

func (a *LookaheadAnalyzer) NumSuccess() uint64 {
	return a.numSuccess
}

func (a *LookaheadAnalyzer) NumFail() uint64 {
	return a.numFail
}

func (a *LookaheadAnalyzer) NumPrefixFail() uint64 {
	return a.numPrefixFail
}

func (a *LookaheadAnalyzer) NumErrors() uint64 {
	return a.numErrors
}

func (a *LookaheadAnalyzer) CoveredPathsPerLID() map[string]uint64 {
	cps := map[string]uint64{}
	for lid, cnt := range a.coveredPaths {
		cps[lid] = cnt
	}
	return cps
}

func (a *LookaheadAnalyzer) Time() time.Duration {
	return a.time
}

func (a *LookaheadAnalyzer) FailureCauses() map[string]uint64 {
	fcs := map[string]uint64{}
	for cause, cnt := range a.failureCauses {
		fcs[cause] = cnt
	}
	return fcs
}

type dummyContractRef struct {
	address common.Address
}

func (d dummyContractRef) Address() common.Address {
	return common.BytesToAddress(d.address.Bytes())
}

// newDummyContract creates a mock contract that only remembers its address.
func newDummyContract(address common.Address, code []byte, codeHash common.Hash) *vm.Contract {
	dummyRef := dummyContractRef{address: address}
	val := topVal()
	ct := vm.NewContract(dummyRef, dummyRef, val, MagicUInt64(0xffffffffffffffff))               // NewContract(): contract.go
	ct.SetCodeOptionalHash(&(dummyRef.address), &vm.CodeAndHash{Code: code, CodeHash: codeHash}) // CodeAndHash(): evm.go
	return ct
}

// newDummyEVM creates a EVM object we can use to run code.
func newDummyEVM() *vm.EVM {
	ctx := vm.Context{
		BlockNumber: big.NewInt(1),
	}
	evmConfig := vm.Config{JumpTable: vm.NewConstantinopleInstructionSet()}
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(1),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		Ethash:              new(params.EthashConfig),
	}
	dummyStateDB := &state.StateDB{}
	return vm.NewEVM(ctx, dummyStateDB, chainConfig, evmConfig)
}
