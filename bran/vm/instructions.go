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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/sha3"
)

var (
	bigZero                  = new(big.Int)
	tt255                    = math.BigPow(2, 255)
	errWriteProtection       = errors.New("evm: write protection")
	errReturnDataOutOfBounds = errors.New("evm: return data out of bounds")
	errExecutionReverted     = errors.New("evm: execution reverted")
	errMaxCodeSizeExceeded   = errors.New("evm: max code size exceeded")
	errInvalidJump           = errors.New("evm: invalid jump destination")
)

func opAdd(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	math.U256(y.Add(x, y))

	interpreter.IntPool.put(x)
	return nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	math.U256(y.Sub(x, y))

	interpreter.IntPool.put(x)
	return nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Pop()
	stack.Push(math.U256(x.Mul(x, y)))

	interpreter.IntPool.put(y)

	return nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	if y.Sign() != 0 {
		math.U256(y.Div(x, y))
	} else {
		y.SetUint64(0)
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := math.S256(stack.Pop()), math.S256(stack.Pop())
	res := interpreter.IntPool.getZero()

	if y.Sign() == 0 || x.Sign() == 0 {
		stack.Push(res)
	} else {
		if x.Sign() != y.Sign() {
			res.Div(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Div(x.Abs(x), y.Abs(y))
		}
		stack.Push(math.U256(res))
	}
	interpreter.IntPool.put(x, y)
	return nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Pop()
	if y.Sign() == 0 {
		stack.Push(x.SetUint64(0))
	} else {
		stack.Push(math.U256(x.Mod(x, y)))
	}
	interpreter.IntPool.put(y)
	return nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := math.S256(stack.Pop()), math.S256(stack.Pop())
	res := interpreter.IntPool.getZero()

	if y.Sign() == 0 {
		stack.Push(res)
	} else {
		if x.Sign() < 0 {
			res.Mod(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Mod(x.Abs(x), y.Abs(y))
		}
		stack.Push(math.U256(res))
	}
	interpreter.IntPool.put(x, y)
	return nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	base, exponent := stack.Pop(), stack.Pop()
	// some shortcuts
	cmpToOne := exponent.Cmp(big1)
	if cmpToOne < 0 { // Exponent is zero
		// x ^ 0 == 1
		stack.Push(base.SetUint64(1))
	} else if base.Sign() == 0 {
		// 0 ^ y, if y != 0, == 0
		stack.Push(base.SetUint64(0))
	} else if cmpToOne == 0 { // Exponent is one
		// x ^ 1 == x
		stack.Push(base)
	} else {
		stack.Push(math.Exp(base, exponent))
		interpreter.IntPool.put(base)
	}
	interpreter.IntPool.put(exponent)
	return nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	back := stack.Pop()
	if back.Cmp(big.NewInt(31)) < 0 {
		bit := uint(back.Uint64()*8 + 7)
		num := stack.Pop()
		mask := back.Lsh(common.Big1, bit)
		mask.Sub(mask, common.Big1)
		if num.Bit(int(bit)) > 0 {
			num.Or(num, mask.Not(mask))
		} else {
			num.And(num, mask)
		}

		stack.Push(math.U256(num))
	}

	interpreter.IntPool.put(back)
	return nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.Peek()
	math.U256(x.Not(x))
	return nil, nil
}

func opLt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	if x.Cmp(y) < 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opGt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	if x.Cmp(y) > 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(1)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(0)

	default:
		if x.Cmp(y) < 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(0)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(1)

	default:
		if x.Cmp(y) > 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opEq(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	if x.Cmp(y) == 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.IntPool.put(x)
	return nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.Peek()
	if x.Sign() > 0 {
		x.SetUint64(0)
	} else {
		x.SetUint64(1)
	}
	return nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Pop()
	stack.Push(x.And(x, y))

	interpreter.IntPool.put(y)
	return nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	y.Or(x, y)

	interpreter.IntPool.put(x)
	return nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.Pop(), stack.Peek()
	y.Xor(x, y)

	interpreter.IntPool.put(x)
	return nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	th, val := stack.Pop(), stack.Peek()
	if th.Cmp(common.Big32) < 0 {
		b := math.Byte(val, 32, int(th.Int64()))
		val.SetUint64(uint64(b))
	} else {
		val.SetUint64(0)
	}
	interpreter.IntPool.put(th)
	return nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.Pop(), stack.Pop(), stack.Pop()
	if z.Cmp(bigZero) > 0 {
		x.Add(x, y)
		x.Mod(x, z)
		stack.Push(math.U256(x))
	} else {
		stack.Push(x.SetUint64(0))
	}
	interpreter.IntPool.put(y, z)
	return nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.Pop(), stack.Pop(), stack.Pop()
	if z.Cmp(bigZero) > 0 {
		x.Mul(x, y)
		x.Mod(x, z)
		stack.Push(math.U256(x))
	} else {
		stack.Push(x.SetUint64(0))
	}
	interpreter.IntPool.put(y, z)
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := math.U256(stack.Pop()), math.U256(stack.Peek())
	defer interpreter.IntPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	math.U256(value.Lsh(value, n))

	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := math.U256(stack.Pop()), math.U256(stack.Peek())
	defer interpreter.IntPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	math.U256(value.Rsh(value, n))

	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, S256 returns (potentially) a new bigint, so we're popping, not peeking this one
	shift, value := math.U256(stack.Pop()), math.S256(stack.Pop())
	defer interpreter.IntPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		if value.Sign() >= 0 {
			value.SetUint64(0)
		} else {
			value.SetInt64(-1)
		}
		stack.Push(math.U256(value))
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.Rsh(value, n)
	stack.Push(math.U256(value))

	return nil, nil
}

func opSha3(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.Pop(), stack.Pop()
	data := memory.GetPtr(offset.Int64(), size.Int64())

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.vmConfig.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}
	stack.Push(interpreter.IntPool.get().SetBytes(interpreter.hasherBuf[:]))

	interpreter.IntPool.put(offset, size)
	return nil, nil
}

func opAddress(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetBytes(contract.Address().Bytes()))
	return nil, nil
}

func opBalance(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.Peek()
	slot.Set(interpreter.evm.StateDB.GetBalance(common.BigToAddress(slot)))
	return nil, nil
}

func opOrigin(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetBytes(interpreter.evm.Origin.Bytes()))
	return nil, nil
}

func opCaller(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetBytes(contract.Caller().Bytes()))
	return nil, nil
}

func opCallValue(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().Set(contract.value))
	return nil, nil
}

func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetBytes(getDataBig(contract.Input, stack.Pop(), big32)))
	return nil, nil
}

func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetInt64(int64(len(contract.Input))))
	return nil, nil
}

func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.Pop()
		dataOffset = stack.Pop()
		length     = stack.Pop()
	)
	memory.Set(memOffset.Uint64(), length.Uint64(), getDataBig(contract.Input, dataOffset, length))

	interpreter.IntPool.put(memOffset, dataOffset, length)
	return nil, nil
}

func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetUint64(uint64(len(interpreter.returnData))))
	return nil, nil
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.Pop()
		dataOffset = stack.Pop()
		length     = stack.Pop()

		end = interpreter.IntPool.get().Add(dataOffset, length)
	)
	defer interpreter.IntPool.put(memOffset, dataOffset, length, end)

	if !end.IsUint64() || uint64(len(interpreter.returnData)) < end.Uint64() {
		return nil, errReturnDataOutOfBounds
	}
	memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[dataOffset.Uint64():end.Uint64()])

	return nil, nil
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.Peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(common.BigToAddress(slot))))

	return nil, nil
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	l := interpreter.IntPool.get().SetInt64(int64(len(contract.Code)))
	stack.Push(l)

	return nil, nil
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.Pop()
		codeOffset = stack.Pop()
		length     = stack.Pop()
	)
	codeCopy := getDataBig(contract.Code, codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	interpreter.IntPool.put(memOffset, codeOffset, length)
	return nil, nil
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		addr       = common.BigToAddress(stack.Pop())
		memOffset  = stack.Pop()
		codeOffset = stack.Pop()
		length     = stack.Pop()
	)
	codeCopy := getDataBig(interpreter.evm.StateDB.GetCode(addr), codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	interpreter.IntPool.put(memOffset, codeOffset, length)
	return nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.Peek()
	address := common.BigToAddress(slot)
	if interpreter.evm.StateDB.Empty(address) {
		slot.SetUint64(0)
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().Set(interpreter.evm.GasPrice))
	return nil, nil
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	num := stack.Pop()

	n := interpreter.IntPool.get().Sub(interpreter.evm.BlockNumber, common.Big257)
	if num.Cmp(n) > 0 && num.Cmp(interpreter.evm.BlockNumber) < 0 {
		stack.Push(interpreter.evm.GetHash(num.Uint64()).Big())
	} else {
		stack.Push(interpreter.IntPool.getZero())
	}
	interpreter.IntPool.put(num, n)
	return nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetBytes(interpreter.evm.Coinbase.Bytes()))
	return nil, nil
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(math.U256(interpreter.IntPool.get().Set(interpreter.evm.Time)))
	return nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(math.U256(interpreter.IntPool.get().Set(interpreter.evm.BlockNumber)))
	return nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(math.U256(interpreter.IntPool.get().Set(interpreter.evm.Difficulty)))
	return nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(math.U256(interpreter.IntPool.get().SetUint64(interpreter.evm.GasLimit)))
	return nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	interpreter.IntPool.put(stack.Pop())
	return nil, nil
}

func opMload(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	v := stack.Peek()
	offset := v.Int64()
	v.SetBytes(memory.GetPtr(offset, 32))
	return nil, nil
}

func opMstore(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// pop value of the stack
	mStart, val := stack.Pop(), stack.Pop()
	memory.Set32(mStart.Uint64(), val)

	interpreter.IntPool.put(mStart, val)
	return nil, nil
}

func opMstore8(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	off, val := stack.Pop().Int64(), stack.Pop().Int64()
	memory.store[off] = byte(val & 0xff)

	return nil, nil
}

func opSload(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := stack.Peek()
	val := interpreter.evm.StateDB.GetState(contract.Address(), common.BigToHash(loc))
	loc.SetBytes(val.Bytes())
	return nil, nil
}

func opSstore(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := common.BigToHash(stack.Pop())
	val := stack.Pop()
	interpreter.evm.StateDB.SetState(contract.Address(), loc, common.BigToHash(val))

	interpreter.IntPool.put(val)
	return nil, nil
}

func opJump(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos := stack.Pop()
	if !contract.validJumpdest(pos) {
		return nil, errInvalidJump
	}
	*pc = pos.Uint64()

	interpreter.IntPool.put(pos)
	return nil, nil
}

func opJumpi(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos, cond := stack.Pop(), stack.Pop()
	if cond.Sign() != 0 {
		if !contract.validJumpdest(pos) {
			return nil, errInvalidJump
		}
		*pc = pos.Uint64()
	} else {
		*pc++
	}

	interpreter.IntPool.put(pos, cond)
	return nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetUint64(*pc))
	return nil, nil
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetInt64(int64(memory.Len())))
	return nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.Push(interpreter.IntPool.get().SetUint64(contract.Gas))
	return nil, nil
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		value        = stack.Pop()
		offset, size = stack.Pop(), stack.Pop()
		input        = memory.GetCopy(offset.Int64(), size.Int64())
		gas          = contract.Gas
	)
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}

	contract.UseGas(gas)
	res, addr, returnGas, suberr := interpreter.evm.Create(contract, input, gas, value)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stack.Push(interpreter.IntPool.getZero())
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetBytes(addr.Bytes()))
	}
	contract.Gas += returnGas
	interpreter.IntPool.put(value, offset, size)

	if suberr == errExecutionReverted {
		return res, nil
	}
	return nil, nil
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		endowment    = stack.Pop()
		offset, size = stack.Pop(), stack.Pop()
		salt         = stack.Pop()
		input        = memory.GetCopy(offset.Int64(), size.Int64())
		gas          = contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	contract.UseGas(gas)
	res, addr, returnGas, suberr := interpreter.evm.Create2(contract, input, gas, endowment, salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetBytes(addr.Bytes()))
	}
	contract.Gas += returnGas
	interpreter.IntPool.put(endowment, offset, size, salt)

	if suberr == errExecutionReverted {
		return res, nil
	}
	return nil, nil
}

func opCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	interpreter.IntPool.put(stack.Pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop()
	toAddr := common.BigToAddress(addr)
	value = math.U256(value)
	// Get the arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	if value.Sign() != 0 {
		gas += params.CallStipend
	}
	ret, returnGas, err := interpreter.evm.Call(contract, toAddr, args, gas, value)
	if err != nil {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.IntPool.put(addr, value, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opCallCode(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.IntPool.put(stack.Pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop()
	toAddr := common.BigToAddress(addr)
	value = math.U256(value)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	if value.Sign() != 0 {
		gas += params.CallStipend
	}
	ret, returnGas, err := interpreter.evm.CallCode(contract, toAddr, args, gas, value)
	if err != nil {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.IntPool.put(addr, value, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.IntPool.put(stack.Pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop()
	toAddr := common.BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	ret, returnGas, err := interpreter.evm.DelegateCall(contract, toAddr, args, gas)
	if err != nil {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.IntPool.put(addr, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opStaticCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.IntPool.put(stack.Pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop(), stack.Pop()
	toAddr := common.BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	ret, returnGas, err := interpreter.evm.StaticCall(contract, toAddr, args, gas)
	if err != nil {
		stack.Push(interpreter.IntPool.getZero())
	} else {
		stack.Push(interpreter.IntPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.IntPool.put(addr, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.Pop(), stack.Pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	interpreter.IntPool.put(offset, size)
	return ret, nil
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.Pop(), stack.Pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	interpreter.IntPool.put(offset, size)
	return ret, nil
}

func opStop(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opSuicide(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	balance := interpreter.evm.StateDB.GetBalance(contract.Address())
	interpreter.evm.StateDB.AddBalance(common.BigToAddress(stack.Pop()), balance)

	interpreter.evm.StateDB.Suicide(contract.Address())
	return nil, nil
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) ExecutionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		topics := make([]common.Hash, size)
		mStart, mSize := stack.Pop(), stack.Pop()
		for i := 0; i < size; i++ {
			topics[i] = common.BigToHash(stack.Pop())
		}

		d := memory.GetCopy(mStart.Int64(), mSize.Int64())
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.BlockNumber.Uint64(),
		})

		interpreter.IntPool.put(mStart, mSize)
		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		codeLen = uint64(len(contract.Code))
		integer = interpreter.IntPool.get()
	)
	*pc += 1
	if *pc < codeLen {
		stack.Push(integer.SetUint64(uint64(contract.Code[*pc])))
	} else {
		stack.Push(integer.SetUint64(0))
	}
	return nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) ExecutionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		codeLen := len(contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := interpreter.IntPool.get()
		stack.Push(integer.SetBytes(common.RightPadBytes(contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		return nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) ExecutionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.dup(interpreter.IntPool, int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) ExecutionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.swap(int(size))
		return nil, nil
	}
}
