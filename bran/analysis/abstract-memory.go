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

	"github.com/practical-formal-methods/bran/vm"
)

// absMem represents a memory that can be top.
type absMem struct {
	isTop bool
	mem   *vm.Memory
}

// len returns the number of bytes in memory.
func (m absMem) len() int {
	return m.mem.Len()
}

// resize resizes a non-top memory.
func (m absMem) resize(ns uint64) {
	if !m.isTop {
		m.mem.Resize(ns)
	}
}

// clone does a deep copy the memory.
func (m absMem) clone() absMem {
	if m.isTop {
		return topMem()
	}
	return absMem{mem: m.mem.Clone()}
}

// get gets a slice of bytes from memory.
// If any of the bytes are top, then the top slice is returned.
func (m absMem) get(offset, size int64) absBytes {
	if m.isTop {
		return topBytes()
	}
	bs := m.mem.GetCopy(offset, size)
	for _, b := range bs {
		if absByte(b).isTop() {
			return topBytes()
		}
	}
	return absBytes{bytes: bs}
}

// set writes to the [offset, offset + size) section of memory.
// if absBytes is top, then every memory location is filled with the top byte.
func (m absMem) set(offset, size uint64, bytes absBytes) {
	if m.isTop {
		return
	}
	var bs []byte
	if bytes.isTop {
		bs = make([]byte, size)
		for i := range bs {
			bs[i] = byte(topByte())
		}
	} else {
		bs = bytes.bytes
	}
	m.mem.Set(offset, size, bs)
}

func topMem() absMem {
	return absMem{isTop: true}
}

// joinMems computes the join of two memory elements.
// It also returns a boolean indicating whether we went up (relative to the first memory) in the lattice.
func joinMems(m1 absMem, m2 absMem) (absMem, bool) {
	if m1.isTop {
		return topMem(), false
	}
	if m2.isTop || m1.len() != m2.len() {
		return topMem(), true
	}
	nm := vm.NewMemory()
	nm.Resize(uint64(m1.len()))
	diff := false
	for i := 0; i < m1.len(); i++ {
		b, diffB := joinBytes(absByte(m1.mem.Data()[i]), absByte(m2.mem.Data()[i]))
		nm.Data()[i] = byte(b)
		diff = diff || diffB
	}
	return absMem{mem: nm}, diff
}

// absBytes represents a byte slice that can be top.
type absBytes struct {
	isTop bool
	bytes []byte
}

func (bs absBytes) toBigInt() *big.Int {
	if bs.isTop {
		return topVal()
	}
	res := &big.Int{}
	res.SetBytes(bs.bytes)
	return res
}

func topBytes() absBytes {
	return absBytes{
		isTop: true,
	}
}

// absByte is the type of abstract memory contents.
type absByte byte

// topByte returns the top of the abstract byte lattice.
// 101 is an arbitrary number in the domain.
// This can lead to loss of precision.
func topByte() absByte {
	return absByte(MagicByte(101))
}

// isTop determines if a byte represents the top value.
func (b absByte) isTop() bool {
	return b == topByte()
}

// joinBytes computes the join of two abstract bytes.
// It also returns a boolean indicating whether we went up (relative to the first byte) in the lattice.
func joinBytes(b1 absByte, b2 absByte) (absByte, bool) {
	if b1.isTop() {
		return topByte(), false
	}
	if b2.isTop() || b1 != b2 {
		return topByte(), true
	}
	return b1, false
}
