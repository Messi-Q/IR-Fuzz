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
	"fmt"
	"math/big"

	"github.com/practical-formal-methods/bran/vm"
)

// absStack represents a stack that can be top.
type absStack struct {
	isTop bool
	stack *vm.Stack
}

// cloneStack does a deep copy of an abstract stack.
func (s absStack) clone() absStack {
	if s.isTop {
		return topStack()
	}
	return absStack{stack: s.stack.Clone()}
}

// hasTop returns true if any of the given stack indices is the top value.
func (s absStack) hasTop(indices ...int) (bool, error) {
	if s.isTop {
		return true, nil
	}
	for _, idx := range indices {
		if s.len() <= idx {
			return false, fmt.Errorf("expected indices within bounds")
		}
		if isTop(s.stack.Back(idx)) {
			return true, nil
		}
	}
	return false, nil
}

func (s absStack) len() int {
	return s.stack.Len()
}

func topStack() absStack {
	return absStack{isTop: true}
}

func emptyStack() absStack {
	return absStack{
		stack: vm.NewStack(),
	}
}

// joinStacks computes the join of two abstract stacks.
// It also returns a boolean indicating whether we went up (relative to the first stack in the lattice.
func joinStacks(s1 absStack, s2 absStack, avoidShrinking bool) (absStack, bool) {
	if s1.isTop {
		return topStack(), false
	}
	if s2.isTop {
		return topStack(), true
	}

	l1 := s1.stack.Len()
	l2 := s2.stack.Len()

	if avoidShrinking {
		maxLen := l1
		if maxLen < l2 {
			maxLen = l2
		}
		diff := false
		res := emptyStack()
		for i := maxLen - 1; 0 <= i; i-- {
			var v1 *big.Int
			if i < l1 {
				v1 = s1.stack.Back(i)
			}
			var v2 *big.Int
			if i < l2 {
				v2 = s2.stack.Back(i)
			}
			if v1 != nil && v2 != nil {
				v, diffV := joinVals(v1, v2)
				diff = diff || diffV
				res.stack.Push(v)
			} else if v2 != nil {
				res.stack.Push(v2)
				diff = true
			} else if v1 != nil {
				res.stack.Push(v1)
			}
		}
		return res, diff
	}

	diff := false
	minLen := l1
	// If the stack sizes differ we make the joined stack be of the smaller size and join the elements pointwise.
	// This is sound, but may result in spurious failures later when validating stacks (i.e., it is too small).
	if l2 < minLen {
		minLen = l2
		diff = true
	}
	res := emptyStack()
	for i := minLen - 1; 0 <= i; i-- {
		v, diffV := joinVals(s1.stack.Back(i), s2.stack.Back(i))
		res.stack.Push(v)
		diff = diff || diffV
	}
	return res, diff
}
