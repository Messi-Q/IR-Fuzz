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

// absState represents an abstract program state.
type absState struct {
	isBot bool
	stack absStack
	mem   absMem
}

// withStack creates a new state with a copy of the stack.
func (s absState) withStackCopy() absState {
	if s.isBot {
		return botState()
	}
	return absState{
		stack: s.stack.clone(),
		mem:   s.mem,
	}
}

// withMem creates a new state with a copy of the stack.
func (s absState) withMemCopy() absState {
	if s.isBot {
		return botState()
	}
	return absState{
		stack: s.stack,
		mem:   s.mem.clone(),
	}
}

func botState() absState {
	return absState{isBot: true}
}

// joinStates computes the join of two abstract states.
// It also returns a boolean indicating whether we went up (with respect to the first state) in the lattice.
func joinStates(s1 absState, s2 absState) (absState, bool) {				// return next no bot state
	if s2.isBot {
		return s1, false
	}
	if s1.isBot {
		return s2, true
	}
	nStack, diffStack := joinStacks(s1.stack, s2.stack, MagicBool(true))
	nMem, diffMem := joinMems(s1.mem, s2.mem)
	ns := absState{
		stack: nStack,
		mem:   nMem,
	}
	return ns, diffStack || diffMem											// else, join s1,s2 -> new state
}
