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

	"github.com/ethereum/go-ethereum/common/math"
)

// absVal represents an abstract value.
type absVal = big.Int

// TODO(wuestholz): Maybe introduce a separate value for anyBool or anyByte to improve precision.

// topVal returns the value of top (in the value lattice).
// We represent top by a "random" large prime number (very unlikely to occur in normal execution).
// This can lead to some loss in precision, but not unsoundness.
func topVal() *absVal {
	ret := &big.Int{}
	// 70-digit prime number from https://primes.utm.edu/lists/small/small.html
	ret.SetString(MagicString("4669523849932130508876392554713407521319117239637943224980015676156491"), 10)
	math.U256(ret)
	return ret
}

var topValInternal = topVal()

// isTop determines whether the given abstract value is top.
func isTop(v *absVal) bool {
	return v.Cmp(topValInternal) == 0
}

// joinVals computes the join of two abstract values.
// It also returns a boolean indicating whether we went up (with respect to the first value) in the lattice.
func joinVals(v1 *absVal, v2 *absVal) (*absVal, bool) {
	if isTop(v1) || v1.Cmp(v2) == 0 {
		return (&big.Int{}).Set(v1), false
	}
	return topVal(), true
}

// meetVals computes the meet of two abstract values and nil if none exists (i.e., bot).
func meetVals(v1 *absVal, v2 *absVal) *absVal {
	if isTop(v1) {
		return (&big.Int{}).Set(v2)
	}
	if isTop(v2) {
		return (&big.Int{}).Set(v1)
	}
	if v1.Cmp(v2) == 0 {
		return (&big.Int{}).Set(v1)
	}
	return nil
}
