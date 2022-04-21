package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/practical-formal-methods/bran/analysis"
)

type Prefix_msg struct {
	Code   string
	Prefix map[string][]uint64
	Coverage int
}

type Weight_msg struct {
	Weight map[string]int
	Coverage int
}

var prefixtList map[string]*Prefix_msg
var targetList map[string][]int
var weightList map[string]*Weight_msg

func read_prefix() {
	filePtr, err := os.Open("branch_msg/prefix.json")
	if err != nil {
		fmt.Println("Can not open prefix file", err.Error())
		return
	}
	defer filePtr.Close()

	decoder := json.NewDecoder(filePtr)
	err = decoder.Decode(&prefixtList)
	if err != nil {
		fmt.Println("Decode prefix file failed", err.Error())
	} else {
		fmt.Println("Decode prefix success")
		/* debug */
		// for name, msg := range contractList {
		// 	fmt.Println("\n")
		// 	fmt.Println(name)
		// 	fmt.Println("Bin : " + msg.Code)
		// 	fmt.Println("Prefix : ")
		// 	for branch, prefix := range msg.Prefix {
		// 		fmt.Println(branch + " : ")
		// 		fmt.Println(prefix)
		// 	}
		// }
	}
}

func read_targetLoction() {
	filePtr, err := os.Open("branch_msg/targets.json")
	if err != nil {
		fmt.Println("Can not open targes file", err.Error())
		return
	}
	defer filePtr.Close()

	decoder := json.NewDecoder(filePtr)
	err = decoder.Decode(&targetList)
	if err != nil {
		fmt.Println("Decode targes file failed", err.Error())
	} else {
		fmt.Println("Decode targes success")
		/* debug */
		// for name, msg := range targetList {
		// 	fmt.Println(name)
		// 	fmt.Println("Targets : ")
		// 	fmt.Println(msg)
		// }
		// fmt.Println("read targetLoc debug finished!")
	}
}

func init_weight(baseWeight int) {
	weightList = map[string]*Weight_msg{}
	for name, msg := range prefixtList {
		weightList[name] = &Weight_msg{Weight: make(map[string]int)}
		branchNum := make(map[int]string)
		var num int
		for branch := range msg.Prefix {
			num, _ = strconv.Atoi(strings.Split(branch, ":")[0])
			if _, ok := branchNum[num]; ok {
				branchNum[num] += "," + branch
			} else {
				branchNum[num] = branch
			}
		}
		var nums []int
		for n := range branchNum {
			nums = append(nums, n)
		}
		// sort.Sort(sort.IntSlice(nums))
		/*
			set longer branches with smaller weight,
			since they are more difficult to reach
		*/
		sort.Sort(sort.Reverse(sort.IntSlice(nums)))
		for mult, n := range nums {
			branchs := strings.Split(branchNum[n], ",")
			for _, b := range branchs {
				weightList[name].Weight[b] = (1 + mult) * baseWeight
			}
		}
		weightList[name].Coverage = msg.Coverage
	}
}

func write_tojson() {
	filePtr, err := os.Create("branch_msg/weight.json")
	if err != nil {
		fmt.Println("Create file failed", err.Error())
		return
	}
	defer filePtr.Close()

	encoder := json.NewEncoder(filePtr)
	err = encoder.Encode(weightList)
	if err != nil {
		fmt.Println("Encode result file failed", err.Error())
	} else {
		fmt.Println("Encode result success")
	}
}

func main() {
	read_prefix()
	read_targetLoction()
	var branchNumber uint64

	init_weight(1)

	for name, msg := range prefixtList {
		code, err := hex.DecodeString(msg.Code)
		if err != nil {
			fmt.Printf("\n[%v] error decoding contract code: %v\n", name, msg.Code)
			continue
		}
		fmt.Println(name)

		a := analysis.NewLookaheadAnalyzer()
		branchNumber = 0
		/* add target location for current branch here */
		for _, t := range targetList[name] {
			a.AddTargetInstruction(crypto.Keccak256Hash(code).Bytes(), uint64(t))
			// fmt.Println(t)		// debug
		}
		for branch, prefix := range msg.Prefix {
			branchNumber++
			// weightList[name].Weight[branch] = 5 // 									set branch initial running times
			// fmt.Println(branchNumber)
			// fmt.Println("Prefix to append:")
			// fmt.Println(prefix)

			a.Start(branchNumber, code, crypto.Keccak256Hash(code).Bytes())
			for _, pc := range prefix {
				a.AppendPrefixInstruction(branchNumber, pc)
			}
			fmt.Printf(branch + ": ")
			canIgnore, _, cause, _, err := a.CanIgnoreSuffix(branchNumber)

			if err != nil {
				fmt.Printf("\n[%v] analysis ended with an error: %v\n", name, err)
				continue
			}
			fmt.Println(canIgnore)
			if !canIgnore {
				fmt.Println(cause)
			}
			if !canIgnore && strings.Contains(cause, "reached-target-instruction") {
				weightList[name].Weight[branch] *= 16 //									give more energy
			}
		}
	}

	write_tojson()
}
