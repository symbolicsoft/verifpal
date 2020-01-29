/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package verifpal

import (
	"strings"
	"sync"
)

func replacementMapInit(valPrincipalState principalState, valAttackerState attackerState, stage int) replacementMap {
	var replacementsGroup sync.WaitGroup
	var replacementsMutex sync.Mutex
	valReplacementMap := replacementMap{
		initialized:       true,
		constants:         []constant{},
		replacements:      [][]value{},
		combination:       []value{},
		depthIndex:        []int{},
		outOfReplacements: false,
	}
	for i, v := range valAttackerState.known {
		if !valAttackerState.wire[i] || v.kind != "constant" {
			continue
		}
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, v.constant)
		iii := sanityGetAttackerStateIndexFromConstant(valAttackerState, v.constant)
		mutatedTo := strInSlice(valPrincipalState.sender[ii], valAttackerState.mutatedTo[iii])
		trulyGuarded := false
		if valPrincipalState.guard[ii] {
			trulyGuarded = true
			if iii >= 0 && mutatedTo {
				trulyGuarded = false
			}
		}
		if trulyGuarded {
			continue
		}
		if valPrincipalState.creator[ii] == valPrincipalState.name {
			continue
		}
		if !valPrincipalState.known[ii] {
			continue
		}
		if !intInSlice(valAttackerState.currentPhase, valPrincipalState.phase[ii]) {
			continue
		}
		a := valPrincipalState.assigned[ii]
		replacementsGroup.Add(1)
		go func(v value) {
			c, r, b := replacementMapReplaceValue(
				a, v, ii, stage,
				valPrincipalState, valAttackerState,
			)
			if !b {
				replacementsGroup.Done()
				return
			}
			replacementsMutex.Lock()
			valReplacementMap.constants = append(valReplacementMap.constants, c)
			valReplacementMap.replacements = append(valReplacementMap.replacements, r)
			replacementsMutex.Unlock()
			replacementsGroup.Done()
		}(v)
	}
	replacementsGroup.Wait()
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for iiii := range valReplacementMap.constants {
		valReplacementMap.depthIndex[iiii] = 0
	}
	return valReplacementMap
}

func replacementMapReplaceValue(
	a value, v value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) (constant, []value, bool) {
	replacements := []value{}
	gOrNil := ((strings.ToLower(a.constant.name) == "g") ||
		(a.constant.name == "nil"))
	switch a.kind {
	case "constant":
		if gOrNil {
			return v.constant, replacements, false
		}
		replacements = append(replacements, a)
		replacements = append(replacements, constantN)
		for _, c := range valAttackerState.known {
			switch c.kind {
			case "constant":
				cc := sanityResolveConstant(c.constant, valPrincipalState)
				switch cc.kind {
				case "constant":
					if gOrNil {
						return v.constant, replacements, false
					}
					if sanityExactSameValueInValues(cc, replacements) < 0 {
						replacements = append(replacements, cc)
					}
				}
			}
		}
	case "primitive":
		replacements = append(replacements, a)
		if stage < 2 {
			return v.constant, replacements, true
		}
		includeHashes := (stage > 2)
		injectants := inject(
			a.primitive, a.primitive, true, rootIndex,
			valPrincipalState, valAttackerState, includeHashes,
		)
		for _, aa := range injectants {
			if sanityExactSameValueInValues(aa, replacements) < 0 {
				replacements = append(replacements, aa)
			}
		}
	case "equation":
		replacements = append(replacements, a)
		replacements = append(replacements, constantGN)
	}
	return v.constant, replacements, true
}

func replacementMapNext(valReplacementMap replacementMap) replacementMap {
	if len(valReplacementMap.combination) == 0 {
		valReplacementMap.outOfReplacements = true
		return valReplacementMap
	}
	for i := 0; i < len(valReplacementMap.combination); i++ {
		valReplacementMap.combination[i] = valReplacementMap.replacements[i][valReplacementMap.depthIndex[i]]
		if i != len(valReplacementMap.combination)-1 {
			continue
		}
		valReplacementMap.depthIndex[i] = valReplacementMap.depthIndex[i] + 1
		valReplacementMap.lastIncrement = i
		for ii := i; ii >= 0; ii-- {
			if valReplacementMap.depthIndex[ii] == len(valReplacementMap.replacements[ii]) {
				if ii > 0 {
					valReplacementMap.depthIndex[ii] = 0
					valReplacementMap.depthIndex[ii-1] = valReplacementMap.depthIndex[ii-1] + 1
					valReplacementMap.lastIncrement = ii - 1
				} else {
					valReplacementMap.outOfReplacements = true
					break
				}
			}
		}
	}
	return valReplacementMap
}
