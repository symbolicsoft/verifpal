/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package verifpal

import (
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
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, v.constant)
		if replacementMapSkipValue(v, i, ii, valPrincipalState, valAttackerState) {
			continue
		}
		a := valPrincipalState.assigned[ii]
		replacementsGroup.Add(1)
		go func(v value) {
			c, r := replacementMapReplaceValue(
				a, v, ii, stage,
				valPrincipalState, valAttackerState,
			)
			if len(r) == 0 {
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

func replacementMapSkipValue(
	v value, i int, ii int, valPrincipalState principalState, valAttackerState attackerState,
) bool {
	switch v.kind {
	case "primitive":
		return true
	case "equation":
		return true
	}
	switch {
	case !valAttackerState.wire[i]:
		return true
	case !strInSlice(valPrincipalState.name, valPrincipalState.wire[ii]):
		return true
	case valPrincipalState.guard[ii]:
		iii := sanityGetAttackerStateIndexFromConstant(
			valAttackerState, v.constant,
		)
		mutatedTo := strInSlice(
			valPrincipalState.sender[ii],
			valAttackerState.mutatedTo[iii],
		)
		if iii < 0 || !mutatedTo {
			return true
		}
	case valPrincipalState.creator[ii] == valPrincipalState.name:
		return true
	case !valPrincipalState.known[ii]:
		return true
	case !intInSlice(valAttackerState.currentPhase, valPrincipalState.phase[ii]):
		return true
	}
	return false
}

func replacementMapReplaceValue(
	a value, v value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) (constant, []value) {
	replacements := []value{}
	switch a.kind {
	case "constant":
		if constantIsGOrNil(a.constant) {
			return v.constant, replacements
		}
		replacements = append(replacements, a)
		replacements = append(replacements, constantN)
		for _, c := range valAttackerState.known {
			switch c.kind {
			case "constant":
				if constantIsGOrNil(c.constant) {
					continue
				}
				cc := sanityResolveConstant(c.constant, valPrincipalState)
				switch cc.kind {
				case "constant":
					if sanityExactSameValueInValues(cc, replacements) < 0 {
						replacements = append(replacements, cc)
					}
				}
			}
		}
	case "primitive":
		replacements = append(replacements, a)
		injectants := inject(
			a.primitive, a.primitive, true, rootIndex,
			valPrincipalState, valAttackerState, stage,
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
	return v.constant, replacements
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
