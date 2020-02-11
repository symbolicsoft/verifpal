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
	for _, v := range valAttackerState.known {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, v.constant)
		if replacementMapSkipValue(v, i, valPrincipalState, valAttackerState) {
			continue
		}
		a := valPrincipalState.assigned[i]
		replacementsGroup.Add(1)
		go func(v value) {
			c, r := replacementMapReplaceValue(
				a, v, i, stage,
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
	v value, i int, valPrincipalState principalState, valAttackerState attackerState,
) bool {
	switch v.kind {
	case "primitive":
		return true
	case "equation":
		return true
	}
	switch {
	case !strInSlice(valPrincipalState.name, valPrincipalState.wire[i]):
		return true
	case valPrincipalState.guard[i]:
		if !strInSlice(valPrincipalState.sender[i], valPrincipalState.mutatableTo[i]) {
			return true
		}
	case valPrincipalState.creator[i] == valPrincipalState.name:
		return true
	case !valPrincipalState.known[i]:
		return true
	case !intInSlice(valAttackerState.currentPhase, valPrincipalState.phase[i]):
		return true
	}
	return false
}

func replacementMapReplaceValue(
	a value, v value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) (constant, []value) {
	switch a.kind {
	case "constant":
		return v.constant, replacementMapReplaceConstant(
			a, stage, valPrincipalState, valAttackerState,
		)
	case "primitive":
		return v.constant, replacementMapReplacePrimitive(
			a, rootIndex, stage, valPrincipalState, valAttackerState,
		)
	case "equation":
		return v.constant, replacementMapReplaceEquation(a)
	}
	return v.constant, []value{}
}

func replacementMapReplaceConstant(
	a value, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) []value {
	replacements := []value{}
	if constantIsGOrNil(a.constant) {
		return replacements
	}
	replacements = append(replacements, constantN)
	if stage <= 3 {
		return replacements
	}
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
	return replacements
}

func replacementMapReplacePrimitive(
	a value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) []value {
	replacements := []value{}
	injectants := inject(
		a.primitive, a.primitive, true, rootIndex,
		valPrincipalState, valAttackerState, stage,
	)
	for _, aa := range injectants {
		if sanityExactSameValueInValues(aa, replacements) < 0 {
			replacements = append(replacements, aa)
		}
	}
	return replacements
}

func replacementMapReplaceEquation(a value) []value {
	return []value{constantGN}
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
