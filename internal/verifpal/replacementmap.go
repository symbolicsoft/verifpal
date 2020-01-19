/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package verifpal

func replacementMapInit(valPrincipalState principalState, valAttackerState attackerState, stage int) replacementMap {
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
		a := valPrincipalState.assigned[ii]
		valReplacementMap = replacementMapReplaceValues(
			a, v, ii, stage,
			valPrincipalState, valAttackerState, valReplacementMap,
		)
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for iiii := range valReplacementMap.constants {
		valReplacementMap.depthIndex[iiii] = 0
	}
	return valReplacementMap
}

func replacementMapReplaceValues(
	a value, v value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState, valReplacementMap replacementMap,
) replacementMap {
	switch a.kind {
	case "constant":
		if (a.constant.name == "g") || (a.constant.name == "nil") {
			return valReplacementMap
		}
		replacements := []value{a, constantN}
		for _, v := range valAttackerState.known {
			switch v.kind {
			case "constant":
				if sanityExactSameValueInValues(v, replacements) < 0 {
					replacements = append(replacements, v)
				}
			}
		}
		valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
		valReplacementMap.replacements = append(valReplacementMap.replacements, replacements)
	case "primitive":
		valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
		valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
		if stage < 2 {
			return valReplacementMap
		}
		l := len(valReplacementMap.replacements) - 1
		includeHashes := (stage > 2)
		injectants := inject(a.primitive, a.primitive, true, rootIndex, valPrincipalState, includeHashes)
		for _, aa := range injectants {
			if sanityExactSameValueInValues(aa, valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			}
		}
	case "equation":
		replacements := []value{a, constantGN}
		valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
		valReplacementMap.replacements = append(valReplacementMap.replacements, replacements)
	}
	return valReplacementMap
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
