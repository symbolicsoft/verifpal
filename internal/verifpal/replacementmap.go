/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package verifpal

func replacementMapInit(
	valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState, stage int,
) replacementMap {
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
		if replacementMapSkipValue(v, i, valKnowledgeMap, valPrincipalState, valAttackerState) {
			continue
		}
		a := valPrincipalState.beforeMutate[i]
		c, r := replacementMapReplaceValue(
			a, v, i, stage,
			valPrincipalState, valAttackerState,
		)
		if len(r) == 0 {
			continue
		}
		valReplacementMap.constants = append(valReplacementMap.constants, c)
		valReplacementMap.replacements = append(valReplacementMap.replacements, r)
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for iiii := range valReplacementMap.constants {
		valReplacementMap.depthIndex[iiii] = 0
	}
	return valReplacementMap
}

func replacementMapSkipValue(
	v value, i int, valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState,
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
	case !sanityConstantIsUsedByPrincipalInKnowledgeMap(valKnowledgeMap, valPrincipalState.name, v.constant):
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
		return v.constant, replacementMapReplaceEquation(
			a, stage, valAttackerState,
		)
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
	for _, v := range valAttackerState.known {
		switch v.kind {
		case "constant":
			if constantIsGOrNil(v.constant) {
				continue
			}
			c := sanityResolveConstant(v.constant, valPrincipalState)
			switch c.kind {
			case "constant":
				if sanityEquivalentValueInValues(c, replacements) < 0 {
					replacements = append(replacements, c)
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
	for _, v := range valAttackerState.known {
		switch v.kind {
		case "primitive":
			a = sanityResolveValueInternalValuesFromPrincipalState(
				a, a, rootIndex, valPrincipalState, valAttackerState, false,
			)
			if sanityEquivalentValues(a, v) {
				continue
			}
			if !injectMatchSkeletons(v.primitive, injectPrimitiveSkeleton(a.primitive)) {
				continue
			}
			if sanityEquivalentValueInValues(v, replacements) < 0 {
				replacements = append(replacements, v)
			}
		}
	}
	injectants := inject(
		a.primitive, a.primitive, true,
		valPrincipalState, valAttackerState, stage,
	)
	for _, aa := range injectants {
		if sanityEquivalentValueInValues(aa, replacements) < 0 {
			replacements = append(replacements, aa)
		}
	}
	return replacements
}

func replacementMapReplaceEquation(a value, stage int, valAttackerState attackerState) []value {
	replacements := []value{}
	if stage <= 3 {
		return []value{constantGN}
	}
	for _, v := range valAttackerState.known {
		switch v.kind {
		case "equation":
			switch len(v.equation.values) {
			case len(a.equation.values):
				if sanityEquivalentValueInValues(v, replacements) < 0 {
					replacements = append(replacements, v)
				}
			}
		}
	}
	return replacements
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
			if valReplacementMap.depthIndex[ii] != len(valReplacementMap.replacements[ii]) {
				continue
			}
			if ii <= 0 {
				valReplacementMap.outOfReplacements = true
				break
			}
			valReplacementMap.depthIndex[ii] = 0
			valReplacementMap.depthIndex[ii-1] = valReplacementMap.depthIndex[ii-1] + 1
			valReplacementMap.lastIncrement = ii - 1
		}
	}
	return valReplacementMap
}
