/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package verifpal

func mutationMapInit(
	valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState, stage int,
) MutationMap {
	valMutationMap := MutationMap{
		initialized:    true,
		constants:      []constant{},
		mutations:      [][]value{},
		combination:    []value{},
		depthIndex:     []int{},
		outOfMutations: false,
	}
	for _, v := range valAttackerState.known {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, v.constant)
		if mutationMapSkipValue(v, i, valKnowledgeMap, valPrincipalState, valAttackerState) {
			continue
		}
		a := valPrincipalState.beforeMutate[i]
		c, r := mutationMapReplaceValue(
			a, v, i, stage,
			valPrincipalState, valAttackerState,
		)
		if len(r) == 0 {
			continue
		}
		valMutationMap.constants = append(valMutationMap.constants, c)
		valMutationMap.mutations = append(valMutationMap.mutations, r)
	}
	valMutationMap.combination = make([]value, len(valMutationMap.constants))
	valMutationMap.depthIndex = make([]int, len(valMutationMap.constants))
	for iiii := range valMutationMap.constants {
		valMutationMap.depthIndex[iiii] = 0
	}
	return valMutationMap
}

func mutationMapSkipValue(
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

func mutationMapReplaceValue(
	a value, v value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) (constant, []value) {
	switch a.kind {
	case "constant":
		return v.constant, mutationMapReplaceConstant(
			a, stage, valPrincipalState, valAttackerState,
		)
	case "primitive":
		return v.constant, mutationMapReplacePrimitive(
			a, rootIndex, stage, valPrincipalState, valAttackerState,
		)
	case "equation":
		return v.constant, mutationMapReplaceEquation(
			a, stage, valAttackerState,
		)
	}
	return v.constant, []value{}
}

func mutationMapReplaceConstant(
	a value, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) []value {
	mutations := []value{}
	if constantIsGOrNil(a.constant) {
		return mutations
	}
	mutations = append(mutations, constantN)
	if stage <= 3 {
		return mutations
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
				if sanityEquivalentValueInValues(c, mutations) < 0 {
					mutations = append(mutations, c)
				}
			}
		}
	}
	return mutations
}

func mutationMapReplacePrimitive(
	a value, rootIndex int, stage int,
	valPrincipalState principalState, valAttackerState attackerState,
) []value {
	mutations := []value{}
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
			if sanityEquivalentValueInValues(v, mutations) < 0 {
				mutations = append(mutations, v)
			}
		}
	}
	injectants := inject(
		a.primitive, a.primitive, true,
		valPrincipalState, valAttackerState, stage,
	)
	for _, aa := range injectants {
		if sanityEquivalentValueInValues(aa, mutations) < 0 {
			mutations = append(mutations, aa)
		}
	}
	return mutations
}

func mutationMapReplaceEquation(a value, stage int, valAttackerState attackerState) []value {
	mutations := []value{}
	if stage <= 3 {
		return []value{constantGN}
	}
	for _, v := range valAttackerState.known {
		switch v.kind {
		case "equation":
			switch len(v.equation.values) {
			case len(a.equation.values):
				if sanityEquivalentValueInValues(v, mutations) < 0 {
					mutations = append(mutations, v)
				}
			}
		}
	}
	return mutations
}

func mutationMapNext(valMutationMap MutationMap) MutationMap {
	if len(valMutationMap.combination) == 0 {
		valMutationMap.outOfMutations = true
		return valMutationMap
	}
	for i := 0; i < len(valMutationMap.combination); i++ {
		valMutationMap.combination[i] = valMutationMap.mutations[i][valMutationMap.depthIndex[i]]
		if i != len(valMutationMap.combination)-1 {
			continue
		}
		valMutationMap.depthIndex[i] = valMutationMap.depthIndex[i] + 1
		valMutationMap.lastIncrement = i
		for ii := i; ii >= 0; ii-- {
			if valMutationMap.depthIndex[ii] != len(valMutationMap.mutations[ii]) {
				continue
			}
			if ii <= 0 {
				valMutationMap.outOfMutations = true
				break
			}
			valMutationMap.depthIndex[ii] = 0
			valMutationMap.depthIndex[ii-1] = valMutationMap.depthIndex[ii-1] + 1
			valMutationMap.lastIncrement = ii - 1
		}
	}
	return valMutationMap
}
