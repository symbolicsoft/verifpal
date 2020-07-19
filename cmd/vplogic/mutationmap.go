/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package vplogic

import (
	"fmt"
	"sync"
)

func mutationMapInit(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
	valAttackerState AttackerState, stage int,
) (MutationMap, error) {
	var mutationMapGroup sync.WaitGroup
	var mutationMapMutex sync.Mutex
	var err error
	valMutationMap := MutationMap{
		Initialized:    true,
		Constants:      []Constant{},
		Mutations:      [][]Value{},
		Combination:    []Value{},
		DepthIndex:     []int{},
		OutOfMutations: false,
	}
	InfoMessage(fmt.Sprintf(
		"Initializing Stage %d mutation map for %s...", stage, valPrincipalState.Name,
	), "analysis", false)
	for _, v := range valAttackerState.Known {
		mutationMapGroup.Add(1)
		go func(v Value, valKnowledgeMap KnowledgeMap,
			valPrincipalState PrincipalState, valAttackerState AttackerState,
		) {
			switch v.Kind {
			case "primitive":
				mutationMapGroup.Done()
				return
			case "equation":
				mutationMapGroup.Done()
				return
			}
			a, i := valueResolveConstant(v.Constant, valPrincipalState)
			if mutationMapSkipValue(v, i, valKnowledgeMap, valPrincipalState, valAttackerState) {
				mutationMapGroup.Done()
				return
			}
			var c Constant
			var r []Value
			c, r, err = mutationMapReplaceValue(
				a, v, i, stage, valPrincipalState, valAttackerState,
			)
			if err != nil {
				mutationMapGroup.Done()
				return
			}
			if len(r) == 0 {
				mutationMapGroup.Done()
				return
			}
			mutationMapMutex.Lock()
			valMutationMap.Constants = append(valMutationMap.Constants, c)
			valMutationMap.Mutations = append(valMutationMap.Mutations, r)
			mutationMapMutex.Unlock()
			mutationMapGroup.Done()
		}(v, valKnowledgeMap, valPrincipalState, valAttackerState)
	}
	mutationMapGroup.Wait()
	valMutationMap.Combination = make([]Value, len(valMutationMap.Constants))
	valMutationMap.DepthIndex = make([]int, len(valMutationMap.Constants))
	for iiii := range valMutationMap.Constants {
		valMutationMap.DepthIndex[iiii] = 0
	}
	return valMutationMap, err
}

func mutationMapSkipValue(
	v Value, i int, valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState, valAttackerState AttackerState,
) bool {
	switch {
	case i < 0:
		return true
	case !strInSlice(valPrincipalState.Name, valPrincipalState.Wire[i]):
		return true
	case valPrincipalState.Guard[i]:
		if !strInSlice(valPrincipalState.Sender[i], valPrincipalState.MutatableTo[i]) {
			return true
		}
	case valPrincipalState.Creator[i] == valPrincipalState.Name:
		return true
	case !valPrincipalState.Known[i]:
		return true
	case !valueConstantIsUsedByPrincipalInKnowledgeMap(valKnowledgeMap, valPrincipalState.Name, v.Constant):
		return true
	case !intInSlice(valAttackerState.CurrentPhase, valPrincipalState.Phase[i]):
		return true
	}
	return false
}

func mutationMapReplaceValue(
	a Value, v Value, rootIndex int, stage int,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) (Constant, []Value, error) {
	switch a.Kind {
	case "constant":
		return v.Constant, mutationMapReplaceConstant(
			a, rootIndex, stage, valPrincipalState, valAttackerState,
		), nil
	case "primitive":
		p, err := mutationMapReplacePrimitive(
			a, rootIndex, stage, valPrincipalState, valAttackerState,
		)
		return v.Constant, p, err
	case "equation":
		return v.Constant, mutationMapReplaceEquation(
			a, stage, valAttackerState,
		), nil
	}
	return v.Constant, []Value{}, nil
}

func mutationMapReplaceConstant(
	a Value, rootIndex int, stage int, valPrincipalState PrincipalState, valAttackerState AttackerState,
) []Value {
	mutations := []Value{}
	if valueIsGOrNil(a.Constant) {
		return mutations
	}
	mutations = append(mutations, valueN)
	if stage <= 3 {
		return mutations
	}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case "constant":
			if valueIsGOrNil(v.Constant) {
				continue
			}
			c, i := valueResolveConstant(v.Constant, valPrincipalState)
			switch c.Kind {
			case "constant":
				if valPrincipalState.DeclaredAt[rootIndex] > valPrincipalState.DeclaredAt[i] {
					continue
				}
				if valueEquivalentValueInValues(c, mutations) < 0 {
					mutations = append(mutations, c)
				}
			}
		}
	}
	return mutations
}

func mutationMapReplacePrimitive(
	a Value, rootIndex int, stage int,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) ([]Value, error) {
	var err error
	mutations := []Value{}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case "primitive":
			a, err = valueResolveValueInternalValuesFromPrincipalState(
				a, a, rootIndex, valPrincipalState, valAttackerState, false, 0,
			)
			if err != nil {
				return []Value{}, err
			}
			if !injectMatchSkeletons(v.Primitive, injectPrimitiveSkeleton(a.Primitive)) {
				continue
			}
			if valueEquivalentValueInValues(v, mutations) < 0 {
				mutations = append(mutations, v)
			}
		}
	}
	injectants := inject(
		a.Primitive, a.Primitive, true, 0,
		valPrincipalState, valAttackerState, stage,
	)
	uinjectants := []Value{}
	for _, a := range injectants {
		if valueEquivalentValueInValues(a, uinjectants) < 0 {
			uinjectants = append(uinjectants, a)
			mutations = append(mutations, a)
		}
	}
	return mutations, nil
}

func mutationMapReplaceEquation(a Value, stage int, valAttackerState AttackerState) []Value {
	mutations := []Value{}
	switch len(a.Equation.Values) {
	case 1:
		mutations = append(mutations, valueG)
	case 2:
		mutations = append(mutations, valueGN)
	case 3:
		mutations = append(mutations, valueGNN)
	}
	if stage <= 3 {
		return mutations
	}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case "equation":
			switch len(v.Equation.Values) {
			case len(a.Equation.Values):
				if valueEquivalentValueInValues(v, mutations) < 0 {
					mutations = append(mutations, v)
				}
			}
		}
	}
	return mutations
}

func mutationMapNext(valMutationMap MutationMap) MutationMap {
	if len(valMutationMap.Combination) == 0 {
		valMutationMap.OutOfMutations = true
		return valMutationMap
	}
	for i := 0; i < len(valMutationMap.Combination); i++ {
		valMutationMap.Combination[i] = valMutationMap.Mutations[i][valMutationMap.DepthIndex[i]]
		if i != len(valMutationMap.Combination)-1 {
			continue
		}
		valMutationMap.DepthIndex[i] = valMutationMap.DepthIndex[i] + 1
		valMutationMap.LastIncrement = i
		for ii := i; ii >= 0; ii-- {
			if valMutationMap.DepthIndex[ii] != len(valMutationMap.Mutations[ii]) {
				continue
			}
			if ii <= 0 {
				valMutationMap.OutOfMutations = true
				break
			}
			valMutationMap.DepthIndex[ii] = 0
			valMutationMap.DepthIndex[ii-1] = valMutationMap.DepthIndex[ii-1] + 1
			valMutationMap.LastIncrement = ii - 1
		}
	}
	return valMutationMap
}
