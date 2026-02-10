/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package vplogic

import (
	"fmt"
)

func mutationMapInit(
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, stage int,
) (MutationMap, error) {
	var err error
	valMutationMap := MutationMap{
		Initialized:    true,
		OutOfMutations: false,
		Constants:      []*Constant{},
		Mutations:      [][]*Value{},
		Combination:    []*Value{},
		DepthIndex:     []int{},
	}
	InfoMessage(fmt.Sprintf(
		"Initializing Stage %d mutation map for %s...", stage, valPrincipalState.Name,
	), "analysis", false)
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case typesEnumPrimitive:
			continue
		case typesEnumEquation:
			continue
		}
		a, i := valueResolveConstant(v.Data.(*Constant), valPrincipalState, true)
		if mutationMapSkipValue(v, i, valKnowledgeMap, valPrincipalState, valAttackerState) {
			continue
		}
		var r []*Value
		r, err = mutationMapReplaceValue(a, i, stage, valPrincipalState, valAttackerState)
		if err != nil {
			return MutationMap{}, err
		}
		if len(r) == 0 {
			continue
		}
		valMutationMap.Constants = append(valMutationMap.Constants, v.Data.(*Constant))
		valMutationMap.Mutations = append(valMutationMap.Mutations, r)
	}
	valMutationMap.Combination = make([]*Value, len(valMutationMap.Constants))
	valMutationMap.DepthIndex = make([]int, len(valMutationMap.Constants)) // Go initializes to zero
	if len(valMutationMap.Constants) > 0 {
		mutSizes := make([]int, len(valMutationMap.Constants))
		for i := range valMutationMap.Constants {
			mutSizes[i] = len(valMutationMap.Mutations[i])
		}
		InfoMessage(fmt.Sprintf(
			"Mutation map for %s at stage %d: %d constants, mutations: %v",
			valPrincipalState.Name, stage, len(valMutationMap.Constants), mutSizes,
		), "analysis", false)
	}
	return valMutationMap, err
}

func mutationMapSkipValue(
	v *Value, i int, valKnowledgeMap *KnowledgeMap,
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
) bool {
	switch {
	case i < 0:
		return true
	case valPrincipalState.Guard[i]:
		if !principalEnumInSlice(valPrincipalState.Sender[i], valPrincipalState.MutatableTo[i]) {
			return true
		}
	case valPrincipalState.Creator[i] == valPrincipalState.ID:
		return true
	case !intInSlice(valAttackerState.CurrentPhase, valPrincipalState.Phase[i]):
		return true
	case !valueConstantIsUsedByPrincipalInKnowledgeMap(valKnowledgeMap, valPrincipalState.ID, v.Data.(*Constant)):
		return true
	}
	return false
}

func mutationMapReplaceValue(
	a *Value, rootIndex int, stage int,
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
) ([]*Value, error) {
	a, err := valueResolveValueInternalValuesFromPrincipalState(
		a, a, rootIndex, valPrincipalState, valAttackerState, false,
	)
	if err != nil {
		return []*Value{}, err
	}
	switch a.Kind {
	case typesEnumConstant:
		return mutationMapReplaceConstant(
			a, stage, valPrincipalState, valAttackerState,
		), nil
	case typesEnumPrimitive:
		p := mutationMapReplacePrimitive(
			a, stage, valPrincipalState, valAttackerState,
		)
		return p, err
	case typesEnumEquation:
		return mutationMapReplaceEquation(
			a, stage, valAttackerState,
		), nil
	}
	return []*Value{}, fmt.Errorf("invalid value kind")
}

func mutationMapReplaceConstant(
	a *Value, stage int,
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
) []*Value {
	mutations := []*Value{}
	if valueIsGOrNil(a.Data.(*Constant)) {
		return mutations
	}
	mutations = append(mutations, valueNil)
	if stage <= stageMutationExpansion {
		return mutations
	}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case typesEnumConstant:
			if valueIsGOrNil(v.Data.(*Constant)) {
				continue
			}
			c, _ := valueResolveConstant(v.Data.(*Constant), valPrincipalState, true)
			switch c.Kind {
			case typesEnumConstant:
				if valueEquivalentValueInValues(c, mutations) < 0 {
					mutations = append(mutations, c)
				}
			}
		}
	}
	return mutations
}

func mutationMapReplacePrimitive(
	a *Value, stage int,
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
) []*Value {
	mutations := []*Value{}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case typesEnumConstant:
			if valueIsGOrNil(v.Data.(*Constant)) {
				continue
			}
			c, _ := valueResolveConstant(v.Data.(*Constant), valPrincipalState, true)
			switch c.Kind {
			case typesEnumConstant:
				if valueEquivalentValueInValues(c, mutations) < 0 {
					mutations = append(mutations, c)
				}
			}
		case typesEnumPrimitive:
			if !injectSkeletonNotDeeper(v.Data.(*Primitive), a.Data.(*Primitive)) {
				continue
			}
			if valueEquivalentValueInValues(v, mutations) < 0 {
				mutations = append(mutations, v)
			}
		}
	}
	injectants := inject(
		a.Data.(*Primitive), 0,
		valPrincipalState, valAttackerState, stage,
	)
	uinjectants := []*Value{}
	for _, a := range injectants {
		if valueEquivalentValueInValues(a, uinjectants) < 0 {
			uinjectants = append(uinjectants, a)
			mutations = append(mutations, a)
		}
	}
	return mutations
}

func mutationMapReplaceEquation(
	a *Value, stage int, valAttackerState AttackerState,
) []*Value {
	mutations := []*Value{}
	switch len(a.Data.(*Equation).Values) {
	case 1:
		mutations = append(mutations, valueG)
	case 2:
		mutations = append(mutations, valueGNil)
	case 3:
		mutations = append(mutations, valueGNilNil)
	}
	if stage <= stageMutationExpansion {
		return mutations
	}
	for _, v := range valAttackerState.Known {
		switch v.Kind {
		case typesEnumEquation:
			switch len(v.Data.(*Equation).Values) {
			case len(a.Data.(*Equation).Values):
				if valueEquivalentValueInValues(v, mutations) < 0 {
					mutations = append(mutations, v)
				}
			}
		}
	}
	return mutations
}

func mutationMapSubset(fullMap MutationMap, indices []int) MutationMap {
	subMap := MutationMap{
		Initialized:    true,
		OutOfMutations: false,
		Constants:      make([]*Constant, len(indices)),
		Mutations:      make([][]*Value, len(indices)),
		Combination:    make([]*Value, len(indices)),
		DepthIndex:     make([]int, len(indices)),
	}
	for i, idx := range indices {
		subMap.Constants[i] = fullMap.Constants[idx]
		subMap.Mutations[i] = fullMap.Mutations[idx]
	}
	return subMap
}

func mutationMapSubsetCapped(fullMap MutationMap, indices []int, maxProduct int) MutationMap {
	subMap := mutationMapSubset(fullMap, indices)
	// Truncate mutation lists so their product stays under maxProduct.
	// Distribute the budget evenly across dimensions.
	n := len(indices)
	if n == 0 {
		return subMap
	}
	product := 1
	overflow := false
	for i := 0; i < n; i++ {
		m := len(subMap.Mutations[i])
		if m > 0 && product > maxProduct/m {
			overflow = true
			break
		}
		product *= m
	}
	if !overflow && product <= maxProduct {
		return subMap
	}
	// Compute per-dimension cap: nth root of maxProduct
	perDim := maxProduct
	for i := 1; i < n; i++ {
		// Approximate nth root by repeated sqrt-like division
		perDim = intNthRoot(maxProduct, n)
	}
	if perDim < 1 {
		perDim = 1
	}
	for i := 0; i < n; i++ {
		if len(subMap.Mutations[i]) > perDim {
			subMap.Mutations[i] = subMap.Mutations[i][:perDim]
		}
	}
	return subMap
}

func intNthRoot(val int, n int) int {
	if n <= 1 || val <= 1 {
		return val
	}
	// Binary search for integer nth root
	lo, hi := 1, val
	for lo < hi {
		mid := lo + (hi-lo)/2
		// Check if mid^n > val
		power := 1
		overflow := false
		for i := 0; i < n; i++ {
			if power > val/mid {
				overflow = true
				break
			}
			power *= mid
		}
		if overflow || power > val {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo - 1
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
		}
	}
	return valMutationMap
}
