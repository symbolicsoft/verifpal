/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package verifpal

import (
	"fmt"
	"os"
)

func verifyActive(
	m *model,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
) []verifyResult {
	var verifyResults []verifyResult
	analysis := 0
	stage := 0
	valAttackerState := constructAttackerState(true, m, valKnowledgeMap, true)
	prettyMessage("attacker is configured as active", 0, 0, "info")
	for stage <= 3 {
		switch stage {
		case 0:
			analysis, stage = verifyActiveStage0(
				m, valKnowledgeMap, valPrincipalStates,
				&verifyResults, valAttackerState,
				analysis, stage,
			)
		default:
			analysis, stage = verifyActiveStage123(
				m, valKnowledgeMap, valPrincipalStates,
				&verifyResults, valAttackerState,
				analysis, stage,
			)
		}
	}
	return verifyResults
}

func verifyActiveStage0(
	m *model,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
	verifyResults *[]verifyResult, valAttackerState *attackerState,
	analysis int, stage int,
) (int, int) {
	for _, valPrincipalState := range valPrincipalStates {
		valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
		valPrincipalStateClone = sanityResolveAllPrincipalStateValues(valPrincipalStateClone, valKnowledgeMap)
		failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStateClone)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalStateClone.assigned {
			sanityCheckEquationGenerators(valPrincipalStateClone.assigned[i], valPrincipalStateClone)
		}
		verifyAnalysis(m, valPrincipalStateClone, valAttackerState, analysis, 0)
		prettyAnalysis(analysis, stage)
	}
	stage = verifyActiveIncrementStage(stage)
	return analysis, stage
}

func verifyActiveStage123(
	m *model,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
	verifyResults *[]verifyResult, valAttackerState *attackerState,
	analysis int, stage int,
) (int, int) {
	for _, valPrincipalState := range valPrincipalStates {
		analysis = verifyActiveIncrementAnalysis(analysis)
		valReplacementMap := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, 0)
		analysis, stage = verifyActiveScanCombination(m,
			valPrincipalState, valKnowledgeMap, valAttackerState, &valReplacementMap,
			verifyResults, true, analysis, stage,
		)
	}
	stage = verifyActiveIncrementStage(stage)
	return analysis, stage
}

func verifyActiveIncrementAnalysis(analysis int) int {
	return analysis + 1
}

func verifyActiveIncrementStage(stage int) int {
	return stage + 1
}

func verifyActiveScanCombination(
	m *model,
	valPrincipalState *principalState, valKnowledgeMap *knowledgeMap,
	valAttackerState *attackerState, valReplacementMap *replacementMap,
	verifyResults *[]verifyResult, newStage bool, analysis int, stage int,
) (int, int) {
	var lastReplacement bool
	var valPrincipalStateWithReplacements *principalState
	attackerKnown := len(valAttackerState.known)
	lastReplacement = valReplacementMap.combinationNext()
	valPrincipalStateWithReplacements, _ = verifyActiveMutatePrincipalState(valPrincipalState, valKnowledgeMap, valAttackerState, valReplacementMap)
	verifyAnalysis(m, valPrincipalStateWithReplacements, valAttackerState, analysis, 0)
	verifyResolveQueries(m,
		valKnowledgeMap, valPrincipalStateWithReplacements, valAttackerState,
		verifyResults, analysis,
	)
	valAttackerState = verifyActiveClearFreshValues(m, valKnowledgeMap, valAttackerState)
	analysis = verifyActiveIncrementAnalysis(analysis)
	prettyAnalysis(analysis, stage)
	if len(*verifyResults) == len(m.queries) {
		return analysis, stage
	}
	if (len(valAttackerState.known) > attackerKnown) || newStage {
		valReplacementMapUpdate := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, stage)
		return verifyActiveScanCombination(m,
			valPrincipalState, valKnowledgeMap, valAttackerState, &valReplacementMapUpdate,
			verifyResults, false, analysis, stage,
		)
	}
	if !lastReplacement {
		return verifyActiveScanCombination(m,
			valPrincipalState, valKnowledgeMap, valAttackerState, valReplacementMap,
			verifyResults, false, analysis, stage,
		)
	}
	return analysis, stage
}

func verifyActiveClearFreshValues(m *model, valKnowledgeMap *knowledgeMap, valAttackerState *attackerState) *attackerState {
	valAttackerStateCleared := attackerState{
		active:      valAttackerState.active,
		known:       []value{},
		wire:        []bool{},
		conceivable: valAttackerState.conceivable,
		mutatedTo:   [][]string{},
	}
	for i, a := range valAttackerState.known {
		if !verifyActiveValueHasFreshValues(valKnowledgeMap, a) {
			if sanityExactSameValueInValues(a, &valAttackerStateCleared.known) < 0 {
				valAttackerStateCleared.known = append(valAttackerStateCleared.known, valAttackerState.known[i])
				valAttackerStateCleared.wire = append(valAttackerStateCleared.wire, valAttackerState.wire[i])
				valAttackerStateCleared.mutatedTo = append(valAttackerStateCleared.mutatedTo, valAttackerState.mutatedTo[i])
			}
		}
	}
	constructAttackerStatePopulate(m, valKnowledgeMap, &valAttackerStateCleared, false)
	return &valAttackerStateCleared
}

func verifyActiveValueHasFreshValues(valKnowledgeMap *knowledgeMap, a value) bool {
	aa := a
	switch a.kind {
	case "constant":
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.constant)
		aa = valKnowledgeMap.assigned[i]
	}
	switch aa.kind {
	case "constant":
		if aa.constant.fresh {
			return true
		}
	case "primitive":
		for _, aaa := range aa.primitive.arguments {
			if verifyActiveValueHasFreshValues(valKnowledgeMap, aaa) {
				return true
			}
		}
	case "equation":
		for _, aaa := range aa.equation.values {
			if verifyActiveValueHasFreshValues(valKnowledgeMap, aaa) {
				return true
			}
		}
	}
	return false
}

func verifyActiveInitReplacementMap(valPrincipalState *principalState, valAttackerState *attackerState, stage int) replacementMap {
	valReplacementMap := replacementMap{
		constants:    []constant{},
		replacements: [][]value{},
		combination:  []value{},
		depthIndex:   []int{},
	}
	n := value{
		kind: "constant",
		constant: constant{
			name:        "nil",
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "public",
		},
	}
	g := value{
		kind: "constant",
		constant: constant{
			name:        "g",
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "public",
		},
	}
	gn := value{
		kind: "equation",
		equation: equation{
			values: []value{g, n},
		},
	}
	for i, v := range valAttackerState.known {
		if !valAttackerState.wire[i] || v.kind != "constant" {
			continue
		}
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, v.constant)
		iii := sanityGetAttackerStateIndexFromConstant(valAttackerState, v.constant)
		mutatedTo := strInSlice(valPrincipalState.sender[ii], valAttackerState.mutatedTo[iii])
		unassailable := false
		if valPrincipalState.guard[ii] {
			unassailable = true
			if iii >= 0 && mutatedTo {
				unassailable = false
			}
		}
		if unassailable {
			continue
		}
		if valPrincipalState.creator[ii] == valPrincipalState.name {
			continue
		}
		if !valPrincipalState.known[ii] {
			continue
		}
		a := valPrincipalState.assigned[ii]
		switch a.kind {
		case "constant":
			if a.constant.name == "g" {
				continue
			}
			if a.constant.name == "nil" {
				continue
			}
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a, n})
		case "primitive":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			if stage < 2 {
				continue
			}
			l := len(valReplacementMap.replacements) - 1
			injectants := inject(a.primitive, true, ii, valPrincipalState, valAttackerState, (stage > 2))
			for _, aa := range *injectants {
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
			}
		case "equation":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a, gn})
		}
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for iiii := range valReplacementMap.constants {
		valReplacementMap.depthIndex[iiii] = 0
	}
	return valReplacementMap
}

func verifyActiveMutatePrincipalState(
	valPrincipalState *principalState, valKnowledgeMap *knowledgeMap,
	valAttackerState *attackerState, valReplacementMap *replacementMap,
) (*principalState, bool) {
	isWorthwhileMutation := false
	valPrincipalStateWithReplacements := constructPrincipalStateClone(valPrincipalState)
	for i, c := range valReplacementMap.constants {
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalStateWithReplacements, c)
		iii := sanityGetAttackerStateIndexFromConstant(valAttackerState, c)
		ac := valReplacementMap.combination[i]
		ar := valPrincipalStateWithReplacements.assigned[ii]
		switch ar.kind {
		case "primitive":
			ac.primitive.output = ar.primitive.output
			ac.primitive.check = ar.primitive.check
		}
		if sanityEquivalentValues(ar, ac, valPrincipalState) {
			continue
		}
		valPrincipalStateWithReplacements.creator[ii] = "Attacker"
		valPrincipalStateWithReplacements.sender[ii] = "Attacker"
		valPrincipalStateWithReplacements.wasMutated[ii] = true
		valPrincipalStateWithReplacements.assigned[ii] = ac
		valPrincipalStateWithReplacements.beforeRewrite[ii] = ac
		if !strInSlice(valPrincipalState.name, valAttackerState.mutatedTo[iii]) {
			valAttackerState.mutatedTo[iii] = append(valAttackerState.mutatedTo[iii], valPrincipalState.name)
		}
		if i >= valReplacementMap.lastIncrement {
			isWorthwhileMutation = true
		}
	}
	valPrincipalStateWithReplacements = sanityResolveAllPrincipalStateValues(valPrincipalStateWithReplacements, valKnowledgeMap)
	t1 := sanityGetPrincipalStateIndexFromConstant(valPrincipalStateWithReplacements, constant{
		name: "m2",
	})
	if prettyValue(valPrincipalStateWithReplacements.assigned[t1]) == "G^nil" {
		fmt.Fprintln(os.Stdout, valPrincipalStateWithReplacements.name)
		for i, x := range valPrincipalStateWithReplacements.constants {
			fmt.Fprintln(os.Stdout, x.name+": "+prettyValue(valPrincipalStateWithReplacements.assigned[i]))
		}
		fmt.Fprintln(os.Stdout, "")
	}
	failedRewrites, failedRewriteIndices := sanityPerformAllRewrites(valPrincipalStateWithReplacements)
	for i, p := range failedRewrites {
		if !p.check {
			continue
		}
		verifyActiveDropPrincipalStateAfterIndex(valPrincipalStateWithReplacements, failedRewriteIndices[i]+1)
		break
	}
	return valPrincipalStateWithReplacements, isWorthwhileMutation
}

func verifyActiveDropPrincipalStateAfterIndex(valPrincipalState *principalState, f int) {
	valPrincipalState.constants = valPrincipalState.constants[:f]
	valPrincipalState.assigned = valPrincipalState.assigned[:f]
	valPrincipalState.guard = valPrincipalState.guard[:f]
	valPrincipalState.known = valPrincipalState.known[:f]
	valPrincipalState.creator = valPrincipalState.creator[:f]
	valPrincipalState.sender = valPrincipalState.sender[:f]
	valPrincipalState.wasRewritten = valPrincipalState.wasRewritten[:f]
	valPrincipalState.beforeRewrite = valPrincipalState.beforeRewrite[:f]
	valPrincipalState.wasMutated = valPrincipalState.wasMutated[:f]
	valPrincipalState.beforeMutate = valPrincipalState.beforeMutate[:f]
}
