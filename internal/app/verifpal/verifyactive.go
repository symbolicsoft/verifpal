/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package main

import (
	"fmt"
	"os"
)

func verifyActive(
	model *verifpal,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
) []verifyResult {
	var verifyResults []verifyResult
	analysis := 0
	stage := 0
	valAttackerState := constructAttackerState(true, model, valKnowledgeMap, true)
	prettyMessage("attacker is configured as active", 0, 0, "info")
	// attackerKnown := -1
	// for len(valAttackerState.known) > attackerKnown {
	// attackerKnown = len(valAttackerState.known)
	for stage < 3 {
		if stage == 0 {
			for _, valPrincipalState := range valPrincipalStates {
				valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
				sanityResolveAllPrincipalStateValues(valPrincipalStateClone, valKnowledgeMap)
				failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStateClone)
				sanityFailOnFailedRewrite(failedRewrites)
				for i := range valPrincipalStateClone.assigned {
					sanityCheckEquationGenerators(valPrincipalStateClone.assigned[i], valPrincipalStateClone)
				}
				verifyAnalysis(model, valPrincipalStateClone, valAttackerState, analysis, 0)
				if !mainDebug {
					prettyAnalysis(analysis, stage)
				}
			}
			stage = verifyActiveIncrementStage(stage)
			continue
		}
		if stage > 0 {
			for _, valPrincipalState := range valPrincipalStates {
				analysis = verifyActiveIncrementAnalysis(analysis)
				valReplacementMap := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, 0)
				analysis, stage = verifyActiveScanCombination(model,
					valPrincipalState, valKnowledgeMap, valAttackerState, &valReplacementMap,
					&verifyResults, true, analysis, stage,
				)
			}
			stage = verifyActiveIncrementStage(stage)
			continue
		}
	}
	// }
	return verifyResults
}

func verifyActiveIncrementAnalysis(analysis int) int {
	return analysis + 1
}

func verifyActiveIncrementStage(stage int) int {
	return stage + 1
}

func verifyActiveScanCombination(
	model *verifpal,
	valPrincipalState *principalState, valKnowledgeMap *knowledgeMap,
	valAttackerState *attackerState, valReplacementMap *replacementMap,
	verifyResults *[]verifyResult, newStage bool, analysis int, stage int,
) (int, int) {
	lastReplacement := valReplacementMap.combinationNext()
	attackerKnown := len(valAttackerState.known)
	valPrincipalStateWithReplacements := verifyActiveMutatePrincipalState(valPrincipalState, valKnowledgeMap, valAttackerState, valReplacementMap)
	verifyAnalysis(model, valPrincipalStateWithReplacements, valAttackerState, analysis, 0)
	verifyResolveQueries(model,
		valKnowledgeMap, valPrincipalStateWithReplacements, valAttackerState,
		verifyResults, analysis,
	)
	valAttackerState = verifyActiveClearFreshValues(model, valKnowledgeMap, valAttackerState)
	analysis = verifyActiveIncrementAnalysis(analysis)
	if !mainDebug {
		prettyAnalysis(analysis, stage)
	}
	if len(*verifyResults) == len(model.queries) {
		return analysis, stage
	}
	if (len(valAttackerState.known) > attackerKnown) || newStage {
		valReplacementMapUpdate := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, stage)
		return verifyActiveScanCombination(model,
			valPrincipalState, valKnowledgeMap, valAttackerState, &valReplacementMapUpdate,
			verifyResults, false, analysis, stage,
		)
	}
	if !lastReplacement {
		return verifyActiveScanCombination(model,
			valPrincipalState, valKnowledgeMap, valAttackerState, valReplacementMap,
			verifyResults, false, analysis, stage,
		)
	}
	return analysis, stage
}

func verifyActiveClearFreshValues(model *verifpal, valKnowledgeMap *knowledgeMap, valAttackerState *attackerState) *attackerState {
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
	constructAttackerStatePopulate(model, valKnowledgeMap, false, &valAttackerStateCleared)
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
		constants:      []constant{},
		replacements:   [][]value{},
		requiredKnowns: [][][]int{},
		combination:    []value{},
		requiredKnown:  [][]int{},
		depthIndex:     []int{},
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
		a := sanityResolveConstant(v.constant, valPrincipalState, true)
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
			valReplacementMap.requiredKnowns = append(valReplacementMap.requiredKnowns, [][]int{[]int{-1}, []int{-1}})
		case "primitive":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			valReplacementMap.requiredKnowns = append(valReplacementMap.requiredKnowns, [][]int{[]int{-1}})
			if stage == 2 {
				inject(a.primitive, valPrincipalState, &valReplacementMap, valAttackerState)
			}
		case "equation":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a, gn})
			valReplacementMap.requiredKnowns = append(valReplacementMap.requiredKnowns, [][]int{[]int{-1}, []int{-1}})
		}
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.requiredKnown = make([][]int, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for ii := range valReplacementMap.constants {
		valReplacementMap.requiredKnown[ii] = []int{-1}
		valReplacementMap.depthIndex[ii] = 0
	}
	return valReplacementMap
}

func verifyActiveMutatePrincipalState(
	valPrincipalState *principalState, valKnowledgeMap *knowledgeMap,
	valAttackerState *attackerState, valReplacementMap *replacementMap,
) *principalState {
	valPrincipalStateWithReplacements := constructPrincipalStateClone(valPrincipalState)
	for i, c := range valReplacementMap.constants {
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalStateWithReplacements, c)
		iii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		iiii := sanityGetAttackerStateIndexFromConstant(valAttackerState, c)
		mutatedTo := strInSlice(valPrincipalState.sender[iii], valAttackerState.mutatedTo[iiii])
		unassailable := false
		if valPrincipalState.guard[iii] {
			unassailable = true
			if iiii >= 0 && mutatedTo {
				unassailable = false
			}
		}
		if unassailable {
			continue
		}
		if valPrincipalStateWithReplacements.creator[ii] == valPrincipalStateWithReplacements.name {
			continue
		}
		if !valPrincipalState.known[iii] {
			continue
		}
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
		failedMutate := false
		if ac.kind == "primitive" {
			ac, _ = sanityResolveInternalValuesFromPrincipalState(ac, ii, valPrincipalStateWithReplacements, false)
			for _, r := range valReplacementMap.requiredKnown[i] {
				if r < 0 {
				} else if sanityEquivalentValueInValues(ac.primitive.arguments[r], &valAttackerState.known, valPrincipalState) < 0 {
					failedMutate = true
				}
			}
		}
		if failedMutate {
			continue
		}
		valPrincipalStateWithReplacements.creator[ii] = "Attacker"
		valPrincipalStateWithReplacements.sender[ii] = "Attacker"
		valPrincipalStateWithReplacements.wasMutated[ii] = true
		valPrincipalStateWithReplacements.assigned[ii] = ac
		valPrincipalStateWithReplacements.beforeRewrite[ii] = ac
		if !strInSlice(valPrincipalState.name, valAttackerState.mutatedTo[iiii]) {
			valAttackerState.mutatedTo[iiii] = append(valAttackerState.mutatedTo[iiii], valPrincipalState.name)
		}
	}
	sanityResolveAllPrincipalStateValues(valPrincipalStateWithReplacements, valKnowledgeMap)
	if mainDebug {
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
	return valPrincipalStateWithReplacements
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
