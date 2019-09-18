/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package main

import (
	"fmt"
	"os"
)

func verifyActive(model *verifpal, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) []verifyResult {
	var verifyResults []verifyResult
	valAttackerState := constructAttackerState(true, model, valKnowledgeMap, true)
	prettyMessage("attacker is configured as active", 0, 0, "info")
	analysis := 0
	attackerKnown := -1
	for len(valAttackerState.known) > attackerKnown {
		for principalIndex, valPrincipalState := range valPrincipalStates {
			lastReplacement := false
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
			sanityResolveAllPrincipalStateValues(valPrincipalStateClone, valKnowledgeMap)
			failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStateClone)
			sanityFailOnFailedRewrite(failedRewrites)
			for i := range valPrincipalStateClone.assigned {
				sanityCheckEquationGenerators(valPrincipalStateClone.assigned[i], valPrincipalStateClone)
			}
			verifyAnalysis(model, valPrincipalStateClone, valAttackerState, analysis, 0)
			analysis = verifyActiveIncrementAnalysis(analysis)
			valReplacementMap := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState)
			injectAttackerValues(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				valReplacementMap.injectCounter, (principalIndex == 0),
			)
			for !lastReplacement {
				valPrincipalStateWithReplacements, _ := verifyActiveMutatePrincipalState(valPrincipalState, valKnowledgeMap, valAttackerState, &valReplacementMap)
				verifyAnalysis(model, valPrincipalStateWithReplacements, valAttackerState, analysis, 0)
				analysis = verifyActiveIncrementAnalysis(analysis)
				if !mainDebug {
					prettyAnalysis(analysis)
				}
				verifyResults = verifyResolveQueries(model, valKnowledgeMap, valPrincipalStateWithReplacements, valAttackerState, verifyResults, analysis)
				valAttackerState = verifyActiveClearFreshValues(model, valKnowledgeMap, valAttackerState)
				if len(verifyResults) == len(model.queries) {
					return verifyResults
				}
				if len(valAttackerState.known) > attackerKnown {
					valReplacementMap = verifyActiveInitReplacementMap(valPrincipalState, valAttackerState)
				} else {
					lastReplacement = valReplacementMap.combinationNext()
				}
				attackerKnown = len(valAttackerState.known)
			}
			attackerKnown = len(valAttackerState.known)
		}
	}
	return verifyResults
}

func verifyActiveIncrementAnalysis(analysis int) int {
	return analysis + 1
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

func verifyActiveInitReplacementMap(valPrincipalState *principalState, valAttackerState *attackerState) replacementMap {
	valReplacementMap := replacementMap{
		constants:     []constant{},
		replacements:  [][]value{},
		combination:   []value{},
		depthIndex:    []int{},
		injectCounter: 0,
	}
	e, ge := injectGetAttackerEquations(valReplacementMap.injectCounter)
	// valReplacementMap.injectCounter = valReplacementMap.injectCounter + 1
	valReplacementMap.constants = append(valReplacementMap.constants, e.constant)
	valReplacementMap.replacements = append(valReplacementMap.replacements, []value{e})
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
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			l := len(valReplacementMap.replacements) - 1
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], e)
		case "primitive":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			inject(a.primitive, valPrincipalState, &valReplacementMap, valAttackerState)
		case "equation":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			l := len(valReplacementMap.replacements) - 1
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], ge)
		}
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for ii := range valReplacementMap.depthIndex {
		valReplacementMap.depthIndex[ii] = 0
	}
	return valReplacementMap
}

func verifyActiveMutatePrincipalState(valPrincipalState *principalState, valKnowledgeMap *knowledgeMap, valAttackerState *attackerState, valReplacementMap *replacementMap) (*principalState, bool) {
	valPrincipalStateWithReplacements := constructPrincipalStateClone(valPrincipalState)
	failedCheck := false
	for i, c := range valReplacementMap.constants {
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalStateWithReplacements, c)
		iii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		iiii := sanityGetAttackerStateIndexFromConstant(valAttackerState, c)
		if valPrincipalStateWithReplacements.creator[ii] != valPrincipalStateWithReplacements.name {
			unassailable := false
			if valPrincipalState.guard[iii] {
				unassailable = true
				if iiii >= 0 {
					if strInSlice(valPrincipalState.sender[iii], valAttackerState.mutatedTo[iiii]) {
						unassailable = false
					}
				}
			}
			if valPrincipalState.known[iii] && !unassailable {
				ar := valPrincipalStateWithReplacements.assigned[ii]
				ac := valReplacementMap.combination[i]
				switch ar.kind {
				case "primitive":
					ac.primitive.output = ar.primitive.output
					ac.primitive.check = ar.primitive.check
				}
				if !sanityEquivalentValues(ar, ac, valPrincipalState) {
					valPrincipalStateWithReplacements.creator[ii] = "Attacker"
					valPrincipalStateWithReplacements.sender[ii] = "Attacker"
					valPrincipalStateWithReplacements.wasMutated[ii] = true
					valPrincipalStateWithReplacements.assigned[ii] = ac
					valPrincipalStateWithReplacements.beforeRewrite[ii] = ac
					if !strInSlice(valPrincipalState.name, valAttackerState.mutatedTo[iiii]) {
						valAttackerState.mutatedTo[iiii] = append(valAttackerState.mutatedTo[iiii], valPrincipalState.name)
					}
				}
			}
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
		failedCheck = true
		f := failedRewriteIndices[i] + 1
		valPrincipalStateWithReplacements.constants = valPrincipalStateWithReplacements.constants[:f]
		valPrincipalStateWithReplacements.assigned = valPrincipalStateWithReplacements.assigned[:f]
		valPrincipalStateWithReplacements.guard = valPrincipalStateWithReplacements.guard[:f]
		valPrincipalStateWithReplacements.known = valPrincipalStateWithReplacements.known[:f]
		valPrincipalStateWithReplacements.creator = valPrincipalStateWithReplacements.creator[:f]
		valPrincipalStateWithReplacements.sender = valPrincipalStateWithReplacements.sender[:f]
		valPrincipalStateWithReplacements.wasRewritten = valPrincipalStateWithReplacements.wasRewritten[:f]
		valPrincipalStateWithReplacements.beforeRewrite = valPrincipalStateWithReplacements.beforeRewrite[:f]
		valPrincipalStateWithReplacements.wasMutated = valPrincipalStateWithReplacements.wasMutated[:f]
		valPrincipalStateWithReplacements.beforeMutate = valPrincipalStateWithReplacements.beforeMutate[:f]
		break
	}
	return valPrincipalStateWithReplacements, failedCheck
}
