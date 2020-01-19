/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package verifpal

import (
	"sync"
)

func verifyActive(
	m Model,
	valKnowledgeMap knowledgeMap, valPrincipalStates []principalState,
) {
	constructAttackerState(true, m, valKnowledgeMap, true)
	prettyMessage("Attacker is configured as active.", 0, "info")
	analysis := verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0, 0)
	analysis = verifyActiveStages(valKnowledgeMap, valPrincipalStates, analysis, 1)
	analysis = verifyActiveStages(valKnowledgeMap, valPrincipalStates, analysis, 2)
	verifyActiveStages(valKnowledgeMap, valPrincipalStates, analysis, 3)
}

func verifyActiveStages(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, analysis int, stage int) int {
	var principalsGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		principalsGroup.Add(1)
		go func(valPrincipalState principalState, pg *sync.WaitGroup) {
			var combinationsGroup sync.WaitGroup
			analysis = verifyActiveIncrementAnalysis(analysis)
			combinationsGroup.Add(1)
			go verifyActiveScanCombination(
				valPrincipalState, valKnowledgeMap, replacementMap{initialized: false},
				true, analysis, stage, &combinationsGroup,
			)
			combinationsGroup.Wait()
			pg.Done()
		}(valPrincipalState, &principalsGroup)
	}
	principalsGroup.Wait()
	return analysis
}

func verifyActiveIncrementAnalysis(analysis int) int {
	return analysis + 1
}

func verifyActiveScanCombination(
	valPrincipalState principalState, valKnowledgeMap knowledgeMap, valReplacementMap replacementMap,
	newStage bool, analysis int, stage int, cg *sync.WaitGroup,
) (int, int) {
	var scanGroup sync.WaitGroup
	valAttackerState := attackerStateGetRead()
	attackerKnown := len(valAttackerState.known)
	if !valReplacementMap.initialized {
		valReplacementMapInit := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, 0)
		valReplacementMap = valReplacementMapInit
	}
	lastReplacement := valReplacementMap.combinationNext()
	valPrincipalStateWithReplacements, _ := verifyActiveMutatePrincipalState(
		valPrincipalState, valKnowledgeMap, valReplacementMap,
	)
	scanGroup.Add(1)
	go verifyAnalysis(valKnowledgeMap, valPrincipalStateWithReplacements, analysis, &scanGroup)
	analysis = verifyActiveIncrementAnalysis(analysis)
	prettyAnalysis(analysis, stage)
	verifyResults := verifyResultsGetRead()
	allQueriesResolved := true
	for _, verifyResult := range verifyResults {
		if !verifyResult.resolved {
			allQueriesResolved = false
			break
		}
	}
	if allQueriesResolved {
		scanGroup.Done()
		cg.Done()
		return analysis, stage
	}
	if (len(valAttackerState.known) > attackerKnown) || newStage {
		valReplacementMapUpdate := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState, stage)
		cg.Add(1)
		go verifyActiveScanCombination(valPrincipalState, valKnowledgeMap, valReplacementMapUpdate, false, analysis, stage, cg)
	} else if !lastReplacement {
		cg.Add(1)
		go verifyActiveScanCombination(valPrincipalState, valKnowledgeMap, valReplacementMap, false, analysis, stage, cg)
	}
	scanGroup.Wait()
	cg.Done()
	return analysis, stage
}

func verifyActiveInitReplacementMap(valPrincipalState principalState, valAttackerState attackerState, stage int) replacementMap {
	valReplacementMap := replacementMap{
		initialized:  true,
		constants:    []constant{},
		replacements: [][]value{},
		combination:  []value{},
		depthIndex:   []int{},
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
		valReplacementMap = verifyActiveProvideValueReplacements(
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

func verifyActiveProvideValueReplacements(
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

func verifyActiveMutatePrincipalState(valPrincipalState principalState, valKnowledgeMap knowledgeMap, valReplacementMap replacementMap) (principalState, bool) {
	valAttackerState := attackerStateGetRead()
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
	failedRewrites, failedRewriteIndices := sanityPerformAllRewrites(valPrincipalStateWithReplacements)
	for i, p := range failedRewrites {
		if p.check {
			valPrincipalStateWithReplacements = verifyActiveDropPrincipalStateAfterIndex(valPrincipalStateWithReplacements, failedRewriteIndices[i]+1)
			break
		}
	}
	return valPrincipalStateWithReplacements, isWorthwhileMutation
}

func verifyActiveDropPrincipalStateAfterIndex(valPrincipalState principalState, f int) principalState {
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
	return valPrincipalState
}
