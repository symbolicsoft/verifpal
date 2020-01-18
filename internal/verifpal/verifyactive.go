/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package verifpal

import "sync"

func verifyActive(
	m *Model,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
) []VerifyResult {
	var VerifyResults []VerifyResult
	analysis := 0
	stage := 0
	constructAttackerState(true, m, valKnowledgeMap, true)
	prettyMessage("Attacker is configured as active.", 0, "info")
	for stage <= 3 {
		switch stage {
		case 0:
			analysis, stage = verifyActiveStage0(
				m, valKnowledgeMap, valPrincipalStates,
				&VerifyResults, analysis, stage,
			)
		default:
			analysis, stage = verifyActiveStage123(
				m, valKnowledgeMap, valPrincipalStates,
				&VerifyResults, analysis, stage,
			)
		}
	}
	return VerifyResults
}

func verifyActiveStage0(
	m *Model, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
	VerifyResults *[]VerifyResult, analysis int, stage int,
) (int, int) {
	for _, valPrincipalState := range valPrincipalStates {
		valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
		valPrincipalStateClone = sanityResolveAllPrincipalStateValues(valPrincipalStateClone, valKnowledgeMap)
		failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStateClone)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalStateClone.assigned {
			sanityCheckEquationGenerators(valPrincipalStateClone.assigned[i], valPrincipalStateClone)
		}
		verifyAnalysis(m, valPrincipalStateClone, analysis)
		prettyAnalysis(analysis, stage)
	}
	stage = verifyActiveIncrementStage(stage)
	return analysis, stage
}

func verifyActiveStage123(
	m *Model,
	valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState,
	VerifyResults *[]VerifyResult, analysis int, stage int,
) (int, int) {
	var principalsGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		principalsGroup.Add(1)
		go func(valPrincipalState *principalState, pg *sync.WaitGroup) {
			var combinationsGroup sync.WaitGroup
			analysis = verifyActiveIncrementAnalysis(analysis)
			combinationsGroup.Add(1)
			go verifyActiveScanCombination(m,
				valPrincipalState, valKnowledgeMap, &replacementMap{initialized: false},
				VerifyResults, true, analysis, stage, &combinationsGroup,
			)
			combinationsGroup.Wait()
			pg.Done()
		}(valPrincipalState, &principalsGroup)
	}
	principalsGroup.Wait()
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
	m *Model,
	valPrincipalState *principalState, valKnowledgeMap *knowledgeMap, valReplacementMap *replacementMap,
	VerifyResults *[]VerifyResult, newStage bool, analysis int, stage int, cg *sync.WaitGroup,
) (int, int) {
	var lastReplacement bool
	var valPrincipalStateWithReplacements *principalState
	valAttackerState := attackerStateGetRead()
	if !valReplacementMap.initialized {
		valReplacementMapInit := verifyActiveInitReplacementMap(valPrincipalState, 0)
		valReplacementMap = &valReplacementMapInit
	}
	attackerKnown := len(valAttackerState.known)
	lastReplacement = valReplacementMap.combinationNext()
	valPrincipalStateWithReplacements, _ = verifyActiveMutatePrincipalState(
		valPrincipalState, valKnowledgeMap, valReplacementMap,
	)
	verifyAnalysis(m, valPrincipalStateWithReplacements, analysis)
	verifyResolveQueries(m,
		valKnowledgeMap, valPrincipalStateWithReplacements,
		VerifyResults, analysis,
	)
	analysis = verifyActiveIncrementAnalysis(analysis)
	prettyAnalysis(analysis, stage)
	if len(*VerifyResults) == len(m.queries) {
		// Nothing
	} else if (len(valAttackerState.known) > attackerKnown) || newStage {
		valReplacementMapUpdate := verifyActiveInitReplacementMap(valPrincipalState, stage)
		cg.Add(1)
		go verifyActiveScanCombination(m,
			valPrincipalState, valKnowledgeMap, &valReplacementMapUpdate,
			VerifyResults, false, analysis, stage, cg,
		)
	} else if !lastReplacement {
		cg.Add(1)
		go verifyActiveScanCombination(m,
			valPrincipalState, valKnowledgeMap, valReplacementMap,
			VerifyResults, false, analysis, stage, cg,
		)
	}
	cg.Done()
	return analysis, stage
}

func verifyActiveInitReplacementMap(valPrincipalState *principalState, stage int) replacementMap {
	valReplacementMap := replacementMap{
		initialized:  true,
		constants:    []constant{},
		replacements: [][]value{},
		combination:  []value{},
		depthIndex:   []int{},
	}
	valAttackerState := attackerStateGetRead()
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
		verifyActiveProvideValueReplacements(
			a, v, ii, stage,
			valPrincipalState, &valReplacementMap,
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
	valPrincipalState *principalState, valReplacementMap *replacementMap,
) {
	valAttackerState := attackerStateGetRead()
	switch a.kind {
	case "constant":
		if (a.constant.name == "g") || (a.constant.name == "nil") {
			return
		}
		replacements := []value{a, constantN}
		for _, v := range valAttackerState.known {
			switch v.kind {
			case "constant":
				if sanityExactSameValueInValues(v, &replacements) < 0 {
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
			return
		}
		l := len(valReplacementMap.replacements) - 1
		includeHashes := (stage > 2)
		injectants := inject(a.primitive, a.primitive, true, rootIndex, valPrincipalState, includeHashes)
		for _, aa := range *injectants {
			if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			}
		}
	case "equation":
		replacements := []value{a, constantGN}
		valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
		valReplacementMap.replacements = append(valReplacementMap.replacements, replacements)
	}
}

func verifyActiveMutatePrincipalState(valPrincipalState *principalState, valKnowledgeMap *knowledgeMap, valReplacementMap *replacementMap) (*principalState, bool) {
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
			verifyActiveDropPrincipalStateAfterIndex(valPrincipalStateWithReplacements, failedRewriteIndices[i]+1)
			break
		}
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
