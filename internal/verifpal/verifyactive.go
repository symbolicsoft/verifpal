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
	prettyMessage("Attacker is configured as active.", "info")
	verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
	verifyActiveStages(valKnowledgeMap, valPrincipalStates, 1)
	verifyActiveStages(valKnowledgeMap, valPrincipalStates, 2)
	verifyActiveStages(valKnowledgeMap, valPrincipalStates, 3)
}

func verifyActiveStages(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, stage int) {
	var principalsGroup sync.WaitGroup
	for i, valPrincipalState := range valPrincipalStates {
		principalsGroup.Add(1)
		go func(valPrincipalState principalState, lockIndex int, pg *sync.WaitGroup) {
			var combinationsGroup sync.WaitGroup
			combinationsGroup.Add(1)
			go verifyActiveScan(
				valKnowledgeMap, valPrincipalState, replacementMap{initialized: false},
				0, stage, lockIndex, &combinationsGroup,
			)
			combinationsGroup.Wait()
			pg.Done()
		}(valPrincipalState, i, &principalsGroup)
	}
	principalsGroup.Wait()
}

func verifyActiveScan(
	valKnowledgeMap knowledgeMap, valPrincipalState principalState, valReplacementMap replacementMap,
	attackerKnown int, stage int, lockIndex int, cg *sync.WaitGroup,
) {
	var scanGroup sync.WaitGroup
	valAttackerState := attackerStateGetRead()
	attackerKnowsMore := false
	if len(valAttackerState.known) > attackerKnown {
		attackerKnowsMore = true
		attackerKnown = len(valAttackerState.known)
	}
	if !valReplacementMap.initialized || attackerKnowsMore {
		valReplacementMap = replacementMapInit(valPrincipalState, valAttackerState, stage)
		verifyActiveScan(
			valKnowledgeMap, valPrincipalState, replacementMapNext(valReplacementMap),
			attackerKnown, stage, lockIndex, cg,
		)
		return
	}
	if !valReplacementMap.outOfReplacements {
		cg.Add(1)
		go verifyActiveScan(
			valKnowledgeMap, valPrincipalState, replacementMapNext(valReplacementMap),
			attackerKnown, stage, lockIndex, cg,
		)
	}
	scanGroup.Add(1)
	go func() {
		valPrincipalStateMutated, _ := verifyActiveMutatePrincipalState(
			valPrincipalState, valKnowledgeMap, valReplacementMap,
		)
		verifyAnalysis(valKnowledgeMap, valPrincipalStateMutated, stage, &scanGroup)
		if verifyResultsAllResolved() {
			verifyEnd()
		}
	}()
	scanGroup.Wait()
	cg.Done()
	return
}

func verifyActiveMutatePrincipalState(valPrincipalState principalState, valKnowledgeMap knowledgeMap, valReplacementMap replacementMap) (principalState, bool) {
	valAttackerState := attackerStateGetRead()
	isWorthwhileMutation := false
	for i, c := range valReplacementMap.constants {
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		iii := sanityGetAttackerStateIndexFromConstant(valAttackerState, c)
		ac := valReplacementMap.combination[i]
		ar := valPrincipalState.assigned[ii]
		switch ar.kind {
		case "primitive":
			ac.primitive.output = ar.primitive.output
			ac.primitive.check = ar.primitive.check
		}
		if sanityEquivalentValues(ar, ac, valPrincipalState) {
			continue
		}
		valPrincipalState.creator[ii] = "Attacker"
		valPrincipalState.sender[ii] = "Attacker"
		valPrincipalState.wasMutated[ii] = true
		valPrincipalState.assigned[ii] = ac
		valPrincipalState.beforeRewrite[ii] = ac
		if !strInSlice(valPrincipalState.name, valAttackerState.mutatedTo[iii]) {
			valAttackerState.mutatedTo[iii] = append(valAttackerState.mutatedTo[iii], valPrincipalState.name)
		}
		if i >= valReplacementMap.lastIncrement {
			isWorthwhileMutation = true
		}
	}
	valPrincipalState = sanityResolveAllPrincipalStateValues(valPrincipalState, valKnowledgeMap)
	failedRewrites, failedRewriteIndices := sanityPerformAllRewrites(valPrincipalState)
	for i, p := range failedRewrites {
		if p.check {
			valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(valPrincipalState, failedRewriteIndices[i]+1)
			break
		}
	}
	return valPrincipalState, isWorthwhileMutation
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
