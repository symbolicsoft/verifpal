/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package verifpal

import (
	"fmt"
	"sync"
)

func verifyActive(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState) {
	var stagesGroup sync.WaitGroup
	InfoMessage("Attacker is configured as active.", "info", false)
	phase := 0
	for phase <= valKnowledgeMap.MaxPhase {
		InfoMessage(fmt.Sprintf("Running at phase %d.", phase), "info", false)
		attackerStateInit(true)
		attackerStatePutPhaseUpdate(valPrincipalStates[0], phase)
		verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
		stagesGroup.Add(4)
		verifyActiveStages(valKnowledgeMap, valPrincipalStates, 1, &stagesGroup)
		verifyActiveStages(valKnowledgeMap, valPrincipalStates, 2, &stagesGroup)
		verifyActiveStages(valKnowledgeMap, valPrincipalStates, 3, &stagesGroup)
		verifyActiveStages(valKnowledgeMap, valPrincipalStates, 4, &stagesGroup)
		stagesGroup.Wait()
		phase = phase + 1
	}
}

func verifyActiveStages(
	valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState,
	stage int, sg *sync.WaitGroup,
) {
	var principalsGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		principalsGroup.Add(1)
		go func(valPrincipalState PrincipalState, pg *sync.WaitGroup) {
			var combinationsGroup sync.WaitGroup
			combinationsGroup.Add(1)
			go verifyActiveScan(
				valKnowledgeMap, valPrincipalState, MutationMap{Initialized: false},
				stage, &combinationsGroup,
			)
			combinationsGroup.Wait()
			pg.Done()
		}(valPrincipalState, &principalsGroup)
	}
	principalsGroup.Wait()
	sg.Done()
}

func verifyActiveScan(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState, valMutationMap MutationMap,
	stage int, cg *sync.WaitGroup,
) {
	var scanGroup sync.WaitGroup
	if verifyResultsAllResolved() {
		cg.Done()
		return
	}
	valAttackerState := attackerStateGetRead()
	attackerKnown := len(valAttackerState.Known)
	attackerKnowsMore := len(valAttackerState.Known) > attackerKnown
	goodLock := valPrincipalState.Lock == 0 || valPrincipalState.Lock >= attackerKnown
	if attackerKnowsMore {
		valPrincipalState.Lock = attackerKnown
	}
	if (goodLock && !valMutationMap.Initialized) || attackerKnowsMore {
		cg.Add(1)
		go func() {
			valMutationMap = mutationMapInit(
				valKnowledgeMap, valPrincipalState, valAttackerState, stage,
			)
			verifyActiveScan(
				valKnowledgeMap, valPrincipalState, mutationMapNext(valMutationMap),
				stage, cg,
			)
		}()
		cg.Done()
		return
	}
	valPrincipalStateMutated, isWorthwhileMutation := verifyActiveMutatePrincipalState(
		valKnowledgeMap, constructPrincipalStateClone(valPrincipalState, true),
		valAttackerState, valMutationMap,
	)
	if isWorthwhileMutation {
		scanGroup.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalStateMutated, stage, &scanGroup)
	}
	if goodLock && !valMutationMap.OutOfMutations {
		cg.Add(1)
		go verifyActiveScan(
			valKnowledgeMap, valPrincipalState, mutationMapNext(valMutationMap),
			stage, cg,
		)
	}
	scanGroup.Wait()
	cg.Done()
}

func verifyActiveMutatePrincipalState(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
) (PrincipalState, bool) {
	isWorthwhileMutation := false
	for i, c := range valMutationMap.Constants {
		ii := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		ac := valMutationMap.Combination[i]
		ar := valueResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.Assigned[ii], valPrincipalState.Assigned[ii],
			ii, valPrincipalState, valAttackerState, true,
		)
		if valueEquivalentValues(ac, ar, true) {
			continue
		}
		switch ar.Kind {
		case "primitive":
			ac.Primitive.Output = ar.Primitive.Output
			ac.Primitive.Check = ar.Primitive.Check
		}
		valPrincipalState.Creator[ii] = "Attacker"
		valPrincipalState.Sender[ii] = "Attacker"
		valPrincipalState.Mutated[ii] = true
		valPrincipalState.Assigned[ii] = ac
		valPrincipalState.BeforeRewrite[ii] = ac
		if i >= valMutationMap.LastIncrement {
			isWorthwhileMutation = true
		}
	}
	valPrincipalState = valueResolveAllPrincipalStateValues(valPrincipalState, valAttackerState)
	failedRewrites, failedRewriteIndices, valPrincipalState := valuePerformAllRewrites(valPrincipalState)
FailedRewritesLoop:
	for i, p := range failedRewrites {
		if !p.Check {
			continue
		}
		ii := valueGetKnowledgeMapIndexFromConstant(
			valKnowledgeMap, valPrincipalState.Constants[failedRewriteIndices[i]],
		)
		declaredAt := valKnowledgeMap.DeclaredAt[ii]
		maxDeclaredAt := valKnowledgeMap.DeclaredAt[len(valKnowledgeMap.Constants)-1]
		if declaredAt == maxDeclaredAt {
			valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(
				valPrincipalState, failedRewriteIndices[i]+1,
			)
			break FailedRewritesLoop
		}
		for iii, c := range valKnowledgeMap.Constants {
			if valKnowledgeMap.DeclaredAt[iii] == declaredAt {
				iiii := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
				valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(
					valPrincipalState, iiii+1,
				)
				break FailedRewritesLoop
			}
		}
	}
	return valPrincipalState, isWorthwhileMutation
}

func verifyActiveDropPrincipalStateAfterIndex(valPrincipalState PrincipalState, f int) PrincipalState {
	valPrincipalState.Constants = valPrincipalState.Constants[:f]
	valPrincipalState.Assigned = valPrincipalState.Assigned[:f]
	valPrincipalState.Guard = valPrincipalState.Guard[:f]
	valPrincipalState.Known = valPrincipalState.Known[:f]
	valPrincipalState.KnownBy = valPrincipalState.KnownBy[:f]
	valPrincipalState.Creator = valPrincipalState.Creator[:f]
	valPrincipalState.Sender = valPrincipalState.Sender[:f]
	valPrincipalState.Rewritten = valPrincipalState.Rewritten[:f]
	valPrincipalState.BeforeRewrite = valPrincipalState.BeforeRewrite[:f]
	valPrincipalState.Mutated = valPrincipalState.Mutated[:f]
	valPrincipalState.BeforeMutate = valPrincipalState.BeforeMutate[:f]
	valPrincipalState.Phase = valPrincipalState.Phase[:f]
	return valPrincipalState
}
