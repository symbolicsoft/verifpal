/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package vplogic

import (
	"fmt"
	"sync"
)

func verifyActive(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState) error {
	InfoMessage("Attacker is configured as active.", "info", false)
	phase := 0
	for phase <= valKnowledgeMap.MaxPhase {
		var stageGroup sync.WaitGroup
		InfoMessage(fmt.Sprintf("Running at phase %d.", phase), "info", false)
		attackerStateInit(true)
		err := attackerStatePutPhaseUpdate(valPrincipalStates[0], phase)
		if err != nil {
			return err
		}
		err = verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
		if err != nil {
			return err
		}
		stageGroup.Add(1)
		go verifyActiveStages(1, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
		stageGroup.Wait()
		stageGroup.Add(2)
		go verifyActiveStages(2, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
		go verifyActiveStages(3, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
		stageGroup.Wait()
		stageGroup.Add(2)
		go verifyActiveStages(4, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
		go verifyActiveStages(5, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
		stageGroup.Wait()
		stage := 6
		for !verifyResultsAllResolved() && !attackerStateGetExhausted() {
			stageGroup.Add(1)
			go verifyActiveStages(stage, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
			stageGroup.Wait()
			stage = stage + 1
		}
		phase = phase + 1
	}
	return nil
}

func verifyActiveStages(
	stage int, valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState,
	valAttackerState AttackerState, stageGroup *sync.WaitGroup,
) {
	var scanGroup sync.WaitGroup
	var err error
	oldKnown := len(valAttackerState.Known)
	valAttackerState = attackerStateGetRead()
	for _, valPrincipalState := range valPrincipalStates {
		var valMutationMap MutationMap
		valMutationMap, err = mutationMapInit(
			valKnowledgeMap, valPrincipalState, valAttackerState, stage,
		)
		if err != nil {
			break
		}
		scanGroup.Add(1)
		err = verifyActiveScan(
			valKnowledgeMap, valPrincipalState, valAttackerState,
			mutationMapNext(valMutationMap), stage, &scanGroup,
		)
		if err != nil {
			break
		}
	}
	scanGroup.Wait()
	exhausted := (stage > 5 && (oldKnown == len(valAttackerState.Known)))
	if exhausted {
		attackerStatePutExhausted()
	}
	stageGroup.Done()
}

func verifyActiveScan(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup,
) error {
	var err error
	if verifyResultsAllResolved() {
		scanGroup.Done()
		return err
	}
	valPrincipalStateMutated, isWorthwhileMutation, err := verifyActiveMutatePrincipalState(
		constructPrincipalStateClone(valPrincipalState, true), valAttackerState, valMutationMap,
	)
	if err != nil {
		return err
	}
	if isWorthwhileMutation {
		scanGroup.Add(1)
		go func() {
			err = verifyAnalysis(
				valKnowledgeMap, valPrincipalStateMutated, valAttackerState, stage, scanGroup,
			)
			if err != nil {
				scanGroup.Done()
				return
			}
		}()
	}
	if valMutationMap.OutOfMutations {
		scanGroup.Done()
		return err
	}
	go func() {
		err := verifyActiveScan(
			valKnowledgeMap, valPrincipalState, valAttackerState,
			mutationMapNext(valMutationMap), stage, scanGroup,
		)
		if err != nil {
			scanGroup.Done()
		}
	}()
	return nil
}

func verifyActiveMutatePrincipalState(
	valPrincipalState PrincipalState, valAttackerState AttackerState, valMutationMap MutationMap,
) (PrincipalState, bool, error) {
	isWorthwhileMutation := false
	for i, c := range valMutationMap.Constants {
		ai, ii := valueResolveConstant(&c, &valPrincipalState)
		ac := valMutationMap.Combination[i]
		ar, err := valueResolveValueInternalValuesFromPrincipalState(
			&ai, &ai, ii, valPrincipalState, valAttackerState, true, 0,
		)
		if err != nil {
			return valPrincipalState, false, err
		}
		switch ar.Kind {
		case typesEnumPrimitive:
			ac.Primitive.Output = ar.Primitive.Output
			ac.Primitive.Check = ar.Primitive.Check
			_, aar := possibleToRewrite(ar.Primitive, valPrincipalState)
			ar.Primitive = aar[0].Primitive
		}
		switch ac.Kind {
		case typesEnumPrimitive:
			_, aac := possibleToRewrite(ac.Primitive, valPrincipalState)
			ac.Primitive = aac[0].Primitive
		}
		if valueEquivalentValues(&ac, &ar, true) {
			continue
		}
		valPrincipalState.Creator[ii] = principalNamesMap["Attacker"]
		valPrincipalState.Sender[ii] = principalNamesMap["Attacker"]
		valPrincipalState.Mutated[ii] = true
		valPrincipalState.Assigned[ii] = ac
		valPrincipalState.BeforeRewrite[ii] = ac
		if i >= valMutationMap.LastIncrement {
			isWorthwhileMutation = true
		}
	}
	if !isWorthwhileMutation {
		return valPrincipalState, isWorthwhileMutation, nil
	}
	valPrincipalState, err := valueResolveAllPrincipalStateValues(valPrincipalState, valAttackerState)
	if err != nil {
		return valPrincipalState, false, err
	}
	failedRewrites, failedRewriteIndices, valPrincipalState := valuePerformAllRewrites(valPrincipalState)
FailedRewritesLoop:
	for i, p := range failedRewrites {
		if !p.Check {
			continue
		}
		if valPrincipalState.Creator[failedRewriteIndices[i]] != valPrincipalState.ID {
			continue
		}
		declaredAt := valPrincipalState.DeclaredAt[failedRewriteIndices[i]]
		if declaredAt == valPrincipalState.MaxDeclaredAt {
			valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(
				valPrincipalState, failedRewriteIndices[i]+1,
			)
			break FailedRewritesLoop
		}
		for iii := range valPrincipalState.Constants {
			if valPrincipalState.DeclaredAt[iii] == declaredAt {
				valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(
					valPrincipalState, iii+1,
				)
				break FailedRewritesLoop
			}
		}
	}
	return valPrincipalState, isWorthwhileMutation, nil
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
