/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package vplogic

import (
	"fmt"
	"sync"
)

func verifyActive(valKnowledgeMap *KnowledgeMap, valPrincipalStates []*PrincipalState) error {
	InfoMessage("Attacker is configured as active.", "info", false)
	phase := 0
	for phase <= valKnowledgeMap.MaxPhase {
		var stageGroup sync.WaitGroup
		InfoMessage(fmt.Sprintf("Running at phase %d.", phase), "info", false)
		attackerStateInit(true)
		valPrincipalStatePureResolved := constructPrincipalStateClone(valPrincipalStates[0], true)
		valPrincipalStatePureResolved, err := valueResolveAllPrincipalStateValues(
			valPrincipalStatePureResolved, attackerStateGetRead(),
		)
		if err != nil {
			return err
		}
		err = attackerStatePutPhaseUpdate(valKnowledgeMap, valPrincipalStatePureResolved, phase)
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
	stage int, valKnowledgeMap *KnowledgeMap, valPrincipalStates []*PrincipalState,
	valAttackerState AttackerState, stageGroup *sync.WaitGroup,
) {
	var principalGroup sync.WaitGroup
	var err error
	oldKnown := len(valAttackerState.Known)
	valAttackerState = attackerStateGetRead()
	principalGroup.Add(len(valPrincipalStates))
	for _, valPrincipalState := range valPrincipalStates {
		func(valPrincipalState *PrincipalState) {
			var scanGroup sync.WaitGroup
			var valMutationMap MutationMap
			valMutationMap, err = mutationMapInit(
				valKnowledgeMap, valPrincipalState, valAttackerState, stage,
			)
			if err != nil {
				scanGroup.Done()
				return
			}
			scanGroup.Add(1)
			err = verifyActiveScan(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				mutationMapNext(valMutationMap), stage, &scanGroup,
			)
			if err != nil {
				scanGroup.Done()
				return
			}
			scanGroup.Wait()
			principalGroup.Done()
		}(valPrincipalState)
	}
	principalGroup.Wait()
	exhausted := (stage > 5 && (oldKnown == len(valAttackerState.Known)))
	if exhausted {
		attackerStatePutExhausted()
	}
	stageGroup.Done()
}

func verifyActiveScan(
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup,
) error {
	var err error
	if verifyResultsAllResolved() {
		scanGroup.Done()
		return err
	}
	valPrincipalStateMutated, isWorthwhileMutation := verifyActiveMutatePrincipalState(
		valKnowledgeMap, constructPrincipalStateClone(valPrincipalState, true),
		valAttackerState, valMutationMap,
	)
	if isWorthwhileMutation {
		scanGroup.Add(1)
		go func() {
			err = verifyAnalysis(
				valKnowledgeMap, valPrincipalStateMutated, attackerStateGetRead(), stage, scanGroup,
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
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
) (*PrincipalState, bool) {
	earliestMutation := len(valPrincipalState.Constants)
	isWorthwhileMutation := false
	for i := 0; i < len(valMutationMap.Constants); i++ {
		ai, ii := valueResolveConstant(valMutationMap.Constants[i], valPrincipalState, true)
		ac := valMutationMap.Combination[i]
		ar, _ := valueResolveValueInternalValuesFromKnowledgeMap(ai, valKnowledgeMap)
		switch ar.Kind {
		case typesEnumPrimitive:
			_, aar := possibleToRewrite(ar.Data.(*Primitive), valPrincipalState)
			switch aar[0].Kind {
			case typesEnumPrimitive:
				ar.Data = aar[0].Data.(*Primitive)
			}
		}
		switch ac.Kind {
		case typesEnumPrimitive:
			_, aac := possibleToRewrite(ac.Data.(*Primitive), valPrincipalState)
			switch aac[0].Kind {
			case typesEnumPrimitive:
				ac.Data = aac[0].Data.(*Primitive)
			}
			switch ai.Kind {
			case typesEnumPrimitive:
				ac.Data.(*Primitive).Output = ar.Data.(*Primitive).Output
				ac.Data.(*Primitive).Check = ar.Data.(*Primitive).Check
			}
		}
		valPrincipalState.Creator[ii] = principalNamesMap["Attacker"]
		valPrincipalState.Sender[ii] = principalNamesMap["Attacker"]
		valPrincipalState.Mutated[ii] = true
		valPrincipalState.Assigned[ii] = ac
		valPrincipalState.BeforeRewrite[ii] = ac
		if ii < earliestMutation {
			earliestMutation = ii
		}
		switch {
		case valueEquivalentValues(ac, ar, true):
			continue
		}
		isWorthwhileMutation = true
	}
	if !isWorthwhileMutation {
		return valPrincipalState, isWorthwhileMutation
	}
	valPrincipalState, _ = valueResolveAllPrincipalStateValues(valPrincipalState, valAttackerState)
	failedRewrites, failedRewriteIndices, valPrincipalState := valuePerformAllRewrites(valPrincipalState)
	for i := 0; i < len(failedRewrites); i++ {
		if !failedRewrites[i].Check {
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
			return valPrincipalState, isWorthwhileMutation && earliestMutation < failedRewriteIndices[i]
		}
		for ii := 0; ii < len(valPrincipalState.Constants); ii++ {
			if valPrincipalState.DeclaredAt[ii] == declaredAt {
				valPrincipalState = verifyActiveDropPrincipalStateAfterIndex(
					valPrincipalState, ii+1,
				)
				return valPrincipalState, isWorthwhileMutation && earliestMutation < failedRewriteIndices[i]
			}
		}
	}
	return valPrincipalState, isWorthwhileMutation
}

func verifyActiveDropPrincipalStateAfterIndex(valPrincipalState *PrincipalState, f int) *PrincipalState {
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
