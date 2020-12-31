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
		err = verifyActiveStages(valKnowledgeMap, valPrincipalStates)
		if err != nil {
			return err
		}
		phase = phase + 1
	}
	return nil
}

func verifyActiveStages(
	valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState,
) error {
	var scanGroup sync.WaitGroup
	var err error
	stage := 1
	valAttackerState := attackerStateGetRead()
	for {
		oldKnown := len(valAttackerState.Known)
		valAttackerState = attackerStateGetRead()
		known := len(valAttackerState.Known)
		for _, valPrincipalState := range valPrincipalStates {
			scanGroup.Add(1)
			go func(valPrincipalState PrincipalState, valAttackerState AttackerState, stage int) {
				var valMutationMap MutationMap
				valMutationMap, err = mutationMapInit(
					valKnowledgeMap, valPrincipalState, valAttackerState, stage,
				)
				if err != nil {
					scanGroup.Done()
					return
				}
				err = verifyActiveScan(
					valKnowledgeMap, valPrincipalState, valAttackerState,
					mutationMapNext(valMutationMap), stage, &scanGroup,
				)
				if err != nil {
					scanGroup.Done()
				}
			}(valPrincipalState, valAttackerState, stage)
		}
		scanGroup.Wait()
		exhaustion := (stage >= 5 && (oldKnown == known))
		if verifyResultsAllResolved() || exhaustion {
			break
		}
		stage = stage + 1
	}
	return nil
}

func verifyActiveScan(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup,
) error {
	var err error
	if verifyResultsAllResolved() {
		scanGroup.Done()
		return nil
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
		return nil
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
		ai, ii := valueResolveConstant(c, valPrincipalState)
		ac := valMutationMap.Combination[i]
		ar, err := valueResolveValueInternalValuesFromPrincipalState(
			ai, ai, ii, valPrincipalState, valAttackerState, true, 0,
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
