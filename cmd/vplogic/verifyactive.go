/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package vplogic

import (
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	stageExhaustionThreshold  = 5
	stageRecursiveInjection   = 5
	stageMutationExpansion    = 3
	maxStageLimit             = 8
	maxSubsetMutationWeight   = 3
	maxSubsetsPerWeight       = 50
	maxWeight1MutationsPerVar = 50
	maxMutationsPerSubset     = 20000
	maxFullMutationProduct    = 50000
	maxScanBudget             = 20000
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
			if stage+1 <= maxStageLimit {
				stageGroup.Add(2)
				go verifyActiveStages(stage, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
				go verifyActiveStages(stage+1, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
				stageGroup.Wait()
				stage = stage + 2
			} else {
				stageGroup.Add(1)
				go verifyActiveStages(stage, valKnowledgeMap, valPrincipalStates, attackerStateGetRead(), &stageGroup)
				stageGroup.Wait()
				stage = stage + 1
			}
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
	var worthwhileMutationCount uint32
	oldKnown := len(valAttackerState.Known)
	valAttackerState = attackerStateGetRead()
	principalGroup.Add(len(valPrincipalStates))
	for _, valPrincipalState := range valPrincipalStates {
		func(valPrincipalState *PrincipalState) {
			defer principalGroup.Done()
			var scanGroup sync.WaitGroup
			valMutationMap, err := mutationMapInit(
				valKnowledgeMap, valPrincipalState, valAttackerState, stage,
			)
			if err != nil {
				return
			}
			verifyActiveScanWeighted(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				valMutationMap, stage, &scanGroup, &worthwhileMutationCount,
			)
		}(valPrincipalState)
	}
	principalGroup.Wait()
	worthwhile := atomic.LoadUint32(&worthwhileMutationCount)
	stagnant := worthwhile == 0 || oldKnown == attackerStateGetKnownCount()
	exhausted := stage > stageExhaustionThreshold && (stagnant || stage > maxStageLimit)
	if exhausted {
		attackerStatePutExhausted()
	}
	stageGroup.Done()
}

func verifyActiveScanWeighted(
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup, worthwhileMutationCount *uint32,
) {
	n := len(valMutationMap.Constants)
	if n == 0 {
		return
	}
	var budgetUsed uint32
	budget := uint32(maxScanBudget)
	maxWeight := maxSubsetMutationWeight
	if maxWeight > n {
		maxWeight = n
	}
	for weight := 1; weight <= maxWeight; weight++ {
		if verifyResultsAllResolved() {
			break
		}
		if atomic.LoadUint32(&budgetUsed) >= budget {
			break
		}
		verifyActiveScanAtWeight(
			valKnowledgeMap, valPrincipalState, valAttackerState,
			valMutationMap, stage, scanGroup, worthwhileMutationCount,
			n, weight, &budgetUsed, budget,
		)
	}
	if !verifyResultsAllResolved() && atomic.LoadUint32(&budgetUsed) < budget {
		totalProduct := 1
		overflow := false
		for i := 0; i < n; i++ {
			m := len(valMutationMap.Mutations[i])
			if m > 0 && totalProduct > maxFullMutationProduct/m {
				overflow = true
				break
			}
			totalProduct *= m
		}
		if !overflow && totalProduct <= maxFullMutationProduct {
			scanGroup.Add(1)
			verifyActiveScan(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				mutationMapNext(valMutationMap), stage, scanGroup, worthwhileMutationCount,
			)
		}
	}
	scanGroup.Wait()
}

func verifyActiveScanAtWeight(
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup, worthwhileMutationCount *uint32,
	n int, weight int, budgetUsed *uint32, budget uint32,
) {
	indices := make([]int, weight)
	for i := range indices {
		indices[i] = i
	}
	scanned := 0
	for {
		if verifyResultsAllResolved() {
			return
		}
		if atomic.LoadUint32(budgetUsed) >= budget {
			return
		}
		subIndices := make([]int, weight)
		copy(subIndices, indices)
		if weight == 1 {
			subMap := mutationMapSubsetCapped(valMutationMap, subIndices, maxWeight1MutationsPerVar)
			cost := uint32(len(subMap.Mutations[0])) //nolint:gosec
			atomic.AddUint32(budgetUsed, cost)
			scanGroup.Add(1)
			verifyActiveScan(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				mutationMapNext(subMap), stage, scanGroup, worthwhileMutationCount,
			)
			scanned++
		} else {
			product := 1
			overflow := false
			for _, idx := range indices {
				m := len(valMutationMap.Mutations[idx])
				if m > 0 && product > maxMutationsPerSubset/m {
					overflow = true
					break
				}
				product *= m
			}
			if !overflow && product <= maxMutationsPerSubset {
				subMap := mutationMapSubset(valMutationMap, subIndices)
				atomic.AddUint32(budgetUsed, uint32(product)) //nolint:gosec
				scanGroup.Add(1)
				verifyActiveScan(
					valKnowledgeMap, valPrincipalState, valAttackerState,
					mutationMapNext(subMap), stage, scanGroup, worthwhileMutationCount,
				)
				scanned++
			}
		}
		if scanned >= maxSubsetsPerWeight {
			return
		}
		i := weight - 1
		for i >= 0 {
			indices[i]++
			if indices[i] <= n-weight+i {
				break
			}
			i--
		}
		if i < 0 {
			break
		}
		for j := i + 1; j < weight; j++ {
			indices[j] = indices[j-1] + 1
		}
	}
}

func verifyActiveScan(
	valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, valMutationMap MutationMap,
	stage int, scanGroup *sync.WaitGroup, worthwhileMutationCount *uint32,
) {
	if verifyResultsAllResolved() {
		scanGroup.Done()
		return
	}
	valPrincipalStateMutated, isWorthwhileMutation := verifyActiveMutatePrincipalState(
		valKnowledgeMap, constructPrincipalStateClone(valPrincipalState, true),
		valAttackerState, valMutationMap,
	)
	if isWorthwhileMutation {
		atomic.AddUint32(worthwhileMutationCount, 1)
		scanGroup.Add(1)
		go func() {
			err := verifyAnalysis(
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
		return
	}
	go func() {
		verifyActiveScan(
			valKnowledgeMap, valPrincipalState, valAttackerState,
			mutationMapNext(valMutationMap), stage, scanGroup, worthwhileMutationCount,
		)
	}()
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
