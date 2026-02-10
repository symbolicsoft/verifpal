/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"sync"
	"sync/atomic"
)

var attackerStateShared AttackerState
var attackerStateMutex sync.RWMutex
var attackerStateSnapshot atomic.Pointer[AttackerState]

func attackerStatePublishSnapshot() {
	knownCopy := make([]*Value, len(attackerStateShared.Known))
	copy(knownCopy, attackerStateShared.Known)
	principalStateCopy := make([]*PrincipalState, len(attackerStateShared.PrincipalState))
	copy(principalStateCopy, attackerStateShared.PrincipalState)
	knownMapCopy := make(map[uint64][]int, len(attackerStateShared.KnownMap))
	for k, v := range attackerStateShared.KnownMap {
		knownMapCopy[k] = v
	}
	snapshot := &AttackerState{
		Active:         attackerStateShared.Active,
		CurrentPhase:   attackerStateShared.CurrentPhase,
		Exhausted:      attackerStateShared.Exhausted,
		Known:          knownCopy,
		KnownMap:       knownMapCopy,
		PrincipalState: principalStateCopy,
	}
	attackerStateSnapshot.Store(snapshot)
}

func attackerStateInit(active bool) {
	attackerStateMutex.Lock()
	attackerStateShared = AttackerState{
		Active:         active,
		CurrentPhase:   0,
		Exhausted:      false,
		Known:          []*Value{},
		KnownMap:       make(map[uint64][]int),
		PrincipalState: []*PrincipalState{},
	}
	attackerStatePublishSnapshot()
	attackerStateMutex.Unlock()
}

func attackerStateKnownMapAdd(v *Value, idx int) {
	h := valueHash(v)
	attackerStateShared.KnownMap[h] = append(attackerStateShared.KnownMap[h], idx)
}

func attackerStateAbsorbPhaseValues(valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState) error {
	attackerStateMutex.Lock()
	for i := 0; i < len(valPrincipalState.Constants); i++ {
		switch valPrincipalState.Assigned[i].Kind {
		case typesEnumConstant:
			if valPrincipalState.Assigned[i].Data.(*Constant).Qualifier != typesEnumPublic {
				continue
			}
			earliestPhase, err := minIntInSlice(valPrincipalState.Phase[i])
			if err == nil && earliestPhase > attackerStateShared.CurrentPhase {
				continue
			}
			if !valueConstantIsUsedByAtLeastOnePrincipalInKnowledgeMap(
				valKnowledgeMap, valPrincipalState.Assigned[i].Data.(*Constant),
			) {
				continue
			}
			if valueEquivalentValueInValuesMap(valPrincipalState.Assigned[i], attackerStateShared.Known, attackerStateShared.KnownMap) < 0 {
				valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
				idx := len(attackerStateShared.Known)
				attackerStateShared.Known = append(attackerStateShared.Known, valPrincipalState.Assigned[i])
				attackerStateKnownMapAdd(valPrincipalState.Assigned[i], idx)
				attackerStateShared.PrincipalState = append(
					attackerStateShared.PrincipalState, valPrincipalStateClone,
				)
			}
		}
	}
	for i, c := range valPrincipalState.Constants {
		cc := &Value{Kind: typesEnumConstant, Data: c}
		a := valPrincipalState.Assigned[i]
		if len(valPrincipalState.Wire[i]) == 0 && !valPrincipalState.Constants[i].Leaked {
			continue
		}
		if valPrincipalState.Constants[i].Qualifier == typesEnumPublic {
			continue
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.Phase[i])
		if err != nil {
			attackerStateMutex.Unlock()
			return err
		}
		if earliestPhase > attackerStateShared.CurrentPhase {
			continue
		}
		if valueEquivalentValueInValuesMap(cc, attackerStateShared.Known, attackerStateShared.KnownMap) < 0 {
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
			idx := len(attackerStateShared.Known)
			attackerStateShared.Known = append(attackerStateShared.Known, cc)
			attackerStateKnownMapAdd(cc, idx)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState, valPrincipalStateClone,
			)
		}
		if valueEquivalentValueInValuesMap(a, attackerStateShared.Known, attackerStateShared.KnownMap) < 0 {
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
			idx := len(attackerStateShared.Known)
			attackerStateShared.Known = append(attackerStateShared.Known, a)
			attackerStateKnownMapAdd(a, idx)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState, valPrincipalStateClone,
			)
		}
	}
	attackerStatePublishSnapshot()
	attackerStateMutex.Unlock()
	return nil
}

func attackerStateGetRead() AttackerState {
	snapshot := attackerStateSnapshot.Load()
	if snapshot != nil {
		return *snapshot
	}
	attackerStateMutex.RLock()
	knownCopy := make([]*Value, len(attackerStateShared.Known))
	copy(knownCopy, attackerStateShared.Known)
	principalStateCopy := make([]*PrincipalState, len(attackerStateShared.PrincipalState))
	copy(principalStateCopy, attackerStateShared.PrincipalState)
	knownMapCopy := make(map[uint64][]int, len(attackerStateShared.KnownMap))
	for k, v := range attackerStateShared.KnownMap {
		knownMapCopy[k] = v
	}
	valAttackerState := AttackerState{
		Active:         attackerStateShared.Active,
		CurrentPhase:   attackerStateShared.CurrentPhase,
		Exhausted:      attackerStateShared.Exhausted,
		Known:          knownCopy,
		KnownMap:       knownMapCopy,
		PrincipalState: principalStateCopy,
	}
	attackerStateMutex.RUnlock()
	return valAttackerState
}

func attackerStateGetExhausted() bool {
	snapshot := attackerStateSnapshot.Load()
	if snapshot != nil {
		return snapshot.Exhausted
	}
	attackerStateMutex.RLock()
	exhausted := attackerStateShared.Exhausted
	attackerStateMutex.RUnlock()
	return exhausted
}

func attackerStateGetKnownCount() int {
	snapshot := attackerStateSnapshot.Load()
	if snapshot != nil {
		return len(snapshot.Known)
	}
	attackerStateMutex.RLock()
	count := len(attackerStateShared.Known)
	attackerStateMutex.RUnlock()
	return count
}

func attackerStatePutWrite(known *Value, valPrincipalState *PrincipalState) bool {
	attackerStateMutex.RLock()
	found := valueEquivalentValueInValuesMap(known, attackerStateShared.Known, attackerStateShared.KnownMap) >= 0
	attackerStateMutex.RUnlock()
	if found {
		return false
	}
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	attackerStateMutex.Lock()
	if valueEquivalentValueInValuesMap(known, attackerStateShared.Known, attackerStateShared.KnownMap) >= 0 {
		attackerStateMutex.Unlock()
		return false
	}
	idx := len(attackerStateShared.Known)
	attackerStateShared.Known = append(attackerStateShared.Known, known)
	attackerStateKnownMapAdd(known, idx)
	attackerStateShared.PrincipalState = append(
		attackerStateShared.PrincipalState, valPrincipalStateClone,
	)
	attackerStatePublishSnapshot()
	attackerStateMutex.Unlock()
	return true
}

func attackerStatePutPhaseUpdate(valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState, phase int) error {
	attackerStateMutex.Lock()
	attackerStateShared.CurrentPhase = phase
	attackerStatePublishSnapshot()
	attackerStateMutex.Unlock()
	err := attackerStateAbsorbPhaseValues(valKnowledgeMap, valPrincipalState)
	return err
}

func attackerStatePutExhausted() bool {
	attackerStateMutex.Lock()
	attackerStateShared.Exhausted = true
	attackerStatePublishSnapshot()
	attackerStateMutex.Unlock()
	return true
}
