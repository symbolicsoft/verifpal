/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"sync"
)

var attackerStateShared AttackerState
var attackerStateMutex sync.Mutex

func attackerStateInit(active bool) {
	attackerStateMutex.Lock()
	attackerStateShared = AttackerState{
		Active:         active,
		CurrentPhase:   0,
		Exhausted:      false,
		Known:          []*Value{},
		PrincipalState: []*PrincipalState{},
	}
	attackerStateMutex.Unlock()
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
			if valueEquivalentValueInValues(valPrincipalState.Assigned[i], attackerStateShared.Known) < 0 {
				valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
				attackerStateShared.Known = append(attackerStateShared.Known, valPrincipalState.Assigned[i])
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
			return err
		}
		if earliestPhase > attackerStateShared.CurrentPhase {
			continue
		}
		if valueEquivalentValueInValues(cc, attackerStateShared.Known) < 0 {
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
			attackerStateShared.Known = append(attackerStateShared.Known, cc)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState, valPrincipalStateClone,
			)
		}
		if valueEquivalentValueInValues(a, attackerStateShared.Known) < 0 {
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
			attackerStateShared.Known = append(attackerStateShared.Known, a)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState, valPrincipalStateClone,
			)
		}
	}
	attackerStateMutex.Unlock()
	return nil
}

func attackerStateGetRead() AttackerState {
	attackerStateMutex.Lock()
	valAttackerState := attackerStateShared
	attackerStateMutex.Unlock()
	return valAttackerState
}

func attackerStateGetExhausted() bool {
	var exhausted bool
	attackerStateMutex.Lock()
	exhausted = attackerStateShared.Exhausted
	attackerStateMutex.Unlock()
	return exhausted
}

func attackerStatePutWrite(known *Value, valPrincipalState *PrincipalState) bool {
	written := false
	if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
		attackerStateMutex.Lock()
		if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
			valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
			attackerStateShared.Known = append(attackerStateShared.Known, known)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState, valPrincipalStateClone,
			)
			written = true
		}
		attackerStateMutex.Unlock()
	}
	return written
}

func attackerStatePutPhaseUpdate(valKnowledgeMap *KnowledgeMap, valPrincipalState *PrincipalState, phase int) error {
	attackerStateMutex.Lock()
	attackerStateShared.CurrentPhase = phase
	attackerStateMutex.Unlock()
	err := attackerStateAbsorbPhaseValues(valKnowledgeMap, valPrincipalState)
	return err
}

func attackerStatePutExhausted() bool {
	attackerStateMutex.Lock()
	attackerStateShared.Exhausted = true
	attackerStateMutex.Unlock()
	return true
}
