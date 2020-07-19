/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
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
		Known:          []Value{},
		PrincipalState: []PrincipalState{},
	}
	attackerStateMutex.Unlock()
}

func attackerStateAbsorbPhaseValues(valPrincipalState PrincipalState) error {
	attackerStateMutex.Lock()
	for i, c := range valPrincipalState.Constants {
		cc := Value{Kind: "constant", Constant: c}
		if c.Qualifier != "public" {
			continue
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.Phase[i])
		if err == nil && earliestPhase > attackerStateShared.CurrentPhase {
			continue
		}
		if valueEquivalentValueInValues(cc, attackerStateShared.Known) < 0 {
			attackerStateShared.Known = append(attackerStateShared.Known, cc)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState,
				constructPrincipalStateClone(valPrincipalState, false),
			)
		}
	}
	for i, c := range valPrincipalState.Constants {
		cc := Value{Kind: "constant", Constant: c}
		a := valPrincipalState.Assigned[i]
		if len(valPrincipalState.Wire[i]) == 0 && !valPrincipalState.Constants[i].Leaked {
			continue
		}
		if valPrincipalState.Constants[i].Qualifier != "private" {
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
			attackerStateShared.Known = append(attackerStateShared.Known, cc)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState,
				constructPrincipalStateClone(valPrincipalState, false),
			)
		}
		aa, err := valueResolveValueInternalValuesFromPrincipalState(
			a, a, i, valPrincipalState, attackerStateShared, true, 0,
		)
		if err != nil {
			return err
		}
		if valueEquivalentValueInValues(aa, attackerStateShared.Known) < 0 {
			attackerStateShared.Known = append(attackerStateShared.Known, aa)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState,
				constructPrincipalStateClone(valPrincipalState, false),
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

func attackerStatePutWrite(known Value, valPrincipalState PrincipalState) bool {
	written := false
	if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
		attackerStateMutex.Lock()
		if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
			attackerStateShared.Known = append(attackerStateShared.Known, known)
			attackerStateShared.PrincipalState = append(
				attackerStateShared.PrincipalState,
				constructPrincipalStateClone(valPrincipalState, false),
			)
			written = true
		}
		attackerStateMutex.Unlock()
	}
	return written
}

func attackerStatePutPhaseUpdate(valPrincipalState PrincipalState, phase int) error {
	attackerStateMutex.Lock()
	attackerStateShared.CurrentPhase = phase
	attackerStateMutex.Unlock()
	err := attackerStateAbsorbPhaseValues(valPrincipalState)
	return err
}
