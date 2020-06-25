/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"sync"
)

var attackerStateShared AttackerState
var attackerStateMutex sync.Mutex

func attackerStateInit(active bool) {
	attackerStateMutex.Lock()
	attackerStateShared = AttackerState{
		Active:       active,
		CurrentPhase: 0,
		Known:        []Value{},
	}
	attackerStateMutex.Unlock()
}

func attackerStateAbsorbPhaseValues(valPrincipalState PrincipalState) {
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
		}
	}
	for i, c := range valPrincipalState.Constants {
		cc := Value{Kind: "constant", Constant: c}
		if len(valPrincipalState.Wire[i]) == 0 && !valPrincipalState.Constants[i].Leaked {
			continue
		}
		if valPrincipalState.Constants[i].Qualifier != "private" {
			continue
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.Phase[i])
		if err != nil {
			errorCritical(err.Error())
		}
		if earliestPhase > attackerStateShared.CurrentPhase {
			continue
		}
		if valueEquivalentValueInValues(cc, attackerStateShared.Known) < 0 {
			attackerStateShared.Known = append(attackerStateShared.Known, cc)
		}
	}
	attackerStateMutex.Unlock()
}

func attackerStateGetRead() AttackerState {
	attackerStateMutex.Lock()
	valAttackerState := attackerStateShared
	attackerStateMutex.Unlock()
	return valAttackerState
}

func attackerStatePutWrite(known Value) bool {
	written := false
	if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
		attackerStateMutex.Lock()
		if valueEquivalentValueInValues(known, attackerStateShared.Known) < 0 {
			attackerStateShared.Known = append(attackerStateShared.Known, known)
			written = true
		}
		attackerStateMutex.Unlock()
	}
	return written
}

func attackerStatePutPhaseUpdate(valPrincipalState PrincipalState, phase int) {
	attackerStateMutex.Lock()
	attackerStateShared.CurrentPhase = phase
	attackerStateMutex.Unlock()
	attackerStateAbsorbPhaseValues(valPrincipalState)
}
