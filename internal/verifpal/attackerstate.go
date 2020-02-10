/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"sync"
)

var attackerStateShared attackerState
var attackerStateMutex sync.Mutex

func attackerStateInit(active bool) {
	attackerStateMutex.Lock()
	attackerStateShared = attackerState{
		active:       active,
		currentPhase: 0,
		known:        []value{},
	}
	attackerStateMutex.Unlock()
}

func attackerStateAbsorbPhaseValues(valPrincipalState principalState) {
	attackerStateMutex.Lock()
	for i, c := range valPrincipalState.constants {
		if c.qualifier != "public" {
			continue
		}
		v := value{
			kind:     "constant",
			constant: c,
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.phase[i])
		if err == nil && earliestPhase > attackerStateShared.currentPhase {
			continue
		}
		attackerStateShared.known = append(attackerStateShared.known, v)
	}
	for i, c := range valPrincipalState.constants {
		if !strInSlice(valPrincipalState.name, valPrincipalState.wire[i]) && !valPrincipalState.constants[i].leaked {
			continue
		}
		if valPrincipalState.constants[i].qualifier != "private" {
			continue
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.phase[i])
		if err != nil {
			errorCritical(err.Error())
		}
		if earliestPhase > attackerStateShared.currentPhase {
			continue
		}
		v := value{
			kind:     "constant",
			constant: c,
		}
		ii := sanityExactSameValueInValues(v, attackerStateShared.known)
		if ii >= 0 {
			continue
		}
		attackerStateShared.known = append(attackerStateShared.known, v)
	}
	attackerStateMutex.Unlock()
}

func attackerStateGetRead() attackerState {
	attackerStateMutex.Lock()
	valAttackerState := attackerStateShared
	attackerStateMutex.Unlock()
	return valAttackerState
}

func attackerStatePutWrite(write attackerStateWrite) bool {
	written := false
	attackerStateMutex.Lock()
	if sanityExactSameValueInValues(write.known, attackerStateShared.known) < 0 {
		attackerStateShared.known = append(attackerStateShared.known, write.known)
		written = true
	}
	attackerStateMutex.Unlock()
	return written
}

func attackerStatePutPhaseUpdate(valPrincipalState principalState, phase int) {
	attackerStateMutex.Lock()
	attackerStateShared.currentPhase = phase
	attackerStateMutex.Unlock()
	attackerStateAbsorbPhaseValues(valPrincipalState)
}
