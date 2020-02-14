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
		cc := value{kind: "constant", constant: c}
		v := valPrincipalState.assigned[i]
		if c.qualifier != "public" {
			continue
		}
		earliestPhase, err := minIntInSlice(valPrincipalState.phase[i])
		if err == nil && earliestPhase > attackerStateShared.currentPhase {
			continue
		}
		if sanityExactSameValueInValues(cc, attackerStateShared.known) < 0 {
			attackerStateShared.known = append(attackerStateShared.known, cc)
		}
		if sanityExactSameValueInValues(v, attackerStateShared.known) < 0 {
			attackerStateShared.known = append(attackerStateShared.known, v)
		}
	}
	for i, c := range valPrincipalState.constants {
		cc := value{kind: "constant", constant: c}
		v := valPrincipalState.assigned[i]
		if len(valPrincipalState.wire[i]) == 0 && !valPrincipalState.constants[i].leaked {
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
		if sanityExactSameValueInValues(cc, attackerStateShared.known) < 0 {
			attackerStateShared.known = append(attackerStateShared.known, cc)
		}
		if sanityExactSameValueInValues(v, attackerStateShared.known) < 0 {
			attackerStateShared.known = append(attackerStateShared.known, v)
		}
	}
	attackerStateMutex.Unlock()
}

func attackerStateGetRead() attackerState {
	attackerStateMutex.Lock()
	valAttackerState := attackerStateShared
	attackerStateMutex.Unlock()
	return valAttackerState
}

func attackerStatePutWrite(known value) bool {
	written := false
	if sanityExactSameValueInValues(known, attackerStateShared.known) < 0 {
		attackerStateMutex.Lock()
		if sanityExactSameValueInValues(known, attackerStateShared.known) < 0 {
			attackerStateShared.known = append(attackerStateShared.known, known)
		}
		attackerStateMutex.Unlock()
		written = true
	}
	return written
}

func attackerStatePutPhaseUpdate(valPrincipalState principalState, phase int) {
	attackerStateMutex.Lock()
	attackerStateShared.currentPhase = phase
	attackerStateMutex.Unlock()
	attackerStateAbsorbPhaseValues(valPrincipalState)
}
