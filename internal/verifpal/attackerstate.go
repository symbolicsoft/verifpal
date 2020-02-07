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
		wire:         []bool{},
		mutatedTo:    [][]string{},
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
		attackerStateShared.wire = append(attackerStateShared.wire, false)
		attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, []string{})
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
			attackerStateShared.wire[ii] = true
			continue
		}
		attackerStateShared.known = append(attackerStateShared.known, v)
		attackerStateShared.wire = append(attackerStateShared.wire, true)
		attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, []string{})
	}
	attackerStateMutex.Unlock()
}

/*
func attackerStateClearFreshValues(valPrincipalState principalState) {
	attackerStateMutex.Lock()
	attackerStateCleared := attackerState{
		active:       attackerStateShared.active,
		currentPhase: attackerStateShared.currentPhase,
		known:        []value{},
		wire:         []bool{},
		mutatedTo:    [][]string{},
	}
	for i, a := range attackerStateShared.known {
		if sanityValueHasFreshValues(valPrincipalState, a) {
			continue
		}
		if sanityExactSameValueInValues(a, attackerStateCleared.known) >= 0 {
			continue
		}
		attackerStateCleared.known = append(
			attackerStateCleared.known, attackerStateShared.known[i],
		)
		attackerStateCleared.wire = append(
			attackerStateCleared.wire, attackerStateShared.wire[i],
		)
		attackerStateCleared.mutatedTo = append(
			attackerStateCleared.mutatedTo, attackerStateShared.mutatedTo[i],
		)
	}
	attackerStateShared = attackerStateCleared
	attackerStateMutex.Unlock()
	attackerStateAbsorbPhaseValues(valPrincipalState)
}
*/

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
		attackerStateShared.wire = append(attackerStateShared.wire, write.wire)
		attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, write.mutatedTo)
		written = true
	}
	attackerStateMutex.Unlock()
	return written
}

func attackerStatePutMutatedToUpdate(update attackerStateMutatedToUpdate) bool {
	var err error
	attackerStateMutex.Lock()
	attackerStateShared.mutatedTo[update.i], err = appendUniqueString(
		attackerStateShared.mutatedTo[update.i], update.principal,
	)
	attackerStateMutex.Unlock()
	return (err == nil)
}

func attackerStatePutPhaseUpdate(valPrincipalState principalState, phase int) {
	attackerStateMutex.Lock()
	attackerStateShared.currentPhase = phase
	attackerStateMutex.Unlock()
	attackerStateAbsorbPhaseValues(valPrincipalState)
}
