/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import "sync"

var attackerStateShared attackerState
var attackerStateMutex sync.Mutex

func attackerStateInit(m Model, valKnowledgeMap knowledgeMap, active bool) bool {
	attackerStateMutex.Lock()
	attackerStateShared = attackerState{
		active:    active,
		known:     []value{},
		wire:      []bool{},
		mutatedTo: [][]string{},
	}
	for _, c := range valKnowledgeMap.constants {
		if c.qualifier == "public" {
			v := value{
				kind:     "constant",
				constant: c,
			}
			attackerStateShared.known = append(attackerStateShared.known, v)
			attackerStateShared.wire = append(attackerStateShared.wire, false)
			attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, []string{})
		}
	}
	for _, blck := range m.blocks {
		switch blck.kind {
		case "message":
		MessageLoop:
			for _, c := range blck.message.constants {
				i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
				v := value{
					kind:     "constant",
					constant: valKnowledgeMap.constants[i],
				}
				if valKnowledgeMap.constants[i].qualifier != "private" {
					continue MessageLoop
				}
				ii := sanityExactSameValueInValues(v, attackerStateShared.known)
				if ii >= 0 {
					attackerStateShared.wire[ii] = true
					continue MessageLoop
				}
				attackerStateShared.known = append(attackerStateShared.known, v)
				attackerStateShared.wire = append(attackerStateShared.wire, true)
				attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, []string{})
			}
		}
	}
	attackerStateMutex.Unlock()
	return true
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
		attackerStateShared.wire = append(attackerStateShared.wire, write.wire)
		attackerStateShared.mutatedTo = append(attackerStateShared.mutatedTo, write.mutatedTo)
		written = true
	}
	attackerStateMutex.Unlock()
	return written
}

func attackerStatePutMutatedToUpdate(update attackerStateMutatedToUpdate) bool {
	attackerStateMutex.Lock()
	attackerStateShared.mutatedTo[update.i] = append(attackerStateShared.mutatedTo[update.i], update.principal)
	attackerStateMutex.Unlock()
	return true
}
