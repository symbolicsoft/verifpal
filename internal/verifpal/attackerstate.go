/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

var attackerStateReady chan bool = make(chan bool)
var attackerStateReads chan attackerStateRead = make(chan attackerStateRead)
var attackerStateWrites chan attackerStateWrite = make(chan attackerStateWrite)
var attackerStateMutatedToUpdates chan attackerStateMutatedToUpdate = make(chan attackerStateMutatedToUpdate)

func attackerStateInit(active bool) bool {
	go func() {
		valAttackerState := attackerState{
			active:    active,
			known:     []value{},
			wire:      []bool{},
			mutatedTo: [][]string{},
		}
		attackerStateReady <- true
		for {
			select {
			case read := <-attackerStateReads:
				read.resp <- valAttackerState
			case write := <-attackerStateWrites:
				if sanityExactSameValueInValues(write.known, valAttackerState.known) < 0 {
					valAttackerState.known = append(valAttackerState.known, write.known)
					valAttackerState.wire = append(valAttackerState.wire, write.wire)
					valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, write.mutatedTo)
					write.resp <- true
				} else {
					write.resp <- false
				}
			case update := <-attackerStateMutatedToUpdates:
				valAttackerState.mutatedTo[update.i] = append(valAttackerState.mutatedTo[update.i], update.principal)
				update.resp <- true
			}
		}
	}()
	return <-attackerStateReady
}

func attackerStateGetRead() attackerState {
	read := attackerStateRead{
		resp: make(chan attackerState),
	}
	attackerStateReads <- read
	return <-read.resp
}

func attackerStatePutWrite(write attackerStateWrite) bool {
	attackerStateWrites <- write
	return <-write.resp
}

func attackerStatePutMutatedToUpdate(update attackerStateMutatedToUpdate) bool {
	attackerStateMutatedToUpdates <- update
	return <-update.resp

}

func attackerStatePopulate(m Model, valKnowledgeMap knowledgeMap, verbose bool) {
	for _, c := range valKnowledgeMap.constants {
		if c.qualifier == "public" {
			v := value{
				kind:     "constant",
				constant: c,
			}
			write := attackerStateWrite{
				known:     v,
				wire:      false,
				mutatedTo: []string{},
				resp:      make(chan bool),
			}
			attackerStatePutWrite(write)
		}
	}
	for _, blck := range m.blocks {
		switch blck.kind {
		case "message":
			attackerStateRenderMessage(valKnowledgeMap, blck)
		}
	}
}

func attackerStateRenderMessage(valKnowledgeMap knowledgeMap, blck block) {
	valAttackerState := attackerStateGetRead()
	for _, c := range blck.message.constants {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		v := value{
			kind:     "constant",
			constant: valKnowledgeMap.constants[i],
		}
		if valKnowledgeMap.constants[i].qualifier == "private" {
			ii := sanityExactSameValueInValues(v, valAttackerState.known)
			if ii >= 0 {
				valAttackerState.wire[ii] = true
			} else {
				write := attackerStateWrite{
					known:     v,
					wire:      true,
					mutatedTo: []string{},
					resp:      make(chan bool),
				}
				attackerStatePutWrite(write)
			}
		}
	}
}
