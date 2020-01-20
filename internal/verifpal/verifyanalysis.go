/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package verifpal

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var verifyAnalysisCount uint32

func verifyAnalysis(valKnowledgeMap knowledgeMap, valPrincipalState principalState, stage int, sg *sync.WaitGroup) {
	var aGroup sync.WaitGroup
	var pGroup sync.WaitGroup
	valAttackerState := attackerStateGetRead()
	var output uint32
	for _, a := range valAttackerState.known {
		aGroup.Add(1)
		go func(a value) {
			switch a.kind {
			case "constant":
				a = sanityResolveConstant(a.constant, valPrincipalState, false)
			}
			atomic.AddUint32(&output, verifyAnalysisResolve(a, valPrincipalState, valAttackerState, 0))
			atomic.AddUint32(&output, verifyAnalysisDecompose(a, valPrincipalState, valAttackerState, 0))
			atomic.AddUint32(&output, verifyAnalysisEquivalize(a, valPrincipalState, 0))
			aGroup.Done()
		}(a)
	}
	for _, a := range valPrincipalState.assigned {
		pGroup.Add(1)
		go func(a value) {
			atomic.AddUint32(&output, verifyAnalysisRecompose(a, valPrincipalState, valAttackerState, 0))
			atomic.AddUint32(&output, verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, 0))
			pGroup.Done()
		}(a)
	}
	aGroup.Wait()
	pGroup.Wait()
	verifyResolveQueries(valKnowledgeMap, valPrincipalState, valAttackerState)
	verifyAnalysisIncrementCount()
	prettyAnalysis(stage)
	if atomic.LoadUint32(&output) > 0 {
		sg.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, sg)
	}
	sg.Done()
}

func verifyAnalysisIncrementCount() {
	atomic.AddUint32(&verifyAnalysisCount, 1)
}

func verifyAnalysisGetCount() int {
	analysisCount := atomic.LoadUint32(&verifyAnalysisCount)
	return int(analysisCount)
}

func verifyAnalysisResolve(a value, valPrincipalState principalState, valAttackerState attackerState, obtained uint32) uint32 {
	lastObtained := obtained
	ii := sanityExactSameValueInValues(a, valAttackerState.known)
	if ii >= 0 {
		return obtained
	}
	output := []value{}
	switch a.kind {
	case "constant":
		output = append(output, a)
	case "primitive":
		for _, v := range valAttackerState.known {
			switch v.kind {
			case "constant":
				if sanityEquivalentValues(v, a, valPrincipalState) {
					output = append(output, v)
				}
			}
		}
		if len(output) != primitiveGet(a.primitive.name).output {
			return obtained
		}
	case "equation":
		output = append(output, a)
	}
	write := attackerStateWrite{
		known:     a,
		wire:      false,
		mutatedTo: []string{},
		resp:      make(chan bool),
	}
	if attackerStatePutWrite(write) {
		prettyMessage(fmt.Sprintf(
			"%s resolves to %s.",
			prettyValues(output), prettyValue(a),
		), "deduction")
		obtained = obtained + 1
	}
	if obtained > lastObtained {
		return verifyAnalysisResolve(a, valPrincipalState, valAttackerState, obtained)
	}
	return obtained
}

func verifyAnalysisDecompose(a value, valPrincipalState principalState, valAttackerState attackerState, obtained uint32) uint32 {
	var r bool
	var revealed value
	var ar []value
	lastObtained := obtained
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known:     revealed,
			wire:      false,
			mutatedTo: []string{},
			resp:      make(chan bool),
		}
		if attackerStatePutWrite(write) {
			prettyMessage(fmt.Sprintf(
				"%s obtained by decomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), "deduction")
			obtained = obtained + 1
		}
	}
	if obtained > lastObtained {
		return verifyAnalysisDecompose(a, valPrincipalState, valAttackerState, obtained)
	}
	return obtained
}

func verifyAnalysisRecompose(a value, valPrincipalState principalState, valAttackerState attackerState, obtained uint32) uint32 {
	var r bool
	var revealed value
	var ar []value
	lastObtained := obtained
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known:     revealed,
			wire:      false,
			mutatedTo: []string{},
			resp:      make(chan bool),
		}
		if attackerStatePutWrite(write) {
			prettyMessage(fmt.Sprintf(
				"%s obtained by recomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), "deduction")
			obtained = obtained + 1
		}
	}
	if obtained > lastObtained {
		return verifyAnalysisRecompose(a, valPrincipalState, valAttackerState, obtained)
	}
	return obtained
}

func verifyAnalysisReconstruct(a value, valPrincipalState principalState, valAttackerState attackerState, obtained uint32) uint32 {
	var r bool
	var ar []value
	lastObtained := obtained
	switch a.kind {
	case "primitive":
		r, ar = possibleToReconstructPrimitive(a.primitive, valPrincipalState, valAttackerState)
		for _, aa := range a.primitive.arguments {
			verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, obtained)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.equation, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known:     a,
			wire:      false,
			mutatedTo: []string{},
			resp:      make(chan bool),
		}
		if attackerStatePutWrite(write) {
			prettyMessage(fmt.Sprintf(
				"%s obtained by reconstructing with %s.",
				prettyValue(a), prettyValues(ar),
			), "deduction")
			obtained = obtained + 1
		}
	}
	if obtained > lastObtained {
		return verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, obtained)
	}
	return obtained
}

func verifyAnalysisEquivalize(a value, valPrincipalState principalState, obtained uint32) uint32 {
	lastObtained := obtained
	for _, c := range valPrincipalState.constants {
		aa := sanityResolveConstant(c, valPrincipalState, false)
		if sanityEquivalentValues(a, aa, valPrincipalState) {
			write := attackerStateWrite{
				known:     aa,
				wire:      false,
				mutatedTo: []string{},
				resp:      make(chan bool),
			}
			if attackerStatePutWrite(write) {
				obtained = obtained + 1
			}
		}
		switch aa.kind {
		case "primitive":
			for _, aaa := range aa.primitive.arguments {
				if sanityEquivalentValues(a, aaa, valPrincipalState) {
					write := attackerStateWrite{
						known:     aaa,
						wire:      false,
						mutatedTo: []string{},
						resp:      make(chan bool),
					}
					if attackerStatePutWrite(write) {
						obtained = obtained + 1
					}
				}
			}
		}
	}
	if obtained > lastObtained {
		return verifyAnalysisEquivalize(a, valPrincipalState, obtained)
	}
	return obtained
}
