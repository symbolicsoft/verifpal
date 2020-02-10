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
	var o int
	valAttackerState := attackerStateGetRead()
	for _, a := range valAttackerState.known {
		switch a.kind {
		case "constant":
			a = sanityResolveConstant(a.constant, valPrincipalState)
		}
		o = o + verifyAnalysisDecompose(a, valPrincipalState, valAttackerState, 0)
		o = o + verifyAnalysisEquivalize(a, valPrincipalState, 0)
		o = o + verifyAnalysisPasswords(a, valPrincipalState, 0)
	}
	for _, a := range valPrincipalState.assigned {
		o = o + verifyAnalysisRecompose(a, valPrincipalState, valAttackerState, 0)
		o = o + verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, 0)
	}
	verifyResolveQueries(valKnowledgeMap, valPrincipalState, valAttackerState)
	verifyAnalysisCountIncrement()
	prettyAnalysis(stage)
	if o > 0 {
		sg.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, sg)
	}
	sg.Done()
}

func verifyAnalysisCountInit() {
	analysisCount := atomic.LoadUint32(&verifyAnalysisCount)
	atomic.AddUint32(&verifyAnalysisCount, -analysisCount)
}

func verifyAnalysisCountIncrement() {
	atomic.AddUint32(&verifyAnalysisCount, 1)
}

func verifyAnalysisCountGet() int {
	return int(atomic.LoadUint32(&verifyAnalysisCount))
}

func verifyAnalysisDecompose(
	a value, valPrincipalState principalState, valAttackerState attackerState, o int,
) int {
	var r bool
	var revealed value
	var ar []value
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known: revealed,
		}
		if attackerStatePutWrite(write) {
			PrettyMessage(fmt.Sprintf(
				"%s obtained by decomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisRecompose(
	a value, valPrincipalState principalState, valAttackerState attackerState, o int,
) int {
	var r bool
	var revealed value
	var ar []value
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known: revealed,
		}
		if attackerStatePutWrite(write) {
			PrettyMessage(fmt.Sprintf(
				"%s obtained by recomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisReconstruct(
	a value, valPrincipalState principalState, valAttackerState attackerState, o int,
) int {
	var r bool
	var ar []value
	switch a.kind {
	case "primitive":
		r, ar = possibleToReconstructPrimitive(a.primitive, valPrincipalState, valAttackerState)
		for _, aa := range a.primitive.arguments {
			verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, o)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.equation, valPrincipalState, valAttackerState)
	}
	if r {
		write := attackerStateWrite{
			known: a,
		}
		if attackerStatePutWrite(write) {
			PrettyMessage(fmt.Sprintf(
				"%s obtained by reconstructing with %s.",
				prettyValue(a), prettyValues(ar),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisEquivalize(a value, valPrincipalState principalState, o int) int {
	for _, aa := range valPrincipalState.assigned {
		if sanityEquivalentValues(a, aa, valPrincipalState) {
			write := attackerStateWrite{
				known: aa,
			}
			if attackerStatePutWrite(write) {
				o = o + 1
			}
		}
		switch aa.kind {
		case "primitive":
			for _, aaa := range aa.primitive.arguments {
				if sanityEquivalentValues(a, aaa, valPrincipalState) {
					write := attackerStateWrite{
						known: aaa,
					}
					if attackerStatePutWrite(write) {
						o = o + 1
					}
				}
			}
		}
	}
	return o
}

func verifyAnalysisPasswords(a value, valPrincipalState principalState, o int) int {
	passwords := possibleToObtainPasswords(a, valPrincipalState)
	for _, password := range passwords {
		write := attackerStateWrite{
			known: password,
		}
		if attackerStatePutWrite(write) {
			PrettyMessage(fmt.Sprintf(
				"%s obtained as a password unsafely used within %s.",
				prettyValue(password), prettyValue(a),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}
