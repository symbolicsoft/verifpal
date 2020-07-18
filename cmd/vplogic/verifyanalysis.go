/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package vplogic

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var verifyAnalysisCount uint32

func verifyAnalysis(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
	valAttackerState AttackerState, stage int, scanGroup *sync.WaitGroup,
) {
	o := 0
	for _, a := range valAttackerState.Known {
		o = o + verifyAnalysisDecompose(a, valPrincipalState, valAttackerState)
		if o > 0 {
			break
		}
	}
	for _, a := range valPrincipalState.Assigned {
		o = o + verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, 0)
		if o > 0 {
			break
		}
		o = o + verifyAnalysisRecompose(a, valAttackerState)
		if o > 0 {
			break
		}
	}
	for _, a := range valAttackerState.Known {
		o = o + verifyAnalysisEquivalize(a, valPrincipalState)
		if o > 0 {
			break
		}
		o = o + verifyAnalysisPasswords(a, valPrincipalState)
		if o > 0 {
			break
		}
		o = o + verifyAnalysisConcat(a)
		if o > 0 {
			break
		}
	}
	if o > 0 {
		valAttackerState = attackerStateGetRead()
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, valAttackerState, stage, scanGroup)
	} else {
		verifyAnalysisCountIncrement()
		infoAnalysis(stage)
		verifyResolveQueries(valKnowledgeMap, valPrincipalState)
		scanGroup.Done()
	}
}

func verifyAnalysisCountInit() {
	atomic.StoreUint32(&verifyAnalysisCount, uint32(0))
}

func verifyAnalysisCountIncrement() {
	atomic.AddUint32(&verifyAnalysisCount, 1)
}

func verifyAnalysisCountGet() int {
	return int(atomic.LoadUint32(&verifyAnalysisCount))
}

func verifyAnalysisDecompose(
	a Value, valPrincipalState PrincipalState, valAttackerState AttackerState,
) int {
	o := 0
	r := false
	revealed := Value{}
	ar := []Value{}
	switch a.Kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.Primitive, valPrincipalState, valAttackerState)
	}
	if r && attackerStatePutWrite(revealed) {
		InfoMessage(fmt.Sprintf(
			"%s obtained by decomposing %s with %s.",
			infoOutputText(revealed), prettyValue(a), prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisRecompose(
	a Value, valAttackerState AttackerState,
) int {
	o := 0
	r := false
	revealed := Value{}
	ar := []Value{}
	switch a.Kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.Primitive, valAttackerState)
	}
	if r && attackerStatePutWrite(revealed) {
		InfoMessage(fmt.Sprintf(
			"%s obtained by recomposing %s with %s.",
			infoOutputText(revealed), prettyValue(a), prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisReconstruct(
	a Value, valPrincipalState PrincipalState, valAttackerState AttackerState, o int,
) int {
	r := false
	ar := []Value{}
	isCorePrim := false
	switch a.Kind {
	case "primitive":
		isCorePrim = primitiveIsCorePrim(a.Primitive.Name)
		r, ar = possibleToReconstructPrimitive(a.Primitive, valPrincipalState, valAttackerState)
		for _, aa := range a.Primitive.Arguments {
			o = o + verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, o)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.Equation, valAttackerState)
	}
	if r && !isCorePrim && attackerStatePutWrite(a) {
		InfoMessage(fmt.Sprintf(
			"%s obtained by reconstructing with %s.",
			infoOutputText(a), prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisEquivalize(a Value, valPrincipalState PrincipalState) int {
	o := 0
	ar := a
	switch a.Kind {
	case "constant":
		ar, _ = valueResolveConstant(a.Constant, valPrincipalState)
	}
	for _, aa := range valPrincipalState.Assigned {
		if valueEquivalentValues(ar, aa, true) {
			if attackerStatePutWrite(aa) {
				InfoMessage(fmt.Sprintf(
					"%s obtained by equivalizing with the current resolution of %s.",
					infoOutputText(aa), prettyValue(a),
				), "deduction", true)
				o = o + 1
			}
		}
	}
	return o
}

func verifyAnalysisPasswords(a Value, valPrincipalState PrincipalState) int {
	o := 0
	passwords := possibleToObtainPasswords(a, a, -1, valPrincipalState)
	for _, revealed := range passwords {
		if attackerStatePutWrite(revealed) {
			InfoMessage(fmt.Sprintf(
				"%s obtained as a password unsafely used within %s.",
				infoOutputText(revealed), prettyValue(a),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisConcat(a Value) int {
	o := 0
	switch a.Kind {
	case "primitive":
		switch a.Primitive.Name {
		case "CONCAT":
			for _, revealed := range a.Primitive.Arguments {
				if attackerStatePutWrite(revealed) {
					InfoMessage(fmt.Sprintf(
						"%s obtained as a concatenated fragment of %s.",
						infoOutputText(revealed), prettyValue(a),
					), "deduction", true)
					o = o + 1
				}
			}
		}
	}
	return o
}
