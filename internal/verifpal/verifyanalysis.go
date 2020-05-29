/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package verifpal

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

var verifyAnalysisCount uint32

func verifyAnalysis(valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState, stage int, sg *sync.WaitGroup) {
	o := 0
	valAttackerState := attackerStateGetRead()
	for _, a := range valAttackerState.Known {
		o = o + verifyAnalysisDecompose(a, valAttackerState, 0)
		o = o + verifyAnalysisEquivalize(a, valPrincipalState, 0)
		o = o + verifyAnalysisPasswords(a, valPrincipalState, 0)
		o = o + verifyAnalysisConcat(a, 0)
	}
	for _, a := range valPrincipalState.Assigned {
		o = o + verifyAnalysisRecompose(a, valAttackerState, 0)
		o = o + verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, 0)
	}
	verifyResolveQueries(valKnowledgeMap, valPrincipalState)
	verifyAnalysisCountIncrement()
	infoAnalysis(stage)
	if o > 0 {
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, sg)
	} else {
		sg.Done()
	}
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
	a Value, valAttackerState AttackerState, o int,
) int {
	r := false
	revealed := Value{}
	ar := []Value{}
	switch a.Kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.Primitive, valAttackerState)
	}
	if !r {
		return o
	}
	if attackerStatePutWrite(revealed) {
		valueText := prettyValue(revealed)
		if revealed.Kind == "primitive" {
			valueText = fmt.Sprintf(
				"%s output of %s",
				strings.Title(infoLiteralNumber(revealed.Primitive.Output)),
				valueText,
			)
		}
		InfoMessage(fmt.Sprintf(
			"%s obtained by decomposing %s with %s.",
			valueText, prettyValue(a), prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisRecompose(
	a Value, valAttackerState AttackerState, o int,
) int {
	r := false
	revealed := Value{}
	ar := []Value{}
	switch a.Kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.Primitive, valAttackerState)
	}
	if !r {
		return o
	}
	if attackerStatePutWrite(revealed) {
		valueText := prettyValue(revealed)
		if revealed.Kind == "primitive" {
			valueText = fmt.Sprintf(
				"%s output of %s",
				strings.Title(infoLiteralNumber(revealed.Primitive.Output)),
				valueText,
			)
		}
		InfoMessage(fmt.Sprintf(
			"%s obtained by recomposing %s with %s.",
			valueText, prettyValue(a), prettyValues(ar),
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
	switch a.Kind {
	case "primitive":
		r, ar = possibleToReconstructPrimitive(a.Primitive, valAttackerState)
		for _, aa := range a.Primitive.Arguments {
			verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, o)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.Equation, valAttackerState)
	}
	if !r {
		return o
	}
	if attackerStatePutWrite(a) {
		valueText := prettyValue(a)
		if a.Kind == "primitve" {
			valueText = fmt.Sprintf(
				"%s output of %s",
				strings.Title(infoLiteralNumber(a.Primitive.Output)),
				valueText,
			)
		}
		InfoMessage(fmt.Sprintf(
			"%s obtained by reconstructing with %s.",
			valueText, prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisEquivalize(a Value, valPrincipalState PrincipalState, o int) int {
	switch a.Kind {
	case "constant":
		a = valueResolveConstant(a.Constant, valPrincipalState)
	}
	for _, aa := range valPrincipalState.Assigned {
		if valueEquivalentValues(a, aa, true) {
			if attackerStatePutWrite(aa) {
				o = o + 1
			}
		}
	}
	return o
}

func verifyAnalysisPasswords(a Value, valPrincipalState PrincipalState, o int) int {
	passwords := possibleToObtainPasswords(a, a, -1, valPrincipalState)
	for _, revealed := range passwords {
		if attackerStatePutWrite(revealed) {
			InfoMessage(fmt.Sprintf(
				"%s obtained as a password unsafely used within %s.",
				prettyValue(revealed), prettyValue(a),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisConcat(a Value, o int) int {
	switch a.Kind {
	case "primitive":
		switch a.Primitive.Name {
		case "CONCAT":
			for _, revealed := range a.Primitive.Arguments {
				if attackerStatePutWrite(revealed) {
					InfoMessage(fmt.Sprintf(
						"%s obtained as a concatenated fragment of %s.",
						prettyValue(revealed), prettyValue(a),
					), "deduction", true)
					o = o + 1
				}
			}
		}
	}
	return o
}
