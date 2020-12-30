/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
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
) error {
	o := 0
	err := verifyResolveQueries(valKnowledgeMap, valPrincipalState)
	if err != nil {
		return err
	}
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
		o = o + verifyAnalysisRecompose(a, valPrincipalState, valAttackerState)
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
		o = o + verifyAnalysisConcat(a, valPrincipalState)
		if o > 0 {
			break
		}
	}
	if o > 0 {
		valAttackerState = attackerStateGetRead()
		go func() {
			err := verifyAnalysis(valKnowledgeMap, valPrincipalState, valAttackerState, stage, scanGroup)
			if err != nil {
				scanGroup.Done()
			}
		}()
	} else {
		verifyAnalysisCountIncrement()
		infoAnalysis(stage)
		scanGroup.Done()
	}
	return nil
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
	case typesEnumPrimitive:
		r, revealed, ar = possibleToDecomposePrimitive(a.Primitive, valPrincipalState, valAttackerState)
	}
	if r && attackerStatePutWrite(revealed, valPrincipalState) {
		InfoMessage(fmt.Sprintf(
			"%s obtained by decomposing %s with %s.",
			infoOutputText(revealed), prettyValue(a), prettyValues(ar),
		), "deduction", true)
		o = o + 1
	}
	return o
}

func verifyAnalysisRecompose(
	a Value, valPrincipalState PrincipalState, valAttackerState AttackerState,
) int {
	o := 0
	r := false
	revealed := Value{}
	ar := []Value{}
	switch a.Kind {
	case typesEnumPrimitive:
		r, revealed, ar = possibleToRecomposePrimitive(a.Primitive, valAttackerState)
	}
	if r && attackerStatePutWrite(revealed, valPrincipalState) {
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
	switch a.Kind {
	case typesEnumPrimitive:
		r, ar = possibleToReconstructPrimitive(a.Primitive, valPrincipalState, valAttackerState)
		for _, aa := range a.Primitive.Arguments {
			o = o + verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, o)
		}
	case typesEnumEquation:
		r, ar = possibleToReconstructEquation(a.Equation, valAttackerState)
	}
	if r && attackerStatePutWrite(a, valPrincipalState) {
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
	case typesEnumConstant:
		ar, _ = valueResolveConstant(a.Constant, valPrincipalState)
	}
	for _, aa := range valPrincipalState.Assigned {
		if valueEquivalentValues(&ar, &aa, true) {
			if attackerStatePutWrite(aa, valPrincipalState) {
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
		if attackerStatePutWrite(revealed, valPrincipalState) {
			InfoMessage(fmt.Sprintf(
				"%s obtained as a password unsafely used within %s.",
				infoOutputText(revealed), prettyValue(a),
			), "deduction", true)
			o = o + 1
		}
	}
	return o
}

func verifyAnalysisConcat(a Value, valPrincipalState PrincipalState) int {
	o := 0
	switch a.Kind {
	case typesEnumPrimitive:
		switch a.Primitive.ID {
		case primitiveEnumCONCAT:
			for _, revealed := range a.Primitive.Arguments {
				if attackerStatePutWrite(revealed, valPrincipalState) {
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
