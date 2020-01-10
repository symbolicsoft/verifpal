/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package verifpal

import (
	"fmt"
)

func verifyAnalysis(m *Model, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	for _, a := range valAttackerState.known {
		switch a.kind {
		case "constant":
			a = sanityResolveConstant(a.constant, valPrincipalState, false)
		}
		depth = verifyAnalysisResolve(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisDecompose(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisEquivalize(a, valPrincipalState, valAttackerState, analysis, depth)
	}
	for _, a := range valPrincipalState.assigned {
		depth = verifyAnalysisRecompose(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, analysis, depth)
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysis(m, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisResolve(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	ii := sanityExactSameValueInValues(a, &valAttackerState.known)
	if ii >= 0 {
		return depth
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
			return depth
		}
	case "equation":
		output = append(output, a)
	}
	if sanityExactSameValueInValues(a, &valAttackerState.conceivable) < 0 {
		prettyMessage(fmt.Sprintf(
			"%s resolves to %s.",
			prettyValues(output), prettyValue(a),
		), analysis, depth, "deduction")
		valAttackerState.conceivable = append(valAttackerState.conceivable, a)
	}
	valAttackerState.known = append(valAttackerState.known, a)
	valAttackerState.wire = append(valAttackerState.wire, false)
	valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisResolve(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisDecompose(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	var r bool
	var revealed value
	var ar []value
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
	}
	if r {
		if sanityExactSameValueInValues(revealed, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(revealed, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s obtained by decomposing %s with %s.",
					prettyValue(revealed), prettyValue(a), prettyValues(ar),
				), analysis, depth, "deduction")
				valAttackerState.conceivable = append(valAttackerState.conceivable, revealed)
			}
			valAttackerState.known = append(valAttackerState.known, revealed)
			valAttackerState.wire = append(valAttackerState.wire, false)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisDecompose(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisRecompose(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	var r bool
	var revealed value
	var ar []value
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
	}
	if r {
		if sanityExactSameValueInValues(revealed, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(revealed, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s obtained by recomposing %s with %s.",
					prettyValue(revealed), prettyValue(a), prettyValues(ar),
				), analysis, depth, "deduction")
				valAttackerState.conceivable = append(valAttackerState.conceivable, revealed)
			}
			valAttackerState.known = append(valAttackerState.known, revealed)
			valAttackerState.wire = append(valAttackerState.wire, false)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisRecompose(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisReconstruct(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	var r bool
	var ar []value
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, ar = possibleToReconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
		for _, aa := range a.primitive.arguments {
			verifyAnalysisReconstruct(aa, valPrincipalState, valAttackerState, analysis, depth)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.equation, valAttackerState, valPrincipalState)
	}
	if r {
		if sanityExactSameValueInValues(a, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(a, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s obtained by reconstructing with %s.",
					prettyValue(a), prettyValues(ar),
				), analysis, depth, "deduction")
				valAttackerState.conceivable = append(valAttackerState.conceivable, a)
			}
			valAttackerState.known = append(valAttackerState.known, a)
			valAttackerState.wire = append(valAttackerState.wire, false)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisEquivalize(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	for _, c := range valPrincipalState.constants {
		aa := sanityResolveConstant(c, valPrincipalState, false)
		if sanityEquivalentValues(a, aa, valPrincipalState) {
			if sanityExactSameValueInValues(aa, &valAttackerState.known) < 0 {
				if sanityExactSameValueInValues(aa, &valAttackerState.conceivable) < 0 {
					prettyMessage(fmt.Sprintf(
						"%s obtained by equivalizing with %s.",
						prettyValue(aa), prettyValue(a),
					), analysis, depth, "deduction")
					valAttackerState.conceivable = append(valAttackerState.conceivable, aa)
				}
				valAttackerState.known = append(valAttackerState.known, aa)
				valAttackerState.wire = append(valAttackerState.wire, false)
				valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
			}
		}
		switch aa.kind {
		case "primitive":
			for _, aaa := range aa.primitive.arguments {
				if sanityEquivalentValues(a, aaa, valPrincipalState) {
					if sanityExactSameValueInValues(aaa, &valAttackerState.known) < 0 {
						if sanityExactSameValueInValues(aaa, &valAttackerState.conceivable) < 0 {
							prettyMessage(fmt.Sprintf(
								"%s obtained by equivalizing with %s.",
								prettyValue(aaa), prettyValue(a),
							), analysis, depth, "deduction")
							valAttackerState.conceivable = append(valAttackerState.conceivable, aaa)
						}
						valAttackerState.known = append(valAttackerState.known, aaa)
						valAttackerState.wire = append(valAttackerState.wire, false)
						valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
					}
				}
			}
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisEquivalize(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}
