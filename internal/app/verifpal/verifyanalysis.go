/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package main

import (
	"fmt"
)

func verifyAnalysis(model *verifpal, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	for _, a := range valAttackerState.known {
		depth = verifyAnalysisResolve(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisDeconstruct(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, analysis, depth)
		depth = verifyAnalysisEquivocate(a, valPrincipalState, valAttackerState, analysis, depth)
	}
	for _, c := range valPrincipalState.constants {
		a := sanityResolveConstant(valPrincipalState, c, false)
		depth = verifyAnalysisReconstruct(a, valPrincipalState, valAttackerState, analysis, depth)
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysis(model, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisResolve(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "constant":
		a = sanityResolveConstant(valPrincipalState, a.constant, false)
	}
	ii := sanityExactSameValueInValues(a, &valAttackerState.known)
	if ii >= 0 {
		return depth
	}
	resolved, _ := sanityResolveInternalValues(a, valPrincipalState, false)
	output := []value{}
	switch resolved.kind {
	case "constant":
		output = append(output, a)
	case "primitive":
		for _, v := range valAttackerState.known {
			switch v.kind {
			case "constant":
				if sanityEquivalentValues(v, resolved, false, false, valPrincipalState) {
					output = append(output, v)
				}
			}
		}
		if len(output) != primitiveGet(resolved.primitive.name).output {
			return depth
		}
	case "equation":
		output = append(output, a)
	}
	if sanityExactSameValueInValues(resolved, &valAttackerState.known) < 0 {
		if sanityExactSameValueInValues(resolved, &valAttackerState.conceivable) < 0 {
			prettyMessage(fmt.Sprintf(
				"%s resolves to %s",
				prettyValues(output), prettyValue(resolved),
			), analysis, depth, "deduction")
			valAttackerState.conceivable = append(valAttackerState.conceivable, resolved)
		}
		valAttackerState.known = append(valAttackerState.known, resolved)
		valAttackerState.wire = append(valAttackerState.wire, false)
		valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisResolve(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisDeconstruct(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	var r bool
	var revealed value
	var ar []value
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "constant":
		a = sanityResolveConstant(valPrincipalState, a.constant, false)
	}
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToDeconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
		revealed, _ = sanityResolveInternalValues(revealed, valPrincipalState, false)
	}
	if r {
		if sanityExactSameValueInValues(revealed, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(revealed, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s found by attacker by deconstructing %s with %s",
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
		depth = verifyAnalysisDeconstruct(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisReconstruct(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	var r bool
	var ar []value
	a, _ = sanityResolveInternalValues(a, valPrincipalState, false)
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	aBackup := a
	switch a.kind {
	case "constant":
		a = sanityResolveConstant(valPrincipalState, a.constant, false)
	}
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
		if sanityExactSameValueInValues(aBackup, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(aBackup, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s found by attacker by reconstructing with %s",
					prettyValue(aBackup), prettyValues(ar),
				), analysis, depth, "deduction")
				valAttackerState.conceivable = append(valAttackerState.conceivable, a)
			}
			valAttackerState.known = append(valAttackerState.known, a)
			valAttackerState.wire = append(valAttackerState.wire, false)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		depth = verifyAnalysisReconstruct(aBackup, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}

func verifyAnalysisEquivocate(a value, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) int {
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	aBackup := a
	a, _ = sanityResolveInternalValues(a, valPrincipalState, false)
	for _, c := range valPrincipalState.constants {
		aa := sanityResolveConstant(valPrincipalState, c, false)
		aa, _ = sanityResolveInternalValues(aa, valPrincipalState, false)
		if sanityEquivalentValues(a, aa, false, false, valPrincipalState) {
			if sanityExactSameValueInValues(aa, &valAttackerState.known) < 0 {
				if sanityExactSameValueInValues(aa, &valAttackerState.conceivable) < 0 {
					prettyMessage(fmt.Sprintf(
						"%s found by attacker by equivocating with %s",
						prettyValue(aa), prettyValue(aBackup),
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
				aaa, _ := sanityResolveInternalValues(aaa, valPrincipalState, false)
				if sanityEquivalentValues(a, aaa, false, false, valPrincipalState) {
					if sanityExactSameValueInValues(aaa, &valAttackerState.known) < 0 {
						if sanityExactSameValueInValues(aaa, &valAttackerState.conceivable) < 0 {
							prettyMessage(fmt.Sprintf(
								"%s found by attacker by equivocating with %s",
								prettyValue(aaa), prettyValue(aBackup),
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
		depth = verifyAnalysisEquivocate(a, valPrincipalState, valAttackerState, analysis, depth+1)
	}
	return depth
}
