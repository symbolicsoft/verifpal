/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bc668866bf7ad5972a2f8a9999e62fe7

package verifpal

import (
	"fmt"
)

func verifyAnalysis(valPrincipalState principalState, analysis int) {
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	for _, a := range valAttackerState.known {
		switch a.kind {
		case "constant":
			a = sanityResolveConstant(a.constant, valPrincipalState, false)
		}
		verifyAnalysisResolve(a, valPrincipalState, analysis)
		verifyAnalysisDecompose(a, valPrincipalState, analysis)
		verifyAnalysisEquivalize(a, valPrincipalState, analysis)
	}
	for _, a := range valPrincipalState.assigned {
		verifyAnalysisRecompose(a, valPrincipalState, analysis)
		verifyAnalysisReconstruct(a, valPrincipalState, analysis)
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysis(valPrincipalState, analysis)
	}
}

func verifyAnalysisResolve(a value, valPrincipalState principalState, analysis int) {
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	ii := sanityExactSameValueInValues(a, valAttackerState.known)
	if ii >= 0 {
		return
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
			return
		}
	case "equation":
		output = append(output, a)
	}
	prettyMessage(fmt.Sprintf(
		"%s resolves to %s.",
		prettyValues(output), prettyValue(a),
	), analysis, "deduction")
	write := attackerStateWrite{
		known:     a,
		wire:      false,
		mutatedTo: []string{},
		resp:      make(chan bool),
	}
	attackerStatePutWrite(write)
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysisResolve(a, valPrincipalState, analysis)
	}
}

func verifyAnalysisDecompose(a value, valPrincipalState principalState, analysis int) {
	var r bool
	var revealed value
	var ar []value
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToDecomposePrimitive(a.primitive, valPrincipalState, analysis)
	}
	if r {
		if sanityExactSameValueInValues(revealed, valAttackerState.known) < 0 {
			prettyMessage(fmt.Sprintf(
				"%s obtained by decomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), analysis, "deduction")
			write := attackerStateWrite{
				known:     revealed,
				wire:      false,
				mutatedTo: []string{},
				resp:      make(chan bool),
			}
			attackerStatePutWrite(write)
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysisDecompose(a, valPrincipalState, analysis)
	}
}

func verifyAnalysisRecompose(a value, valPrincipalState principalState, analysis int) {
	var r bool
	var revealed value
	var ar []value
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, revealed, ar = possibleToRecomposePrimitive(a.primitive, valPrincipalState, analysis)
	}
	if r {
		if sanityExactSameValueInValues(revealed, valAttackerState.known) < 0 {
			prettyMessage(fmt.Sprintf(
				"%s obtained by recomposing %s with %s.",
				prettyValue(revealed), prettyValue(a), prettyValues(ar),
			), analysis, "deduction")
			write := attackerStateWrite{
				known:     revealed,
				wire:      false,
				mutatedTo: []string{},
				resp:      make(chan bool),
			}
			attackerStatePutWrite(write)
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysisRecompose(a, valPrincipalState, analysis)
	}
}

func verifyAnalysisReconstruct(a value, valPrincipalState principalState, analysis int) {
	var r bool
	var ar []value
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	switch a.kind {
	case "primitive":
		r, ar = possibleToReconstructPrimitive(a.primitive, valPrincipalState, analysis)
		for _, aa := range a.primitive.arguments {
			verifyAnalysisReconstruct(aa, valPrincipalState, analysis)
		}
	case "equation":
		r, ar = possibleToReconstructEquation(a.equation, valPrincipalState)
	}
	if r {
		if sanityExactSameValueInValues(a, valAttackerState.known) < 0 {
			prettyMessage(fmt.Sprintf(
				"%s obtained by reconstructing with %s.",
				prettyValue(a), prettyValues(ar),
			), analysis, "deduction")
			write := attackerStateWrite{
				known:     a,
				wire:      false,
				mutatedTo: []string{},
				resp:      make(chan bool),
			}
			attackerStatePutWrite(write)
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysisReconstruct(a, valPrincipalState, analysis)
	}
}

func verifyAnalysisEquivalize(a value, valPrincipalState principalState, analysis int) {
	valAttackerState := attackerStateGetRead()
	valAttackerStateKnownInitLen := len(valAttackerState.known)
	for _, c := range valPrincipalState.constants {
		aa := sanityResolveConstant(c, valPrincipalState, false)
		if sanityEquivalentValues(a, aa, valPrincipalState) {
			if sanityExactSameValueInValues(aa, valAttackerState.known) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s obtained by equivalizing with %s.",
					prettyValue(aa), prettyValue(a),
				), analysis, "deduction")
				write := attackerStateWrite{
					known:     aa,
					wire:      false,
					mutatedTo: []string{},
					resp:      make(chan bool),
				}
				attackerStatePutWrite(write)
			}
		}
		valAttackerState = attackerStateGetRead()
		switch aa.kind {
		case "primitive":
			for _, aaa := range aa.primitive.arguments {
				if sanityEquivalentValues(a, aaa, valPrincipalState) {
					if sanityExactSameValueInValues(aaa, valAttackerState.known) < 0 {
						prettyMessage(fmt.Sprintf(
							"%s obtained by equivalizing with %s.",
							prettyValue(aaa), prettyValue(a),
						), analysis, "deduction")
						write := attackerStateWrite{
							known:     aaa,
							wire:      false,
							mutatedTo: []string{},
							resp:      make(chan bool),
						}
						attackerStatePutWrite(write)
					}
				}
			}
		}
	}
	if len(valAttackerState.known) > valAttackerStateKnownInitLen {
		verifyAnalysisEquivalize(a, valPrincipalState, analysis)
	}
}
