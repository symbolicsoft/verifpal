/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import "strings"

var valueG = Value{
	Kind: "constant",
	Constant: Constant{
		Name:        "g",
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: "knows",
		Qualifier:   "public",
	},
}

var valueN = Value{
	Kind: "constant",
	Constant: Constant{
		Name:        "nil",
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: "knows",
		Qualifier:   "public",
	},
}

var valueGN = Value{
	Kind: "equation",
	Equation: Equation{
		Values: []Value{valueG, valueN},
	},
}

func valueIsGOrNil(c Constant) bool {
	switch strings.ToLower(c.Name) {
	case "g", "nil":
		return true
	}
	return false
}

func valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap KnowledgeMap, c Constant) int {
	for i := range valKnowledgeMap.Constants {
		if valKnowledgeMap.Constants[i].Name == c.Name {
			return i
		}
	}
	return -1
}

func valueGetPrincipalStateIndexFromConstant(valPrincipalState PrincipalState, c Constant) int {
	for i := range valPrincipalState.Constants {
		if valPrincipalState.Constants[i].Name == c.Name {
			return i
		}
	}
	return -1
}

func valueGetConstantsFromValue(v Value) []Constant {
	c := []Constant{}
	switch v.Kind {
	case "constant":
		c = append(c, v.Constant)
	case "primitive":
		c = append(c, valueGetConstantsFromPrimitive(v.Primitive)...)
	case "equation":
		c = append(c, valueGetConstantsFromEquation(v.Equation)...)
	}
	return c
}

func valueGetConstantsFromPrimitive(p Primitive) []Constant {
	c := []Constant{}
	for _, a := range p.Arguments {
		switch a.Kind {
		case "constant":
			c = append(c, a.Constant)
		case "primitive":
			c = append(c, valueGetConstantsFromPrimitive(a.Primitive)...)
		case "equation":
			c = append(c, valueGetConstantsFromEquation(a.Equation)...)
		}
	}
	return c
}

func valueGetConstantsFromEquation(e Equation) []Constant {
	c := []Constant{}
	for _, a := range e.Values {
		switch a.Kind {
		case "constant":
			c = append(c, a.Constant)
		case "primitive":
			c = append(c, valueGetConstantsFromPrimitive(a.Primitive)...)
		case "equation":
			c = append(c, valueGetConstantsFromEquation(a.Equation)...)
		}
	}
	return c
}

func valueEquivalentValues(a1 Value, a2 Value, considerOutput bool) bool {
	switch a1.Kind {
	case "constant":
		switch a2.Kind {
		case "constant":
			if a1.Constant.Name != a2.Constant.Name {
				return false
			}
		case "primitive":
			return false
		case "equation":
			return false
		}
	case "primitive":
		switch a2.Kind {
		case "constant":
			return false
		case "primitive":
			equivPrim, _, _ := valueEquivalentPrimitives(
				a1.Primitive, a2.Primitive, considerOutput,
			)
			return equivPrim
		case "equation":
			return false
		}
	case "equation":
		switch a2.Kind {
		case "constant":
			return false
		case "primitive":
			return false
		case "equation":
			return valueEquivalentEquations(
				a1.Equation, a2.Equation,
			)
		}
	}
	return true
}

func valueEquivalentPrimitives(
	p1 Primitive, p2 Primitive, considerOutput bool,
) (bool, int, int) {
	if p1.Name != p2.Name {
		return false, 0, 0
	}
	if len(p1.Arguments) != len(p2.Arguments) {
		return false, 0, 0
	}
	if considerOutput && (p1.Output != p2.Output) {
		return false, 0, 0
	}
	for i := range p1.Arguments {
		equiv := valueEquivalentValues(p1.Arguments[i], p2.Arguments[i], true)
		if !equiv {
			return false, 0, 0
		}
	}
	return true, p1.Output, p2.Output
}

func valueEquivalentEquations(e1 Equation, e2 Equation) bool {
	e1Base := e1.Values[0].Equation.Values
	e2Base := e2.Values[0].Equation.Values
	e1Kind := e1.Values[0].Kind
	e2Kind := e2.Values[0].Kind
	switch {
	case len(e1.Values) != len(e2.Values), len(e1.Values) == 0:
		return false
	case e1Kind == "equation" && e2Kind == "equation":
		return valueEquivalentEquationsRule(
			e1Base[1], e2Base[1], e1.Values[1], e2.Values[1],
		) || valueEquivalentEquationsRule(
			e1Base[1], e2.Values[1], e1.Values[1], e2Base[1],
		)
	case len(e1.Values) > 2:
		return valueEquivalentEquationsRule(
			e1.Values[1], e2.Values[1], e1.Values[2], e2.Values[2],
		) || valueEquivalentEquationsRule(
			e1.Values[1], e2.Values[2], e1.Values[2], e2.Values[1],
		)
	default:
		return valueEquivalentEquationsRule(
			e1.Values[0], e2.Values[1], e1.Values[1], e2.Values[0],
		)
	}
}

func valueEquivalentEquationsRule(base1 Value, base2 Value, exp1 Value, exp2 Value) bool {
	return (valueEquivalentValues(base1, exp2, true) &&
		valueEquivalentValues(exp1, base2, true))
}

func valueFindConstantInPrimitive(
	c Constant, p Primitive, valPrincipalState PrincipalState,
) bool {
	a := valueResolveConstant(c, valPrincipalState)
	for _, aa := range p.Arguments {
		switch aa.Kind {
		case "constant":
			if c.Name == aa.Constant.Name {
				return true
			}
			switch a.Kind {
			case "constant":
				if a.Constant.Name == aa.Constant.Name {
					return true
				}
			}
		case "primitive":
			switch a.Kind {
			case "primitive":
				equivPrim, _, _ := valueEquivalentPrimitives(
					a.Primitive, aa.Primitive, true,
				)
				if equivPrim {
					return true
				}
			}
			if valueFindConstantInPrimitive(c, aa.Primitive, valPrincipalState) {
				return true
			}
		case "equation":
			if valueFindConstantInEquation(c, aa.Equation, valPrincipalState) {
				return true
			}
		}
	}
	return false
}

func valueFindConstantInEquation(
	c Constant, e Equation, valPrincipalState PrincipalState,
) bool {
	a := valueResolveConstant(c, valPrincipalState)
	switch a.Kind {
	case "equation":
		if valueEquivalentEquations(a.Equation, e) {
			return true
		}
	}
	for _, ee := range e.Values {
		switch ee.Kind {
		case "constant":
			if c.Name == ee.Constant.Name {
				return true
			}
			switch a.Kind {
			case "constant":
				if a.Constant.Name == ee.Constant.Name {
					return true
				}
			}
		}
	}
	return false
}

func valueEquivalentValueInValues(v Value, a []Value) int {
	index := -1
	for i, aa := range a {
		if valueEquivalentValues(v, aa, true) {
			index = i
			break
		}
	}
	return index
}

func valuePerformPrimitiveRebuild(
	rewrites []Value, rIndex int, pi int,
	rebuild Value, valPrincipalState PrincipalState,
) []Value {
	rewrites[rIndex] = rebuild
	if pi >= 0 {
		valPrincipalState.Assigned[pi] = rebuild
		if !valPrincipalState.Mutated[pi] {
			valPrincipalState.BeforeMutate[pi] = rebuild
		}
	}
	return rewrites
}

func valuePerformPrimitiveRewrite(
	p Primitive, pi int, valPrincipalState PrincipalState,
) ([]Primitive, bool, Value) {
	rIndex := 0
	rewrites, failedRewrites, rewritten := valuePerformPrimitiveArgumentsRewrite(
		p, rIndex, valPrincipalState,
	)
	rebuilt, rebuild := possibleToRebuild(rewrites[rIndex].Primitive)
	if rebuilt {
		rewrites = valuePerformPrimitiveRebuild(
			rewrites, rIndex, pi, rebuild, valPrincipalState,
		)
		switch rebuild.Kind {
		case "constant", "equation":
			return failedRewrites, rewritten, rewrites[rIndex]
		}
	}
	rewrittenRoot, rewrites := possibleToRewrite(
		rewrites[rIndex].Primitive, valPrincipalState,
	)
	if !rewrittenRoot {
		failedRewrites = append(failedRewrites, rewrites[rIndex].Primitive)
	} else if primitiveIsCorePrim(p.Name) {
		rIndex = p.Output
	}
	if (rewritten || rewrittenRoot) && pi >= 0 {
		valPrincipalState.Rewritten[pi] = true
		valPrincipalState.Assigned[pi] = rewrites[rIndex]
		if !valPrincipalState.Mutated[pi] {
			valPrincipalState.BeforeMutate[pi] = rewrites[rIndex]
		}
	}
	return failedRewrites, (rewritten || rewrittenRoot), rewrites[rIndex]
}

func valuePerformPrimitiveArgumentsRewrite(
	p Primitive, rIndex int, valPrincipalState PrincipalState,
) ([]Value, []Primitive, bool) {
	rewrites := []Value{{
		Kind: "primitive",
		Primitive: Primitive{
			Name:      p.Name,
			Arguments: make([]Value, len(p.Arguments)),
			Output:    p.Output,
			Check:     p.Check,
		},
	}}
	failedRewrites := []Primitive{}
	rewritten := false
	for i, a := range p.Arguments {
		switch a.Kind {
		case "constant":
			rewrites[rIndex].Primitive.Arguments[i] = p.Arguments[i]
		case "primitive":
			pFailedRewrite, pRewritten, pRewrite := valuePerformPrimitiveRewrite(
				a.Primitive, -1, valPrincipalState,
			)
			if pRewritten {
				rewritten = true
				rewrites[rIndex].Primitive.Arguments[i] = pRewrite
				continue
			}
			rewrites[rIndex].Primitive.Arguments[i] = p.Arguments[i]
			failedRewrites = append(failedRewrites, pFailedRewrite...)
		case "equation":
			eFailedRewrite, eRewritten, eRewrite := valuePerformEquationRewrite(
				a.Equation, -1, valPrincipalState,
			)
			if eRewritten {
				rewritten = true
				rewrites[rIndex].Primitive.Arguments[i] = eRewrite
				continue
			}
			rewrites[rIndex].Primitive.Arguments[i] = p.Arguments[i]
			failedRewrites = append(failedRewrites, eFailedRewrite...)
		}
	}
	return rewrites, failedRewrites, rewritten
}

func valuePerformEquationRewrite(
	e Equation, pi int, valPrincipalState PrincipalState,
) ([]Primitive, bool, Value) {
	rewritten := false
	failedRewrites := []Primitive{}
	rewrite := Value{
		Kind: "equation",
		Equation: Equation{
			Values: []Value{},
		},
	}
	for i, a := range e.Values {
		switch a.Kind {
		case "constant":
			rewrite.Equation.Values = append(rewrite.Equation.Values, a)
		case "primitive":
			hasRule := false
			if primitiveIsCorePrim(a.Primitive.Name) {
				prim, _ := primitiveCoreGet(a.Primitive.Name)
				hasRule = prim.HasRule
			} else {
				prim, _ := primitiveGet(a.Primitive.Name)
				hasRule = prim.Rewrite.HasRule
			}
			if !hasRule {
				continue
			}
			pFailedRewrite, pRewritten, pRewrite := valuePerformPrimitiveRewrite(
				a.Primitive, -1, valPrincipalState,
			)
			if !pRewritten {
				rewrite.Equation.Values = append(rewrite.Equation.Values, e.Values[i])
				failedRewrites = append(failedRewrites, pFailedRewrite...)
				continue
			}
			rewritten = true
			switch pRewrite.Kind {
			case "constant":
				rewrite.Equation.Values = append(rewrite.Equation.Values, pRewrite)
			case "primitive":
				rewrite.Equation.Values = append(rewrite.Equation.Values, pRewrite)
			case "equation":
				rewrite.Equation.Values = append(rewrite.Equation.Values, pRewrite.Equation.Values...)
			}
		case "equation":
			eFailedRewrite, eRewritten, eRewrite := valuePerformEquationRewrite(
				a.Equation, -1, valPrincipalState,
			)
			if !eRewritten {
				rewrite.Equation.Values = append(rewrite.Equation.Values, e.Values[i])
				failedRewrites = append(failedRewrites, eFailedRewrite...)
				continue
			}
			rewritten = true
			rewrite.Equation.Values = append(rewrite.Equation.Values, eRewrite)
		}
	}
	if rewritten && pi >= 0 {
		valPrincipalState.Rewritten[pi] = true
		valPrincipalState.Assigned[pi] = rewrite
		if !valPrincipalState.Mutated[pi] {
			valPrincipalState.BeforeMutate[pi] = rewrite
		}
	}
	return failedRewrites, rewritten, rewrite
}

func valuePerformAllRewrites(valPrincipalState PrincipalState) ([]Primitive, []int, PrincipalState) {
	failedRewrites := []Primitive{}
	failedRewriteIndices := []int{}
	for i := range valPrincipalState.Assigned {
		switch valPrincipalState.Assigned[i].Kind {
		case "primitive":
			failedRewrite, _, _ := valuePerformPrimitiveRewrite(
				valPrincipalState.Assigned[i].Primitive, i, valPrincipalState,
			)
			if len(failedRewrite) == 0 {
				continue
			}
			failedRewrites = append(failedRewrites, failedRewrite...)
			for range failedRewrite {
				failedRewriteIndices = append(failedRewriteIndices, i)
			}
		case "equation":
			failedRewrite, _, _ := valuePerformEquationRewrite(
				valPrincipalState.Assigned[i].Equation, i, valPrincipalState,
			)
			if len(failedRewrite) == 0 {
				continue
			}
			failedRewrites = append(failedRewrites, failedRewrite...)
			for range failedRewrite {
				failedRewriteIndices = append(failedRewriteIndices, i)
			}
		}
	}
	return failedRewrites, failedRewriteIndices, valPrincipalState
}

func valueShouldResolveToBeforeMutate(i int, valPrincipalState PrincipalState) bool {
	if valPrincipalState.Creator[i] == valPrincipalState.Name {
		return true
	}
	if !valPrincipalState.Known[i] {
		return true
	}
	if !strInSlice(valPrincipalState.Name, valPrincipalState.Wire[i]) {
		return true
	}
	if !valPrincipalState.Mutated[i] {
		return true
	}

	return false
}

func valueResolveConstant(c Constant, valPrincipalState PrincipalState) Value {
	i := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return Value{Kind: "constant", Constant: c}
	}
	if valueShouldResolveToBeforeMutate(i, valPrincipalState) {
		return valPrincipalState.BeforeMutate[i]
	}
	return valPrincipalState.Assigned[i]
}

func valueResolveValueInternalValuesFromKnowledgeMap(
	a Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	var v []Value
	switch a.Kind {
	case "constant":
		if valueEquivalentValueInValues(a, v) < 0 {
			v = append(v, a)
		}
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.Constant)
		a = valKnowledgeMap.Assigned[i]
	}
	switch a.Kind {
	case "constant":
		return valueResolveConstantInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	case "primitive":
		return valueResolvePrimitiveInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	case "equation":
		return valueResolveEquationInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	}
	return a, v
}

func valueResolveConstantInternalValuesFromKnowledgeMap(
	a Value, v []Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	return a, v
}

func valueResolvePrimitiveInternalValuesFromKnowledgeMap(
	a Value, v []Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	r := Value{
		Kind: "primitive",
		Primitive: Primitive{
			Name:      a.Primitive.Name,
			Arguments: []Value{},
			Output:    a.Primitive.Output,
			Check:     a.Primitive.Check,
		},
	}
	for _, aa := range a.Primitive.Arguments {
		s, vv := valueResolveValueInternalValuesFromKnowledgeMap(aa, valKnowledgeMap)
		for _, vvv := range vv {
			if valueEquivalentValueInValues(vvv, v) < 0 {
				v = append(v, vvv)
			}
		}
		r.Primitive.Arguments = append(r.Primitive.Arguments, s)
	}
	return r, v
}

func valueResolveEquationInternalValuesFromKnowledgeMap(
	a Value, v []Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	r := Value{
		Kind: "equation",
		Equation: Equation{
			Values: []Value{},
		},
	}
	aa := []Value{}
	for _, c := range a.Equation.Values {
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c.Constant)
		aa = append(aa, valKnowledgeMap.Assigned[i])
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aa[aai].Constant)
			aa[aai] = valKnowledgeMap.Assigned[i]
		}
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			r.Equation.Values = append(r.Equation.Values, aa[aai])
		case "primitive":
			r.Equation.Values = append(r.Equation.Values, aa[aai])
		case "equation":
			if aai == 0 {
				r.Equation.Values = aa[aai].Equation.Values
			} else {
				r.Equation.Values = append(
					r.Equation.Values, aa[aai].Equation.Values[1:]...,
				)
			}
			if valueEquivalentValueInValues(r, v) < 0 {
				v = append(v, r)
			}
		}
	}
	if valueEquivalentValueInValues(r, v) < 0 {
		v = append(v, r)
	}
	return r, v
}

func valueResolveValueInternalValuesFromPrincipalState(
	a Value, rootValue Value, rootIndex int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, forceBeforeMutate bool,
) Value {
	switch a.Kind {
	case "constant":
		nextRootIndex := valueGetPrincipalStateIndexFromConstant(valPrincipalState, a.Constant)
		switch nextRootIndex {
		case rootIndex:
			if !forceBeforeMutate {
				forceBeforeMutate = valueShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a = valueResolveConstant(a.Constant, valPrincipalState)
			}
		default:
			switch rootValue.Kind {
			case "primitive":
				x, _ := possibleToReconstructPrimitive(rootValue.Primitive, valAttackerState)
				if !x && valPrincipalState.Creator[rootIndex] != valPrincipalState.Name {
					forceBeforeMutate = true
				}
			}
			if !forceBeforeMutate {
				forceBeforeMutate = valueShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a = valueResolveConstant(a.Constant, valPrincipalState)
			}
			rootIndex = nextRootIndex
			rootValue = a
		}
	}
	switch a.Kind {
	case "constant":
		return a
	case "primitive":
		return valueResolvePrimitiveInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	case "equation":
		return valueResolveEquationInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	}
	return a
}

func valueResolvePrimitiveInternalValuesFromPrincipalState(
	a Value, rootValue Value, rootIndex int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, forceBeforeMutate bool,
) Value {
	if valPrincipalState.Creator[rootIndex] == valPrincipalState.Name {
		forceBeforeMutate = false
	}
	r := Value{
		Kind: "primitive",
		Primitive: Primitive{
			Name:      a.Primitive.Name,
			Arguments: []Value{},
			Output:    a.Primitive.Output,
			Check:     a.Primitive.Check,
		},
	}
	for _, aa := range a.Primitive.Arguments {
		s := valueResolveValueInternalValuesFromPrincipalState(
			aa, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
		r.Primitive.Arguments = append(r.Primitive.Arguments, s)
	}
	return r
}

func valueResolveEquationInternalValuesFromPrincipalState(
	a Value, rootValue Value, rootIndex int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, forceBeforeMutate bool,
) Value {
	if valPrincipalState.Creator[rootIndex] == valPrincipalState.Name {
		forceBeforeMutate = false
	}
	r := Value{
		Kind: "equation",
		Equation: Equation{
			Values: []Value{},
		},
	}
	aa := []Value{}
	aa = append(aa, a.Equation.Values...)
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			if forceBeforeMutate {
				i := valueGetPrincipalStateIndexFromConstant(valPrincipalState, aa[aai].Constant)
				aa[aai] = valPrincipalState.BeforeMutate[i]
			} else {
				aa[aai] = valueResolveConstant(aa[aai].Constant, valPrincipalState)
			}
		}
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			r.Equation.Values = append(r.Equation.Values, aa[aai])
		case "primitive":
			aaa := valueResolveValueInternalValuesFromPrincipalState(
				aa[aai], rootValue, rootIndex,
				valPrincipalState, valAttackerState, forceBeforeMutate,
			)
			r.Equation.Values = append(r.Equation.Values, aaa)
		case "equation":
			if aai == 0 {
				r.Equation.Values = aa[aai].Equation.Values
			} else {
				r.Equation.Values = append(r.Equation.Values, aa[aai].Equation.Values[1:]...)
			}
		}
	}
	return r
}

func valueConstantIsUsedByPrincipalInKnowledgeMap(
	valKnowledgeMap KnowledgeMap, name string, c Constant,
) bool {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	for ii, a := range valKnowledgeMap.Assigned {
		if valKnowledgeMap.Creator[ii] != name {
			continue
		}
		switch a.Kind {
		case "primitive":
			_, v := valueResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
			if valueEquivalentValueInValues(valKnowledgeMap.Assigned[i], v) >= 0 {
				return true
			}
			if valueEquivalentValueInValues(Value{Kind: "constant", Constant: c}, v) >= 0 {
				return true
			}
		}
	}
	return false
}

func valueResolveAllPrincipalStateValues(
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) PrincipalState {
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	for i := range valPrincipalState.Assigned {
		valPrincipalStateClone.Assigned[i] = valueResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.Assigned[i], valPrincipalState.Assigned[i], i, valPrincipalState, valAttackerState,
			valueShouldResolveToBeforeMutate(i, valPrincipalState),
		)
		valPrincipalStateClone.BeforeRewrite[i] = valueResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.BeforeRewrite[i], valPrincipalState.BeforeRewrite[i], i, valPrincipalState, valAttackerState,
			valueShouldResolveToBeforeMutate(i, valPrincipalState),
		)
	}
	return valPrincipalStateClone
}

func valueContainsFreshValues(v Value, c Constant, valPrincipalState PrincipalState, valAttackerState AttackerState) bool {
	i := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	v = valueResolveValueInternalValuesFromPrincipalState(v, v, i, valPrincipalState, valAttackerState, false)
	cc := valueGetConstantsFromValue(v)
	for _, ccc := range cc {
		ii := valueGetPrincipalStateIndexFromConstant(valPrincipalState, ccc)
		if ii >= 0 {
			ccc = valPrincipalState.Constants[ii]
			if ccc.Fresh {
				return true
			}
		}
	}
	return false
}
