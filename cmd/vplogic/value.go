/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"errors"
)

var valueG = &Value{
	Kind: typesEnumConstant,
	Data: &Constant{
		Name:        "g",
		ID:          0,
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: typesEnumKnows,
		Qualifier:   typesEnumPublic,
	},
}

var valueNil = &Value{
	Kind: typesEnumConstant,
	Data: &Constant{
		Name:        "nil",
		ID:          1,
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: typesEnumKnows,
		Qualifier:   typesEnumPublic,
	},
}

var valueGNil = &Value{
	Kind: typesEnumEquation,
	Data: &Equation{
		Values: []*Value{valueG, valueNil},
	},
}

var valueGNilNil = &Value{
	Kind: typesEnumEquation,
	Data: &Equation{
		Values: []*Value{valueG, valueNil, valueNil},
	},
}

var valueNamesMap map[string]valueEnum = map[string]valueEnum{
	"g":   valueG.Data.(*Constant).ID,
	"nil": valueNil.Data.(*Constant).ID,
}

var valueNamesMapCounter valueEnum = 2

func valueNamesMapAdd(name string) valueEnum {
	id, exists := valueNamesMap[name]
	if !exists {
		id = valueNamesMapCounter
		valueNamesMap[name] = id
		valueNamesMapCounter++
	}
	return id
}

func valueIsGOrNil(c *Constant) bool {
	switch c.ID {
	case valueG.Data.(*Constant).ID, valueNil.Data.(*Constant).ID:
		return true
	}
	return false
}

func valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap *KnowledgeMap, c *Constant) int {
	if valKnowledgeMap.ConstantIndex != nil {
		if i, ok := valKnowledgeMap.ConstantIndex[c.ID]; ok {
			return i
		}
		return -1
	}
	for i := range valKnowledgeMap.Constants {
		if valueEquivalentConstants(valKnowledgeMap.Constants[i], c) {
			return i
		}
	}
	return -1
}

func valueGetPrincipalStateIndexFromConstant(valPrincipalState *PrincipalState, c *Constant) int {
	if valPrincipalState.ConstantIndex != nil {
		if i, ok := valPrincipalState.ConstantIndex[c.ID]; ok && i < len(valPrincipalState.Constants) {
			return i
		}
		return -1
	}
	for i := range valPrincipalState.Constants {
		if valueEquivalentConstants(valPrincipalState.Constants[i], c) {
			return i
		}
	}
	return -1
}

func valueGetConstantsFromValue(v *Value) []*Constant {
	switch v.Kind {
	case typesEnumConstant:
		return []*Constant{v.Data.(*Constant)}
	case typesEnumPrimitive:
		c := []*Constant{}
		for _, a := range v.Data.(*Primitive).Arguments {
			c = append(c, valueGetConstantsFromValue(a)...)
		}
		return c
	case typesEnumEquation:
		c := []*Constant{}
		for _, a := range v.Data.(*Equation).Values {
			c = append(c, valueGetConstantsFromValue(a)...)
		}
		return c
	}
	return []*Constant{}
}

func valueEquivalentValues(a1 *Value, a2 *Value, considerOutput bool) bool {
	if a1.Kind != a2.Kind {
		return false
	}
	switch a1.Kind {
	case typesEnumConstant:
		return valueEquivalentConstants(a1.Data.(*Constant), a2.Data.(*Constant))
	case typesEnumPrimitive:
		equivPrim, _, _ := valueEquivalentPrimitives(
			a1.Data.(*Primitive), a2.Data.(*Primitive), considerOutput,
		)
		return equivPrim
	case typesEnumEquation:
		return valueEquivalentEquations(
			a1.Data.(*Equation), a2.Data.(*Equation),
		)
	}
	return false
}

func valueEquivalentConstants(c1 *Constant, c2 *Constant) bool {
	return c1.ID == c2.ID
}

func valueEquivalentPrimitives(
	p1 *Primitive, p2 *Primitive, considerOutput bool,
) (bool, int, int) {
	if p1.ID != p2.ID {
		return false, 0, 0
	}
	if considerOutput && (p1.Output != p2.Output) {
		return false, 0, 0
	}
	if len(p1.Arguments) != len(p2.Arguments) {
		return false, 0, 0
	}
	for i := range p1.Arguments {
		if !valueEquivalentValues(p1.Arguments[i], p2.Arguments[i], true) {
			return false, 0, 0
		}
	}
	return true, p1.Output, p2.Output
}

func valueEquivalentEquations(e1 *Equation, e2 *Equation) bool {
	if len(e1.Values) == 0 || len(e2.Values) == 0 {
		return false
	}
	var e1f, e2f *Equation
	if valueEquationIsFlat(e1) && valueEquationIsFlat(e2) {
		e1f = e1
		e2f = e2
	} else {
		e1f = valueFlattenEquation(e1)
		e2f = valueFlattenEquation(e2)
	}
	if len(e1f.Values) != len(e2f.Values) {
		return false
	}
	switch len(e1f.Values) {
	case 1:
		return valueEquivalentValues(e1f.Values[0], e2f.Values[0], true)
	case 2:
		return valueEquivalentValues(e1f.Values[0], e2f.Values[0], true) &&
			valueEquivalentValues(e1f.Values[1], e2f.Values[1], true)
	case 3:
		return valueEquivalentEquationsRule(
			e1f.Values[1], e2f.Values[1], e1f.Values[2], e2f.Values[2],
		) || valueEquivalentEquationsRule(
			e1f.Values[1], e2f.Values[2], e1f.Values[2], e2f.Values[1],
		)
	}
	return false
}

func valueEquivalentEquationsRule(base1 *Value, base2 *Value, exp1 *Value, exp2 *Value) bool {
	return (valueEquivalentValues(base1, exp2, true) &&
		valueEquivalentValues(exp1, base2, true))
}

func valueEquationIsFlat(e *Equation) bool {
	for _, v := range e.Values {
		if v.Kind == typesEnumEquation {
			return false
		}
	}
	return true
}

func valueFlattenEquation(e *Equation) *Equation {
	ef := &Equation{
		Values: make([]*Value, 0, len(e.Values)),
	}
	for _, v := range e.Values {
		if v.Kind == typesEnumEquation {
			eff := valueFlattenEquation(v.Data.(*Equation))
			ef.Values = append(ef.Values, eff.Values...)
		} else {
			ef.Values = append(ef.Values, v)
		}
	}
	return ef
}

func valueFindConstantInPrimitiveFromKnowledgeMap(c *Constant, a *Value, valKnowledgeMap *KnowledgeMap) bool {
	v := &Value{
		Kind: typesEnumConstant,
		Data: c,
	}
	_, vv := valueResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
	return valueEquivalentValueInValues(v, vv) >= 0
}

func valueHash(v *Value) uint64 {
	switch v.Kind {
	case typesEnumConstant:
		return uint64(v.Data.(*Constant).ID)
	case typesEnumPrimitive:
		return valuePrimitiveHash(v.Data.(*Primitive))
	case typesEnumEquation:
		return valueEquationHash(v.Data.(*Equation))
	}
	return 0
}

func valuePrimitiveHash(p *Primitive) uint64 {
	h := uint64(p.ID)*2654435761 ^ uint64(p.Output)*97 //nolint:gosec
	for _, a := range p.Arguments {
		h = h*31 + valueHash(a)
	}
	return h
}

func valueEquationHash(e *Equation) uint64 {
	if valueEquationIsFlat(e) {
		return valueEquationHashInner(e)
	}
	ef := valueFlattenEquation(e)
	return valueEquationHashInner(ef)
}

func valueEquationHashInner(e *Equation) uint64 {
	switch len(e.Values) {
	case 0:
		return 0
	case 1:
		return valueHash(e.Values[0])
	case 2:
		return valueHash(e.Values[0])*31 + valueHash(e.Values[1])
	case 3:
		h1 := valueHash(e.Values[1])
		h2 := valueHash(e.Values[2])
		// Commutative hash for 3-element DH equations
		if h1 > h2 {
			h1, h2 = h2, h1
		}
		return valueHash(e.Values[0])*31 + h1*17 + h2
	default:
		h := uint64(0)
		for _, v := range e.Values {
			h = h*31 + valueHash(v)
		}
		return h
	}
}

func valueEquivalentValueInValuesMap(v *Value, a []*Value, m map[uint64][]int) int {
	h := valueHash(v)
	indices, ok := m[h]
	if !ok {
		return -1
	}
	for _, i := range indices {
		if valueEquivalentValues(v, a[i], true) {
			return i
		}
	}
	return -1
}

func valueEquivalentValueInValues(v *Value, a []*Value) int {
	for i, av := range a {
		if valueEquivalentValues(v, av, true) {
			return i
		}
	}
	return -1
}

func valueEquivalentConstantInConstants(c *Constant, a []*Constant) int {
	for i, ac := range a {
		if valueEquivalentConstants(c, ac) {
			return i
		}
	}
	return -1
}

func valuePerformPrimitiveRewrite(
	p *Primitive, pi int, valPrincipalState *PrincipalState,
) ([]*Primitive, bool, *Value) {
	rIndex := 0
	rewrite, failedRewrites, rewritten := valuePerformPrimitiveArgumentsRewrite(
		p, valPrincipalState,
	)
	rebuilt, rebuild := possibleToRebuild(rewrite.Data.(*Primitive))
	if rebuilt {
		rewrite = rebuild
		if pi >= 0 {
			valPrincipalState.Assigned[pi] = rebuild
			if !valPrincipalState.Mutated[pi] {
				valPrincipalState.BeforeMutate[pi] = rebuild
			}
		}
		switch rebuild.Kind {
		case typesEnumConstant, typesEnumEquation:
			return failedRewrites, rewritten, rewrite
		}
	}
	rewrittenRoot, rewrittenValues := possibleToRewrite(
		rewrite.Data.(*Primitive), valPrincipalState,
	)
	if !rewrittenRoot {
		failedRewrites = append(failedRewrites, rewrittenValues[rIndex].Data.(*Primitive))
	} else if primitiveIsCorePrimitive(p.ID) {
		rIndex = p.Output
	}
	if rIndex >= len(rewrittenValues) {
		if pi >= 0 {
			valPrincipalState.Assigned[pi] = valueNil
			if !valPrincipalState.Mutated[pi] {
				valPrincipalState.BeforeMutate[pi] = valueNil
			}
		}
		return failedRewrites, (rewritten || rewrittenRoot), valueNil
	}
	if rewritten || rewrittenRoot {
		if pi >= 0 {
			valPrincipalState.Rewritten[pi] = true
			valPrincipalState.Assigned[pi] = rewrittenValues[rIndex]
			if !valPrincipalState.Mutated[pi] {
				valPrincipalState.BeforeMutate[pi] = rewrittenValues[rIndex]
			}
		}
	}
	return failedRewrites, (rewritten || rewrittenRoot), rewrittenValues[rIndex]
}

func valuePerformPrimitiveArgumentsRewrite(
	p *Primitive, valPrincipalState *PrincipalState,
) (*Value, []*Primitive, bool) {
	rewrite := &Value{
		Kind: typesEnumPrimitive,
		Data: &Primitive{
			ID:        p.ID,
			Arguments: make([]*Value, len(p.Arguments)),
			Output:    p.Output,
			Check:     p.Check,
		},
	}
	failedRewrites := []*Primitive{}
	rewritten := false
	for i, a := range p.Arguments {
		switch a.Kind {
		case typesEnumConstant:
			rewrite.Data.(*Primitive).Arguments[i] = p.Arguments[i]
		case typesEnumPrimitive:
			pFailedRewrite, pRewritten, pRewrite := valuePerformPrimitiveRewrite(
				a.Data.(*Primitive), -1, valPrincipalState,
			)
			if pRewritten {
				rewritten = true
				rewrite.Data.(*Primitive).Arguments[i] = pRewrite
				continue
			}
			rewrite.Data.(*Primitive).Arguments[i] = p.Arguments[i]
			failedRewrites = append(failedRewrites, pFailedRewrite...)
		case typesEnumEquation:
			eFailedRewrite, eRewritten, eRewrite := valuePerformEquationRewrite(
				a.Data.(*Equation), -1, valPrincipalState,
			)
			if eRewritten {
				rewritten = true
				rewrite.Data.(*Primitive).Arguments[i] = eRewrite
				continue
			}
			rewrite.Data.(*Primitive).Arguments[i] = p.Arguments[i]
			failedRewrites = append(failedRewrites, eFailedRewrite...)
		}
	}
	return rewrite, failedRewrites, rewritten
}

func valuePerformEquationRewrite(
	e *Equation, pi int, valPrincipalState *PrincipalState,
) ([]*Primitive, bool, *Value) {
	rewritten := false
	failedRewrites := []*Primitive{}
	rewrite := &Value{
		Kind: typesEnumEquation,
		Data: &Equation{
			Values: []*Value{},
		},
	}
	for i, a := range e.Values {
		switch a.Kind {
		case typesEnumConstant:
			rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, a)
		case typesEnumPrimitive:
			hasRule := false
			if primitiveIsCorePrimitive(a.Data.(*Primitive).ID) {
				prim, _ := primitiveCoreGet(a.Data.(*Primitive).ID)
				hasRule = prim.HasRule
			} else {
				prim, _ := primitiveGet(a.Data.(*Primitive).ID)
				hasRule = prim.Rewrite.HasRule
			}
			if !hasRule {
				continue
			}
			pFailedRewrite, pRewritten, pRewrite := valuePerformPrimitiveRewrite(
				a.Data.(*Primitive), -1, valPrincipalState,
			)
			if !pRewritten {
				rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, e.Values[i])
				failedRewrites = append(failedRewrites, pFailedRewrite...)
				continue
			}
			rewritten = true
			switch pRewrite.Kind {
			case typesEnumConstant:
				rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, pRewrite)
			case typesEnumPrimitive:
				rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, pRewrite)
			case typesEnumEquation:
				rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, pRewrite.Data.(*Equation).Values...)
			}
		case typesEnumEquation:
			eFailedRewrite, eRewritten, eRewrite := valuePerformEquationRewrite(
				a.Data.(*Equation), -1, valPrincipalState,
			)
			if !eRewritten {
				rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, e.Values[i])
				failedRewrites = append(failedRewrites, eFailedRewrite...)
				continue
			}
			rewritten = true
			rewrite.Data.(*Equation).Values = append(rewrite.Data.(*Equation).Values, eRewrite)
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

func valuePerformAllRewrites(valPrincipalState *PrincipalState) ([]*Primitive, []int, *PrincipalState) {
	failedRewrites := []*Primitive{}
	failedRewriteIndices := []int{}
	for i := range valPrincipalState.Assigned {
		switch valPrincipalState.Assigned[i].Kind {
		case typesEnumPrimitive:
			failedRewrite, _, _ := valuePerformPrimitiveRewrite(
				valPrincipalState.Assigned[i].Data.(*Primitive), i, valPrincipalState,
			)
			if len(failedRewrite) == 0 {
				continue
			}
			failedRewrites = append(failedRewrites, failedRewrite...)
			for range failedRewrite {
				failedRewriteIndices = append(failedRewriteIndices, i)
			}
		case typesEnumEquation:
			failedRewrite, _, _ := valuePerformEquationRewrite(
				valPrincipalState.Assigned[i].Data.(*Equation), i, valPrincipalState,
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

func valueShouldResolveToBeforeMutate(i int, valPrincipalState *PrincipalState) bool {
	if valPrincipalState.Creator[i] == valPrincipalState.ID {
		return true
	}
	if !valPrincipalState.Known[i] {
		return true
	}
	if !principalEnumInSlice(valPrincipalState.ID, valPrincipalState.Wire[i]) {
		return true
	}
	if !valPrincipalState.Mutated[i] {
		return true
	}
	return false
}

func valueResolveConstant(c *Constant, valPrincipalState *PrincipalState, allowBeforeMutate bool) (*Value, int) {
	i := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return &Value{Kind: typesEnumConstant, Data: c}, i
	}
	if allowBeforeMutate && valueShouldResolveToBeforeMutate(i, valPrincipalState) {
		return valPrincipalState.BeforeMutate[i], i
	}
	return valPrincipalState.Assigned[i], i
}

func valueResolveValueInternalValuesFromKnowledgeMap(
	a *Value, valKnowledgeMap *KnowledgeMap,
) (*Value, []*Value) {
	var v []*Value
	switch a.Kind {
	case typesEnumConstant:
		if valueEquivalentValueInValues(a, v) < 0 {
			v = append(v, a)
		}
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.Data.(*Constant))
		a = valKnowledgeMap.Assigned[i]
	}
	switch a.Kind {
	case typesEnumConstant:
		if valueEquivalentValueInValues(a, v) < 0 {
			v = append(v, a)
		}
		return a, v
	case typesEnumPrimitive:
		return valueResolvePrimitiveInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	case typesEnumEquation:
		return valueResolveEquationInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	}
	return a, v
}

func valueResolvePrimitiveInternalValuesFromKnowledgeMap(
	a *Value, v []*Value, valKnowledgeMap *KnowledgeMap,
) (*Value, []*Value) {
	r := &Value{
		Kind: typesEnumPrimitive,
		Data: &Primitive{
			ID:        a.Data.(*Primitive).ID,
			Arguments: []*Value{},
			Output:    a.Data.(*Primitive).Output,
			Check:     a.Data.(*Primitive).Check,
		},
	}
	for aai := range a.Data.(*Primitive).Arguments {
		s, vv := valueResolveValueInternalValuesFromKnowledgeMap(a.Data.(*Primitive).Arguments[aai], valKnowledgeMap)
		r.Data.(*Primitive).Arguments = append(r.Data.(*Primitive).Arguments, s)
		for _, vvv := range vv {
			if valueEquivalentValueInValues(vvv, v) < 0 {
				v = append(v, vvv)
			}
		}
	}
	return r, v
}

func valueResolveEquationInternalValuesFromKnowledgeMap(
	a *Value, v []*Value, valKnowledgeMap *KnowledgeMap,
) (*Value, []*Value) {
	r := &Value{
		Kind: typesEnumEquation,
		Data: &Equation{
			Values: []*Value{},
		},
	}
	aa := []*Value{}
	for ai := range a.Data.(*Equation).Values {
		switch a.Data.(*Equation).Values[ai].Kind {
		case typesEnumConstant:
			i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.Data.(*Equation).Values[ai].Data.(*Constant))
			aa = append(aa, valKnowledgeMap.Assigned[i])
			if valueEquivalentValueInValues(a.Data.(*Equation).Values[ai], v) < 0 {
				v = append(v, a.Data.(*Equation).Values[ai])
			}
		}
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case typesEnumConstant:
			r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aa[aai])
			if valueEquivalentValueInValues(aa[aai], v) < 0 {
				v = append(v, aa[aai])
			}
		case typesEnumPrimitive:
			aaa, vv := valueResolvePrimitiveInternalValuesFromKnowledgeMap(aa[aai], v, valKnowledgeMap)
			r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aaa)
			for _, vvv := range vv {
				if valueEquivalentValueInValues(vvv, v) < 0 {
					v = append(v, vvv)
				}
			}
		case typesEnumEquation:
			aaa, vv := valueResolveEquationInternalValuesFromKnowledgeMap(aa[aai], v, valKnowledgeMap)
			r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aaa)
			if aai == 0 {
				r.Data.(*Equation).Values = aaa.Data.(*Equation).Values
			} else {
				r.Data.(*Equation).Values = append(
					r.Data.(*Equation).Values, aaa.Data.(*Equation).Values[1:]...,
				)
			}
			for _, vvv := range vv {
				if valueEquivalentValueInValues(vvv, v) < 0 {
					v = append(v, vvv)
				}
			}
		}
	}
	return r, v
}

func valueResolveValueInternalValuesFromPrincipalState(
	a *Value, rootValue *Value, rootIndex int, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, forceBeforeMutate bool,
) (*Value, error) {
	switch a.Kind {
	case typesEnumConstant:
		nextRootIndex := valueGetPrincipalStateIndexFromConstant(valPrincipalState, a.Data.(*Constant))
		if nextRootIndex < 0 {
			return &Value{}, errors.New("invalid index")
		}
		switch nextRootIndex {
		case rootIndex:
			if !forceBeforeMutate {
				forceBeforeMutate = valueShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a, _ = valueResolveConstant(a.Data.(*Constant), valPrincipalState, true)
			}
		default:
			switch rootValue.Kind {
			case typesEnumPrimitive:
				if valPrincipalState.Creator[rootIndex] != valPrincipalState.ID {
					forceBeforeMutate = true
				}
			}
			if forceBeforeMutate {
				forceBeforeMutate = !principalEnumInSlice(
					valPrincipalState.Creator[rootIndex],
					valPrincipalState.MutatableTo[nextRootIndex],
				)
			} else {
				forceBeforeMutate = valueShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a = valPrincipalState.Assigned[nextRootIndex]
			}
			rootIndex = nextRootIndex
			rootValue = a
		}
	}
	switch a.Kind {
	case typesEnumConstant:
		return a, nil
	case typesEnumPrimitive:
		return valueResolvePrimitiveInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	case typesEnumEquation:
		return valueResolveEquationInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	}
	return a, nil
}

func valueResolvePrimitiveInternalValuesFromPrincipalState(
	a *Value, rootValue *Value, rootIndex int, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, forceBeforeMutate bool,
) (*Value, error) {
	if valPrincipalState.Creator[rootIndex] == valPrincipalState.ID {
		forceBeforeMutate = false
	}
	r := &Value{
		Kind: typesEnumPrimitive,
		Data: &Primitive{
			ID:        a.Data.(*Primitive).ID,
			Arguments: []*Value{},
			Output:    a.Data.(*Primitive).Output,
			Check:     a.Data.(*Primitive).Check,
		},
	}
	for i := 0; i < len(a.Data.(*Primitive).Arguments); i++ {
		s, err := valueResolveValueInternalValuesFromPrincipalState(
			a.Data.(*Primitive).Arguments[i], rootValue, rootIndex, valPrincipalState,
			valAttackerState, forceBeforeMutate,
		)
		if err != nil {
			return &Value{}, err
		}
		r.Data.(*Primitive).Arguments = append(r.Data.(*Primitive).Arguments, s)
	}
	return r, nil
}

func valueResolveEquationInternalValuesFromPrincipalState(
	a *Value, rootValue *Value, rootIndex int, valPrincipalState *PrincipalState,
	valAttackerState AttackerState, forceBeforeMutate bool,
) (*Value, error) {
	r := &Value{
		Kind: typesEnumEquation,
		Data: &Equation{
			Values: []*Value{},
		},
	}
	aa := []*Value{}
	aa = append(aa, a.Data.(*Equation).Values...)
	if valPrincipalState.Creator[rootIndex] == valPrincipalState.ID {
		forceBeforeMutate = false
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case typesEnumConstant:
			var i int
			aa[aai], i = valueResolveConstant(aa[aai].Data.(*Constant), valPrincipalState, true)
			if forceBeforeMutate {
				aa[aai] = valPrincipalState.BeforeMutate[i]
			}
		}
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case typesEnumConstant:
			r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aa[aai])
		case typesEnumPrimitive:
			aaa, err := valueResolvePrimitiveInternalValuesFromPrincipalState(
				aa[aai], rootValue, rootIndex,
				valPrincipalState, valAttackerState, forceBeforeMutate,
			)
			if err != nil {
				return &Value{}, err
			}
			r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aaa)
		case typesEnumEquation:
			aaa, err := valueResolveEquationInternalValuesFromPrincipalState(
				aa[aai], rootValue, rootIndex,
				valPrincipalState, valAttackerState, forceBeforeMutate,
			)
			if err != nil {
				return &Value{}, err
			}
			if aai == 0 {
				r.Data.(*Equation).Values = aaa.Data.(*Equation).Values
			} else {
				r.Data.(*Equation).Values = append(r.Data.(*Equation).Values, aaa.Data.(*Equation).Values[1:]...)
			}
		}
	}
	return r, nil
}

func valueConstantIsUsedByPrincipalInKnowledgeMap(
	valKnowledgeMap *KnowledgeMap, principalID principalEnum, c *Constant,
) bool {
	if valKnowledgeMap.UsedBy != nil {
		if principals, ok := valKnowledgeMap.UsedBy[c.ID]; ok {
			return principals[principalID]
		}
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i >= 0 {
			assignedVal := valKnowledgeMap.Assigned[i]
			if assignedVal.Kind == typesEnumConstant {
				if principals, ok := valKnowledgeMap.UsedBy[assignedVal.Data.(*Constant).ID]; ok {
					return principals[principalID]
				}
			}
		}
		return false
	}
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	for ii, a := range valKnowledgeMap.Assigned {
		if valKnowledgeMap.Creator[ii] != principalID {
			continue
		}
		switch a.Kind {
		case typesEnumPrimitive, typesEnumEquation:
			_, v := valueResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
			if valueEquivalentValueInValues(valKnowledgeMap.Assigned[i], v) >= 0 {
				return true
			}
			if valueEquivalentValueInValues(&Value{Kind: typesEnumConstant, Data: c}, v) >= 0 {
				return true
			}
		}
	}
	return false
}

func valueConstantIsUsedByAtLeastOnePrincipalInKnowledgeMap(valKnowledgeMap *KnowledgeMap, c *Constant) bool {
	if c.Name == "nil" {
		return true
	}
	for i := 0; i < len(valKnowledgeMap.PrincipalIDs); i++ {
		if valueConstantIsUsedByPrincipalInKnowledgeMap(
			valKnowledgeMap, valKnowledgeMap.PrincipalIDs[i], c,
		) {
			return true
		}
	}
	return false
}

func valueResolveAllPrincipalStateValues(
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
) (*PrincipalState, error) {
	var err error
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	for i := range valPrincipalState.Assigned {
		valPrincipalStateClone.Assigned[i], err = valueResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.Assigned[i], valPrincipalState.Assigned[i], i, valPrincipalState,
			valAttackerState, valueShouldResolveToBeforeMutate(i, valPrincipalState),
		)
		if err != nil {
			return &PrincipalState{}, err
		}
		valPrincipalStateClone.BeforeRewrite[i], err = valueResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.BeforeRewrite[i], valPrincipalState.BeforeRewrite[i], i, valPrincipalState,
			valAttackerState, valueShouldResolveToBeforeMutate(i, valPrincipalState),
		)
		if err != nil {
			return &PrincipalState{}, err
		}
	}
	return valPrincipalStateClone, nil
}

func valueConstantContainsFreshValues(
	c *Constant, valPrincipalState *PrincipalState,
) (bool, error) {
	i := valueGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return false, errors.New("invalid value")
	}
	cc := valueGetConstantsFromValue(valPrincipalState.Assigned[i])
	for i := 0; i < len(cc); i++ {
		ii := valueGetPrincipalStateIndexFromConstant(valPrincipalState, cc[i])
		if ii >= 0 {
			cc[i] = valPrincipalState.Constants[ii]
			if cc[i].Fresh {
				return true, nil
			}
		}
	}
	return false, nil
}

func valueDeepCopy(v *Value) Value {
	d := Value{Kind: v.Kind}
	switch v.Kind {
	case typesEnumConstant:
		c := v.Data.(*Constant)
		d.Data = &Constant{
			Name:        c.Name,
			ID:          c.ID,
			Guard:       c.Guard,
			Fresh:       c.Fresh,
			Leaked:      c.Leaked,
			Declaration: c.Declaration,
			Qualifier:   c.Qualifier,
		}
	case typesEnumPrimitive:
		p := v.Data.(*Primitive)
		newP := &Primitive{
			ID:        p.ID,
			Arguments: make([]*Value, len(p.Arguments)),
			Output:    p.Output,
			Check:     p.Check,
		}
		for i, arg := range p.Arguments {
			argCopy := valueDeepCopy(arg)
			newP.Arguments[i] = &argCopy
		}
		d.Data = newP
	case typesEnumEquation:
		e := v.Data.(*Equation)
		newE := &Equation{
			Values: make([]*Value, len(e.Values)),
		}
		for i, val := range e.Values {
			valCopy := valueDeepCopy(val)
			newE.Values[i] = &valCopy
		}
		d.Data = newE
	}
	return d
}
