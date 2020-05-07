/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package verifpal

import (
	"fmt"
	"strings"
)

func sanity(m Model) (KnowledgeMap, []PrincipalState) {
	sanityPhases(m)
	principals := sanityDeclaredPrincipals(m)
	valKnowledgeMap := constructKnowledgeMap(m, principals)
	sanityQueries(m, valKnowledgeMap)
	valPrincipalStates := constructPrincipalStates(m, valKnowledgeMap)
	return valKnowledgeMap, valPrincipalStates
}

func sanityPhases(m Model) {
	phase := 0
	for _, blck := range m.Blocks {
		switch blck.Kind {
		case "phase":
			switch {
			case blck.Phase.Number <= phase:
				errorCritical(fmt.Sprintf(
					"phase being declared (%d) must be superior to last declared phase (%d)",
					blck.Phase.Number, phase,
				))
			case blck.Phase.Number != phase+1:
				errorCritical(fmt.Sprintf(
					"phase being declared (%d) skips phases since last declared phase (%d)",
					blck.Phase.Number, phase,
				))
			default:
				phase = blck.Phase.Number
			}
		}
	}
}

func sanityAssignmentConstants(
	right Value, constants []Constant, valKnowledgeMap KnowledgeMap,
) []Constant {
	switch right.Kind {
	case "constant":
		unique := true
		for _, c := range constants {
			if right.Constant.Name == c.Name {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, right.Constant)
		}
	case "primitive":
		constants = append(constants, sanityAssignmentConstantsFromPrimitive(
			right, constants, valKnowledgeMap,
		)...)
	case "equation":
		constants = append(constants, sanityAssignmentConstantsFromEquation(
			right, constants,
		)...)
	}
	return constants
}

func sanityAssignmentConstantsFromPrimitive(
	right Value, constants []Constant, valKnowledgeMap KnowledgeMap,
) []Constant {
	primArguments := len(right.Primitive.Arguments)
	specArity, err := primitiveGetArity(right.Primitive)
	if err != nil {
		errorCritical(err.Error())
	}
	if primArguments == 0 {
		errorCritical(fmt.Sprintf(
			"primitive %s has no inputs.", right.Primitive.Name,
		))
	}
	if !intInSlice(primArguments, specArity) {
		arityString := prettyArity(specArity)
		errorCritical(fmt.Sprintf(
			"primitive %s has %d inputs, expecting %s",
			right.Primitive.Name, primArguments, arityString,
		))
	}
	for _, a := range right.Primitive.Arguments {
		switch a.Kind {
		case "constant":
			unique := true
			for _, c := range constants {
				if a.Constant.Name == c.Name {
					unique = false
					break
				}
			}
			if unique {
				constants = append(constants, a.Constant)
			}
		case "primitive":
			constants = sanityAssignmentConstants(a, constants, valKnowledgeMap)
		case "equation":
			constants = sanityAssignmentConstants(a, constants, valKnowledgeMap)
		}
	}
	return constants
}

func sanityAssignmentConstantsFromEquation(right Value, constants []Constant) []Constant {
	for _, v := range right.Equation.Values {
		unique := true
		for _, c := range constants {
			if v.Constant.Name == c.Name {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, v.Constant)
		}
	}
	return constants
}

func sanityPrimitive(p Primitive, outputs []Constant) {
	output := 0
	check := false
	if primitiveIsCorePrim(p.Name) {
		prim, _ := primitiveCoreGet(p.Name)
		output = prim.Output
		check = prim.Check
	} else {
		prim, err := primitiveGet(p.Name)
		if err != nil {
			errorCritical(err.Error())
		}
		output = prim.Output
		check = prim.Check
	}
	if (len(outputs) != output) && (output >= 0) {
		outputString := fmt.Sprintf("%d", output)
		if output < 0 {
			outputString = "at least 1"
		}
		errorCritical(fmt.Sprintf(
			"primitive %s has %d outputs, expecting %s",
			p.Name, len(outputs), outputString,
		))
	}
	if p.Check && !check {
		errorCritical(fmt.Sprintf(
			"primitive %s is checked but does not support checking",
			p.Name,
		))
	}
}

func sanityQueries(m Model, valKnowledgeMap KnowledgeMap) {
	for _, query := range m.Queries {
		switch query.Kind {
		case "confidentiality":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
			if i < 0 {
				errorCritical(fmt.Sprintf(
					"confidentiality query (%s) refers to unknown constant (%s)",
					prettyQuery(query),
					prettyConstant(query.Constants[0]),
				))
			}
		case "authentication":
			if len(query.Message.Constants) != 1 {
				errorCritical(fmt.Sprintf(
					"authentication query (%s) has more than one constant",
					prettyQuery(query),
				))
			}
			c := query.Message.Constants[0]
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
			if i < 0 {
				errorCritical(fmt.Sprintf(
					"authentication query refers to unknown constant (%s)",
					prettyConstant(c),
				))
			}
			senderKnows := false
			recipientKnows := false
			if valKnowledgeMap.Creator[i] == query.Message.Sender {
				senderKnows = true
			}
			if valKnowledgeMap.Creator[i] == query.Message.Recipient {
				recipientKnows = true
			}
			for _, m := range valKnowledgeMap.KnownBy[i] {
				if _, ok := m[query.Message.Sender]; ok {
					senderKnows = true
				}
				if _, ok := m[query.Message.Recipient]; ok {
					recipientKnows = true
				}
			}
			constantUsedByPrincipal := sanityConstantIsUsedByPrincipalInKnowledgeMap(
				valKnowledgeMap, query.Message.Recipient, c,
			)
			sanityQueriesCheckKnown(query, c, senderKnows, recipientKnows, constantUsedByPrincipal)
		case "freshness":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
			if i < 0 {
				errorCritical(fmt.Sprintf(
					"freshness query (%s) refers to unknown constant (%s)",
					prettyQuery(query),
					prettyConstant(query.Constants[0]),
				))
			}
		case "unlinkability":
			if len(query.Constants) < 2 {
				errorCritical(fmt.Sprintf(
					"unlinkability query (%s) must specify at least two constants",
					prettyQuery(query),
				))
			}
			for _, c := range query.Constants {
				i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
				if i < 0 {
					errorCritical(fmt.Sprintf(
						"unlinkability query (%s) refers to unknown value (%s)",
						prettyQuery(query),
						prettyConstant(c),
					))
				}
			}
		}
		sanityQueryOptions(query)
	}
}

func sanityQueryOptions(query Query) {
	for _, option := range query.Options {
		switch option.Kind {
		case "precondition":
			if len(option.Message.Constants) != 1 {
				errorCritical(fmt.Sprintf(
					"precondition option message (%s) has more than one constant",
					prettyQuery(query),
				))
			}
		default:
			errorCritical(fmt.Sprintf(
				"invalid query option kind (%s)", option.Kind,
			))
		}
	}
}

func sanityQueriesCheckKnown(
	query Query, c Constant, senderKnows bool, recipientKnows bool, constantUsedByPrincipal bool,
) {
	if !senderKnows {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s sending a constant (%s) that they do not know",
			prettyQuery(query),
			query.Message.Sender,
			prettyConstant(c),
		))
	}
	if !recipientKnows {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s receiving a constant (%s) that they never receive",
			prettyQuery(query),
			query.Message.Recipient,
			prettyConstant(c),
		))
	}
	if !constantUsedByPrincipal {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s using (%s) in a primitive, but this never happens",
			prettyQuery(query),
			query.Message.Recipient,
			prettyConstant(c),
		))
	}
}

func sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap KnowledgeMap, c Constant) int {
	for i := range valKnowledgeMap.Constants {
		if valKnowledgeMap.Constants[i].Name == c.Name {
			return i
		}
	}
	return -1
}

func sanityGetPrincipalStateIndexFromConstant(valPrincipalState PrincipalState, c Constant) int {
	for i := range valPrincipalState.Constants {
		if valPrincipalState.Constants[i].Name == c.Name {
			return i
		}
	}
	return -1
}

func sanityDeclaredPrincipals(m Model) []string {
	declared := []string{}
	principals := []string{}
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			principals, _ = appendUniqueString(principals, block.Principal.Name)
			declared, _ = appendUniqueString(declared, block.Principal.Name)
		}
	}
	for _, block := range m.Blocks {
		switch block.Kind {
		case "message":
			principals, _ = appendUniqueString(principals, block.Message.Sender)
			principals, _ = appendUniqueString(principals, block.Message.Recipient)
		}
	}
	for _, query := range m.Queries {
		switch query.Kind {
		case "authentication":
			principals, _ = appendUniqueString(principals, query.Message.Sender)
			principals, _ = appendUniqueString(principals, query.Message.Recipient)
		}
	}
	for _, p := range principals {
		if !strInSlice(p, declared) {
			errorCritical(fmt.Sprintf("principal does not exist (%s)", p))
		}
	}
	if len(declared) > 64 {
		errorCritical(fmt.Sprintf("more than 64 principals (%d) declared", len(declared)))
	}
	return principals
}

func sanityEquivalentValues(a1 Value, a2 Value, considerOutput bool) bool {
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
			equivPrim, _, _ := sanityEquivalentPrimitives(
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
			return sanityEquivalentEquations(
				a1.Equation, a2.Equation,
			)
		}
	}
	return true
}

func sanityEquivalentPrimitives(
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
		equiv := sanityEquivalentValues(p1.Arguments[i], p2.Arguments[i], true)
		if !equiv {
			return false, 0, 0
		}
	}
	return true, p1.Output, p2.Output
}

func sanityEquivalentEquations(e1 Equation, e2 Equation) bool {
	e1Base := e1.Values[0].Equation.Values
	e2Base := e2.Values[0].Equation.Values
	if len(e1.Values) != len(e2.Values) || len(e1.Values) == 0 {
		return false
	}
	if e1.Values[0].Kind == "equation" && e2.Values[0].Kind == "equation" {
		if sanityEquivalentValues(e1Base[1], e2.Values[1], true) &&
			sanityEquivalentValues(e1.Values[1], e2Base[1], true) {
			return true
		}
		if sanityEquivalentValues(e1Base[1], e2Base[1], true) &&
			sanityEquivalentValues(e1.Values[1], e2.Values[1], true) {
			return true
		}
		return false
	}
	if len(e1.Values) > 2 {
		if sanityEquivalentValues(e1.Values[1], e2.Values[2], true) &&
			sanityEquivalentValues(e1.Values[2], e2.Values[1], true) {
			return true
		}
		if sanityEquivalentValues(e1.Values[1], e2.Values[1], true) &&
			sanityEquivalentValues(e1.Values[2], e2.Values[2], true) {
			return true
		}
		return false
	}
	if sanityEquivalentValues(e1.Values[0], e2.Values[0], true) &&
		sanityEquivalentValues(e1.Values[1], e2.Values[1], true) {
		return true
	}
	return false
}

func sanityGetConstantsFromValue(v Value) []Constant {
	c := []Constant{}
	switch v.Kind {
	case "constant":
		c = append(c, v.Constant)
	case "primitive":
		c = append(c, sanityGetConstantsFromPrimitive(v.Primitive)...)
	case "equation":
		c = append(c, sanityGetConstantsFromEquation(v.Equation)...)
	}
	return c
}

func sanityGetConstantsFromPrimitive(p Primitive) []Constant {
	c := []Constant{}
	for _, a := range p.Arguments {
		switch a.Kind {
		case "constant":
			c = append(c, a.Constant)
		case "primitive":
			c = append(c, sanityGetConstantsFromPrimitive(a.Primitive)...)
		case "equation":
			c = append(c, sanityGetConstantsFromEquation(a.Equation)...)
		}
	}
	return c
}

func sanityGetConstantsFromEquation(e Equation) []Constant {
	c := []Constant{}
	for _, a := range e.Values {
		switch a.Kind {
		case "constant":
			c = append(c, a.Constant)
		case "primitive":
			c = append(c, sanityGetConstantsFromPrimitive(a.Primitive)...)
		case "equation":
			c = append(c, sanityGetConstantsFromEquation(a.Equation)...)
		}
	}
	return c
}

func sanityFindConstantInPrimitive(
	c Constant, p Primitive, valPrincipalState PrincipalState,
) bool {
	a := sanityResolveConstant(c, valPrincipalState)
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
				equivPrim, _, _ := sanityEquivalentPrimitives(
					a.Primitive, aa.Primitive, true,
				)
				if equivPrim {
					return true
				}
			}
			if sanityFindConstantInPrimitive(c, aa.Primitive, valPrincipalState) {
				return true
			}
		case "equation":
			if sanityFindConstantInEquation(c, aa.Equation, valPrincipalState) {
				return true
			}
		}
	}
	return false
}

func sanityFindConstantInEquation(
	c Constant, e Equation, valPrincipalState PrincipalState,
) bool {
	a := sanityResolveConstant(c, valPrincipalState)
	switch a.Kind {
	case "equation":
		if sanityEquivalentEquations(a.Equation, e) {
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

func sanityEquivalentValueInValues(v Value, a []Value) int {
	index := -1
	for i, aa := range a {
		if sanityEquivalentValues(v, aa, true) {
			index = i
			break
		}
	}
	return index
}

func sanityPerformPrimitiveRewrite(
	p Primitive, pi int, valPrincipalState PrincipalState,
) ([]Primitive, bool, Value) {
	rewritten := false
	failedRewrites := []Primitive{}
	rIndex := 0
	rewrites := []Value{{
		Kind: "primitive",
		Primitive: Primitive{
			Name:      p.Name,
			Arguments: make([]Value, len(p.Arguments)),
			Output:    p.Output,
			Check:     p.Check,
		},
	}}
	for i, a := range p.Arguments {
		switch a.Kind {
		case "constant":
			rewrites[0].Primitive.Arguments[i] = p.Arguments[i]
		case "primitive":
			pFailedRewrite, pRewritten, pRewrite := sanityPerformPrimitiveRewrite(
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
			eFailedRewrite, eRewritten, eRewrite := sanityPerformEquationRewrite(
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
	wasRebuilt, rebuild := possibleToRebuild(rewrites[rIndex].Primitive)
	if wasRebuilt {
		rewrites[0] = rebuild
		if pi >= 0 {
			valPrincipalState.Assigned[pi] = rebuild
			if !valPrincipalState.Mutated[pi] {
				valPrincipalState.BeforeMutate[pi] = rebuild
			}
		}
		switch rebuild.Kind {
		case "constant", "equation":
			return failedRewrites, rewritten, rewrites[rIndex]
		}
	}
	rewrittenRoot, rewrites := possibleToRewrite(rewrites[rIndex].Primitive, valPrincipalState)
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

func sanityPerformEquationRewrite(
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
			pFailedRewrite, pRewritten, pRewrite := sanityPerformPrimitiveRewrite(
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
			eFailedRewrite, eRewritten, eRewrite := sanityPerformEquationRewrite(
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

func sanityPerformAllRewrites(valPrincipalState PrincipalState) ([]Primitive, []int, PrincipalState) {
	failedRewrites := []Primitive{}
	failedRewriteIndices := []int{}
	for i := range valPrincipalState.Assigned {
		switch valPrincipalState.Assigned[i].Kind {
		case "primitive":
			failedRewrite, _, _ := sanityPerformPrimitiveRewrite(
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
			failedRewrite, _, _ := sanityPerformEquationRewrite(
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

func sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites []Primitive) {
	for _, p := range failedRewrites {
		if !p.Check {
			continue
		}
		errorCritical(fmt.Sprintf(
			"checked primitive fails: %s",
			prettyPrimitive(p),
		))
	}
}

func sanityCheckEquationRootGenerator(e Equation) {
	if len(e.Values) > 3 {
		errorCritical(fmt.Sprintf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		))
	}
	for i, c := range e.Values {
		if i == 0 {
			if strings.ToLower(c.Constant.Name) != "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) does not use 'g' as generator",
					prettyEquation(e),
				))
			}
		}
		if i > 0 {
			if strings.ToLower(c.Constant.Name) == "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) uses 'g' not as a generator",
					prettyEquation(e),
				))
			}
		}
	}
}

func sanityCheckEquationGenerators(a Value, valPrincipalState PrincipalState) {
	switch a.Kind {
	case "primitive":
		for _, va := range a.Primitive.Arguments {
			switch va.Kind {
			case "primitive":
				sanityCheckEquationGenerators(va, valPrincipalState)
			case "equation":
				sanityCheckEquationRootGenerator(va.Equation)
			}
		}
	case "equation":
		sanityCheckEquationRootGenerator(a.Equation)
	}
}

func sanityShouldResolveToBeforeMutate(i int, valPrincipalState PrincipalState) bool {
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

func sanityResolveConstant(c Constant, valPrincipalState PrincipalState) Value {
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return Value{Kind: "constant", Constant: c}
	}
	if sanityShouldResolveToBeforeMutate(i, valPrincipalState) {
		return valPrincipalState.BeforeMutate[i]
	}
	return valPrincipalState.Assigned[i]
}

func sanityResolveValueInternalValuesFromKnowledgeMap(
	a Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	var v []Value
	switch a.Kind {
	case "constant":
		if sanityEquivalentValueInValues(a, v) < 0 {
			v = append(v, a)
		}
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.Constant)
		a = valKnowledgeMap.Assigned[i]
	}
	switch a.Kind {
	case "constant":
		return sanityResolveConstantInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	case "primitive":
		return sanityResolvePrimitiveInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	case "equation":
		return sanityResolveEquationInternalValuesFromKnowledgeMap(
			a, v, valKnowledgeMap,
		)
	}
	return a, v
}

func sanityResolveConstantInternalValuesFromKnowledgeMap(
	a Value, v []Value, valKnowledgeMap KnowledgeMap,
) (Value, []Value) {
	return a, v
}

func sanityResolvePrimitiveInternalValuesFromKnowledgeMap(
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
		s, vv := sanityResolveValueInternalValuesFromKnowledgeMap(aa, valKnowledgeMap)
		for _, vvv := range vv {
			if sanityEquivalentValueInValues(vvv, v) < 0 {
				v = append(v, vvv)
			}
		}
		r.Primitive.Arguments = append(r.Primitive.Arguments, s)
	}
	return r, v
}

func sanityResolveEquationInternalValuesFromKnowledgeMap(
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
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c.Constant)
		aa = append(aa, valKnowledgeMap.Assigned[i])
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aa[aai].Constant)
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
				r.Equation.Values = append(r.Equation.Values, aa[aai].Equation.Values[1:]...)
			}
			if sanityEquivalentValueInValues(r, v) < 0 {
				v = append(v, r)
			}
		}
	}
	if sanityEquivalentValueInValues(r, v) < 0 {
		v = append(v, r)
	}
	return r, v
}

func sanityResolveValueInternalValuesFromPrincipalState(
	a Value, rootValue Value, rootIndex int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, forceBeforeMutate bool,
) Value {
	switch a.Kind {
	case "constant":
		nextRootIndex := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.Constant)
		switch nextRootIndex {
		case rootIndex:
			if !forceBeforeMutate {
				forceBeforeMutate = sanityShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a = sanityResolveConstant(a.Constant, valPrincipalState)
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
				forceBeforeMutate = sanityShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.BeforeMutate[nextRootIndex]
			} else {
				a = sanityResolveConstant(a.Constant, valPrincipalState)
			}
			rootIndex = nextRootIndex
			rootValue = a
		}
	}
	switch a.Kind {
	case "constant":
		return a
	case "primitive":
		return sanityResolvePrimitiveInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	case "equation":
		return sanityResolveEquationInternalValuesFromPrincipalState(
			a, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
	}
	return a
}

func sanityResolvePrimitiveInternalValuesFromPrincipalState(
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
		s := sanityResolveValueInternalValuesFromPrincipalState(
			aa, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
		r.Primitive.Arguments = append(r.Primitive.Arguments, s)
	}
	return r
}

func sanityResolveEquationInternalValuesFromPrincipalState(
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
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, aa[aai].Constant)
				aa[aai] = valPrincipalState.BeforeMutate[i]
			} else {
				aa[aai] = sanityResolveConstant(aa[aai].Constant, valPrincipalState)
			}
		}
	}
	for aai := range aa {
		switch aa[aai].Kind {
		case "constant":
			r.Equation.Values = append(r.Equation.Values, aa[aai])
		case "primitive":
			aaa := sanityResolveValueInternalValuesFromPrincipalState(
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

func sanityConstantIsUsedByPrincipalInKnowledgeMap(
	valKnowledgeMap KnowledgeMap, name string, c Constant,
) bool {
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	for ii, a := range valKnowledgeMap.Assigned {
		if valKnowledgeMap.Creator[ii] != name {
			continue
		}
		switch a.Kind {
		case "primitive":
			_, v := sanityResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
			if sanityEquivalentValueInValues(valKnowledgeMap.Assigned[i], v) >= 0 {
				return true
			}
			if sanityEquivalentValueInValues(Value{Kind: "constant", Constant: c}, v) >= 0 {
				return true
			}
		}
	}
	return false
}

func sanityResolveAllPrincipalStateValues(
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) PrincipalState {
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	for i := range valPrincipalState.Assigned {
		valPrincipalStateClone.Assigned[i] = sanityResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.Assigned[i], valPrincipalState.Assigned[i], i, valPrincipalState, valAttackerState,
			sanityShouldResolveToBeforeMutate(i, valPrincipalState),
		)
		valPrincipalStateClone.BeforeRewrite[i] = sanityResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.BeforeRewrite[i], valPrincipalState.BeforeRewrite[i], i, valPrincipalState, valAttackerState,
			sanityShouldResolveToBeforeMutate(i, valPrincipalState),
		)
	}
	return valPrincipalStateClone
}
