/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package verifpal

import (
	"fmt"
	"strings"
)

func sanity(m Model) (knowledgeMap, []principalState) {
	var valKnowledgeMap knowledgeMap
	sanityPhases(m)
	principals := sanityDeclaredPrincipals(m)
	valKnowledgeMap = constructKnowledgeMap(m, principals)
	sanityQueries(m, valKnowledgeMap)
	valPrincipalStates := constructPrincipalStates(m, valKnowledgeMap)
	return valKnowledgeMap, valPrincipalStates
}

func sanityPhases(m Model) {
	phase := 0
	for _, blck := range m.blocks {
		switch blck.kind {
		case "phase":
			switch {
			case m.attacker == "passive":
				errorCritical("phases may only be used for analysis with an active attacker")
			case blck.phase.number <= phase:
				errorCritical(fmt.Sprintf(
					"phase being declared (%d) must be superior to last declared phase (%d)",
					blck.phase.number, phase,
				))
			case blck.phase.number != phase+1:
				errorCritical(fmt.Sprintf(
					"phase being declared (%d) skips phases since last declared phase (%d)",
					blck.phase.number, phase,
				))
			default:
				phase = blck.phase.number
			}
		}
	}
}

func sanityAssignmentConstants(right value, constants []constant, valKnowledgeMap knowledgeMap) []constant {
	switch right.kind {
	case "constant":
		unique := true
		for _, c := range constants {
			if right.constant.name == c.name {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, right.constant)
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
	right value, constants []constant, valKnowledgeMap knowledgeMap,
) []constant {
	prim := primitiveGet(right.primitive.name)
	if (len(right.primitive.arguments) == 0) ||
		(len(right.primitive.arguments) > 5) ||
		((prim.arity >= 0) && (len(right.primitive.arguments) != prim.arity)) {
		plural := ""
		arity := fmt.Sprintf("%d", prim.arity)
		if len(right.primitive.arguments) > 1 {
			plural = "s"
		}
		if prim.arity < 0 {
			arity = "between 1 and 5"
		}
		errorCritical(fmt.Sprintf(
			"primitive %s has %d input%s, expecting %s",
			right.primitive.name, len(right.primitive.arguments), plural, arity,
		))
	}
	for _, a := range right.primitive.arguments {
		switch a.kind {
		case "constant":
			unique := true
			for _, c := range constants {
				if a.constant.name == c.name {
					unique = false
					break
				}
			}
			if unique {
				constants = append(constants, a.constant)
			}
		case "primitive":
			constants = sanityAssignmentConstants(a, constants, valKnowledgeMap)
		case "equation":
			constants = sanityAssignmentConstants(a, constants, valKnowledgeMap)
		}
	}
	return constants
}

func sanityAssignmentConstantsFromEquation(right value, constants []constant) []constant {
	for _, v := range right.equation.values {
		unique := true
		for _, c := range constants {
			if v.constant.name == c.name {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, v.constant)
		}
	}
	return constants
}

func sanityPrimitive(p primitive, outputs []constant) {
	prim := primitiveGet(p.name)
	if (len(outputs) != prim.output) && (prim.output >= 0) {
		output := fmt.Sprintf("%d", prim.output)
		if prim.output < 0 {
			output = "at least 1"
		}
		errorCritical(fmt.Sprintf(
			"primitive %s has %d outputs, expecting %s",
			prim.name, len(outputs), output,
		))
	}
	if p.check && !prim.check {
		errorCritical(fmt.Sprintf(
			"primitive %s is checked but does not support checking",
			prim.name,
		))
	}
}

func sanityQueries(m Model, valKnowledgeMap knowledgeMap) {
	for _, query := range m.queries {
		switch query.kind {
		case "confidentiality":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.constant)
			if i < 0 {
				errorCritical(fmt.Sprintf(
					"confidentiality query (%s) refers to unknown value (%s)",
					prettyQuery(query),
					prettyConstant(query.constant),
				))
			}
		case "authentication":
			if len(query.message.constants) != 1 {
				errorCritical(fmt.Sprintf(
					"authentication query (%s) has more than one constant",
					prettyQuery(query),
				))
			}
			c := query.message.constants[0]
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
			if i < 0 {
				errorCritical(fmt.Sprintf(
					"authentication query refers to unknown constant (%s)",
					prettyConstant(c),
				))
			}
			senderKnows := false
			recipientKnows := false
			if valKnowledgeMap.creator[i] == query.message.sender {
				senderKnows = true
			}
			if valKnowledgeMap.creator[i] == query.message.recipient {
				recipientKnows = true
			}
			for _, m := range valKnowledgeMap.knownBy[i] {
				if _, ok := m[query.message.sender]; ok {
					senderKnows = true
				}
				if _, ok := m[query.message.recipient]; ok {
					recipientKnows = true
				}
			}
			constantUsedByPrincipal := sanityConstantIsUsedByPrincipalInKnowledgeMap(
				valKnowledgeMap, query.message.recipient, c,
			)
			sanityQueriesCheckKnown(query, c, senderKnows, recipientKnows, constantUsedByPrincipal)
		}
		sanityQueryOptions(query)
	}
}

func sanityQueryOptions(query query) {
	for _, option := range query.options {
		switch option.kind {
		case "precondition":
			if len(option.message.constants) != 1 {
				errorCritical(fmt.Sprintf(
					"precondition option message (%s) has more than one constant",
					prettyQuery(query),
				))
			}
		default:
			errorCritical(fmt.Sprintf(
				"invalid query option kind (%s)", option.kind,
			))
		}
	}
}

func sanityQueriesCheckKnown(
	query query, c constant, senderKnows bool, recipientKnows bool, constantUsedByPrincipal bool,
) {
	if !senderKnows {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s sending a constant (%s) that they do not know",
			prettyQuery(query),
			query.message.sender,
			prettyConstant(c),
		))
	}
	if !recipientKnows {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s receiving a constant (%s) that they never receive",
			prettyQuery(query),
			query.message.recipient,
			prettyConstant(c),
		))
	}
	if !constantUsedByPrincipal {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) depends on %s using (%s) in a primitive, but this never happens",
			prettyQuery(query),
			query.message.recipient,
			prettyConstant(c),
		))
	}
}

func sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap knowledgeMap, c constant) int {
	var index int
	found := false
	for i := range valKnowledgeMap.constants {
		if valKnowledgeMap.constants[i].name == c.name {
			found = true
			index = i
			break
		}
	}
	if !found {
		index = -1
	}
	return index
}

func sanityGetPrincipalStateIndexFromConstant(valPrincipalState principalState, c constant) int {
	var index int
	found := false
	for i := range valPrincipalState.constants {
		if valPrincipalState.constants[i].name == c.name {
			found = true
			index = i
			break
		}
	}
	if !found {
		index = -1
	}
	return index
}

func sanityDeclaredPrincipals(m Model) []string {
	var declared []string
	var principals []string
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			declared, _ = appendUniqueString(declared, block.principal.name)
		}
	}
	for _, block := range m.blocks {
		switch block.kind {
		case "message":
			principals, _ = appendUniqueString(principals, block.message.sender)
			principals, _ = appendUniqueString(principals, block.message.recipient)
		}
	}
	for _, query := range m.queries {
		switch query.kind {
		case "authentication":
			principals, _ = appendUniqueString(principals, query.message.sender)
			principals, _ = appendUniqueString(principals, query.message.recipient)
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

func sanityEquivalentValues(a1 value, a2 value, valPrincipalState principalState) bool {
	switch a1.kind {
	case "constant":
		switch a2.kind {
		case "constant":
			if a1.constant.name != a2.constant.name {
				return false
			}
		case "primitive":
			return false
		case "equation":
			return false
		}
	case "primitive":
		switch a2.kind {
		case "constant":
			return false
		case "primitive":
			equivPrim, _, _ := sanityEquivalentPrimitives(
				a1.primitive, a2.primitive, valPrincipalState, true,
			)
			return equivPrim
		case "equation":
			return false
		}
	case "equation":
		switch a2.kind {
		case "constant":
			return false
		case "primitive":
			return false
		case "equation":
			return sanityEquivalentEquations(
				a1.equation, a2.equation, valPrincipalState,
			)
		}
	}
	return true
}

func sanityEquivalentPrimitives(
	p1 primitive, p2 primitive, valPrincipalState principalState, considerOutput bool,
) (bool, int, int) {
	if p1.name != p2.name {
		return false, 0, 0
	}
	if len(p1.arguments) != len(p2.arguments) {
		return false, 0, 0
	}
	if considerOutput && (p1.output != p2.output) {
		return false, 0, 0
	}
	for i := range p1.arguments {
		equiv := sanityEquivalentValues(p1.arguments[i], p2.arguments[i], valPrincipalState)
		if !equiv {
			return false, 0, 0
		}
	}
	return true, p1.output, p2.output
}

func sanityEquivalentEquations(e1 equation, e2 equation, valPrincipalState principalState) bool {
	e1Values := sanityDecomposeEquationValues(e1, valPrincipalState)
	e2Values := sanityDecomposeEquationValues(e2, valPrincipalState)
	if len(e1Values) != len(e2Values) || len(e1Values) == 0 {
		return false
	}
	if e1Values[0].kind == "equation" && e2Values[0].kind == "equation" {
		return sanityEquivalentEquationsFull(e1Values, e2Values, valPrincipalState)
	}
	if len(e1Values) > 2 {
		if sanityEquivalentValues(e1Values[1], e2Values[2], valPrincipalState) &&
			sanityEquivalentValues(e1Values[2], e2Values[1], valPrincipalState) {
			return true
		}
		if sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) &&
			sanityEquivalentValues(e1Values[2], e2Values[2], valPrincipalState) {
			return true
		}
		return false
	}
	if sanityEquivalentValues(e1Values[0], e2Values[0], valPrincipalState) &&
		sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
		return true
	}
	return false
}

func sanityEquivalentEquationsFull(e1Values []value, e2Values []value, valPrincipalState principalState) bool {
	e1Base := sanityDecomposeEquationValues(e1Values[0].equation, valPrincipalState)
	e2Base := sanityDecomposeEquationValues(e2Values[0].equation, valPrincipalState)
	if sanityEquivalentValues(e1Base[1], e2Values[1], valPrincipalState) &&
		sanityEquivalentValues(e1Values[1], e2Base[1], valPrincipalState) {
		return true
	}
	if sanityEquivalentValues(e1Base[1], e2Base[1], valPrincipalState) &&
		sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
		return true
	}
	return false
}

func sanityDecomposeEquationValues(e equation, valPrincipalState principalState) []value {
	values := []value{}
	for _, v := range e.values {
		switch v.kind {
		case "constant":
			v = sanityResolveConstant(v.constant, valPrincipalState)
		}
		values = append(values, v)
	}
	return values
}

func sanityFindConstantInPrimitive(
	c constant, p primitive, valPrincipalState principalState,
) bool {
	a := sanityResolveConstant(c, valPrincipalState)
	for _, aa := range p.arguments {
		switch aa.kind {
		case "constant":
			if c.name == aa.constant.name {
				return true
			}
			switch a.kind {
			case "constant":
				if a.constant.name == aa.constant.name {
					return true
				}
			}
		case "primitive":
			switch a.kind {
			case "primitive":
				equivPrim, _, _ := sanityEquivalentPrimitives(
					a.primitive, aa.primitive, valPrincipalState, true,
				)
				if equivPrim {
					return true
				}
			}
			if sanityFindConstantInPrimitive(c, aa.primitive, valPrincipalState) {
				return true
			}
		case "equation":
			if sanityFindConstantInEquation(c, aa.equation, valPrincipalState) {
				return true
			}
		}
	}
	return false
}

func sanityFindConstantInEquation(
	c constant, e equation, valPrincipalState principalState,
) bool {
	a := sanityResolveConstant(c, valPrincipalState)
	switch a.kind {
	case "equation":
		if sanityEquivalentEquations(a.equation, e, valPrincipalState) {
			return true
		}
	}
	v := sanityDecomposeEquationValues(e, valPrincipalState)
	for _, vv := range v {
		switch vv.kind {
		case "constant":
			if c.name == vv.constant.name {
				return true
			}
			switch a.kind {
			case "constant":
				if a.constant.name == vv.constant.name {
					return true
				}
			}
		}
	}
	return false
}

func sanityExactSameValueInValues(v value, assigneds []value) int {
	index := -1
assignedsLoop:
	for i, a := range assigneds {
		if v.kind != a.kind {
			continue
		}
		switch v.kind {
		case "constant":
			if v.constant.name != a.constant.name {
				continue
			}
		case "primitive":
			if len(v.primitive.arguments) != len(a.primitive.arguments) {
				continue
			}
			if v.primitive.output != a.primitive.output {
				continue
			}
			for i := range v.primitive.arguments {
				if sanityExactSameValueInValues(
					v.primitive.arguments[i],
					[]value{a.primitive.arguments[i]},
				) < 0 {
					continue assignedsLoop
				}
			}
		case "equation":
			if len(v.equation.values) != len(a.equation.values) {
				continue
			}
			for i := range v.equation.values {
				if sanityExactSameValueInValues(
					v.equation.values[i],
					[]value{a.equation.values[i]},
				) < 0 {
					continue assignedsLoop
				}
			}
		}
		index = i
		break
	}
	return index
}

func sanityEquivalentValueInValues(v value, assigneds []value, valPrincipalState principalState) int {
	index := -1
	for i, a := range assigneds {
		if sanityEquivalentValues(v, a, valPrincipalState) {
			index = i
			break
		}
	}
	return index
}

func sanityPerformPrimitiveRewrite(
	p primitive, pi int, valPrincipalState principalState,
) ([]primitive, bool, value, principalState) {
	var rewritten bool
	var failedRewrites []primitive
	var pFailedRewrite []primitive
	var prewritten bool
	var pRewrite value
	var eFailedRewrite []primitive
	var erewritten bool
	var eRewrite value
	rewrite := value{
		kind: "primitive",
		primitive: primitive{
			name:      p.name,
			arguments: make([]value, len(p.arguments)),
			output:    p.output,
			check:     p.check,
		},
	}
	for i, a := range p.arguments {
		switch a.kind {
		case "constant":
			rewrite.primitive.arguments[i] = p.arguments[i]
		case "primitive":
			pFailedRewrite, prewritten, pRewrite, valPrincipalState = sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if prewritten {
				rewritten = true
				rewrite.primitive.arguments[i] = pRewrite
				continue
			}
			rewrite.primitive.arguments[i] = p.arguments[i]
			failedRewrites = append(failedRewrites, pFailedRewrite...)
		case "equation":
			eFailedRewrite, erewritten, eRewrite, valPrincipalState = sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if erewritten {
				rewritten = true
				rewrite.primitive.arguments[i] = eRewrite
				continue
			}
			rewrite.primitive.arguments[i] = p.arguments[i]
			failedRewrites = append(failedRewrites, eFailedRewrite...)
		}
	}
	wasRebuilt, rebuild := possibleToRebuild(rewrite.primitive, valPrincipalState)
	if wasRebuilt {
		rewrite = rebuild
		if pi >= 0 {
			valPrincipalState.assigned[pi] = rebuild
			if !valPrincipalState.mutated[pi] {
				valPrincipalState.beforeMutate[pi] = rebuild
			}
		}
		switch rebuild.kind {
		case "constant", "equation":
			return failedRewrites, rewritten, rewrite, valPrincipalState
		}
	}
	rewrittenTotal, rewrite := possibleToRewrite(rewrite.primitive, valPrincipalState)
	if rewrittenTotal {
		rewritten = true
	} else {
		failedRewrites = append(failedRewrites, rewrite.primitive)
	}
	if rewritten && pi >= 0 {
		valPrincipalState.rewritten[pi] = true
		valPrincipalState.assigned[pi] = rewrite
		if !valPrincipalState.mutated[pi] {
			valPrincipalState.beforeMutate[pi] = rewrite
		}
	}
	return failedRewrites, rewritten, rewrite, valPrincipalState
}

func sanityPerformEquationRewrite(
	e equation, pi int, valPrincipalState principalState,
) ([]primitive, bool, value, principalState) {
	var rewritten bool
	var failedRewrites []primitive
	var pFailedRewrite []primitive
	var prewritten bool
	var pRewrite value
	var eFailedRewrite []primitive
	var erewritten bool
	var eRewrite value
	rewrite := value{
		kind: "equation",
		equation: equation{
			values: []value{},
		},
	}
	for i, a := range e.values {
		switch a.kind {
		case "constant":
			rewrite.equation.values = append(rewrite.equation.values, a)
		case "primitive":
			prim := primitiveGet(a.primitive.name)
			if !prim.rewrite.hasRule {
				continue
			}
			pFailedRewrite, prewritten, pRewrite, valPrincipalState = sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if !prewritten {
				rewrite.equation.values = append(rewrite.equation.values, e.values[i])
				failedRewrites = append(failedRewrites, pFailedRewrite...)
				continue
			}
			rewritten = true
			switch pRewrite.kind {
			case "constant":
				rewrite.equation.values = append(rewrite.equation.values, pRewrite)
			case "primitive":
				rewrite.equation.values = append(rewrite.equation.values, pRewrite)
			case "equation":
				rewrite.equation.values = append(rewrite.equation.values, pRewrite.equation.values...)
			}
		case "equation":
			eFailedRewrite, erewritten, eRewrite, valPrincipalState = sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if !erewritten {
				rewrite.equation.values = append(rewrite.equation.values, e.values[i])
				failedRewrites = append(failedRewrites, eFailedRewrite...)
				continue
			}
			rewritten = true
			rewrite.equation.values = append(rewrite.equation.values, eRewrite)
		}
	}
	if rewritten && pi >= 0 {
		valPrincipalState.rewritten[pi] = true
		valPrincipalState.assigned[pi] = rewrite
		if !valPrincipalState.mutated[pi] {
			valPrincipalState.beforeMutate[pi] = rewrite
		}
	}
	return failedRewrites, rewritten, rewrite, valPrincipalState
}

func sanityPerformAllRewrites(valPrincipalState principalState) ([]primitive, []int, principalState) {
	var failedRewrites []primitive
	var failedRewriteIndices []int
	var failedRewrite []primitive
	for i := range valPrincipalState.assigned {
		switch valPrincipalState.assigned[i].kind {
		case "primitive":
			failedRewrite, _, _, valPrincipalState = sanityPerformPrimitiveRewrite(
				valPrincipalState.assigned[i].primitive, i, valPrincipalState,
			)
			if len(failedRewrite) == 0 {
				continue
			}
			failedRewrites = append(failedRewrites, failedRewrite...)
			for range failedRewrite {
				failedRewriteIndices = append(failedRewriteIndices, i)
			}
		case "equation":
			failedRewrite, _, _, valPrincipalState = sanityPerformEquationRewrite(
				valPrincipalState.assigned[i].equation, i, valPrincipalState,
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

func sanityFailOnFailedRewrite(failedRewrites []primitive) {
	for _, p := range failedRewrites {
		if !p.check {
			continue
		}
		errorCritical(fmt.Sprintf(
			"checked primitive fails: %s",
			prettyPrimitive(p),
		))
	}
}

func sanityCheckEquationRootGenerator(e equation) {
	if len(e.values) > 3 {
		errorCritical(fmt.Sprintf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		))
	}
	for i, c := range e.values {
		if i == 0 {
			if strings.ToLower(c.constant.name) != "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) does not use 'g' as generator",
					prettyEquation(e),
				))
			}
		}
		if i > 0 {
			if strings.ToLower(c.constant.name) == "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) uses 'g' not as a generator",
					prettyEquation(e),
				))
			}
		}
	}
}

func sanityCheckEquationGenerators(a value, valPrincipalState principalState) {
	switch a.kind {
	case "primitive":
		for _, va := range a.primitive.arguments {
			switch va.kind {
			case "primitive":
				sanityCheckEquationGenerators(va, valPrincipalState)
			case "equation":
				sanityCheckEquationRootGenerator(va.equation)
			}
		}
	case "equation":
		sanityCheckEquationRootGenerator(a.equation)
	}
}

func sanityShouldResolveToBeforeMutate(i int, valPrincipalState principalState) bool {
	if valPrincipalState.creator[i] == valPrincipalState.name {
		return true
	}
	if !valPrincipalState.known[i] {
		return true
	}
	if !strInSlice(valPrincipalState.name, valPrincipalState.wire[i]) {
		return true
	}
	if !valPrincipalState.mutated[i] {
		return true
	}

	return false
}

func sanityResolveConstant(c constant, valPrincipalState principalState) value {
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return value{kind: "constant", constant: c}
	}
	if sanityShouldResolveToBeforeMutate(i, valPrincipalState) {
		return valPrincipalState.beforeMutate[i]
	}
	return valPrincipalState.assigned[i]
}

func sanityResolveValueInternalValuesFromKnowledgeMap(
	a value, valKnowledgeMap knowledgeMap,
) (value, []value) {
	var v []value
	switch a.kind {
	case "constant":
		if sanityExactSameValueInValues(a, v) < 0 {
			v = append(v, a)
		}
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.constant)
		a = valKnowledgeMap.assigned[i]
	}
	switch a.kind {
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
	a value, v []value, valKnowledgeMap knowledgeMap,
) (value, []value) {
	return a, v
}

func sanityResolvePrimitiveInternalValuesFromKnowledgeMap(
	a value, v []value, valKnowledgeMap knowledgeMap,
) (value, []value) {
	r := value{
		kind: "primitive",
		primitive: primitive{
			name:      a.primitive.name,
			arguments: []value{},
			output:    a.primitive.output,
			check:     a.primitive.check,
		},
	}
	for _, aa := range a.primitive.arguments {
		s, vv := sanityResolveValueInternalValuesFromKnowledgeMap(aa, valKnowledgeMap)
		for _, vvv := range vv {
			if sanityExactSameValueInValues(vvv, v) < 0 {
				v = append(v, vvv)
			}
		}
		r.primitive.arguments = append(r.primitive.arguments, s)
	}
	return r, v
}

func sanityResolveEquationInternalValuesFromKnowledgeMap(
	a value, v []value, valKnowledgeMap knowledgeMap,
) (value, []value) {
	r := value{
		kind: "equation",
		equation: equation{
			values: []value{},
		},
	}
	aa := []value{}
	for _, c := range a.equation.values {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c.constant)
		aa = append(aa, valKnowledgeMap.assigned[i])
	}
	for aai := range aa {
		switch aa[aai].kind {
		case "constant":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aa[aai].constant)
			aa[aai] = valKnowledgeMap.assigned[i]
		}
	}
	for aai := range aa {
		switch aa[aai].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[aai])
		case "primitive":
			r.equation.values = append(r.equation.values, aa[aai])
		case "equation":
			if aai == 0 {
				r.equation.values = aa[aai].equation.values
			} else {
				r.equation.values = append(r.equation.values, aa[aai].equation.values[1:]...)
			}
			if sanityExactSameValueInValues(r, v) < 0 {
				v = append(v, r)
			}
		}
	}
	if sanityExactSameValueInValues(r, v) < 0 {
		v = append(v, r)
	}
	return r, v
}

func sanityResolveValueInternalValuesFromPrincipalState(
	a value, rootValue value, rootIndex int,
	valPrincipalState principalState, valAttackerState attackerState, forceBeforeMutate bool,
) value {
	switch a.kind {
	case "constant":
		nextRootIndex := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
		switch nextRootIndex {
		case rootIndex:
			if !forceBeforeMutate {
				forceBeforeMutate = sanityShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.beforeMutate[nextRootIndex]
			} else {
				a = sanityResolveConstant(a.constant, valPrincipalState)
			}
		default:
			switch rootValue.kind {
			case "primitive":
				x, _ := possibleToReconstructPrimitive(rootValue.primitive, valPrincipalState, valAttackerState)
				if !x && valPrincipalState.creator[rootIndex] != valPrincipalState.name {
					forceBeforeMutate = true
				}
			}
			if !forceBeforeMutate {
				forceBeforeMutate = sanityShouldResolveToBeforeMutate(nextRootIndex, valPrincipalState)
			}
			if forceBeforeMutate {
				a = valPrincipalState.beforeMutate[nextRootIndex]
			} else {
				a = sanityResolveConstant(a.constant, valPrincipalState)
			}
			rootIndex = nextRootIndex
			rootValue = a
		}
	}
	switch a.kind {
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
	a value, rootValue value, rootIndex int,
	valPrincipalState principalState, valAttackerState attackerState, forceBeforeMutate bool,
) value {
	if valPrincipalState.creator[rootIndex] == valPrincipalState.name {
		forceBeforeMutate = false
	}
	r := value{
		kind: "primitive",
		primitive: primitive{
			name:      a.primitive.name,
			arguments: []value{},
			output:    a.primitive.output,
			check:     a.primitive.check,
		},
	}
	for _, aa := range a.primitive.arguments {
		s := sanityResolveValueInternalValuesFromPrincipalState(
			aa, rootValue, rootIndex, valPrincipalState, valAttackerState, forceBeforeMutate,
		)
		r.primitive.arguments = append(r.primitive.arguments, s)
	}
	return r
}

func sanityResolveEquationInternalValuesFromPrincipalState(
	a value, rootValue value, rootIndex int,
	valPrincipalState principalState, valAttackerState attackerState, forceBeforeMutate bool,
) value {
	if valPrincipalState.creator[rootIndex] == valPrincipalState.name {
		forceBeforeMutate = false
	}
	r := value{
		kind: "equation",
		equation: equation{
			values: []value{},
		},
	}
	aa := []value{}
	aa = append(aa, a.equation.values...)
	for aai := range aa {
		switch aa[aai].kind {
		case "constant":
			if forceBeforeMutate {
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, aa[aai].constant)
				aa[aai] = valPrincipalState.beforeMutate[i]
			} else {
				aa[aai] = sanityResolveConstant(aa[aai].constant, valPrincipalState)
			}
		}
	}
	for aai := range aa {
		switch aa[aai].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[aai])
		case "primitive":
			aaa := sanityResolveValueInternalValuesFromPrincipalState(
				aa[aai], rootValue, rootIndex,
				valPrincipalState, valAttackerState, forceBeforeMutate,
			)
			r.equation.values = append(r.equation.values, aaa)
		case "equation":
			if aai == 0 {
				r.equation.values = aa[aai].equation.values
			} else {
				r.equation.values = append(r.equation.values, aa[aai].equation.values[1:]...)
			}
		}
	}
	return r
}

func sanityConstantIsUsedByPrincipalInKnowledgeMap(
	valKnowledgeMap knowledgeMap, name string, c constant,
) bool {
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	for ii, a := range valKnowledgeMap.assigned {
		if valKnowledgeMap.creator[ii] != name {
			continue
		}
		switch a.kind {
		case "primitive":
			_, v := sanityResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
			if sanityExactSameValueInValues(valKnowledgeMap.assigned[i], v) >= 0 {
				return true
			}
			if sanityExactSameValueInValues(value{kind: "constant", constant: c}, v) >= 0 {
				return true
			}
		}
	}
	return false
}

func sanityResolveAllPrincipalStateValues(
	valPrincipalState principalState, valAttackerState attackerState,
) principalState {
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	for i := range valPrincipalState.assigned {
		valPrincipalStateClone.assigned[i] = sanityResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.assigned[i], valPrincipalState.assigned[i], i, valPrincipalState, valAttackerState,
			sanityShouldResolveToBeforeMutate(i, valPrincipalState),
		)
		valPrincipalStateClone.beforeRewrite[i] = sanityResolveValueInternalValuesFromPrincipalState(
			valPrincipalState.beforeRewrite[i], valPrincipalState.beforeRewrite[i], i, valPrincipalState, valAttackerState,
			sanityShouldResolveToBeforeMutate(i, valPrincipalState),
		)
	}
	return valPrincipalStateClone
}
