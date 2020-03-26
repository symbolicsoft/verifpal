/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package verifpal

import (
	"fmt"
	"strings"
)

func sanity(m Model) (knowledgeMap, []principalState) {
	sanityPhases(m)
	principals := sanityDeclaredPrincipals(m)
	valKnowledgeMap := constructKnowledgeMap(m, principals)
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

func sanityAssignmentConstants(
	right value, constants []constant, valKnowledgeMap knowledgeMap,
) []constant {
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
	arity := 0
	if primitiveIsCorePrim(right.primitive.name) {
		prim, _ := primitiveCoreGet(right.primitive.name)
		arity = prim.arity
	} else {
		prim, err := primitiveGet(right.primitive.name)
		if err != nil {
			errorCritical(err.Error())
		}
		arity = prim.arity
	}
	if (len(right.primitive.arguments) == 0) ||
		(len(right.primitive.arguments) > 5) ||
		((arity >= 0) && (len(right.primitive.arguments) != arity)) {
		arityString := fmt.Sprintf("%d", arity)
		if arity < 0 {
			arityString = "between 1 and 5"
		}
		errorCritical(fmt.Sprintf(
			"primitive %s has %d inputs, expecting %s",
			right.primitive.name, len(right.primitive.arguments), arityString,
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
	output := 0
	check := false
	if primitiveIsCorePrim(p.name) {
		prim, _ := primitiveCoreGet(p.name)
		output = prim.output
		check = prim.check
	} else {
		prim, err := primitiveGet(p.name)
		if err != nil {
			errorCritical(err.Error())
		}
		output = prim.output
		check = prim.check
	}
	if (len(outputs) != output) && (output >= 0) {
		outputString := fmt.Sprintf("%d", output)
		if output < 0 {
			outputString = "at least 1"
		}
		errorCritical(fmt.Sprintf(
			"primitive %s has %d outputs, expecting %s",
			p.name, len(outputs), outputString,
		))
	}
	if p.check && !check {
		errorCritical(fmt.Sprintf(
			"primitive %s is checked but does not support checking",
			p.name,
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
	for i := range valKnowledgeMap.constants {
		if valKnowledgeMap.constants[i].name == c.name {
			return i
		}
	}
	return -1
}

func sanityGetPrincipalStateIndexFromConstant(valPrincipalState principalState, c constant) int {
	for i := range valPrincipalState.constants {
		if valPrincipalState.constants[i].name == c.name {
			return i
		}
	}
	return -1
}

func sanityDeclaredPrincipals(m Model) []string {
	declared := []string{}
	principals := []string{}
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			principals, _ = appendUniqueString(principals, block.principal.name)
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

func sanityEquivalentValues(a1 value, a2 value) bool {
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
				a1.primitive, a2.primitive, true,
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
				a1.equation, a2.equation,
			)
		}
	}
	return true
}

func sanityEquivalentPrimitives(
	p1 primitive, p2 primitive, considerOutput bool,
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
		equiv := sanityEquivalentValues(p1.arguments[i], p2.arguments[i])
		if !equiv {
			return false, 0, 0
		}
	}
	return true, p1.output, p2.output
}

func sanityEquivalentEquations(e1 equation, e2 equation) bool {
	e1Base := e1.values[0].equation.values
	e2Base := e2.values[0].equation.values
	if len(e1.values) != len(e2.values) || len(e1.values) == 0 {
		return false
	}
	if e1.values[0].kind == "equation" && e2.values[0].kind == "equation" {
		if sanityEquivalentValues(e1Base[1], e2.values[1]) &&
			sanityEquivalentValues(e1.values[1], e2Base[1]) {
			return true
		}
		if sanityEquivalentValues(e1Base[1], e2Base[1]) &&
			sanityEquivalentValues(e1.values[1], e2.values[1]) {
			return true
		}
		return false
	}
	if len(e1.values) > 2 {
		if sanityEquivalentValues(e1.values[1], e2.values[2]) &&
			sanityEquivalentValues(e1.values[2], e2.values[1]) {
			return true
		}
		if sanityEquivalentValues(e1.values[1], e2.values[1]) &&
			sanityEquivalentValues(e1.values[2], e2.values[2]) {
			return true
		}
		return false
	}
	if sanityEquivalentValues(e1.values[0], e2.values[0]) &&
		sanityEquivalentValues(e1.values[1], e2.values[1]) {
		return true
	}
	return false
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
					a.primitive, aa.primitive, true,
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
		if sanityEquivalentEquations(a.equation, e) {
			return true
		}
	}
	for _, ee := range e.values {
		switch ee.kind {
		case "constant":
			if c.name == ee.constant.name {
				return true
			}
			switch a.kind {
			case "constant":
				if a.constant.name == ee.constant.name {
					return true
				}
			}
		}
	}
	return false
}

func sanityEquivalentValueInValues(v value, a []value) int {
	index := -1
	for i, aa := range a {
		if sanityEquivalentValues(v, aa) {
			index = i
			break
		}
	}
	return index
}

func sanityPerformPrimitiveRewrite(
	p primitive, pi int, valPrincipalState principalState,
) ([]primitive, bool, value) {
	rewritten := false
	failedRewrites := []primitive{}
	rIndex := 0
	rewrites := []value{{
		kind: "primitive",
		primitive: primitive{
			name:      p.name,
			arguments: make([]value, len(p.arguments)),
			output:    p.output,
			check:     p.check,
		},
	}}
	for i, a := range p.arguments {
		switch a.kind {
		case "constant":
			rewrites[0].primitive.arguments[i] = p.arguments[i]
		case "primitive":
			pFailedRewrite, pRewritten, pRewrite := sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if pRewritten {
				rewritten = true
				rewrites[rIndex].primitive.arguments[i] = pRewrite
				continue
			}
			rewrites[rIndex].primitive.arguments[i] = p.arguments[i]
			failedRewrites = append(failedRewrites, pFailedRewrite...)
		case "equation":
			eFailedRewrite, eRewritten, eRewrite := sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if eRewritten {
				rewritten = true
				rewrites[rIndex].primitive.arguments[i] = eRewrite
				continue
			}
			rewrites[rIndex].primitive.arguments[i] = p.arguments[i]
			failedRewrites = append(failedRewrites, eFailedRewrite...)
		}
	}
	wasRebuilt, rebuild := possibleToRebuild(rewrites[rIndex].primitive)
	if wasRebuilt {
		rewrites[0] = rebuild
		if pi >= 0 {
			valPrincipalState.assigned[pi] = rebuild
			if !valPrincipalState.mutated[pi] {
				valPrincipalState.beforeMutate[pi] = rebuild
			}
		}
		switch rebuild.kind {
		case "constant", "equation":
			return failedRewrites, rewritten, rewrites[rIndex]
		}
	}
	rewrittenRoot, rewrites := possibleToRewrite(rewrites[rIndex].primitive, valPrincipalState)
	if !rewrittenRoot {
		failedRewrites = append(failedRewrites, rewrites[rIndex].primitive)
	} else if primitiveIsCorePrim(p.name) {
		rIndex = p.output
	}
	if (rewritten || rewrittenRoot) && pi >= 0 {
		valPrincipalState.rewritten[pi] = true
		valPrincipalState.assigned[pi] = rewrites[rIndex]
		if !valPrincipalState.mutated[pi] {
			valPrincipalState.beforeMutate[pi] = rewrites[rIndex]
		}
	}
	return failedRewrites, (rewritten || rewrittenRoot), rewrites[rIndex]
}

func sanityPerformEquationRewrite(
	e equation, pi int, valPrincipalState principalState,
) ([]primitive, bool, value) {
	rewritten := false
	failedRewrites := []primitive{}
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
			hasRule := false
			if primitiveIsCorePrim(a.primitive.name) {
				prim, _ := primitiveCoreGet(a.primitive.name)
				hasRule = prim.hasRule
			} else {
				prim, _ := primitiveGet(a.primitive.name)
				hasRule = prim.rewrite.hasRule
			}
			if !hasRule {
				continue
			}
			pFailedRewrite, pRewritten, pRewrite := sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if !pRewritten {
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
			eFailedRewrite, eRewritten, eRewrite := sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if !eRewritten {
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
	return failedRewrites, rewritten, rewrite
}

func sanityPerformAllRewrites(valPrincipalState principalState) ([]primitive, []int, principalState) {
	failedRewrites := []primitive{}
	failedRewriteIndices := []int{}
	for i := range valPrincipalState.assigned {
		switch valPrincipalState.assigned[i].kind {
		case "primitive":
			failedRewrite, _, _ := sanityPerformPrimitiveRewrite(
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
			failedRewrite, _, _ := sanityPerformEquationRewrite(
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

func sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites []primitive) {
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
		if sanityEquivalentValueInValues(a, v) < 0 {
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
			if sanityEquivalentValueInValues(vvv, v) < 0 {
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
				x, _ := possibleToReconstructPrimitive(rootValue.primitive, valAttackerState)
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
			if sanityEquivalentValueInValues(valKnowledgeMap.assigned[i], v) >= 0 {
				return true
			}
			if sanityEquivalentValueInValues(value{kind: "constant", constant: c}, v) >= 0 {
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
