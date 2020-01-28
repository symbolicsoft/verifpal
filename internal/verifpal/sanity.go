/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package verifpal

import (
	"fmt"
	"strings"
	"sync"
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
			constantUsedByPrincipal := sanityConstantIsUsedByPrincipal(valKnowledgeMap, query.message.recipient, c)
			sanityQueriesCheckKnown(query, c, senderKnows, recipientKnows, constantUsedByPrincipal)
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

func sanityGetAttackerStateIndexFromConstant(valAttackerState attackerState, c constant) int {
	for i, cc := range valAttackerState.known {
		switch cc.kind {
		case "constant":
			if cc.constant.name == c.name {
				return i
			}
		}
	}
	return -1
}

func sanityDeclaredPrincipals(m Model) []string {
	var principals []string
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			principals, _ = appendUnique(principals, block.principal.name)
		case "message":
			if !strInSlice(block.message.sender, principals) {
				errorCritical(fmt.Sprintf(
					"principal does not exist (%s)",
					block.message.sender,
				))
			}
			if !strInSlice(block.message.recipient, principals) {
				errorCritical(fmt.Sprintf(
					"principal does not exist (%s)",
					block.message.recipient,
				))
			}
		}
	}
	for _, query := range m.queries {
		switch query.kind {
		case "authentication":
			if !strInSlice(query.message.sender, principals) {
				errorCritical(fmt.Sprintf(
					"principal does not exist (%s)",
					query.message.sender,
				))
			}
			if !strInSlice(query.message.recipient, principals) {
				errorCritical(fmt.Sprintf(
					"principal does not exist (%s)",
					query.message.recipient,
				))
			}
		}
	}
	if len(principals) > 64 {
		errorCritical(fmt.Sprintf(
			"more than 64 principals not supported (%d declared)",
			len(principals),
		))
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
			equivPrim, _, _ := sanityEquivalentPrimitives(a1.primitive, a2.primitive, valPrincipalState, true)
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
			return sanityEquivalentEquations(a1.equation, a2.equation, valPrincipalState)
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
	if (len(e1Values) == 0) || (len(e2Values) == 0) {
		return false
	}
	if len(e1Values) != len(e2Values) {
		return false
	}
	if e1Values[0].kind == "equation" && e2Values[0].kind == "equation" {
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
	if len(e1Values) > 2 {
		if sanityEquivalentValues(e1Values[1], e2Values[2], valPrincipalState) {
			if sanityEquivalentValues(e1Values[2], e2Values[1], valPrincipalState) {
				return true
			}
		}
		if sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
			if sanityEquivalentValues(e1Values[2], e2Values[2], valPrincipalState) {
				return true
			}
		}
	} else if sanityEquivalentValues(e1Values[0], e2Values[0], valPrincipalState) {
		if sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
			return true
		}
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
			switch a.kind {
			case "equation":
				if sanityEquivalentEquations(a.equation, aa.equation, valPrincipalState) {
					return true
				}
			}
			v := sanityDecomposeEquationValues(aa.equation, valPrincipalState)
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
		}
	}
	return false
}

func sanityExactSameValueInValues(v value, assigneds []value) int {
	index := -1
	for i, a := range assigneds {
		vs := prettyValue(v)
		as := prettyValue(a)
		switch v.kind {
		case "primitive":
			vs = fmt.Sprintf("%s|%d", vs, v.primitive.output)
		}
		switch a.kind {
		case "primitive":
			as = fmt.Sprintf("%s|%d", as, a.primitive.output)
		}
		if vs == as {
			index = i
			break
		}
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
	var wasRewritten bool
	var failedRewrites []primitive
	var pFailedRewrite []primitive
	var pWasRewritten bool
	var pRewrite value
	var eFailedRewrite []primitive
	var eWasRewritten bool
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
			pFailedRewrite, pWasRewritten, pRewrite, valPrincipalState = sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if pWasRewritten {
				wasRewritten = true
				rewrite.primitive.arguments[i] = pRewrite
			} else {
				rewrite.primitive.arguments[i] = p.arguments[i]
				failedRewrites = append(failedRewrites, pFailedRewrite...)
			}
		case "equation":
			eFailedRewrite, eWasRewritten, eRewrite, valPrincipalState = sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if eWasRewritten {
				wasRewritten = true
				rewrite.primitive.arguments[i] = eRewrite
			} else {
				rewrite.primitive.arguments[i] = p.arguments[i]
				failedRewrites = append(failedRewrites, eFailedRewrite...)
			}
		}
	}
	wasRebuilt, rebuild := possibleToRebuild(rewrite.primitive, valPrincipalState)
	if wasRebuilt {
		rewrite = rebuild
		if pi >= 0 {
			valPrincipalState.assigned[pi] = rebuild
			if !valPrincipalState.wasMutated[pi] {
				valPrincipalState.beforeMutate[pi] = rebuild
			}
		}
		switch rebuild.kind {
		case "constant", "equation":
			return failedRewrites, wasRewritten, rewrite, valPrincipalState
		}
	}
	wasRewrittenTotal, rewrite := possibleToRewrite(rewrite.primitive, valPrincipalState)
	if wasRewrittenTotal {
		wasRewritten = true
	} else {
		failedRewrites = append(failedRewrites, rewrite.primitive)
	}
	if wasRewritten && pi >= 0 {
		valPrincipalState.wasRewritten[pi] = true
		valPrincipalState.assigned[pi] = rewrite
		if !valPrincipalState.wasMutated[pi] {
			valPrincipalState.beforeMutate[pi] = rewrite
		}
	}
	return failedRewrites, wasRewritten, rewrite, valPrincipalState
}

func sanityPerformEquationRewrite(
	e equation, pi int, valPrincipalState principalState,
) ([]primitive, bool, value, principalState) {
	var wasRewritten bool
	var failedRewrites []primitive
	var pFailedRewrite []primitive
	var pWasRewritten bool
	var pRewrite value
	var eFailedRewrite []primitive
	var eWasRewritten bool
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
			pFailedRewrite, pWasRewritten, pRewrite, valPrincipalState = sanityPerformPrimitiveRewrite(
				a.primitive, -1, valPrincipalState,
			)
			if pWasRewritten {
				wasRewritten = true
				switch pRewrite.kind {
				case "constant":
					rewrite.equation.values = append(rewrite.equation.values, pRewrite)
				case "primitive":
					rewrite.equation.values = append(rewrite.equation.values, pRewrite)
				case "equation":
					rewrite.equation.values = append(rewrite.equation.values, pRewrite.equation.values...)
				}
				continue
			}
			rewrite.equation.values = append(rewrite.equation.values, e.values[i])
			failedRewrites = append(failedRewrites, pFailedRewrite...)
		case "equation":
			eFailedRewrite, eWasRewritten, eRewrite, valPrincipalState = sanityPerformEquationRewrite(
				a.equation, -1, valPrincipalState,
			)
			if eWasRewritten {
				wasRewritten = true
				rewrite.equation.values = append(rewrite.equation.values, eRewrite)
				continue
			}
			rewrite.equation.values = append(rewrite.equation.values, e.values[i])
			failedRewrites = append(failedRewrites, eFailedRewrite...)
		}
	}
	if wasRewritten && pi >= 0 {
		valPrincipalState.wasRewritten[pi] = true
		valPrincipalState.assigned[pi] = rewrite
		if !valPrincipalState.wasMutated[pi] {
			valPrincipalState.beforeMutate[pi] = rewrite
		}
	}
	return failedRewrites, wasRewritten, rewrite, valPrincipalState
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
	return !valPrincipalState.wasMutated[i]
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
		v = append(v, a)
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.constant)
		a = valKnowledgeMap.assigned[i]
	}
	switch a.kind {
	case "constant":
		return a, v
	case "primitive":
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
			v = append(v, vv...)
			r.primitive.arguments = append(r.primitive.arguments, s)
		}
		return r, v
	case "equation":
		r := value{
			kind: "equation",
			equation: equation{
				values: []value{},
			},
		}
		if len(a.equation.values) > 2 {
			v = append(v, a.equation.values...)
			return a, v
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
				aaa, _ := sanityResolveValueInternalValuesFromKnowledgeMap(aa[aai], valKnowledgeMap)
				if aai == 0 {
					r.equation.values = aaa.equation.values
				} else {
					r.equation.values = append(r.equation.values, aaa.equation.values[1:]...)
				}
			}
		}
		v = append(v, r.equation.values...)
		return r, v
	}
	return a, v
}

func sanityResolveValueInternalValuesFromPrincipalState(
	a value, rootIndex int, valPrincipalState principalState, forceBeforeMutate bool,
) (value, []value) {
	var v []value
	switch a.kind {
	case "constant":
		rootIndex = sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
		if !forceBeforeMutate {
			forceBeforeMutate = sanityShouldResolveToBeforeMutate(rootIndex, valPrincipalState)
		}
		if forceBeforeMutate {
			a = valPrincipalState.beforeMutate[rootIndex]
		} else {
			a = sanityResolveConstant(a.constant, valPrincipalState)
		}
		v = append(v, a)
	}
	switch a.kind {
	case "constant":
		return sanityResolveConstantInternalValuesFromPrincipalState(a, v, rootIndex, valPrincipalState, forceBeforeMutate)
	case "primitive":
		return sanityResolvePrimitiveInternalValuesFromPrincipalState(a, v, rootIndex, valPrincipalState, forceBeforeMutate)
	case "equation":
		return sanityResolveEquationInternalValuesFromPrincipalState(a, v, rootIndex, valPrincipalState, forceBeforeMutate)
	}
	return a, v
}

func sanityResolveConstantInternalValuesFromPrincipalState(
	a value, v []value, rootIndex int, valPrincipalState principalState, forceBeforeMutate bool,
) (value, []value) {
	return a, v
}

func sanityResolvePrimitiveInternalValuesFromPrincipalState(
	a value, v []value, rootIndex int, valPrincipalState principalState, forceBeforeMutate bool,
) (value, []value) {
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
		s, vv := sanityResolveValueInternalValuesFromPrincipalState(aa, rootIndex, valPrincipalState, forceBeforeMutate)
		v = append(v, vv...)
		r.primitive.arguments = append(r.primitive.arguments, s)
	}
	return r, v
}

func sanityResolveEquationInternalValuesFromPrincipalState(
	a value, v []value, rootIndex int, valPrincipalState principalState, forceBeforeMutate bool,
) (value, []value) {
	if valPrincipalState.creator[rootIndex] == valPrincipalState.name {
		forceBeforeMutate = false
	}
	r := value{
		kind: "equation",
		equation: equation{
			values: []value{},
		},
	}
	if len(a.equation.values) > 2 {
		v = append(v, a.equation.values...)
		return a, v
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
			aaa, _ := sanityResolveValueInternalValuesFromPrincipalState(
				aa[aai], rootIndex, valPrincipalState, forceBeforeMutate,
			)
			r.equation.values = append(r.equation.values, aaa)
		case "equation":
			aaa, _ := sanityResolveValueInternalValuesFromPrincipalState(
				aa[aai], rootIndex, valPrincipalState, forceBeforeMutate,
			)
			if aai == 0 {
				r.equation.values = aaa.equation.values
			} else {
				r.equation.values = append(r.equation.values, aaa.equation.values[1:]...)
			}
		}
	}
	v = append(v, r.equation.values...)
	return r, v
}

func sanityConstantIsUsedByPrincipal(valKnowledgeMap knowledgeMap, name string, c constant) bool {
	for i, a := range valKnowledgeMap.assigned {
		if valKnowledgeMap.creator[i] != name {
			continue
		}
		switch a.kind {
		case "primitive":
			_, v := sanityResolveValueInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
			for _, vv := range v {
				switch vv.kind {
				case "constant":
					if vv.constant.name == c.name {
						return true
					}
				}
			}
		}
	}
	return false
}

func sanityResolveAllPrincipalStateValues(
	valPrincipalState principalState, valKnowledgeMap knowledgeMap,
) principalState {
	var resolvesGroup sync.WaitGroup
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState, false)
	for i := range valPrincipalState.assigned {
		resolvesGroup.Add(1)
		go func(i int) {
			valPrincipalStateClone.assigned[i], _ = sanityResolveValueInternalValuesFromPrincipalState(
				valPrincipalState.assigned[i], i, valPrincipalState,
				sanityShouldResolveToBeforeMutate(i, valPrincipalState),
			)
			valPrincipalStateClone.beforeRewrite[i], _ = sanityResolveValueInternalValuesFromPrincipalState(
				valPrincipalState.beforeRewrite[i], i, valPrincipalState,
				sanityShouldResolveToBeforeMutate(i, valPrincipalState),
			)
			valPrincipalStateClone.beforeMutate[i], _ = sanityResolveValueInternalValuesFromKnowledgeMap(
				valPrincipalState.beforeMutate[i], valKnowledgeMap,
			)
			resolvesGroup.Done()
		}(i)
	}
	resolvesGroup.Wait()
	return valPrincipalStateClone
}
