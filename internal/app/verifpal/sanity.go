/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package main

import (
	"fmt"
	"strings"
)

func sanity(model *verifpal) (*knowledgeMap, []*principalState) {
	var valKnowledgeMap *knowledgeMap
	principals := sanityDeclaredPrincipals(model)
	valKnowledgeMap = constructKnowledgeMap(model, principals)
	valPrincipalStates := constructPrincipalStates(model, valKnowledgeMap)
	sanityQueries(model, valKnowledgeMap)
	return valKnowledgeMap, valPrincipalStates
}

func sanityAssignmentConstants(right value, constants []constant, valKnowledgeMap *knowledgeMap) []constant {
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
		p := primitiveGet(right.primitive.name)
		if len(p.name) == 0 {
			errorCritical(fmt.Sprintf(
				"invalid primitive (%s)",
				right.primitive.name,
			))
		}
		if (len(right.primitive.arguments) == 0) || (len(right.primitive.arguments) > 5) || ((p.arity >= 0) && (len(right.primitive.arguments) != p.arity)) {
			plural := ""
			arity := fmt.Sprintf("%d", p.arity)
			if len(right.primitive.arguments) > 1 {
				plural = "s"
			}
			if p.arity < 0 {
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
	case "equation":
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
	}
	return constants
}

func sanityQueries(model *verifpal, valKnowledgeMap *knowledgeMap) {
	for _, query := range model.queries {
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
			if !sanityConstantIsUsedByPrincipal(valKnowledgeMap, query.message.recipient, c) {
				errorCritical(fmt.Sprintf(
					"authentication query (%s) depends on %s using (%s) in a primitive, but this never happens",
					prettyQuery(query),
					query.message.recipient,
					prettyConstant(c),
				))
			}
		}
	}
}

func sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap *knowledgeMap, c constant) int {
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

func sanityGetPrincipalStateIndexFromConstant(valPrincipalState *principalState, c constant) int {
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

func sanityGetAttackerStateIndexFromConstant(valAttackerState *attackerState, c constant) int {
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

func sanityDeclaredPrincipals(model *verifpal) []string {
	var principals []string
	for _, block := range model.blocks {
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
	for _, query := range model.queries {
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
	return principals
}

func sanityEquivalentValues(a1 value, a2 value, valPrincipalState *principalState) bool {
	switch a1.kind {
	case "constant":
		a1 = sanityResolveConstant(a1.constant, valPrincipalState, false)
	}
	switch a2.kind {
	case "constant":
		a2 = sanityResolveConstant(a2.constant, valPrincipalState, false)
	}
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
			return sanityEquivalentPrimitives(a1.primitive, a2.primitive, valPrincipalState)
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

func sanityEquivalentPrimitives(p1 primitive, p2 primitive, valPrincipalState *principalState) bool {
	if p1.name != p2.name {
		return false
	}
	if len(p1.arguments) != len(p2.arguments) {
		return false
	}
	if p1.output != p2.output {
		return false
	}
	for i := range p1.arguments {
		equiv := sanityEquivalentValues(p1.arguments[i], p2.arguments[i], valPrincipalState)
		if !equiv {
			return false
		}
	}
	return true
}

func sanityEquivalentEquations(e1 equation, e2 equation, valPrincipalState *principalState) bool {
	e1Values := sanityDeconstructEquationValues(e1, valPrincipalState)
	e2Values := sanityDeconstructEquationValues(e2, valPrincipalState)
	if (len(e1Values) == 0) || (len(e2Values) == 0) {
		return false
	}
	if len(e1Values) != len(e2Values) {
		return false
	}
	if e1Values[0].kind == "equation" && e2Values[0].kind == "equation" {
		e1Base := sanityDeconstructEquationValues(e1Values[0].equation, valPrincipalState)
		e2Base := sanityDeconstructEquationValues(e2Values[0].equation, valPrincipalState)
		if sanityEquivalentValues(e1Base[1], e2Values[1], valPrincipalState) && sanityEquivalentValues(e1Values[1], e2Base[1], valPrincipalState) {
			return true
		}
		if sanityEquivalentValues(e1Base[1], e2Base[1], valPrincipalState) && sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
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
	}
	if sanityEquivalentValues(e1Values[0], e2Values[0], valPrincipalState) {
		if sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
			return true
		}
	}
	return false
}

func sanityDeconstructEquationValues(e equation, valPrincipalState *principalState) []value {
	var values []value
	for _, v := range e.values {
		switch v.kind {
		case "constant":
			v = sanityResolveConstant(v.constant, valPrincipalState, false)
		}
		values = append(values, v)
	}
	return values
}

func sanityFindConstantInPrimitive(c constant, p primitive, valPrincipalState *principalState) bool {
	a := sanityResolveConstant(c, valPrincipalState, true)
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
				if sanityEquivalentPrimitives(a.primitive, aa.primitive, valPrincipalState) {
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
			v := sanityDeconstructEquationValues(aa.equation, valPrincipalState)
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

func sanityExactSameValueInValues(v value, assigneds *[]value) int {
	index := -1
	for i, a := range *assigneds {
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
		s := strings.Compare(vs, as)
		if s == 0 {
			index = i
			break
		}
	}
	return index
}

func sanityEquivalentValueInValues(v value, assigneds *[]value, valPrincipalState *principalState) int {
	index := -1
	for i, a := range *assigneds {
		if sanityEquivalentValues(v, a, valPrincipalState) {
			index = i
			break
		}
	}
	return index
}

func sanityPerformPrimitiveRewrite(p primitive, i int, valPrincipalState *principalState) ([]primitive, bool, value) {
	wasRewritten := false
	failedRewrites := []primitive{}
	rewrite := value{
		kind: "primitive",
		primitive: primitive{
			name:      p.name,
			arguments: []value{},
			output:    p.output,
			check:     p.check,
		},
	}
	for i, a := range p.arguments {
		switch a.kind {
		case "constant":
			rewrite.primitive.arguments = append(rewrite.primitive.arguments, p.arguments[i])
		case "primitive":
			pFailedRewrite, pWasRewritten, pRewrite := sanityPerformPrimitiveRewrite(a.primitive, -1, valPrincipalState)
			if pWasRewritten {
				wasRewritten = true
				rewrite.primitive.arguments = append(rewrite.primitive.arguments, pRewrite)
			} else {
				rewrite.primitive.arguments = append(rewrite.primitive.arguments, p.arguments[i])
				failedRewrites = append(failedRewrites, pFailedRewrite...)
			}
		case "equation":
			eFailedRewrite, eWasRewritten, eRewrite := sanityPerformEquationRewrite(a.equation, -1, valPrincipalState)
			if eWasRewritten {
				wasRewritten = true
				rewrite.primitive.arguments = append(rewrite.primitive.arguments, eRewrite)
			} else {
				rewrite.primitive.arguments = append(rewrite.primitive.arguments, p.arguments[i])
				failedRewrites = append(failedRewrites, eFailedRewrite...)
			}
		}
	}
	wasRewrittenTotal, rewrite := possibleToPrimitivePassRewrite(rewrite.primitive, valPrincipalState)
	if wasRewrittenTotal {
		wasRewritten = true
	} else {
		failedRewrites = append(failedRewrites, rewrite.primitive)
	}
	if wasRewritten && i >= 0 {
		valPrincipalState.wasRewritten[i] = true
		valPrincipalState.assigned[i] = rewrite
		valPrincipalState.beforeMutate[i] = rewrite
	}
	return failedRewrites, wasRewritten, rewrite
}

func sanityPerformEquationRewrite(e equation, i int, valPrincipalState *principalState) ([]primitive, bool, value) {
	wasRewritten := false
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
			prim := primitiveGet(a.primitive.name)
			if prim.rewrite.hasRule {
				pFailedRewrite, pWasRewritten, pRewrite := sanityPerformPrimitiveRewrite(a.primitive, -1, valPrincipalState)
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
				} else {
					rewrite.equation.values = append(rewrite.equation.values, e.values[i])
					failedRewrites = append(failedRewrites, pFailedRewrite...)
				}
			}
		case "equation":
			eFailedRewrite, eWasRewritten, eRewrite := sanityPerformEquationRewrite(a.equation, -1, valPrincipalState)
			if eWasRewritten {
				wasRewritten = true
				rewrite.equation.values = append(rewrite.equation.values, eRewrite)
			} else {
				rewrite.equation.values = append(rewrite.equation.values, e.values[i])
				failedRewrites = append(failedRewrites, eFailedRewrite...)
			}
		}
	}
	if wasRewritten && i >= 0 {
		valPrincipalState.wasRewritten[i] = true
		valPrincipalState.assigned[i] = rewrite
		valPrincipalState.beforeMutate[i] = rewrite
	}
	return failedRewrites, wasRewritten, rewrite
}

func sanityPerformAllRewrites(valPrincipalState *principalState) ([]primitive, []int) {
	var failedRewrites []primitive
	var failedRewriteIndices []int
	for i := range valPrincipalState.assigned {
		switch valPrincipalState.assigned[i].kind {
		case "primitive":
			failedRewrite, _, _ := sanityPerformPrimitiveRewrite(valPrincipalState.assigned[i].primitive, i, valPrincipalState)
			if len(failedRewrite) > 0 {
				failedRewrites = append(failedRewrites, failedRewrite...)
				for range failedRewrite {
					failedRewriteIndices = append(failedRewriteIndices, i)
				}
			}
		case "equation":
			failedRewrite, _, _ := sanityPerformEquationRewrite(valPrincipalState.assigned[i].equation, i, valPrincipalState)
			if len(failedRewrite) > 0 {
				failedRewrites = append(failedRewrites, failedRewrite...)
				for range failedRewrite {
					failedRewriteIndices = append(failedRewriteIndices, i)
				}
			}
		}
	}
	return failedRewrites, failedRewriteIndices
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

func sanityCheckEquationRootGenerator(e equation, valPrincipalState *principalState) {
	if len(e.values) > 3 {
		errorCritical(fmt.Sprintf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		))
	}
	for i, c := range e.values {
		if i == 0 {
			if c.constant.name != "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) does not use 'g' as generator",
					prettyEquation(e),
				))
			}
		}
		if i > 0 {
			if c.constant.name == "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) uses 'g' not as a generator",
					prettyEquation(e),
				))
			}
		}
	}
}

func sanityCheckEquationGenerators(a value, valPrincipalState *principalState) {
	switch a.kind {
	case "primitive":
		for _, va := range a.primitive.arguments {
			switch va.kind {
			case "primitive":
				sanityCheckEquationGenerators(va, valPrincipalState)
			case "equation":
				sanityCheckEquationRootGenerator(va.equation, valPrincipalState)
			}
		}
	case "equation":
		sanityCheckEquationRootGenerator(a.equation, valPrincipalState)
	}
}

func sanityShouldResolveToBeforeMutate(i int, valPrincipalState *principalState) bool {
	if valPrincipalState.creator[i] == valPrincipalState.name {
		return true
	}
	if !valPrincipalState.known[i] {
		return true
	}
	return !valPrincipalState.wasMutated[i]
}

func sanityResolveConstant(c constant, valPrincipalState *principalState, forceAssigned bool) value {
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
	if i < 0 {
		return value{kind: "constant", constant: c}
	}
	if forceAssigned {
		return valPrincipalState.assigned[i]
	}
	if sanityShouldResolveToBeforeMutate(i, valPrincipalState) {
		return valPrincipalState.beforeMutate[i]
	}
	return valPrincipalState.assigned[i]
}

func sanityResolveInternalValuesFromPrincipalState(a value, rootIndex int, valPrincipalState *principalState, forceBeforeMutate bool) (value, []value) {
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
			a = sanityResolveConstant(a.constant, valPrincipalState, true)
		}
		v = append(v, a)
	}
	switch a.kind {
	case "constant":
		return a, v
	case "primitive":
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
			s, vv := sanityResolveInternalValuesFromPrincipalState(aa, rootIndex, valPrincipalState, forceBeforeMutate)
			v = append(v, vv...)
			r.primitive.arguments = append(r.primitive.arguments, s)
		}
		return r, v
	case "equation":
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
		switch aa[0].kind {
		case "constant":
			if forceBeforeMutate {
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, aa[0].constant)
				aa[0] = valPrincipalState.beforeMutate[i]
			} else {
				aa[0] = sanityResolveConstant(aa[0].constant, valPrincipalState, true)
			}
		}
		switch aa[1].kind {
		case "constant":
			if forceBeforeMutate {
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, aa[1].constant)
				aa[1] = valPrincipalState.beforeMutate[i]
			} else {
				aa[1] = sanityResolveConstant(aa[1].constant, valPrincipalState, true)
			}
		}
		switch aa[0].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[0])
		case "primitive":
			aaa, _ := sanityResolveInternalValuesFromPrincipalState(aa[0], rootIndex, valPrincipalState, forceBeforeMutate)
			r.equation.values = append(r.equation.values, aaa)
		case "equation":
			aaa, _ := sanityResolveInternalValuesFromPrincipalState(aa[0], rootIndex, valPrincipalState, forceBeforeMutate)
			r.equation.values = aaa.equation.values
		}
		switch aa[1].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[1])
		case "primitive":
			aaa, _ := sanityResolveInternalValuesFromPrincipalState(aa[1], rootIndex, valPrincipalState, forceBeforeMutate)
			r.equation.values = append(r.equation.values, aaa)
		case "equation":
			aaa, _ := sanityResolveInternalValuesFromPrincipalState(aa[1], rootIndex, valPrincipalState, forceBeforeMutate)
			r.equation.values = append(r.equation.values, aaa.equation.values[1:]...)
		}
		v = append(v, r.equation.values...)
		return r, v
	}
	return a, v
}

func sanityResolveInternalValuesFromKnowledgeMap(a value, valKnowledgeMap *knowledgeMap) (value, []value) {
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
			s, vv := sanityResolveInternalValuesFromKnowledgeMap(aa, valKnowledgeMap)
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
		switch aa[0].kind {
		case "constant":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aa[0].constant)
			aa[0] = valKnowledgeMap.assigned[i]
		}
		switch aa[1].kind {
		case "constant":
			i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aa[1].constant)
			aa[1] = valKnowledgeMap.assigned[i]
		}
		switch aa[0].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[0])
		case "primitive":
			r.equation.values = append(r.equation.values, aa[0])
		case "equation":
			aaa, _ := sanityResolveInternalValuesFromKnowledgeMap(aa[0], valKnowledgeMap)
			r.equation.values = aaa.equation.values
		}
		switch aa[1].kind {
		case "constant":
			r.equation.values = append(r.equation.values, aa[1])
		case "primitive":
			r.equation.values = append(r.equation.values, aa[1])
		case "equation":
			aaa, _ := sanityResolveInternalValuesFromKnowledgeMap(aa[1], valKnowledgeMap)
			r.equation.values = append(r.equation.values, aaa.equation.values[1:]...)
		}
		v = append(v, r.equation.values...)
		return r, v
	}
	return a, v
}

func sanityConstantIsUsedByPrincipal(valKnowledgeMap *knowledgeMap, name string, c constant) bool {
	for i, a := range valKnowledgeMap.assigned {
		if valKnowledgeMap.creator[i] != name {
			continue
		}
		switch a.kind {
		case "primitive":
			_, v := sanityResolveInternalValuesFromKnowledgeMap(a, valKnowledgeMap)
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

func sanityResolveAllPrincipalStateValues(valPrincipalState *principalState, valKnowledgeMap *knowledgeMap) *principalState {
	valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
	for i := range valPrincipalState.assigned {
		valPrincipalStateClone.assigned[i], _ = sanityResolveInternalValuesFromPrincipalState(valPrincipalState.assigned[i], i, valPrincipalState, sanityShouldResolveToBeforeMutate(i, valPrincipalState))
		valPrincipalStateClone.beforeRewrite[i], _ = sanityResolveInternalValuesFromPrincipalState(valPrincipalState.beforeRewrite[i], i, valPrincipalState, sanityShouldResolveToBeforeMutate(i, valPrincipalState))
		valPrincipalStateClone.beforeMutate[i], _ = sanityResolveInternalValuesFromKnowledgeMap(valPrincipalState.beforeMutate[i], valKnowledgeMap)
	}
	return valPrincipalStateClone
}
