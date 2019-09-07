/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

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
	sanityQueries(model, valKnowledgeMap, valPrincipalStates)
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
		if (len(right.primitive.arguments) == 0) || ((p.arity >= 0) && (len(right.primitive.arguments) != p.arity)) {
			plural := ""
			arity := fmt.Sprintf("%d", p.arity)
			if len(right.primitive.arguments) > 1 {
				plural = "s"
			}
			if p.arity < 0 {
				arity = "at least 1"
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
		for _, v := range right.equation.constants {
			unique := true
			for _, c := range constants {
				if v.name == c.name {
					unique = false
					break
				}
			}
			if unique {
				constants = append(constants, v)
			}
		}
	}
	return constants
}

func sanityQueries(model *verifpal, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) {
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
			if !sanityConstantIsUsedByPrincipal(valPrincipalStates[0], query.message.recipient, c) {
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

func sanityExactSameValue(a1 value, a2 value) bool {
	return strings.Compare(prettyValue(a1), prettyValue(a2)) == 0
}

func sanityEquivalentValues(a1 value, a2 value, valPrincipalState *principalState) bool {
	switch a1.kind {
	case "constant":
		i1 := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a1.constant)
		if i1 < 0 {
			return false
		}
		a1 = valPrincipalState.assigned[i1]
	}
	switch a2.kind {
	case "constant":
		i2 := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a2.constant)
		if i2 < 0 {
			return false
		}
		a2 = valPrincipalState.assigned[i2]
	}
	switch a1.kind {
	case "constant":
		switch a2.kind {
		case "constant":
			if a1.constant.name != a2.constant.name {
				return false
			}
			if a1.constant.output != a2.constant.output {
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
	for i := range p1.arguments {
		equiv := sanityEquivalentValues(p1.arguments[i], p2.arguments[i], valPrincipalState)
		if !equiv {
			return false
		}
	}
	return true
}

func sanityDeconstructEquationValues(e equation, valPrincipalState *principalState) []value {
	var values []value
	for _, c := range e.constants {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		if i >= 0 {
			values = append(values, valPrincipalState.assigned[i])
		} else {
			values = append(values, value{kind: "constant", constant: c})
		}
	}
	return values
}

func sanityFindConstantInPrimitive(c constant, p primitive, valPrincipalState *principalState) bool {
	for _, a := range p.arguments {
		switch a.kind {
		case "constant":
			if sanityEquivalentValues(a, value{kind: "constant", constant: c}, valPrincipalState) {
				return true
			}
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
			a = valPrincipalState.assigned[i]
		}
		switch a.kind {
		case "constant":
			if sanityEquivalentValues(a, value{kind: "constant", constant: c}, valPrincipalState) {
				return true
			}
		case "primitive":
			if sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
				return true
			}
		case "equation":
			v := sanityDeconstructEquationValues(a.equation, valPrincipalState)
			for _, vv := range v {
				if sanityEquivalentValues(vv, value{kind: "constant", constant: c}, valPrincipalState) {
					return true
				}
			}
		}
	}
	return false
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
	if !sanityEquivalentValues(e1Values[0], e2Values[0], valPrincipalState) {
		return false
	}
	if !sanityEquivalentValues(e1Values[1], e2Values[1], valPrincipalState) {
		return false
	}
	return true
}

func sanityExactSameValueInValues(v value, assigneds *[]value) int {
	index := -1
	for i, a := range *assigneds {
		if sanityExactSameValue(v, a) {
			index = i
			break
		}
	}
	return index
}

func sanityValueInValues(v value, assigneds *[]value, valPrincipalState *principalState) int {
	index := -1
	for i, a := range *assigneds {
		if sanityEquivalentValues(v, a, valPrincipalState) {
			index = i
			break
		}
	}
	return index
}

func sanityPerformRewrites(valPrincipalState *principalState) ([]primitive, []int) {
	var failedRewrites []primitive
	var failedRewritesIndices []int
	for i, a := range valPrincipalState.assigned {
		switch a.kind {
		case "constant":
			continue
		case "primitive":
			prim := primitiveGet(a.primitive.name)
			if prim.rewrite.hasRule {
				wasRewritten, rewrite := possibleToPrimitivePassRewrite(a.primitive, valPrincipalState)
				if wasRewritten {
					valPrincipalState.wasRewritten[i] = true
					valPrincipalState.assigned[i] = rewrite
					valPrincipalState.beforeMutate[i] = rewrite
				} else {
					failedRewrites = append(failedRewrites, a.primitive)
					failedRewritesIndices = append(failedRewritesIndices, i)
				}
			}
		case "equation":
			continue
		}
	}
	return failedRewrites, failedRewritesIndices
}

func sanityGetEquationRootGenerator(e equation, ee equation, valPrincipalState *principalState, d int) constant {
	if d >= 2 {
		errorCritical(fmt.Sprintf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		))
	}
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, e.constants[0])
	if d > 0 {
		i = sanityGetPrincipalStateIndexFromConstant(valPrincipalState, ee.constants[0])
	}
	if valPrincipalState.assigned[i].kind == "equation" {
		return sanityGetEquationRootGenerator(e, valPrincipalState.assigned[i].equation, valPrincipalState, d+1)
	}
	return valPrincipalState.assigned[i].constant
}

func sanityCheckEquationGenerators(valPrincipalState *principalState) {
	for _, a := range valPrincipalState.assigned {
		if a.kind == "equation" {
			c := sanityGetEquationRootGenerator(a.equation, a.equation, valPrincipalState, 0)
			if c.name != "g" {
				errorCritical(fmt.Sprintf(
					"equation (%s) does not use 'g' as generator",
					prettyEquation(a.equation),
				))
			}
		}
	}
}

func sanityResolveInternalValues(a value, valPrincipalState *principalState) (value, []value) {
	var v []value
	switch a.kind {
	case "constant":
		v = append(v, a)
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
		if i >= 0 {
			a = valPrincipalState.assigned[i]
		}
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
				check:     a.primitive.check,
			},
		}
		for _, aa := range a.primitive.arguments {
			s, vv := sanityResolveInternalValues(aa, valPrincipalState)
			v = append(v, vv...)
			r.primitive.arguments = append(r.primitive.arguments, s)
		}
		return r, v
	case "equation":
		r := value{
			kind: "equation",
			equation: equation{
				constants: []constant{},
			},
		}
		if len(a.equation.constants) > 2 {
			for _, vv := range a.equation.constants {
				v = append(v, value{kind: "constant", constant: vv})
			}
			return a, v
		}
		aa := sanityDeconstructEquationValues(a.equation, valPrincipalState)
		switch aa[0].kind {
		case "constant":
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, aa[0].constant)
			if i >= 0 {
				aa[0] = valPrincipalState.assigned[i]
			}
		}
		switch aa[0].kind {
		case "constant":
			r.equation.constants = append(r.equation.constants, aa[0].constant)
			r.equation.constants = append(r.equation.constants, aa[1].constant)
		case "primitive":
			r.equation.constants = append(r.equation.constants, aa[0].constant)
			r.equation.constants = append(r.equation.constants, aa[1].constant)
		case "equation":
			aaa := sanityDeconstructEquationValues(aa[0].equation, valPrincipalState)
			r.equation.constants = append(r.equation.constants, aaa[0].constant)
			r.equation.constants = append(r.equation.constants, aaa[1].constant)
			r.equation.constants = append(r.equation.constants, aa[1].constant)
		}
		for _, vv := range r.equation.constants {
			v = append(v, value{kind: "constant", constant: vv})
		}
		return r, v
	}
	return a, v
}

func sanityConstantIsUsedByPrincipal(valPrincipalState *principalState, name string, c constant) bool {
	for i, a := range valPrincipalState.beforeRewrite {
		if valPrincipalState.creator[i] != name {
			continue
		}
		switch a.kind {
		case "primitive":
			_, v := sanityResolveInternalValues(a, valPrincipalState)
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
