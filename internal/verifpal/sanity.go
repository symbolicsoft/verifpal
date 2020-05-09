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
			sanityQueriesConfidentiality(query, valKnowledgeMap)
		case "authentication":
			sanityQueriesAuthentication(query, valKnowledgeMap)
		case "freshness":
			sanityQueriesFreshness(query, valKnowledgeMap)
		case "unlinkability":
			sanityQueriesUnlinkability(query, valKnowledgeMap)
		}
		sanityQueryOptions(query)
	}
}

func sanityQueriesConfidentiality(query Query, valKnowledgeMap KnowledgeMap) {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
	if i < 0 {
		errorCritical(fmt.Sprintf(
			"confidentiality query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(query.Constants[0]),
		))
	}
}

func sanityQueriesAuthentication(query Query, valKnowledgeMap KnowledgeMap) {
	if len(query.Message.Constants) != 1 {
		errorCritical(fmt.Sprintf(
			"authentication query (%s) has more than one constant",
			prettyQuery(query),
		))
	}
	c := query.Message.Constants[0]
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
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
	constantUsedByPrincipal := valueConstantIsUsedByPrincipalInKnowledgeMap(
		valKnowledgeMap, query.Message.Recipient, c,
	)
	sanityQueriesCheckKnown(query, c, senderKnows, recipientKnows, constantUsedByPrincipal)
}

func sanityQueriesFreshness(query Query, valKnowledgeMap KnowledgeMap) {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
	if i < 0 {
		errorCritical(fmt.Sprintf(
			"freshness query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(query.Constants[0]),
		))
	}
}

func sanityQueriesUnlinkability(query Query, valKnowledgeMap KnowledgeMap) {
	if len(query.Constants) < 2 {
		errorCritical(fmt.Sprintf(
			"unlinkability query (%s) must specify at least two constants",
			prettyQuery(query),
		))
	}
	for _, c := range query.Constants {
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i < 0 {
			errorCritical(fmt.Sprintf(
				"unlinkability query (%s) refers to unknown value (%s)",
				prettyQuery(query),
				prettyConstant(c),
			))
		}
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
