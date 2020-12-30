/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package vplogic

import (
	"fmt"
	"strings"
)

func sanity(m Model) (KnowledgeMap, []PrincipalState, error) {
	err := sanityPhases(m)
	if err != nil {
		return KnowledgeMap{}, []PrincipalState{}, err
	}
	principals, err := sanityDeclaredPrincipals(m)
	if err != nil {
		return KnowledgeMap{}, []PrincipalState{}, err
	}
	valKnowledgeMap, err := constructKnowledgeMap(m, principals)
	if err != nil {
		return KnowledgeMap{}, []PrincipalState{}, err
	}
	err = sanityQueries(m, valKnowledgeMap)
	if err != nil {
		return KnowledgeMap{}, []PrincipalState{}, err
	}
	valPrincipalStates := constructPrincipalStates(m, valKnowledgeMap)
	return valKnowledgeMap, valPrincipalStates, nil
}

func sanityPhases(m Model) error {
	phase := 0
	for _, blck := range m.Blocks {
		switch blck.Kind {
		case "phase":
			switch {
			case blck.Phase.Number <= phase:
				return fmt.Errorf(
					"phase being declared (%d) must be superior to last declared phase (%d)",
					blck.Phase.Number, phase,
				)
			case blck.Phase.Number != phase+1:
				return fmt.Errorf(
					"phase being declared (%d) skips phases since last declared phase (%d)",
					blck.Phase.Number, phase,
				)
			default:
				phase = blck.Phase.Number
			}
		}
	}
	return nil
}

func sanityAssignmentConstants(
	right Value, constants []Constant, valKnowledgeMap KnowledgeMap,
) ([]Constant, error) {
	switch right.Kind {
	case typesEnumConstant:
		unique := true
		for _, c := range constants {
			if right.Constant.ID == c.ID {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, right.Constant)
		}
	case typesEnumPrimitive:
		sacfp, err := sanityAssignmentConstantsFromPrimitive(
			right, constants, valKnowledgeMap,
		)
		if err != nil {
			return []Constant{}, err
		}
		constants = append(constants, sacfp...)
	case typesEnumEquation:
		constants = append(constants, sanityAssignmentConstantsFromEquation(
			right, constants,
		)...)
	}
	return constants, nil
}

func sanityAssignmentConstantsFromPrimitive(
	right Value, constants []Constant, valKnowledgeMap KnowledgeMap,
) ([]Constant, error) {
	primArguments := len(right.Primitive.Arguments)
	specArity, err := primitiveGetArity(right.Primitive)
	if err != nil {
		return []Constant{}, err
	}
	if primArguments == 0 {
		return []Constant{}, fmt.Errorf("primitive has no inputs")
	}
	if !intInSlice(primArguments, specArity) {
		arityString := prettyArity(specArity)
		return []Constant{}, fmt.Errorf(
			"primitive has %d inputs, expecting %s", primArguments, arityString,
		)
	}
	for _, a := range right.Primitive.Arguments {
		switch a.Kind {
		case typesEnumConstant:
			unique := true
			for _, c := range constants {
				if a.Constant.ID == c.ID {
					unique = false
					break
				}
			}
			if unique {
				constants = append(constants, a.Constant)
			}
		case typesEnumPrimitive:
			constants, err = sanityAssignmentConstants(a, constants, valKnowledgeMap)
			if err != nil {
				return []Constant{}, err
			}
		case typesEnumEquation:
			constants, err = sanityAssignmentConstants(a, constants, valKnowledgeMap)
			if err != nil {
				return []Constant{}, err
			}
		}
	}
	return constants, nil
}

func sanityAssignmentConstantsFromEquation(right Value, constants []Constant) []Constant {
	for _, v := range right.Equation.Values {
		unique := true
		for _, c := range constants {
			if v.Constant.ID == c.ID {
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

func sanityPrimitive(p Primitive, outputs []Constant) error {
	var output []int
	var check bool
	if primitiveIsCorePrim(p.ID) {
		prim, _ := primitiveCoreGet(p.ID)
		output = prim.Output
		check = prim.Check
	} else {
		prim, err := primitiveGet(p.ID)
		if err != nil {
			return err
		}
		output = prim.Output
		check = prim.Check
	}
	if !intInSlice(len(outputs), output) {
		outputString := prettyArity(output)
		return fmt.Errorf(
			"primitive has %d outputs, expecting %s",
			len(outputs), outputString,
		)
	}
	if p.Check && !check {
		return fmt.Errorf("primitive is checked but does not support checking")
	}
	return nil
}

func sanityQueries(m Model, valKnowledgeMap KnowledgeMap) error {
	var err error
	for _, query := range m.Queries {
		switch query.Kind {
		case typesEnumConfidentiality:
			err = sanityQueriesConfidentiality(query, valKnowledgeMap)
		case typesEnumAuthentication:
			err = sanityQueriesAuthentication(query, valKnowledgeMap)
		case typesEnumFreshness:
			err = sanityQueriesFreshness(query, valKnowledgeMap)
		case typesEnumUnlinkability:
			err = sanityQueriesUnlinkability(query, valKnowledgeMap)
		default:
			return fmt.Errorf("invalid query kind")
		}
		if err != nil {
			return err
		}
		err = sanityQueryOptions(query, valKnowledgeMap)
		if err != nil {
			return err
		}
	}
	return nil
}

func sanityQueriesConfidentiality(query Query, valKnowledgeMap KnowledgeMap) error {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
	if i < 0 {
		return fmt.Errorf(
			"confidentiality query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(query.Constants[0]),
		)
	}
	return nil
}

func sanityQueriesAuthentication(query Query, valKnowledgeMap KnowledgeMap) error {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Message.Constants[0])
	if i < 0 {
		return fmt.Errorf(
			"authentication query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(query.Message.Constants[0]),
		)
	}
	if len(query.Message.Constants) != 1 {
		return fmt.Errorf(
			"authentication query (%s) has more than one constant",
			prettyQuery(query),
		)
	}
	c := query.Message.Constants[0]
	return sanityQueriesCheckKnown(query, query.Message, c, valKnowledgeMap)
}

func sanityQueriesFreshness(query Query, valKnowledgeMap KnowledgeMap) error {
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[0])
	if i < 0 {
		return fmt.Errorf(
			"freshness query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(query.Constants[0]),
		)
	}
	return nil
}

func sanityQueriesUnlinkability(query Query, valKnowledgeMap KnowledgeMap) error {
	if len(query.Constants) < 2 {
		return fmt.Errorf(
			"unlinkability query (%s) must specify at least two constants",
			prettyQuery(query),
		)
	}
	for _, c := range query.Constants {
		i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i < 0 {
			return fmt.Errorf(
				"unlinkability query (%s) refers to unknown constant (%s)",
				prettyQuery(query),
				prettyConstant(c),
			)
		}
	}
	return nil
}

func sanityQueryOptions(query Query, valKnowledgeMap KnowledgeMap) error {
	for _, option := range query.Options {
		switch option.Kind {
		case typesEnumPrecondition:
			if len(option.Message.Constants) != 1 {
				return fmt.Errorf(
					"precondition option message (%s) has more than one constant",
					prettyQuery(query),
				)
			}
			c := option.Message.Constants[0]
			return sanityQueriesCheckKnown(query, option.Message, c, valKnowledgeMap)
		default:
			return fmt.Errorf("invalid query option kind")
		}
	}
	return nil
}

func sanityQueriesCheckKnown(query Query, m Message, c Constant, valKnowledgeMap KnowledgeMap) error {
	senderKnows := false
	recipientKnows := false
	i := valueGetKnowledgeMapIndexFromConstant(
		valKnowledgeMap, m.Constants[0],
	)
	if i < 0 {
		return fmt.Errorf(
			"query (%s) refers to unknown constant (%s)",
			prettyQuery(query),
			prettyConstant(m.Constants[0]),
		)
	}
	if valKnowledgeMap.Creator[i] == m.Sender {
		senderKnows = true
	}
	if valKnowledgeMap.Creator[i] == m.Recipient {
		recipientKnows = true
	}
	for _, kb := range valKnowledgeMap.KnownBy[i] {
		if _, ok := kb[m.Sender]; ok {
			senderKnows = true
		}
		if _, ok := kb[m.Recipient]; ok {
			recipientKnows = true
		}
	}
	constantUsedByPrincipal := valueConstantIsUsedByPrincipalInKnowledgeMap(
		valKnowledgeMap, m.Recipient, m.Constants[0],
	)
	if !senderKnows {
		return fmt.Errorf(
			"authentication query (%s) depends on %s sending a constant (%s) that they do not know",
			prettyQuery(query), m.Sender, prettyConstant(c),
		)
	}
	if !recipientKnows {
		return fmt.Errorf(
			"authentication query (%s) depends on %s receiving a constant (%s) that they never receive",
			prettyQuery(query), m.Recipient, prettyConstant(c),
		)
	}
	if !constantUsedByPrincipal {
		return fmt.Errorf(
			"authentication query (%s) depends on %s using a constant (%s) in a primitive, but this never happens",
			prettyQuery(query), m.Recipient, prettyConstant(c),
		)
	}
	return nil
}

func sanityDeclaredPrincipals(m Model) ([]string, error) {
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
		case typesEnumAuthentication:
			principals, _ = appendUniqueString(principals, query.Message.Sender)
			principals, _ = appendUniqueString(principals, query.Message.Recipient)
		}
	}
	for _, p := range principals {
		if !strInSlice(p, declared) {
			return []string{}, fmt.Errorf("principal does not exist (%s)", p)
		}
	}
	if len(declared) > 64 {
		return []string{}, fmt.Errorf("more than 64 principals (%d) declared", len(declared))
	}
	return principals, nil
}

func sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites []Primitive) error {
	for _, p := range failedRewrites {
		if !p.Check {
			continue
		}
		return fmt.Errorf(
			"checked primitive fails: %s",
			prettyPrimitive(p),
		)
	}
	return nil
}

func sanityCheckEquationRootGenerator(e Equation) error {
	if len(e.Values) > 3 {
		return fmt.Errorf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		)
	}
	for i, c := range e.Values {
		if i == 0 {
			if strings.ToLower(c.Constant.Name) != "g" {
				return fmt.Errorf(
					"equation (%s) does not use 'g' as generator",
					prettyEquation(e),
				)
			}
		}
		if i > 0 {
			if strings.ToLower(c.Constant.Name) == "g" {
				return fmt.Errorf(
					"equation (%s) uses 'g' not as a generator",
					prettyEquation(e),
				)
			}
		}
	}
	return nil
}

func sanityCheckEquationGenerators(a Value, valPrincipalState PrincipalState) error {
	var err error
	switch a.Kind {
	case typesEnumPrimitive:
		for _, va := range a.Primitive.Arguments {
			switch va.Kind {
			case typesEnumPrimitive:
				err = sanityCheckEquationGenerators(va, valPrincipalState)
			case typesEnumEquation:
				err = sanityCheckEquationRootGenerator(va.Equation)
			}
			if err != nil {
				return err
			}
		}
	case typesEnumEquation:
		err = sanityCheckEquationRootGenerator(a.Equation)
		if err != nil {
			return err
		}
	}
	return nil
}
