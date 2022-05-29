/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 274578ab4bbd4d70871016e78cd562ad

package vplogic

import (
	"fmt"
)

func sanity(m Model) (*KnowledgeMap, []*PrincipalState, error) {
	err := sanityPhases(m)
	if err != nil {
		return &KnowledgeMap{}, []*PrincipalState{}, err
	}
	principals, principalIDs, err := sanityDeclaredPrincipals(m)
	if err != nil {
		return &KnowledgeMap{}, []*PrincipalState{}, err
	}
	valKnowledgeMap, err := constructKnowledgeMap(m, principals, principalIDs)
	if err != nil {
		return &KnowledgeMap{}, []*PrincipalState{}, err
	}
	err = sanityQueries(m, valKnowledgeMap)
	if err != nil {
		return &KnowledgeMap{}, []*PrincipalState{}, err
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
	right *Value, constants []*Constant, valKnowledgeMap *KnowledgeMap,
) ([]*Constant, error) {
	switch right.Kind {
	case typesEnumConstant:
		unique := true
		for _, c := range constants {
			if valueEquivalentConstants(right.Data.(*Constant), c) {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, right.Data.(*Constant))
		}
	case typesEnumPrimitive:
		sacfp, err := sanityAssignmentConstantsFromPrimitive(
			right, constants, valKnowledgeMap,
		)
		if err != nil {
			return []*Constant{}, err
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
	right *Value, constants []*Constant, valKnowledgeMap *KnowledgeMap,
) ([]*Constant, error) {
	primArguments := len(right.Data.(*Primitive).Arguments)
	specArity, err := primitiveGetArity(right.Data.(*Primitive))
	if err != nil {
		return []*Constant{}, err
	}
	if primArguments == 0 {
		return []*Constant{}, fmt.Errorf("primitive has no inputs")
	}
	if !intInSlice(primArguments, specArity) {
		arityString := prettyArity(specArity)
		return []*Constant{}, fmt.Errorf(
			"primitive has %d inputs, expecting %s", primArguments, arityString,
		)
	}
	for _, a := range right.Data.(*Primitive).Arguments {
		switch a.Kind {
		case typesEnumConstant:
			unique := true
			for _, c := range constants {
				if valueEquivalentConstants(a.Data.(*Constant), c) {
					unique = false
					break
				}
			}
			if unique {
				constants = append(constants, a.Data.(*Constant))
			}
		case typesEnumPrimitive:
			constants, err = sanityAssignmentConstants(a, constants, valKnowledgeMap)
			if err != nil {
				return []*Constant{}, err
			}
		case typesEnumEquation:
			constants, err = sanityAssignmentConstants(a, constants, valKnowledgeMap)
			if err != nil {
				return []*Constant{}, err
			}
		}
	}
	return constants, nil
}

func sanityAssignmentConstantsFromEquation(right *Value, constants []*Constant) []*Constant {
	for _, v := range right.Data.(*Equation).Values {
		unique := true
		for _, c := range constants {
			if valueEquivalentConstants(v.Data.(*Constant), c) {
				unique = false
				break
			}
		}
		if unique {
			constants = append(constants, v.Data.(*Constant))
		}
	}
	return constants
}

func sanityPrimitive(p *Primitive, outputs []*Constant) error {
	var output []int
	var check bool
	if primitiveIsCorePrimitive(p.ID) {
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
	return sanityCheckPrimitiveArgumentOutputs(p)
}

func sanityQueries(m Model, valKnowledgeMap *KnowledgeMap) error {
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
		case typesEnumEquivalence:
			err = sanityQueriesEquivalence(query, valKnowledgeMap)
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

func sanityQueriesConfidentiality(query Query, valKnowledgeMap *KnowledgeMap) error {
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

func sanityQueriesAuthentication(query Query, valKnowledgeMap *KnowledgeMap) error {
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
	err := sanityQueriesCheckMessagePrincipals(query.Message)
	if err != nil {
		return err
	}
	return sanityQueriesCheckKnown(query, query.Message, c, valKnowledgeMap)
}

func sanityQueriesFreshness(query Query, valKnowledgeMap *KnowledgeMap) error {
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

func sanityQueriesUnlinkability(query Query, valKnowledgeMap *KnowledgeMap) error {
	if len(query.Constants) < 2 {
		return fmt.Errorf(
			"unlinkability query (%s) must specify at least two constants",
			prettyQuery(query),
		)
	}
	for i := 0; i < len(query.Constants); i++ {
		ii := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[i])
		if ii < 0 {
			return fmt.Errorf(
				"unlinkability query (%s) refers to unknown constant (%s)",
				prettyQuery(query), prettyConstant(query.Constants[i]),
			)
		}
		if valueEquivalentConstantInConstants(query.Constants[i], query.Constants[:i]) >= 0 {
			return fmt.Errorf(
				"unlinkability query (%s) refers to same constant more than once (%s)",
				prettyQuery(query), prettyConstant(query.Constants[i]),
			)
		}
	}
	return nil
}

func sanityQueriesEquivalence(query Query, valKnowledgeMap *KnowledgeMap) error {
	if len(query.Constants) < 2 {
		return fmt.Errorf(
			"equivalence query (%s) must specify at least two constants",
			prettyQuery(query),
		)
	}
	for i := 0; i < len(query.Constants); i++ {
		ii := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Constants[i])
		if ii < 0 {
			return fmt.Errorf(
				"equivalence query (%s) refers to unknown constant (%s)",
				prettyQuery(query), prettyConstant(query.Constants[i]),
			)
		}
		if valueEquivalentConstantInConstants(query.Constants[i], query.Constants[:i]) >= 0 {
			return fmt.Errorf(
				"equivalence query (%s) refers to same constant more than once (%s)",
				prettyQuery(query), prettyConstant(query.Constants[i]),
			)
		}
	}
	return nil
}

func sanityQueryOptions(query Query, valKnowledgeMap *KnowledgeMap) error {
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
			err := sanityQueriesCheckMessagePrincipals(option.Message)
			if err != nil {
				return err
			}
			return sanityQueriesCheckKnown(query, option.Message, c, valKnowledgeMap)
		default:
			return fmt.Errorf("invalid query option kind")
		}
	}
	return nil
}

func sanityQueriesCheckMessagePrincipals(message Message) error {
	if message.Sender == message.Recipient {
		return fmt.Errorf(
			"query with message (%s) has identical sender and recipient",
			prettyMessage(Block{Kind: "message", Message: message}),
		)
	}
	return nil
}

func sanityQueriesCheckKnown(query Query, m Message, c *Constant, valKnowledgeMap *KnowledgeMap) error {
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
			prettyQuery(query), principalGetNameFromID(m.Sender), prettyConstant(c),
		)
	}
	if !recipientKnows {
		return fmt.Errorf(
			"authentication query (%s) depends on %s receiving a constant (%s) that they never receive",
			prettyQuery(query), principalGetNameFromID(m.Recipient), prettyConstant(c),
		)
	}
	if !constantUsedByPrincipal {
		return fmt.Errorf(
			"authentication query (%s) depends on %s using a constant (%s) in a primitive, but this never happens",
			prettyQuery(query), principalGetNameFromID(m.Recipient), prettyConstant(c),
		)
	}
	return nil
}

func sanityDeclaredPrincipals(m Model) ([]string, []principalEnum, error) {
	declaredNames := []string{}
	declaredIDs := []principalEnum{}
	principals := []principalEnum{}
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			principals, _ = appendUniquePrincipalEnum(principals, block.Principal.ID)
			declaredNames, _ = appendUniqueString(declaredNames, block.Principal.Name)
			declaredIDs, _ = appendUniquePrincipalEnum(declaredIDs, block.Principal.ID)
		}
	}
	for _, block := range m.Blocks {
		switch block.Kind {
		case "message":
			principals, _ = appendUniquePrincipalEnum(principals, block.Message.Sender)
			principals, _ = appendUniquePrincipalEnum(principals, block.Message.Recipient)
		}
	}
	for _, query := range m.Queries {
		switch query.Kind {
		case typesEnumAuthentication:
			principals, _ = appendUniquePrincipalEnum(principals, query.Message.Sender)
			principals, _ = appendUniquePrincipalEnum(principals, query.Message.Recipient)
		}
	}
	for _, p := range principals {
		if !principalEnumInSlice(p, declaredIDs) {
			return []string{}, []principalEnum{}, fmt.Errorf("principal does not exist")
		}
	}
	if len(declaredNames) > 64 {
		return []string{}, []principalEnum{}, fmt.Errorf("more than 64 principals (%d) declared", len(declaredNames))
	}
	return declaredNames, declaredIDs, nil
}

func sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites []*Primitive) error {
	for _, p := range failedRewrites {
		if p.Check {
			return fmt.Errorf(
				"checked primitive fails: %s",
				prettyPrimitive(p),
			)
		}
	}
	return nil
}

func sanityCheckPrimitiveArgumentOutputs(p *Primitive) error {
	for i := 0; i < len(p.Arguments); i++ {
		switch p.Arguments[i].Kind {
		case typesEnumPrimitive:
			var output []int
			if primitiveIsCorePrimitive(p.Arguments[i].Data.(*Primitive).ID) {
				prim, err := primitiveCoreGet(p.Arguments[i].Data.(*Primitive).ID)
				if err != nil {
					return err
				}
				output = prim.Output
			} else {
				prim, err := primitiveGet(p.Arguments[i].Data.(*Primitive).ID)
				if err != nil {
					return err
				}
				output = prim.Output
			}
			if !intInSlice(1, output) {
				return fmt.Errorf(
					"primitive %s cannot have %s as an argument, since %s necessarily produces more than one output",
					prettyPrimitive(p),
					prettyPrimitive(p.Arguments[i].Data.(*Primitive)),
					prettyPrimitive(p.Arguments[i].Data.(*Primitive)),
				)
			}
		}
	}
	return nil
}

func sanityCheckEquationRootGenerator(e *Equation) error {
	if len(e.Values) > 3 {
		return fmt.Errorf(
			"too many layers in equation (%s), maximum is 2",
			prettyEquation(e),
		)
	}
	for i, c := range e.Values {
		switch c.Kind {
		case typesEnumConstant:
			if i == 0 {
				if c.Data.(*Constant).ID != valueG.Data.(*Constant).ID {
					return fmt.Errorf(
						"equation (%s) does not use 'g' as generator",
						prettyEquation(e),
					)
				}
			}
			if i > 0 {
				if valueEquivalentConstants(c.Data.(*Constant), valueG.Data.(*Constant)) {
					return fmt.Errorf(
						"equation (%s) uses 'g' not as a generator",
						prettyEquation(e),
					)
				}
			}
		}
	}
	return nil
}

func sanityCheckEquationGenerators(a *Value) error {
	var err error
	switch a.Kind {
	case typesEnumPrimitive:
		for _, va := range a.Data.(*Primitive).Arguments {
			switch va.Kind {
			case typesEnumPrimitive:
				err = sanityCheckEquationGenerators(va)
			case typesEnumEquation:
				err = sanityCheckEquationRootGenerator(va.Data.(*Equation))
			}
			if err != nil {
				return err
			}
		}
	case typesEnumEquation:
		err = sanityCheckEquationRootGenerator(a.Data.(*Equation))
		if err != nil {
			return err
		}
	}
	return nil
}
