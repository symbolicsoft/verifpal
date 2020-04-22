/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// e7f38dcfcb1b02f4419c2e9e90efa017

package verifpal

import "fmt"

func constructKnowledgeMap(m Model, principals []string) KnowledgeMap {
	valKnowledgeMap := KnowledgeMap{
		Principals: principals,
		Constants:  []Constant{},
		Assigned:   []Value{},
		Creator:    []string{},
		KnownBy:    [][]map[string]string{},
		Phase:      [][]int{},
	}
	currentPhase := 0
	valKnowledgeMap.Constants = append(valKnowledgeMap.Constants, constantG.Constant)
	valKnowledgeMap.Assigned = append(valKnowledgeMap.Assigned, constantG)
	valKnowledgeMap.Creator = append(valKnowledgeMap.Creator, principals[0])
	valKnowledgeMap.KnownBy = append(valKnowledgeMap.KnownBy, []map[string]string{})
	valKnowledgeMap.Phase = append(valKnowledgeMap.Phase, []int{currentPhase})
	for _, principal := range principals {
		valKnowledgeMap.KnownBy[0] = append(
			valKnowledgeMap.KnownBy[0],
			map[string]string{principal: principal},
		)
	}
	valKnowledgeMap.Constants = append(valKnowledgeMap.Constants, constantN.Constant)
	valKnowledgeMap.Assigned = append(valKnowledgeMap.Assigned, constantN)
	valKnowledgeMap.Creator = append(valKnowledgeMap.Creator, principals[0])
	valKnowledgeMap.KnownBy = append(valKnowledgeMap.KnownBy, []map[string]string{})
	valKnowledgeMap.Phase = append(valKnowledgeMap.Phase, []int{currentPhase})
	for _, principal := range principals {
		valKnowledgeMap.KnownBy[1] = append(
			valKnowledgeMap.KnownBy[1],
			map[string]string{principal: principal},
		)
	}
	for _, blck := range m.Blocks {
		switch blck.Kind {
		case "principal":
			for _, expr := range blck.Principal.Expressions {
				switch expr.Kind {
				case "knows":
					valKnowledgeMap = constructKnowledgeMapRenderKnows(
						valKnowledgeMap, blck, expr,
					)
				case "generates":
					valKnowledgeMap = constructKnowledgeMapRenderGenerates(
						valKnowledgeMap, blck, expr,
					)
				case "leaks":
					valKnowledgeMap = constructKnowledgeMapRenderLeaks(
						valKnowledgeMap, blck, expr, currentPhase,
					)
				case "assignment":
					valKnowledgeMap = constructKnowledgeMapRenderAssignment(
						valKnowledgeMap, blck, expr,
					)
				}
			}
		case "message":
			valKnowledgeMap = constructKnowledgeMapRenderMessage(
				valKnowledgeMap, blck, currentPhase,
			)
		case "phase":
			currentPhase = blck.Phase.Number
		}
	}
	valKnowledgeMap.MaxPhase = currentPhase
	return valKnowledgeMap
}

func constructKnowledgeMapRenderKnows(
	valKnowledgeMap KnowledgeMap, blck Block, expr Expression,
) KnowledgeMap {
	for _, c := range expr.Constants {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i >= 0 {
			d1 := valKnowledgeMap.Constants[i].Declaration
			d2 := "knows"
			q1 := valKnowledgeMap.Constants[i].Qualifier
			q2 := expr.Qualifier
			fresh := valKnowledgeMap.Constants[i].Fresh
			if d1 != d2 || q1 != q2 || fresh {
				errorCritical(fmt.Sprintf(
					"constant is known more than once and in different ways (%s)",
					prettyConstant(c),
				))
			}
			valKnowledgeMap.KnownBy[i] = append(
				valKnowledgeMap.KnownBy[i],
				map[string]string{blck.Principal.Name: blck.Principal.Name},
			)
			continue
		}
		c = Constant{
			Name:        c.Name,
			Guard:       c.Guard,
			Fresh:       false,
			Leaked:      false,
			Declaration: "knows",
			Qualifier:   expr.Qualifier,
		}
		valKnowledgeMap.Constants = append(valKnowledgeMap.Constants, c)
		valKnowledgeMap.Assigned = append(valKnowledgeMap.Assigned, Value{
			Kind:     "constant",
			Constant: c,
		})
		valKnowledgeMap.Creator = append(valKnowledgeMap.Creator, blck.Principal.Name)
		valKnowledgeMap.KnownBy = append(valKnowledgeMap.KnownBy, []map[string]string{})
		valKnowledgeMap.Phase = append(valKnowledgeMap.Phase, []int{})
		l := len(valKnowledgeMap.Constants) - 1
		if expr.Qualifier != "public" {
			continue
		}
		for _, principal := range valKnowledgeMap.Principals {
			if principal != blck.Principal.Name {
				valKnowledgeMap.KnownBy[l] = append(
					valKnowledgeMap.KnownBy[l],
					map[string]string{principal: principal},
				)
			}
		}
	}
	return valKnowledgeMap
}

func constructKnowledgeMapRenderGenerates(
	valKnowledgeMap KnowledgeMap, blck Block, expr Expression,
) KnowledgeMap {
	for _, c := range expr.Constants {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i >= 0 {
			errorCritical(fmt.Sprintf(
				"generated constant already exists (%s)",
				prettyConstant(c),
			))
		}
		c = Constant{
			Name:        c.Name,
			Guard:       c.Guard,
			Fresh:       true,
			Leaked:      false,
			Declaration: "generates",
			Qualifier:   "private",
		}
		valKnowledgeMap.Constants = append(valKnowledgeMap.Constants, c)
		valKnowledgeMap.Assigned = append(valKnowledgeMap.Assigned, Value{
			Kind:     "constant",
			Constant: c,
		})
		valKnowledgeMap.Creator = append(valKnowledgeMap.Creator, blck.Principal.Name)
		valKnowledgeMap.KnownBy = append(valKnowledgeMap.KnownBy, []map[string]string{{}})
		valKnowledgeMap.Phase = append(valKnowledgeMap.Phase, []int{})
	}
	return valKnowledgeMap
}

func constructKnowledgeMapRenderLeaks(
	valKnowledgeMap KnowledgeMap, blck Block, expr Expression, currentPhase int,
) KnowledgeMap {
	for _, c := range expr.Constants {
		i := sanityGetKnowledgeMapIndexFromConstant(
			valKnowledgeMap, c,
		)
		if i < 0 {
			errorCritical(fmt.Sprintf(
				"leaked constant does not exist (%s)",
				prettyConstant(c),
			))
		}
		known := valKnowledgeMap.Creator[i] == blck.Principal.Name
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if _, ok := m[blck.Principal.Name]; ok {
				known = true
				break
			}
		}
		if !known {
			errorCritical(fmt.Sprintf(
				"%s leaks a constant that they do not know (%s)",
				blck.Principal.Name, prettyConstant(c),
			))
		}
		valKnowledgeMap.Constants[i].Leaked = true
		valKnowledgeMap.Phase[i], _ = appendUniqueInt(
			valKnowledgeMap.Phase[i], currentPhase,
		)
	}
	return valKnowledgeMap
}

func constructKnowledgeMapRenderAssignment(
	valKnowledgeMap KnowledgeMap, blck Block, expr Expression,
) KnowledgeMap {
	constants := sanityAssignmentConstants(expr.Right, []Constant{}, valKnowledgeMap)
	switch expr.Right.Kind {
	case "primitive":
		sanityPrimitive(expr.Right.Primitive, expr.Left)
	}
	for _, c := range constants {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i < 0 {
			errorCritical(fmt.Sprintf(
				"constant does not exist (%s)",
				prettyConstant(c),
			))
		}
		knows := valKnowledgeMap.Creator[i] == blck.Principal.Name
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if _, ok := m[blck.Principal.Name]; ok {
				knows = true
				break
			}
		}
		if !knows {
			errorCritical(fmt.Sprintf(
				"%s is using constant (%s) despite not knowing it",
				blck.Principal.Name,
				prettyConstant(c),
			))
		}
	}
	for i, c := range expr.Left {
		ii := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if ii >= 0 {
			errorCritical(fmt.Sprintf(
				"constant assigned twice (%s)",
				prettyConstant(c),
			))
		}
		c = Constant{
			Name:        c.Name,
			Guard:       c.Guard,
			Fresh:       false,
			Leaked:      false,
			Declaration: "assignment",
			Qualifier:   "private",
		}
		switch expr.Right.Kind {
		case "primitive":
			expr.Right.Primitive.Output = i
		}
		valKnowledgeMap.Constants = append(valKnowledgeMap.Constants, c)
		valKnowledgeMap.Assigned = append(valKnowledgeMap.Assigned, expr.Right)
		valKnowledgeMap.Creator = append(valKnowledgeMap.Creator, blck.Principal.Name)
		valKnowledgeMap.KnownBy = append(valKnowledgeMap.KnownBy, []map[string]string{{}})
		valKnowledgeMap.Phase = append(valKnowledgeMap.Phase, []int{})
	}
	return valKnowledgeMap
}

func constructKnowledgeMapRenderMessage(
	valKnowledgeMap KnowledgeMap, blck Block, currentPhase int,
) KnowledgeMap {
	for _, c := range blck.Message.Constants {
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
		if i < 0 {
			errorCritical(fmt.Sprintf(
				"%s sends unknown constant to %s (%s)",
				blck.Message.Sender,
				blck.Message.Recipient,
				prettyConstant(c),
			))
		}
		c = valKnowledgeMap.Constants[i]
		senderKnows := false
		recipientKnows := false
		if valKnowledgeMap.Creator[i] == blck.Message.Sender {
			senderKnows = true
		}
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if _, ok := m[blck.Message.Sender]; ok {
				senderKnows = true
			}
		}
		if valKnowledgeMap.Creator[i] == blck.Message.Recipient {
			recipientKnows = true
		}
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if _, ok := m[blck.Message.Recipient]; ok {
				recipientKnows = true
			}
		}
		switch {
		case !senderKnows:
			errorCritical(fmt.Sprintf(
				"%s is sending constant (%s) despite not knowing it",
				blck.Message.Sender,
				prettyConstant(c),
			))
		case recipientKnows:
			errorCritical(fmt.Sprintf(
				"%s is receiving constant (%s) despite already knowing it",
				blck.Message.Recipient,
				prettyConstant(c),
			))
		}
		valKnowledgeMap.KnownBy[i] = append(
			valKnowledgeMap.KnownBy[i], map[string]string{
				blck.Message.Recipient: blck.Message.Sender,
			},
		)
		valKnowledgeMap.Phase[i], _ = appendUniqueInt(
			valKnowledgeMap.Phase[i], currentPhase,
		)
	}
	return valKnowledgeMap
}

func constructPrincipalStates(m Model, valKnowledgeMap KnowledgeMap) []PrincipalState {
	valPrincipalStates := []PrincipalState{}
	for _, principal := range valKnowledgeMap.Principals {
		valPrincipalState := PrincipalState{
			Name:          principal,
			Constants:     []Constant{},
			Assigned:      []Value{},
			Guard:         []bool{},
			Known:         []bool{},
			Wire:          [][]string{},
			KnownBy:       [][]map[string]string{},
			Creator:       []string{},
			Sender:        []string{},
			Rewritten:     []bool{},
			BeforeRewrite: []Value{},
			Mutated:       []bool{},
			MutatableTo:   [][]string{},
			BeforeMutate:  []Value{},
			Phase:         [][]int{},
			Lock:          0,
		}
		for i, c := range valKnowledgeMap.Constants {
			wire := []string{}
			guard := false
			mutatableTo := []string{}
			knows := false
			sender := valKnowledgeMap.Creator[i]
			assigned := valKnowledgeMap.Assigned[i]
			if valKnowledgeMap.Creator[i] == principal {
				knows = true
			}
			for _, m := range valKnowledgeMap.KnownBy[i] {
				if precedingSender, ok := m[principal]; ok {
					sender = precedingSender
					knows = true
					break
				}
			}
			for _, blck := range m.Blocks {
				wire, guard, mutatableTo = constructPrincipalStatesGetValueMutatability(
					c, blck, principal, valKnowledgeMap.Creator[i],
					wire, guard, mutatableTo,
				)
			}
			valPrincipalState.Constants = append(valPrincipalState.Constants, c)
			valPrincipalState.Assigned = append(valPrincipalState.Assigned, assigned)
			valPrincipalState.Guard = append(valPrincipalState.Guard, guard)
			valPrincipalState.Known = append(valPrincipalState.Known, knows)
			valPrincipalState.Wire = append(valPrincipalState.Wire, wire)
			valPrincipalState.KnownBy = append(valPrincipalState.KnownBy, valKnowledgeMap.KnownBy[i])
			valPrincipalState.Creator = append(valPrincipalState.Creator, valKnowledgeMap.Creator[i])
			valPrincipalState.Sender = append(valPrincipalState.Sender, sender)
			valPrincipalState.Rewritten = append(valPrincipalState.Rewritten, false)
			valPrincipalState.BeforeRewrite = append(valPrincipalState.BeforeRewrite, assigned)
			valPrincipalState.Mutated = append(valPrincipalState.Mutated, false)
			valPrincipalState.MutatableTo = append(valPrincipalState.MutatableTo, mutatableTo)
			valPrincipalState.BeforeMutate = append(valPrincipalState.BeforeMutate, assigned)
			valPrincipalState.Phase = append(valPrincipalState.Phase, valKnowledgeMap.Phase[i])
		}
		valPrincipalStates = append(valPrincipalStates, valPrincipalState)
	}
	return valPrincipalStates
}

func constructPrincipalStatesGetValueMutatability(
	c Constant, blck Block, principal string, creator string,
	wire []string, guard bool, mutatableTo []string,
) ([]string, bool, []string) {
	switch blck.Kind {
	case "message":
		ir := (blck.Message.Recipient == principal)
		ic := (creator == principal)
		for _, cc := range blck.Message.Constants {
			if c.Name != cc.Name {
				continue
			}
			wire, _ = appendUniqueString(wire, blck.Message.Recipient)
			if !guard {
				guard = cc.Guard && (ir || ic)
			}
			if !cc.Guard {
				mutatableTo, _ = appendUniqueString(
					mutatableTo, blck.Message.Recipient,
				)
			}
		}
	}
	return wire, guard, mutatableTo
}

func constructPrincipalStateClone(valPrincipalState PrincipalState, purify bool) PrincipalState {
	valPrincipalStateClone := PrincipalState{
		Name:          valPrincipalState.Name,
		Constants:     make([]Constant, len(valPrincipalState.Constants)),
		Assigned:      make([]Value, len(valPrincipalState.Assigned)),
		Guard:         make([]bool, len(valPrincipalState.Guard)),
		Known:         make([]bool, len(valPrincipalState.Known)),
		Wire:          make([][]string, len(valPrincipalState.Wire)),
		KnownBy:       make([][]map[string]string, len(valPrincipalState.KnownBy)),
		Creator:       make([]string, len(valPrincipalState.Creator)),
		Sender:        make([]string, len(valPrincipalState.Sender)),
		Rewritten:     make([]bool, len(valPrincipalState.Rewritten)),
		BeforeRewrite: make([]Value, len(valPrincipalState.BeforeRewrite)),
		Mutated:       make([]bool, len(valPrincipalState.Mutated)),
		MutatableTo:   make([][]string, len(valPrincipalState.MutatableTo)),
		BeforeMutate:  make([]Value, len(valPrincipalState.BeforeMutate)),
		Phase:         make([][]int, len(valPrincipalState.Phase)),
		Lock:          valPrincipalState.Lock,
	}
	copy(valPrincipalStateClone.Constants, valPrincipalState.Constants)
	if purify {
		copy(valPrincipalStateClone.Assigned, valPrincipalState.BeforeMutate)
	} else {
		copy(valPrincipalStateClone.Assigned, valPrincipalState.Assigned)
	}
	copy(valPrincipalStateClone.Guard, valPrincipalState.Guard)
	copy(valPrincipalStateClone.Known, valPrincipalState.Known)
	copy(valPrincipalStateClone.Wire, valPrincipalState.Wire)
	copy(valPrincipalStateClone.KnownBy, valPrincipalState.KnownBy)
	copy(valPrincipalStateClone.Creator, valPrincipalState.Creator)
	copy(valPrincipalStateClone.Sender, valPrincipalState.Sender)
	copy(valPrincipalStateClone.Rewritten, valPrincipalState.Rewritten)
	if purify {
		copy(valPrincipalStateClone.BeforeRewrite, valPrincipalState.BeforeMutate)
	} else {
		copy(valPrincipalStateClone.BeforeRewrite, valPrincipalState.BeforeRewrite)
	}
	copy(valPrincipalStateClone.Mutated, valPrincipalState.Mutated)
	copy(valPrincipalStateClone.MutatableTo, valPrincipalState.MutatableTo)
	copy(valPrincipalStateClone.BeforeMutate, valPrincipalState.BeforeMutate)
	copy(valPrincipalStateClone.Phase, valPrincipalState.Phase)
	return valPrincipalStateClone
}
