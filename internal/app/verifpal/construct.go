/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// e7f38dcfcb1b02f4419c2e9e90efa017

package main

import "fmt"

func constructKnowledgeMap(model *verifpal, principals []string) *knowledgeMap {
	var valKnowledgeMap knowledgeMap
	valKnowledgeMap.principals = principals
	g := constant{
		name:      "g",
		guard:     false,
		output:    0,
		fresh:     false,
		qualifier: "public",
	}
	valKnowledgeMap.constants = append(valKnowledgeMap.constants, g)
	valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, value{
		kind:     "constant",
		constant: g,
	})
	valKnowledgeMap.creator = append(valKnowledgeMap.creator, principals[0])
	valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{})
	for _, principal := range principals {
		valKnowledgeMap.knownBy[0] = append(valKnowledgeMap.knownBy[0], map[string]string{principal: principal})
	}
	for _, block := range model.blocks {
		switch block.kind {
		case "principal":
			for _, expression := range block.principal.expressions {
				switch expression.kind {
				case "knows":
					for _, c := range expression.constants {
						i := sanityGetKnowledgeMapIndexFromConstant(&valKnowledgeMap, c)
						if i < 0 {
							c = constant{
								name:      c.name,
								guard:     c.guard,
								output:    c.output,
								fresh:     false,
								qualifier: expression.qualifier,
							}
							valKnowledgeMap.constants = append(valKnowledgeMap.constants, c)
							valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, value{
								kind:     "constant",
								constant: c,
							})
							valKnowledgeMap.creator = append(valKnowledgeMap.creator, block.principal.name)
							valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{})
							l := len(valKnowledgeMap.constants) - 1
							if expression.qualifier == "public" {
								for _, principal := range principals {
									if principal != block.principal.name {
										valKnowledgeMap.knownBy[l] = append(valKnowledgeMap.knownBy[l], map[string]string{principal: principal})
									}
								}
							}
						} else if valKnowledgeMap.constants[i].fresh || (valKnowledgeMap.constants[i].qualifier != expression.qualifier) {
							errorCritical(fmt.Sprintf(
								"constant is known more than once and in different ways (%s)",
								prettyConstant(c),
							))
						} else {
							valKnowledgeMap.knownBy[i] = append(valKnowledgeMap.knownBy[i], map[string]string{block.principal.name: block.principal.name})
						}
					}
				case "generates":
					for _, c := range expression.constants {
						i := sanityGetKnowledgeMapIndexFromConstant(&valKnowledgeMap, c)
						if i < 0 {
							c = constant{
								name:      c.name,
								guard:     c.guard,
								output:    c.output,
								fresh:     true,
								qualifier: "private",
							}
							valKnowledgeMap.constants = append(valKnowledgeMap.constants, c)
							valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, value{
								kind:     "constant",
								constant: c,
							})
							valKnowledgeMap.creator = append(valKnowledgeMap.creator, block.principal.name)
							valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{{}})
						} else {
							errorCritical(fmt.Sprintf(
								"constant generated twice (%s)",
								prettyConstant(c),
							))
						}
					}
				case "assignment":
					constants := sanityAssignmentConstants(expression.right, []constant{}, &valKnowledgeMap)
					switch expression.right.kind {
					case "primitive":
						prim := primitiveGet(expression.right.primitive.name)
						if (len(expression.left) != prim.output) && (prim.output >= 0) {
							plural := ""
							output := fmt.Sprintf("%d", prim.output)
							if len(expression.left) > 1 {
								plural = "s"
							}
							if prim.output < 0 {
								output = "at least 1"
							}
							errorCritical(fmt.Sprintf(
								"primitive %s has %d output%s, expecting %s",
								prim.name, len(expression.left), plural, output,
							))
						}
						if expression.right.primitive.check {
							if !prim.check {
								errorCritical(fmt.Sprintf(
									"primitive %s is checked but does not support checking",
									prim.name,
								))
							}
						}
					}
					for _, c := range constants {
						i := sanityGetKnowledgeMapIndexFromConstant(&valKnowledgeMap, c)
						if i >= 0 {
							knows := false
							if valKnowledgeMap.creator[i] == block.principal.name {
								knows = true
							}
							for _, m := range valKnowledgeMap.knownBy[i] {
								if _, ok := m[block.principal.name]; ok {
									knows = true
								}
							}
							if !knows {
								errorCritical(fmt.Sprintf(
									"%s is using constant (%s) despite not knowing it",
									block.principal.name,
									prettyConstant(c),
								))
							}
						} else {
							errorCritical(fmt.Sprintf(
								"constant does not exist (%s)",
								prettyConstant(c),
							))
						}
					}
					for i, c := range expression.left {
						ii := sanityGetKnowledgeMapIndexFromConstant(&valKnowledgeMap, c)
						if ii >= 0 {
							errorCritical(fmt.Sprintf(
								"constant assigned twice (%s)",
								prettyConstant(c),
							))
						}
						c = constant{
							name:      c.name,
							guard:     c.guard,
							output:    i,
							fresh:     false,
							qualifier: "private",
						}
						valKnowledgeMap.constants = append(valKnowledgeMap.constants, c)
						valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, expression.right)
						valKnowledgeMap.creator = append(valKnowledgeMap.creator, block.principal.name)
						valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{{}})
					}
				}
			}
		case "message":
			for _, c := range block.message.constants {
				i := sanityGetKnowledgeMapIndexFromConstant(&valKnowledgeMap, c)
				if i >= 0 {
					c = valKnowledgeMap.constants[i]
					senderKnows := false
					recipientKnows := false
					if valKnowledgeMap.creator[i] == block.message.sender {
						senderKnows = true
					}
					for _, m := range valKnowledgeMap.knownBy[i] {
						if _, ok := m[block.message.sender]; ok {
							senderKnows = true
						}
					}
					if valKnowledgeMap.creator[i] == block.message.recipient {
						recipientKnows = true
					}
					for _, m := range valKnowledgeMap.knownBy[i] {
						if _, ok := m[block.message.recipient]; ok {
							recipientKnows = true
						}
					}
					if !senderKnows {
						errorCritical(fmt.Sprintf(
							"%s is sending constant (%s) despite not knowing it",
							block.message.sender,
							prettyConstant(c),
						))
					} else if recipientKnows {
						errorCritical(fmt.Sprintf(
							"%s is receiving constant (%s) despite already knowing it",
							block.message.recipient,
							prettyConstant(c),
						))
					} else {
						valKnowledgeMap.knownBy[i] = append(
							valKnowledgeMap.knownBy[i],
							map[string]string{block.message.recipient: block.message.sender},
						)
					}
				} else {
					errorCritical(fmt.Sprintf(
						"%s sends unknown constant to %s (%s)",
						block.message.sender,
						block.message.recipient,
						prettyConstant(c),
					))
				}
			}
		}
	}
	return &valKnowledgeMap
}

func constructPrincipalStates(model *verifpal, valKnowledgeMap *knowledgeMap) []*principalState {
	var valPrincipalStates []*principalState
	for _, principal := range valKnowledgeMap.principals {
		valPrincipalState := principalState{
			name:          principal,
			constants:     []constant{},
			assigned:      []value{},
			guard:         []bool{},
			known:         []bool{},
			sender:        []string{},
			wasRewritten:  []bool{},
			beforeRewrite: []value{},
			wasMutated:    []bool{},
			beforeMutate:  []value{},
		}
		for i, c := range valKnowledgeMap.constants {
			guard := false
			knows := false
			sender := valKnowledgeMap.creator[i]
			assigned := valKnowledgeMap.assigned[i]
			if valKnowledgeMap.creator[i] == principal {
				knows = true
			}
			for _, m := range valKnowledgeMap.knownBy[i] {
				if realSender, ok := m[principal]; ok {
					sender = realSender
					knows = true
				}
			}
			for _, block := range model.blocks {
				switch block.kind {
				case "message":
					for _, cc := range block.message.constants {
						if ((c.name == cc.name) && cc.guard) &&
							((block.message.recipient == principal) || (valKnowledgeMap.creator[i] == principal)) {
							guard = true
						}
					}
				}
			}
			valPrincipalState.constants = append(valPrincipalState.constants, c)
			valPrincipalState.assigned = append(valPrincipalState.assigned, assigned)
			valPrincipalState.guard = append(valPrincipalState.guard, guard)
			valPrincipalState.known = append(valPrincipalState.known, knows)
			valPrincipalState.sender = append(valPrincipalState.sender, sender)
			valPrincipalState.creator = append(valPrincipalState.creator, valKnowledgeMap.creator[i])
			valPrincipalState.wasRewritten = append(valPrincipalState.wasRewritten, false)
			valPrincipalState.beforeRewrite = append(valPrincipalState.beforeRewrite, assigned)
			valPrincipalState.wasMutated = append(valPrincipalState.wasMutated, false)
			valPrincipalState.beforeMutate = append(valPrincipalState.beforeMutate, assigned)
		}
		failedRewrites, _ := sanityPerformRewrites(&valPrincipalState)
		for _, p := range failedRewrites {
			if p.check {
				errorCritical(fmt.Sprintf(
					"checked primitive fails: %s",
					prettyPrimitive(p),
				))
			}
		}
		sanityCheckEquationGenerators(&valPrincipalState)
		valPrincipalStates = append(valPrincipalStates, &valPrincipalState)
	}
	return valPrincipalStates
}

func constructAttackerState(active bool, model *verifpal, valKnowledgeMap *knowledgeMap, verbose bool) *attackerState {
	valAttackerState := attackerState{
		active:      active,
		known:       []value{},
		conceivable: []value{},
	}
	constructAttackerStatePopulate(model, valKnowledgeMap, verbose, &valAttackerState)
	return &valAttackerState
}

func constructAttackerStatePopulate(model *verifpal, valKnowledgeMap *knowledgeMap, verbose bool, valAttackerState *attackerState) {
	for _, c := range valKnowledgeMap.constants {
		if c.qualifier == "public" {
			v := value{
				kind:     "constant",
				constant: c,
			}
			if sanityExactSameValueInValues(v, &valAttackerState.known) < 0 {
				valAttackerState.known = append(valAttackerState.known, v)
				valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
			}
		}
	}
	for _, block := range model.blocks {
		switch block.kind {
		case "message":
			for _, c := range block.message.constants {
				i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
				v := value{
					kind:     "constant",
					constant: valKnowledgeMap.constants[i],
				}
				if valKnowledgeMap.constants[i].qualifier == "private" {
					if sanityExactSameValueInValues(v, &valAttackerState.known) < 0 {
						if verbose {
							prettyMessage(fmt.Sprintf(
								"%s has sent %s to %s, rendering it public",
								block.message.sender, prettyConstant(c), block.message.recipient,
							), 0, 0, "analysis")
						}
						valAttackerState.known = append(valAttackerState.known, v)
						valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
					}
				}
			}
		}
	}
}
