/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"fmt"
)

func inject(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	switch p.name {
	case "AEAD_ENC":
		//injectAEADENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "ENC":
		//injectENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "SIGN":
		//injectSIGN(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "MAC":
		//injectMAC(p, valPrincipalState, valReplacementMap, valAttackerState)
	}
}

func injectGetAttackerEquations(injectCounter int) (value, value) {
	e := value{}
	ge := value{}
	g := value{
		kind: "constant",
		constant: constant{
			name:        "g",
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "public",
		},
	}
	e = value{
		kind: "constant",
		constant: constant{
			name:        fmt.Sprintf("attacker_%d", injectCounter),
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "private",
		},
	}
	ge = value{
		kind: "equation",
		equation: equation{
			values: []value{g, e},
		},
	}
	return e, ge
}

func injectGetAttackerPrimitives(injectCounter int) []value {
	attackerPrimitives := []value{}
	e, ge := injectGetAttackerEquations(injectCounter)
	attackerPrimitives = append(attackerPrimitives, value{
		kind: "primitive",
		primitive: primitive{
			name: "AEAD_ENC",
			arguments: []value{
				e,
				ge,
				e,
			},
			output: primitiveGet("AEAD_ENC").output,
			check:  false,
		},
	})
	attackerPrimitives = append(attackerPrimitives, value{
		kind: "primitive",
		primitive: primitive{
			name: "ENC",
			arguments: []value{
				e,
				ge,
			},
			output: primitiveGet("ENC").output,
			check:  false,
		},
	})
	attackerPrimitives = append(attackerPrimitives, value{
		kind: "primitive",
		primitive: primitive{
			name: "SIGN",
			arguments: []value{
				e,
				ge,
			},
			output: primitiveGet("SIGN").output,
			check:  false,
		},
	})
	attackerPrimitives = append(attackerPrimitives, value{
		kind: "primitive",
		primitive: primitive{
			name: "MAC",
			arguments: []value{
				e,
				ge,
			},
			output: primitiveGet("MAC").output,
			check:  false,
		},
	})
	return attackerPrimitives
}

func injectAttackerValues(
	valKnowledgeMap *knowledgeMap, valPrincipalState *principalState,
	valAttackerState *attackerState, injectCounter int, alsoKnowledgeMap bool,
) {
	attackerValues := []value{}
	e, _ := injectGetAttackerEquations(injectCounter)
	//attackerPrimitives := injectGetAttackerPrimitives(injectCounter)
	attackerValues = append(attackerValues, []value{e}...)
	//attackerValues = append(attackerValues, attackerPrimitives...)
	for _, v := range attackerValues {
		valPrincipalState.constants = append(valPrincipalState.constants, v.constant)
		valPrincipalState.assigned = append(valPrincipalState.assigned, v)
		valPrincipalState.guard = append(valPrincipalState.guard, false)
		valPrincipalState.known = append(valPrincipalState.known, false)
		valPrincipalState.sender = append(valPrincipalState.sender, "Attacker")
		valPrincipalState.creator = append(valPrincipalState.creator, "Attacker")
		valPrincipalState.wasRewritten = append(valPrincipalState.wasRewritten, false)
		valPrincipalState.beforeRewrite = append(valPrincipalState.beforeRewrite, v)
		valPrincipalState.wasMutated = append(valPrincipalState.wasMutated, false)
		valPrincipalState.beforeMutate = append(valPrincipalState.beforeMutate, v)
		valAttackerState.known = append(valAttackerState.known, v)
		valAttackerState.wire = append(valAttackerState.wire, false)
		valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		if alsoKnowledgeMap {
			valKnowledgeMap.constants = append(valKnowledgeMap.constants, v.constant)
			valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, v)
			valKnowledgeMap.creator = append(valKnowledgeMap.creator, "Attacker")
			valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{{}})
		}
	}
}

func injectAEADENC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "AEAD_ENC",
				arguments: []value{
					p.arguments[0],
					k,
					p.arguments[2],
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		}
	}
}

func injectSIGN(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		if sanityEquivalentValueInValues(p.arguments[1], &valAttackerState.known, valPrincipalState) >= 0 {
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: "SIGN",
					arguments: []value{
						k,
						p.arguments[1],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			}
		}
	}
}
