/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 7d5d2341a999bccff8fc2ff129fefc89

package main

import (
	"fmt"
)

func verifyActive(model *verifpal, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) []verifyResult {
	var verifyResults []verifyResult
	valAttackerState := constructAttackerState(true, model, valKnowledgeMap, true)
	prettyMessage("attacker is configured as active", 0, 0, "info")
	analysis := 0
	attackerKnown := -1
	for len(valAttackerState.known) > attackerKnown {
		for principalIndex, valPrincipalState := range valPrincipalStates {
			if principalIndex > 0 || attackerKnown >= 0 {
				valAttackerState.known = valAttackerState.known[1:]
				valAttackerState.wire = valAttackerState.wire[1:]
				valAttackerState.mutatedTo = valAttackerState.mutatedTo[1:]
			}
			verifyAnalysis(model, valPrincipalState, valAttackerState, analysis, 0)
			analysis = analysis + 1
			valReplacementMap, attackerValues := verifyActiveInitReplacementMap(valPrincipalState, valAttackerState)
			lastReplacement := valReplacementMap.combinationNext()
			verifyActiveInjectAttackerValues(
				valKnowledgeMap, valPrincipalState, valAttackerState,
				&attackerValues, (principalIndex == 0),
			)
			for !lastReplacement {
				valPrincipalStateWithReplacements, _ := verifyActiveMutatePrincipalState(valPrincipalState, valAttackerState, &valReplacementMap)
				verifyAnalysis(model, valPrincipalStateWithReplacements, valAttackerState, analysis, 0)
				analysis = analysis + 1
				prettyAnalysis(analysis)
				verifyResults = verifyResolveQueries(model, valKnowledgeMap, valPrincipalStateWithReplacements, valAttackerState, verifyResults, analysis)
				valAttackerState = verifyActiveClearFreshValues(model, valKnowledgeMap, valAttackerState)
				if len(verifyResults) == len(model.queries) {
					return verifyResults
				}
				if len(valAttackerState.known) > attackerKnown {
					valReplacementMap, _ = verifyActiveInitReplacementMap(valPrincipalState, valAttackerState)
				}
				attackerKnown = len(valAttackerState.known)
				lastReplacement = valReplacementMap.combinationNext()
			}
			attackerKnown = len(valAttackerState.known)
		}
	}
	return verifyResults
}

func verifyActiveInjectAttackerValues(
	valKnowledgeMap *knowledgeMap, valPrincipalState *principalState, valAttackerState *attackerState,
	attackerValues *[]value, alsoKnowledgeMap bool,
) {
	for _, v := range *attackerValues {
		valPrincipalState.constants = append([]constant{v.constant}, valPrincipalState.constants...)
		valPrincipalState.assigned = append([]value{v}, valPrincipalState.assigned...)
		valPrincipalState.guard = append([]bool{false}, valPrincipalState.guard...)
		valPrincipalState.known = append([]bool{false}, valPrincipalState.known...)
		valPrincipalState.sender = append([]string{"Attacker"}, valPrincipalState.sender...)
		valPrincipalState.creator = append([]string{"Attacker"}, valPrincipalState.creator...)
		valPrincipalState.wasRewritten = append([]bool{false}, valPrincipalState.wasRewritten...)
		valPrincipalState.beforeRewrite = append([]value{v}, valPrincipalState.beforeRewrite...)
		valPrincipalState.wasMutated = append([]bool{false}, valPrincipalState.wasMutated...)
		valPrincipalState.beforeMutate = append([]value{v}, valPrincipalState.beforeMutate...)
		valAttackerState.known = append([]value{v}, valAttackerState.known...)
		valAttackerState.wire = append([]bool{false}, valAttackerState.wire...)
		valAttackerState.mutatedTo = append([][]string{{}}, valAttackerState.mutatedTo...)
		if alsoKnowledgeMap {
			valKnowledgeMap.constants = append(valKnowledgeMap.constants, v.constant)
			valKnowledgeMap.assigned = append(valKnowledgeMap.assigned, v)
			valKnowledgeMap.creator = append(valKnowledgeMap.creator, "Attacker")
			valKnowledgeMap.knownBy = append(valKnowledgeMap.knownBy, []map[string]string{{}})
		}
	}
}

func verifyActiveClearFreshValues(model *verifpal, valKnowledgeMap *knowledgeMap, valAttackerState *attackerState) *attackerState {
	valAttackerStateCleared := attackerState{
		active:      valAttackerState.active,
		known:       []value{},
		wire:        []bool{},
		conceivable: valAttackerState.conceivable,
		mutatedTo:   [][]string{},
	}
	for i, a := range valAttackerState.known {
		if !verifyActiveValueHasFreshValues(valKnowledgeMap, a) {
			if sanityExactSameValueInValues(a, &valAttackerStateCleared.known) < 0 {
				valAttackerStateCleared.known = append(valAttackerStateCleared.known, valAttackerState.known[i])
				valAttackerStateCleared.wire = append(valAttackerStateCleared.wire, valAttackerState.wire[i])
				valAttackerStateCleared.mutatedTo = append(valAttackerStateCleared.mutatedTo, valAttackerState.mutatedTo[i])
			}
		}
	}
	constructAttackerStatePopulate(model, valKnowledgeMap, false, &valAttackerStateCleared)
	return &valAttackerStateCleared
}

func verifyActiveValueHasFreshValues(valKnowledgeMap *knowledgeMap, a value) bool {
	aa := a
	switch a.kind {
	case "constant":
		i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, a.constant)
		aa = valKnowledgeMap.assigned[i]
	}
	switch aa.kind {
	case "constant":
		if aa.constant.fresh {
			return true
		}
	case "primitive":
		for _, aaa := range aa.primitive.arguments {
			if verifyActiveValueHasFreshValues(valKnowledgeMap, aaa) {
				return true
			}
		}
	case "equation":
		for _, aaa := range aa.equation.constants {
			ii := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, aaa)
			if verifyActiveValueHasFreshValues(valKnowledgeMap, valKnowledgeMap.assigned[ii]) {
				return true
			}
		}
	}
	return false
}

func verifyActiveInitReplacementMap(valPrincipalState *principalState, valAttackerState *attackerState) (replacementMap, []value) {
	valReplacementMap := replacementMap{
		injectCounter: 0,
	}
	e := []value{}
	ge := []value{}
	g := constant{
		name:        "g",
		guard:       false,
		fresh:       false,
		declaration: "knows",
		qualifier:   "public",
	}
	e = append(e, value{
		kind: "constant",
		constant: constant{
			name:        fmt.Sprintf("attacker_%d", valReplacementMap.injectCounter),
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "private",
		},
	})
	ge = append(ge, value{
		kind: "equation",
		equation: equation{
			constants: []constant{g, e[0].constant},
		},
	})
	valReplacementMap.constants = append(valReplacementMap.constants, e[0].constant)
	valReplacementMap.replacements = append(valReplacementMap.replacements, []value{e[0]})
	valReplacementMap.injectCounter = valReplacementMap.injectCounter + 1
	for i, v := range valAttackerState.known {
		if !valAttackerState.wire[i] || v.kind != "constant" {
			continue
		}
		a := sanityResolveConstant(valPrincipalState, v.constant, false)
		a, _ = sanityResolveInternalValues(a, valPrincipalState, false)
		switch a.kind {
		case "constant":
			if a.constant.name == "g" {
				continue
			}
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			l := len(valReplacementMap.replacements) - 1
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], e[0])
		case "primitive":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			l := len(valReplacementMap.replacements) - 1
			switch a.primitive.name {
			case "AEAD_ENC":
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: "AEAD_ENC",
						arguments: []value{
							e[0],
							e[0],
							e[0],
						},
						output: a.primitive.output,
						check:  a.primitive.check,
					},
				}
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
				for _, aaa := range valAttackerState.known {
					if aaa.kind == a.primitive.arguments[1].kind &&
						((aaa.kind == "constant" && aaa.constant.name == e[0].constant.name) ||
							(aaa.kind == "primitive" &&
								aaa.primitive.name == a.primitive.arguments[1].primitive.name &&
								len(aaa.primitive.arguments) == len(a.primitive.arguments[1].primitive.arguments)) ||
							(aaa.kind == "equation" &&
								len(aaa.equation.constants) == len(a.primitive.arguments[1].equation.constants))) {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: "AEAD_ENC",
								arguments: []value{
									a.primitive.arguments[0],
									aaa,
									a.primitive.arguments[2],
								},
								output: a.primitive.output,
								check:  a.primitive.check,
							},
						}
						if sanityValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
							if sanityValueInValues(a.primitive.arguments[2], &valAttackerState.known, valPrincipalState) >= 0 {
								if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
									valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
								}
							}
						}
					}
				}
			case "ENC":
				for _, aaa := range valAttackerState.known {
					aa := value{
						kind: "primitive",
						primitive: primitive{
							name: "ENC",
							arguments: []value{
								e[0],
								e[0],
							},
							output: a.primitive.output,
							check:  a.primitive.check,
						},
					}
					if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
						valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
					}
					if aaa.kind == a.primitive.arguments[1].kind &&
						((aaa.kind == "constant" && aaa.constant.name == e[0].constant.name) ||
							(aaa.kind == "primitive" &&
								aaa.primitive.name == a.primitive.arguments[1].primitive.name &&
								len(aaa.primitive.arguments) == len(a.primitive.arguments[1].primitive.arguments)) ||
							(aaa.kind == "equation" &&
								len(aaa.equation.constants) == len(a.primitive.arguments[1].equation.constants))) {
						aa = value{
							kind: "primitive",
							primitive: primitive{
								name: "ENC",
								arguments: []value{
									a.primitive.arguments[0],
									aaa,
								},
								output: a.primitive.output,
								check:  a.primitive.check,
							},
						}
						if sanityValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
							if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
								valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
							}
						}
					}
				}
			case "SIGN":
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: "SIGN",
						arguments: []value{
							e[0],
							e[0],
						},
						output: a.primitive.output,
						check:  a.primitive.check,
					},
				}
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
				for _, aaa := range valAttackerState.known {
					if aaa.kind == a.primitive.arguments[0].kind &&
						((aaa.kind == "constant" && aaa.constant.name == e[0].constant.name) ||
							(aaa.kind == "primitive" &&
								aaa.primitive.name == a.primitive.arguments[0].primitive.name &&
								len(aaa.primitive.arguments) == len(a.primitive.arguments[0].primitive.arguments)) ||
							(aaa.kind == "equation" &&
								len(aaa.equation.constants) == len(a.primitive.arguments[0].equation.constants))) {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: "SIGN",
								arguments: []value{
									aaa,
									a.primitive.arguments[1],
								},
								output: a.primitive.output,
								check:  a.primitive.check,
							},
						}
						if sanityValueInValues(a.primitive.arguments[1], &valAttackerState.known, valPrincipalState) >= 0 {
							if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
								valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
							}
						}
					}
				}
			case "MAC":
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: "MAC",
						arguments: []value{
							e[0],
							e[0],
						},
						output: a.primitive.output,
						check:  a.primitive.check,
					},
				}
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
				for _, aaa := range valAttackerState.known {
					if aaa.kind == a.primitive.arguments[0].kind &&
						((aaa.kind == "constant" && aaa.constant.name == e[0].constant.name) ||
							(aaa.kind == "primitive" &&
								aaa.primitive.name == a.primitive.arguments[0].primitive.name &&
								len(aaa.primitive.arguments) == len(a.primitive.arguments[0].primitive.arguments)) ||
							(aaa.kind == "equation" &&
								len(aaa.equation.constants) == len(a.primitive.arguments[0].equation.constants))) {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: "MAC",
								arguments: []value{
									aaa,
									a.primitive.arguments[1],
								},
								output: a.primitive.output,
								check:  a.primitive.check,
							},
						}
						if sanityValueInValues(a.primitive.arguments[1], &valAttackerState.known, valPrincipalState) >= 0 {
							if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
								valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
							}
						}
					}
					if aaa.kind == a.primitive.arguments[1].kind &&
						((aaa.kind == "constant" && aaa.constant.name == e[0].constant.name) ||
							(aaa.kind == "primitive" &&
								aaa.primitive.name == a.primitive.arguments[1].primitive.name &&
								len(aaa.primitive.arguments) == len(a.primitive.arguments[1].primitive.arguments)) ||
							(aaa.kind == "equation" &&
								len(aaa.equation.constants) == len(a.primitive.arguments[1].equation.constants))) {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: "MAC",
								arguments: []value{
									a.primitive.arguments[0],
									aaa,
								},
								output: a.primitive.output,
								check:  a.primitive.check,
							},
						}
						if sanityValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
							if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
								valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
							}
						}
					}
				}
			}
		case "equation":
			valReplacementMap.constants = append(valReplacementMap.constants, v.constant)
			valReplacementMap.replacements = append(valReplacementMap.replacements, []value{a})
			l := len(valReplacementMap.replacements) - 1
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], ge[0])
		}
	}
	valReplacementMap.combination = make([]value, len(valReplacementMap.constants))
	valReplacementMap.depthIndex = make([]int, len(valReplacementMap.constants))
	for ii := range valReplacementMap.depthIndex {
		valReplacementMap.depthIndex[ii] = 0
	}
	return valReplacementMap, e
}

func verifyActiveMutatePrincipalState(valPrincipalState *principalState, valAttackerState *attackerState, valReplacementMap *replacementMap) (*principalState, bool) {
	failedCheck := false
	valPrincipalStateWithReplacements := principalState{
		name:          valPrincipalState.name,
		constants:     make([]constant, len(valPrincipalState.constants)),
		assigned:      make([]value, len(valPrincipalState.assigned)),
		guard:         make([]bool, len(valPrincipalState.guard)),
		known:         make([]bool, len(valPrincipalState.known)),
		creator:       make([]string, len(valPrincipalState.creator)),
		sender:        make([]string, len(valPrincipalState.sender)),
		wasRewritten:  make([]bool, len(valPrincipalState.wasRewritten)),
		beforeRewrite: make([]value, len(valPrincipalState.beforeRewrite)),
		wasMutated:    make([]bool, len(valPrincipalState.wasMutated)),
		beforeMutate:  make([]value, len(valPrincipalState.beforeMutate)),
	}
	copy(valPrincipalStateWithReplacements.constants, valPrincipalState.constants)
	copy(valPrincipalStateWithReplacements.assigned, valPrincipalState.beforeRewrite)
	copy(valPrincipalStateWithReplacements.guard, valPrincipalState.guard)
	copy(valPrincipalStateWithReplacements.known, valPrincipalState.known)
	copy(valPrincipalStateWithReplacements.creator, valPrincipalState.creator)
	copy(valPrincipalStateWithReplacements.sender, valPrincipalState.sender)
	copy(valPrincipalStateWithReplacements.beforeRewrite, valPrincipalState.beforeRewrite)
	copy(valPrincipalStateWithReplacements.wasMutated, valPrincipalState.wasMutated)
	copy(valPrincipalStateWithReplacements.beforeMutate, valPrincipalState.beforeRewrite)
	for i := range valPrincipalStateWithReplacements.wasRewritten {
		valPrincipalStateWithReplacements.wasRewritten[i] = false
		valPrincipalStateWithReplacements.wasMutated[i] = false
	}
	for i, c := range valReplacementMap.constants {
		ii := sanityGetPrincipalStateIndexFromConstant(&valPrincipalStateWithReplacements, c)
		iii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		iiii := sanityGetAttackerStateIndexFromConstant(valAttackerState, c)
		if valPrincipalStateWithReplacements.creator[ii] != valPrincipalStateWithReplacements.name {
			unassailable := false
			if valPrincipalState.guard[iii] {
				unassailable = true
				if iiii >= 0 {
					if strInSlice(valPrincipalState.sender[iii], valAttackerState.mutatedTo[iiii]) {
						unassailable = false
					}
				}
			}
			if valPrincipalState.known[iii] && !unassailable {
				ar, _ := sanityResolveInternalValues(valPrincipalStateWithReplacements.assigned[ii], valPrincipalState, false)
				ac, _ := sanityResolveInternalValues(valReplacementMap.combination[i], valPrincipalState, false)
				if !sanityEquivalentValues(ar, ac, false, false, valPrincipalState) {
					valPrincipalStateWithReplacements.creator[ii] = "Attacker"
					valPrincipalStateWithReplacements.sender[ii] = "Attacker"
					valPrincipalStateWithReplacements.assigned[ii] = valReplacementMap.combination[i]
					valPrincipalStateWithReplacements.wasMutated[ii] = true
					if !strInSlice(valPrincipalState.name, valAttackerState.mutatedTo[iiii]) {
						valAttackerState.mutatedTo[iiii] = append(valAttackerState.mutatedTo[iiii], valPrincipalState.name)
					}
				}
			}
		}
	}
	failedRewrites, failedRewriteIndices := sanityPerformPrimitiveRewrites(&valPrincipalStateWithReplacements)
	for i, p := range failedRewrites {
		if !p.check {
			continue
		}
		failedCheck = true
		f := failedRewriteIndices[i] + 1
		valPrincipalStateWithReplacements.constants = valPrincipalStateWithReplacements.constants[:f]
		valPrincipalStateWithReplacements.assigned = valPrincipalStateWithReplacements.assigned[:f]
		valPrincipalStateWithReplacements.guard = valPrincipalStateWithReplacements.guard[:f]
		valPrincipalStateWithReplacements.known = valPrincipalStateWithReplacements.known[:f]
		valPrincipalStateWithReplacements.creator = valPrincipalStateWithReplacements.creator[:f]
		valPrincipalStateWithReplacements.sender = valPrincipalStateWithReplacements.sender[:f]
		valPrincipalStateWithReplacements.wasRewritten = valPrincipalStateWithReplacements.wasRewritten[:f]
		valPrincipalStateWithReplacements.beforeRewrite = valPrincipalStateWithReplacements.beforeRewrite[:f]
		valPrincipalStateWithReplacements.wasMutated = valPrincipalStateWithReplacements.wasMutated[:f]
		valPrincipalStateWithReplacements.beforeMutate = valPrincipalStateWithReplacements.beforeMutate[:f]
		break
	}
	return &valPrincipalStateWithReplacements, failedCheck
}
