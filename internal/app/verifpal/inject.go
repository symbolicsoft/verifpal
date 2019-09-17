/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import "fmt"

func inject(a value, valPrincipalState *principalState, valReplacementMap *replacementMap, valAttackerState *attackerState) {
	switch a.primitive.name {
	case "AEAD_ENC":
		injectAEADENC(a, valPrincipalState, valReplacementMap, valAttackerState)
	case "ENC":
		injectENC(a, valPrincipalState, valReplacementMap, valAttackerState)
	case "SIGN":
		injectSIGN(a, valPrincipalState, valReplacementMap, valAttackerState)
	case "MAC":
		injectMAC(a, valPrincipalState, valReplacementMap, valAttackerState)
	}
}

func injectGetAttackerValues(valReplacementMap *replacementMap) ([]value, []value) {
	e := []value{}
	ge := []value{}
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
			values: []value{g, e[0]},
		},
	})
	return e, ge
}

func injectAEADENC(a value, valPrincipalState *principalState, valReplacementMap *replacementMap, valAttackerState *attackerState) {
	e, ge := injectGetAttackerValues(valReplacementMap)
	l := len(valReplacementMap.replacements) - 1
	aa := value{
		kind: "primitive",
		primitive: primitive{
			name: "AEAD_ENC",
			arguments: []value{
				e[0],
				ge[0],
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
			((aaa.kind == "constant") ||
				(aaa.kind == "primitive" &&
					aaa.primitive.name == a.primitive.arguments[1].primitive.name) ||
				(aaa.kind == "equation")) {
			if sanityEquivalentValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
				if sanityEquivalentValueInValues(a.primitive.arguments[2], &valAttackerState.known, valPrincipalState) >= 0 {
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
					if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
						valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
					}
				}
			}
		}
	}
}

func injectENC(a value, valPrincipalState *principalState, valReplacementMap *replacementMap, valAttackerState *attackerState) {
	e, ge := injectGetAttackerValues(valReplacementMap)
	l := len(valReplacementMap.replacements) - 1
	for _, aaa := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "ENC",
				arguments: []value{
					e[0],
					ge[0],
				},
				output: a.primitive.output,
				check:  a.primitive.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		}
		if aaa.kind == a.primitive.arguments[1].kind &&
			((aaa.kind == "constant") ||
				(aaa.kind == "primitive" &&
					aaa.primitive.name == a.primitive.arguments[1].primitive.name) ||
				(aaa.kind == "equation")) {
			if sanityEquivalentValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
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
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
			}
		}
	}
}

func injectSIGN(a value, valPrincipalState *principalState, valReplacementMap *replacementMap, valAttackerState *attackerState) {
	e, ge := injectGetAttackerValues(valReplacementMap)
	l := len(valReplacementMap.replacements) - 1
	aa := value{
		kind: "primitive",
		primitive: primitive{
			name: "SIGN",
			arguments: []value{
				e[0],
				ge[0],
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
			((aaa.kind == "constant") ||
				(aaa.kind == "primitive" &&
					aaa.primitive.name == a.primitive.arguments[0].primitive.name) ||
				(aaa.kind == "equation")) {
			if sanityEquivalentValueInValues(a.primitive.arguments[1], &valAttackerState.known, valPrincipalState) >= 0 {
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
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
			}
		}
	}
}

func injectMAC(a value, valPrincipalState *principalState, valReplacementMap *replacementMap, valAttackerState *attackerState) {
	e, ge := injectGetAttackerValues(valReplacementMap)
	l := len(valReplacementMap.replacements) - 1
	aa := value{
		kind: "primitive",
		primitive: primitive{
			name: "MAC",
			arguments: []value{
				e[0],
				ge[0],
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
			((aaa.kind == "constant") ||
				(aaa.kind == "primitive" &&
					aaa.primitive.name == a.primitive.arguments[0].primitive.name) ||
				(aaa.kind == "equation")) {
			if sanityEquivalentValueInValues(a.primitive.arguments[1], &valAttackerState.known, valPrincipalState) >= 0 {
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
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
			}
		}
		if aaa.kind == a.primitive.arguments[1].kind &&
			((aaa.kind == "constant") ||
				(aaa.kind == "primitive" &&
					aaa.primitive.name == a.primitive.arguments[1].primitive.name) ||
				(aaa.kind == "equation")) {
			if sanityEquivalentValueInValues(a.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
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
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				}
			}
		}
	}
}
