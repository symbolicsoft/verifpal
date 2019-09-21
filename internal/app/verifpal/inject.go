/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

func inject(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	switch p.name {
	case "AEAD_ENC":
		injectAEADENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "ENC":
		injectENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "SIGN":
		injectSIGN(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "MAC":
		injectMAC(p, valPrincipalState, valReplacementMap, valAttackerState)
	}
}

func injectAEADENC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	n := value{
		kind: "constant",
		constant: constant{
			name:        "nil",
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "public",
		},
	}
	aa := value{
		kind: "primitive",
		primitive: primitive{
			name: "AEAD_ENC",
			arguments: []value{
				n,
				p.arguments[1],
				p.arguments[2],
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{1, 2})
	}
	aa = value{
		kind: "primitive",
		primitive: primitive{
			name: "AEAD_ENC",
			arguments: []value{
				n,
				n,
				p.arguments[2],
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{2})
	}
	aa = value{
		kind: "primitive",
		primitive: primitive{
			name: "AEAD_ENC",
			arguments: []value{
				n,
				n,
				n,
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{-1})
	}
	for _, k := range valAttackerState.known {
		aa = value{
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
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0, 2})
		}
	}
}

func injectENC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	n := value{
		kind: "constant",
		constant: constant{
			name:        "nil",
			guard:       false,
			fresh:       false,
			declaration: "knows",
			qualifier:   "public",
		},
	}
	aa := value{
		kind: "primitive",
		primitive: primitive{
			name: "ENC",
			arguments: []value{
				n,
				p.arguments[1],
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{1})
	}
	aa = value{
		kind: "primitive",
		primitive: primitive{
			name: "ENC",
			arguments: []value{
				n,
				n,
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{-1})
	}
	for _, k := range valAttackerState.known {
		aa = value{
			kind: "primitive",
			primitive: primitive{
				name: "ENC",
				arguments: []value{
					p.arguments[0],
					k,
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
		}
		aa = value{
			kind: "primitive",
			primitive: primitive{
				name: "ENC",
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
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{1})
		}
	}
}

func injectSIGN(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "SIGN",
				arguments: []value{
					p.arguments[0],
					k,
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
		}
		aa = value{
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
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{1})
		}
	}
}

func injectMAC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "MAC",
				arguments: []value{
					p.arguments[0],
					k,
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
		}
		aa = value{
			kind: "primitive",
			primitive: primitive{
				name: "MAC",
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
			valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{1})
		}
	}
}
