/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

func inject(
	p primitive, rootIndex int, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	pp, _ := sanityResolveInternalValuesFromPrincipalState(value{
		kind: "primitive", primitive: p,
	}, rootIndex, valPrincipalState, false)
	p = pp.primitive
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
				n,
				n,
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		switch k.kind {
		case "constant":
			if p.arguments[0].kind != "constant" {
				continue
			}
			if k.constant.name == "g" {
				continue
			}
		case "primitive":
			if p.arguments[0].kind != "primitive" {
				continue
			}
			if k.primitive.name != p.arguments[0].primitive.name {
				continue
			}
		case "equation":
			if p.arguments[0].kind != "equation" {
				continue
			}
			if len(k.equation.values) != len(p.arguments[0].equation.values) {
				continue
			}
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			switch kk.kind {
			case "constant":
				if p.arguments[1].kind != "constant" {
					continue
				}
				if kk.constant.name == "g" {
					continue
				}
			case "primitive":
				if p.arguments[1].kind != "primitive" {
					continue
				}
				if kk.primitive.name != p.arguments[1].primitive.name {
					continue
				}
			case "equation":
				if p.arguments[1].kind != "equation" {
					continue
				}
				if len(kk.equation.values) != len(p.arguments[1].equation.values) {
					continue
				}
			}
			for iii, kkk := range valAttackerState.known {
				switch kkk.kind {
				case "constant":
					kkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkk.constant)]
				}
				switch kkk.kind {
				case "constant":
					if p.arguments[2].kind != "constant" {
						continue
					}
					if kkk.constant.name == "g" {
						continue
					}
				case "primitive":
					if p.arguments[2].kind != "primitive" {
						continue
					}
					if kkk.primitive.name != p.arguments[2].primitive.name {
						continue
					}
				case "equation":
					if p.arguments[2].kind != "equation" {
						continue
					}
					if len(kkk.equation.values) != len(p.arguments[2].equation.values) {
						continue
					}
				}
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: "AEAD_ENC",
						arguments: []value{
							valAttackerState.known[i],
							valAttackerState.known[ii],
							valAttackerState.known[iii],
						},
						output: p.output,
						check:  p.check,
					},
				}
				if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
					valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
					valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{-1})
				}
			}
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
				n,
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		switch k.kind {
		case "constant":
			if p.arguments[0].kind != "constant" {
				continue
			}
			if k.constant.name == "g" {
				continue
			}
		case "primitive":
			if p.arguments[0].kind != "primitive" {
				continue
			}
			if k.primitive.name != p.arguments[0].primitive.name {
				continue
			}
		case "equation":
			if p.arguments[0].kind != "equation" {
				continue
			}
			if len(k.equation.values) != len(p.arguments[0].equation.values) {
				continue
			}
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			switch kk.kind {
			case "constant":
				if p.arguments[1].kind != "constant" {
					continue
				}
				if kk.constant.name == "g" {
					continue
				}
			case "primitive":
				if p.arguments[1].kind != "primitive" {
					continue
				}
				if kk.primitive.name != p.arguments[1].primitive.name {
					continue
				}
			case "equation":
				if p.arguments[1].kind != "equation" {
					continue
				}
				if len(kk.equation.values) != len(p.arguments[1].equation.values) {
					continue
				}
			}
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: "ENC",
					arguments: []value{
						valAttackerState.known[i],
						valAttackerState.known[ii],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{-1})
			}
		}
	}
}

func injectSIGN(
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
			name: "SIGN",
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
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		switch k.kind {
		case "constant":
			if p.arguments[0].kind != "constant" {
				continue
			}
			if k.constant.name == "g" {
				continue
			}
		case "primitive":
			if p.arguments[0].kind != "primitive" {
				continue
			}
			if k.primitive.name != p.arguments[0].primitive.name {
				continue
			}
		case "equation":
			if p.arguments[0].kind != "equation" {
				continue
			}
			if len(k.equation.values) != len(p.arguments[0].equation.values) {
				continue
			}
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			switch kk.kind {
			case "constant":
				if p.arguments[1].kind != "constant" {
					continue
				}
				if kk.constant.name == "g" {
					continue
				}
			case "primitive":
				if p.arguments[1].kind != "primitive" {
					continue
				}
				if kk.primitive.name != p.arguments[1].primitive.name {
					continue
				}
			case "equation":
				if p.arguments[1].kind != "equation" {
					continue
				}
				if len(kk.equation.values) != len(p.arguments[1].equation.values) {
					continue
				}
			}
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: "SIGN",
					arguments: []value{
						valAttackerState.known[i],
						valAttackerState.known[ii],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{-1})
			}
		}
	}
}

func injectMAC(
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
			name: "MAC",
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
		valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		switch k.kind {
		case "constant":
			if p.arguments[0].kind != "constant" {
				continue
			}
			if k.constant.name == "g" {
				continue
			}
		case "primitive":
			if p.arguments[0].kind != "primitive" {
				continue
			}
			if k.primitive.name != p.arguments[0].primitive.name {
				continue
			}
		case "equation":
			if p.arguments[0].kind != "equation" {
				continue
			}
			if len(k.equation.values) != len(p.arguments[0].equation.values) {
				continue
			}
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			switch kk.kind {
			case "constant":
				if p.arguments[1].kind != "constant" {
					continue
				}
				if kk.constant.name == "g" {
					continue
				}
			case "primitive":
				if p.arguments[1].kind != "primitive" {
					continue
				}
				if kk.primitive.name != p.arguments[1].primitive.name {
					continue
				}
			case "equation":
				if p.arguments[1].kind != "equation" {
					continue
				}
				if len(kk.equation.values) != len(p.arguments[1].equation.values) {
					continue
				}
			}
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: "MAC",
					arguments: []value{
						valAttackerState.known[i],
						valAttackerState.known[ii],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
				valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
				valReplacementMap.requiredKnowns[l] = append(valReplacementMap.requiredKnowns[l], []int{0})
			}
		}
	}
}
