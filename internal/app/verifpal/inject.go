/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

func inject(
	p primitive, rootIndex int, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
	includeHashes bool,
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
	case "HASH":
		if !includeHashes {
			return
		}
		switch len(p.arguments) {
		case 1:
			injectHASH1(p, valPrincipalState, valReplacementMap, valAttackerState)
		case 2:
			injectHASH2(p, valPrincipalState, valReplacementMap, valAttackerState)
		case 3:
			injectHASH3(p, valPrincipalState, valReplacementMap, valAttackerState)
		case 4:
			injectHASH4(p, valPrincipalState, valReplacementMap, valAttackerState)
		case 5:
			injectHASH5(p, valPrincipalState, valReplacementMap, valAttackerState)
		}
	}
}

func injectValueRules(k value, arg int, p primitive, valPrincipalState *principalState) bool {
	if sanityEquivalentValues(k, value{kind: "primitive", primitive: p}, valPrincipalState) {
		return false
	}
	switch k.kind {
	case "constant":
		if p.arguments[arg].kind != "constant" {
			return false
		}
		if k.constant.name == "g" {
			return false
		}
	case "primitive":
		if p.arguments[arg].kind != "primitive" {
			return false
		}
		if k.primitive.name != p.arguments[arg].primitive.name {
			return false
		}
	case "equation":
		if p.arguments[arg].kind != "equation" {
			return false
		}
		if len(k.equation.values) != len(p.arguments[arg].equation.values) {
			return false
		}
	}
	return true
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
			}
			for iii, kkk := range valAttackerState.known {
				switch kkk.kind {
				case "constant":
					kkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkk.constant)]
				}
				if !injectValueRules(kkk, 2, p, valPrincipalState) {
					continue
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
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
			}
		}
	}
}

func injectHASH1(
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
			name: "HASH",
			arguments: []value{
				n,
			},
			output: p.output,
			check:  p.check,
		},
	}
	if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
		valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "HASH",
				arguments: []value{
					valAttackerState.known[i],
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

func injectHASH2(
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
			name: "HASH",
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
			}
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: "HASH",
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
			}
		}
	}
}

func injectHASH3(
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
			name: "HASH",
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
			}
			for iii, kkk := range valAttackerState.known {
				switch kkk.kind {
				case "constant":
					kkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkk.constant)]
				}
				if !injectValueRules(kkk, 2, p, valPrincipalState) {
					continue
				}
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: "HASH",
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
				}
			}
		}
	}
}

func injectHASH4(
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
			name: "HASH",
			arguments: []value{
				n,
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
			}
			for iii, kkk := range valAttackerState.known {
				switch kkk.kind {
				case "constant":
					kkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkk.constant)]
				}
				if !injectValueRules(kkk, 2, p, valPrincipalState) {
					continue
				}
				for iiii, kkkk := range valAttackerState.known {
					switch kkkk.kind {
					case "constant":
						kkkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkkk.constant)]
					}
					if !injectValueRules(kkkk, 3, p, valPrincipalState) {
						continue
					}
					aa := value{
						kind: "primitive",
						primitive: primitive{
							name: "HASH",
							arguments: []value{
								valAttackerState.known[i],
								valAttackerState.known[ii],
								valAttackerState.known[iii],
								valAttackerState.known[iiii],
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
	}
}

func injectHASH5(
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
			name: "HASH",
			arguments: []value{
				n,
				n,
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
	}
	for i, k := range valAttackerState.known {
		switch k.kind {
		case "constant":
			k = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)]
		}
		if !injectValueRules(k, 0, p, valPrincipalState) {
			continue
		}
		for ii, kk := range valAttackerState.known {
			switch kk.kind {
			case "constant":
				kk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kk.constant)]
			}
			if !injectValueRules(kk, 1, p, valPrincipalState) {
				continue
			}
			for iii, kkk := range valAttackerState.known {
				switch kkk.kind {
				case "constant":
					kkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkk.constant)]
				}
				if !injectValueRules(kkk, 2, p, valPrincipalState) {
					continue
				}
				for iiii, kkkk := range valAttackerState.known {
					switch kkkk.kind {
					case "constant":
						kkkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkkk.constant)]
					}
					if !injectValueRules(kkkk, 3, p, valPrincipalState) {
						continue
					}
					for iiiii, kkkkk := range valAttackerState.known {
						switch kkkkk.kind {
						case "constant":
							kkkkk = valPrincipalState.beforeMutate[sanityGetPrincipalStateIndexFromConstant(valPrincipalState, kkkkk.constant)]
						}
						if !injectValueRules(kkkkk, 4, p, valPrincipalState) {
							continue
						}
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: "HASH",
								arguments: []value{
									valAttackerState.known[i],
									valAttackerState.known[ii],
									valAttackerState.known[iii],
									valAttackerState.known[iiii],
									valAttackerState.known[iiiii],
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
		}
	}
}
