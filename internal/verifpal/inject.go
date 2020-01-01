/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

func inject(
	p primitive, isRootValue bool, rootIndex int, valPrincipalState *principalState,
	valAttackerState *attackerState, includeHashes bool,
) *[]value {
	var injectants []value
	if isRootValue {
		pp, _ := sanityResolveInternalValuesFromPrincipalState(value{
			kind: "primitive", primitive: p,
		}, rootIndex, valPrincipalState, false)
		p = pp.primitive
	}
	switch p.name {
	case "AEAD_ENC":
		injectants = injectPrimitive(p, valPrincipalState, valAttackerState, includeHashes)
	case "ENC":
		injectants = injectPrimitive(p, valPrincipalState, valAttackerState, includeHashes)
	case "SIGN":
		injectants = injectPrimitive(p, valPrincipalState, valAttackerState, includeHashes)
	case "MAC":
		injectants = injectPrimitive(p, valPrincipalState, valAttackerState, includeHashes)
	case "HASH":
		if includeHashes {
			injectants = injectPrimitive(p, valPrincipalState, valAttackerState, includeHashes)
		}
	}
	return &injectants
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

func injectPrimitiveSkeleton(p primitive) primitive {
	skeleton := primitive{
		name:      p.name,
		arguments: []value{},
		output:    p.output,
		check:     false,
	}
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
	for _, a := range p.arguments {
		switch a.kind {
		case "constant":
			skeleton.arguments = append(skeleton.arguments, n)
		case "primitive":
			aa := value{
				kind:      "primitive",
				primitive: injectPrimitiveSkeleton(a.primitive),
			}
			skeleton.arguments = append(skeleton.arguments, aa)
		case "equation":
			aa := value{
				kind: "equation",
				equation: equation{
					values: []value{g},
				},
			}
			if len(a.equation.values) == 2 {
				aa.equation.values = append(aa.equation.values, n)
			} else if len(a.equation.values) == 3 {
				aa.equation.values = append(aa.equation.values, n)
				aa.equation.values = append(aa.equation.values, n)
			}
			skeleton.arguments = append(skeleton.arguments, aa)
		}
	}
	return skeleton
}

func injectPrimitive(
	p primitive, valPrincipalState *principalState,
	valAttackerState *attackerState, includeHashes bool,
) []value {
	var injectants []value
	skeleton := value{
		kind:      "primitive",
		primitive: injectPrimitiveSkeleton(p),
	}
	if sanityExactSameValueInValues(skeleton, &valAttackerState.known) < 0 {
		valAttackerState.known = append(valAttackerState.known, skeleton)
		valAttackerState.wire = append(valAttackerState.wire, false)
		valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
	}
	kinjectants := make([][]value, len(p.arguments))
	for arg := range p.arguments {
		for _, k := range valAttackerState.known {
			switch k.kind {
			case "constant":
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)
				k = valPrincipalState.beforeMutate[i]
			}
			if injectValueRules(k, arg, p, valPrincipalState) {
				switch k.kind {
				case "constant":
					kinjectants[arg] = append(kinjectants[arg], k)
				case "primitive":
					kprims := inject(k.primitive, false, -1, valPrincipalState, valAttackerState, includeHashes)
					kinjectants[arg] = append(kinjectants[arg], *kprims...)
				case "equation":
					kinjectants[arg] = append(kinjectants[arg], k)
				}
			}
		}
	}
	switch len(p.arguments) {
	case 1:
		injectLoop1(p, &injectants, &kinjectants)
	case 2:
		injectLoop2(p, &injectants, &kinjectants)
	case 3:
		injectLoop3(p, &injectants, &kinjectants)
	case 4:
		injectLoop4(p, &injectants, &kinjectants)
	case 5:
		injectLoop5(p, &injectants, &kinjectants)
	}
	return injectants
}

func injectLoop1(p primitive, injectants *[]value, kinjectants *[][]value) {
	for i := range (*kinjectants)[0] {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: p.name,
				arguments: []value{
					(*kinjectants)[0][i],
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, injectants) < 0 {
			*injectants = append(*injectants, aa)
		}
	}
}

func injectLoop2(p primitive, injectants *[]value, kinjectants *[][]value) {
	for i := range (*kinjectants)[0] {
		for ii := range (*kinjectants)[1] {
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: p.name,
					arguments: []value{
						(*kinjectants)[0][i],
						(*kinjectants)[1][ii],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityExactSameValueInValues(aa, injectants) < 0 {
				*injectants = append(*injectants, aa)
			}
		}
	}
}

func injectLoop3(p primitive, injectants *[]value, kinjectants *[][]value) {
	for i := range (*kinjectants)[0] {
		for ii := range (*kinjectants)[1] {
			for iii := range (*kinjectants)[2] {
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: p.name,
						arguments: []value{
							(*kinjectants)[0][i],
							(*kinjectants)[1][ii],
							(*kinjectants)[2][iii],
						},
						output: p.output,
						check:  p.check,
					},
				}
				if sanityExactSameValueInValues(aa, injectants) < 0 {
					*injectants = append(*injectants, aa)
				}
			}
		}
	}
}

func injectLoop4(p primitive, injectants *[]value, kinjectants *[][]value) {
	for i := range (*kinjectants)[0] {
		for ii := range (*kinjectants)[1] {
			for iii := range (*kinjectants)[2] {
				for iiii := range (*kinjectants)[3] {
					aa := value{
						kind: "primitive",
						primitive: primitive{
							name: p.name,
							arguments: []value{
								(*kinjectants)[0][i],
								(*kinjectants)[1][ii],
								(*kinjectants)[2][iii],
								(*kinjectants)[3][iiii],
							},
							output: p.output,
							check:  p.check,
						},
					}
					if sanityExactSameValueInValues(aa, injectants) < 0 {
						*injectants = append(*injectants, aa)
					}
				}
			}
		}
	}
}

func injectLoop5(p primitive, injectants *[]value, kinjectants *[][]value) {
	for i := range (*kinjectants)[0] {
		for ii := range (*kinjectants)[1] {
			for iii := range (*kinjectants)[2] {
				for iiii := range (*kinjectants)[3] {
					for iiiii := range (*kinjectants)[4] {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: p.name,
								arguments: []value{
									(*kinjectants)[0][i],
									(*kinjectants)[1][ii],
									(*kinjectants)[2][iii],
									(*kinjectants)[3][iiii],
									(*kinjectants)[4][iiiii],
								},
								output: p.output,
								check:  p.check,
							},
						}
						if sanityExactSameValueInValues(aa, injectants) < 0 {
							*injectants = append(*injectants, aa)
						}
					}
				}
			}
		}
	}
}
