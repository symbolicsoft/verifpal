/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"fmt"
	"strings"
)

func inject(
	p primitive, rootPrimitive primitive, isRootPrimitive bool,
	valPrincipalState principalState, valAttackerState attackerState, stage int,
) []value {
	if verifyResultsAllResolved() {
		return []value{}
	}
	prim := primitiveGet(p.name)
	if !prim.injectable {
		return []value{}
	}
	if isRootPrimitive {
		rootPrimitive = p
	}
	return injectPrimitive(
		p, rootPrimitive, valPrincipalState, valAttackerState, stage,
	)
}

func injectValueRules(
	k value, arg int, p primitive, rootPrimitive primitive, stage int,
) bool {
	if sanityEquivalentValues(k, value{
		kind:      "primitive",
		primitive: p,
	}) {
		return false
	}
	if sanityEquivalentValues(k, value{
		kind:      "primitive",
		primitive: rootPrimitive,
	}) {
		return false
	}
	switch k.kind {
	case "constant":
		return injectConstantRules(k.constant, arg, p)
	case "primitive":
		return injectPrimitiveRules(k.primitive, arg, p, stage)
	case "equation":
		return injectEquationRules(k.equation, arg, p)
	}
	return true
}

func injectConstantRules(c constant, arg int, p primitive) bool {
	switch {
	case p.arguments[arg].kind != "constant":
		return false
	case strings.ToLower(c.name) == "g":
		return false
	}
	return true
}

func injectPrimitiveRules(k primitive, arg int, p primitive, stage int) bool {
	switch {
	case p.arguments[arg].kind != "primitive":
		return false
	case injectPrimitiveStageRestricted(k, stage):
		return false
	case !injectMatchSkeletons(k, injectPrimitiveSkeleton(p.arguments[arg].primitive)):
		return false
	}
	return true
}

func injectEquationRules(e equation, arg int, p primitive) bool {
	switch {
	case p.arguments[arg].kind != "equation":
		return false
	case len(e.values) != len(p.arguments[arg].equation.values):
		return false
	}
	for i := range e.values {
		if e.values[i].kind != p.arguments[arg].equation.values[i].kind {
			return false
		}
	}
	return true
}

func injectPrimitiveStageRestricted(p primitive, stage int) bool {
	switch stage {
	case 0:
		return true
	case 1:
		return true
	case 2:
		switch p.name {
		case "HASH", "HKDF":
			return true
		}
	case 3:
		return false
	case 4:
		return false
	}
	return false
}

func injectPrimitiveSkeleton(p primitive) primitive {
	skeleton := primitive{
		name:      p.name,
		arguments: make([]value, len(p.arguments)),
		output:    p.output,
		check:     false,
	}
	for i, a := range p.arguments {
		switch a.kind {
		case "constant":
			skeleton.arguments[i] = constantN
		case "primitive":
			aa := value{
				kind:      "primitive",
				primitive: injectPrimitiveSkeleton(a.primitive),
			}
			skeleton.arguments[i] = aa
		case "equation":
			skeleton.arguments[i] = constantN
		}
	}
	return skeleton
}

func injectMatchSkeletons(p primitive, skeleton primitive) bool {
	if p.name != skeleton.name {
		return false
	}
	pv := value{kind: "primitive", primitive: injectPrimitiveSkeleton(p)}
	sv := value{kind: "primitive", primitive: skeleton}
	return sanityEquivalentValues(pv, sv)
}

func injectMissingSkeletons(p primitive, valAttackerState attackerState) {
	skeleton := injectPrimitiveSkeleton(p)
	matchingSkeleton := false
SkeletonSearch:
	for _, a := range valAttackerState.known {
		switch a.kind {
		case "primitive":
			if injectMatchSkeletons(a.primitive, skeleton) {
				matchingSkeleton = true
				break SkeletonSearch
			}
		}
	}
	if !matchingSkeleton {
		known := value{
			kind:      "primitive",
			primitive: skeleton,
		}
		if attackerStatePutWrite(known) {
			PrettyMessage(fmt.Sprintf(
				"Constructed skeleton %s.",
				prettyPrimitive(skeleton),
			), "analysis", true)
		}
	}
	for _, a := range p.arguments {
		switch a.kind {
		case "primitive":
			injectMissingSkeletons(a.primitive, valAttackerState)
		}
	}
}

func injectPrimitive(
	p primitive, rootPrimitive primitive,
	valPrincipalState principalState, valAttackerState attackerState,
	stage int,
) []value {
	if injectPrimitiveStageRestricted(p, stage) {
		return []value{}
	}
	kinjectants := make([][]value, len(p.arguments))
	injectMissingSkeletons(p, valAttackerState)
	for arg := range p.arguments {
		for _, k := range valAttackerState.known {
			switch k.kind {
			case "constant":
				i := sanityGetPrincipalStateIndexFromConstant(
					valPrincipalState, k.constant,
				)
				k = valPrincipalState.assigned[i]
			}
			if !injectValueRules(k, arg, p, rootPrimitive, stage) {
				continue
			}
			switch k.kind {
			case "constant":
				kinjectants[arg] = append(kinjectants[arg], k)
			case "primitive":
				if stage <= 3 {
					kinjectants[arg] = append(kinjectants[arg], k)
					continue
				}
				kinjectants[arg] = append(kinjectants[arg], inject(
					k.primitive, rootPrimitive, false,
					valPrincipalState, valAttackerState, stage,
				)...)
			case "equation":
				kinjectants[arg] = append(kinjectants[arg], k)
			}
		}
	}
	return injectLoopN(p, kinjectants)
}

func injectLoopN(p primitive, kinjectants [][]value) []value {
	switch len(p.arguments) {
	case 1:
		return injectLoop1(p, kinjectants)
	case 2:
		return injectLoop2(p, kinjectants)
	case 3:
		return injectLoop3(p, kinjectants)
	case 4:
		return injectLoop4(p, kinjectants)
	case 5:
		return injectLoop5(p, kinjectants)
	}
	return []value{}
}

func injectLoop1(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
		if verifyResultsAllResolved() {
			return []value{}
		}
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: p.name,
				arguments: []value{
					kinjectants[0][i],
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityEquivalentValueInValues(aa, injectants) < 0 {
			injectants = append(injectants, aa)
		}
	}
	return injectants
}

func injectLoop2(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
		if verifyResultsAllResolved() {
			return []value{}
		}
		for ii := range kinjectants[1] {
			aa := value{
				kind: "primitive",
				primitive: primitive{
					name: p.name,
					arguments: []value{
						kinjectants[0][i],
						kinjectants[1][ii],
					},
					output: p.output,
					check:  p.check,
				},
			}
			if sanityEquivalentValueInValues(aa, injectants) < 0 {
				injectants = append(injectants, aa)
			}
		}
	}
	return injectants
}

func injectLoop3(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
		if verifyResultsAllResolved() {
			return []value{}
		}
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				aa := value{
					kind: "primitive",
					primitive: primitive{
						name: p.name,
						arguments: []value{
							kinjectants[0][i],
							kinjectants[1][ii],
							kinjectants[2][iii],
						},
						output: p.output,
						check:  p.check,
					},
				}
				if sanityEquivalentValueInValues(aa, injectants) < 0 {
					injectants = append(injectants, aa)
				}
			}
		}
	}
	return injectants
}

func injectLoop4(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
		if verifyResultsAllResolved() {
			return []value{}
		}
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				for iiii := range kinjectants[3] {
					aa := value{
						kind: "primitive",
						primitive: primitive{
							name: p.name,
							arguments: []value{
								kinjectants[0][i],
								kinjectants[1][ii],
								kinjectants[2][iii],
								kinjectants[3][iiii],
							},
							output: p.output,
							check:  p.check,
						},
					}
					if sanityEquivalentValueInValues(aa, injectants) < 0 {
						injectants = append(injectants, aa)
					}
				}
			}
		}
	}
	return injectants
}

func injectLoop5(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
		if verifyResultsAllResolved() {
			return []value{}
		}
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				for iiii := range kinjectants[3] {
					for iiiii := range kinjectants[4] {
						aa := value{
							kind: "primitive",
							primitive: primitive{
								name: p.name,
								arguments: []value{
									kinjectants[0][i],
									kinjectants[1][ii],
									kinjectants[2][iii],
									kinjectants[3][iiii],
									kinjectants[4][iiiii],
								},
								output: p.output,
								check:  p.check,
							},
						}
						if sanityEquivalentValueInValues(aa, injectants) < 0 {
							injectants = append(injectants, aa)
						}
					}
				}
			}
		}
	}
	return injectants
}
