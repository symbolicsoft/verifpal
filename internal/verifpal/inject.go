/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"fmt"
	"strings"
)

func inject(
	p primitive, rootPrimitive primitive, isRootPrimitive bool, rootIndex int,
	valPrincipalState principalState, valAttackerState attackerState,
	stage int, depth int,
) []value {
	if verifyResultsAllResolved() {
		return []value{}
	}
	prim := primitiveGet(p.name)
	if !prim.injectable {
		return []value{}
	}
	if isRootPrimitive {
		pp, _ := sanityResolveValueInternalValuesFromPrincipalState(value{
			kind: "primitive", primitive: p,
		}, rootIndex, valPrincipalState, false)
		p = pp.primitive
		rootPrimitive = p
	}
	return injectPrimitive(
		p, rootPrimitive, valPrincipalState, valAttackerState,
		stage, depth,
	)
}

func injectValueRules(
	k value, arg int, p primitive, rootPrimitive primitive,
	valPrincipalState principalState, stage int, depth int,
) bool {
	if sanityEquivalentValues(k, value{
		kind:      "primitive",
		primitive: p,
	}, valPrincipalState) {
		return false
	}
	if sanityEquivalentValues(k, value{
		kind:      "primitive",
		primitive: rootPrimitive,
	}, valPrincipalState) {
		return false
	}
	switch k.kind {
	case "constant":
		return injectConstantRules(k.constant, arg, p, valPrincipalState)
	case "primitive":
		return injectPrimitiveRules(k.primitive, arg, p, stage, depth)
	case "equation":
		return injectEquationRules(k.equation, arg, p)
	}
	return true
}

func injectConstantRules(c constant, arg int, p primitive, valPrincipalState principalState) bool {
	switch {
	case p.arguments[arg].kind != "constant":
		return false
	case strings.ToLower(c.name) == "g":
		return false
	case !sanityConstantIsUsedByPrincipalInPrincipalState(valPrincipalState, c):
		if strings.ToLower(c.name) != "nil" {
			return false
		}
	}
	return true
}

func injectPrimitiveRules(k primitive, arg int, p primitive, stage int, depth int) bool {
	switch {
	case injectPrimitiveStageRestricted(k, stage, depth):
		return false
	case p.arguments[arg].kind != "primitive":
		return false
	case k.name != p.arguments[arg].primitive.name:
		return false
	case len(k.arguments) != len(p.arguments[arg].primitive.arguments):
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
	return true
}

func injectPrimitiveStageRestricted(p primitive, stage int, depth int) bool {
	switch stage {
	case 0:
		return true
	case 1:
		return true
	case 2:
		if depth > 2 {
			return true
		}
	case 3:
		switch p.name {
		case "HKDF":
			if depth > 2 {
				return true
			}
		}
	case 4:
		switch p.name {
		case "HKDF":
			if depth > 2 {
				return true
			}
		}
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
	return prettyPrimitive(injectPrimitiveSkeleton(p)) == prettyPrimitive(skeleton)
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
		write := attackerStateWrite{
			known: value{
				kind:      "primitive",
				primitive: skeleton,
			},
			wire:      false,
			mutatedTo: []string{},
		}
		if attackerStatePutWrite(write) {
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
	stage int, depth int,
) []value {
	if injectPrimitiveStageRestricted(p, stage, depth) {
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
				k = valPrincipalState.beforeMutate[i]
			}
			if !injectValueRules(
				k, arg, p, rootPrimitive, valPrincipalState,
				stage, depth,
			) {
				continue
			}
			switch k.kind {
			case "constant":
				kinjectants[arg] = append(kinjectants[arg], k)
			case "primitive":
				var kprims []value
				kprims = inject(
					k.primitive, rootPrimitive, false, -1,
					valPrincipalState, valAttackerState,
					stage, injectIncrementDepth(depth),
				)
				if len(kprims) > 0 {
					kinjectants[arg] = append(kinjectants[arg], kprims...)
				}
			case "equation":
				kinjectants[arg] = append(kinjectants[arg], k)
			}
		}
	}

	return injectLoopN(p, kinjectants)
}

func injectIncrementDepth(depth int) int {
	return depth + 1
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
		if sanityExactSameValueInValues(aa, injectants) < 0 {
			injectants = append(injectants, aa)
		}
	}
	return injectants
}

func injectLoop2(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
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
			if sanityExactSameValueInValues(aa, injectants) < 0 {
				injectants = append(injectants, aa)
			}
		}
	}
	return injectants
}

func injectLoop3(p primitive, kinjectants [][]value) []value {
	var injectants []value
	for i := range kinjectants[0] {
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
				if sanityExactSameValueInValues(aa, injectants) < 0 {
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
					if sanityExactSameValueInValues(aa, injectants) < 0 {
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
						if sanityExactSameValueInValues(aa, injectants) < 0 {
							injectants = append(injectants, aa)
						}
					}
				}
			}
		}
	}
	return injectants
}
