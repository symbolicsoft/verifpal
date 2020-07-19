/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
	"strings"
)

func inject(
	p Primitive, rootPrimitive Primitive, isRootPrimitive bool, injectDepth int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, stage int,
) []Value {
	if verifyResultsAllResolved() {
		return []Value{}
	}
	if primitiveIsCorePrim(p.Name) {
		prim, _ := primitiveCoreGet(p.Name)
		if !prim.Injectable {
			return []Value{}
		}
	} else {
		prim, _ := primitiveGet(p.Name)
		if !prim.Injectable {
			return []Value{}
		}
	}
	if isRootPrimitive {
		rootPrimitive = p
	}
	return injectPrimitive(
		p, rootPrimitive, valPrincipalState, valAttackerState, injectDepth, stage,
	)
}

func injectValueRules(
	k Value, arg int, p Primitive, valPrincipalState PrincipalState, stage int,
) bool {
	switch k.Kind {
	case "constant":
		return injectConstantRules(k.Constant, arg, p, valPrincipalState)
	case "primitive":
		return injectPrimitiveRules(k.Primitive, arg, p, stage)
	case "equation":
		return injectEquationRules(k.Equation, arg, p)
	}
	return true
}

func injectConstantRules(c Constant, arg int, p Primitive, valPrincipalState PrincipalState) bool {
	switch {
	case p.Arguments[arg].Kind != "constant":
		return false
	case strings.ToLower(c.Name) == "g":
		return false
	}
	_, i := valueResolveConstant(p.Arguments[arg].Constant, valPrincipalState)
	_, ii := valueResolveConstant(c, valPrincipalState)
	return valPrincipalState.DeclaredAt[i] >= valPrincipalState.DeclaredAt[ii]
}

func injectPrimitiveRules(k Primitive, arg int, p Primitive, stage int) bool {
	switch {
	case p.Arguments[arg].Kind != "primitive":
		return false
	case injectPrimitiveStageRestricted(k, stage):
		return false
	case !injectMatchSkeletons(k, injectPrimitiveSkeleton(p.Arguments[arg].Primitive)):
		return false
	}
	return true
}

func injectEquationRules(e Equation, arg int, p Primitive) bool {
	switch {
	case p.Arguments[arg].Kind != "equation":
		return false
	case len(e.Values) != len(p.Arguments[arg].Equation.Values):
		return false
	}
	return true
}

func injectPrimitiveStageRestricted(p Primitive, stage int) bool {
	switch stage {
	case 0:
		return true
	case 1:
		return true
	case 2:
		explosive := false
		if primitiveIsCorePrim(p.Name) {
			prim, _ := primitiveCoreGet(p.Name)
			explosive = prim.Explosive
		} else {
			prim, _ := primitiveGet(p.Name)
			explosive = prim.Explosive
		}
		return explosive
	default:
		return false
	}
}

func injectPrimitiveSkeleton(p Primitive) Primitive {
	skeleton := Primitive{
		Name:      p.Name,
		Arguments: make([]Value, len(p.Arguments)),
		Output:    p.Output,
		Check:     false,
	}
	for i, a := range p.Arguments {
		switch a.Kind {
		case "constant":
			skeleton.Arguments[i] = valueN
		case "primitive":
			aa := Value{
				Kind:      "primitive",
				Primitive: injectPrimitiveSkeleton(a.Primitive),
			}
			skeleton.Arguments[i] = aa
		case "equation":
			switch len(a.Equation.Values) {
			case 1:
				skeleton.Arguments[i] = valueG
			default:
				skeleton.Arguments[i] = valueGN
			}
		}
	}
	return skeleton
}

func injectMatchSkeletons(p Primitive, skeleton Primitive) bool {
	if p.Name != skeleton.Name {
		return false
	}
	pv := Value{Kind: "primitive", Primitive: injectPrimitiveSkeleton(p)}
	sv := Value{Kind: "primitive", Primitive: skeleton}
	return valueEquivalentValues(pv, sv, true)
}

func injectMissingSkeletons(p Primitive, valPrincipalState PrincipalState, valAttackerState AttackerState) {
	skeleton := injectPrimitiveSkeleton(p)
	matchingSkeleton := false
SkeletonSearch:
	for _, a := range valAttackerState.Known {
		switch a.Kind {
		case "primitive":
			if injectMatchSkeletons(a.Primitive, skeleton) {
				matchingSkeleton = true
				break SkeletonSearch
			}
		}
	}
	if !matchingSkeleton {
		known := Value{
			Kind:      "primitive",
			Primitive: skeleton,
		}
		if attackerStatePutWrite(known, valPrincipalState) {
			InfoMessage(fmt.Sprintf(
				"Constructed skeleton %s based on %s.",
				prettyPrimitive(skeleton), prettyPrimitive(p),
			), "analysis", true)
		}
	}
}

func injectPrimitive(
	p Primitive, rootPrimitive Primitive,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
	injectDepth int, stage int,
) []Value {
	if injectPrimitiveStageRestricted(p, stage) {
		return []Value{}
	}
	kinjectants := make([][]Value, len(p.Arguments))
	uinjectants := make([][]Value, len(p.Arguments))
	for arg := range p.Arguments {
		for _, k := range valAttackerState.Known {
			switch k.Kind {
			case "constant":
				k, _ = valueResolveConstant(k.Constant, valPrincipalState)
			}
			if !injectValueRules(k, arg, p, valPrincipalState, stage) {
				continue
			}
			switch k.Kind {
			case "constant":
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
			case "primitive":
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
				if stage >= 5 && injectDepth <= stage-5 {
					kinjectants[arg] = append(kinjectants[arg], inject(
						k.Primitive, rootPrimitive, false, injectDepth+1,
						valPrincipalState, valAttackerState, stage,
					)...)
				}
			case "equation":
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
			}
		}
	}
	return injectLoopN(p, kinjectants)
}

func injectLoopN(p Primitive, kinjectants [][]Value) []Value {
	if verifyResultsAllResolved() {
		return []Value{}
	}
	switch len(p.Arguments) {
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
	return []Value{}
}

func injectLoop1(p Primitive, kinjectants [][]Value) []Value {
	injectants := []Value{}
	if verifyResultsAllResolved() {
		return []Value{}
	}
	for i := range kinjectants[0] {
		aa := Value{
			Kind: "primitive",
			Primitive: Primitive{
				Name: p.Name,
				Arguments: []Value{
					kinjectants[0][i],
				},
				Output: p.Output,
				Check:  p.Check,
			},
		}
		injectants = append(injectants, aa)
	}
	return injectants
}

func injectLoop2(p Primitive, kinjectants [][]Value) []Value {
	injectants := []Value{}
	for i := range kinjectants[0] {
		for ii := range kinjectants[1] {
			aa := Value{
				Kind: "primitive",
				Primitive: Primitive{
					Name: p.Name,
					Arguments: []Value{
						kinjectants[0][i],
						kinjectants[1][ii],
					},
					Output: p.Output,
					Check:  p.Check,
				},
			}
			injectants = append(injectants, aa)
		}
	}
	return injectants
}

func injectLoop3(p Primitive, kinjectants [][]Value) []Value {
	injectants := []Value{}
	for i := range kinjectants[0] {
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				aa := Value{
					Kind: "primitive",
					Primitive: Primitive{
						Name: p.Name,
						Arguments: []Value{
							kinjectants[0][i],
							kinjectants[1][ii],
							kinjectants[2][iii],
						},
						Output: p.Output,
						Check:  p.Check,
					},
				}
				injectants = append(injectants, aa)
			}
		}
	}
	return injectants
}

func injectLoop4(p Primitive, kinjectants [][]Value) []Value {
	injectants := []Value{}
	for i := range kinjectants[0] {
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				for iiii := range kinjectants[3] {
					aa := Value{
						Kind: "primitive",
						Primitive: Primitive{
							Name: p.Name,
							Arguments: []Value{
								kinjectants[0][i],
								kinjectants[1][ii],
								kinjectants[2][iii],
								kinjectants[3][iiii],
							},
							Output: p.Output,
							Check:  p.Check,
						},
					}
					injectants = append(injectants, aa)
				}
			}
		}
	}
	return injectants
}

func injectLoop5(p Primitive, kinjectants [][]Value) []Value {
	injectants := []Value{}
	for i := range kinjectants[0] {
		for ii := range kinjectants[1] {
			for iii := range kinjectants[2] {
				for iiii := range kinjectants[3] {
					for iiiii := range kinjectants[4] {
						aa := Value{
							Kind: "primitive",
							Primitive: Primitive{
								Name: p.Name,
								Arguments: []Value{
									kinjectants[0][i],
									kinjectants[1][ii],
									kinjectants[2][iii],
									kinjectants[3][iiii],
									kinjectants[4][iiiii],
								},
								Output: p.Output,
								Check:  p.Check,
							},
						}
						injectants = append(injectants, aa)
					}
				}
			}
		}
	}
	return injectants
}
