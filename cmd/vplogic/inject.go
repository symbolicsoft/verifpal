/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
)

func inject(
	p Primitive, injectDepth int,
	valPrincipalState PrincipalState, valAttackerState AttackerState, stage int,
) []Value {
	if verifyResultsAllResolved() {
		return []Value{}
	}
	if primitiveIsCorePrim(p.ID) {
		prim, _ := primitiveCoreGet(p.ID)
		if !prim.Injectable {
			return []Value{}
		}
	} else {
		prim, _ := primitiveGet(p.ID)
		if !prim.Injectable {
			return []Value{}
		}
	}
	return injectPrimitive(
		p, valPrincipalState, valAttackerState, injectDepth, stage,
	)
}

func injectValueRules(
	k Value, arg int, p Primitive, stage int,
) bool {
	switch k.Kind {
	case typesEnumConstant:
		return injectConstantRules(k.Constant, arg, p)
	case typesEnumPrimitive:
		return injectPrimitiveRules(k.Primitive, arg, p, stage)
	case typesEnumEquation:
		return injectEquationRules(k.Equation, arg, p)
	}
	return true
}

func injectConstantRules(c Constant, arg int, p Primitive) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumConstant:
		return false
	case c.ID == valueG.Constant.ID:
		return false
	}
	return true
}

func injectPrimitiveRules(k Primitive, arg int, p Primitive, stage int) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumPrimitive:
		return false
	case injectPrimitiveStageRestricted(k, stage):
		return false
	}
	return injectSkeletonNotDeeper(k, p.Arguments[arg].Primitive)
}

func injectEquationRules(e Equation, arg int, p Primitive) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumEquation:
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
		if primitiveIsCorePrim(p.ID) {
			prim, _ := primitiveCoreGet(p.ID)
			explosive = prim.Explosive
		} else {
			prim, _ := primitiveGet(p.ID)
			explosive = prim.Explosive
		}
		return explosive
	default:
		return false
	}
}

func injectPrimitiveSkeleton(p Primitive, depth int) (Primitive, int) {
	skeleton := Primitive{
		ID:        p.ID,
		Arguments: make([]Value, len(p.Arguments)),
		Output:    p.Output,
		Check:     false,
	}
	for i, a := range p.Arguments {
		switch a.Kind {
		case typesEnumConstant:
			skeleton.Arguments[i] = valueNil
		case typesEnumPrimitive:
			pp, dd := injectPrimitiveSkeleton(a.Primitive, depth)
			if dd > depth {
				depth = dd
			}
			aa := Value{
				Kind:      typesEnumPrimitive,
				Primitive: pp,
			}
			skeleton.Arguments[i] = aa
		case typesEnumEquation:
			switch len(a.Equation.Values) {
			case 1:
				skeleton.Arguments[i] = valueG
			default:
				skeleton.Arguments[i] = valueGNil
			}
		}
	}
	return skeleton, depth + 1
}

func injectSkeletonNotDeeper(p Primitive, reference Primitive) bool {
	if p.ID != reference.ID {
		return false
	}
	_, pd := injectPrimitiveSkeleton(p, 0)
	_, sd := injectPrimitiveSkeleton(reference, 0)
	return pd <= sd
}

func injectMatchSkeletons(p Primitive, skeleton Primitive) bool {
	if p.ID != skeleton.ID {
		return false
	}
	ps, _ := injectPrimitiveSkeleton(p, 0)
	pv := Value{Kind: typesEnumPrimitive, Primitive: ps}
	sv := Value{Kind: typesEnumPrimitive, Primitive: skeleton}
	return valueEquivalentValues(&pv, &sv, true)
}

func injectMissingSkeletons(p Primitive, valPrincipalState PrincipalState, valAttackerState AttackerState) {
	skeleton, _ := injectPrimitiveSkeleton(p, 0)
	matchingSkeleton := false
SkeletonSearch:
	for _, a := range valAttackerState.Known {
		switch a.Kind {
		case typesEnumPrimitive:
			if injectMatchSkeletons(a.Primitive, skeleton) {
				matchingSkeleton = true
				break SkeletonSearch
			}
		}
	}
	if !matchingSkeleton {
		known := Value{
			Kind:      typesEnumPrimitive,
			Primitive: skeleton,
		}
		if attackerStatePutWrite(known, valPrincipalState) {
			InfoMessage(fmt.Sprintf(
				"Constructed skeleton %s based on %s.",
				prettyPrimitive(skeleton), prettyPrimitive(p),
			), "analysis", true)
		}
	}
	for _, a := range p.Arguments {
		switch a.Kind {
		case typesEnumPrimitive:
			injectMissingSkeletons(a.Primitive, valPrincipalState, valAttackerState)
		}
	}
}

func injectPrimitive(
	p Primitive, valPrincipalState PrincipalState, valAttackerState AttackerState,
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
			case typesEnumConstant:
				k, _ = valueResolveConstant(k.Constant, valPrincipalState)
			}
			if !injectValueRules(k, arg, p, stage) {
				continue
			}
			switch k.Kind {
			case typesEnumConstant:
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
			case typesEnumPrimitive:
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
				if stage >= 5 && injectDepth <= stage-5 {
					uinjectants, kinjectants = injectPrimitiveRecursively(
						k, arg, uinjectants, kinjectants,
						valPrincipalState, valAttackerState, injectDepth, stage,
					)
				}
			case typesEnumEquation:
				if valueEquivalentValueInValues(k, uinjectants[arg]) < 0 {
					uinjectants[arg] = append(uinjectants[arg], k)
					kinjectants[arg] = append(kinjectants[arg], k)
				}
			}
		}
	}
	return injectLoopN(p, kinjectants)
}

func injectPrimitiveRecursively(
	k Value, arg int, uinjectants [][]Value, kinjectants [][]Value,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
	injectDepth int, stage int,
) ([][]Value, [][]Value) {
	kp := inject(
		k.Primitive, injectDepth+1,
		valPrincipalState, valAttackerState, stage,
	)
	for _, kkp := range kp {
		if valueEquivalentValueInValues(kkp, uinjectants[arg]) < 0 {
			uinjectants[arg] = append(uinjectants[arg], kkp)
			kinjectants[arg] = append(kinjectants[arg], kkp)
		}
	}
	return uinjectants, kinjectants
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
			Kind: typesEnumPrimitive,
			Primitive: Primitive{
				ID: p.ID,
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
				Kind: typesEnumPrimitive,
				Primitive: Primitive{
					ID: p.ID,
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
					Kind: typesEnumPrimitive,
					Primitive: Primitive{
						ID: p.ID,
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
						Kind: typesEnumPrimitive,
						Primitive: Primitive{
							ID: p.ID,
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
							Kind: typesEnumPrimitive,
							Primitive: Primitive{
								ID: p.ID,
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
