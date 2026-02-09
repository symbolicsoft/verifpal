/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
)

func inject(
	p *Primitive, injectDepth int,
	valPrincipalState *PrincipalState, valAttackerState AttackerState, stage int,
) []*Value {
	if verifyResultsAllResolved() {
		return []*Value{}
	}
	return injectPrimitive(
		p, valPrincipalState, valAttackerState, injectDepth, stage,
	)
}

func injectValueRules(
	k *Value, arg int, p *Primitive, stage int,
) bool {
	switch k.Kind {
	case typesEnumConstant:
		return injectConstantRules(k.Data.(*Constant), arg, p)
	case typesEnumPrimitive:
		return injectPrimitiveRules(k.Data.(*Primitive), arg, p, stage)
	case typesEnumEquation:
		return injectEquationRules(k.Data.(*Equation), arg, p)
	}
	return true
}

func injectConstantRules(c *Constant, arg int, p *Primitive) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumConstant:
		return false
	case valueEquivalentConstants(c, valueG.Data.(*Constant)):
		return false
	}
	return true
}

func injectPrimitiveRules(k *Primitive, arg int, p *Primitive, stage int) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumPrimitive:
		return false
	case injectPrimitiveStageRestricted(k, stage):
		return false
	}
	return injectSkeletonEquivalent(k, p.Arguments[arg].Data.(*Primitive))
}

func injectEquationRules(e *Equation, arg int, p *Primitive) bool {
	switch {
	case p.Arguments[arg].Kind != typesEnumEquation:
		return false
	case len(e.Values) != len(p.Arguments[arg].Data.(*Equation).Values):
		return false
	}
	return true
}

func injectPrimitiveStageRestricted(p *Primitive, stage int) bool {
	switch stage {
	case 0:
		return true
	case 1:
		return true
	case 2:
		explosive := false
		if primitiveIsCorePrimitive(p.ID) {
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

func injectPrimitiveSkeleton(p *Primitive, depth int) (*Primitive, int) {
	skeleton := &Primitive{
		ID:        p.ID,
		Arguments: make([]*Value, len(p.Arguments)),
		Output:    p.Output,
		Check:     false,
	}
	for i, a := range p.Arguments {
		switch a.Kind {
		case typesEnumConstant:
			skeleton.Arguments[i] = valueNil
		case typesEnumPrimitive:
			var pp *Primitive
			pp, depth = injectPrimitiveSkeleton(a.Data.(*Primitive), depth+1)
			aa := &Value{
				Kind: typesEnumPrimitive,
				Data: pp,
			}
			skeleton.Arguments[i] = aa
		case typesEnumEquation:
			switch len(a.Data.(*Equation).Values) {
			case 1:
				skeleton.Arguments[i] = valueG
			default:
				skeleton.Arguments[i] = valueGNil
			}
		}
	}
	return skeleton, depth + 1
}

func injectSkeletonNotDeeper(p *Primitive, reference *Primitive) bool {
	if p.ID != reference.ID {
		return false
	}
	_, pd := injectPrimitiveSkeleton(p, 0)
	_, sd := injectPrimitiveSkeleton(reference, 0)
	return pd <= sd
}

func injectSkeletonEquivalent(p *Primitive, reference *Primitive) bool {
	if p.ID != reference.ID {
		return false
	}
	p1, pd := injectPrimitiveSkeleton(p, 0)
	p2, sd := injectPrimitiveSkeleton(reference, 0)
	if sd > pd {
		return false
	}
	e, _, _ := valueEquivalentPrimitives(p1, p2, false)
	return e
}

func injectMatchSkeletons(p *Primitive, skeleton *Primitive) bool {
	if p.ID != skeleton.ID {
		return false
	}
	ps, _ := injectPrimitiveSkeleton(p, 0)
	pv := Value{Kind: typesEnumPrimitive, Data: ps}
	sv := Value{Kind: typesEnumPrimitive, Data: skeleton}
	return valueEquivalentValues(&pv, &sv, true)
}

func injectMissingSkeletons(p *Primitive, valPrincipalState *PrincipalState, valAttackerState AttackerState) {
	skeleton, _ := injectPrimitiveSkeleton(p, 0)
	matchingSkeleton := false
SkeletonSearch:
	for _, a := range valAttackerState.Known {
		switch a.Kind {
		case typesEnumPrimitive:
			if injectMatchSkeletons(a.Data.(*Primitive), skeleton) {
				matchingSkeleton = true
				break SkeletonSearch
			}
		}
	}
	if !matchingSkeleton {
		known := &Value{
			Kind: typesEnumPrimitive,
			Data: skeleton,
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
			injectMissingSkeletons(a.Data.(*Primitive), valPrincipalState, valAttackerState)
		}
	}
}

func injectPrimitive(
	p *Primitive, valPrincipalState *PrincipalState, valAttackerState AttackerState,
	injectDepth int, stage int,
) []*Value {
	if injectPrimitiveStageRestricted(p, stage) {
		return []*Value{}
	}
	kinjectants := make([][]*Value, len(p.Arguments))
	uinjectants := make([][]*Value, len(p.Arguments))
	for arg := range p.Arguments {
		if verifyResultsAllResolved() {
			return []*Value{}
		}
		for _, k := range valAttackerState.Known {
			switch k.Kind {
			case typesEnumConstant:
				k, _ = valueResolveConstant(k.Data.(*Constant), valPrincipalState, true)
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
				if stage >= stageRecursiveInjection && injectDepth <= stage-stageRecursiveInjection {
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
	k *Value, arg int, uinjectants [][]*Value, kinjectants [][]*Value,
	valPrincipalState *PrincipalState, valAttackerState AttackerState,
	injectDepth int, stage int,
) ([][]*Value, [][]*Value) {
	kp := inject(
		k.Data.(*Primitive), injectDepth+1,
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

func injectLoopN(p *Primitive, kinjectants [][]*Value) []*Value {
	if verifyResultsAllResolved() {
		return []*Value{}
	}
	n := len(kinjectants)
	if n == 0 {
		return []*Value{}
	}
	for _, k := range kinjectants {
		if len(k) == 0 {
			return []*Value{}
		}
	}
	totalSize := 1
	for _, k := range kinjectants {
		totalSize *= len(k)
	}
	injectants := make([]*Value, 0, totalSize)
	indices := make([]int, n)
	for {
		if verifyResultsAllResolved() {
			return injectants
		}
		args := make([]*Value, n)
		for j := 0; j < n; j++ {
			args[j] = kinjectants[j][indices[j]]
		}
		injectants = append(injectants, &Value{
			Kind: typesEnumPrimitive,
			Data: &Primitive{
				ID:        p.ID,
				Arguments: args,
				Output:    p.Output,
				Check:     p.Check,
			},
		})
		carry := true
		for j := n - 1; j >= 0 && carry; j-- {
			indices[j]++
			if indices[j] < len(kinjectants[j]) {
				carry = false
			} else {
				indices[j] = 0
			}
		}
		if carry {
			break
		}
	}
	return injectants
}
