/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bba897c5cdfd22cdbe7a6c25141b97b2

package verifpal

import "fmt"

func possibleToDecomposePrimitive(
	p primitive, valPrincipalState principalState, valAttackerState attackerState,
) (bool, value, []value) {
	has := []value{}
	prim := primitiveGet(p.name)
	if !prim.decompose.hasRule {
		return false, value{}, has
	}
	for i, g := range prim.decompose.given {
		a := p.arguments[g]
		a, valid := prim.decompose.filter(a, i, valPrincipalState)
		ii := sanityEquivalentValueInValues(a, valAttackerState.known, valPrincipalState)
		if valid && ii >= 0 {
			has = append(has, a)
			continue
		}
		switch a.kind {
		case "primitive":
			r, _ := possibleToReconstructPrimitive(a.primitive, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
			r, _, _ = possibleToDecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		case "equation":
			r, _ := possibleToReconstructEquation(a.equation, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) >= len(prim.decompose.given) {
		revealed := p.arguments[prim.decompose.reveal]
		write := attackerStateWrite{
			known:     revealed,
			wire:      false,
			mutatedTo: []string{},
		}
		if attackerStatePutWrite(write) {
			prettyMessage(fmt.Sprintf(
				"%s obtained by decomposing %s with %s.",
				prettyValue(revealed), prettyPrimitive(p), prettyValues(has),
			), "deduction", true)
		}
		return true, revealed, has
	}
	return false, value{}, has
}

func possibleToRecomposePrimitive(
	p primitive, valPrincipalState principalState, valAttackerState attackerState,
) (bool, value, []value) {
	prim := primitiveGet(p.name)
	if !prim.recompose.hasRule {
		return false, value{}, []value{}
	}
	for _, i := range prim.recompose.given {
		ar := []value{}
		for _, ii := range i {
			for _, v := range valAttackerState.known {
				vb := v
				switch v.kind {
				case "constant":
					v = sanityResolveConstant(v.constant, valPrincipalState)
				}
				switch v.kind {
				case "primitive":
					equivPrim, vo, _ := sanityEquivalentPrimitives(v.primitive, p, valPrincipalState, false)
					if equivPrim && vo == ii {
						ar = append(ar, vb)
						if len(ar) >= len(i) {
							return true, p.arguments[prim.recompose.reveal], ar
						}
					}
				}
			}
		}
	}
	return false, value{}, []value{}
}

func possibleToReconstructPrimitive(
	p primitive, valPrincipalState principalState, valAttackerState attackerState,
) (bool, []value) {
	has := []value{}
	for _, a := range p.arguments {
		if sanityEquivalentValueInValues(a, valAttackerState.known, valPrincipalState) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.kind {
		case "primitive":
			r, _, _ := possibleToDecomposePrimitive(a.primitive, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
			r, _ = possibleToReconstructPrimitive(a.primitive, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		case "equation":
			r, _ := possibleToReconstructEquation(a.equation, valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) >= len(p.arguments) {
		vp := value{
			kind:      "primitive",
			primitive: p,
		}
		write := attackerStateWrite{
			known:     vp,
			wire:      false,
			mutatedTo: []string{},
		}
		if attackerStatePutWrite(write) {
			prettyMessage(fmt.Sprintf(
				"%s obtained by reconstructing with %s.",
				prettyValue(vp), prettyValues(has),
			), "deduction", true)
		}
		return true, has
	}
	return false, []value{}
}

func possibleToReconstructEquation(
	e equation, valPrincipalState principalState, valAttackerState attackerState,
) (bool, []value) {
	eValues := sanityDecomposeEquationValues(e, valPrincipalState)
	if len(eValues) > 2 {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, eValues[2].constant)
		if i < 0 {
			return false, []value{}
		}
		s0 := eValues[1]
		s1 := eValues[2]
		hs0 := sanityEquivalentValueInValues(s0, valAttackerState.known, valPrincipalState) >= 0
		hs1 := sanityEquivalentValueInValues(s1, valAttackerState.known, valPrincipalState) >= 0
		p0 := value{
			kind: "equation",
			equation: equation{
				values: []value{e.values[0], e.values[1]},
			},
		}
		p1 := value{
			kind: "equation",
			equation: equation{
				values: []value{e.values[0], e.values[2]},
			},
		}
		hp0 := sanityEquivalentValueInValues(p0, valAttackerState.known, valPrincipalState) >= 0
		hp1 := sanityEquivalentValueInValues(p1, valAttackerState.known, valPrincipalState) >= 0
		if hs0 && hs1 {
			return true, []value{s0, s1}
		}
		if hs0 && hp1 {
			return true, []value{s0, p1}
		}
		if hp0 && hs1 {
			return true, []value{p0, s1}
		}
	}
	if sanityEquivalentValueInValues(eValues[1], valAttackerState.known, valPrincipalState) >= 0 {
		return true, []value{eValues[1]}
	}
	return false, []value{}
}

func possibleToPassAssert(p primitive, valPrincipalState principalState) (bool, value) {
	if sanityEquivalentValues(p.arguments[0], p.arguments[1], valPrincipalState) {
		return true, value{kind: "primitive", primitive: p}
	}
	return false, value{kind: "primitive", primitive: p}
}

func possibleToRewrite(
	p primitive, valPrincipalState principalState,
) (bool, value) {
	if p.name == "ASSERT" {
		return possibleToPassAssert(p, valPrincipalState)
	}
	prim := primitiveGet(p.name)
	from := p.arguments[prim.rewrite.from]
	switch from.kind {
	case "primitive":
		if from.primitive.name != prim.rewrite.name {
			return (false || !prim.check), value{kind: "primitive", primitive: p}
		}
		for _, m := range prim.rewrite.matching {
			var valid bool
			ax := []value{p.arguments[m], from.primitive.arguments[m]}
			ax[0], valid = prim.rewrite.filter(ax[0], m, valPrincipalState)
			if !valid {
				return (false || !prim.check), value{kind: "primitive", primitive: p}
			}
			for i := range ax {
				switch ax[i].kind {
				case "primitive":
					r, v := possibleToRewrite(ax[i].primitive, valPrincipalState)
					if r {
						ax[i] = v
					}
				}
			}
			if !sanityEquivalentValues(ax[0], ax[1], valPrincipalState) {
				return (false || !prim.check), value{kind: "primitive", primitive: p}
			}
		}
		rewrite := value{kind: "primitive", primitive: p}
		if prim.rewrite.to > 0 {
			rewrite = from.primitive.arguments[prim.rewrite.to]
		}
		return true, rewrite
	}
	return (false || !prim.check), value{kind: "primitive", primitive: p}
}

func possibleToForceRewrite(p primitive, valPrincipalState principalState, valAttackerState attackerState) bool {
	switch p.name {
	case "DEC", "AEAD_DEC":
		return possibleToForceRewriteDECandAEADDEC(p, valPrincipalState, valAttackerState)
	case "SIGNVERIF":
		return possibleToForceRewriteSIGNVERIF(p, valPrincipalState, valAttackerState)
	}
	return false
}

func possibleToForceRewriteDECandAEADDEC(
	p primitive, valPrincipalState principalState, valAttackerState attackerState,
) bool {
	prim := primitiveGet(p.name)
	k := p.arguments[prim.decompose.given[0]]
	switch k.kind {
	case "primitive":
		r, v := possibleToRewrite(k.primitive, valPrincipalState)
		if r {
			k = v
		}
	}
	switch k.kind {
	case "constant":
		if sanityEquivalentValueInValues(k, valAttackerState.known, valPrincipalState) >= 0 {
			return true
		}
	case "primitive":
		r, _ := possibleToReconstructPrimitive(k.primitive, valPrincipalState, valAttackerState)
		if r {
			return true
		}
	case "equation":
		r, _ := possibleToReconstructEquation(k.equation, valPrincipalState, valAttackerState)
		if r {
			return true
		}
	}
	return false
}

func possibleToForceRewriteSIGNVERIF(
	p primitive, valPrincipalState principalState, valAttackerState attackerState,
) bool {
	k := p.arguments[0]
	switch k.kind {
	case "constant":
		return false
	case "primitive":
		return false
	case "equation":
		r, _ := possibleToReconstructEquation(k.equation, valPrincipalState, valAttackerState)
		if r {
			return true
		}
	}
	return false
}

func possibleToRebuild(p primitive, valPrincipalState principalState) (bool, value) {
	prim := primitiveGet(p.name)
	if !prim.rebuild.hasRule {
		return false, value{}
	}
	for _, g := range prim.rebuild.given {
		has := []value{}
	aLoop:
		for _, a := range p.arguments {
			switch a.kind {
			case "constant":
				continue aLoop
			case "primitive":
				if a.primitive.name == prim.rebuild.name {
					has = append(has, a)
				}
			case "equation":
				continue aLoop
			}
			if len(has) < len(g) {
				continue aLoop
			}
			for ai := 1; ai < len(has); ai++ {
				equivPrim, o1, o2 := sanityEquivalentPrimitives(
					has[0].primitive, has[ai].primitive,
					valPrincipalState, false,
				)
				if !equivPrim || (o1 == o2) {
					continue aLoop
				}
			}
			return true, has[0].primitive.arguments[prim.rebuild.reveal]
		}
	}
	return false, value{}
}

func possibleToObtainPasswords(a value, valPrincipalState principalState) []value {
	var passwords []value
	switch a.kind {
	case "constant":
		aa := sanityResolveConstant(a.constant, valPrincipalState)
		switch aa.kind {
		case "constant":
			if aa.constant.qualifier == "password" {
				passwords = append(passwords, aa)
			}
		}
	case "primitive":
		prim := primitiveGet(a.primitive.name)
		if prim.passwordHashing {
			return passwords
		}
		for _, aa := range a.primitive.arguments {
			passwords = append(passwords, possibleToObtainPasswords(aa, valPrincipalState)...)
		}
	case "equation":
		e := sanityDecomposeEquationValues(a.equation, valPrincipalState)
		for _, ee := range e {
			passwords = append(passwords, possibleToObtainPasswords(ee, valPrincipalState)...)
		}
	}
	return passwords
}
