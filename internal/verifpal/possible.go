/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bba897c5cdfd22cdbe7a6c25141b97b2

package verifpal

import "fmt"

func possibleToDecomposePrimitive(
	p primitive, valAttackerState attackerState,
) (bool, value, []value) {
	has := []value{}
	prim := primitiveGet(p.name)
	if !prim.decompose.hasRule {
		return false, value{}, has
	}
	for i, g := range prim.decompose.given {
		a := p.arguments[g]
		a, valid := prim.decompose.filter(a, i)
		ii := sanityEquivalentValueInValues(a, valAttackerState.known)
		if valid && ii >= 0 {
			has = append(has, a)
			continue
		}
	}
	if len(has) >= len(prim.decompose.given) {
		revealed := p.arguments[prim.decompose.reveal]
		if attackerStatePutWrite(revealed) {
			PrettyMessage(fmt.Sprintf(
				"%s obtained by decomposing %s with %s.",
				prettyValue(revealed), prettyPrimitive(p), prettyValues(has),
			), "deduction", true)
		}
		return true, revealed, has
	}
	return false, value{}, has
}

func possibleToRecomposePrimitive(
	p primitive, valAttackerState attackerState,
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
				case "primitive":
					equivPrim, vo, _ := sanityEquivalentPrimitives(
						v.primitive, p, false,
					)
					if !equivPrim || vo != ii {
						continue
					}
					ar = append(ar, vb)
					if len(ar) < len(i) {
						continue
					}
					return true, p.arguments[prim.recompose.reveal], ar
				}
			}
		}
	}
	return false, value{}, []value{}
}

func possibleToReconstructPrimitive(
	p primitive, valAttackerState attackerState,
) (bool, []value) {
	has := []value{}
	for _, a := range p.arguments {
		if sanityEquivalentValueInValues(a, valAttackerState.known) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.kind {
		case "primitive":
			r, _, _ := possibleToDecomposePrimitive(a.primitive, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
			r, _ = possibleToReconstructPrimitive(a.primitive, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		case "equation":
			r, _ := possibleToReconstructEquation(a.equation, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) < len(p.arguments) {
		return false, []value{}
	}
	revealed := value{
		kind:      "primitive",
		primitive: p,
	}
	if attackerStatePutWrite(revealed) {
		PrettyMessage(fmt.Sprintf(
			"%s obtained by reconstructing with %s.",
			prettyValue(revealed), prettyValues(has),
		), "deduction", true)
	}
	return true, has
}

func possibleToReconstructEquation(
	e equation, valAttackerState attackerState,
) (bool, []value) {
	if len(e.values) > 2 {
		s0 := e.values[1]
		s1 := e.values[2]
		hs0 := sanityEquivalentValueInValues(s0, valAttackerState.known) >= 0
		hs1 := sanityEquivalentValueInValues(s1, valAttackerState.known) >= 0
		if hs0 && hs1 {
			return true, []value{s0, s1}
		}
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
		hp0 := sanityEquivalentValueInValues(p0, valAttackerState.known) >= 0
		hp1 := sanityEquivalentValueInValues(p1, valAttackerState.known) >= 0
		if hs0 && hp1 {
			return true, []value{s0, p1}
		}
		if hp0 && hs1 {
			return true, []value{p0, s1}
		}
	}
	if sanityEquivalentValueInValues(e.values[1], valAttackerState.known) >= 0 {
		return true, []value{e.values[1]}
	}
	return false, []value{}
}

func possibleToPassAssert(p primitive) (bool, value) {
	if sanityEquivalentValues(p.arguments[0], p.arguments[1]) {
		return true, value{kind: "primitive", primitive: p}
	}
	return false, value{kind: "primitive", primitive: p}
}

func possibleToRewrite(
	p primitive, valPrincipalState principalState,
) (bool, value) {
	if p.name == "ASSERT" {
		return possibleToPassAssert(p)
	}
	prim := primitiveGet(p.name)
	from := p.arguments[prim.rewrite.from]
	switch from.kind {
	case "primitive":
		if from.primitive.name != prim.rewrite.name {
			return (false || !prim.check), value{kind: "primitive", primitive: p}
		}
		if !possibleToRewritePrim(p, valPrincipalState) {
			return (false || !prim.check), value{kind: "primitive", primitive: p}
		}
		rewrite := value{kind: "primitive", primitive: p}
		if prim.rewrite.to > 0 {
			rewrite = from.primitive.arguments[prim.rewrite.to]
		}
		return true, rewrite
	}
	return (false || !prim.check), value{kind: "primitive", primitive: p}
}

func possibleToRewritePrim(
	p primitive, valPrincipalState principalState,
) bool {
	prim := primitiveGet(p.name)
	from := p.arguments[prim.rewrite.from]
	for a, m := range prim.rewrite.matching {
		valid := false
		for _, mm := range m {
			ax := []value{p.arguments[a], from.primitive.arguments[mm]}
			ax[0], valid = prim.rewrite.filter(ax[0], mm)
			if !valid {
				continue
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
			valid = sanityEquivalentValues(ax[0], ax[1])
			if valid {
				break
			}
		}
		if !valid {
			return false
		}
	}
	return true
}

func possibleToRebuild(p primitive) (bool, value) {
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
					has[0].primitive, has[ai].primitive, false,
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

func possibleToObtainPasswords(
	a value, valPrincipalState principalState,
) []value {
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
			passwords = append(passwords,
				possibleToObtainPasswords(aa, valPrincipalState)...,
			)
		}
	case "equation":
		for _, aa := range a.equation.values {
			passwords = append(passwords,
				possibleToObtainPasswords(aa, valPrincipalState)...,
			)
		}
	}
	return passwords
}
