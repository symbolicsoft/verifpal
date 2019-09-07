/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

// bba897c5cdfd22cdbe7a6c25141b97b2

package main

import (
	"fmt"
)

func possibleToDeconstructPrimitive(p primitive, valAttackerState *attackerState, valPrincipalState *principalState, analysis int, depth int) (bool, value, []value) {
	has := []value{}
	primitive := primitiveGet(p.name)
	pp, _ := sanityResolveInternalValues(value{
		kind:      "primitive",
		primitive: p,
	}, valPrincipalState, false)
	p = pp.primitive
	if !primitive.decompose.hasRule {
		return false, value{}, has
	}
	for _, g := range primitive.decompose.given {
		a := p.arguments[g]
		i := sanityValueInValues(a, &valAttackerState.known, valPrincipalState)
		if i >= 0 {
			has = append(has, a)
			continue
		}
		switch a.kind {
		case "constant":
			a = sanityResolveConstant(valPrincipalState, a.constant, false)
		}
		switch a.kind {
		case "primitive":
			r, _ := possibleToReconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
			if r {
				has = append(has, a)
				continue
			}
			r, _, _ = possibleToDeconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
			if r {
				has = append(has, a)
				continue
			}
		case "equation":
			r, _ := possibleToReconstructEquation(a.equation, valAttackerState, valPrincipalState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) >= len(primitive.decompose.given) {
		revealed := p.arguments[primitive.decompose.reveal]
		v := value{
			kind:      "primitive",
			primitive: p,
		}
		if sanityExactSameValueInValues(v, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(revealed, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s now conceivable by deconstructing %s with %s",
					prettyValue(revealed), prettyPrimitive(p), prettyValues(has),
				), analysis, depth, "analysis")
				valAttackerState.conceivable = append(valAttackerState.conceivable, v)
			}
			valAttackerState.known = append(valAttackerState.known, v)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
		return true, revealed, has
	}
	return false, value{}, has
}

func possibleToReconstructPrimitive(p primitive, valAttackerState *attackerState, valPrincipalState *principalState, analysis int, depth int) (bool, []value) {
	pp, _ := sanityResolveInternalValues(value{
		kind:      "primitive",
		primitive: p,
	}, valPrincipalState, false)
	p = pp.primitive
	d, _, has := possibleToDeconstructPrimitive(p, valAttackerState, valPrincipalState, analysis, depth)
	if d {
		return true, has
	}
	for _, a := range p.arguments {
		if sanityValueInValues(a, &valAttackerState.known, valPrincipalState) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.kind {
		case "constant":
			a = sanityResolveConstant(valPrincipalState, a.constant, false)
		}
		switch a.kind {
		case "primitive":
			r, _, _ := possibleToDeconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
			if r {
				has = append(has, a)
				continue
			}
			r, _ = possibleToReconstructPrimitive(a.primitive, valAttackerState, valPrincipalState, analysis, depth)
			if r {
				has = append(has, a)
				continue
			}
		case "equation":
			r, _ := possibleToReconstructEquation(a.equation, valAttackerState, valPrincipalState)
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
		if sanityExactSameValueInValues(vp, &valAttackerState.known) < 0 {
			if sanityExactSameValueInValues(vp, &valAttackerState.conceivable) < 0 {
				prettyMessage(fmt.Sprintf(
					"%s now conceivable by reconstructing with %s",
					prettyPrimitive(p), prettyValues(has),
				), analysis, depth, "analysis")
				valAttackerState.conceivable = append(valAttackerState.conceivable, vp)
			}
			valAttackerState.known = append(valAttackerState.known, vp)
			valAttackerState.mutatedTo = append(valAttackerState.mutatedTo, []string{})
		}
		return true, has
	}
	return false, []value{}
}

func possibleToReconstructEquation(e equation, valAttackerState *attackerState, valPrincipalState *principalState) (bool, []value) {
	eValues := sanityDeconstructEquationValues(e, valPrincipalState)
	if len(eValues) > 2 {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, eValues[2].constant)
		if i >= 0 {
			s0 := sanityResolveConstant(valPrincipalState, eValues[1].constant, false)
			s1 := sanityResolveConstant(valPrincipalState, eValues[2].constant, false)
			hs0 := sanityValueInValues(s0, &valAttackerState.known, valPrincipalState) >= 0
			hs1 := sanityValueInValues(s1, &valAttackerState.known, valPrincipalState) >= 0
			p0 := value{
				kind: "equation",
				equation: equation{
					constants: []constant{e.constants[0], e.constants[1]},
				},
			}
			p1 := value{
				kind: "equation",
				equation: equation{
					constants: []constant{e.constants[0], e.constants[2]},
				},
			}
			hp0 := sanityValueInValues(p0, &valAttackerState.known, valPrincipalState) >= 0
			hp1 := sanityValueInValues(p1, &valAttackerState.known, valPrincipalState) >= 0
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
		return false, []value{}
	}
	if sanityValueInValues(eValues[1], &valAttackerState.known, valPrincipalState) < 0 {
		return true, []value{eValues[1]}
	}
	return false, []value{}
}

func possibleToPrimitivePassRewrite(p primitive, valPrincipalState *principalState) (bool, value) {
	prim := primitiveGet(p.name)
	from := p.arguments[prim.rewrite.from]
	fromCreator := valPrincipalState.name
	switch from.kind {
	case "constant":
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, from.constant)
		fromCreator = valPrincipalState.creator[i]
		from = sanityResolveConstant(valPrincipalState, from.constant, false)
	}
	switch from.kind {
	case "constant":
		return false, value{}
	case "primitive":
		if p.name == "HMACVERIF" {
			if sanityEquivalentValues(p.arguments[0], p.arguments[1], false, false, valPrincipalState) {
				return true, p.arguments[0]
			}
			return false, value{}
		}
		if from.primitive.name != prim.rewrite.name {
			return false, value{}
		}
		for _, m := range prim.rewrite.matching {
			x := p.arguments[m]
			switch x.kind {
			case "constant":
				x = sanityResolveConstant(valPrincipalState, x.constant, false)
			}
			x, valid := prim.rewrite.filter(x, m, valPrincipalState)
			if !valid {
				return false, value{}
			}
			var a1 value
			var a2 value
			switch x.kind {
			case "constant":
				a1 = sanityResolveConstant(valPrincipalState, x.constant, false)
			case "primitive":
				a1 = x
			case "equation":
				a1 = x
			}
			switch from.primitive.arguments[m].kind {
			case "constant":
				a2 = sanityResolveConstant(valPrincipalState, from.primitive.arguments[m].constant, true)
			case "primitive":
				a2 = from.primitive.arguments[m]
			case "equation":
				a2 = from.primitive.arguments[m]
			}
			a1, _ = sanityResolveInternalValues(a1, valPrincipalState, false)
			a2, _ = sanityResolveInternalValues(a2, valPrincipalState, (fromCreator != valPrincipalState.name))
			if !sanityEquivalentValues(a1, a2, false, (fromCreator != valPrincipalState.name), valPrincipalState) {
				return false, value{}
			}
		}
	case "equation":
		return false, value{}
	}
	rewrite := from.primitive.arguments[prim.rewrite.to]
	switch rewrite.kind {
	case "constant":
		rewrite = sanityResolveConstant(valPrincipalState, rewrite.constant, false)
	}
	return true, rewrite
}

func possibleToPrimitiveForcePassRewrite(p primitive, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) bool {
	prim := primitiveGet(p.name)
	switch p.name {
	case "AEAD_DEC":
		k := p.arguments[prim.decompose.given[0]]
		switch k.kind {
		case "constant":
			k = sanityResolveConstant(valPrincipalState, k.constant, false)
		}
		switch k.kind {
		case "constant":
			if sanityValueInValues(k, &valAttackerState.known, valPrincipalState) >= 0 {
				return true
			}
		case "primitive":
			r, _ := possibleToReconstructPrimitive(k.primitive, valAttackerState, valPrincipalState, analysis, depth)
			if r {
				return true
			}
		case "equation":
			r, _ := possibleToReconstructEquation(k.equation, valAttackerState, valPrincipalState)
			if r {
				return true
			}
		}
	case "SIGNVERIF":
		k := p.arguments[prim.rewrite.from]
		switch k.kind {
		case "constant":
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)
			differentCreator := valPrincipalState.creator[i] != valPrincipalState.name
			k = sanityResolveConstant(valPrincipalState, k.constant, differentCreator)
		}
		switch k.kind {
		case "constant":
			return false
		case "primitive":
			if k.primitive.name != "SIGN" {
				return false
			}
			if sanityValueInValues(k.primitive.arguments[0], &valAttackerState.known, valPrincipalState) >= 0 {
				return true
			}
			return false
		case "equation":
			return false
		}
	case "HMACVERIF":
		for ii, k := range p.arguments {
			iii := 0
			if ii == 0 {
				iii = 1
			}
			switch k.kind {
			case "constant":
				k = sanityResolveConstant(valPrincipalState, k.constant, false)
			}
			switch k.kind {
			case "constant":
				if sanityValueInValues(k, &valAttackerState.known, valPrincipalState) >= 0 {
					if sanityEquivalentValues(k, p.arguments[iii], false, false, valPrincipalState) {
						return true
					}
				}
			case "primitive":
				r, _ := possibleToReconstructPrimitive(k.primitive, valAttackerState, valPrincipalState, analysis, depth)
				if r {
					if sanityEquivalentValues(k, p.arguments[iii], false, false, valPrincipalState) {
						return true
					}
				}
			case "equation":
				r, _ := possibleToReconstructEquation(k.equation, valAttackerState, valPrincipalState)
				if r {
					if sanityEquivalentValues(k, p.arguments[iii], false, false, valPrincipalState) {
						return true
					}
				}
			}
		}

	}
	return false
}
