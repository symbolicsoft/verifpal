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
	}, valPrincipalState)
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
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
			if valPrincipalState.assigned[i].kind != "constant" {
				a = valPrincipalState.assigned[i]
			}
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
	}, valPrincipalState)
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
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, a.constant)
			if valPrincipalState.assigned[i].kind != "constant" {
				a = valPrincipalState.assigned[i]
			}
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
	if eValues[0].kind == "equation" {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, eValues[1].constant)
		if i >= 0 {
			ii := sanityValueInValues(valPrincipalState.assigned[i], &valAttackerState.known, valPrincipalState)
			if ii >= 0 {
				return true, []value{valPrincipalState.assigned[i]}
			}
			iii := sanityValueInValues(value{kind: "constant", constant: eValues[0].equation.constants[1]}, &valAttackerState.known, valPrincipalState)
			if iii >= 0 {
				return true, []value{eValues[0]}
			}
			if valPrincipalState.assigned[i].kind == "equation" {
				return possibleToReconstructEquation(valPrincipalState.assigned[i].equation, valAttackerState, valPrincipalState)
			}
		}
	}
	if sanityValueInValues(eValues[0], &valAttackerState.known, valPrincipalState) < 0 {
		return false, []value{}
	}
	if sanityValueInValues(eValues[1], &valAttackerState.known, valPrincipalState) < 0 {
		return false, []value{}
	}
	return true, []value{}
}

func possibleToPrimitivePassRewrite(p primitive, valPrincipalState *principalState) (bool, value) {
	prim := primitiveGet(p.name)
	from := p.arguments[prim.rewrite.from]
	switch from.kind {
	case "constant":
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, from.constant)
		from = valPrincipalState.assigned[i]
	}
	switch from.kind {
	case "constant":
		return false, value{}
	case "primitive":
		if p.name == "HMACVERIF" {
			if sanityEquivalentValues(p.arguments[0], p.arguments[1], valPrincipalState) {
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
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, x.constant)
				x = valPrincipalState.assigned[i]
			}
			x, valid := prim.rewrite.filter(x, m, valPrincipalState)
			if !valid {
				return false, value{}
			}
			var a1 value
			var a2 value
			switch x.kind {
			case "constant":
				i1 := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, x.constant)
				a1 = valPrincipalState.assigned[i1]
			case "primitive":
				a1 = x
			case "equation":
				a1 = x
			}
			switch from.primitive.arguments[m].kind {
			case "constant":
				i2 := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, from.primitive.arguments[m].constant)
				a2 = valPrincipalState.assigned[i2]
			case "primitive":
				a2 = from.primitive.arguments[m]
			case "equation":
				a2 = from.primitive.arguments[m]
			}
			if !sanityEquivalentValues(a1, a2, valPrincipalState) {
				return false, value{}
			}
		}
	case "equation":
		return false, value{}
	}
	rewrite := from.primitive.arguments[prim.rewrite.to]
	switch rewrite.kind {
	case "constant":
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, rewrite.constant)
		rewrite = valPrincipalState.assigned[i]
	}
	return true, rewrite
}

func possibleToPrimitiveForcePassRewrite(p primitive, valPrincipalState *principalState, valAttackerState *attackerState, analysis int, depth int) bool {
	switch p.name {
	case "AEAD_DEC":
		k := p.arguments[0]
		switch k.kind {
		case "constant":
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)
			k = valPrincipalState.assigned[i]
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
		k := p.arguments[0]
		switch k.kind {
		case "constant":
			i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)
			k = valPrincipalState.assigned[i]
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
	case "HMACVERIF":
		for ii, k := range p.arguments {
			iii := 0
			if ii == 0 {
				iii = 1
			}
			switch k.kind {
			case "constant":
				i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, k.constant)
				k = valPrincipalState.assigned[i]
			}
			switch k.kind {
			case "constant":
				if sanityValueInValues(k, &valAttackerState.known, valPrincipalState) >= 0 {
					if sanityEquivalentValues(k, p.arguments[iii], valPrincipalState) {
						return true
					}
				}
			case "primitive":
				r, _ := possibleToReconstructPrimitive(k.primitive, valAttackerState, valPrincipalState, analysis, depth)
				if r {
					if sanityEquivalentValues(k, p.arguments[iii], valPrincipalState) {
						return true
					}
				}
			case "equation":
				r, _ := possibleToReconstructEquation(k.equation, valAttackerState, valPrincipalState)
				if r {
					if sanityEquivalentValues(k, p.arguments[iii], valPrincipalState) {
						return true
					}
				}
			}
		}

	}
	return false
}
