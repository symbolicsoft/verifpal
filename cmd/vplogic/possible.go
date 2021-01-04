/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bba897c5cdfd22cdbe7a6c25141b97b2

package vplogic

func possibleToDecomposePrimitive(
	p *Primitive, valPrincipalState *PrincipalState, valAttackerState AttackerState,
) (bool, *Value, []*Value) {
	has := []*Value{}
	if primitiveIsCorePrim(p.ID) {
		return false, &Value{}, has
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Decompose.HasRule {
		return false, &Value{}, has
	}
	for i, g := range prim.Decompose.Given {
		a := p.Arguments[g]
		a, valid := prim.Decompose.Filter(p, a, i)
		if !valid {
			continue
		}
		ii := valueEquivalentValueInValues(a, valAttackerState.Known)
		if ii >= 0 {
			has = append(has, a)
			continue
		}
		switch a.Kind {
		case typesEnumPrimitive:
			r, _ := possibleToReconstructPrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
			r, _, _ = possibleToDecomposePrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		case typesEnumEquation:
			r, _ := possibleToReconstructEquation(a.Data.(*Equation), valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) >= len(prim.Decompose.Given) {
		revealed := p.Arguments[prim.Decompose.Reveal]
		return true, revealed, has
	}
	return false, &Value{}, has
}

func possibleToRecomposePrimitive(
	p *Primitive, valAttackerState AttackerState,
) (bool, *Value, []*Value) {
	if primitiveIsCorePrim(p.ID) {
		return false, &Value{}, []*Value{}
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Recompose.HasRule {
		return false, &Value{}, []*Value{}
	}
	for _, i := range prim.Recompose.Given {
		ar := []*Value{}
		for _, ii := range i {
			for _, v := range valAttackerState.Known {
				vb := v
				switch v.Kind {
				case typesEnumPrimitive:
					equivPrim, vo, _ := valueEquivalentPrimitives(
						v.Data.(*Primitive), p, false,
					)
					if !equivPrim || vo != ii {
						continue
					}
					ar = append(ar, vb)
					if len(ar) < len(i) {
						continue
					}
					return true, p.Arguments[prim.Recompose.Reveal], ar
				}
			}
		}
	}
	return false, &Value{}, []*Value{}
}

func possibleToReconstructPrimitive(
	p *Primitive, valPrincipalState *PrincipalState, valAttackerState AttackerState,
) (bool, []*Value) {
	has := []*Value{}
	r, _ := possibleToRewrite(p, valPrincipalState)
	if !r {
		return false, []*Value{}
	}
	for _, a := range p.Arguments {
		if valueEquivalentValueInValues(a, valAttackerState.Known) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.Kind {
		case typesEnumPrimitive:
			r, _, _ = possibleToDecomposePrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
			r, _ = possibleToReconstructPrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		case typesEnumEquation:
			r, _ := possibleToReconstructEquation(a.Data.(*Equation), valAttackerState)
			if r {
				has = append(has, a)
				continue
			}
		}
	}
	if len(has) < len(p.Arguments) {
		return false, []*Value{}
	}
	return true, has
}

func possibleToReconstructEquation(e *Equation, valAttackerState AttackerState) (bool, []*Value) {
	if len(e.Values) <= 2 {
		if valueEquivalentValueInValues(e.Values[1], valAttackerState.Known) >= 0 {
			return true, []*Value{e.Values[1]}
		}
		return false, []*Value{}
	}
	s0 := e.Values[1]
	s1 := e.Values[2]
	hs0 := valueEquivalentValueInValues(s0, valAttackerState.Known) >= 0
	hs1 := valueEquivalentValueInValues(s1, valAttackerState.Known) >= 0
	if hs0 && hs1 {
		return true, []*Value{s0, s1}
	}
	p0 := &Value{
		Kind: typesEnumEquation,
		Data: &Equation{
			Values: []*Value{e.Values[0], e.Values[1]},
		},
	}
	p1 := &Value{
		Kind: typesEnumEquation,
		Data: &Equation{
			Values: []*Value{e.Values[0], e.Values[2]},
		},
	}
	hp1 := valueEquivalentValueInValues(p1, valAttackerState.Known) >= 0
	if hs0 && hp1 {
		return true, []*Value{s0, p1}
	}
	hp0 := valueEquivalentValueInValues(p0, valAttackerState.Known) >= 0
	if hp0 && hs1 {
		return true, []*Value{p0, s1}
	}
	return false, []*Value{}
}

func possibleToRewrite(
	p *Primitive, valPrincipalState *PrincipalState,
) (bool, []*Value) {
	v := []*Value{{Kind: typesEnumPrimitive, Data: p}}
	for i, a := range p.Arguments {
		switch a.Kind {
		case typesEnumPrimitive:
			_, pp := possibleToRewrite(a.Data.(*Primitive), valPrincipalState)
			p.Arguments[i] = pp[0]
		}
	}
	if primitiveIsCorePrim(p.ID) {
		prim, _ := primitiveCoreGet(p.ID)
		if prim.HasRule {
			return prim.CoreRule(p)
		}
		return !prim.Check, v
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Rewrite.HasRule {
		return true, v
	}
	from := p.Arguments[prim.Rewrite.From]
	switch from.Kind {
	case typesEnumPrimitive:
		if from.Data.(*Primitive).ID != prim.Rewrite.ID {
			return !prim.Check, v
		}
		if !possibleToRewritePrim(p, valPrincipalState) {
			return !prim.Check, v
		}
		rewrite := prim.Rewrite.To(from.Data.(*Primitive))
		return true, []*Value{rewrite}
	}
	return !prim.Check, v
}

func possibleToRewritePrim(
	p *Primitive, valPrincipalState *PrincipalState,
) bool {
	prim, _ := primitiveGet(p.ID)
	from := p.Arguments[prim.Rewrite.From]
	for a, m := range prim.Rewrite.Matching {
		valid := false
		for _, mm := range m {
			ax := []*Value{p.Arguments[a], from.Data.(*Primitive).Arguments[mm]}
			ax[0], valid = prim.Rewrite.Filter(p, ax[0], mm)
			if !valid {
				continue
			}
			for i := range ax {
				switch ax[i].Kind {
				case typesEnumPrimitive:
					r, v := possibleToRewrite(ax[i].Data.(*Primitive), valPrincipalState)
					if r {
						ax[i] = v[0]
					}
				}
			}
			valid = valueEquivalentValues(ax[0], ax[1], true)
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

func possibleToRebuild(p *Primitive) (bool, *Value) {
	if primitiveIsCorePrim(p.ID) {
		return false, &Value{}
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Rebuild.HasRule {
		return false, &Value{}
	}
	for _, g := range prim.Rebuild.Given {
		has := []*Value{}
	ggLoop:
		for _, gg := range g {
			if len(p.Arguments) <= gg {
				continue ggLoop
			}
			switch p.Arguments[gg].Kind {
			case typesEnumPrimitive:
				if p.Arguments[gg].Data.(*Primitive).ID == prim.Rebuild.ID {
					has = append(has, p.Arguments[gg])
				}
			}
			if len(has) < len(g) {
				continue ggLoop
			}
			for hasP := 1; hasP < len(has); hasP++ {
				equivPrim, o1, o2 := valueEquivalentPrimitives(
					has[0].Data.(*Primitive), has[hasP].Data.(*Primitive), false,
				)
				if !equivPrim || (o1 == o2) {
					continue ggLoop
				}
			}
			if len(has) == len(g) {
				return true, has[0].Data.(*Primitive).Arguments[prim.Rebuild.Reveal]
			}
		}
	}
	return false, &Value{}
}

func possibleToObtainPasswords(
	a *Value, aParent *Value, aIndex int, valPrincipalState *PrincipalState,
) []*Value {
	passwords := []*Value{}
	switch a.Kind {
	case typesEnumConstant:
		aa, _ := valueResolveConstant(a.Data.(*Constant), valPrincipalState)
		switch aa.Kind {
		case typesEnumConstant:
			if aa.Data.(*Constant).Qualifier == typesEnumPassword {
				if aIndex >= 0 {
					if !primitiveIsCorePrim(aParent.Data.(*Primitive).ID) {
						prim, _ := primitiveGet(aParent.Data.(*Primitive).ID)
						if intInSlice(aIndex, prim.PasswordHashing) {
							return passwords
						}
					}
				}
				passwords = append(passwords, aa)
			}
		}
	case typesEnumPrimitive:
		for i := 0; i < len(a.Data.(*Primitive).Arguments); i++ {
			if !primitiveIsCorePrim(a.Data.(*Primitive).ID) {
				prim, _ := primitiveGet(a.Data.(*Primitive).ID)
				if intInSlice(aIndex, prim.PasswordHashing) {
					aParent = a
				}
			}
			passwords = append(passwords,
				possibleToObtainPasswords(a.Data.(*Primitive).Arguments[i], aParent, i, valPrincipalState)...,
			)
		}
	case typesEnumEquation:
		for i := 0; i < len(a.Data.(*Equation).Values); i++ {
			passwords = append(passwords,
				possibleToObtainPasswords(a.Data.(*Equation).Values[i], a, -1, valPrincipalState)...,
			)
		}
	}
	return passwords
}
