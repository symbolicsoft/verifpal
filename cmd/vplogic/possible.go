/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// bba897c5cdfd22cdbe7a6c25141b97b2

package vplogic

const maxPossibleDepth = 16

func possibleToPassivelyDecomposePrimitive(p *Primitive) []*Value {
	revealed := []*Value{}
	if primitiveIsCorePrimitive(p.ID) {
		return revealed
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Decompose.HasRule {
		return revealed
	}
	for _, i := range prim.Decompose.PassiveReveal {
		revealed = append(revealed, p.Arguments[i])
	}
	return revealed
}

func possibleToDecomposePrimitive(
	p *Primitive, valPrincipalState *PrincipalState, valAttackerState AttackerState,
	depth int,
) (bool, *Value, []*Value) {
	if depth > maxPossibleDepth {
		return false, &Value{}, nil
	}
	if primitiveIsCorePrimitive(p.ID) {
		return false, &Value{}, nil
	}
	prim, _ := primitiveGet(p.ID)
	if !prim.Decompose.HasRule {
		return false, &Value{}, nil
	}
	has := make([]*Value, 0, len(prim.Decompose.Given))
	for i, idx := range prim.Decompose.Given {
		a := p.Arguments[idx]
		a, valid := prim.Decompose.Filter(p, a, i)
		if !valid {
			continue
		}
		if valueEquivalentValueInValuesMap(a, valAttackerState.Known, valAttackerState.KnownMap) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.Kind {
		case typesEnumPrimitive:
			if r, _ := possibleToReconstructPrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState, depth+1); r {
				has = append(has, a)
				continue
			}
			if r, _, _ := possibleToDecomposePrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState, depth+1); r {
				has = append(has, a)
			}
		case typesEnumEquation:
			if r, _ := possibleToReconstructEquation(a.Data.(*Equation), valAttackerState); r {
				has = append(has, a)
			}
		}
	}
	if len(has) >= len(prim.Decompose.Given) {
		return true, p.Arguments[prim.Decompose.Reveal], has
	}
	return false, &Value{}, has
}

func possibleToRecomposePrimitive(
	p *Primitive, valAttackerState AttackerState,
) (bool, *Value, []*Value) {
	if primitiveIsCorePrimitive(p.ID) {
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
	depth int,
) (bool, []*Value) {
	if depth > maxPossibleDepth {
		return false, []*Value{}
	}
	has := []*Value{}
	r, rv := possibleToRewrite(p, valPrincipalState, 0)
	if !r {
		return false, []*Value{}
	}
	rp := rv[0].Data.(*Primitive)
	for _, a := range rp.Arguments {
		if valueEquivalentValueInValuesMap(a, valAttackerState.Known, valAttackerState.KnownMap) >= 0 {
			has = append(has, a)
			continue
		}
		switch a.Kind {
		case typesEnumPrimitive:
			r, _, _ = possibleToDecomposePrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState, depth+1)
			if r {
				has = append(has, a)
				continue
			}
			r, _ = possibleToReconstructPrimitive(a.Data.(*Primitive), valPrincipalState, valAttackerState, depth+1)
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
	if len(has) < len(rp.Arguments) {
		return false, []*Value{}
	}
	return true, has
}

func possibleToReconstructEquation(e *Equation, valAttackerState AttackerState) (bool, []*Value) {
	if len(e.Values) < 2 {
		return false, []*Value{}
	}
	if len(e.Values) == 2 {
		if valueEquivalentValueInValuesMap(e.Values[1], valAttackerState.Known, valAttackerState.KnownMap) >= 0 {
			return true, []*Value{e.Values[1]}
		}
		return false, []*Value{}
	}
	s0 := e.Values[1]
	s1 := e.Values[2]
	hs0 := valueEquivalentValueInValuesMap(s0, valAttackerState.Known, valAttackerState.KnownMap) >= 0
	hs1 := valueEquivalentValueInValuesMap(s1, valAttackerState.Known, valAttackerState.KnownMap) >= 0
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
	hp1 := valueEquivalentValueInValuesMap(p1, valAttackerState.Known, valAttackerState.KnownMap) >= 0
	if hs0 && hp1 {
		return true, []*Value{s0, p1}
	}
	hp0 := valueEquivalentValueInValuesMap(p0, valAttackerState.Known, valAttackerState.KnownMap) >= 0
	if hp0 && hs1 {
		return true, []*Value{p0, s1}
	}
	return false, []*Value{}
}

func possibleToRewrite(
	p *Primitive, valPrincipalState *PrincipalState, depth int,
) (bool, []*Value) {
	v := []*Value{{Kind: typesEnumPrimitive, Data: p}}
	if depth > maxPossibleDepth {
		return false, v
	}
	// Create a shallow copy so we don't mutate the shared original.
	pc := *p
	args := make([]*Value, len(pc.Arguments))
	copy(args, pc.Arguments)
	pc.Arguments = args
	for i, a := range pc.Arguments {
		switch a.Kind {
		case typesEnumPrimitive:
			_, pp := possibleToRewrite(a.Data.(*Primitive), valPrincipalState, depth+1)
			pc.Arguments[i] = pp[0]
		}
	}
	v = []*Value{{Kind: typesEnumPrimitive, Data: &pc}}
	if primitiveIsCorePrimitive(pc.ID) {
		prim, _ := primitiveCoreGet(pc.ID)
		if prim.HasRule {
			return prim.CoreRule(&pc)
		}
		return !prim.Check, v
	}
	prim, _ := primitiveGet(pc.ID)
	if !prim.Rewrite.HasRule {
		return true, v
	}
	from := pc.Arguments[prim.Rewrite.From]
	switch from.Kind {
	case typesEnumPrimitive:
		if from.Data.(*Primitive).ID != prim.Rewrite.ID {
			return !prim.Check, v
		}
		if !possibleToRewritePrimitive(&pc, valPrincipalState, depth) {
			return !prim.Check, v
		}
		rewrite := prim.Rewrite.To(from.Data.(*Primitive))
		return true, []*Value{rewrite}
	}
	return !prim.Check, v
}

func possibleToRewritePrimitive(
	p *Primitive, valPrincipalState *PrincipalState, depth int,
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
			for i, axElem := range ax {
				switch axElem.Kind {
				case typesEnumPrimitive:
					r, v := possibleToRewrite(axElem.Data.(*Primitive), valPrincipalState, depth+1)
					if r {
						ax[i] = v[0]
					}
				case typesEnumEquation:
					for ii, a := range axElem.Data.(*Equation).Values {
						switch a.Kind {
						case typesEnumPrimitive:
							r, v := possibleToRewrite(a.Data.(*Primitive), valPrincipalState, depth+1)
							if r {
								ax[i].Data.(*Equation).Values[ii] = v[0]
							}
						}
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
	if primitiveIsCorePrimitive(p.ID) {
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
	var passwords []*Value
	switch a.Kind {
	case typesEnumConstant:
		aa, _ := valueResolveConstant(a.Data.(*Constant), valPrincipalState, true)
		if aa.Kind == typesEnumConstant && aa.Data.(*Constant).Qualifier == typesEnumPassword {
			if aIndex >= 0 && aParent.Kind == typesEnumPrimitive {
				if !primitiveIsCorePrimitive(aParent.Data.(*Primitive).ID) {
					prim, _ := primitiveGet(aParent.Data.(*Primitive).ID)
					if intInSlice(aIndex, prim.PasswordHashing) {
						return passwords
					}
				}
			}
			passwords = append(passwords, aa)
		}
	case typesEnumPrimitive:
		p := a.Data.(*Primitive)
		parent := aParent
		if !primitiveIsCorePrimitive(p.ID) {
			prim, _ := primitiveGet(p.ID)
			if intInSlice(aIndex, prim.PasswordHashing) {
				parent = a
			}
		}
		for i, arg := range p.Arguments {
			passwords = append(passwords,
				possibleToObtainPasswords(arg, parent, i, valPrincipalState)...,
			)
		}
	case typesEnumEquation:
		for _, v := range a.Data.(*Equation).Values {
			passwords = append(passwords,
				possibleToObtainPasswords(v, a, -1, valPrincipalState)...,
			)
		}
	}
	return passwords
}
