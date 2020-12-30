/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 5e88e17b2b330ef227c81153d720b176

package vplogic

import (
	"fmt"
)

type primitiveEnum uint8

const (
	primitiveEnumEmpty         primitiveEnum = iota
	primitiveEnumASSERT        primitiveEnum = iota
	primitiveEnumCONCAT        primitiveEnum = iota
	primitiveEnumSPLIT         primitiveEnum = iota
	primitiveEnumPWHASH        primitiveEnum = iota
	primitiveEnumHASH          primitiveEnum = iota
	primitiveEnumHKDF          primitiveEnum = iota
	primitiveEnumAEADENC       primitiveEnum = iota
	primitiveEnumAEADDEC       primitiveEnum = iota
	primitiveEnumENC           primitiveEnum = iota
	primitiveEnumDEC           primitiveEnum = iota
	primitiveEnumMAC           primitiveEnum = iota
	primitiveEnumSIGN          primitiveEnum = iota
	primitiveEnumSIGNVERIF     primitiveEnum = iota
	primitiveEnumPKEENC        primitiveEnum = iota
	primitiveEnumPKEDEC        primitiveEnum = iota
	primitiveEnumSHAMIRSPLIT   primitiveEnum = iota
	primitiveEnumSHAMIRJOIN    primitiveEnum = iota
	primitiveEnumRINGSIGN      primitiveEnum = iota
	primitiveEnumRINGSIGNVERIF primitiveEnum = iota
	primitiveEnumBLIND         primitiveEnum = iota
	primitiveEnumUNBLIND       primitiveEnum = iota
)

var primitiveCoreSpecs = []PrimitiveCoreSpec{
	{
		Name:       primitiveEnumASSERT,
		StringName: "ASSERT",
		Arity:      []int{2},
		Output:     []int{1},
		HasRule:    true,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: typesEnumPrimitive, Primitive: p}}
			if valueEquivalentValues(p.Arguments[0], p.Arguments[1], true) {
				return true, v
			}
			return false, v
		},
		Check:      true,
		Injectable: false,
		Explosive:  false,
	},
	{
		Name:       primitiveEnumCONCAT,
		StringName: "CONCAT",
		Arity:      []int{2, 3, 4, 5},
		Output:     []int{1},
		HasRule:    false,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: typesEnumPrimitive, Primitive: p}}
			return false, v
		},
		Check:      false,
		Injectable: true,
		Explosive:  true,
	},
	{
		Name:       primitiveEnumSPLIT,
		StringName: "SPLIT",
		Arity:      []int{1},
		Output:     []int{1, 2, 3, 4, 5},
		HasRule:    true,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: typesEnumPrimitive, Primitive: p}}
			switch p.Arguments[0].Kind {
			case typesEnumConstant:
				return false, v
			case typesEnumPrimitive:
				pp := p.Arguments[0].Primitive
				switch pp.Name {
				case primitiveEnumCONCAT:
					return true, pp.Arguments
				}
				return false, v
			case typesEnumEquation:
				return false, v
			}
			return false, v
		},
		Check:      true,
		Injectable: false,
		Explosive:  false,
	},
}

var primitiveSpecs = []PrimitiveSpec{
	{
		Name:       primitiveEnumPWHASH,
		StringName: "PW_HASH",
		Arity:      []int{1, 2, 3, 4, 5},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{0, 1, 2, 3, 4},
	},
	{
		Name:       primitiveEnumHASH,
		StringName: "HASH",
		Arity:      []int{1, 2, 3, 4, 5},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       true,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumHKDF,
		StringName: "HKDF",
		Arity:      []int{3},
		Output:     []int{1, 2, 3, 4, 5},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       true,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumAEADENC,
		StringName: "AEAD_ENC",
		Arity:      []int{3},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumAEADDEC,
		StringName: "AEAD_DEC",
		Arity:      []int{3},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumAEADENC,
			From:    1,
			To: func(p Primitive) Value {
				return p.Arguments[1]
			},
			Matching: map[int][]int{
				0: {0},
				2: {2},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					return x, true
				case 2:
					return x, true
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           true,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumENC,
		StringName: "ENC",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumDEC,
		StringName: "DEC",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumENC,
			From:    1,
			To: func(p Primitive) Value {
				return p.Arguments[1]
			},
			Matching: map[int][]int{
				0: {0},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					return x, true
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumMAC,
		StringName: "MAC",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumSIGN,
		StringName: "SIGN",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumSIGNVERIF,
		StringName: "SIGNVERIF",
		Arity:      []int{3},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumSIGN,
			From:    2,
			To: func(p Primitive) Value {
				return valueNil
			},
			Matching: map[int][]int{
				0: {0},
				1: {1},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					switch x.Kind {
					case typesEnumConstant:
						return x, false
					case typesEnumPrimitive:
						return x, false
					case typesEnumEquation:
						switch {
						case len(x.Equation.Values) != 2:
							return x, false
						case !valueEquivalentValues(x.Equation.Values[0], valueG, true):
							return x, false
						default:
							return x.Equation.Values[1], true
						}
					}
				case 1:
					return x, true
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           true,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumPKEENC,
		StringName: "PKE_ENC",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					switch x.Kind {
					case typesEnumConstant:
						return x, false
					case typesEnumPrimitive:
						return x, false
					case typesEnumEquation:
						switch {
						case len(x.Equation.Values) != 2:
							return x, false
						case !valueEquivalentValues(x.Equation.Values[0], valueG, true):
							return x, false
						default:
							return x.Equation.Values[1], true
						}
					}
				case 1:
					return x, true
				}
				return x, false
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumPKEDEC,
		StringName: "PKE_DEC",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumPKEENC,
			From:    1,
			To: func(p Primitive) Value {
				return p.Arguments[1]
			},
			Matching: map[int][]int{
				0: {0},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					switch x.Kind {
					case typesEnumConstant, typesEnumPrimitive:
						return Value{
							Kind: typesEnumEquation,
							Equation: Equation{
								Values: []Value{valueG, x},
							},
						}, true
					case typesEnumEquation:
						return x, false
					}
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumSHAMIRSPLIT,
		StringName: "SHAMIR_SPLIT",
		Arity:      []int{1},
		Output:     []int{3},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: true,
			Given: [][]int{
				{0, 1},
				{0, 2},
				{1, 2},
			},
			Reveal: 0,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumSHAMIRJOIN,
		StringName: "SHAMIR_JOIN",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: true,
			Name:    primitiveEnumSHAMIRSPLIT,
			Given: [][]int{
				{0, 1},
				{1, 0},
				{0, 2},
				{2, 0},
				{1, 2},
				{2, 1},
			},
			Reveal: 0,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Check:           false,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumRINGSIGN,
		StringName: "RINGSIGN",
		Arity:      []int{4},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{3},
	},
	{
		Name:       primitiveEnumRINGSIGNVERIF,
		StringName: "RINGSIGNVERIF",
		Arity:      []int{5},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumRINGSIGN,
			From:    4,
			To: func(p Primitive) Value {
				return valueNil
			},
			Matching: map[int][]int{
				0: {0, 1, 2},
				1: {0, 1, 2},
				2: {0, 1, 2},
				3: {3},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					switch x.Kind {
					case typesEnumConstant:
						return x, false
					case typesEnumPrimitive:
						return x, false
					case typesEnumEquation:
						switch len(x.Equation.Values) {
						case 2:
							return x.Equation.Values[1], true
						default:
							return x, false
						}
					}
				case 1:
					return x, true
				case 2:
					return x, true
				case 3:
					return x, true
				case 4:
					return x, true
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           true,
		Injectable:      false,
		Explosive:       false,
		PasswordHashing: []int{},
	},
	{
		Name:       primitiveEnumBLIND,
		StringName: "BLIND",
		Arity:      []int{2},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				return x, true
			},
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: false,
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{1},
	},
	{
		Name:       primitiveEnumUNBLIND,
		StringName: "UNBLIND",
		Arity:      []int{3},
		Output:     []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    primitiveEnumSIGN,
			From:    2,
			To: func(p Primitive) Value {
				return Value{
					Kind: typesEnumPrimitive,
					Primitive: Primitive{
						Name: primitiveEnumSIGN,
						Arguments: []Value{
							p.Arguments[0],
							p.Arguments[1].Primitive.Arguments[1],
						},
						Output: 0,
						Check:  false,
					},
				}
			},
			Matching: map[int][]int{
				0: {1},
			},
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 1:
					blindPrim := Value{
						Kind: typesEnumPrimitive,
						Primitive: Primitive{
							Name: primitiveEnumBLIND,
							Arguments: []Value{
								p.Arguments[0], p.Arguments[1],
							},
							Output: 0,
							Check:  false,
						},
					}
					return blindPrim, true
				}
				return x, false
			},
		},
		Rebuild: RebuildRule{
			HasRule: false,
		},
		Check:           false,
		Injectable:      true,
		Explosive:       false,
		PasswordHashing: []int{},
	},
}

func primitiveIsCorePrim(name primitiveEnum) bool {
	switch name {
	case primitiveEnumASSERT, primitiveEnumCONCAT, primitiveEnumSPLIT:
		return true
	}
	return false
}

func primitiveCoreGet(name primitiveEnum) (PrimitiveCoreSpec, error) {
	for _, v := range primitiveCoreSpecs {
		if v.Name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive")
	return PrimitiveCoreSpec{}, err
}

func primitiveGet(name primitiveEnum) (PrimitiveSpec, error) {
	for _, v := range primitiveSpecs {
		if v.Name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive")
	return PrimitiveSpec{}, err
}

func primitiveGetEnum(stringName string) (primitiveEnum, error) {
	for _, v := range primitiveCoreSpecs {
		if v.StringName == stringName {
			return v.Name, nil
		}
	}
	for _, v := range primitiveSpecs {
		if v.StringName == stringName {
			return v.Name, nil
		}
	}
	err := fmt.Errorf("unknown primitive")
	return primitiveEnumEmpty, err
}

func primitiveGetArity(p Primitive) ([]int, error) {
	if primitiveIsCorePrim(p.Name) {
		prim, err := primitiveCoreGet(p.Name)
		if err != nil {
			return []int{}, err
		}
		return prim.Arity, nil
	}
	prim, err := primitiveGet(p.Name)
	if err != nil {
		return []int{}, err
	}
	return prim.Arity, nil
}
