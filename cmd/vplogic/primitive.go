/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 5e88e17b2b330ef227c81153d720b176

package vplogic

import (
	"fmt"
)

var primitiveCoreSpecs = []PrimitiveCoreSpec{
	{
		Name:    "ASSERT",
		Arity:   []int{2},
		Output:  []int{1},
		HasRule: true,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: "primitive", Primitive: p}}
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
		Name:    "CONCAT",
		Arity:   []int{2, 3, 4, 5},
		Output:  []int{1},
		HasRule: false,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: "primitive", Primitive: p}}
			return false, v
		},
		Check:      false,
		Injectable: true,
		Explosive:  true,
	},
	{
		Name:    "SPLIT",
		Arity:   []int{1},
		Output:  []int{1, 2, 3, 4, 5},
		HasRule: true,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: "primitive", Primitive: p}}
			switch p.Arguments[0].Kind {
			case "constant":
				return false, v
			case "primitive":
				pp := p.Arguments[0].Primitive
				switch pp.Name {
				case "CONCAT":
					return true, pp.Arguments
				}
				return false, v
			case "equation":
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
		Name:   "PW_HASH",
		Arity:  []int{1, 2, 3, 4, 5},
		Output: []int{1},
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
		Name:   "HASH",
		Arity:  []int{1, 2, 3, 4, 5},
		Output: []int{1},
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
		Name:   "HKDF",
		Arity:  []int{3},
		Output: []int{1, 2, 3, 4, 5},
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
		Name:   "AEAD_ENC",
		Arity:  []int{3},
		Output: []int{1},
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
		Name:   "AEAD_DEC",
		Arity:  []int{3},
		Output: []int{1},
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
			Name:    "AEAD_ENC",
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
		Name:   "ENC",
		Arity:  []int{2},
		Output: []int{1},
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
		Name:   "DEC",
		Arity:  []int{2},
		Output: []int{1},
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
			Name:    "ENC",
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
		Name:   "MAC",
		Arity:  []int{2},
		Output: []int{1},
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
		Name:   "SIGN",
		Arity:  []int{2},
		Output: []int{1},
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
		Name:   "SIGNVERIF",
		Arity:  []int{3},
		Output: []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    "SIGN",
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
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
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
		Name:   "PKE_ENC",
		Arity:  []int{2},
		Output: []int{1},
		Decompose: DecomposeRule{
			HasRule: true,
			Given:   []int{0},
			Reveal:  1,
			Filter: func(p Primitive, x Value, i int) (Value, bool) {
				switch i {
				case 0:
					switch x.Kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
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
		Name:   "PKE_DEC",
		Arity:  []int{2},
		Output: []int{1},
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
			Name:    "PKE_ENC",
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
					case "constant", "primitive":
						return Value{
							Kind: "equation",
							Equation: Equation{
								Values: []Value{valueG, x},
							},
						}, true
					case "equation":
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
		Name:   "SHAMIR_SPLIT",
		Arity:  []int{1},
		Output: []int{3},
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
		Name:   "SHAMIR_JOIN",
		Arity:  []int{2},
		Output: []int{1},
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
			Name:    "SHAMIR_SPLIT",
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
		Name:   "RINGSIGN",
		Arity:  []int{4},
		Output: []int{1},
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
		Name:   "RINGSIGNVERIF",
		Arity:  []int{5},
		Output: []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    "RINGSIGN",
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
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
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
		Name:   "BLIND",
		Arity:  []int{2},
		Output: []int{1},
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
		Name:   "UNBLIND",
		Arity:  []int{3},
		Output: []int{1},
		Decompose: DecomposeRule{
			HasRule: false,
		},
		Recompose: RecomposeRule{
			HasRule: false,
		},
		Rewrite: RewriteRule{
			HasRule: true,
			Name:    "SIGN",
			From:    2,
			To: func(p Primitive) Value {
				return Value{
					Kind: "primitive",
					Primitive: Primitive{
						Name: "SIGN",
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
						Kind: "primitive",
						Primitive: Primitive{
							Name: "BLIND",
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

func primitiveIsCorePrim(name string) bool {
	switch name {
	case "ASSERT", "CONCAT", "SPLIT":
		return true
	}
	return false
}

func primitiveCoreGet(name string) (PrimitiveCoreSpec, error) {
	for _, v := range primitiveCoreSpecs {
		if v.Name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive (%s)", name)
	return PrimitiveCoreSpec{}, err
}

func primitiveGet(name string) (PrimitiveSpec, error) {
	for _, v := range primitiveSpecs {
		if v.Name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive (%s)", name)
	return PrimitiveSpec{}, err
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
