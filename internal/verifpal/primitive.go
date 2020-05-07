/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 5e88e17b2b330ef227c81153d720b176

package verifpal

import (
	"fmt"
)

var primitiveCoreSpecs = []PrimitiveCoreSpec{
	{
		Name:    "ASSERT",
		Arity:   []int{2},
		Output:  1,
		HasRule: true,
		CoreRule: func(p Primitive) (bool, []Value) {
			v := []Value{{Kind: "primitive", Primitive: p}}
			if sanityEquivalentValues(p.Arguments[0], p.Arguments[1], true) {
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
		Output:  1,
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
		Output:  -1,
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
		Output: 1,
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
		PasswordHashing: true,
	},
	{
		Name:   "HASH",
		Arity:  []int{1, 2, 3, 4, 5},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "HKDF",
		Arity:  []int{3},
		Output: -1,
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
		PasswordHashing: false,
	},
	{
		Name:   "AEAD_ENC",
		Arity:  []int{3},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "AEAD_DEC",
		Arity:  []int{3},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "ENC",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "DEC",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "MAC",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "SIGN",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "SIGNVERIF",
		Arity:  []int{3},
		Output: 1,
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
				return constantN
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
						switch len(x.Equation.Values) {
						case 2:
							return x.Equation.Values[1], true
						default:
							return x, false
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
		PasswordHashing: false,
	},
	{
		Name:   "PKE_ENC",
		Arity:  []int{2},
		Output: 1,
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
						if len(x.Equation.Values) == 2 {
							return x.Equation.Values[1], true
						}
						return x, false
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
		PasswordHashing: false,
	},
	{
		Name:   "PKE_DEC",
		Arity:  []int{2},
		Output: 1,
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
								Values: []Value{constantG, x},
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
		PasswordHashing: false,
	},
	{
		Name:   "SHAMIR_SPLIT",
		Arity:  []int{1},
		Output: 3,
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
		PasswordHashing: false,
	},
	{
		Name:   "SHAMIR_JOIN",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "RINGSIGN",
		Arity:  []int{4},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "RINGSIGNVERIF",
		Arity:  []int{5},
		Output: 1,
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
				return constantN
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
		PasswordHashing: false,
	},
	{
		Name:   "BLIND",
		Arity:  []int{2},
		Output: 1,
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
		PasswordHashing: false,
	},
	{
		Name:   "UNBLIND",
		Arity:  []int{3},
		Output: 1,
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
		PasswordHashing: false,
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
