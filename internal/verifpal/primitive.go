/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 5e88e17b2b330ef227c81153d720b176

package verifpal

import (
	"fmt"
)

var primitiveCoreSpecs = []primitiveCoreSpec{
	{
		name:    "ASSERT",
		arity:   2,
		output:  1,
		hasRule: true,
		coreRule: func(p primitive) (bool, []value) {
			v := []value{{kind: "primitive", primitive: p}}
			if sanityEquivalentValues(p.arguments[0], p.arguments[1]) {
				return true, v
			}
			return false, v
		},
		check:      true,
		injectable: false,
		explosive:  false,
	},
	{
		name:    "CONCAT",
		arity:   -1,
		output:  1,
		hasRule: false,
		coreRule: func(p primitive) (bool, []value) {
			v := []value{{kind: "primitive", primitive: p}}
			return false, v
		},
		check:      false,
		injectable: true,
		explosive:  true,
	},
	{
		name:    "SPLIT",
		arity:   1,
		output:  -1,
		hasRule: true,
		coreRule: func(p primitive) (bool, []value) {
			v := []value{{kind: "primitive", primitive: p}}
			switch p.arguments[0].kind {
			case "constant":
				return false, v
			case "primitive":
				pp := p.arguments[0].primitive
				switch pp.name {
				case "CONCAT":
					return true, pp.arguments
				}
				errorCritical(fmt.Sprintf(
					"SPLIT must have CONCAT as input but instead has %s",
					prettyPrimitive(pp),
				))
				return false, v
			case "equation":
				return false, v
			}
			return false, v
		},
		check:      true,
		injectable: false,
		explosive:  false,
	},
}

var primitiveSpecs = []primitiveSpec{
	{
		name:   "PW_HASH",
		arity:  -1,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: true,
	},
	{
		name:   "HASH",
		arity:  -1,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       true,
		passwordHashing: false,
	},
	{
		name:   "HKDF",
		arity:  3,
		output: -1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       true,
		passwordHashing: false,
	},
	{
		name:   "AEAD_ENC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "AEAD_DEC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			name:    "AEAD_ENC",
			from:    1,
			to:      1,
			matching: map[int][]int{
				0: {0},
				2: {2},
			},
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					return x, true
				case 2:
					return x, true
				}
				return x, false
			},
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           true,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "ENC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "DEC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			name:    "ENC",
			from:    1,
			to:      1,
			matching: map[int][]int{
				0: {0},
			},
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					return x, true
				}
				return x, false
			},
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "MAC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "SIGN",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "SIGNVERIF",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			name:    "SIGN",
			from:    2,
			to:      -1,
			matching: map[int][]int{
				0: {0},
				1: {1},
			},
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						switch len(x.equation.values) {
						case 2:
							return x.equation.values[1], true
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
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           true,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "PKE_ENC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						if len(x.equation.values) == 2 {
							return x.equation.values[1], true
						}
						return x, false
					}
				case 1:
					return x, true
				}
				return x, false
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "PKE_DEC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			name:    "PKE_ENC",
			from:    1,
			to:      1,
			matching: map[int][]int{
				0: {0},
			},
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant", "primitive":
						return value{
							kind: "equation",
							equation: equation{
								values: []value{constantG, x},
							},
						}, true
					case "equation":
						return x, false
					}
				}
				return x, false
			},
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "SHAMIR_SPLIT",
		arity:  1,
		output: 3,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: true,
			given: [][]int{
				{0, 1},
				{0, 2},
				{1, 2},
			},
			reveal: 0,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "SHAMIR_JOIN",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: true,
			name:    "SHAMIR_SPLIT",
			given: [][]int{
				{0, 1},
				{1, 0},
				{0, 2},
				{2, 0},
				{1, 2},
				{2, 1},
			},
			reveal: 0,
			filter: func(x value, i int) (value, bool) {
				return x, true
			},
		},
		check:           false,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "RINGSIGN",
		arity:  4,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           false,
		injectable:      true,
		explosive:       false,
		passwordHashing: false,
	},
	{
		name:   "RINGSIGNVERIF",
		arity:  5,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			name:    "RINGSIGN",
			from:    4,
			to:      -1,
			matching: map[int][]int{
				0: {0, 1, 2},
				1: {0, 1, 2},
				2: {0, 1, 2},
				3: {3},
			},
			filter: func(x value, i int) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						switch len(x.equation.values) {
						case 2:
							return x.equation.values[1], true
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
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:           true,
		injectable:      false,
		explosive:       false,
		passwordHashing: false,
	},
}

func primitiveIsCorePrim(name string) bool {
	switch name {
	case "ASSERT", "CONCAT", "SPLIT":
		return true
	}
	return false
}

func primitiveCoreGet(name string) (primitiveCoreSpec, error) {
	for _, v := range primitiveCoreSpecs {
		if v.name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive (%s)", name)
	return primitiveCoreSpec{}, err
}

func primitiveGet(name string) (primitiveSpec, error) {
	for _, v := range primitiveSpecs {
		if v.name == name {
			return v, nil
		}
	}
	err := fmt.Errorf("unknown primitive (%s)", name)
	return primitiveSpec{}, err
}
