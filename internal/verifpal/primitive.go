/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 5e88e17b2b330ef227c81153d720b176

package verifpal

import "fmt"

var primitiveSpecs = []primitiveSpec{
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
		check:      false,
		injectable: true,
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
		check:      false,
		injectable: false,
	},
	{
		name:   "AEAD_ENC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
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
		check:      false,
		injectable: true,
	},
	{
		name:   "AEAD_DEC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "AEAD_ENC",
			from:     1,
			to:       1,
			matching: []int{0, 2},
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
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
		check:      true,
		injectable: false,
	},
	{
		name:   "ENC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
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
		check:      false,
		injectable: true,
	},
	{
		name:   "DEC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "ENC",
			from:     1,
			to:       1,
			matching: []int{0},
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
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
		check:      false,
		injectable: false,
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
		check:      false,
		injectable: true,
	},
	{
		name:   "ASSERT",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
			to:      -1,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:      true,
		injectable: false,
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
		check:      false,
		injectable: true,
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
			hasRule:  true,
			name:     "SIGN",
			from:     2,
			to:       -1,
			matching: []int{0, 1},
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						values := sanityDecomposeEquationValues(
							x.equation,
							valPrincipalState,
						)
						if len(values) == 2 {
							return values[1], true
						}
						return x, false
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
		check:      true,
		injectable: false,
	},
	{
		name:   "PKE_ENC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						values := sanityDecomposeEquationValues(
							x.equation,
							valPrincipalState,
						)
						if len(values) == 2 {
							return values[1], true
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
		check:      false,
		injectable: true,
	},
	{
		name:   "PKE_DEC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				return x, true
			},
		},
		recompose: recomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "PKE_ENC",
			from:     1,
			to:       1,
			matching: []int{0},
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
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
		check:      false,
		injectable: false,
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
				[]int{0, 1},
				[]int{0, 2},
				[]int{1, 2},
			},
			reveal: 0,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				return x, true
			},
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		rebuild: rebuildRule{
			hasRule: false,
		},
		check:      false,
		injectable: false,
	},
	{
		name:   "SHAMIR_JOIN",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
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
				[]int{0, 1},
				[]int{1, 0},
				[]int{0, 2},
				[]int{2, 0},
				[]int{1, 2},
				[]int{2, 1},
			},
			reveal: 0,
			filter: func(x value, i int, valPrincipalState principalState) (value, bool) {
				return x, true
			},
		},
		check:      false,
		injectable: false,
	},
}

func primitiveGet(name string) primitiveSpec {
	var p primitiveSpec
	found := false
	for _, v := range primitiveSpecs {
		if v.name == name {
			found = true
			p = v
			break
		}
	}
	if !found {
		errorCritical(fmt.Sprintf("invalid primitive (%s)", name))
	}
	return p
}
