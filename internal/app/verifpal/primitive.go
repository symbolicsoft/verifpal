/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

// 5e88e17b2b330ef227c81153d720b176

package main

var primitiveSpecs = []primitiveSpec{
	{
		name:   "HASH",
		arity:  -1,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		check: false,
	},
	{
		name:   "HKDF",
		arity:  3,
		output: -1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		check: false,
	},
	{
		name:   "AEAD_ENC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "AEAD_DEC",
			from:     1,
			to:       1,
			matching: []int{0, 2},
			filter: func(x value, i int, valPrincipalState *principalState) (value, bool) {
				switch i {
				case 0:
					return x, true
				case 2:
					return x, true
				}
				return x, false
			},
		},
		check: false,
	},
	{
		name:   "AEAD_DEC",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "AEAD_ENC",
			from:     1,
			to:       1,
			matching: []int{0, 2},
			filter: func(x value, i int, valPrincipalState *principalState) (value, bool) {
				switch i {
				case 0:
					return x, true
				case 2:
					return x, true
				}
				return x, false
			},
		},
		check: true,
	},
	{
		name:   "ENC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "DEC",
			from:     1,
			to:       1,
			matching: []int{0},
			filter: func(x value, i int, valPrincipalState *principalState) (value, bool) {
				switch i {
				case 0:
					return x, true
				}
				return x, false
			},
		},
		check: false,
	},
	{
		name:   "DEC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: true,
			given:   []int{0},
			reveal:  1,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "ENC",
			from:     1,
			to:       1,
			matching: []int{0},
			filter: func(x value, i int, valPrincipalState *principalState) (value, bool) {
				switch i {
				case 0:
					return x, true
				}
				return x, false
			},
		},
		check: false,
	},
	{
		name:   "MAC",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		check: false,
	},
	{
		name:   "ASSERT",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: true,
		},
		check: true,
	},
	{
		name:   "SIGN",
		arity:  2,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule: false,
		},
		check: false,
	},
	{
		name:   "SIGNVERIF",
		arity:  3,
		output: 1,
		decompose: decomposeRule{
			hasRule: false,
		},
		rewrite: rewriteRule{
			hasRule:  true,
			name:     "SIGN",
			from:     2,
			to:       1,
			matching: []int{0, 1},
			filter: func(x value, i int, valPrincipalState *principalState) (value, bool) {
				switch i {
				case 0:
					switch x.kind {
					case "constant":
						return x, false
					case "primitive":
						return x, false
					case "equation":
						values := sanityDeconstructEquationValues(
							x.equation,
							false,
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
		check: true,
	},
}

func primitiveGet(name string) *primitiveSpec {
	p := &primitiveSpec{
		name: "",
	}
	for _, v := range primitiveSpecs {
		if v.name == name {
			p = &v
			break
		}
	}
	return p
}
