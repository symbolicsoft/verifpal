/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import "strings"

var constantG = Value{
	Kind: "constant",
	Constant: Constant{
		Name:        "g",
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: "knows",
		Qualifier:   "public",
	},
}

var constantN = Value{
	Kind: "constant",
	Constant: Constant{
		Name:        "nil",
		Guard:       false,
		Fresh:       false,
		Leaked:      false,
		Declaration: "knows",
		Qualifier:   "public",
	},
}

var constantGN = Value{
	Kind: "equation",
	Equation: Equation{
		Values: []Value{constantG, constantN},
	},
}

func constantIsGOrNil(c Constant) bool {
	switch strings.ToLower(c.Name) {
	case "g", "nil":
		return true
	}
	return false
}
