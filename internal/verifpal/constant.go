/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import "strings"

var constantG = value{
	kind: "constant",
	constant: constant{
		name:        "g",
		guard:       false,
		fresh:       false,
		declaration: "knows",
		qualifier:   "public",
	},
}

var constantN = value{
	kind: "constant",
	constant: constant{
		name:        "nil",
		guard:       false,
		fresh:       false,
		declaration: "knows",
		qualifier:   "public",
	},
}

var constantGN = value{
	kind: "equation",
	equation: equation{
		values: []value{constantG, constantN},
	},
}

func constantIsGOrNil(c constant) bool {
	switch strings.ToLower(c.name) {
	case "g", "nil":
		return true
	}
	return false
}
