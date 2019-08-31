/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// df2c8510573b322af6eba9e4a25c4c51

package main

import (
	"errors"
)

func strInSlice(x string, a []string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func appendUnique(a []string, x string) ([]string, error) {
	if !strInSlice(x, a) {
		return append(a, x), nil
	}
	return a, errors.New("string is not unique")
}
