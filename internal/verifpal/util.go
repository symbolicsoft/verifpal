/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// df2c8510573b322af6eba9e4a25c4c51

package verifpal

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/logrusorgru/aurora"
)

// b2s converts a byte array to a string.
func b2s(bs []uint8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}
	return string(b)
}

// strInSlice checks if a string can be found within a slice.
func strInSlice(x string, a []string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// appendUnique appends a string to a slice only if it is unique within that slice.
func appendUnique(a []string, x string) ([]string, error) {
	if !strInSlice(x, a) {
		return append(a, x), nil
	}
	return a, errors.New("string is not unique")
}

// errorCritical declares an unrecoverable error and ends the Verifpal program.
func errorCritical(errText string) {
	err := errors.New(errText)
	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, " Verifpal! Error: %v.\n", err)
	} else {
		fmt.Fprintf(os.Stderr, " %s! %s: %v.\n",
			aurora.Red("Verifpal").Bold(),
			aurora.Red("Error"), err,
		)
	}
	os.Exit(1)
}
