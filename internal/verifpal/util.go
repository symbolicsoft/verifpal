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
	copy(b, bs)
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

// colorOutputSupport tells us whether color output is supported based on the GOOS build target.
func colorOutputSupport() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if runtime.GOOS == "js" {
		return false
	}
	return true
}

// errorCritical declares an unrecoverable error and ends the Verifpal program.
func errorCritical(errText string) {
	err := errors.New(errText)
	if colorOutputSupport() {
		fmt.Fprintf(os.Stderr, " %s! %s: %v.\n",
			aurora.Red("Verifpal").Bold(),
			aurora.Red("Error"), err,
		)
	} else {
		fmt.Fprintf(os.Stderr, " Verifpal! Error: %v.\n", err)
	}
	os.Exit(1)
}
