/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// df2c8510573b322af6eba9e4a25c4c51

package verifpal

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sort"

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

// intInSlice checks if an integer can be found within a slice.
func intInSlice(x int, a []int) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// appendUniqueString appends a string to a slice only if it is unique within that slice.
func appendUniqueString(a []string, x string) ([]string, error) {
	if !strInSlice(x, a) {
		return append(a, x), nil
	}
	return a, errors.New("string is not unique")
}

// appendUniqueInt appends an integer to a slice only if it is unique within that slice.
func appendUniqueInt(a []int, x int) ([]int, error) {
	if !intInSlice(x, a) {
		return append(a, x), nil
	}
	return a, errors.New("int is not unique")
}

// minIntInSlice returns the smallest integer in a slice of integers.
func minIntInSlice(v []int) (int, error) {
	if len(v) == 0 {
		return 0, errors.New("slice has no integers")
	}
	sort.Ints(v)
	return v[0], nil
}

// colorOutputSupport tells us whether color output is supported based on the GOOS build target.
func colorOutputSupport() bool {
	switch runtime.GOOS {
	case "windows":
		return false
	case "js":
		return false
	}
	return true
}

// errorCritical declares an unrecoverable error and ends the Verifpal program.
func errorCritical(errText string) {
	err := errors.New(errText)
	if colorOutputSupport() {
		log.Fatal(fmt.Errorf(" %s! %s: %v.\n",
			aurora.Red("Verifpal").Bold(),
			aurora.Red("Error"), err,
		))
	} else {
		log.Fatal(fmt.Errorf("Verifpal! Error: %v.\n", err))
	}
}

// openBrowser opens a URI using the appropriate binding for the host operating system.
func OpenBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}
