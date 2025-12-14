/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// df2c8510573b322af6eba9e4a25c4c51

package vplogic

import (
	"errors"
	"os/exec"
	"runtime"
)

// b2s converts a byte array to a string.
func b2s(bs []uint8) string {
	return string(bs)
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

// principalEnumInSlice checks if a principalEnum can be found within a slice.
func principalEnumInSlice(x principalEnum, a []principalEnum) bool {
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

// appendUniquePrincipalEnum appends a principalEnum to a slice only if it is unique within that slice.
func appendUniquePrincipalEnum(a []principalEnum, x principalEnum) ([]principalEnum, error) {
	if !principalEnumInSlice(x, a) {
		return append(a, x), nil
	}
	return a, errors.New("principalEnum is not unique")
}

// minIntInSlice returns the smallest integer in a slice of integers.
func minIntInSlice(v []int) (int, error) {
	if len(v) == 0 {
		return 0, errors.New("slice has no integers")
	}
	min := v[0]
	for i := 1; i < len(v); i++ {
		if v[i] < min {
			min = v[i]
		}
	}
	return min, nil
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

// OpenBrowser opens a URI using the appropriate binding for the host operating system.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	}
	return nil
}
