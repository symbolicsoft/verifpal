/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// ce25ae21cf9eb2957686b8bb45225a31

package verifpal

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/logrusorgru/aurora"
)

func ErrorCritical(errText string) {
	err := errors.New(errText)
	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, " Verifpal! Error: %v.\n", err)
	} else {
		fmt.Fprintf(os.Stderr, " %s! %s: %v.\n", aurora.Red("Verifpal").Bold(), aurora.Red("Error"), err)
	}
	os.Exit(1)
}
