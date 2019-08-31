/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// ce25ae21cf9eb2957686b8bb45225a31

package main

import (
	"errors"
	"fmt"
	"os"
)

func errorCritical(errText string) {
	err := errors.New(errText)
	fmt.Fprintf(os.Stderr, "[Verifpal] Error: %v\n", err)
	os.Exit(1)
}
