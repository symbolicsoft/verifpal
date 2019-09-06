/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

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
