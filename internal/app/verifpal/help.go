/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// 2f07afecf9e6e77cc63ba896cc25d1da

package main

import (
	"fmt"
	"os"
)

func help() {
	fmt.Fprint(os.Stdout, fmt.Sprintf("%s\n%s\n%s\n%s\n",
		"verify    [file]: verify Verifpal model.",
		"implement [file]: implement Verifpal model in Go.",
		"pretty    [file]: pretty-print Verifpal model.",
		"help:             show this help text.",
	))
	os.Exit(0)
}
