/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 2f07afecf9e6e77cc63ba896cc25d1da

package verifpal

import (
	"fmt"
	"os"
)

// Help displays Verifpal command-line usage instructions.
func Help() {
	fmt.Fprintf(os.Stdout, "%s\n%s\n%s\n%s\n",
		"verify    [file]: verify Verifpal model.",
		"implement [file]: implement Verifpal model in Go.",
		"pretty    [file]: pretty-print Verifpal model.",
		"help:             show this help text.",
	)
	os.Exit(0)
}
