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
		"verify    [file]: Load Verifpal model from file and analyze.",
		"implement [file]: Implement Verifpal model in Go.",
		"pretty    [file]: Pretty-print Verifpal model.",
		"help:             Show this help text.",
	)
}
