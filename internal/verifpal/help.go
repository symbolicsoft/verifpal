/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 2f07afecf9e6e77cc63ba896cc25d1da

package verifpal

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Help displays Verifpal command-line usage instructions.
func Help(a string) {
	fmt.Fprintf(os.Stdout, strings.Join([]string{
		"verify    [file]: Analyze Verifpal model.",
		"pv        [file]: Translate Verifpal model into ProVerif model.",
		"coq       [file]: Translate Verifpal model into Coq model.",
		"go        [file]: Translate Verifpal model into a Go implementation.",
		"pretty    [file]: Pretty-print Verifpal model.",
		"help            : Show this help text.\n",
	}, "\n"))
	x := make([]byte, 07)
	y := make([]byte, 38)
	hex.Decode(x, []byte("667269656e6473"))
	hex.Decode(y, []byte(strings.Join([]string{
		"68747470733a2f2f766572696670616c2e636f",
		"6d2f7265732f65787472612f667269656e6473",
	}, "")))
	switch a {
	case string(x):
		openBrowser(string(y))
	}
}
