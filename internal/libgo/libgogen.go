/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var header = []string{
	"/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>",
	" * SPDX-License-Identifier: GPL-3.0-only */",
	"// 00000000000000000000000000000000",
	"",
	"package vplogic\n",
	"import \"strings\"\n",
	"// nolint:unused",
	"var libgo = strings.Join([]string{\n",
}

func main() {
	r, err := os.Open(filepath.Join(
		"..", "..", "internal", "libgo", "libgotemplate.go",
	))
	check(err)
	w, err := os.Create(filepath.Join(
		"..", "..", "cmd", "vplogic", "libgo.go",
	))
	check(err)
	_, err = w.WriteString(strings.Join(header, "\n"))
	check(err)
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		temp := s.Text()
		_, err = w.WriteString(fmt.Sprintf("\t%q,\n", temp))
		check(err)
	}
	r.Close()
	_, err = w.WriteString("\t\"\"},\n\t\"\\n\")\n")
	check(err)
	w.Close()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
