package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	r, err := os.Open("./signal.v")
	check(err)

	w, err := os.Create("../internal/verifpal/coqheader.go")
	check(err)

	_, err = w.WriteString(strings.Join(
		[]string{
			"/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>",
			"* SPDX-License-Identifier: GPL-3.0-only */",
			"// 806d8db3ce9f3ded40fd35fdba02fb84",
			"package verifpal\n",
			"import \"strings\"\n",
			"var coqHeader = strings.Join([]string{\n",
		}, "\n"))
	check(err)

	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		temp := s.Text()
		if temp == "(*!DELIMITER!*)" {
			break
		}
		_, err = w.WriteString(fmt.Sprintf("\t%q,\n", temp))
		check(err)
	}
	r.Close()

	_, err = w.WriteString("\t\"\"},\n\t\"\\n\")\n")
	check(err)

	w.Close()
}
