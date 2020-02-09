/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 8e05848fe7fc3fb8ed3ba50a825c5493

//go:generate goversioninfo -64=true -icon=../../assets/icon.ico

package main

import (
	"fmt"
	"os"

	"github.com/logrusorgru/aurora"
	"verifpal.com/internal/verifpal"
)

var version = "0.10.8"

func main() {
	fmt.Fprintf(os.Stdout,
		aurora.Bold("Verifpal %s - %s\n").String(),
		version, "https://verifpal.com",
	)
	verifpal.PrettyMessage(
		"Verifpal is experimental software.",
		"warning", false,
	)
	if len(os.Args) != 3 {
		verifpal.Help()
		return
	}
	switch os.Args[1] {
	case "verify":
		verifpal.Verify(os.Args[2])
	case "implement":
		verifpal.Implement()
	case "pretty":
		prettyModel := verifpal.PrettyPrint(os.Args[2])
		fmt.Fprint(os.Stdout, prettyModel)
	case "help":
		verifpal.Help()
	default:
		verifpal.Help()
	}
}
