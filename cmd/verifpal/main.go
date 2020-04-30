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

var version = "0.13.3"

func main() {
	switch len(os.Args) {
	case 3:
		mainGanbatte(os.Args)
	case 2:
		mainIntro()
		verifpal.Help(os.Args[1])
	default:
		mainIntro()
		verifpal.Help("")
	}
}

func mainIntro() {
	fmt.Fprintf(os.Stdout,
		aurora.Bold("Verifpal %s - %s\n").String(),
		version, "https://verifpal.com",
	)
	verifpal.PrettyInfo(
		"Verifpal is experimental software.",
		"warning", false,
	)
}

func mainGanbatte(args []string) {
	switch args[1] {
	case "verify":
		mainIntro()
		verifpal.Verify(args[2])
	case "proverif":
		verifpal.ProVerif(args[2])
	case "coq":
		verifpal.Coq(args[2])
	case "pretty":
		verifpal.PrettyPrint(args[2])
	case "implement":
		verifpal.Implement()
	case "internal-json":
		verifpal.Json(args[2])
	default:
		mainIntro()
		verifpal.Help(args[1])
	}
}
