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

var version = "0.11.4"

func main() {
	mainIntro()
	switch len(os.Args) {
	case 3:
		mainGanbatte(os.Args)
	default:
		verifpal.Help()
	}
}

func mainIntro() {
	fmt.Fprintf(os.Stdout,
		aurora.Bold("Verifpal %s - %s\n").String(),
		version, "https://verifpal.com",
	)
	verifpal.PrettyMessage(
		"Verifpal is experimental software.",
		"warning", false,
	)
}

func mainGanbatte(args []string) {
	switch args[1] {
	case "verify":
		verifpal.Verify(args[2])
	case "implement":
		verifpal.Implement()
	case "pretty":
		verifpal.PrettyPrint(args[2])
	default:
		verifpal.Help()
	}
}
