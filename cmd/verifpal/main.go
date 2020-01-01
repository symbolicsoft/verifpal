/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 8e05848fe7fc3fb8ed3ba50a825c5493

//go:generate goversioninfo -64=true -icon=icon.ico

package main

import (
	"fmt"
	"os"
	"runtime"

	"verifpal.com/internal/verifpal"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	fmt.Fprintf(os.Stdout, "%s%s%s%s%s\n%s\n\n",
		"Verifpal ", version, " (", runtime.Version(), ") — https://verifpal.com",
		"WARNING: Verifpal is experimental software.",
	)
	if len(os.Args) != 3 {
		verifpal.Help()
		return
	}
	switch os.Args[1] {
	case "verify":
		model, valKnowledgeMap, valPrincipalStates := verifpal.ParseModel(os.Args[2])
		verifpal.Verify(model, valKnowledgeMap, valPrincipalStates)
	case "implement":
		verifpal.Implement()
	case "pretty":
		model, _, _ := verifpal.ParseModel(os.Args[2])
		fmt.Fprint(os.Stdout, verifpal.PrettyPrint(model))
	default:
		verifpal.Help()
	}
}
