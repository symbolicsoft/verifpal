/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

// 8e05848fe7fc3fb8ed3ba50a825c5493

package main

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

const mainVersion = "0.4.4"

func mainParse(filename string) (*verifpal, *knowledgeMap, []*principalState) {
	var model verifpal
	prettyMessage(fmt.Sprintf(
		"parsing model \"%s\"...",
		path.Base(filename),
	), 0, 0, "verifpal")
	parsed, err := ParseFile(filename)
	if err != nil {
		errorCritical(err.Error())
	}
	model = parsed.(verifpal)
	valKnowledgeMap, valPrincipalStates := sanity(&model)
	return &model, valKnowledgeMap, valPrincipalStates
}

func main() {
	fmt.Fprint(os.Stdout, fmt.Sprintf("%s%s%s%s%s\n%s\n%s\n\n",
		"Verifpal ", mainVersion, " (", runtime.Version(), ")",
		"© 2019 Symbolic Software — https://verifpal.com",
		"WARNING: Verifpal is experimental software.",
	))
	if len(os.Args) != 3 {
		help()
	}
	switch os.Args[1] {
	case "verify":
		model, valKnowledgeMap, valPrincipalStates := mainParse(os.Args[2])
		verify(model, valKnowledgeMap, valPrincipalStates)
		prettyMessage("thank you for using verifpal!", 0, 0, "verifpal")
		prettyMessage("verifpal is experimental software and may miss attacks.", 0, 0, "info")
	case "implement":
		errorCritical("this feature does not yet exist")
	case "pretty":
		model, _, _ := mainParse(os.Args[2])
		fmt.Fprint(os.Stdout, prettyPrint(model))
	default:
		help()
	}
}
