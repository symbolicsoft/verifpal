/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// 8e05848fe7fc3fb8ed3ba50a825c5493

package main

import (
	"fmt"
	"os"
)

const mainVersion = "0.3"

func mainParse(filename string) (*verifpal, *knowledgeMap) {
	var model verifpal
	prettyMessage("parsing model...", 0, 0, "verifpal")
	parsed, err := ParseFile(filename)
	if err != nil {
		errorCritical(err.Error())
	}
	model = parsed.(verifpal)
	valKnowledgeMap := sanity(&model)
	return &model, valKnowledgeMap
}

func main() {
	fmt.Fprint(os.Stdout, fmt.Sprintf("%s%s%s\n%s\n%s\n\n",
		"Verifpal ", mainVersion, " (https://verifpal.com)",
		"© 2019 Symbolic Software",
		"WARNING: Verifpal is experimental software.",
	))
	if len(os.Args) != 3 {
		help()
	}
	switch os.Args[1] {
	case "verify":
		model, valKnowledgeMap := mainParse(os.Args[2])
		verify(model, valKnowledgeMap)
		prettyMessage("thank you for using verifpal!", 0, 0, "verifpal")
		prettyMessage("verifpal is experimental software and may miss attacks.", 0, 0, "info")
	case "implement":
		errorCritical("this feature does not yet exist")
	case "pretty":
		model, _ := mainParse(os.Args[2])
		fmt.Fprint(os.Stdout, prettyPrint(model))
	default:
		help()
	}
}
