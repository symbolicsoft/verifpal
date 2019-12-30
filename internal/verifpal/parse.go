/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"fmt"
	"path"
)

func ParseModel(filename string) (*model, *knowledgeMap, []*principalState) {
	var m model
	prettyMessage(fmt.Sprintf(
		"parsing model \"%s\"...",
		path.Base(filename),
	), 0, 0, "verifpal")
	parsed, err := ParseFile(filename)
	if err != nil {
		errorCritical(err.Error())
	}
	m = parsed.(model)
	valKnowledgeMap, valPrincipalStates := sanity(&m)
	return &m, valKnowledgeMap, valPrincipalStates
}
