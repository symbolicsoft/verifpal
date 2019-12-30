/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 458871bd68906e9965785ac87c2708ec

package verifpal

import (
	"fmt"
	"os"
	"time"
)

func Verify(m *model, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) []verifyResult {
	var verifyResults []verifyResult
	prettyMessage(fmt.Sprintf(
		"verification initiated at %s",
		time.Now().Format("15:04:05"),
	), 0, 0, "verifpal")
	if m.attacker == "passive" {
		verifyResults = verifyPassive(m, valKnowledgeMap, valPrincipalStates)
	} else if m.attacker == "active" {
		verifyResults = verifyActive(m, valKnowledgeMap, valPrincipalStates)
	} else {
		errorCritical(fmt.Sprintf("invalid attacker (%s)", m.attacker))
	}
	fmt.Fprint(os.Stdout, "\n")
	for _, verifyResult := range verifyResults {
		prettyMessage(fmt.Sprintf(
			"%s: %s",
			prettyQuery(verifyResult.query),
			verifyResult.summary,
		), 0, 0, "result")
	}
	prettyMessage(fmt.Sprintf(
		"verification completed at %s",
		time.Now().Format("15:04:05"),
	), 0, 0, "verifpal")
	prettyMessage("thank you for using verifpal!", 0, 0, "verifpal")
	prettyMessage("verifpal is experimental software and may miss attacks.", 0, 0, "info")
	return verifyResults
}

func verifyResolveQueries(
	m *model,
	valKnowledgeMap *knowledgeMap, valPrincipalState *principalState,
	valAttackerState *attackerState, verifyResults *[]verifyResult, analysis int,
) {
	for q, query := range m.queries {
		if m.queries[q].resolved {
			continue
		}
		verifyResult := queryStart(query, valAttackerState, valPrincipalState, valKnowledgeMap)
		if verifyResult.query.resolved {
			m.queries[q].resolved = true
			*verifyResults = append(*verifyResults, verifyResult)
			prettyMessage(fmt.Sprintf(
				"%s: %s",
				prettyQuery(verifyResult.query),
				verifyResult.summary,
			), analysis, 0, "result")
		}
	}
}
