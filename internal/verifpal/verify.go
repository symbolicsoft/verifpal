/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 458871bd68906e9965785ac87c2708ec

package verifpal

import (
	"fmt"
	"os"
	"time"
)

// Verify runs the main verification engine for Verifpal on a model loaded from a file.
func Verify(modelFile string) (Model, []VerifyResult) {
	m, valKnowledgeMap, valPrincipalStates := parserParseModel(modelFile)
	verifyResultsInit(m)
	prettyMessage(fmt.Sprintf(
		"Verification initiated at %s.",
		time.Now().Format("15:04:05"),
	), 0, "verifpal")
	switch m.attacker {
	case "passive":
		verifyPassive(m, valKnowledgeMap, valPrincipalStates)
	case "active":
		verifyActive(m, valKnowledgeMap, valPrincipalStates)
	default:
		errorCritical(fmt.Sprintf("invalid attacker (%s)", m.attacker))
	}
	fmt.Fprint(os.Stdout, "\n")
	verifyResults := verifyResultsGetRead()
	for _, verifyResult := range verifyResults {
		prettyMessage(fmt.Sprintf(
			"%s: %s",
			prettyQuery(verifyResult.query),
			verifyResult.summary,
		), 0, "result")
	}
	prettyMessage(fmt.Sprintf(
		"Verification completed at %s. Thank you for using Verifpal.",
		time.Now().Format("15:04:05"),
	), 0, "verifpal")
	return m, verifyResults
}

func verifyResolveQueries(valKnowledgeMap knowledgeMap, valPrincipalState principalState, analysis int) {
	verifyResults := verifyResultsGetRead()
	for _, verifyResult := range verifyResults {
		if verifyResult.resolved {
			continue
		}
		queryStart(verifyResult.query, valPrincipalState, valKnowledgeMap, analysis)
	}
}

func verifyPassive(m Model, valKnowledgeMap knowledgeMap, valPrincipalStates []principalState) {
	constructAttackerState(false, m, valKnowledgeMap, true)
	prettyMessage("Attacker is configured as passive.", 0, "info")
	valPrincipalStates[0] = sanityResolveAllPrincipalStateValues(valPrincipalStates[0], valKnowledgeMap)
	failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStates[0])
	sanityFailOnFailedRewrite(failedRewrites)
	for _, a := range valPrincipalStates[0].assigned {
		sanityCheckEquationGenerators(a, valPrincipalStates[0])
	}
	verifyAnalysis(valPrincipalStates[0], 0)
	verifyResolveQueries(valKnowledgeMap, valPrincipalStates[0], 0)
}
