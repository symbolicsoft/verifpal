/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 458871bd68906e9965785ac87c2708ec

package verifpal

import (
	"fmt"
	"os"
	"sync"
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
		if !verifyResult.resolved {
			continue
		}
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

func verifyStandardRun(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, analysis int, stage int) int {
	var scanGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		valPrincipalStateClone := constructPrincipalStateClone(valPrincipalState)
		valPrincipalStateClone = sanityResolveAllPrincipalStateValues(valPrincipalStateClone, valKnowledgeMap)
		failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStateClone)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalStateClone.assigned {
			sanityCheckEquationGenerators(valPrincipalStateClone.assigned[i], valPrincipalStateClone)
		}
		scanGroup.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalStateClone, analysis, &scanGroup)
		scanGroup.Wait()
		prettyAnalysis(analysis, stage)
	}
	return analysis
}

func verifyPassive(m Model, valKnowledgeMap knowledgeMap, valPrincipalStates []principalState) {
	constructAttackerState(false, m, valKnowledgeMap, true)
	prettyMessage("Attacker is configured as passive.", 0, "info")
	verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0, 0)
}
