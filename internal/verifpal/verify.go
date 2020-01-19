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
func Verify(modelFile string) {
	m, valKnowledgeMap, valPrincipalStates := parserParseModel(modelFile)
	verifyResultsInit(m)
	prettyMessage(fmt.Sprintf(
		"Verification initiated at %s.",
		time.Now().Format("15:04:05"),
	), "verifpal")
	switch m.attacker {
	case "passive":
		verifyPassive(m, valKnowledgeMap, valPrincipalStates)
	case "active":
		verifyActive(m, valKnowledgeMap, valPrincipalStates)
	default:
		errorCritical(fmt.Sprintf("invalid attacker (%s)", m.attacker))
	}
	fmt.Fprint(os.Stdout, "\n")
	verifyEnd()
}

func verifyResolveQueries(valKnowledgeMap knowledgeMap, valPrincipalState principalState) {
	verifyResults := verifyResultsGetRead()
	for _, verifyResult := range verifyResults {
		if verifyResult.resolved {
			continue
		}
		queryStart(verifyResult.query, valPrincipalState, valKnowledgeMap)
	}
}

func verifyStandardRun(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, stage int) {
	var scanGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		valPrincipalState = sanityResolveAllPrincipalStateValues(valPrincipalState, valKnowledgeMap)
		failedRewrites, _ := sanityPerformAllRewrites(valPrincipalState)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalState.assigned {
			sanityCheckEquationGenerators(valPrincipalState.assigned[i], valPrincipalState)
		}
		scanGroup.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, &scanGroup)
		scanGroup.Wait()
	}
}

func verifyPassive(m Model, valKnowledgeMap knowledgeMap, valPrincipalStates []principalState) {
	constructAttackerState(false, m, valKnowledgeMap, true)
	prettyMessage("Attacker is configured as passive.", "info")
	verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
}

func verifyEnd() {
	verifyResults := verifyResultsGetRead()
	for _, verifyResult := range verifyResults {
		if !verifyResult.resolved {
			continue
		}
		prettyMessage(fmt.Sprintf(
			"%s: %s",
			prettyQuery(verifyResult.query),
			verifyResult.summary,
		), "result")
	}
	prettyMessage(fmt.Sprintf(
		"Verification completed at %s. Thank you for using Verifpal.",
		time.Now().Format("15:04:05"),
	), "verifpal")
	os.Exit(0)
}
