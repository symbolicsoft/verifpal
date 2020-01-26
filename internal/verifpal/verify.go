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
	attackerStateInit(m, valKnowledgeMap, m.attacker == "active")
	verifyResultsInit(m)
	initiated := time.Now().Format("15:04:05")
	prettyMessage(fmt.Sprintf("Verification initiated at %s.", initiated), "verifpal")
	for i, valPrincipalState := range valPrincipalStates {
		valPrincipalStates[i] = sanityResolveAllPrincipalStateValues(valPrincipalState, valKnowledgeMap)
	}
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

func verifyResolveQueries(valPrincipalState principalState, valAttackerState attackerState) {
	valVerifyResults := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if !verifyResult.resolved {
			queryStart(verifyResult.query, valPrincipalState, valAttackerState)
		}
	}
}

func verifyStandardRun(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, stage int) {
	var scanGroup sync.WaitGroup
	for _, valPrincipalState := range valPrincipalStates {
		failedRewrites, _, valPrincipalState := sanityPerformAllRewrites(valPrincipalState)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalState.assigned {
			sanityCheckEquationGenerators(valPrincipalState.assigned[i], valPrincipalState)
		}
		scanGroup.Add(1)
		go verifyAnalysis(valPrincipalState, stage, &scanGroup)
		scanGroup.Wait()
	}
}

func verifyPassive(m Model, valKnowledgeMap knowledgeMap, valPrincipalStates []principalState) {
	prettyMessage("Attacker is configured as passive.", "info")
	verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
}

func verifyEnd() {
	valVerifyResults := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if verifyResult.resolved {
			prettyMessage(fmt.Sprintf(
				"%s: %s",
				prettyQuery(verifyResult.query),
				verifyResult.summary,
			), "result")
		}
	}
	completed := time.Now().Format("15:04:05")
	prettyMessage(fmt.Sprintf(
		"Verification completed at %s. %s", completed,
		"Thank you for using Verifpal.",
	), "verifpal")
	os.Exit(0)
}
