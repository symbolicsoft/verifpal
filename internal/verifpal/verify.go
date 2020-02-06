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
// It returns a slice of verifyResults and a "results code".
func Verify(filePath string) ([]verifyResult, string) {
	m := parserParseModel(filePath)
	valKnowledgeMap, valPrincipalStates := sanity(m)
	initiated := time.Now().Format("03:04:05 PM")
	verifyAnalysisCountInit()
	verifyResultsInit(m)
	PrettyMessage(fmt.Sprintf(
		"Verification initiated for '%s' at %s.", m.fileName, initiated,
	), "verifpal", false)
	switch m.attacker {
	case "passive":
		verifyPassive(valKnowledgeMap, valPrincipalStates)
	case "active":
		verifyActive(valKnowledgeMap, valPrincipalStates)
	default:
		errorCritical(fmt.Sprintf("invalid attacker (%s)", m.attacker))
	}
	fmt.Fprint(os.Stdout, "\n\n")
	return verifyEnd()
}

func verifyResolveQueries(
	valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState,
) {
	valVerifyResults, _ := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if !verifyResult.resolved {
			queryStart(verifyResult.query, valKnowledgeMap, valPrincipalState, valAttackerState)
		}
	}
}

func verifyStandardRun(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState, stage int) {
	var scanGroup sync.WaitGroup
	for _, state := range valPrincipalStates {
		valPrincipalState := sanityResolveAllPrincipalStateValues(state, valKnowledgeMap)
		failedRewrites, _, valPrincipalState := sanityPerformAllRewrites(valPrincipalState)
		sanityFailOnFailedRewrite(failedRewrites)
		for i := range valPrincipalState.assigned {
			sanityCheckEquationGenerators(valPrincipalState.assigned[i], valPrincipalState)
		}
		scanGroup.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, &scanGroup)
		scanGroup.Wait()
	}
}

func verifyPassive(valKnowledgeMap knowledgeMap, valPrincipalStates []principalState) {
	PrettyMessage("Attacker is configured as passive.", "info", false)
	attackerStateInit(false)
	attackerStatePutPhaseUpdate(valPrincipalStates[0], 0)
	verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
}

func verifyGetResultsCode(valVerifyResults []verifyResult) string {
	resultsCode := ""
	for _, verifyResult := range valVerifyResults {
		q := "c"
		r := "0"
		if verifyResult.query.kind == "authentication" {
			q = "a"
		}
		if verifyResult.resolved {
			r = "1"
		}
		resultsCode = fmt.Sprintf(
			"%s%s%s",
			resultsCode, q, r,
		)
	}
	return resultsCode
}

func verifyEnd() ([]verifyResult, string) {
	valVerifyResults, fileName := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if verifyResult.resolved {
			PrettyMessage(fmt.Sprintf(
				"%s: %s",
				prettyQuery(verifyResult.query),
				verifyResult.summary,
			), "result", false)
		}
	}
	completed := time.Now().Format("03:04:05 PM")
	PrettyMessage(fmt.Sprintf(
		"Verification completed for '%s' at %s.", fileName, completed,
	), "verifpal", false)
	PrettyMessage("Thank you for using Verifpal.", "verifpal", false)
	return valVerifyResults, verifyGetResultsCode(valVerifyResults)
}
