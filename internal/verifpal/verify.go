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
func Verify(filePath string) ([]VerifyResult, string) {
	m := libpegParseModel(filePath, true)
	return verifyModel(m)
}

func verifyModel(m Model) ([]VerifyResult, string) {
	valKnowledgeMap, valPrincipalStates := sanity(m)
	initiated := time.Now().Format("03:04:05 PM")
	verifyAnalysisCountInit()
	verifyResultsInit(m)
	InfoMessage(fmt.Sprintf(
		"Verification initiated for '%s' at %s.", m.FileName, initiated,
	), "verifpal", false)
	switch m.Attacker {
	case "passive":
		verifyPassive(valKnowledgeMap, valPrincipalStates)
	case "active":
		verifyActive(valKnowledgeMap, valPrincipalStates)
	default:
		errorCritical(fmt.Sprintf("invalid attacker (%s)", m.Attacker))
	}
	fmt.Fprint(os.Stdout, "\n\n")
	return verifyEnd()
}

func verifyResolveQueries(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
) {
	valVerifyResults, _ := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if !verifyResult.Resolved {
			queryStart(verifyResult.Query, valKnowledgeMap, valPrincipalState)
		}
	}
}

func verifyStandardRun(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState, stage int) {
	var scanGroup sync.WaitGroup
	valAttackerState := attackerStateGetRead()
	for _, state := range valPrincipalStates {
		valPrincipalState := valueResolveAllPrincipalStateValues(state, valAttackerState)
		failedRewrites, _, valPrincipalState := valuePerformAllRewrites(valPrincipalState)
		sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites)
		for i := range valPrincipalState.Assigned {
			sanityCheckEquationGenerators(valPrincipalState.Assigned[i], valPrincipalState)
		}
		scanGroup.Add(1)
		go verifyAnalysis(valKnowledgeMap, valPrincipalState, stage, &scanGroup)
	}
	scanGroup.Wait()
}

func verifyPassive(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState) {
	InfoMessage("Attacker is configured as passive.", "info", false)
	phase := 0
	for phase <= valKnowledgeMap.MaxPhase {
		attackerStateInit(false)
		attackerStatePutPhaseUpdate(valPrincipalStates[0], phase)
		verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
		phase = phase + 1
	}
}

func verifyGetResultsCode(valVerifyResults []VerifyResult) string {
	resultsCode := ""
	for _, verifyResult := range valVerifyResults {
		q := ""
		r := ""
		switch verifyResult.Query.Kind {
		case "confidentiality":
			q = "c"
		case "authentication":
			q = "a"
		case "freshness":
			q = "f"
		case "unlinkability":
			q = "u"
		}
		switch verifyResult.Resolved {
		case true:
			r = "1"
		case false:
			r = "0"
		}
		resultsCode = fmt.Sprintf(
			"%s%s%s",
			resultsCode, q, r,
		)
	}
	return resultsCode
}

func verifyEnd() ([]VerifyResult, string) {
	valVerifyResults, fileName := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if verifyResult.Resolved {
			InfoMessage(fmt.Sprintf(
				"%s: %s",
				prettyQuery(verifyResult.Query),
				verifyResult.Summary,
			), "result", false)
		}
	}
	completed := time.Now().Format("03:04:05 PM")
	InfoMessage(fmt.Sprintf(
		"Verification completed for '%s' at %s.", fileName, completed,
	), "verifpal", false)
	InfoMessage("Thank you for using Verifpal.", "verifpal", false)
	return valVerifyResults, verifyGetResultsCode(valVerifyResults)
}
