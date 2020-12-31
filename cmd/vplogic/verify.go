/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 458871bd68906e9965785ac87c2708ec

package vplogic

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Verify runs the main verification engine for Verifpal on a model loaded from a file.
// It returns a slice of verifyResults and a "results code".
func Verify(filePath string) ([]VerifyResult, string, error) {
	/*
		f, _ := os.Create("cpu.pprof")
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	*/
	m, err := libpegParseModel(filePath, true)
	if err != nil {
		return []VerifyResult{}, "", err
	}
	return verifyModel(m)
}

func verifyModel(m Model) ([]VerifyResult, string, error) {
	valKnowledgeMap, valPrincipalStates, err := sanity(m)
	if err != nil {
		return []VerifyResult{}, "", err
	}
	initiated := time.Now().Format("03:04:05 PM")
	verifyAnalysisCountInit()
	verifyResultsInit(m)
	InfoMessage(fmt.Sprintf(
		"Verification initiated for '%s' at %s.", m.FileName, initiated,
	), "verifpal", false)
	switch m.Attacker {
	case "passive":
		err := verifyPassive(valKnowledgeMap, valPrincipalStates)
		if err != nil {
			return []VerifyResult{}, "", err
		}
	case "active":
		err := verifyActive(valKnowledgeMap, valPrincipalStates)
		if err != nil {
			return []VerifyResult{}, "", err
		}
	default:
		return []VerifyResult{}, "", fmt.Errorf("invalid attacker (%s)", m.Attacker)
	}
	return verifyEnd(m)
}

func verifyResolveQueries(
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
) error {
	valVerifyResults, _ := verifyResultsGetRead()
	for _, verifyResult := range valVerifyResults {
		if !verifyResult.Resolved {
			err := queryStart(verifyResult.Query, valKnowledgeMap, valPrincipalState)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyStandardRun(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState, stage int) error {
	var scanGroup sync.WaitGroup
	valAttackerState := attackerStateGetRead()
	for _, state := range valPrincipalStates {
		valPrincipalState, err := valueResolveAllPrincipalStateValues(state, valAttackerState)
		if err != nil {
			return err
		}
		for _, a := range valPrincipalState.Assigned {
			switch a.Kind {
			case typesEnumPrimitive:
				injectMissingSkeletons(a.Primitive, valPrincipalState, valAttackerState)
			}
		}
		failedRewrites, _, valPrincipalState := valuePerformAllRewrites(valPrincipalState)
		err = sanityFailOnFailedCheckedPrimitiveRewrite(failedRewrites)
		if err != nil {
			return err
		}
		for i := range valPrincipalState.Assigned {
			err = sanityCheckEquationGenerators(valPrincipalState.Assigned[i], valPrincipalState)
			if err != nil {
				return err
			}
		}
		scanGroup.Add(1)
		err = verifyAnalysis(valKnowledgeMap, valPrincipalState, valAttackerState, stage, &scanGroup)
		if err != nil {
			return err
		}
		scanGroup.Wait()
		err = verifyResolveQueries(valKnowledgeMap, valPrincipalState)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyPassive(valKnowledgeMap KnowledgeMap, valPrincipalStates []PrincipalState) error {
	InfoMessage("Attacker is configured as passive.", "info", false)
	phase := 0
	for phase <= valKnowledgeMap.MaxPhase {
		attackerStateInit(false)
		err := attackerStatePutPhaseUpdate(valPrincipalStates[0], phase)
		if err != nil {
			return err
		}
		err = verifyStandardRun(valKnowledgeMap, valPrincipalStates, 0)
		if err != nil {
			return err
		}
		phase = phase + 1
	}
	return nil
}

func verifyGetResultsCode(valVerifyResults []VerifyResult) string {
	resultsCode := ""
	for _, verifyResult := range valVerifyResults {
		q := ""
		r := ""
		switch verifyResult.Query.Kind {
		case typesEnumConfidentiality:
			q = "c"
		case typesEnumAuthentication:
			q = "a"
		case typesEnumFreshness:
			q = "f"
		case typesEnumUnlinkability:
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

func verifyEnd(m Model) ([]VerifyResult, string, error) {
	var err error
	valVerifyResults, fileName := verifyResultsGetRead()
	noResolved := true
	for _, verifyResult := range valVerifyResults {
		if verifyResult.Resolved {
			noResolved = false
			break
		}
	}
	fmt.Fprint(os.Stdout, "\n\n")
	InfoMessage(fmt.Sprintf(
		"Verification completed for '%s' at %s.",
		fileName, time.Now().Format("03:04:05 PM"),
	), "verifpal", false)
	if noResolved {
		InfoMessage("All queries pass.", "verifpal", false)
	} else {
		InfoMessage("Summary of failed queries will follow.", "verifpal", false)
	}
	fmt.Fprint(os.Stdout, "\n")
	for _, verifyResult := range valVerifyResults {
		if verifyResult.Resolved {
			InfoMessage(fmt.Sprintf("%s — %s",
				prettyQuery(verifyResult.Query), verifyResult.Summary,
			), "result", false)
		}
	}
	InfoMessage("Thank you for using Verifpal.", "verifpal", false)
	resultsCode := verifyGetResultsCode(valVerifyResults)
	if VerifHubScheduledShared {
		err = VerifHub(m, fileName, resultsCode)
	}
	return valVerifyResults, resultsCode, err
}
