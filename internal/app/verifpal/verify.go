/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

// 458871bd68906e9965785ac87c2708ec

package main

import (
	"fmt"
	"time"
)

func verify(model *verifpal, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) []verifyResult {
	var verifyResults []verifyResult
	prettyMessage(fmt.Sprintf(
		"verification initiated at %s",
		time.Now().Format("15:04:05"),
	), 0, 0, "verifpal")
	if model.attacker == "passive" {
		verifyResults = verifyPassive(model, valKnowledgeMap, valPrincipalStates)
	} else if model.attacker == "active" {
		verifyResults = verifyActive(model, valKnowledgeMap, valPrincipalStates)
	} else {
		errorCritical("invalid attacker")
	}
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
	return verifyResults
}

func verifyResolveQueries(
	model *verifpal, valKnowledgeMap *knowledgeMap, valPrincipalState *principalState, valAttackerState *attackerState,
	verifyResults []verifyResult, analysis int,
) []verifyResult {
	for q, query := range model.queries {
		if !model.queries[q].resolved {
			verifyResult := queryStart(query, valAttackerState, valPrincipalState, valKnowledgeMap)
			if verifyResult.query.resolved {
				model.queries[q].resolved = true
				verifyResults = append(verifyResults, verifyResult)
				prettyMessage(verifyResult.summary, analysis, 0, "result")
			}
		}
	}
	return verifyResults
}
