/*
 * SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

// 9ce0b69bd06ba87ed5687886b0d1d56e

package main

import (
	"fmt"
)

func queryStart(query query, valAttackerState *attackerState, valPrincipalState *principalState, valKnowledgeMap *knowledgeMap) verifyResult {
	switch query.kind {
	case "confidentiality":
		return queryConfidentiality(query, valAttackerState, valPrincipalState)
	case "authentication":
		return queryAuthentication(query, valAttackerState, valPrincipalState, valKnowledgeMap)
	}
	return verifyResult{}
}

func queryConfidentiality(query query, valAttackerState *attackerState, valPrincipalState *principalState) verifyResult {
	var verifyResult verifyResult
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.constant)
	if i < 0 {
		return verifyResult
	}
	ii := sanityValueInValues(sanityResolveConstant(valPrincipalState, query.constant, false), &valAttackerState.known, valPrincipalState)
	if ii >= 0 {
		verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
			"%s%s%s",
			prettyConstant(query.constant),
			" is obtained by the attacker as ",
			prettyValue(valAttackerState.known[ii]),
		), true)
		query.resolved = true
	}
	verifyResult.query = query
	return verifyResult
}

func queryAuthentication(query query, valAttackerState *attackerState, valPrincipalState *principalState, valKnowledgeMap *knowledgeMap) verifyResult {
	var verifyResult verifyResult
	var indices []int
	var forcedPass []bool
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if i < 0 {
		return verifyResult
	}
	if query.message.recipient != valPrincipalState.name {
		return verifyResult
	}
	c := valPrincipalState.constants[i]
	sender := valPrincipalState.sender[i]
	for ii := range valPrincipalState.constants {
		a := valPrincipalState.beforeRewrite[ii]
		switch a.kind {
		case "constant":
			continue
		case "primitive":
			p := primitiveGet(a.primitive.name)
			if !sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
				continue
			}
			if !p.check {
				indices = append(indices, ii)
				forcedPass = append(forcedPass, p.rewrite.hasRule)
				continue
			}
			pass, _ := possibleToPrimitivePassRewrite(a.primitive, valPrincipalState)
			if pass {
				indices = append(indices, ii)
				forcedPass = append(forcedPass, false)
				continue
			}
			pass = possibleToPrimitiveForcePassRewrite(a.primitive, valPrincipalState, valAttackerState, 0, 0)
			if pass {
				indices = append(indices, ii)
				forcedPass = append(forcedPass, true)
			}
		case "equation":
			continue
		}
	}
	for f, ii := range indices {
		if valPrincipalState.creator[ii] != query.message.recipient {
			continue
		}
		a := valPrincipalState.beforeRewrite[ii]
		if query.message.sender != sender && !forcedPass[f] {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and not by ",
				query.message.sender, " and resolving to ",
				prettyValue(sanityResolveConstant(valPrincipalState, c, false)),
				", is successfully used in primitive ", prettyValue(a),
				" in ", query.message.recipient, "'s state",
			), true)
			query.resolved = true
			verifyResult.query = query
			return verifyResult
		} else if forcedPass[f] && !valPrincipalState.guard[i] {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and resolving to ",
				prettyValue(sanityResolveConstant(valPrincipalState, c, false)),
				", is successfully used in primitive ", prettyValue(a),
				" in ", query.message.recipient, "'s state, ",
				"despite it being vulnerable to tampering by Attacker",
			), true)
			query.resolved = true
			verifyResult.query = query
			return verifyResult
		}
	}
	verifyResult.query = query
	return verifyResult
}
