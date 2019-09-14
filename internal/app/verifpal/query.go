/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
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
	var passes []bool
	var forcedPasses []bool
	var rewrites []value
	var forcedRewrites []value
	if query.message.recipient != valPrincipalState.name {
		return verifyResult
	}
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if i < 0 {
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
			if !sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
				continue
			}
			if primitiveGet(a.primitive.name).rewrite.hasRule {
				pass, rewrite := possibleToPrimitivePassRewrite(a.primitive, valPrincipalState)
				forcedPass := possibleToPrimitiveForcePassRewrite(a.primitive, valPrincipalState, valAttackerState, 0, 0)
				if pass || forcedPass {
					indices = append(indices, ii)
					passes = append(forcedPasses, pass)
					forcedPasses = append(forcedPasses, forcedPass)
					rewrites = append(rewrites, rewrite)
					forcedRewrites = append(forcedRewrites, a)
				}
			} else {
				indices = append(indices, ii)
				passes = append(passes, true)
				forcedPasses = append(forcedPasses, false)
				rewrites = append(rewrites, sanityResolveConstant(valPrincipalState, c, false))
				forcedRewrites = append(forcedRewrites, sanityResolveConstant(valPrincipalState, c, false))
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
		if query.message.sender != sender && passes[f] {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and not by ",
				query.message.sender, " and resolving to ",
				prettyValue(rewrites[f]),
				", is successfully used in primitive ", prettyValue(a),
				" in ", query.message.recipient, "'s state",
			), true)
			query.resolved = true
			verifyResult.query = query
			return verifyResult
		} else if !valPrincipalState.guard[i] && forcedPasses[f] {
			a, _ = sanityResolveInternalValues(a, valPrincipalState, false)
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and resolving to ",
				prettyValue(forcedRewrites[f]),
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
