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
	ii := sanityEquivalentValueInValues(
		sanityResolveConstant(query.constant, valPrincipalState, false),
		&valAttackerState.known,
		valPrincipalState,
	)
	if ii < 0 {
		return verifyResult
	}
	verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
		"%s%s%s",
		prettyConstant(query.constant),
		" is obtained by the attacker as ",
		prettyValue(valAttackerState.known[ii]),
	), true)
	query.resolved = true
	verifyResult.query = query
	return verifyResult
}

func queryAuthentication(query query, valAttackerState *attackerState, valPrincipalState *principalState, valKnowledgeMap *knowledgeMap) verifyResult {
	var verifyResult verifyResult
	var indices []int
	var passes []bool
	var forcedPasses []bool
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
		a := valPrincipalState.assigned[ii]
		switch a.kind {
		case "constant":
			continue
		case "primitive":
			b := valPrincipalState.beforeMutate[ii]
			if !sanityFindConstantInPrimitive(c, b.primitive, valPrincipalState) {
				continue
			}
			if primitiveGet(a.primitive.name).rewrite.hasRule {
				pass, _ := possibleToPrimitivePassRewrite(a.primitive, valPrincipalState)
				forcedPass := possibleToPrimitiveForcePassRewrite(a.primitive, valPrincipalState, valAttackerState, 0, 0)
				if pass || forcedPass {
					indices = append(indices, ii)
					passes = append(passes, pass)
					forcedPasses = append(forcedPasses, forcedPass)
				}
			} else {
				indices = append(indices, ii)
				passes = append(passes, true)
				forcedPasses = append(forcedPasses, false)
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
		cc := sanityResolveConstant(c, valPrincipalState, true)
		if passes[f] && (query.message.sender != sender) {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and not by ",
				query.message.sender, " and resolving to ",
				prettyValue(cc),
				", is successfully used in primitive ", prettyValue(a),
				" in ", query.message.recipient, "'s state",
			), true)
			query.resolved = true
			verifyResult.query = query
			return verifyResult
		} else if forcedPasses[f] {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and resolving to ",
				prettyValue(cc),
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
