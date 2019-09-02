/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

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
	ii := sanityValueInValues(valPrincipalState.assigned[i], &valAttackerState.known, valPrincipalState)
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
	var checkIndices []int
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if i < 0 {
		return verifyResult
	}
	c := valPrincipalState.constants[i]
	recipientKnows := valPrincipalState.known[i]
	sender := valPrincipalState.sender[i]
	if !recipientKnows {
		verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
			"%s%s%s%s",
			prettyConstant(c), " is not known by ",
			query.message.recipient, ", query cannot be evaluated",
		), true)
		query.resolved = true
		verifyResult.query = query
		return verifyResult
	}
	for ii := range valPrincipalState.constants {
		a := valPrincipalState.beforeRewrite[ii]
		switch a.kind {
		case "constant":
			continue
		case "primitive":
			checkIndexFound := sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState)
			if checkIndexFound {
				checkIndices = append(checkIndices, ii)
			}
		case "equation":
			continue
		}
	}
	for _, ii := range checkIndices {
		a := valPrincipalState.beforeRewrite[ii]
		if query.message.sender != sender {
			verifyResult.summary = prettyVerifyResultSummary(fmt.Sprintf(
				"%s%s%s%s%s%s%s%s%s%s%s%s",
				prettyConstant(c), ", sent by ", sender, " and not by ",
				query.message.sender, " and resolving to ",
				prettyValue(valPrincipalState.assigned[i]),
				", is used in primitive ", prettyValue(a),
				" in ", query.message.recipient, "'s state",
			), true)
			query.resolved = true
			verifyResult.query = query
			return verifyResult
		}
	}
	verifyResult.query = query
	return verifyResult
}
