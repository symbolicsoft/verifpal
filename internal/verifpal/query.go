/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 9ce0b69bd06ba87ed5687886b0d1d56e

package verifpal

import (
	"fmt"
)

func queryStart(
	query query, valKnowledgeMap knowledgeMap,
	valPrincipalState principalState, valAttackerState attackerState,
) verifyResult {
	switch query.kind {
	case "confidentiality":
		return queryConfidentiality(query, valPrincipalState, valAttackerState)
	case "authentication":
		return queryAuthentication(query, valKnowledgeMap, valPrincipalState)
	case "freshness":
		return queryFreshness(query, valPrincipalState)
	case "unlinkability":
		return queryUnlinkability(query, valPrincipalState, valAttackerState)
	}
	errorCritical(fmt.Sprintf("invalid query kind (%s)", query.kind))
	return verifyResult{}
}

func queryConfidentiality(
	query query, valPrincipalState principalState,
	valAttackerState attackerState,
) verifyResult {
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
		options:  []queryOptionResult{},
	}
	v := sanityResolveConstant(query.constants[0], valPrincipalState)
	ii := sanityEquivalentValueInValues(v, valAttackerState.known)
	if ii < 0 {
		return result
	}
	mutatedInfo := queryGetMutatedInfo(valPrincipalState)
	result.resolved = true
	result.summary = prettyVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s) is obtained by Attacker.",
		prettyConstant(query.constants[0]),
		prettyValue(valAttackerState.known[ii]),
	), result.options, true)
	result = queryPrecondition(result, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		PrettyInfo(fmt.Sprintf(
			"%s: %s", prettyQuery(query), result.summary,
		), "result", true)
	}
	return result
}

func queryAuthentication(
	query query, valKnowledgeMap knowledgeMap,
	valPrincipalState principalState,
) verifyResult {
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
		options:  []queryOptionResult{},
	}
	if query.message.recipient != valPrincipalState.name {
		return result
	}
	indices, passes, sender, c := queryAuthenticationGetPassIndices(
		query, valKnowledgeMap, valPrincipalState,
	)
	for f, index := range indices {
		b := valPrincipalState.beforeRewrite[index]
		mutatedInfo := queryGetMutatedInfo(valPrincipalState)
		if passes[f] && (query.message.sender != sender) {
			result.resolved = true
			result = queryPrecondition(result, valPrincipalState)
			return queryAuthenticationHandlePass(result, c, b, mutatedInfo, sender, valPrincipalState)
		}
	}
	return result
}

func queryAuthenticationGetPassIndices(
	query query,
	valKnowledgeMap knowledgeMap, valPrincipalState principalState,
) ([]int, []bool, string, constant) {
	indices := []int{}
	passes := []bool{}
	sender := ""
	c := constant{}
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.message.constants[0])
	ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if ii < 0 {
		return indices, passes, sender, c
	}
	c = valKnowledgeMap.constants[i]
	sender = valPrincipalState.sender[ii]
	for iii := range valKnowledgeMap.constants {
		hasRule := false
		a := valKnowledgeMap.assigned[iii]
		if valKnowledgeMap.creator[iii] != valPrincipalState.name {
			continue
		}
		switch a.kind {
		case "constant", "equation":
			continue
		}
		if !sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
			continue
		}
		iiii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, valKnowledgeMap.constants[iii])
		if iiii < 0 {
			return indices, passes, sender, c
		}
		b := valPrincipalState.beforeRewrite[iiii]
		if primitiveIsCorePrim(b.primitive.name) {
			prim, _ := primitiveCoreGet(b.primitive.name)
			hasRule = prim.hasRule
		} else {
			prim, _ := primitiveGet(b.primitive.name)
			hasRule = prim.rewrite.hasRule
		}
		if !hasRule {
			indices = append(indices, iiii)
			passes = append(passes, true)
			continue
		}
		pass, _ := possibleToRewrite(b.primitive, valPrincipalState)
		if pass {
			indices = append(indices, iiii)
			passes = append(passes, pass)
		}
	}
	return indices, passes, sender, c
}

func queryAuthenticationHandlePass(
	result verifyResult, c constant, b value, mutated string, sender string,
	valPrincipalState principalState,
) verifyResult {
	cc := sanityResolveConstant(c, valPrincipalState)
	result.summary = prettyVerifyResultSummary(mutated, fmt.Sprintf(
		"%s (%s), sent by %s and not by %s, is successfully used in %s within %s's state.",
		prettyConstant(c), prettyValue(cc), sender, result.query.message.sender,
		prettyValue(b), result.query.message.recipient,
	), result.options, true)
	written := verifyResultsPutWrite(result)
	if written {
		PrettyInfo(fmt.Sprintf(
			"%s: %s", prettyQuery(result.query), result.summary,
		), "result", true)
	}
	return result
}

func queryFreshness(
	query query, valPrincipalState principalState,
) verifyResult {
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
		options:  []queryOptionResult{},
	}

	v := sanityResolveConstant(query.constants[0], valPrincipalState)
	c := sanityGetConstantsFromValue(v)
	for _, cc := range c {
		fmt.Println(prettyConstant(cc))
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, cc)
		if ii >= 0 {
			cc = valPrincipalState.constants[ii]
			if cc.declaration == "generates" {
				return result
			}
		}
	}
	mutatedInfo := queryGetMutatedInfo(valPrincipalState)
	result.resolved = true
	result.summary = prettyVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s) is not a fresh value. If used as a message, it could be replayed, leading to potential replay attacks.",
		prettyConstant(query.constants[0]),
		prettyValue(v),
	), result.options, true)
	result = queryPrecondition(result, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		PrettyInfo(fmt.Sprintf(
			"%s: %s", prettyQuery(query), result.summary,
		), "result", true)
	}
	return result
}

func queryUnlinkability(
	query query, valPrincipalState principalState,
	valAttackerState attackerState,
) verifyResult {
	/*
	 * We're doing unlinkability in terms of *values*, not processes
	 */
	return verifyResult{}
}

func queryPrecondition(
	result verifyResult, valPrincipalState principalState,
) verifyResult {
	if !result.resolved {
		return result
	}
	for _, option := range result.query.options {
		oResult := queryOptionResult{
			option:   option,
			resolved: false,
			summary:  "",
		}
		sender := ""
		recipientKnows := false
		i := sanityGetPrincipalStateIndexFromConstant(
			valPrincipalState, option.message.constants[0],
		)
		if i < 0 {
			result.options = append(result.options, oResult)
			continue
		}
		for _, m := range valPrincipalState.knownBy[i] {
			if s, ok := m[option.message.recipient]; ok {
				sender = s
				recipientKnows = true
				break
			}
		}
		if sender == option.message.sender && recipientKnows {
			oResult.resolved = true
			oResult.summary = fmt.Sprintf(
				"%s sends %s to %s despite the query being contradicted.",
				option.message.sender,
				prettyConstant(option.message.constants[0]),
				option.message.recipient,
			)
		}
		result.options = append(result.options, oResult)
	}
	return result
}

func queryGetMutatedInfo(valPrincipalState principalState) string {
	mutatedInfo := ""
	for i := range valPrincipalState.constants {
		if !valPrincipalState.mutated[i] {
			continue
		}
		mutatedInfo = fmt.Sprintf("%s\n%s%s → %s (originally %s)",
			mutatedInfo, "           ",
			prettyConstant(valPrincipalState.constants[i]),
			prettyValue(valPrincipalState.assigned[i]),
			prettyValue(valPrincipalState.beforeMutate[i]),
		)
	}
	return mutatedInfo
}
