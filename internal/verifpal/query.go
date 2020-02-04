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
	var result verifyResult
	switch query.kind {
	case "confidentiality":
		result = queryConfidentiality(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	case "authentication":
		result = queryAuthentication(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	}
	return result
}

func queryConfidentiality(
	query query, valKnowledgeMap knowledgeMap,
	valPrincipalState principalState, valAttackerState attackerState,
) verifyResult {
	var mutated string
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
		options:  []queryOptionResult{},
	}
	ii := sanityEquivalentValueInValues(
		sanityResolveConstant(query.constant, valPrincipalState),
		valAttackerState.known,
		valPrincipalState,
	)
	if ii < 0 {
		return result
	}
	for i := range valPrincipalState.constants {
		if valPrincipalState.wasMutated[i] {
			mutated = fmt.Sprintf("%s\n%s%s → %s (originally %s)",
				mutated, "           ",
				prettyConstant(valPrincipalState.constants[i]),
				prettyValue(valPrincipalState.assigned[i]),
				prettyValue(valPrincipalState.beforeMutate[i]),
			)
		}
	}
	summary := prettyVerifyResultSummary(mutated, fmt.Sprintf(
		"%s (%s) is obtained by Attacker.",
		prettyConstant(query.constant),
		prettyValue(valAttackerState.known[ii]),
	), result.options, true)
	result = verifyResult{
		query:    query,
		resolved: true,
		summary:  summary,
		options:  []queryOptionResult{},
	}
	result = queryPrecondition(result, valKnowledgeMap, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		prettyMessage(fmt.Sprintf(
			"%s: %s", prettyQuery(query), summary,
		), "result", true)
	}
	return result
}

func queryAuthentication(
	query query, valKnowledgeMap knowledgeMap,
	valPrincipalState principalState, valAttackerState attackerState,
) verifyResult {
	var indices []int
	var passes []bool
	var forcedPasses []bool
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
		options:  []queryOptionResult{},
	}
	if query.message.recipient != valPrincipalState.name {
		return result
	}
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.message.constants[0])
	ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if ii < 0 {
		return result
	}
	c := valKnowledgeMap.constants[i]
	sender := valPrincipalState.sender[ii]
	for iii := range valKnowledgeMap.constants {
		a := valKnowledgeMap.assigned[iii]
		if valKnowledgeMap.creator[iii] != valPrincipalState.name {
			continue
		}
		switch a.kind {
		case "primitive":
			if !sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
				continue
			}
			iiii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, valKnowledgeMap.constants[iii])
			if iiii < 0 {
				return result
			}
			b := valPrincipalState.beforeRewrite[iiii]
			if !primitiveGet(b.primitive.name).rewrite.hasRule {
				indices = append(indices, iiii)
				passes = append(passes, true)
				forcedPasses = append(forcedPasses, false)
				continue
			}
			pass, _ := possibleToRewrite(b.primitive, valPrincipalState)
			forcedPass := possibleToForceRewrite(b.primitive, valPrincipalState, valAttackerState)
			if pass || forcedPass {
				indices = append(indices, iiii)
				passes = append(passes, pass)
				forcedPasses = append(forcedPasses, forcedPass)
			}
		}
	}
	for f, index := range indices {
		var mutated string
		b := valPrincipalState.beforeRewrite[index]
		cc := sanityResolveConstant(c, valPrincipalState)
		for iii := range valPrincipalState.constants {
			if valPrincipalState.wasMutated[iii] {
				mutated = fmt.Sprintf("%s\n%s%s → %s (originally %s)",
					mutated, "           ",
					prettyConstant(valPrincipalState.constants[iii]),
					prettyValue(valPrincipalState.assigned[iii]),
					prettyValue(valPrincipalState.beforeMutate[iii]),
				)
			}
		}
		if passes[f] && (query.message.sender != sender) {
			result = verifyResult{
				query:    query,
				resolved: true,
				summary:  "",
				options:  []queryOptionResult{},
			}
			result = queryPrecondition(result, valKnowledgeMap, valPrincipalState)
			result.summary = prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s (%s), sent by %s and not by %s, is successfully used in %s within %s's state.",
				prettyConstant(c), prettyValue(cc), sender, query.message.sender,
				prettyValue(b), query.message.recipient,
			), result.options, true)
			written := verifyResultsPutWrite(result)
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), result.summary,
				), "result", true)
			}
			return result
		} else if forcedPasses[f] {
			result = verifyResult{
				query:    query,
				resolved: true,
				summary:  "",
				options:  []queryOptionResult{},
			}
			result = queryPrecondition(result, valKnowledgeMap, valPrincipalState)
			result.summary = prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s (%s), sent by %s, is successfully used in %s within %s's state, despite being vulnerable to tampering.",
				prettyConstant(c), prettyValue(cc), sender, prettyValue(b), query.message.recipient,
			), result.options, true)
			written := verifyResultsPutWrite(result)
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), result.summary,
				), "result", true)
			}
			return result
		}
	}
	return result
}

func queryPrecondition(
	result verifyResult,
	valKnowledgeMap knowledgeMap, valPrincipalState principalState,
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
		var sender string
		recipientKnows := false
		i := sanityGetPrincipalStateIndexFromConstant(
			valPrincipalState, option.message.constants[0],
		)
		if i < 0 {
			result.options = append(result.options, oResult)
			continue
		}
		for _, m := range valKnowledgeMap.knownBy[i] {
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
