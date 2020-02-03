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
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
	}
	switch query.kind {
	case "confidentiality":
		result = queryConfidentiality(query, valPrincipalState, valAttackerState)
	case "authentication":
		result = queryAuthentication(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	}
	return result
}

func queryConfidentiality(
	query query,
	valPrincipalState principalState, valAttackerState attackerState,
) verifyResult {
	var mutated string
	result := verifyResult{
		query:    query,
		resolved: false,
		summary:  "",
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
		"%s is obtained by the attacker as %s",
		prettyConstant(query.constant),
		prettyValue(valAttackerState.known[ii]),
	), true)
	result = verifyResult{
		query:    query,
		resolved: true,
		summary:  summary,
	}
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
			summary := prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s, sent by %s and not by %s and resolving to %s, is successfully used in "+
					"primitive %s in %s's state.",
				prettyConstant(c), sender, query.message.sender,
				prettyValue(cc), prettyValue(b), query.message.recipient,
			), true)
			result = verifyResult{
				query:    query,
				resolved: true,
				summary:  summary,
			}
			written := verifyResultsPutWrite(result)
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), summary,
				), "result", true)
			}
			return result
		} else if forcedPasses[f] {
			summary := prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s, sent by %s and resolving to %s, is successfully used in primitive %s in "+
					"%s's state, despite it being vulnerable to tampering by Attacker.",
				prettyConstant(c), sender, prettyValue(cc), prettyValue(b), query.message.recipient,
			), true)
			result = verifyResult{
				query:    query,
				resolved: true,
				summary:  summary,
			}
			written := verifyResultsPutWrite(result)
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), summary,
				), "result", true)
			}
			return result
		}
	}
	return result
}
