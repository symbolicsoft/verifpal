/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 9ce0b69bd06ba87ed5687886b0d1d56e

package verifpal

import (
	"fmt"
)

func queryStart(query query, valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState) {
	switch query.kind {
	case "confidentiality":
		queryConfidentiality(query, valPrincipalState, valAttackerState)
	case "authentication":
		queryAuthentication(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	}
}

func queryConfidentiality(query query, valPrincipalState principalState, valAttackerState attackerState) {
	var mutated string
	ii := sanityEquivalentValueInValues(
		sanityResolveConstant(query.constant, valPrincipalState),
		valAttackerState.known,
		valPrincipalState,
	)
	if ii < 0 {
		return
	}
	for i := range valPrincipalState.constants {
		if valPrincipalState.wasMutated[i] {
			mutated = fmt.Sprintf("%s\n           %s → %s (originally %s)", mutated,
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
	written := verifyResultsPutWrite(verifyResult{
		query:    query,
		resolved: true,
		summary:  summary,
	})
	if written {
		prettyMessage(fmt.Sprintf(
			"%s: %s", prettyQuery(query), summary,
		), "result")
	}
}

func queryAuthentication(query query, valKnowledgeMap knowledgeMap, valPrincipalState principalState, valAttackerState attackerState) {
	var indices []int
	var passes []bool
	var forcedPasses []bool
	if query.message.recipient != valPrincipalState.name {
		return
	}
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.message.constants[0])
	ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if ii < 0 {
		return
	}
	c := valKnowledgeMap.constants[i]
	sender := valPrincipalState.sender[ii]
	for iii := range valKnowledgeMap.constants {
		a := valKnowledgeMap.assigned[iii]
		switch a.kind {
		case "primitive":
			if !sanityFindConstantInPrimitive(c, a.primitive, valPrincipalState) {
				continue
			}
			iiii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, valKnowledgeMap.constants[iii])
			if iiii < 0 {
				return
			}
			b := valPrincipalState.beforeRewrite[iiii]
			if primitiveGet(b.primitive.name).rewrite.hasRule {
				pass, _ := possibleToRewrite(b.primitive, valPrincipalState)
				forcedPass := possibleToForceRewrite(b.primitive, valPrincipalState, valAttackerState)
				if pass || forcedPass {
					indices = append(indices, iiii)
					passes = append(passes, pass)
					forcedPasses = append(forcedPasses, forcedPass)
				}
			} else {
				indices = append(indices, iiii)
				passes = append(passes, true)
				forcedPasses = append(forcedPasses, false)
			}
		}
	}
	for f, index := range indices {
		var mutated string
		b := valPrincipalState.beforeRewrite[index]
		cc := sanityResolveConstant(c, valPrincipalState)
		for iii := range valPrincipalState.constants {
			if valPrincipalState.wasMutated[iii] {
				mutated = fmt.Sprintf("%s\n           %s → %s (originally %s)", mutated,
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
			written := verifyResultsPutWrite(verifyResult{
				query:    query,
				resolved: true,
				summary:  summary,
			})
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), summary,
				), "result")
			}
			return
		} else if forcedPasses[f] {
			summary := prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s, sent by %s and resolving to %s, is successfully used in primitive %s in "+
					"%s's state, despite it being vulnerable to tampering by Attacker.",
				prettyConstant(c), sender, prettyValue(cc), prettyValue(b), query.message.recipient,
			), true)
			written := verifyResultsPutWrite(verifyResult{
				query:    query,
				resolved: true,
				summary:  summary,
			})
			if written {
				prettyMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), summary,
				), "result")
			}
			return
		}
	}
}
