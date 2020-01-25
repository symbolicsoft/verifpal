/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 9ce0b69bd06ba87ed5687886b0d1d56e

package verifpal

import (
	"fmt"
)

func queryStart(query query, valPrincipalState principalState, valKnowledgeMap knowledgeMap, valAttackerState attackerState) {
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
	i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.message.constants[0])
	if i < 0 {
		return
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
				pass, _ := possibleToRewrite(a.primitive, valPrincipalState)
				forcedPass := possibleToForceRewrite(a.primitive, valPrincipalState, valAttackerState)
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
		var mutated string
		if valPrincipalState.creator[ii] != query.message.recipient {
			continue
		}
		a := valPrincipalState.beforeRewrite[ii]
		cc := sanityResolveConstant(c, valPrincipalState)
		for i := range valPrincipalState.constants {
			if valPrincipalState.wasMutated[i] {
				mutated = fmt.Sprintf("%s\n           %s → %s (originally %s)", mutated,
					prettyConstant(valPrincipalState.constants[i]),
					prettyValue(valPrincipalState.assigned[i]),
					prettyValue(valPrincipalState.beforeMutate[i]),
				)
			}
		}
		if passes[f] && (query.message.sender != sender) {
			summary := prettyVerifyResultSummary(mutated, fmt.Sprintf(
				"%s, sent by %s and not by %s and resolving to %s, is successfully used in "+
					"primitive %s in %s's state.",
				prettyConstant(c), sender, query.message.sender,
				prettyValue(cc), prettyValue(a), query.message.recipient,
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
				prettyConstant(c), sender, prettyValue(cc), prettyValue(a), query.message.recipient,
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
