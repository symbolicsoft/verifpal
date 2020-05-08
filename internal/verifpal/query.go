/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 9ce0b69bd06ba87ed5687886b0d1d56e

package verifpal

import (
	"fmt"
)

func queryStart(
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) VerifyResult {
	switch query.Kind {
	case "confidentiality":
		return queryConfidentiality(query, valPrincipalState, valAttackerState)
	case "authentication":
		return queryAuthentication(query, valKnowledgeMap, valPrincipalState)
	case "freshness":
		return queryFreshness(query, valPrincipalState)
	case "unlinkability":
		return queryUnlinkability(query, valPrincipalState, valAttackerState)
	}
	errorCritical(fmt.Sprintf("invalid query kind (%s)", query.Kind))
	return VerifyResult{}
}

func queryConfidentiality(
	query Query, valPrincipalState PrincipalState,
	valAttackerState AttackerState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	v := sanityResolveConstant(query.Constants[0], valPrincipalState)
	ii := sanityEquivalentValueInValues(v, valAttackerState.Known)
	if ii < 0 {
		return result
	}
	mutatedInfo := queryGetMutatedInfo(valPrincipalState)
	result.Resolved = true
	result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s) is obtained by Attacker.",
		prettyConstant(query.Constants[0]),
		prettyValue(valAttackerState.Known[ii]),
	), result.Options)
	result = queryPrecondition(result, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		InfoMessage(fmt.Sprintf(
			"%s: %s", prettyQuery(query), result.Summary,
		), "result", true)
	}
	return result
}

func queryAuthentication(
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	if query.Message.Recipient != valPrincipalState.Name {
		return result
	}
	indices, passes, sender, c := queryAuthenticationGetPassIndices(
		query, valKnowledgeMap, valPrincipalState,
	)
	for f, index := range indices {
		b := valPrincipalState.BeforeRewrite[index]
		mutatedInfo := queryGetMutatedInfo(valPrincipalState)
		if passes[f] && (query.Message.Sender != sender) {
			result.Resolved = true
			result = queryPrecondition(result, valPrincipalState)
			return queryAuthenticationHandlePass(result, c, b, mutatedInfo, sender, valPrincipalState)
		}
	}
	return result
}

func queryAuthenticationGetPassIndices(
	query Query,
	valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
) ([]int, []bool, string, Constant) {
	indices := []int{}
	passes := []bool{}
	sender := ""
	c := Constant{}
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, query.Message.Constants[0])
	ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, query.Message.Constants[0])
	if ii < 0 {
		return indices, passes, sender, c
	}
	c = valKnowledgeMap.Constants[i]
	sender = valPrincipalState.Sender[ii]
	for iii := range valKnowledgeMap.Constants {
		hasRule := false
		a := valKnowledgeMap.Assigned[iii]
		if valKnowledgeMap.Creator[iii] != valPrincipalState.Name {
			continue
		}
		switch a.Kind {
		case "constant", "equation":
			continue
		}
		if !sanityFindConstantInPrimitive(c, a.Primitive, valPrincipalState) {
			continue
		}
		iiii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, valKnowledgeMap.Constants[iii])
		if iiii < 0 {
			return indices, passes, sender, c
		}
		b := valPrincipalState.BeforeRewrite[iiii]
		if primitiveIsCorePrim(b.Primitive.Name) {
			prim, _ := primitiveCoreGet(b.Primitive.Name)
			hasRule = prim.HasRule
		} else {
			prim, _ := primitiveGet(b.Primitive.Name)
			hasRule = prim.Rewrite.HasRule
		}
		if !hasRule {
			indices = append(indices, iiii)
			passes = append(passes, true)
			continue
		}
		pass, _ := possibleToRewrite(b.Primitive, valPrincipalState)
		if pass {
			indices = append(indices, iiii)
			passes = append(passes, pass)
		}
	}
	return indices, passes, sender, c
}

func queryAuthenticationHandlePass(
	result VerifyResult, c Constant, b Value, mutated string, sender string,
	valPrincipalState PrincipalState,
) VerifyResult {
	cc := sanityResolveConstant(c, valPrincipalState)
	result.Summary = infoVerifyResultSummary(mutated, fmt.Sprintf(
		"%s (%s), sent by %s and not by %s, is successfully used in %s within %s's state.",
		prettyConstant(c), prettyValue(cc), sender, result.Query.Message.Sender,
		prettyValue(b), result.Query.Message.Recipient,
	), result.Options)
	written := verifyResultsPutWrite(result)
	if written {
		InfoMessage(fmt.Sprintf(
			"%s: %s", prettyQuery(result.Query), result.Summary,
		), "result", true)
	}
	return result
}

func queryFreshness(
	query Query, valPrincipalState PrincipalState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	freshnessFound := queryFreshnessCheck(query.Constants[0], valPrincipalState)
	if freshnessFound {
		return result
	}
	mutatedInfo := queryGetMutatedInfo(valPrincipalState)
	result.Resolved = true
	result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s) is not a fresh value. If used as a message, it could be replayed, leading to potential replay attacks.",
		prettyConstant(query.Constants[0]),
		prettyValue(sanityResolveConstant(query.Constants[0], valPrincipalState)),
	), result.Options)
	result = queryPrecondition(result, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		InfoMessage(fmt.Sprintf(
			"%s: %s", prettyQuery(query), result.Summary,
		), "result", true)
	}
	return result
}

func queryFreshnessCheck(c Constant, valPrincipalState PrincipalState) bool {
	v := sanityResolveConstant(c, valPrincipalState)
	cc := sanityGetConstantsFromValue(v)
	for _, ccc := range cc {
		ii := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, ccc)
		if ii >= 0 {
			ccc = valPrincipalState.Constants[ii]
			if ccc.Fresh {
				return true
			}
		}
	}
	return false
}

/*
 * We're doing unlinkability in terms of *values*, not processes.
 * Unlinkability fails if:
 * - A value is non-fresh, or,
 * - Attacker can obtain a primitive that produces both values.
 * This definition of unlinkability on values is almost certainly
 * incomplete.
 */
func queryUnlinkability(
	query Query, valPrincipalState PrincipalState,
	valAttackerState AttackerState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	noFreshness := []Constant{}
	for _, c := range query.Constants {
		if !queryFreshnessCheck(c, valPrincipalState) {
			noFreshness = append(noFreshness, c)
		}
	}
	if len(noFreshness) > 0 {
		mutatedInfo := queryGetMutatedInfo(valPrincipalState)
		result.Resolved = true
		result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
			"%s (%s) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
			prettyConstant(noFreshness[0]),
			prettyValue(sanityResolveConstant(noFreshness[0], valPrincipalState)),
		), result.Options)
		result = queryPrecondition(result, valPrincipalState)
		written := verifyResultsPutWrite(result)
		if written {
			InfoMessage(fmt.Sprintf(
				"%s: %s", prettyQuery(query), result.Summary,
			), "result", true)
		}
		return result
	}
	constants := []Constant{}
	assigneds := []Value{}
	for _, c := range query.Constants {
		i := sanityGetPrincipalStateIndexFromConstant(valPrincipalState, c)
		constants = append(constants, c)
		assigneds = append(assigneds, valPrincipalState.Assigned[i])
	}
	for i, a := range assigneds {
		for ii, aa := range assigneds {
			if i == ii {
				continue
			}
			if !sanityEquivalentValues(a, aa, false) {
				continue
			}
			obtainable := false
			switch a.Kind {
			case "primitive":
				ok0, _ := possibleToReconstructPrimitive(a.Primitive, valAttackerState)
				ok1, _, _ := possibleToRecomposePrimitive(a.Primitive, valAttackerState)
				obtainable = ok0 || ok1
			}
			if !obtainable {
				continue
			}
			mutatedInfo := queryGetMutatedInfo(valPrincipalState)
			result.Resolved = true
			result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
				"%s and %s %s (%s), %s.",
				prettyConstant(constants[i]),
				prettyConstant(constants[ii]),
				"are not unlinkable since they are the output of the same primitive",
				prettyValue(a),
				"which can be obtained by Attacker",
			), result.Options)
			result = queryPrecondition(result, valPrincipalState)
			written := verifyResultsPutWrite(result)
			if written {
				InfoMessage(fmt.Sprintf(
					"%s: %s", prettyQuery(query), result.Summary,
				), "result", true)
			}
			return result
		}
	}
	return result
}

func queryPrecondition(
	result VerifyResult, valPrincipalState PrincipalState,
) VerifyResult {
	if !result.Resolved {
		return result
	}
	for _, option := range result.Query.Options {
		oResult := QueryOptionResult{
			Option:   option,
			Resolved: false,
			Summary:  "",
		}
		sender := ""
		recipientKnows := false
		i := sanityGetPrincipalStateIndexFromConstant(
			valPrincipalState, option.Message.Constants[0],
		)
		if i < 0 {
			result.Options = append(result.Options, oResult)
			continue
		}
		for _, m := range valPrincipalState.KnownBy[i] {
			if s, ok := m[option.Message.Recipient]; ok {
				sender = s
				recipientKnows = true
				break
			}
		}
		if sender == option.Message.Sender && recipientKnows {
			oResult.Resolved = true
			oResult.Summary = fmt.Sprintf(
				"%s sends %s to %s despite the query being contradicted.",
				option.Message.Sender,
				prettyConstant(option.Message.Constants[0]),
				option.Message.Recipient,
			)
		}
		result.Options = append(result.Options, oResult)
	}
	return result
}

func queryGetMutatedInfo(valPrincipalState PrincipalState) string {
	mutatedInfo := ""
	for i := range valPrincipalState.Constants {
		if !valPrincipalState.Mutated[i] {
			continue
		}
		mutatedInfo = fmt.Sprintf("%s\n%s%s → %s (originally %s)",
			mutatedInfo, "           ",
			prettyConstant(valPrincipalState.Constants[i]),
			prettyValue(valPrincipalState.Assigned[i]),
			prettyValue(valPrincipalState.BeforeMutate[i]),
		)
	}
	return mutatedInfo
}
