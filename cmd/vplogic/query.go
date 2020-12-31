/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 9ce0b69bd06ba87ed5687886b0d1d56e

package vplogic

import (
	"fmt"
)

func queryStart(
	query Query, valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
) error {
	valAttackerState := attackerStateGetRead()
	var err error
	switch query.Kind {
	case typesEnumConfidentiality:
		queryConfidentiality(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	case typesEnumAuthentication:
		queryAuthentication(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	case typesEnumFreshness:
		_, err = queryFreshness(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	case typesEnumUnlinkability:
		_, err = queryUnlinkability(query, valKnowledgeMap, valPrincipalState, valAttackerState)
	}
	return err
}

func queryConfidentiality(
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	v, _ := valueResolveValueInternalValuesFromKnowledgeMap(Value{
		Kind:     typesEnumConstant,
		Constant: query.Constants[0],
	}, valKnowledgeMap)
	ii := valueEquivalentValueInValues(v, valAttackerState.Known)
	if ii < 0 {
		return result
	}
	mutatedInfo := infoQueryMutatedValues(
		valKnowledgeMap, valAttackerState.PrincipalState[ii], valAttackerState, v,
	)
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
			"%s — %s", prettyQuery(query), result.Summary,
		), "result", true)
	}
	return result
}

func queryAuthentication(
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) VerifyResult {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	if query.Message.Recipient != valPrincipalState.ID {
		return result
	}
	indices, sender, c := queryAuthenticationGetPassIndices(
		query, valKnowledgeMap, valPrincipalState,
	)
	for _, index := range indices {
		if query.Message.Sender == sender {
			continue
		}
		result.Resolved = true
		a := valPrincipalState.Assigned[index]
		b := valPrincipalState.BeforeRewrite[index]
		mutatedInfo := infoQueryMutatedValues(
			valKnowledgeMap, valPrincipalState, valAttackerState, a,
		)
		result = queryPrecondition(result, valPrincipalState)
		return queryAuthenticationHandlePass(
			result, c, b, mutatedInfo, sender, valPrincipalState,
		)
	}
	return result
}

func queryAuthenticationGetPassIndices(
	query Query, valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState,
) ([]int, principalEnum, Constant) {
	indices := []int{}
	_, i := valueResolveConstant(query.Message.Constants[0], valPrincipalState)
	if i < 0 {
		return indices, 0, Constant{}
	}
	c := valKnowledgeMap.Constants[i]
	sender := valPrincipalState.Sender[i]
	if sender == principalNamesMap["Attacker"] {
		v := valPrincipalState.BeforeMutate[i]
		if valueEquivalentValues(&v, &valPrincipalState.Assigned[i], true) {
			return indices, sender, c
		}
	}
	for iii := range valKnowledgeMap.Constants {
		if valKnowledgeMap.Creator[iii] != valPrincipalState.ID {
			continue
		}
		hasRule := false
		a := valKnowledgeMap.Assigned[iii]
		switch a.Kind {
		case typesEnumConstant, typesEnumEquation:
			continue
		}
		if !valueFindConstantInPrimitive(c, a, valKnowledgeMap) {
			continue
		}
		_, iiii := valueResolveConstant(valKnowledgeMap.Constants[iii], valPrincipalState)
		if iiii < 0 {
			return indices, sender, c
		}
		b := valPrincipalState.BeforeRewrite[iiii]
		if primitiveIsCorePrim(b.Primitive.ID) {
			prim, _ := primitiveCoreGet(b.Primitive.ID)
			hasRule = prim.HasRule
		} else {
			prim, _ := primitiveGet(b.Primitive.ID)
			hasRule = prim.Rewrite.HasRule
		}
		if !hasRule {
			indices = append(indices, iiii)
			continue
		}
		pass, _ := possibleToRewrite(b.Primitive, valPrincipalState)
		if pass {
			indices = append(indices, iiii)
		}
	}
	return indices, sender, c
}

func queryAuthenticationHandlePass(
	result VerifyResult, c Constant, b Value, mutatedInfo string, sender principalEnum,
	valPrincipalState PrincipalState,
) VerifyResult {
	cc, _ := valueResolveConstant(c, valPrincipalState)
	result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s), sent by %s and not by %s, is successfully used in %s within %s's state.",
		prettyConstant(c), prettyValue(cc), principalGetNameFromID(sender),
		principalGetNameFromID(result.Query.Message.Sender),
		prettyValue(b), principalGetNameFromID(result.Query.Message.Recipient),
	), result.Options)
	written := verifyResultsPutWrite(result)
	if written {
		InfoMessage(fmt.Sprintf(
			"%s — %s", prettyQuery(result.Query), result.Summary,
		), "result", true)
	}
	return result
}

func queryFreshness(
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) (VerifyResult, error) {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	indices := []int{}
	freshnessFound, err := valueContainsFreshValues(Value{
		Kind:     typesEnumConstant,
		Constant: query.Constants[0],
	}, query.Constants[0], valPrincipalState, valAttackerState)
	if err != nil {
		return result, err
	}
	if freshnessFound {
		return result, nil
	}
	for i := range valKnowledgeMap.Constants {
		if valKnowledgeMap.Creator[i] != valPrincipalState.ID {
			continue
		}
		hasRule := false
		a := valKnowledgeMap.Assigned[i]
		switch a.Kind {
		case typesEnumConstant, typesEnumEquation:
			continue
		}
		if !valueFindConstantInPrimitive(query.Constants[0], a, valKnowledgeMap) {
			continue
		}
		_, ii := valueResolveConstant(valKnowledgeMap.Constants[i], valPrincipalState)
		if ii < 0 {
			return result, nil
		}
		b := valPrincipalState.BeforeRewrite[ii]
		if primitiveIsCorePrim(b.Primitive.ID) {
			prim, _ := primitiveCoreGet(b.Primitive.ID)
			hasRule = prim.HasRule
		} else {
			prim, _ := primitiveGet(b.Primitive.ID)
			hasRule = prim.Rewrite.HasRule
		}
		if !hasRule {
			indices = append(indices, ii)
			continue
		}
		pass, _ := possibleToRewrite(b.Primitive, valPrincipalState)
		if pass {
			indices = append(indices, ii)
		}
	}
	if len(indices) == 0 {
		return result, nil
	}
	resolved, _ := valueResolveConstant(query.Constants[0], valPrincipalState)
	mutatedInfo := infoQueryMutatedValues(
		valKnowledgeMap, valPrincipalState, valAttackerState, resolved,
	)
	result.Resolved = true
	result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
		"%s (%s) is used by %s in %s despite not being a fresh value.",
		prettyConstant(query.Constants[0]), prettyValue(resolved),
		valPrincipalState.Name, prettyValue(valPrincipalState.BeforeRewrite[indices[0]]),
	), result.Options)
	result = queryPrecondition(result, valPrincipalState)
	written := verifyResultsPutWrite(result)
	if written {
		InfoMessage(fmt.Sprintf(
			"%s — %s", prettyQuery(query), result.Summary,
		), "result", true)
	}
	return result, nil
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
	query Query, valKnowledgeMap KnowledgeMap,
	valPrincipalState PrincipalState, valAttackerState AttackerState,
) (VerifyResult, error) {
	result := VerifyResult{
		Query:    query,
		Resolved: false,
		Summary:  "",
		Options:  []QueryOptionResult{},
	}
	noFreshness := []Constant{}
	for _, c := range query.Constants {
		freshnessFound, err := valueContainsFreshValues(Value{
			Kind:     typesEnumConstant,
			Constant: c,
		}, c, valPrincipalState, valAttackerState)
		if err != nil {
			return result, err
		}
		if !freshnessFound {
			noFreshness = append(noFreshness, c)
		}
	}
	if len(noFreshness) > 0 {
		resolved, _ := valueResolveConstant(noFreshness[0], valPrincipalState)
		mutatedInfo := infoQueryMutatedValues(
			valKnowledgeMap, valPrincipalState, valAttackerState, resolved,
		)
		result.Resolved = true
		result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
			"%s (%s) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
			prettyConstant(noFreshness[0]), prettyValue(resolved),
		), result.Options)
		result = queryPrecondition(result, valPrincipalState)
		written := verifyResultsPutWrite(result)
		if written {
			InfoMessage(fmt.Sprintf(
				"%s — %s", prettyQuery(query), result.Summary,
			), "result", true)
		}
		return result, nil
	}
	constants := []Constant{}
	assigneds := []Value{}
	for _, c := range query.Constants {
		a, _ := valueResolveConstant(c, valPrincipalState)
		constants = append(constants, c)
		assigneds = append(assigneds, a)
	}
	for i := range assigneds {
		for ii := range assigneds {
			if i == ii {
				continue
			}
			if !valueEquivalentValues(&assigneds[i], &assigneds[ii], false) {
				continue
			}
			obtainable := false
			switch assigneds[i].Kind {
			case typesEnumPrimitive:
				ok0, _ := possibleToReconstructPrimitive(assigneds[i].Primitive, valPrincipalState, valAttackerState)
				ok1, _, _ := possibleToRecomposePrimitive(assigneds[i].Primitive, valAttackerState)
				obtainable = ok0 || ok1
			}
			if !obtainable {
				continue
			}
			mutatedInfo := infoQueryMutatedValues(
				valKnowledgeMap, valPrincipalState, valAttackerState, Value{},
			)
			result.Resolved = true
			result.Summary = infoVerifyResultSummary(mutatedInfo, fmt.Sprintf(
				"%s and %s %s (%s), %s.",
				prettyConstant(constants[i]), prettyConstant(constants[ii]),
				"are not unlinkable since they are the output of the same primitive",
				prettyValue(assigneds[i]), "which can be obtained by Attacker",
			), result.Options)
			result = queryPrecondition(result, valPrincipalState)
			written := verifyResultsPutWrite(result)
			if written {
				InfoMessage(fmt.Sprintf(
					"%s — %s", prettyQuery(query), result.Summary,
				), "result", true)
			}
			return result, nil
		}
	}
	return result, nil
}

func queryPrecondition(
	result VerifyResult, valPrincipalState PrincipalState,
) VerifyResult {
	if !result.Resolved {
		return result
	}
	for _, option := range result.Query.Options {
		var sender principalEnum
		oResult := QueryOptionResult{
			Option:   option,
			Resolved: false,
			Summary:  "",
		}
		recipientKnows := false
		_, i := valueResolveConstant(option.Message.Constants[0], valPrincipalState)
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
				"%s sends %s to %s despite the query failing.",
				principalGetNameFromID(option.Message.Sender),
				prettyConstant(option.Message.Constants[0]),
				principalGetNameFromID(option.Message.Recipient),
			)
		}
		result.Options = append(result.Options, oResult)
	}
	return result
}
