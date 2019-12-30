/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

func verifyPassive(m *model, valKnowledgeMap *knowledgeMap, valPrincipalStates []*principalState) []verifyResult {
	var verifyResults []verifyResult
	valAttackerState := constructAttackerState(false, m, valKnowledgeMap, true)
	prettyMessage("attacker is configured as passive", 0, 0, "info")
	valPrincipalStates[0] = sanityResolveAllPrincipalStateValues(valPrincipalStates[0], valKnowledgeMap)
	failedRewrites, _ := sanityPerformAllRewrites(valPrincipalStates[0])
	sanityFailOnFailedRewrite(failedRewrites)
	for _, a := range valPrincipalStates[0].assigned {
		sanityCheckEquationGenerators(a, valPrincipalStates[0])
	}
	verifyAnalysis(m, valPrincipalStates[0], valAttackerState, 0, 0)
	verifyResolveQueries(m, valKnowledgeMap, valPrincipalStates[0], valAttackerState, &verifyResults, 0)
	return verifyResults
}
