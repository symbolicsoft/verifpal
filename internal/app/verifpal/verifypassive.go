/* SPDX-License-Identifier: GPL-3.0
 * Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
 * All Rights Reserved. */

// 00000000000000000000000000000000

package main

func verifyPassive(model *verifpal, valKnowledgeMap *knowledgeMap) []verifyResult {
	var verifyResults []verifyResult
	valPrincipalStates := constructPrincipalStates(model, valKnowledgeMap)
	valAttackerState := constructAttackerState(false, model, valKnowledgeMap, true)
	prettyMessage("attacker is configured as a passive attacker", 0, "info")
	verifyAnalysis(model, valPrincipalStates[0], valAttackerState, 0)
	return verifyResolveQueries(model, valKnowledgeMap, valPrincipalStates[0], valAttackerState, verifyResults)
}
