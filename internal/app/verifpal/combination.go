/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// b3217fdc84899bc6c014cee70a82859d

package main

func (valReplacementMap *replacementMap) combinationNext() bool {
	lastCombination := false
	for i := 0; i < len(valReplacementMap.combination); i++ {
		valReplacementMap.combination[i] = valReplacementMap.replacements[i][valReplacementMap.depthIndex[i]]
		valReplacementMap.requiredKnown[i] = valReplacementMap.requiredKnowns[i][valReplacementMap.depthIndex[i]]
		if i == len(valReplacementMap.combination)-1 {
			valReplacementMap.depthIndex[i] = valReplacementMap.depthIndex[i] + 1
			for ii := i; ii >= 0; ii-- {
				if valReplacementMap.depthIndex[ii] == len(valReplacementMap.replacements[ii]) {
					if ii > 0 {
						valReplacementMap.depthIndex[ii] = 0
						valReplacementMap.depthIndex[ii-1] = valReplacementMap.depthIndex[ii-1] + 1
					} else {
						lastCombination = true
						break
					}
				}
			}
		}
	}
	return lastCombination
}
