/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

func inject(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	switch p.name {
	case "AEAD_ENC":
		//injectAEADENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "ENC":
		//injectENC(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "SIGN":
		//injectSIGN(p, valPrincipalState, valReplacementMap, valAttackerState)
	case "MAC":
		//injectMAC(p, valPrincipalState, valReplacementMap, valAttackerState)
	}
}

func injectAEADENC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "AEAD_ENC",
				arguments: []value{
					p.arguments[0],
					k,
					p.arguments[2],
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		}
	}
}

func injectENC(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "ENC",
				arguments: []value{
					p.arguments[0],
					k,
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		}
	}
}

func injectSIGN(
	p primitive, valPrincipalState *principalState,
	valReplacementMap *replacementMap, valAttackerState *attackerState,
) {
	l := len(valReplacementMap.replacements) - 1
	for _, k := range valAttackerState.known {
		aa := value{
			kind: "primitive",
			primitive: primitive{
				name: "SIGN",
				arguments: []value{
					p.arguments[0],
					k,
				},
				output: p.output,
				check:  p.check,
			},
		}
		if sanityExactSameValueInValues(aa, &valReplacementMap.replacements[l]) < 0 {
			valReplacementMap.replacements[l] = append(valReplacementMap.replacements[l], aa)
		}
	}
}
