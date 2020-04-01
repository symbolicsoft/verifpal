/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 616bf0023a90ab68ba9e693bf9994779

package verifpal

import (
	"fmt"
	"os"
	"strings"
)

// ProVerif translates a Verifpal model into a ProVerif model.
func ProVerif(modelFile string) {
	m := parserParseModel(modelFile, false)
	sanity(m)
	pv := proverifModel(m)
	fmt.Fprint(os.Stdout, pv)
}

func proverifConstant(valKnowledgeMap knowledgeMap, principal string, c constant) string {
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	c = valKnowledgeMap.constants[i]
	prefix := "const"
	if valKnowledgeMap.creator[i] == principal && c.declaration == "assignment" {
		prefix = principal
	} else {
		for _, m := range valKnowledgeMap.knownBy[i] {
			if p, ok := m[principal]; ok {
				if p != principal {
					prefix = p
				}
			}
		}
	}
	return fmt.Sprintf("%s_%s", prefix, c.name)
}

func proverifConstants(valKnowledgeMap knowledgeMap, principal string, c []constant) string {
	consts := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s%s",
			consts, proverifConstant(valKnowledgeMap, principal, v), sep,
		)
	}
	return consts
}

func proverifPrimitive(valKnowledgeMap knowledgeMap, principal string, p primitive) string {
	prim := fmt.Sprintf("%s(", p.name)
	for i, arg := range p.arguments {
		sep := ""
		if i != (len(p.arguments) - 1) {
			sep = ", "
		}
		prim = fmt.Sprintf("%s%s%s",
			prim, proverifValue(valKnowledgeMap, principal, arg), sep,
		)
	}
	prim = fmt.Sprintf("%s)", prim)
	switch p.check {
	case true:
		//prim = fmt.Sprintf("if %s = empty then () else (", prim)
	}
	return prim
}

func proverifEquation(valKnowledgeMap knowledgeMap, principal string, e equation) string {
	eq := ""
	switch len(e.values) {
	case 1:
		eq = fmt.Sprintf(
			"G(%s)",
			proverifValue(valKnowledgeMap, principal, e.values[0]),
		)
	case 2:
		eq = fmt.Sprintf(
			"exp(%s, %s)",
			proverifValue(valKnowledgeMap, principal, e.values[1]),
			proverifValue(valKnowledgeMap, principal, e.values[0]),
		)
	}
	return eq
}

func proverifValue(valKnowledgeMap knowledgeMap, principal string, a value) string {
	switch a.kind {
	case "constant":
		return proverifConstant(valKnowledgeMap, principal, a.constant)
	case "primitive":
		return proverifPrimitive(valKnowledgeMap, principal, a.primitive)
	case "equation":
		return proverifEquation(valKnowledgeMap, principal, a.equation)
	}
	return ""
}

/*
func proverifValues(a []value) string {
	values := ""
	for i, v := range a {
		sep := ", "
		if i == len(a)-1 {
			sep = ""
		}
		values = fmt.Sprintf(
			"%s%s%s",
			values, proverifValue(v), sep,
		)
	}
	return values
}
*/

func proverifQuery(query query) string {
	output := ""
	switch query.kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"query attacker(%s).",
			query.constant.name,
		)
	case "authentication":
		output = fmt.Sprintf("%s ==> %s.",
			fmt.Sprintf("query event(RecvMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.message.sender, query.message.recipient, 0, query.message.constants[0].name,
			),
			fmt.Sprintf("event(SendMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.message.sender, query.message.recipient, 0, query.message.constants[0].name,
			),
		)
	}
	if len(query.options) > 0 {
		errorCritical("UNSUPPORTED")
	}
	return output
}

func proverifPrincipal(
	valKnowledgeMap knowledgeMap, block block,
	procs string, consts string, pc int, cc int,
) (string, string, int, int) {
	procs = fmt.Sprintf(
		"%slet %s_%d() =\n",
		procs, block.principal.name, pc,
	)
	for _, expression := range block.principal.expressions {
		switch expression.kind {
		case "knows":
			for _, c := range expression.constants {
				procs = fmt.Sprintf(
					"%s\t(* knows %s %s. *)\n",
					procs,
					expression.qualifier,
					c.name,
				)
			}
		case "generates":
			for _, c := range expression.constants {
				procs = fmt.Sprintf(
					"%s\t(* generates %s. *)\n",
					procs,
					c.name,
				)
			}
		case "leaks":
			errorCritical("UNSUPPORTED")
			procs = procs + ""
		case "assignment":
			procs = fmt.Sprintf(
				"%s\tlet %s = %s in\n",
				procs,
				proverifConstants(valKnowledgeMap, block.principal.name, expression.left),
				proverifValue(valKnowledgeMap, block.principal.name, expression.right),
			)
			procs = fmt.Sprintf(
				"%s\tinsert valuestore(principal_%s, principal_%s, %s);\n",
				procs,
				block.principal.name, block.principal.name,
				proverifConstants(valKnowledgeMap, block.principal.name, expression.left),
			)
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, consts, pc, cc
}

func proverifMessage(
	valKnowledgeMap knowledgeMap, block block,
	procs string, pc int,
) (string, int) {
	procs = fmt.Sprintf(
		"%slet %s_to_%s_%d() =\n",
		procs, block.message.sender, block.message.recipient, pc,
	)
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tget valuestore(=principal_%s, =principal_%s, %s) in\n",
			procs, block.message.sender, block.message.sender,
			proverifConstant(valKnowledgeMap, block.message.sender, c),
		)
	}
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent SendMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.message.sender, block.message.recipient,
			0, proverifConstant(valKnowledgeMap, block.message.sender, c),
		)
	}
	procs = fmt.Sprintf(
		"%s\tout(chan_%s_to_%s, (%s));\n",
		procs, block.message.sender, block.message.recipient,
		proverifConstants(valKnowledgeMap, block.message.sender, block.message.constants),
	)
	procs = procs + "\t0.\n"
	pc = pc + 1
	procs = fmt.Sprintf(
		"%slet %s_from_%s_%d() =\n",
		procs, block.message.recipient, block.message.sender, pc,
	)
	consts := ""
	for i, c := range block.message.constants {
		sep := ""
		if i != len(block.message.constants)-1 {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s:bitstring%s",
			consts, proverifConstant(valKnowledgeMap, block.message.sender, c), sep,
		)
	}
	procs = fmt.Sprintf(
		"%s\tin(chan_%s_to_%s, (%s));\n",
		procs, block.message.sender,
		block.message.recipient, consts,
	)
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent RecvMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.message.sender, block.message.recipient, 0,
			proverifConstant(valKnowledgeMap, block.message.sender, c),
		)
		procs = fmt.Sprintf(
			"%s\tinsert valuestore(principal_%s, principal_%s, %s);\n",
			procs,
			block.message.sender, block.message.recipient,
			proverifConstant(valKnowledgeMap, block.message.sender, c),
		)
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, pc
}

func proverifPhase(block block) string {
	return ""
}

func proverifModel(m Model) string {
	pv := ""
	procs := ""
	consts := ""
	pc := 0
	cc := 0
	valKnowledgeMap := constructKnowledgeMap(m, sanityDeclaredPrincipals(m))
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			procs, consts, pc, cc = proverifPrincipal(
				valKnowledgeMap, block, procs, consts, pc, cc,
			)
		case "message":
			procs, pc = proverifMessage(valKnowledgeMap, block, procs, pc)
		case "phase":
			pv = pv + proverifPhase(block)
		}
	}
	pv = pv + proverifTemplates.parameters(m.attacker)
	pv = pv + proverifTemplates.types()
	pv = pv + proverifTemplates.constants(valKnowledgeMap, consts)
	pv = pv + proverifTemplates.coreprims()
	pv = pv + proverifTemplates.prims()
	pv = pv + proverifTemplates.channels(valKnowledgeMap)
	pv = pv + proverifTemplates.queries(m.queries)
	pv = pv + procs
	pv = pv + proverifTemplates.toplevel(m.blocks)
	return pv
}

var proverifTemplates = proverifTemplate{
	parameters: func(attacker string) string {
		return strings.Join([]string{
			"set expandIfTermsToTerms = true.",
			"set traceBacktracking = false.",
			"set reconstructTrace = false.",
			fmt.Sprintf("set attacker = %s.", attacker),
		}, "\n") + "\n"
	},
	types: func() string {
		return strings.Join([]string{
			"type principal.",
			"type stage.",
		}, "\n") + "\n"
	},
	constants: func(valKnowledgeMap knowledgeMap, consts string) string {
		output := ""
		for _, principal := range valKnowledgeMap.principals {
			output = fmt.Sprintf(
				"%sconst principal_%s:principal.\n",
				output, principal,
			)
		}
		for i := 0; i <= valKnowledgeMap.maxPhase; i++ {
			output = fmt.Sprintf(
				"%sconst phase_%d:stage.\n",
				output, i,
			)
		}
		for _, c := range valKnowledgeMap.constants {
			priv := ""
			switch c.qualifier {
			case "private":
				priv = " [private]"
			}
			consts = fmt.Sprintf(
				"%sconst const_%s:bitstring%s.\n",
				consts, c.name, priv,
			)
		}
		return output + strings.Join([]string{
			"const empty:bitstring [data].",
			"fun shamir_keys_pack(bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring;",
			"\tshamir_keys_unpack(shamir_keys_pack(a, b, c)) = (a, b, c).",
			"table valuestore(principal, principal, bitstring).",
			consts,
		}, "\n") + "\n"
	},
	coreprims: func() string {
		return strings.Join([]string{
			"fun CONCAT2(bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring;",
			"\tSPLIT2(CONCAT2(a, b)) = (a, b).",
			"fun CONCAT3(bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring;",
			"\tSPLIT3(CONCAT3(a, b, c)) = (a, b, c).",
			"fun CONCAT4(bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring, d:bitstring;",
			"\tSPLIT4(CONCAT4(a, b, c, d)) = (a, b, c, d).",
			"fun CONCAT5(bitstring, bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring, d:bitstring, e:bitstring;",
			"\tSPLIT5(CONCAT5(a, b, c, d, e)) = (a, b, c, d, e).",
		}, "\n") + "\n"
	},
	prims: func() string {
		return strings.Join([]string{
			"fun exp(bitstring, bitstring):bitstring.",
			"equation forall a:bitstring, b:bitstring;",
			"\texp(b, exp(a, const_g)) = exp(a, exp(b, const_g)).",
			"fun HASH(bitstring):bitstring.",
			"fun MAC(bitstring, bitstring): bitstring.",
			"fun hmac_hash1(bitstring, bitstring):bitstring.",
			"fun hmac_hash2(bitstring, bitstring):bitstring.",
			"fun hmac_hash3(bitstring, bitstring):bitstring.",
			"letfun HKDF(chaining_bitstring:bitstring, input_bitstring_material:bitstring) =",
			"\tlet output1 = hmac_hash1(chaining_bitstring, input_bitstring_material) in",
			"\tlet output2 = hmac_hash2(chaining_bitstring, input_bitstring_material) in",
			"\tlet output3 = hmac_hash3(chaining_bitstring, input_bitstring_material) in",
			"\t(output1, output2, output3).",
			"fun PW_HASH(bitstring): bitstring.",
			"fun ENC(bitstring, bitstring):bitstring.",
			"fun DEC(bitstring, bitstring):bitstring reduc",
			"\tforall k:bitstring, m:bitstring;",
			"\tDEC(k, ENC(k, m)) = m",
			"\totherwise forall k:bitstring, m:bitstring;",
			"\tDEC(k, m) = empty.",
			"fun AEAD_ENC(bitstring, bitstring, bitstring):bitstring.",
			"fun AEAD_DEC(bitstring, bitstring, bitstring):bitstring reduc",
			"\tforall k:bitstring, m:bitstring, ad:bitstring;",
			"\tAEAD_DEC(k, AEAD_ENC(k, m, ad), ad) = m",
			"\totherwise forall k:bitstring, m:bitstring, ad:bitstring;",
			"\tAEAD_DEC(k, m, ad) = empty.",
			"fun PKE_ENC(bitstring, bitstring):bitstring.",
			"fun PKE_DEC(bitstring, bitstring):bitstring reduc",
			"\tforall k:bitstring, m:bitstring;",
			"\tPKE_DEC(k, PKE_ENC(exp(k, const_g), m)) = m.",
			"fun SIGN(bitstring, bitstring):bitstring.",
			"fun SIGNVERIF(bitstring, bitstring, bitstring):bool reduc",
			"\tforall sk:bitstring, m:bitstring;",
			"\tSIGNVERIF(exp(sk, const_g), SIGN(sk, m), m) = true",
			"\totherwise forall pk:bitstring, s:bitstring, m:bitstring;",
			"\tSIGNVERIF(pk, s, m) = false.",
			"fun RINGSIGN(bitstring, bitstring, bitstring, bitstring):bitstring.",
			"fun shamir_split1(bitstring):bitstring.",
			"fun shamir_split2(bitstring):bitstring.",
			"fun shamir_split3(bitstring):bitstring.",
			"letfun SHAMIR_SPLIT(k:bitstring) =",
			"\tlet k1 = shamir_split1(k) in",
			"\tlet k2 = shamir_split2(k) in",
			"\tlet k3 = shamir_split3(k) in",
			"\t(k1, k2, k3).",
			"fun SHAMIR_JOIN(bitstring, bitstring):bitstring reduc",
			"\tforall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split1(k), shamir_split2(k)) = k",
			"\totherwise forall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split2(k), shamir_split1(k)) = k",
			"\totherwise forall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split1(k), shamir_split3(k)) = k",
			"\totherwise forall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split3(k), shamir_split1(k)) = k",
			"\totherwise forall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split2(k), shamir_split3(k)) = k",
			"\totherwise forall k:bitstring;",
			"\tSHAMIR_JOIN(shamir_split3(k), shamir_split2(k)) = k.",
		}, "\n") + "\n"
	},
	channels: func(valKnowledgeMap knowledgeMap) string {
		channels := []string{"const pub:channel."}
		for i, prin1 := range valKnowledgeMap.principals {
			for ii, prin2 := range valKnowledgeMap.principals {
				if i == ii {
					continue
				}
				channel := fmt.Sprintf(
					"const chan_%s_to_%s:channel.",
					prin1, prin2,
				)
				channels = append(channels, channel)
			}
		}
		return strings.Join(channels, "\n") + "\n"
	},
	queries: func(queries []query) string {
		output := []string{
			"event SendMsg(principal, principal, stage, bitstring).",
			"event RecvMsg(principal, principal, stage, bitstring).",
		}
		for _, q := range queries {
			output = append(output, proverifQuery(q))
		}
		return strings.Join(output, "\n") + "\n"
	},
	toplevel: func(blocks []block) string {
		pc := 0
		parallel := ""
		for i, block := range blocks {
			sep := " | "
			if i == len(blocks)-1 {
				sep = ""
			}
			switch block.kind {
			case "principal":
				parallel = fmt.Sprintf(
					"%s%s_%d()%s",
					parallel, block.principal.name,
					pc, sep,
				)
				pc = pc + 1
			case "message":
				parallel = fmt.Sprintf(
					"%s%s_to_%s_%d()%s",
					parallel, block.message.sender,
					block.message.recipient, pc, sep,
				)
				pc = pc + 1
				parallel = fmt.Sprintf(
					"%s%s_from_%s_%d()%s",
					parallel, block.message.recipient,
					block.message.sender, pc, sep,
				)
				pc = pc + 1
			}
		}
		output := strings.Join([]string{
			"process (",
			fmt.Sprintf("\t(%s)", parallel),
			")",
		}, "\n")
		return output
	},
}
