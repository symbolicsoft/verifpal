/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 616bf0023a90ab68ba9e693bf9994779

/* WARNING: The code here is purely a bunch of thought experiments.
/* It is in no way ready for anything. */

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

func proverifConstantPrefix(valKnowledgeMap knowledgeMap, principal string, c constant) string {
	prefix := "const"
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	c = valKnowledgeMap.constants[i]
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
	return prefix
}

func proverifConstant(valKnowledgeMap knowledgeMap, principal string, c constant, includeType bool) string {
	prefix := proverifConstantPrefix(valKnowledgeMap, principal, c)
	t := ""
	if includeType {
		t = ":bitstring"
	}
	return fmt.Sprintf("%s_%s%s", prefix, c.name, t)
}

func proverifConstants(valKnowledgeMap knowledgeMap, principal string, c []constant, includeType bool) string {
	consts := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s%s",
			consts, proverifConstant(valKnowledgeMap, principal, v, includeType), sep,
		)
	}
	return consts
}

func proverifPrimitive(valKnowledgeMap knowledgeMap, principal string, p primitive) string {
	pname := p.name
	switch p.check {
	case true:
		errorCritical("checked primitives are not yet supported in ProVerif model generation")
	}
	switch p.name {
	case "HASH":
		pname = fmt.Sprintf("%s%d", p.name, len(p.arguments))
	case "ASSERT":
		return "const_nil"
	}
	prim := fmt.Sprintf("%s(", pname)
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
		return proverifConstant(valKnowledgeMap, principal, a.constant, false)
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

func proverifQuery(valKnowledgeMap knowledgeMap, query query) string {
	output := ""
	switch query.kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"query attacker(const_%s).",
			query.constant.name,
		)
	case "authentication":
		output = fmt.Sprintf("%s ==> %s.",
			fmt.Sprintf("query event(RecvMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.message.sender, query.message.recipient, 0,
				proverifConstant(valKnowledgeMap, "attacker", query.message.constants[0], false),
			),
			fmt.Sprintf("event(SendMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.message.sender, query.message.recipient, 0,
				proverifConstant(valKnowledgeMap, "attacker", query.message.constants[0], false),
			),
		)
	}
	if len(query.options) > 0 {
		errorCritical("UNSUPPORTED2")
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
		case "leaks":
			procs = fmt.Sprintf(
				"%s\tout(pub, (%s))\n",
				procs, prettyConstants(expression.constants),
			)
		case "assignment":
			c := sanityGetConstantsFromValue(expression.right)
			get := ""
			for _, cc := range c {
				prefix := proverifConstantPrefix(valKnowledgeMap, block.principal.name, cc)
				if prefix != "const" {
					get = fmt.Sprintf(
						"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
						get,
						prefix, block.principal.name,
						cc.name,
						proverifConstant(valKnowledgeMap, block.principal.name, cc, false),
					)
				}
			}
			if len(get) > 0 {
				procs = fmt.Sprintf(
					"%s%s\n",
					procs, get,
				)
			}
			procs = fmt.Sprintf(
				"%s\tlet (%s) = %s in\n",
				procs,
				proverifConstants(valKnowledgeMap, block.principal.name, expression.left, true),
				proverifValue(valKnowledgeMap, block.principal.name, expression.right),
			)
			for _, l := range expression.left {
				procs = fmt.Sprintf(
					"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
					procs,
					block.principal.name, block.principal.name,
					l.name,
					proverifConstant(valKnowledgeMap, block.principal.name, l, false),
				)
			}
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
			"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
			procs, block.message.sender, block.message.sender,
			c.name,
			proverifConstant(valKnowledgeMap, block.message.sender, c, false),
		)
	}
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent SendMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.message.sender, block.message.recipient,
			0, proverifConstant(valKnowledgeMap, block.message.sender, c, false),
		)
	}
	for _, c := range block.message.constants {
		switch c.guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tout(pub, %s);\n",
				procs, proverifConstant(valKnowledgeMap, block.message.sender, c, false),
			)
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s_private, (%s));\n",
				procs, block.message.sender, block.message.recipient,
				proverifConstant(valKnowledgeMap, block.message.sender, c, false),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s, (%s));\n",
				procs, block.message.sender, block.message.recipient,
				proverifConstant(valKnowledgeMap, block.message.sender, c, false),
			)
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	procs = fmt.Sprintf(
		"%slet %s_from_%s_%d() =\n",
		procs, block.message.recipient, block.message.sender, pc,
	)
	for _, c := range block.message.constants {
		switch c.guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s_private, (%s));\n",
				procs, block.message.sender, block.message.recipient,
				proverifConstant(valKnowledgeMap, block.message.sender, c, true),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s, (%s));\n",
				procs, block.message.sender, block.message.recipient,
				proverifConstant(valKnowledgeMap, block.message.sender, c, true),
			)
		}
	}
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent RecvMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.message.sender, block.message.recipient, 0,
			proverifConstant(valKnowledgeMap, block.message.sender, c, false),
		)
		procs = fmt.Sprintf(
			"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
			procs,
			block.message.sender, block.message.recipient,
			c.name,
			proverifConstant(valKnowledgeMap, block.message.sender, c, false),
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
	pv = pv + proverifTemplates.queries(valKnowledgeMap, m.queries)
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
			"table valuestore(principal, principal, bitstring, bitstring).",
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
			"fun HASH1(bitstring):bitstring.",
			"fun HASH2(bitstring, bitstring):bitstring.",
			"fun HASH3(bitstring, bitstring, bitstring):bitstring.",
			"fun HASH4(bitstring, bitstring, bitstring, bitstring):bitstring.",
			"fun HASH5(bitstring, bitstring, bitstring, bitstring, bitstring):bitstring.",
			"fun MAC(bitstring, bitstring): bitstring.",
			"fun hmac_hash1(bitstring, bitstring, bitstring):bitstring.",
			"fun hmac_hash2(bitstring, bitstring, bitstring):bitstring.",
			"fun hmac_hash3(bitstring, bitstring, bitstring):bitstring.",
			"letfun HKDF(salt:bitstring, ikm:bitstring, info:bitstring) =",
			"\tlet output1 = hmac_hash1(salt, ikm, info) in",
			"\tlet output2 = hmac_hash2(salt, ikm, info) in",
			"\tlet output3 = hmac_hash3(salt, ikm, info) in",
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
				channel := strings.Join([]string{fmt.Sprintf(
					"const chan_%s_to_%s:channel.",
					prin1, prin2,
				), fmt.Sprintf(
					"const chan_%s_to_%s_private:channel [private].",
					prin1, prin2,
				)}, "\n")
				channels = append(channels, channel)
			}
		}
		return strings.Join(channels, "\n") + "\n"
	},
	queries: func(valKnowledgeMap knowledgeMap, queries []query) string {
		output := []string{
			"event SendMsg(principal, principal, stage, bitstring).",
			"event RecvMsg(principal, principal, stage, bitstring).",
		}
		for _, q := range queries {
			output = append(output, proverifQuery(valKnowledgeMap, q))
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
