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

func proverifConstant(c constant) string {
	return c.name
}

func proverifConstants(c []constant) string {
	consts := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s%s",
			consts, proverifConstant(v), sep,
		)
	}
	return consts
}

func proverifPrimitive(p primitive) string {
	return ""
}

func proverifEquation(e equation) string {
	return ""
}

func proverifQuery(query query) string {
	output := ""
	switch query.kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"query attacker(%s).",
			proverifConstant(query.constant),
		)
	case "authentication":
		errorCritical("UNSUPPORTED")
	}
	if len(query.options) > 0 {
		errorCritical("UNSUPPORTED")
	}
	return output
}

// Process, constants, counter
func proverifPrincipal(block block, procs string, consts string, pc int) (string, string, int) {
	procs = fmt.Sprintf(
		"%slet %s_%d() =\n",
		procs, block.principal.name, pc,
	)
	for _, expression := range block.principal.expressions {
		switch expression.kind {
		case "knows":
			for _, c := range expression.constants {
				priv := ""
				switch expression.qualifier {
				case "private":
					priv = "[private]"
				}
				consts = fmt.Sprintf(
					"%sconst %s:bitstring %s.",
					consts, proverifConstant(c), priv,
				)
				procs = fmt.Sprintf(
					"%s\t(* knows %s %s. *)\n",
					procs,
					expression.qualifier,
					proverifConstant(c),
				)
			}
		case "generates":
			procs = fmt.Sprintf(
				"%s\tknows %s %s\n",
				procs,
				expression.qualifier,
				prettyConstants(expression.constants),
			)
		case "leaks":
			procs = fmt.Sprintf(
				"%s\tknows %s %s\n",
				procs,
				expression.qualifier,
				prettyConstants(expression.constants),
			)
		case "assignment":
			procs = fmt.Sprintf(
				"%s\tknows %s %s\n",
				procs,
				expression.qualifier,
				prettyConstants(expression.constants),
			)
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, consts, pc
}

func proverifMessage(block block, procs string, pc int) (string, int) {
	procs = fmt.Sprintf(
		"%slet %s_to_%s_%d() =\n",
		procs, block.message.sender, block.message.recipient, pc,
	)
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent SendMsg(principal_%s, principal_%s, %s, %s);\n",
			procs, block.message.sender, block.message.recipient, "phase_0", proverifConstant(c),
		)
	}
	procs = fmt.Sprintf(
		"%s\tout(chan_%s_to_%s, (%s));\n",
		procs, block.message.sender, block.message.recipient, proverifConstants(block.message.constants),
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
			consts, proverifConstant(c), sep,
		)
	}
	for _, c := range block.message.constants {
		procs = fmt.Sprintf(
			"%s\tevent RecvMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.message.sender, block.message.recipient, 0,
			proverifConstant(c),
		)
	}
	procs = fmt.Sprintf(
		"%s\tin(chan_%s_to_%s, (%s));\n",
		procs, block.message.sender, block.message.recipient,
		consts,
	)
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
	valKnowledgeMap := constructKnowledgeMap(m, sanityDeclaredPrincipals(m))
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			procs, consts, pc = proverifPrincipal(block, procs, consts, pc)
		case "message":
			procs, pc = proverifMessage(block, procs, pc)
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
			"type key.",
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
		return output + strings.Join([]string{
			"const generator:key   [data].",
			"const empty:bitstring [data].",
			"fun shamir_keys_pack(key, key, key):bitstring [data].",
			"reduc forall a:key, b:key, c:key;",
			"\tshamir_keys_unpack(shamir_keys_pack(a, b, c)) = (a, b, c).",
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
			"fun exp(key, key):key.",
			"equation forall a:key, b:key;",
			"\texp(b, exp(a, generator)) = exp(a, exp(b, generator)).",
			"letfun G(basis:key) =",
			"\texp(basis, generator).",
			"fun HASH(bitstring, bitstring):bitstring.",
			"fun MAC(key, bitstring): bitstring.",
			"fun hmac_hash1(key, key):key.",
			"fun hmac_hash2(key, key):key.",
			"fun hmac_hash3(key, key):key.",
			"letfun HKDF(chaining_key:key, input_key_material:key) =",
			"\tlet output1 = hmac_hash1(chaining_key, input_key_material) in",
			"\tlet output2 = hmac_hash2(chaining_key, input_key_material) in",
			"\tlet output3 = hmac_hash3(chaining_key, input_key_material) in",
			"\t(output1, output2, output3).",
			"fun PW_HASH(bitstring): bitstring.",
			"fun ENC(key, bitstring):bitstring.",
			"fun DEC(key, bitstring):bitstring reduc",
			"\tforall k:key, m:bitstring;",
			"\tDEC(k, ENC(k, m)) = m",
			"\totherwise forall k:key, m:bitstring;",
			"\tDEC(k, m) = empty.",
			"fun AEAD_ENC(key, bitstring, bitstring):bitstring.",
			"fun AEAD_DEC(key, bitstring, bitstring):bitstring reduc",
			"\tforall k:key, m:bitstring, ad:bitstring;",
			"\tAEAD_DEC(k, AEAD_ENC(k, m, ad), ad) = m.",
			"fun PKE_ENC(key, bitstring):bitstring.",
			"fun PKE_DEC(key, bitstring):bitstring reduc",
			"\tforall k:key, m:bitstring;",
			"\tPKE_DEC(k, PKE_ENC(exp(k, generator), m)) = m.",
			"fun SIGN(key, bitstring):bitstring.",
			"fun SIGNVERIF(key, bitstring, bitstring):bool reduc",
			"\tforall sk:key, m:bitstring;",
			"\tSIGNVERIF(exp(sk, generator), SIGN(sk, m), m) = true",
			"\totherwise forall pk:key, s:bitstring, m:bitstring;",
			"\tSIGNVERIF(pk, s, m) = false.",
			"fun RINGSIGN(key, key, key, bitstring):bitstring.",
			"fun shamir_split1(key):key.",
			"fun shamir_split2(key):key.",
			"fun shamir_split3(key):key.",
			"letfun SHAMIR_SPLIT(k:key) =",
			"\tlet k1 = shamir_split1(k) in",
			"\tlet k2 = shamir_split2(k) in",
			"\tlet k3 = shamir_split3(k) in",
			"\t(k1, k2, k3).",
			"fun SHAMIR_JOIN(key, key):key reduc",
			"\tforall k:key;",
			"\tSHAMIR_JOIN(shamir_split1(k), shamir_split2(k)) = k",
			"\totherwise forall k:key;",
			"\tSHAMIR_JOIN(shamir_split2(k), shamir_split1(k)) = k",
			"\totherwise forall k:key;",
			"\tSHAMIR_JOIN(shamir_split1(k), shamir_split3(k)) = k",
			"\totherwise forall k:key;",
			"\tSHAMIR_JOIN(shamir_split3(k), shamir_split1(k)) = k",
			"\totherwise forall k:key;",
			"\tSHAMIR_JOIN(shamir_split2(k), shamir_split3(k)) = k",
			"\totherwise forall k:key;",
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
					"%s | %s_from_%s_%d()%s",
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
