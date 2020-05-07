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
	fmt.Fprint(os.Stdout, proverifModel(m))
}

func proverifConstantPrefix(valKnowledgeMap KnowledgeMap, principal string, c Constant) string {
	prefix := "const"
	i := sanityGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	c = valKnowledgeMap.Constants[i]
	if valKnowledgeMap.Creator[i] == principal && c.Declaration == "assignment" {
		prefix = principal
	} else {
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if p, ok := m[principal]; ok {
				if p != principal {
					prefix = p
				}
			}
		}
	}
	return prefix
}

func proverifConstant(valKnowledgeMap KnowledgeMap, principal string, c Constant, valType string) string {
	prefix := proverifConstantPrefix(valKnowledgeMap, principal, c)
	t := ""
	if len(valType) > 0 {
		t = fmt.Sprintf(":%s", valType)
	}
	return fmt.Sprintf("%s_%s%s", prefix, c.Name, t)
}

func proverifConstants(valKnowledgeMap KnowledgeMap, principal string, c []Constant, valType string) string {
	consts := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s%s",
			consts, proverifConstant(valKnowledgeMap, principal, v, valType), sep,
		)
	}
	return consts
}

func proverifPrimitive(valKnowledgeMap KnowledgeMap, principal string, p Primitive, check bool) string {
	pname := p.Name
	checksuffix := ""
	switch check {
	case true:
		switch p.Name {
		case "AEAD_DEC":
			checksuffix = "_check"
		}
	}
	switch p.Name {
	case "HASH", "CONCAT", "SPLIT":
		pname = fmt.Sprintf("%s%d", p.Name, len(p.Arguments))
	}
	prim := fmt.Sprintf("%s%s(", pname, checksuffix)
	for i, arg := range p.Arguments {
		sep := ""
		if i != (len(p.Arguments) - 1) {
			sep = ", "
		}
		prim = fmt.Sprintf("%s%s%s",
			prim, proverifValue(valKnowledgeMap, principal, arg), sep,
		)
	}
	prim = fmt.Sprintf("%s)", prim)
	return prim
}

func proverifEquation(valKnowledgeMap KnowledgeMap, principal string, e Equation) string {
	eq := ""
	switch len(e.Values) {
	case 1:
		eq = fmt.Sprintf(
			"G(%s)",
			proverifValue(valKnowledgeMap, principal, e.Values[0]),
		)
	case 2:
		eq = fmt.Sprintf(
			"exp(%s, %s)",
			proverifValue(valKnowledgeMap, principal, e.Values[1]),
			proverifValue(valKnowledgeMap, principal, e.Values[0]),
		)
	}
	return eq
}

func proverifValue(valKnowledgeMap KnowledgeMap, principal string, a Value) string {
	switch a.Kind {
	case "constant":
		return proverifConstant(valKnowledgeMap, principal, a.Constant, "")
	case "primitive":
		return proverifPrimitive(valKnowledgeMap, principal, a.Primitive, false)
	case "equation":
		return proverifEquation(valKnowledgeMap, principal, a.Equation)
	}
	return ""
}

func proverifQuery(valKnowledgeMap KnowledgeMap, query Query) string {
	output := ""
	switch query.Kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"query attacker(const_%s).",
			query.Constants[0].Name,
		)
	case "authentication":
		output = fmt.Sprintf("%s ==> %s.",
			fmt.Sprintf("query event(RecvMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.Message.Sender, query.Message.Recipient, 0,
				proverifConstant(valKnowledgeMap, "attacker", query.Message.Constants[0], ""),
			),
			fmt.Sprintf("event(SendMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.Message.Sender, query.Message.Recipient, 0,
				proverifConstant(valKnowledgeMap, "attacker", query.Message.Constants[0], ""),
			),
		)
	case "freshness":
		errorCritical("freshness queries are not yet supported in ProVerif model generation")
	case "unlinkability":
		errorCritical("unlinkability queries are not yet supported in ProVerif model generation")
	}
	if len(query.Options) > 0 {
		errorCritical("query options are not yet supported in ProVerif model generation")
	}
	return output
}

func proverifPrincipal(
	valKnowledgeMap KnowledgeMap, block Block,
	procs string, consts string, pc int, cc int,
) (string, string, int, int) {
	procs = fmt.Sprintf(
		"%slet %s_%d() =\n",
		procs, block.Principal.Name, pc,
	)
	for _, expression := range block.Principal.Expressions {
		switch expression.Kind {
		case "leaks":
			for _, c := range expression.Constants {
				procs = fmt.Sprintf(
					"%s\tout(pub, (%s));\n",
					procs, proverifConstant(valKnowledgeMap, block.Principal.Name, c, ""),
				)
			}
		case "assignment":
			c := sanityGetConstantsFromValue(expression.Right)
			get := ""
			for _, cc := range c {
				prefix := proverifConstantPrefix(valKnowledgeMap, block.Principal.Name, cc)
				if prefix == "const" {
					continue
				}
				if strings.HasPrefix(cc.Name, "unnamed_") {
					continue
				}
				get = fmt.Sprintf(
					"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
					get,
					prefix, block.Principal.Name,
					cc.Name,
					proverifConstant(valKnowledgeMap, block.Principal.Name, cc, ""),
				)
			}
			if len(get) > 0 {
				procs = fmt.Sprintf(
					"%s%s",
					procs, get,
				)
			}
			valType := "bitstring"
			switch expression.Right.Kind {
			case "primitive":
				switch expression.Right.Primitive.Name {
				case "SIGNVERIF", "RINGSIGNVERIF":
					valType = "bool"
				}
				switch expression.Right.Primitive.Check {
				case true:
					procs = fmt.Sprintf("%s\tif %s = true then\n",
						procs,
						proverifPrimitive(valKnowledgeMap, block.Principal.Name, expression.Right.Primitive, true),
					)
				}
			}
			procs = fmt.Sprintf(
				"%s\tlet (%s) = %s in\n",
				procs,
				proverifConstants(valKnowledgeMap, block.Principal.Name, expression.Left, valType),
				proverifValue(valKnowledgeMap, block.Principal.Name, expression.Right),
			)
			for _, l := range expression.Left {
				if strings.HasPrefix(l.Name, "unnamed_") {
					continue
				}
				procs = fmt.Sprintf(
					"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
					procs,
					block.Principal.Name, block.Principal.Name,
					l.Name,
					proverifConstant(valKnowledgeMap, block.Principal.Name, l, ""),
				)
			}
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, consts, pc, cc
}

func proverifMessage(
	valKnowledgeMap KnowledgeMap, block Block,
	procs string, pc int,
) (string, int) {
	procs = fmt.Sprintf(
		"%slet %s_to_%s_%d() =\n",
		procs, block.Message.Sender, block.Message.Recipient, pc,
	)
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
			procs, block.Message.Sender, block.Message.Sender,
			c.Name,
			proverifConstant(valKnowledgeMap, block.Message.Sender, c, ""),
		)
	}
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tevent SendMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.Message.Sender, block.Message.Recipient,
			0, proverifConstant(valKnowledgeMap, "", c, ""),
		)
	}
	for _, c := range block.Message.Constants {
		switch c.Guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tout(pub, %s);\n",
				procs, proverifConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s_private, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				proverifConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				proverifConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	procs = fmt.Sprintf(
		"%slet %s_from_%s_%d() =\n",
		procs, block.Message.Recipient, block.Message.Sender, pc,
	)
	for _, c := range block.Message.Constants {
		switch c.Guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s_private, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				proverifConstant(valKnowledgeMap, block.Message.Sender, c, "bitstring"),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				proverifConstant(valKnowledgeMap, block.Message.Sender, c, "bitstring"),
			)
		}
	}
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tevent RecvMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.Message.Sender, block.Message.Recipient, 0,
			proverifConstant(valKnowledgeMap, "", c, ""),
		)
		procs = fmt.Sprintf(
			"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
			procs,
			block.Message.Sender, block.Message.Recipient,
			c.Name,
			proverifConstant(valKnowledgeMap, block.Message.Sender, c, ""),
		)
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, pc
}

func proverifPhase(block Block) string {
	errorCritical("phases are not yet supported in ProVerif model generation")
	return fmt.Sprintf("phase %d;", block.Phase.Number)
}

func proverifModel(m Model) string {
	pv := ""
	procs := ""
	consts := ""
	pc := 0
	cc := 0
	valKnowledgeMap := constructKnowledgeMap(m, sanityDeclaredPrincipals(m))
	for _, block := range m.Blocks {
		switch block.Kind {
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
	pv = pv + proverifTemplates.Parameters(m.Attacker)
	pv = pv + proverifTemplates.Types()
	pv = pv + proverifTemplates.Constants(valKnowledgeMap, consts)
	pv = pv + proverifTemplates.CorePrims()
	pv = pv + proverifTemplates.Prims()
	pv = pv + proverifTemplates.Channels(valKnowledgeMap)
	pv = pv + proverifTemplates.Queries(valKnowledgeMap, m.Queries)
	pv = pv + procs
	pv = pv + proverifTemplates.TopLevel(m.Blocks)
	return pv
}

var proverifTemplates = ProverifTemplate{
	Parameters: func(attacker string) string {
		return strings.Join([]string{
			"set expandIfTermsToTerms = true.",
			"set traceBacktracking = false.",
			"set reconstructTrace = false.",
			fmt.Sprintf("set attacker = %s.", attacker),
		}, "\n") + "\n"
	},
	Types: func() string {
		return strings.Join([]string{
			"type principal.",
			"type stage.",
		}, "\n") + "\n"
	},
	Constants: func(valKnowledgeMap KnowledgeMap, consts string) string {
		output := ""
		for _, principal := range valKnowledgeMap.Principals {
			output = fmt.Sprintf(
				"%sconst principal_%s:principal.\n",
				output, principal,
			)
		}
		for i := 0; i <= valKnowledgeMap.MaxPhase; i++ {
			output = fmt.Sprintf(
				"%sconst phase_%d:stage.\n",
				output, i,
			)
		}
		for _, c := range valKnowledgeMap.Constants {
			priv := ""
			switch c.Qualifier {
			case "private":
				priv = " [private]"
			}
			consts = fmt.Sprintf(
				"%sconst const_%s:bitstring%s.\n",
				consts, c.Name, priv,
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
	CorePrims: func() string {
		return strings.Join([]string{
			"letfun ASSERT(a:bitstring, b:bitstring) = a = b.",
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
	Prims: func() string {
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
			"fun AEAD_DEC_check(bitstring, bitstring, bitstring):bool reduc",
			"\tforall k:bitstring, m:bitstring, ad:bitstring;",
			"\tAEAD_DEC_check(k, AEAD_ENC(k, m, ad), ad) = true",
			"\totherwise forall k:bitstring, m:bitstring, ad:bitstring;",
			"\tAEAD_DEC_check(k, m, ad) = false.",
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
			"fun BLIND(bitstring, bitstring):bitstring.",
			"fun UNBLIND(bitstring, bitstring, bitstring):bitstring reduc",
			"\tforall k:bitstring, m:bitstring, a:bitstring;",
			"\tUNBLIND(k, m, SIGN(a, BLIND(k, m))) = SIGN(a, m)",
			"\totherwise forall k:bitstring, m:bitstring, a:bitstring;",
			"\tUNBLIND(k, m, a) = const_nil.",
		}, "\n") + "\n"
	},
	Channels: func(valKnowledgeMap KnowledgeMap) string {
		channels := []string{"const pub:channel."}
		for i, prin1 := range valKnowledgeMap.Principals {
			for ii, prin2 := range valKnowledgeMap.Principals {
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
	Queries: func(valKnowledgeMap KnowledgeMap, queries []Query) string {
		output := []string{
			"event SendMsg(principal, principal, stage, bitstring).",
			"event RecvMsg(principal, principal, stage, bitstring).",
		}
		for _, q := range queries {
			output = append(output, proverifQuery(valKnowledgeMap, q))
		}
		return strings.Join(output, "\n") + "\n"
	},
	TopLevel: func(blocks []Block) string {
		pc := 0
		parallel := ""
		for i, block := range blocks {
			sep := " | "
			if i == len(blocks)-1 {
				sep = ""
			}
			switch block.Kind {
			case "principal":
				parallel = fmt.Sprintf(
					"%s%s_%d()%s",
					parallel, block.Principal.Name,
					pc, sep,
				)
				pc = pc + 1
			case "message":
				parallel = fmt.Sprintf(
					"%s%s_to_%s_%d()%s",
					parallel, block.Message.Sender,
					block.Message.Recipient, pc, sep,
				)
				pc = pc + 1
				parallel = fmt.Sprintf(
					"%s%s_from_%s_%d()%s",
					parallel, block.Message.Recipient,
					block.Message.Sender, pc, sep,
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
