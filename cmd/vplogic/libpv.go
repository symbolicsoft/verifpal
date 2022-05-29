/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 616bf0023a90ab68ba9e693bf9994779

package vplogic

import (
	"fmt"
	"strings"
)

var libpv = PvTemplate{
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
	Constants: func(valKnowledgeMap *KnowledgeMap, consts string) string {
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
			case typesEnumPrivate:
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
			"fun CONCAT3(bitstring, bitstring, bitstring):bitstring [data].",
			"fun CONCAT4(bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"fun CONCAT5(bitstring, bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"fun SPLIT(bitstring):bitstring reduc forall a:bitstring, b:bitstring;",
			"\tSPLIT(CONCAT2(a, b)) = (a, b)",
			"otherwise forall a:bitstring, b:bitstring, c:bitstring;",
			"\tSPLIT(CONCAT3(a, b, c)) = (a, b, c)",
			"\totherwise forall a:bitstring, b:bitstring, c:bitstring, d:bitstring;",
			"\tSPLIT(CONCAT4(a, b, c, d)) = (a, b, c, d)",
			"\totherwise forall a:bitstring, b:bitstring, c:bitstring, d:bitstring, e:bitstring;",
			"\tSPLIT(CONCAT5(a, b, c, d, e)) = (a, b, c, d, e).",
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
	Channels: func(valKnowledgeMap *KnowledgeMap) string {
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
	Queries: func(valKnowledgeMap *KnowledgeMap, queries []Query) (string, error) {
		output := []string{
			"event SendMsg(principal, principal, stage, bitstring).",
			"event RecvMsg(principal, principal, stage, bitstring).",
		}
		for _, q := range queries {
			pvq, err := pvQuery(valKnowledgeMap, q)
			if err != nil {
				return "", err
			}
			output = append(output, pvq)
		}
		return strings.Join(output, "\n") + "\n", nil
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
					parallel, principalGetNameFromID(block.Message.Sender),
					principalGetNameFromID(block.Message.Recipient), pc, sep,
				)
				pc = pc + 1
				parallel = fmt.Sprintf(
					"%s%s_from_%s_%d()%s",
					parallel, principalGetNameFromID(block.Message.Recipient),
					principalGetNameFromID(block.Message.Sender), pc, sep,
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
