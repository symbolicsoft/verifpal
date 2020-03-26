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

func proverifPrimitive(p primitive) string {
	return ""
}

func proverifEquation(e equation) string {
	return ""
}

func proverifValue(a value) string {
	return ""
}

func proverifValues(a []value) string {
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

func proverifModel(m Model) string {
	pv := ""
	pv = pv + proverifTemplates.parameters(m.attacker)
	pv = pv + proverifTemplates.types()
	pv = pv + proverifTemplates.constants()
	pv = pv + proverifTemplates.coreprims()
	pv = pv + proverifTemplates.prims()
	pv = pv + proverifTemplates.channels()
	pv = pv + proverifTemplates.queries(m.queries)
	// pv = pv + proverifTemplates.procs()
	pv = pv + proverifTemplates.toplevel()
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
			"type key.",
		}, "\n") + "\n"
	},
	constants: func() string {
		return strings.Join([]string{
			"const generator:key   [data].",
			"const empty:bitstring [data].",
			"fun shamir_keys_pack(key, key, key):bitstring [data].",
			"reduc forall a:key, b:key, c:key;",
			"	shamir_keys_unpack(shamir_keys_pack(a, b, c)) = (a, b, c).",
		}, "\n") + "\n"
	},
	coreprims: func() string {
		return strings.Join([]string{
			"fun CONCAT2(bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring;",
			"	SPLIT2(CONCAT2(a, b)) = (a, b).",
			"fun CONCAT3(bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring;",
			"	SPLIT3(CONCAT3(a, b, c)) = (a, b, c).",
			"fun CONCAT4(bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring, d:bitstring;",
			"	SPLIT4(CONCAT4(a, b, c, d)) = (a, b, c, d).",
			"fun CONCAT5(bitstring, bitstring, bitstring, bitstring, bitstring):bitstring [data].",
			"reduc forall a:bitstring, b:bitstring, c:bitstring, d:bitstring, e:bitstring;",
			"	SPLIT5(CONCAT5(a, b, c, d, e)) = (a, b, c, d, e).",
		}, "\n") + "\n"
	},
	prims: func() string {
		return strings.Join([]string{
			"fun exp(key, key):key.",
			"equation forall a:key, b:key;",
			"  exp(b, exp(a, generator)) = exp(a, exp(b, generator)).",
			"letfun G(basis:key) =",
			"	exp(basis, generator).",
			"fun HASH(bitstring, bitstring):bitstring.",
			"fun MAC(key, bitstring): bitstring.",
			"fun hmac_hash1(key, key):key.",
			"fun hmac_hash2(key, key):key.",
			"fun hmac_hash3(key, key):key.",
			"letfun HKDF(chaining_key:key, input_key_material:key) =",
			"	let output1 = hmac_hash1(chaining_key, input_key_material) in",
			"	let output2 = hmac_hash2(chaining_key, input_key_material) in",
			"	let output3 = hmac_hash3(chaining_key, input_key_material) in",
			"	(output1, output2, output3).",
			"fun PW_HASH(bitstring): bitstring.",
			"fun ENC(key, bitstring):bitstring.",
			"fun DEC(key, bitstring):bitstring reduc",
			"	forall k:key, m:bitstring;",
			"		DEC(k, ENC(k, m)) = m",
			"	otherwise forall k:key, m:bitstring;",
			"		DEC(k, m) = empty.",
			"fun AEAD_ENC(key, bitstring, bitstring):bitstring.",
			"fun AEAD_DEC(key, bitstring, bitstring):bitstring reduc",
			"	forall k:key, m:bitstring, ad:bitstring;",
			"		AEAD_DEC(k, AEAD_ENC(k, m, ad), ad) = m.",
			"fun PKE_ENC(key, bitstring):bitstring.",
			"fun PKE_DEC(key, bitstring):bitstring reduc",
			"	forall k:key, m:bitstring;",
			"		PKE_DEC(k, PKE_ENC(exp(k, generator), m)) = m.",
			"fun SIGN(key, bitstring):bitstring.",
			"fun SIGNVERIF(key, bitstring, bitstring):bool reduc",
			"	forall sk:key, m:bitstring;",
			"		SIGNVERIF(exp(sk, generator), SIGN(sk, m), m) = true",
			"	otherwise forall pk:key, s:bitstring, m:bitstring;",
			"		SIGNVERIF(pk, s, m) = false.",
			"fun RINGSIGN(key, key, key, bitstring):bitstring.",
			"fun shamir_split1(key):key.",
			"fun shamir_split2(key):key.",
			"fun shamir_split3(key):key.",
			"letfun SHAMIR_SPLIT(k:key) =",
			"	let k1 = shamir_split1(k) in",
			"	let k2 = shamir_split2(k) in",
			"	let k3 = shamir_split3(k) in",
			"	(k1, k2, k3).",
			"fun SHAMIR_JOIN(key, key):key reduc",
			"	forall k:key;",
			"		SHAMIR_JOIN(shamir_split1(k), shamir_split2(k)) = k",
			"	otherwise forall k:key;",
			"		SHAMIR_JOIN(shamir_split2(k), shamir_split1(k)) = k",
			"	otherwise forall k:key;",
			"		SHAMIR_JOIN(shamir_split1(k), shamir_split3(k)) = k",
			"	otherwise forall k:key;",
			"		SHAMIR_JOIN(shamir_split3(k), shamir_split1(k)) = k",
			"	otherwise forall k:key;",
			"		SHAMIR_JOIN(shamir_split2(k), shamir_split3(k)) = k",
			"	otherwise forall k:key;",
			"		SHAMIR_JOIN(shamir_split3(k), shamir_split2(k)) = k.",
		}, "\n") + "\n"
	},
	channels: func() string {
		return strings.Join([]string{
			"const pub:channel.",
		}, "\n") + "\n"
	},
	queries: func(queries []query) string {
		output := []string{}
		for _, q := range queries {
			output = append(output, proverifQuery(q))
		}
		return strings.Join(output, "\n") + "\n"
	},
	procs: func() string {
		return strings.Join([]string{}, "\n") + "\n"
	},
	toplevel: func() string {
		return strings.Join([]string{
			"process (",
			"	out(pub, generator)",
			")",
		}, "\n") + "\n"
	},
}
