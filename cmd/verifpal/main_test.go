/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"fmt"
	"testing"

	"verifpal.com/cmd/vplogic"
)

type VerifpalTest struct {
	Model       string
	ResultsCode string
}

var verifpalTests = []VerifpalTest{
	{
		Model:       "challengeresponse.vp",
		ResultsCode: "a0a1",
	},
	{
		Model:       "ephemerals_sign.vp",
		ResultsCode: "c1a0",
	},
	{
		Model:       "hmac_ok.vp",
		ResultsCode: "c0a0",
	},
	{
		Model:       "hmac_unchecked_assert.vp",
		ResultsCode: "c0a1",
	},
	{
		Model:       "hmac_unguarded_alice.vp",
		ResultsCode: "c0a1",
	},
	{
		Model:       "hmac_unguarded_bob.vp",
		ResultsCode: "c1a0",
	},
	{
		Model:       "ok.vp",
		ResultsCode: "c0a0a0",
	},
	{
		Model:       "pke.vp",
		ResultsCode: "c0a0",
	},
	{
		Model:       "pke_unguarded_alice.vp",
		ResultsCode: "c0a1",
	},
	{
		Model:       "pke_unguarded_bob.vp",
		ResultsCode: "c1a0",
	},
	{
		Model:       "pke_unchecked_assert.vp",
		ResultsCode: "c0a1",
	},
	{
		Model:       "pw_hash.vp",
		ResultsCode: "c1c0c0c0c1c1",
	},
	{
		Model:       "pw_hash2.vp",
		ResultsCode: "c0",
	},
	{
		Model:       "shamir.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "subkey.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "subkey_hash.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "subkey_hkdf.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "trivial.vp",
		ResultsCode: "c1a1",
	},
	{
		Model:       "unchecked_aead.vp",
		ResultsCode: "c0a0a0",
	},
	{
		Model:       "unguarded_alice.vp",
		ResultsCode: "c0a1a1",
	},
	{
		Model:       "unguarded_bob.vp",
		ResultsCode: "c1a0a0",
	},
	{
		Model:       "signal_small_leaks.vp",
		ResultsCode: "c1a1",
	},
	{
		Model:       "signal_small_nophase.vp",
		ResultsCode: "c1a1",
	},
	{
		Model:       "signal_small_unguarded.vp",
		ResultsCode: "c1a1",
	},
	{
		Model:       "auth_with_signing.vp",
		ResultsCode: "c1a1a1",
	},
	{
		Model:       "auth_with_signing_false-attack.vp",
		ResultsCode: "c0a0a0",
	},
	{
		Model:       "hmac_verif.vp",
		ResultsCode: "a1a1",
	},
	{
		Model:       "sign_ciphertext.vp",
		ResultsCode: "c0a0",
	},
	{
		Model:       "signature.vp",
		ResultsCode: "c0a0a0",
	},
	{
		Model:       "precondition.vp",
		ResultsCode: "a1",
	},
	{
		Model:       "e_collection_key.vp",
		ResultsCode: "c0a1",
	},
	{
		Model:       "ringsign.vp",
		ResultsCode: "a0",
	},
	{
		Model:       "ringsign_substitute.vp",
		ResultsCode: "a1a0a1a1",
	},
	{
		Model:       "ringsign_unguarded.vp",
		ResultsCode: "a1",
	},
	{
		Model:       "saltchannel.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "concat1.vp",
		ResultsCode: "c1",
	},
	{
		Model:       "concat2.vp",
		ResultsCode: "c0",
	},
	{
		Model:       "freshness.vp",
		ResultsCode: "f1f0",
	},
	{
		Model:       "unlinkability.vp",
		ResultsCode: "u1u1u0",
	},
	{
		Model:       "needham-schroeder-pk.vp",
		ResultsCode: "a1a1c1c1",
	},
	{
		Model:       "needham-schroeder-pk-withfix.vp",
		ResultsCode: "a1a1c1c0",
	},
	{
		Model:       "fullresolution.vp",
		ResultsCode: "c1c1c1c1c0",
	},
}

func TestMain(t *testing.T) {
	for _, v := range verifpalTests {
		testModel(v, t)
	}
}

func testModel(v VerifpalTest, t *testing.T) {
	fileName := fmt.Sprintf("../../examples/test/%s", v.Model)
	_, resultsCode := vplogic.Verify(fileName)
	if resultsCode != v.ResultsCode {
		t.Errorf(
			"   FAIL • %s (%s, got %s)\n",
			v.Model, v.ResultsCode, resultsCode,
		)
	}
}
