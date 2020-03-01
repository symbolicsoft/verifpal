/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"fmt"
	"testing"

	"verifpal.com/internal/verifpal"
)

type verifpalTest struct {
	model       string
	resultsCode string
}

var verifpalTests = []verifpalTest{
	{
		model:       "challengeresponse.vp",
		resultsCode: "a0a1",
	},
	{
		model:       "ephemerals_sign.vp",
		resultsCode: "c1a0",
	},
	{
		model:       "hmac_ok.vp",
		resultsCode: "c0a0",
	},
	{
		model:       "hmac_unchecked_assert.vp",
		resultsCode: "c0a1",
	},
	{
		model:       "hmac_unguarded_alice.vp",
		resultsCode: "c0a1",
	},
	{
		model:       "hmac_unguarded_bob.vp",
		resultsCode: "c1a0",
	},
	{
		model:       "ok.vp",
		resultsCode: "c0a0a0",
	},
	{
		model:       "pke.vp",
		resultsCode: "c0a0",
	},
	{
		model:       "pke_unguarded_alice.vp",
		resultsCode: "c0a1",
	},
	{
		model:       "pke_unguarded_bob.vp",
		resultsCode: "c1a0",
	},
	{
		model:       "pke_unchecked_assert.vp",
		resultsCode: "c0a1",
	},
	{
		model:       "pw_hash.vp",
		resultsCode: "c1c0c0c0c1c1",
	},
	{
		model:       "shamir.vp",
		resultsCode: "c1",
	},
	{
		model:       "subkey.vp",
		resultsCode: "c1",
	},
	{
		model:       "subkey_hash.vp",
		resultsCode: "c1",
	},
	{
		model:       "subkey_hkdf.vp",
		resultsCode: "c1",
	},
	{
		model:       "trivial.vp",
		resultsCode: "c1a1",
	},
	{
		model:       "unchecked_aead.vp",
		resultsCode: "c0a0a0",
	},
	{
		model:       "unguarded_alice.vp",
		resultsCode: "c0a1a1",
	},
	{
		model:       "unguarded_bob.vp",
		resultsCode: "c1a0a0",
	},
	{
		model:       "signal_small_leaks.vp",
		resultsCode: "c1a1",
	},
	{
		model:       "signal_small_nophase.vp",
		resultsCode: "c1a1",
	},
	{
		model:       "signal_small_unguarded.vp",
		resultsCode: "c1a1",
	},
	{
		model:       "auth_with_signing.vp",
		resultsCode: "c1a1a1",
	},
	{
		model:       "auth_with_signing_false-attack.vp",
		resultsCode: "c0a0a0",
	},
	{
		model:       "hmac_verif.vp",
		resultsCode: "a1a1",
	},
	{
		model:       "sign_ciphertext.vp",
		resultsCode: "c0a0",
	},
	{
		model:       "signature.vp",
		resultsCode: "c0a0a0",
	},
	{
		model:       "precondition.vp",
		resultsCode: "a1",
	},
	{
		model:       "e_collection_key.vp",
		resultsCode: "c0a1",
	},
	{
		model:       "ringsign.vp",
		resultsCode: "a0",
	},
	{
		model:       "ringsign_substitute.vp",
		resultsCode: "a1a1a1a1",
	},
	{
		model:       "ringsign_unguarded.vp",
		resultsCode: "a1",
	},
	{
		model:       "saltchannel.vp",
		resultsCode: "c1",
	},
	{
		model:       "concat1.vp",
		resultsCode: "c1",
	},
	{
		model:       "concat2.vp",
		resultsCode: "c0",
	},
}

func TestMain(t *testing.T) {
	for _, v := range verifpalTests {
		testModel(v, t)
	}
}

func testModel(v verifpalTest, t *testing.T) {
	fileName := fmt.Sprintf("../../examples/test/%s", v.model)
	_, resultsCode := verifpal.Verify(fileName)
	if resultsCode != v.resultsCode {
		t.Errorf(
			"   FAIL • %s (%s, got %s)\n",
			v.model, v.resultsCode, resultsCode,
		)
	}
}
