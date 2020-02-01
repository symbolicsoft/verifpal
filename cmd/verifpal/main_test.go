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

func TestMain(t *testing.T) {
	tests := []verifpalTest{
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
			resultsCode: "c1a1",
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
			model:       "trivial.vp",
			resultsCode: "c1a1",
		},
		{
			model:       "unchecked_aead.vp",
			resultsCode: "c0a0a1",
		},
		{
			model:       "unguarded_alice.vp",
			resultsCode: "c0a1a1",
		},
		{
			model:       "unguarded_bob.vp",
			resultsCode: "c1a0a1",
		},
		{
			model:       "signal_small.vp",
			resultsCode: "c0a0",
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
			model:       "signal_small_unguarded_alice.vp",
			resultsCode: "c0a1",
		},
		{
			model:       "signal_small_unguarded_bob.vp",
			resultsCode: "c1a0",
		},
	}
	for _, v := range tests {
		testModel(v, t)
	}
}

func testModel(v verifpalTest, t *testing.T) {
	fileName := fmt.Sprintf("../../examples/test/%s", v.model)
	_, resultsCode := verifpal.Verify(fileName)
	if resultsCode != v.resultsCode {
		t.Errorf(
			"%s: Expecting %s, got %s",
			v.model,
			v.resultsCode,
			resultsCode,
		)
	}
}
