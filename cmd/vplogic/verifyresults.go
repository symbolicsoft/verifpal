/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"sync"
	"sync/atomic"
)

var verifyResultsShared []VerifyResult
var verifyResultsFileNameShared string
var verifyResultsMutex sync.RWMutex
var verifyResultsUnresolved int32

func verifyResultsInit(m Model) bool {
	verifyResultsMutex.Lock()
	verifyResultsShared = make([]VerifyResult, len(m.Queries))
	for i, q := range m.Queries {
		verifyResultsShared[i] = VerifyResult{
			Query:    q,
			Resolved: false,
			Summary:  "",
			Options:  []QueryOptionResult{},
		}
	}
	verifyResultsFileNameShared = m.FileName
	atomic.StoreInt32(&verifyResultsUnresolved, int32(len(m.Queries))) //nolint:gosec
	verifyResultsMutex.Unlock()
	return true
}

func verifyResultsGetRead() ([]VerifyResult, string) {
	verifyResultsMutex.RLock()
	valVerifyResults := make([]VerifyResult, len(verifyResultsShared))
	copy(valVerifyResults, verifyResultsShared)
	fileName := verifyResultsFileNameShared
	verifyResultsMutex.RUnlock()
	return valVerifyResults, fileName
}

func verifyResultsPutWrite(result VerifyResult) bool {
	written := false
	qw := prettyQuery(result.Query)
	verifyResultsMutex.Lock()
	for i, verifyResult := range verifyResultsShared {
		qv := prettyQuery(verifyResult.Query)
		if qw == qv && !verifyResultsShared[i].Resolved {
			verifyResultsShared[i].Resolved = result.Resolved
			verifyResultsShared[i].Summary = result.Summary
			written = true
			if result.Resolved {
				atomic.AddInt32(&verifyResultsUnresolved, -1)
			}
		}
	}
	verifyResultsMutex.Unlock()
	return written
}

func verifyResultsAllResolved() bool {
	return atomic.LoadInt32(&verifyResultsUnresolved) <= 0
}
