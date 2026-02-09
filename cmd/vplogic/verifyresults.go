/* SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"sync"
)

var verifyResultsShared []VerifyResult
var verifyResultsFileNameShared string
var verifyResultsMutex sync.RWMutex

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
		}
	}
	verifyResultsMutex.Unlock()
	return written
}

func verifyResultsAllResolved() bool {
	verifyResultsMutex.RLock()
	allResolved := true
	for _, verifyResult := range verifyResultsShared {
		if !verifyResult.Resolved {
			allResolved = false
			break
		}
	}
	verifyResultsMutex.RUnlock()
	return allResolved
}
