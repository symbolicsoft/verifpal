/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"sync"
)

var verifyResultsShared []verifyResult
var verifyResultsFileNameShared string
var verifyResultsMutex sync.Mutex

func verifyResultsInit(m Model) bool {
	verifyResultsMutex.Lock()
	verifyResultsShared = make([]verifyResult, len(m.queries))
	for i, q := range m.queries {
		verifyResultsShared[i] = verifyResult{
			query:    q,
			resolved: false,
			summary:  "",
			options:  []queryOptionResult{},
		}
	}
	verifyResultsFileNameShared = m.fileName
	verifyResultsMutex.Unlock()
	return true
}

func verifyResultsGetRead() ([]verifyResult, string) {
	verifyResultsMutex.Lock()
	valVerifyResults := make([]verifyResult, len(verifyResultsShared))
	copy(valVerifyResults, verifyResultsShared)
	fileName := verifyResultsFileNameShared
	verifyResultsMutex.Unlock()
	return valVerifyResults, fileName
}

func verifyResultsPutWrite(result verifyResult) bool {
	written := false
	qw := prettyQuery(result.query)
	verifyResultsMutex.Lock()
	for i, verifyResult := range verifyResultsShared {
		qv := prettyQuery(verifyResult.query)
		if qw == qv && !verifyResultsShared[i].resolved {
			verifyResultsShared[i].resolved = result.resolved
			verifyResultsShared[i].summary = result.summary
			written = true
		}
	}
	verifyResultsMutex.Unlock()
	return written
}

func verifyResultsAllResolved() bool {
	allResolved := true
	for _, verifyResult := range verifyResultsShared {
		if !verifyResult.resolved {
			allResolved = false
			break
		}
	}
	return allResolved
}
