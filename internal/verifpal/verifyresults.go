/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import (
	"strings"
	"sync"
)

var verifyResultsShared []verifyResult
var verifyResultsMutex sync.Mutex

func verifyResultsInit(m Model) bool {
	verifyResultsMutex.Lock()
	verifyResultsShared = make([]verifyResult, len(m.queries))
	for i, q := range m.queries {
		verifyResultsShared[i] = verifyResult{
			query:    q,
			resolved: false,
			summary:  "",
		}
	}
	verifyResultsMutex.Unlock()
	return true
}

func verifyResultsGetRead() []verifyResult {
	verifyResultsMutex.Lock()
	valVerifyResults := make([]verifyResult, len(verifyResultsShared))
	copy(valVerifyResults, verifyResultsShared)
	verifyResultsMutex.Unlock()
	return valVerifyResults
}

func verifyResultsPutWrite(result verifyResult) bool {
	written := false
	qw := prettyQuery(result.query)
	verifyResultsMutex.Lock()
	for i, verifyResult := range verifyResultsShared {
		qv := prettyQuery(verifyResult.query)
		if strings.Compare(qw, qv) == 0 {
			if !verifyResultsShared[i].resolved {
				verifyResultsShared[i].resolved = result.resolved
				verifyResultsShared[i].summary = result.summary
				written = true
			}
		}
	}
	verifyResultsMutex.Unlock()
	return written
}

func verifyResultsAllResolved() bool {
	allResolved := true
	verifyResultsMutex.Lock()
	for _, verifyResult := range verifyResultsShared {
		if !verifyResult.resolved {
			allResolved = false
			break
		}
	}
	verifyResultsMutex.Unlock()
	return allResolved
}
