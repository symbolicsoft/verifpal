/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package verifpal

import "strings"

var verifyResultsReady chan bool = make(chan bool)
var verifyResultsReads chan verifyResultsRead = make(chan verifyResultsRead)
var verifyResultsWrites chan verifyResultsWrite = make(chan verifyResultsWrite)

func verifyResultsInit(m Model) bool {
	go func() {
		verifyResults := []VerifyResult{}
		for _, q := range m.queries {
			verifyResults = append(verifyResults, VerifyResult{
				query:    q,
				resolved: false,
				summary:  "",
			})
		}
		verifyResultsReady <- true
		for {
			select {
			case read := <-verifyResultsReads:
				read.resp <- verifyResults
			case write := <-verifyResultsWrites:
				written := false
				qw := prettyQuery(write.verifyResult.query)
				for i, verifyResult := range verifyResults {
					qv := prettyQuery(verifyResult.query)
					if strings.Compare(qw, qv) == 0 {
						if !verifyResults[i].resolved {
							verifyResults[i].resolved = write.verifyResult.resolved
							verifyResults[i].summary = write.verifyResult.summary
							written = true
						}
					}
				}
				write.resp <- written
			}
		}
	}()
	return <-verifyResultsReady
}

func verifyResultsGetRead() []VerifyResult {
	read := verifyResultsRead{
		resp: make(chan []VerifyResult),
	}
	verifyResultsReads <- read
	return <-read.resp
}

func verifyResultsPutWrite(write verifyResultsWrite) bool {
	verifyResultsWrites <- write
	return <-write.resp
}

func verifyResultsAllResolved(verifyResults []VerifyResult) bool {
	for _, verifyResult := range verifyResults {
		if !verifyResult.resolved {
			return false
		}
	}
	return true
}
