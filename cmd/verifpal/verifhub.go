/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package main

import (
	"fmt"
	"net/url"
)

var VerifHubScheduledShared bool

func VerifHub(m Model, fileName string, resultsCode string) {
	InfoMessage("Your model will now be submitted to VerifHub.", "verifpal", false)
	submitUri := "http://localhost:8080/submit"
	model := url.PathEscape(prettyModel(m))
	link := fmt.Sprintf(
		"%s?name=%s&model=%s&results=%s",
		submitUri, fileName, model, resultsCode,
	)
	OpenBrowser(link)
}
