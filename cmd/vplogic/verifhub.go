/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
	"net/url"
)

// VerifHubScheduledShared is a global variable that tracks whether
// VerifHub submission has been enabled for this analysis.
var VerifHubScheduledShared bool

// VerifHub submits the given Verifpal model to VerifHub by opening
// the user's browser with the formatted model submission URI.
func VerifHub(m Model, fileName string, resultsCode string) error {
	InfoMessage("Your model will now be submitted to VerifHub.", "verifpal", false)
	submitURI := "https://verifhub.verifpal.com/submit"
	pretty, err := PrettyModel(m)
	if err != nil {
		return err
	}
	model := url.PathEscape(pretty)
	link := fmt.Sprintf(
		"%s?name=%s&model=%s&results=%s",
		submitURI, fileName, model, resultsCode,
	)
	err = OpenBrowser(link)
	return err
}
