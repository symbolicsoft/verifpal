/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
	"net/url"
)

var VerifHubScheduledShared bool

func VerifHub(m Model, fileName string, resultsCode string) error {
	InfoMessage("Your model will now be submitted to VerifHub.", "verifpal", false)
	submitUri := "https://verifhub.verifpal.com/submit"
	pretty, err := PrettyModel(m)
	if err != nil {
		return err
	}
	model := url.PathEscape(pretty)
	link := fmt.Sprintf(
		"%s?name=%s&model=%s&results=%s",
		submitUri, fileName, model, resultsCode,
	)
	err = OpenBrowser(link)
	return err
}
