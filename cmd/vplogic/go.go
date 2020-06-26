/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// ce25ae21cf9eb2957686b8bb45225a31

package vplogic

import (
	"fmt"
)

// Go is supposed to implement Golang generation from Verifpal models. It does not exist yet.
func Go(modelFile string) error {
	return fmt.Errorf("feature not yet implemented")
	// m := libpegParseModel(modelFile, false)
	// fmt.Fprint(os.Stdout, prettyModel(m))
}
