/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84
package verifpal

import (
	"encoding/json"
	"fmt"
	"os"
)

func Json(request string, filePath string) {
	m := parserParseModel(filePath, false)
	j := []byte{}
	switch request {
	case "knowledgeMap":
		valKnowledgeMap, _ := sanity(m)
		j, _ = json.Marshal(valKnowledgeMap)
	case "principalStates":
		_, valPrincipalStates := sanity(m)
		j, _ = json.Marshal(valPrincipalStates)
	}
	fmt.Fprint(os.Stdout, string(j))
}
