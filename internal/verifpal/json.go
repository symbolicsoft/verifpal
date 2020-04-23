/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84
package verifpal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func Json(request string) {
	reader := bufio.NewReader(os.Stdin)
	inputString, _ := reader.ReadString(byte(0x04))
	inputString = inputString[:len(inputString)-1]
	j := []byte{}
	switch request {
	case "knowledgeMap":
		m, err := Parse("model.vp", []byte(inputString))
		if err != nil {
			errorCritical(err.Error())
		}
		valKnowledgeMap, _ := sanity(m.(Model))
		j, _ = json.Marshal(valKnowledgeMap)
	case "principalStates":
		m, err := Parse("model.vp", []byte(inputString))
		if err != nil {
			errorCritical(err.Error())
		}
		_, valPrincipalStates := sanity(m.(Model))
		j, _ = json.Marshal(valPrincipalStates)
	case "prettyValue":
		a := Value{}
		err := json.Unmarshal([]byte(inputString), &a)
		if err != nil {
			errorCritical(err.Error())
		}
		fmt.Fprint(os.Stdout, prettyValue(a))
	case "prettyPrint":
		m, err := Parse("model.vp", []byte(inputString))
		if err != nil {
			errorCritical(err.Error())
		}
		fmt.Fprint(os.Stdout, prettyModel(m.(Model)))
	}
	fmt.Fprint(os.Stdout, string(j))
}
