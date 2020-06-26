/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84
package vplogic

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func Json(request string) error {
	reader := bufio.NewReader(os.Stdin)
	inputString, _ := reader.ReadString(byte(0x04))
	inputString = inputString[:len(inputString)-1]
	switch request {
	case "knowledgeMap":
		return JsonKnowledgeMap(inputString)
	case "principalStates":
		return JsonPrincipalStates(inputString)
	case "prettyValue":
		return JsonPrettyValue(inputString)
	case "prettyQuery":
		return JsonPrettyQuery(inputString)
	case "prettyPrint":
		return JsonPrettyPrint(inputString)
	case "prettyDiagram":
		return JsonPrettyDiagram(inputString)
	case "verify":
		return JsonVerify(inputString)
	}
	return fmt.Errorf("invalid json subcommand")
}

func JsonKnowledgeMap(inputString string) error {
	m, err := Parse("model.vp", []byte(inputString))
	if err != nil {
		return err
	}
	valKnowledgeMap, _, err := sanity(m.(Model))
	if err != nil {
		return err
	}
	j, _ := json.Marshal(valKnowledgeMap)
	fmt.Fprint(os.Stdout, string(j))
	return nil
}

func JsonPrincipalStates(inputString string) error {
	m, err := Parse("model.vp", []byte(inputString))
	if err != nil {
		return err
	}
	_, valPrincipalStates, err := sanity(m.(Model))
	if err != nil {
		return err
	}
	j, _ := json.Marshal(valPrincipalStates)
	fmt.Fprint(os.Stdout, string(j))
	return nil
}

func JsonPrettyValue(inputString string) error {
	a := Value{}
	err := json.Unmarshal([]byte(inputString), &a)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, prettyValue(a))
	return nil
}

func JsonPrettyQuery(inputString string) error {
	q := Query{}
	err := json.Unmarshal([]byte(inputString), &q)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, prettyQuery(q))
	return nil
}

func JsonPrettyPrint(inputString string) error {
	m, err := Parse("model.vp", []byte(inputString))
	if err != nil {
		return err
	}
	pretty, err := PrettyModel(m.(Model))
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, pretty)
	return nil
}

func JsonPrettyDiagram(inputString string) error {
	m, err := Parse("model.vp", []byte(inputString))
	if err != nil {
		return err
	}
	pretty, err := PrettyDiagram(m.(Model))
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, pretty)
	return nil
}

func JsonVerify(inputString string) error {
	m, err := Parse("model.vp", []byte(inputString))
	if err != nil {
		return err
	}
	valVerifyResults, _, err := verifyModel(m.(Model))
	if err != nil {
		return err
	}
	j, _ := json.Marshal(valVerifyResults)
	fmt.Fprint(os.Stdout, string(j))
	return nil
}
