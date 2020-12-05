/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84

// Package vplogic provides the core logic for all of Verifpal, allowing it to
// be imported as a package for use within other software.
package vplogic

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// JSON processes JSON requests made to Verifpal via the Visual Studio Code extension.
func JSON(request string) error {
	reader := bufio.NewReader(os.Stdin)
	inputString, _ := reader.ReadString(byte(0x04))
	inputString = inputString[:len(inputString)-1]
	switch request {
	case "knowledgeMap":
		return JSONKnowledgeMap(inputString)
	case "principalStates":
		return JSONPrincipalStates(inputString)
	case "prettyValue":
		return JSONPrettyValue(inputString)
	case "prettyQuery":
		return JSONPrettyQuery(inputString)
	case "prettyPrint":
		return JSONPrettyPrint(inputString)
	case "prettyDiagram":
		return JSONPrettyDiagram(inputString)
	case "verify":
		return JSONVerify(inputString)
	}
	return fmt.Errorf("invalid json subcommand")
}

// JSONKnowledgeMap returns the KnowledgeMap struct for a given model in JSON format.
func JSONKnowledgeMap(inputString string) error {
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

// JSONPrincipalStates returns the KnowledgeMap struct for a given model in JSON format.
func JSONPrincipalStates(inputString string) error {
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

// JSONPrettyValue pretty-prints a Verifpal value expression and returns the result in JSON format.
func JSONPrettyValue(inputString string) error {
	a := Value{}
	err := json.Unmarshal([]byte(inputString), &a)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, prettyValue(a))
	return nil
}

// JSONPrettyQuery pretty-prints a Verifpal query expression and returns the result in JSON format.
func JSONPrettyQuery(inputString string) error {
	q := Query{}
	err := json.Unmarshal([]byte(inputString), &q)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, prettyQuery(q))
	return nil
}

// JSONPrettyPrint pretty-prints a Verifpal model and returns the result in JSON format.
func JSONPrettyPrint(inputString string) error {
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

// JSONPrettyDiagram formats a Verifpal model into a sequence diagram and returns the result in JSON format.
func JSONPrettyDiagram(inputString string) error {
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

// JSONVerify returns the verification result of a Verifpal model in JSON format.
func JSONVerify(inputString string) error {
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
