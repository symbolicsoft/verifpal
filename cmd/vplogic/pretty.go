/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 362636d0e0b1ba89495c376703a829e8

package vplogic

import (
	"fmt"
	"os"
	"strings"
)

// PrettyPrint pretty-prints a Verifpal model based on a model loaded from a file.
func PrettyPrint(modelFile string) error {
	m, err := libpegParseModel(modelFile, false)
	if err != nil {
		return err
	}
	pretty, err := PrettyModel(m)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, pretty)
	return nil
}

func prettyConstant(c *Constant) string {
	if c.Guard {
		return fmt.Sprintf("[%s]", c.Name)
	}
	if c.Name == "g" {
		return "G"
	}
	return c.Name
}

func prettyConstants(c []*Constant) string {
	pretty := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		pretty = fmt.Sprintf("%s%s%s",
			pretty, prettyConstant(v), sep,
		)
	}
	return pretty
}

func prettyPrimitive(p *Primitive) string {
	pretty := ""
	if primitiveIsCorePrim(p.ID) {
		prim, _ := primitiveCoreGet(p.ID)
		pretty = fmt.Sprintf("%s(", prim.Name)
	} else {
		prim, _ := primitiveGet(p.ID)
		pretty = fmt.Sprintf("%s(", prim.Name)
	}
	check := ""
	if p.Check {
		check = "?"
	}
	for i, arg := range p.Arguments {
		sep := ""
		if i != (len(p.Arguments) - 1) {
			sep = ", "
		}
		pretty = fmt.Sprintf("%s%s%s",
			pretty, prettyValue(arg), sep,
		)
	}
	return fmt.Sprintf("%s)%s",
		pretty, check,
	)
}

func prettyEquation(e *Equation) string {
	pretty := ""
	for i, c := range e.Values {
		if i == 0 {
			pretty = prettyValue(c)
		} else {
			pretty = fmt.Sprintf(
				"%s^%s",
				pretty, prettyValue(c),
			)
		}
	}
	return pretty
}

func prettyValue(a *Value) string {
	switch a.Kind {
	case typesEnumConstant:
		return prettyConstant(a.Data.(*Constant))
	case typesEnumPrimitive:
		return prettyPrimitive(a.Data.(*Primitive))
	case typesEnumEquation:
		return prettyEquation(a.Data.(*Equation))
	}
	return ""
}

func prettyValues(a []*Value) string {
	pretty := ""
	for i, v := range a {
		sep := ", "
		if i == len(a)-1 {
			sep = ""
		}
		pretty = fmt.Sprintf(
			"%s%s%s",
			pretty, prettyValue(v), sep,
		)
	}
	return pretty
}

func prettyQuery(query Query) string {
	output := ""
	switch query.Kind {
	case typesEnumConfidentiality:
		output = fmt.Sprintf(
			"confidentiality? %s",
			prettyConstants(query.Constants),
		)
	case typesEnumAuthentication:
		output = fmt.Sprintf(
			"authentication? %s -> %s: %s",
			principalGetNameFromID(query.Message.Sender),
			principalGetNameFromID(query.Message.Recipient),
			prettyConstants(query.Message.Constants),
		)
	case typesEnumFreshness:
		output = fmt.Sprintf(
			"freshness? %s",
			prettyConstants(query.Constants),
		)
	case typesEnumUnlinkability:
		output = fmt.Sprintf(
			"unlinkability? %s",
			prettyConstants(query.Constants),
		)
	}
	if len(query.Options) > 0 {
		output = fmt.Sprintf("%s[", output)
	}
	for _, option := range query.Options {
		switch option.Kind {
		case typesEnumPrecondition:
			output = fmt.Sprintf(
				"%s\n\t\tprecondition[%s -> %s: %s]",
				output, principalGetNameFromID(option.Message.Sender),
				principalGetNameFromID(option.Message.Recipient),
				prettyConstants(option.Message.Constants),
			)
		}
	}
	if len(query.Options) > 0 {
		output = fmt.Sprintf("%s\n\t]", output)
	}
	return output
}

func prettyPrincipal(block Block) string {
	output := fmt.Sprintf(
		"principal %s[\n",
		block.Principal.Name,
	)
	for _, expression := range block.Principal.Expressions {
		output = fmt.Sprintf(
			"%s\t%s\n",
			output, prettyExpression(expression),
		)
	}
	output = fmt.Sprintf("%s]\n\n", output)
	return output
}

func prettyExpression(expression Expression) string {
	output := ""
	switch expression.Kind {
	case typesEnumKnows:
		switch expression.Qualifier {
		case typesEnumPrivate:
			output = fmt.Sprintf(
				"knows private %s",
				prettyConstants(expression.Constants),
			)
		case typesEnumPublic:
			output = fmt.Sprintf(
				"knows public %s",
				prettyConstants(expression.Constants),
			)
		case typesEnumPassword:
			output = fmt.Sprintf(
				"knows password %s",
				prettyConstants(expression.Constants),
			)
		}
	case typesEnumGenerates:
		output = fmt.Sprintf(
			"generates %s",
			prettyConstants(expression.Constants),
		)
	case typesEnumLeaks:
		output = fmt.Sprintf(
			"leaks %s",
			prettyConstants(expression.Constants),
		)
	case typesEnumAssignment:
		right := prettyValue(expression.Assigned)
		left := []*Constant{}
		for i, c := range expression.Constants {
			left = append(left, c)
			if strings.HasPrefix(c.Name, "unnamed") {
				left[i].Name = "_"
			}
		}
		output = fmt.Sprintf(
			"%s = %s",
			prettyConstants(left),
			right,
		)
	}
	return output
}

func prettyMessage(block Block) string {
	output := fmt.Sprintf(
		"%s -> %s: %s\n\n",
		principalGetNameFromID(block.Message.Sender),
		principalGetNameFromID(block.Message.Recipient),
		prettyConstants(block.Message.Constants),
	)
	return output
}

func prettyPhase(block Block) string {
	output := fmt.Sprintf(
		"phase[%d]\n\n",
		block.Phase.Number,
	)
	return output
}

// PrettyModel pretty-prints a Verifpal model that has already
// been parsed into the Model struct.
func PrettyModel(m Model) (string, error) {
	_, _, err := sanity(m)
	if err != nil {
		return "", err
	}
	output := fmt.Sprintf(
		"attacker[%s]\n\n",
		m.Attacker,
	)
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			output = output + prettyPrincipal(block)
		case "message":
			output = output + prettyMessage(block)
		case "phase":
			output = output + prettyPhase(block)
		}
	}
	output = fmt.Sprintf("%squeries[\n", output)
	for _, query := range m.Queries {
		output = fmt.Sprintf(
			"%s\t%s\n", output, prettyQuery(query),
		)
	}
	output = fmt.Sprintf("%s]\n", output)
	return output, nil
}

// PrettyDiagram generates a sequence diagram format based on a Verifpal model.
func PrettyDiagram(m Model) (string, error) {
	_, _, err := sanity(m)
	if err != nil {
		return "", err
	}
	output := ""
	firstPrincipal := ""
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			output = fmt.Sprintf(
				"%sNote over %s: ",
				output, block.Principal.Name,
			)
			if len(firstPrincipal) == 0 {
				firstPrincipal = block.Principal.Name
			}
			for _, expression := range block.Principal.Expressions {
				output = fmt.Sprintf(
					"%s\t%s\\n",
					output, prettyExpression(expression),
				)
			}
			output = fmt.Sprintf("%s\n", output)
		case "message":
			output = output + prettyMessage(block)
		case "phase":
			output = fmt.Sprintf(
				"%sNote left of %s:phase %d\n",
				output, firstPrincipal, block.Phase.Number,
			)
		}
	}
	return output, nil
}

func prettyArity(specArity []int) string {
	arityString := ""
	if len(specArity) == 1 {
		arityString = fmt.Sprintf("%d", specArity[0])
	} else {
		for i, a := range specArity {
			if i != len(specArity)-1 {
				arityString = fmt.Sprintf("%s%d, ", arityString, a)
			} else {
				arityString = fmt.Sprintf("%sor %d", arityString, a)
			}
		}
	}
	return arityString
}
