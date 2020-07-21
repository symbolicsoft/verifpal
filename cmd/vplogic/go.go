/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// ce25ae21cf9eb2957686b8bb45225a31

package vplogic

import (
	"fmt"
	"os"
	"strings"
)

// Go translates a Verifpal model to a prototype implementation written in Go.
func Go(modelFile string) error {
	m, err := libpegParseModel(modelFile, false)
	if err != nil {
		return err
	}
	goString, err := goModel(m)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, goString)
	return nil
}

func goConstant(c Constant) string {
	if c.Guard {
		return fmt.Sprintf("[%s]", c.Name)
	}
	if c.Name == "g" {
		return "G"
	}
	return c.Name
}

func goConstants(c []Constant) string {
	goString := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		goString = fmt.Sprintf("%s%s%s",
			goString, goConstant(v), sep,
		)
	}
	return goString
}

func goPrimitive(p Primitive) string {
	goString := fmt.Sprintf("%s(", p.Name)
	check := ""
	if p.Check {
		check = "?"
	}
	for i, arg := range p.Arguments {
		sep := ""
		if i != (len(p.Arguments) - 1) {
			sep = ", "
		}
		goString = fmt.Sprintf("%s%s%s",
			goString, goValue(arg), sep,
		)
	}
	return fmt.Sprintf("%s)%s",
		goString, check,
	)
}

func goEquation(e Equation) string {
	goString := ""
	for i, c := range e.Values {
		if i == 0 {
			goString = goValue(c)
		} else {
			goString = fmt.Sprintf(
				"%s^%s",
				goString, goValue(c),
			)
		}
	}
	return goString
}

func goValue(a Value) string {
	switch a.Kind {
	case "constant":
		return goConstant(a.Constant)
	case "primitive":
		return goPrimitive(a.Primitive)
	case "equation":
		return goEquation(a.Equation)
	}
	return ""
}

func goPrincipal(block Block, pc int) (string, int, error) {
	output := fmt.Sprintf(
		"func %s%d() error {\n",
		block.Principal.Name, pc,
	)
	for _, expression := range block.Principal.Expressions {
		e, err := goExpression(expression)
		if err != nil {
			return "", pc, err
		}
		output = fmt.Sprintf(
			"%s\t%s\n",
			output, e,
		)
	}
	output = fmt.Sprintf("%s}\n\n", output)
	return output, pc + 1, nil
}

func goExpression(expression Expression) (string, error) {
	output := ""
	switch expression.Kind {
	case "knows":
		output = fmt.Sprintf(
			"%s %s %s",
			expression.Kind,
			expression.Qualifier,
			goConstants(expression.Constants),
		)
	case "generates":
		for _, c := range expression.Constants {
			output = fmt.Sprintf(
				"%s := GENERATES()\n\tif err != nil {\n\t\treturn err\n\t}",
				c.Name,
			)
		}
	case "leaks":
		return "", fmt.Errorf("%s %s",
			"`leaks` keywords do not make sense",
			"in an implementation template",
		)
	case "assignment":
		right := goValue(expression.Assigned)
		left := []Constant{}
		for i, c := range expression.Constants {
			left = append(left, c)
			if strings.HasPrefix(c.Name, "unnamed") {
				left[i].Name = "_"
			}
		}
		output = fmt.Sprintf(
			"%s = %s",
			goConstants(left),
			right,
		)
	}
	return output, nil
}

func goMessage(block Block) string {
	output := fmt.Sprintf(
		"%s -> %s: %s\n\n",
		block.Message.Sender,
		block.Message.Recipient,
		goConstants(block.Message.Constants),
	)
	return output
}

func goPhase(block Block) string {
	output := fmt.Sprintf(
		"phase[%d]\n\n",
		block.Phase.Number,
	)
	return output
}

func goModel(m Model) (string, error) {
	pc := 0
	_, _, err := sanity(m)
	if err != nil {
		return "", err
	}
	output := ""
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			p := ""
			p, pc, err = goPrincipal(block, pc)
			if err != nil {
				return "", err
			}
			output = output + p
		case "message":
			output = output + goMessage(block)
		case "phase":
			output = output + goPhase(block)
		}
	}
	output = fmt.Sprintf("%s\n%s", libgo, output)
	return output, nil
}
