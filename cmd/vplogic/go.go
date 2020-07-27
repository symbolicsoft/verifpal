/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// ce25ae21cf9eb2957686b8bb45225a31

package vplogic

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Go translates a Verifpal model to a prototype implementation written in Go.
func Go(modelFile string) error {
	log.Fatal("go translation not yet implemented")
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

// nolint:unused
func goConstant(c Constant) string {
	if c.Guard {
		return fmt.Sprintf("[%s]", c.Name)
	}
	if c.Name == "g" {
		return "G"
	}
	return c.Name
}

// nolint:unused
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

// nolint:unused
func goPrimitiveName(p Primitive) string {
	goName := strings.ToLower(p.Name)
	switch goName {
	case "split", "hkdf":
		return fmt.Sprintf("%s%d",
			p.Name, len(p.Arguments),
		)
	case "pw_hash":
		return "pwHash"
	case "aead_enc":
		return "aeadEnc"
	case "aead_dec":
		return "aeadDec"
	case "pke_enc":
		return "pkeEnc"
	case "pke_dec":
		return "pkeDec"
	case "shamir_split":
		return "shamirSplit"
	case "shamir_join":
		return "shamirJoin"
	default:
		return goName
	}
}

// nolint:unused
func goPrimitive(p Primitive) string {
	goString := fmt.Sprintf("%s(",
		goPrimitiveName(p),
	)
	check := ""
	for i, arg := range p.Arguments {
		sep := ""
		if i != (len(p.Arguments) - 1) {
			sep = ", "
		}
		goString = fmt.Sprintf("%s%s%s",
			goString, goValue(arg), sep,
		)
	}
	goString = fmt.Sprintf("%s)%s",
		goString, check,
	)
	if p.Check {
		goString = fmt.Sprintf(
			"%s\n\tif err != nil {\n\t\treturn err\n\t}",
			goString,
		)
	}
	return goString
}

// nolint:unused
func goEquation(e Equation) string {
	goString := ""
	switch len(e.Values) {
	case 2:
		return "dh()"
	case 3:
		return "dh()"
	}
	return goString
}

// nolint:unused
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

// nolint:unused
func goPrincipal(block Block, pc int) (string, int, error) {
	output := fmt.Sprintf(
		"func %s%d() error {\n\tvar err error\n",
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

// nolint:unused
func goExpression(expression Expression) (string, error) {
	output := ""
	switch expression.Kind {
	case "knows":
		for _, c := range expression.Constants {
			output = fmt.Sprintf(
				"%s_%s := \"%s\"",
				expression.Qualifier, c.Name, c.Name,
			)
		}
	case "generates":
		for _, c := range expression.Constants {
			output = fmt.Sprintf(
				"%s, _, err := ed25519Gen()\n\tif err != nil {\n\t\treturn err\n\t}",
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
			"%s, err := %s",
			goConstants(left),
			right,
		)
	}
	return output, nil
}

// nolint:unused
func goMessage(block Block) string {
	output := fmt.Sprintf(
		"%s -> %s: %s\n\n",
		block.Message.Sender,
		block.Message.Recipient,
		goConstants(block.Message.Constants),
	)
	return output
}

// nolint:unused
func goPhase(block Block) string {
	output := fmt.Sprintf(
		"phase[%d]\n\n",
		block.Phase.Number,
	)
	return output
}

// nolint:unused
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
