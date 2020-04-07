/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84
package verifpal

import (
	"fmt"
	"os"
	"strings"
)

// Coq translates a Verifpal model into a representation that fits
// into the Coq model of the Verifpal verification methodology.
func Coq(modelFile string) {
	m := parserParseModel(modelFile, false)
	sanity(m)
	fmt.Fprint(os.Stdout, coqModel(m))
}

func coqModel(m Model) string {
	output := []string{}
	names := make(map[string]int)
	messageLog := make(map[string]string)
	principals := sanityDeclaredPrincipals(m)
	output = append(output, coqHeader())
	output = append(output, fmt.Sprintf("\n(* Protocol: %s *)\n", m.fileName))
	names["kmap"] = 0
	names["unnamed"] = 0
	for _, prin := range principals {
		names[fmt.Sprintf("principal_%s", prin)] = 0
		output, names = coqPrincipalInit(prin, output, names)
	}
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			output, names = coqPrincipalBlock(block, output, names)
		case "message":
			output, names, messageLog = coqMessageBlock(block.message, output, names, messageLog)
		}
	}
	return strings.Join(output, "\n")
}

func coqPrincipalInit(principal string, output []string, names map[string]int) ([]string, map[string]int) {
	if names["kmap"] == 0 {
		output = append(output, fmt.Sprintf(
			"Definition kmap_%d := knowledgemap_constructor \"%s\".",
			names["kmap"], principal,
		))
		names["kmap"]++
	}
	output = append(output, fmt.Sprintf(
		"Definition kmap_%d := add_principal_knowledgemap kmap_%d \"%s\".",
		names["kmap"], names["kmap"]-1, principal,
	))
	names["kmap"]++
	return output, names
}

func coqPrincipalBlock(block block, output []string, names map[string]int) ([]string, map[string]int) {
	pname := fmt.Sprintf("principal_%s", strings.ToLower(block.principal.name))
	for i, expression := range block.principal.expressions {
		if i == 0 {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := get_principal_knowledgemap kmap_%d \"%s\".",
				pname, names[pname],
				names["kmap"]-1, block.principal.name,
			))
			names[pname]++
		}
		output, names = coqExpressionBlock(expression, pname, output, names)
		if i == len(block.principal.expressions)-1 {
			output = append(output, fmt.Sprintf(
				"Definition kmap_%d := update_principal_knowledgemap kmap_%d %s_%d.",
				names["kmap"], (names["kmap"]-1),
				pname, (names[pname]-1),
			))
			names["kmap"]++
		}
	}
	return output, names
}

func coqMessageBlock(
	message message, output []string, names map[string]int, messageLog map[string]string,
) ([]string, map[string]int, map[string]string) {
	for _, constant := range message.constants {
		output = append(output, fmt.Sprintf(
			"Definition kmap_%d := add_message_knowledgemap kmap_%d (message_constructor \"%s\" \"%s\" \"%s\" %s).",
			names["kmap"], (names["kmap"]-1),
			message.sender, message.recipient, constant.name, coqGuard(constant.guard),
		))
		names["kmap"]++
		output = append(output, fmt.Sprintf(
			"Definition kmap_%d := send_message kmap_%d.",
			names["kmap"], (names["kmap"]-1),
		))
		messageLog[constant.name] = fmt.Sprintf("kmap_%d", names["kmap"])
		names["kmap"]++
	}
	return output, names, messageLog
}

func coqExpressionBlock(
	expression expression, principalName string, output []string, names map[string]int,
) ([]string, map[string]int) {
	pname := fmt.Sprintf("principal_%s", strings.ToLower(principalName))
	switch expression.kind {
	case "knows":
		for _, constant := range expression.constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := know_value %s_%d \"%s\" %s.",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.name, expression.qualifier,
			))
			names[pname]++
		}
	case "generates":
		for _, constant := range expression.constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := generate_value %s_%d \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.name,
			))
			names[pname]++
		}
	case "leaks":
		for _, constant := range expression.constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := leak_value %s_%d \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.name,
			))
			names[pname]++
		}
	case "assignment":
		update := ""
		for n, e := range expression.left {
			update, output, names = coqValue(expression.right, principalName, n+1, output, names)
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := assign_value %s_%d %s \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				update, e.name,
			))
			names[pname]++
		}
	}
	return output, names
}

func coqValue(
	v value, principalName string, n int, output []string, names map[string]int,
) (string, []string, map[string]int) {
	update := ""
	switch v.kind {
	case "constant":
		return coqConstant(v.constant.name, principalName, names), output, names
		// TODO: Checked primitives
		// TODO: HASH, concat problem
	case "primitive":
		update = "(" + v.primitive.name
		if v.primitive.name == "HKDF" || v.primitive.name == "SHAMIR_SPLIT" {
			if n > 3 {
				errorCritical("Only 3 outputs are allowed for " + v.primitive.name)
			} else {
				update += fmt.Sprintf("_%d", n)
			}
		}
		update += " "
		for i, argument := range v.primitive.arguments {
			if argument.kind != "constant" {
				newConstName := fmt.Sprintf("unnamed_%d", names["unnamed"])
				exp := expression{
					kind:      "assignment",
					qualifier: "private",
					constants: []constant{},
					left: []constant{
						{
							guard:       false,
							fresh:       false,
							leaked:      false,
							name:        newConstName,
							declaration: "assignment",
							qualifier:   "private",
						},
					},
					right: argument,
				}
				output, names = coqExpressionBlock(exp, principalName, output, names)
				update += coqConstant(newConstName, principalName, names)
				names["unnamed"]++
			} else {
				update += coqConstant(argument.constant.name, principalName, names)
			}
			if i == len(v.primitive.arguments)-1 {
				update += ")"
			} else {
				update += " "
			}
		}
	case "equation":
		if v.equation.values[0].constant.name == "g" {
			update = "(public_key "
		} else {
			update = "(DH " + coqConstant(v.equation.values[0].constant.name, principalName, names)
		}
		update += coqConstant(v.equation.values[1].constant.name, principalName, names) + ")"
	}
	return update, output, names
}

func coqConstant(constantName string, principalName string, names map[string]int) string {
	return fmt.Sprintf(
		"(get %s_%d \"%s\")",
		principalName, names["principal_"+principalName],
		constantName,
	)
}

func coqGuard(guard bool) string {
	if guard {
		return "guarded"
	}
	return "unguarded"
}
