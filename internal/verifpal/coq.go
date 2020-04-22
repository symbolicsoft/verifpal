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
	output = append(output, coqHeader)
	output = append(output, fmt.Sprintf(
		"\n(* Protocol: %s *)\n\n(* Phase 0: *)\n",
		m.FileName))
	names["kmap"] = 0
	names["unnamed"] = 0
	names["attacker"] = 0
	names["queries"] = 0
	phase := 0
	output = append(output, fmt.Sprintf(
		"Definition attacker_%d := attacker_constructor %s attacker_knowledge_empty.",
		names["attacker"], m.Attacker,
	))
	names["attacker"]++
	for _, prin := range principals {
		names[fmt.Sprintf("principal_%s", strings.ToLower(prin))] = 0
		output, names = coqPrincipalInit(prin, output, names)
	}
	for _, block := range m.Blocks {
		if block.Phase.Number > phase {
			output = append(output, coqQuery(m.Queries, names, phase))
			phase = block.Phase.Number
			output = append(output, fmt.Sprintf(
				"\n(* Phase %d: *)\n",
				phase,
			))
		}
		switch block.Kind {
		case "principal":
			output, names = coqPrincipalBlock(block, output, names)
		case "message":
			output, names, messageLog = coqMessageBlock(block.Message, output, names, messageLog)
		}
	}
	output = append(output, coqQuery(m.Queries, names, phase))
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

func coqPrincipalBlock(block Block, output []string, names map[string]int) ([]string, map[string]int) {
	pname := fmt.Sprintf("principal_%s", strings.ToLower(block.Principal.Name))
	for i, expression := range block.Principal.Expressions {
		if i == 0 {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := get_principal_knowledgemap kmap_%d \"%s\".",
				pname, names[pname],
				names["kmap"]-1, block.Principal.Name,
			))
			names[pname]++
		}
		output, names = coqExpressionBlock(expression, pname, output, names)
		if i == len(block.Principal.Expressions)-1 {
			output = append(output, fmt.Sprintf(
				"Definition kmap_%d := update_principal_knowledgemap kmap_%d %s_%d.",
				names["kmap"], (names["kmap"]-1),
				pname, (names[pname]-1),
			))
			names["kmap"]++
			output = append(output, fmt.Sprintf(
				"Definition attacker_%d := absorb_knowledgemap_attacker attacker_%d kmap_%d.",
				names["attacker"], (names["attacker"]-1), (names["kmap"]-1),
			))
			names["attacker"]++
		}
	}
	return output, names
}

func coqMessageBlock(
	message Message, output []string, names map[string]int, messageLog map[string]string,
) ([]string, map[string]int, map[string]string) {
	for _, constant := range message.Constants {
		output = append(output, fmt.Sprintf(
			"Definition kmap_%d := add_message_knowledgemap kmap_%d (message_constructor \"%s\" \"%s\" \"%s\" %s).",
			names["kmap"], (names["kmap"]-1),
			message.Sender, message.Recipient, constant.Name, coqGuard(constant.Guard),
		))
		messageLog[constant.Name] = fmt.Sprintf("kmap_%d", names["kmap"])
		output = append(output, fmt.Sprintf(
			"Definition attacker_%d := absorb_knowledgemap_attacker attacker_%d kmap_%d.",
			names["attacker"], (names["attacker"]-1), (names["kmap"]),
		))
		names["kmap"]++
		names["attacker"]++
		output = append(output, fmt.Sprintf(
			"Definition kmap_%d := send_message kmap_%d.",
			names["kmap"], (names["kmap"]-1),
		))
		names["kmap"]++
	}
	// Ideally this function should look like this
	// for _, constant := range message.constants {
	// 	output = append(output, fmt.Sprintf(
	// 		"Definition kmap_%d := add_message_knowledgemap kmap_%d (message_constructor \"%s\" \"%s\" \"%s\" %s).",
	// 		names["kmap"], (names["kmap"]-1),
	// 		message.sender, message.recipient, constant.name, coqGuard(constant.guard),
	// 	))
	// 	names["kmap"]++
	// 	messageLog[constant.name] = fmt.Sprintf("kmap_%d", names["kmap"])
	// }
	// output = append(output, fmt.Sprintf(
	// 	"Definition attacker_%d := absorb_knowledgemap_attacker attacker_%d kmap_%d.",
	// 	names["attacker"], (names["attacker"]-1), (names["kmap"]-1),
	// ))
	// names["attacker"]++
	// output = append(output, fmt.Sprintf(
	// 	"Definition kmap_%d := send_messages kmap_%d.",
	// 	names["kmap"], (names["kmap"]-1),
	// ))
	// names["kmap"]++
	return output, names, messageLog
}

func coqExpressionBlock(
	expression Expression, principalName string, output []string, names map[string]int,
) ([]string, map[string]int) {
	pname := strings.ToLower(principalName)
	switch expression.Kind {
	case "knows":
		for _, constant := range expression.Constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := know_value %s_%d \"%s\" %s.",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.Name, expression.Qualifier,
			))
			names[pname]++
		}
	case "generates":
		for _, constant := range expression.Constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := generate_value %s_%d \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.Name,
			))
			names[pname]++
		}
	case "leaks":
		for _, constant := range expression.Constants {
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := leak_value %s_%d \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				constant.Name,
			))
			names[pname]++
		}
	case "assignment":
		update := ""
		for n, e := range expression.Left {
			update, output, names = coqValue(expression.Right, principalName, n+1, output, names)
			output = append(output, fmt.Sprintf(
				"Definition %s_%d := assign_value %s_%d %s \"%s\".",
				principalName, names[pname],
				principalName, names[pname]-1,
				update, e.Name,
			))
			names[pname]++
		}
	}
	return output, names
}

func coqValue(
	v Value, principalName string, n int, output []string, names map[string]int,
) (string, []string, map[string]int) {
	update := ""
	switch v.Kind {
	case "constant":
		return coqConstant(v.Constant.Name, principalName, names), output, names
	case "primitive":
		update = "(" + v.Primitive.Name
		switch v.Primitive.Name {
		case "HKDF", "SHAMIR_SPLIT", "SPLIT":
			update += fmt.Sprintf("%d", n)
		case "CONCAT", "HASH":
			update += fmt.Sprintf("%d", len(v.Primitive.Arguments))
		}
		update += " "
		for i, argument := range v.Primitive.Arguments {
			if argument.Kind != "constant" {
				newConstName := fmt.Sprintf("unnamed_%d", names["unnamed"])
				exp := Expression{
					Kind:      "assignment",
					Qualifier: "private",
					Constants: []Constant{},
					Left: []Constant{
						{
							Guard:       false,
							Fresh:       false,
							Leaked:      false,
							Name:        newConstName,
							Declaration: "assignment",
							Qualifier:   "private",
						},
					},
					Right: argument,
				}
				output, names = coqExpressionBlock(exp, principalName, output, names)
				update += coqConstant(newConstName, principalName, names)
				names["unnamed"]++
			} else {
				update += coqConstant(argument.Constant.Name, principalName, names)
			}
			if i == len(v.Primitive.Arguments)-1 {
				update += ")"
			} else {
				update += " "
			}
		}
	case "equation":
		if v.Equation.Values[0].Constant.Name == "g" {
			update = "(public_key "
		} else {
			update = "(DH " + coqConstant(v.Equation.Values[0].Constant.Name, principalName, names)
		}
		update += coqConstant(v.Equation.Values[1].Constant.Name, principalName, names) + ")"
	}
	return update, output, names
}

func coqConstant(constantName string, principalName string, names map[string]int) string {
	return fmt.Sprintf(
		"(get %s_%d \"%s\")",
		principalName, names[principalName]-1,
		constantName,
	)
}

func coqGuard(guard bool) string {
	if guard {
		return "guarded"
	}
	return "unguarded"
}

func coqQuery(queries []Query, names map[string]int, phase int) string {
	queryOutput := []string{}

	queryOutput = append(queryOutput, fmt.Sprintf(
		"\n(* Phase %d queries *)",
		phase,
	))
	for _, q := range queries {
		switch q.Kind {
		case "confidentiality":
			for _, constant := range q.Constants {
				queryOutput = append(queryOutput, fmt.Sprintf(
					"Compute(query_confidentiality attacker_%d \"%s\").",
					names["attacker"]-1, constant.Name,
				))
			}
		// case "authentication":
		// 	for _, constant := range q.message.constants {
		// 		queryOutput = append(queryOutput, fmt.Sprintf(
		// 			"Compute(query_authentication attacker_%d \"%s\" \"%s\" \"%s\").",
		// 			names["attacker"]-1, q.message.sender, q.message.recipient, constant.name,
		// 		))
		// 	}
		default:
			queryOutput = append(queryOutput, "(* Query not supported *)")
		}
	}
	return strings.Join(queryOutput, "\n")
}
