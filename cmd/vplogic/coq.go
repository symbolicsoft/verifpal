/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 806d8db3ce9f3ded40fd35fdba02fb84

package vplogic

import (
	"fmt"
	"os"
	"strings"
)

// Coq translates a Verifpal model into a representation that fits
// into the Coq model of the Verifpal verification methodology.
func Coq(modelFile string) {
	m := libpegParseModel(modelFile, false)
	sanity(m)
	fmt.Fprint(os.Stdout, coqModel(m))
}

func coqModel(m Model) string {
	valKnowledgeMap := constructKnowledgeMap(m, sanityDeclaredPrincipals(m))
	output := []string{}
	output = append(output, libcoq)
	output = append(output, fmt.Sprintf(
		"\n(* Protocol: %s *)",
		m.FileName))
	output = append(output, coqPrincipalNames(sanityDeclaredPrincipals(m)))
	output = append(output, "Definition depth := 10000.")
	blocksByPhase := [][]Block{}
	for i := 0; i < valKnowledgeMap.MaxPhase+1; i++ {
		blocksByPhase = append(blocksByPhase, []Block{})
	}
	for _, block := range m.Blocks {
		blocksByPhase[block.Phase.Number] = append(blocksByPhase[block.Phase.Number], block)
	}
	for i, phase := range blocksByPhase {
		output = append(output, fmt.Sprintf(
			"Definition phase_%d := [", i,
		))
		for _, block := range phase {
			switch block.Kind {
			case "principal":
				output = append(output, fmt.Sprintf(
					"\t\tpblock (PRINCIPAL\"%s\"[%s]);",
					block.Principal.Name, coqPrincipalBlock(block, valKnowledgeMap),
				))
			case "message":
				for _, x := range block.Message.Constants {
					output = append(output, fmt.Sprintf(
						"\t\tmblock(MSG %s (%s));",
						coqGuard(x.Guard), coqResolveConstant(x, valKnowledgeMap),
					))
				}
			default:
				continue
			}
		}
		if len(output) > 1 {
			output[len(output)-1] = strings.TrimSuffix(output[len(output)-1], ";")
			output = append(output, "].")
		}
		output = append(output, fmt.Sprintf(
			"Definition attacker_%d := init_attacker phase_%d.",
			i, i))
		for _, q := range m.Queries {
			switch q.Kind {
			case "confidentiality":
				for _, qc := range q.Constants {
					output = append(output, fmt.Sprintf(strings.Join([]string{
						"Compute analysis (confidentiality %s) attacker_%d",
						"(rewrite_principals (gather_principal_values ",
						"(gather_principals names phase_%d)) depth) depth."}, ""),
						coqResolveConstant(qc, valKnowledgeMap), i, i))
				}
			default:
				errorCritical(fmt.Sprintf("unsupported query: %s", q.Kind))
			}
		}
	}
	return strings.Join(output, "\n")
}

func coqPrincipalNames(principals []string) string {
	output := "Definition names := ["
	for i, pname := range principals {
		output += fmt.Sprintf("\"%s\"%%string",
			pname)
		if i+1 != len(principals) {
			output += "; "
		}
	}
	return output + "]."
}

func coqPrincipalBlock(block Block, valKnowledgeMap KnowledgeMap) string {
	expressions := []string{""}
	for i, expression := range block.Principal.Expressions {
		switch expression.Kind {
		case "knows":
			switch expression.Qualifier {
			case "password":
				for _, c := range expression.Constants {
					expressions = append(expressions, fmt.Sprintf(
						"EXP knowledge private (pass (cnstn \"%s\")) unleaked;",
						c.Name,
					))
				}
			default:
				for _, c := range expression.Constants {
					expressions = append(expressions, fmt.Sprintf(
						"EXP knowledge %s %s unleaked;",
						expression.Qualifier, coqResolveConstant(c, valKnowledgeMap),
					))
				}
			}
		case "generates":
			for _, c := range expression.Constants {
				expressions = append(expressions, fmt.Sprintf(
					"EXP generation private %s unleaked;",
					coqResolveConstant(c, valKnowledgeMap),
				))
			}
		case "leaks":
			for _, c := range expression.Constants {
				expressions = append(expressions, fmt.Sprintf(
					"EXP knows public %s leaked;",
					coqResolveConstant(c, valKnowledgeMap),
				))
			}
		case "assignment":
			expressions = append(expressions,
				coqAssignemntExpression(expression, valKnowledgeMap)...,
			)
		}
		if len(block.Principal.Expressions) == i+1 {
			expressions[len(expressions)-1] = strings.TrimSuffix(
				expressions[len(expressions)-1], ";",
			)
			expressions = append(expressions, "")
		}
	}
	return strings.Join(expressions, "\n\t\t\t\t")
}

func coqAssignemntExpression(expression Expression, valKnowledgeMap KnowledgeMap) []string {
	expressions := []string{}
	switch expression.Right.Kind {
	case "equation":
		expressions = append(expressions, fmt.Sprintf(
			"EXP assignment private %s unleaked;",
			coqResolveEquation(expression.Right.Equation, valKnowledgeMap)))
	case "primitive":
		switch expression.Right.Primitive.Name {
		case "HASH", "PW_HASH", "CONCAT":
			exp := fmt.Sprintf(
				"EXP assignment private (prim(%s%d ",
				expression.Right.Primitive.Name,
				len(expression.Right.Primitive.Arguments))
			for _, argument := range expression.Right.Primitive.Arguments {
				exp += coqResolveValue(argument, valKnowledgeMap)
			}
			expressions = append(expressions, fmt.Sprintf("%s)) unleaked;", exp))
		case "SPLIT", "SHAMIR_SPLIT", "HKDF":
			for i, lhs := range expression.Left {
				if strings.HasPrefix(lhs.Name, "unnamed_") {
					continue
				} else {
					exp := fmt.Sprintf(
						"EXP assignment private (prim(%s%d ",
						expression.Right.Primitive.Name, (i + 1))
					for _, argument := range expression.Right.Primitive.Arguments {
						exp += coqResolveValue(argument, valKnowledgeMap)
					}
					expressions = append(expressions, fmt.Sprintf("%s)) unleaked;", exp))
				}
			}
		default:
			expressions = append(expressions, fmt.Sprintf(
				"EXP assignment private %s unleaked;",
				coqResolvePrimitive(
					expression.Right.Primitive, valKnowledgeMap)))
		}
	}
	return expressions
}

func coqGuard(guard bool) string {
	if guard {
		return "guarded"
	}
	return "unguarded"
}

func coqResolveConstant(c Constant, valKnowledgeMap KnowledgeMap) string {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(Value{
		Kind:     "constant",
		Constant: c,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolvePrimitive(p Primitive, valKnowledgeMap KnowledgeMap) string {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(Value{
		Kind:      "primitive",
		Primitive: p,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolveEquation(e Equation, valKnowledgeMap KnowledgeMap) string {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(Value{
		Kind:     "equation",
		Equation: e,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolveValue(v Value, valKnowledgeMap KnowledgeMap) string {
	switch v.Kind {
	case "constant":
		return coqResolveConstant(v.Constant, valKnowledgeMap)
	case "primitive":
		return coqResolvePrimitive(v.Primitive, valKnowledgeMap)
	case "equation":
		return coqResolveEquation(v.Equation, valKnowledgeMap)
	}
	errorCritical("invalid value kind")
	return ""
}

func coqPrintValue(a Value) string {
	switch a.Kind {
	case "constant":
		return coqPrintConstant(a.Constant)
	case "primitive":
		return coqPrintPrimitive(a.Primitive)
	case "equation":
		return coqPrintEquation(a.Equation)
	}
	errorCritical("invalid value kind")
	return ""
}

func coqPrintConstant(c Constant) string {
	return fmt.Sprintf(
		"(const (cnstn \"%s\"))",
		c.Name)
}

func coqPrintPrimitive(p Primitive) string {
	args := []string{}
	for _, arg := range p.Arguments {
		args = append(args, coqPrintValue(arg))
	}
	switch p.Name {
	case "ASSERT":
		errorCritical(fmt.Sprintf("unsupported primitive: %s", p.Name))
	case "HASH", "PW_HASH", "CONCAT", "SPLIT", "HKDF", "SHAMIR_SPLIT":
		return fmt.Sprintf("(prim(%s%d %s))",
			p.Name, len(p.Arguments), strings.Join(args, " "))
	}
	return fmt.Sprintf("(prim(%s %s))",
		p.Name, strings.Join(args, " "))
}

func coqPrintEquation(e Equation) string {
	switch len(e.Values) {
	case 2:
		return fmt.Sprintf("(eq(PUBKEY G %s))",
			coqPrintValue(e.Values[1]),
		)
	case 3:
		return fmt.Sprintf("(eq(DH G %s %s))",
			coqPrintValue(e.Values[1]), coqPrintValue(e.Values[2]),
		)
	default:
		break
	}
	errorCritical("invalid equation")
	return ""
}
