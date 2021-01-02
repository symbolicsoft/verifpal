/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
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
func Coq(modelFile string) error {
	m, err := libpegParseModel(modelFile, false)
	if err != nil {
		return err
	}
	valKnowledgeMap, _, err := sanity(m)
	if err != nil {
		return err
	}
	cm, err := coqModel(m, valKnowledgeMap)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, cm)
	return err
}

func coqModel(m Model, valKnowledgeMap *KnowledgeMap) (string, error) {
	var err error
	declaredPrincipals, _, err := sanityDeclaredPrincipals(m)
	if err != nil {
		return "", err
	}
	output := []string{}
	output = append(output, libcoq)
	output = append(output, fmt.Sprintf("\n(* Protocol: %s *)", m.FileName))
	output = append(output, coqPrincipalNames(declaredPrincipals))
	output = append(output, "Definition depth := 10000.")
	blocksByPhase := [][]Block{}
	for i := 0; i < valKnowledgeMap.MaxPhase+1; i++ {
		blocksByPhase = append(blocksByPhase, []Block{})
	}
	for _, block := range m.Blocks {
		blocksByPhase[block.Phase.Number] = append(blocksByPhase[block.Phase.Number], block)
	}
	for i, phase := range blocksByPhase {
		output = append(output, fmt.Sprintf("Definition phase_%d := [", i))
		output, err = coqBlockByPhase(valKnowledgeMap, phase, output)
		if err != nil {
			return "", err
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
			case typesEnumConfidentiality:
				for _, qc := range q.Constants {
					crc, err := coqResolveConstant(qc, valKnowledgeMap)
					if err != nil {
						return "", err
					}
					output = append(output, fmt.Sprintf(strings.Join([]string{
						"Compute analysis (confidentiality %s) attacker_%d",
						"(rewrite_principals (gather_principal_values ",
						"(gather_principals names phase_%d)) depth) depth."}, ""),
						crc, i, i))
				}
			default:
				return "", fmt.Errorf("unsupported query: %s", prettyQuery(q))
			}
		}
	}
	return strings.Join(output, "\n"), nil
}

func coqBlockByPhase(valKnowledgeMap *KnowledgeMap, phase []Block, output []string) ([]string, error) {
	var cpb string
	var crc string
	var err error
	for _, block := range phase {
		switch block.Kind {
		case "principal":
			cpb, err = coqPrincipal(block, valKnowledgeMap)
			if err != nil {
				return []string{}, err
			}
			output = append(output, fmt.Sprintf(
				"\t\tpblock (PRINCIPAL\"%s\"[%s]);",
				block.Principal.Name, cpb,
			))
		case "message":
			for _, x := range block.Message.Constants {
				crc, err = coqResolveConstant(x, valKnowledgeMap)
				if err != nil {
					return []string{}, err
				}
				output = append(output, fmt.Sprintf(
					"\t\tmblock(MSG %s (%s));",
					coqGuard(x.Guard), crc,
				))
			}
		default:
			continue
		}
	}
	return output, nil
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

func coqPrincipal(block Block, valKnowledgeMap *KnowledgeMap) (string, error) {
	var err error
	expressions := []string{""}
	for i, expression := range block.Principal.Expressions {
		switch expression.Kind {
		case typesEnumKnows:
			switch expression.Qualifier {
			case typesEnumPassword:
				for _, c := range expression.Constants {
					expressions = append(expressions, fmt.Sprintf(
						"EXP knowledge private (pass (cnstn \"%s\")) unleaked;",
						c.Name,
					))
				}
			default:
				for _, c := range expression.Constants {
					var crc string
					crc, err = coqResolveConstant(c, valKnowledgeMap)
					switch expression.Qualifier {
					case typesEnumPrivate:
						expressions = append(expressions, fmt.Sprintf(
							"EXP knowledge private %s unleaked;", crc,
						))
					case typesEnumPublic:
						expressions = append(expressions, fmt.Sprintf(
							"EXP knowledge public %s unleaked;", crc,
						))
					case typesEnumPassword:
						expressions = append(expressions, fmt.Sprintf(
							"EXP knowledge password %s unleaked;", crc,
						))
					}
				}
			}
		case typesEnumGenerates:
			for _, c := range expression.Constants {
				var crv string
				crv, err = coqResolveConstant(c, valKnowledgeMap)
				expressions = append(expressions, fmt.Sprintf(
					"EXP generation private %s unleaked;", crv,
				))
			}
		case typesEnumLeaks:
			for _, c := range expression.Constants {
				var crc string
				crc, err = coqResolveConstant(c, valKnowledgeMap)
				expressions = append(expressions, fmt.Sprintf(
					"EXP knows public %s leaked;", crc,
				))
			}
		case typesEnumAssignment:
			var cae []string
			cae, err = coqAssignmentExpression(expression, valKnowledgeMap)
			expressions = append(expressions, cae...)
		}
		if len(block.Principal.Expressions) == i+1 {
			expressions[len(expressions)-1] = strings.TrimSuffix(
				expressions[len(expressions)-1], ";",
			)
			expressions = append(expressions, "")
		}
		if err != nil {
			return "", err
		}
	}
	return strings.Join(expressions, "\n\t\t\t\t"), nil
}

func coqAssignmentExpression(expression Expression, valKnowledgeMap *KnowledgeMap) ([]string, error) {
	expressions := []string{}
	switch expression.Assigned.Kind {
	case typesEnumEquation:
		cre, err := coqResolveEquation(expression.Assigned.Equation, valKnowledgeMap)
		if err != nil {
			return []string{}, err
		}
		expressions = append(expressions, fmt.Sprintf(
			"EXP assignment private %s unleaked;", cre,
		))
	case typesEnumPrimitive:
		primitiveStringName := ""
		if primitiveIsCorePrim(expression.Assigned.Primitive.ID) {
			prim, _ := primitiveCoreGet(expression.Assigned.Primitive.ID)
			primitiveStringName = prim.Name
		} else {
			prim, _ := primitiveGet(expression.Assigned.Primitive.ID)
			primitiveStringName = prim.Name
		}
		switch expression.Assigned.Primitive.ID {
		case primitiveEnumHASH, primitiveEnumPWHASH, primitiveEnumCONCAT:
			exp := fmt.Sprintf(
				"EXP assignment private (prim(%s%d ", primitiveStringName,
				len(expression.Assigned.Primitive.Arguments))
			for _, argument := range expression.Assigned.Primitive.Arguments {
				crv, err := coqResolveValue(argument, valKnowledgeMap)
				if err != nil {
					return []string{}, err
				}
				exp += crv
			}
			expressions = append(expressions, fmt.Sprintf("%s)) unleaked;", exp))
		case primitiveEnumSPLIT, primitiveEnumSHAMIRSPLIT, primitiveEnumHKDF:
			for i, lhs := range expression.Constants {
				if strings.HasPrefix(lhs.Name, "unnamed_") {
					continue
				} else {
					exp := fmt.Sprintf(
						"EXP assignment private (prim(%s%d ", primitiveStringName, (i + 1))
					for _, argument := range expression.Assigned.Primitive.Arguments {
						crv, err := coqResolveValue(argument, valKnowledgeMap)
						if err != nil {
							return []string{}, err
						}
						exp += crv
					}
					expressions = append(expressions, fmt.Sprintf("%s)) unleaked;", exp))
				}
			}
		default:
			crp, err := coqResolvePrimitive(expression.Assigned.Primitive, valKnowledgeMap)
			if err != nil {
				return nil, err
			}
			expressions = append(expressions, fmt.Sprintf(
				"EXP assignment private %s unleaked;", crp,
			))
		}
	}
	return expressions, nil
}

func coqGuard(guard bool) string {
	if guard {
		return "guarded"
	}
	return "unguarded"
}

func coqResolveConstant(c *Constant, valKnowledgeMap *KnowledgeMap) (string, error) {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(&Value{
		Kind:     typesEnumConstant,
		Constant: c,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolvePrimitive(p *Primitive, valKnowledgeMap *KnowledgeMap) (string, error) {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(&Value{
		Kind:      typesEnumPrimitive,
		Primitive: p,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolveEquation(e *Equation, valKnowledgeMap *KnowledgeMap) (string, error) {
	a, _ := valueResolveValueInternalValuesFromKnowledgeMap(&Value{
		Kind:     typesEnumEquation,
		Equation: e,
	}, valKnowledgeMap)
	return coqPrintValue(a)
}

func coqResolveValue(v *Value, valKnowledgeMap *KnowledgeMap) (string, error) {
	switch v.Kind {
	case typesEnumConstant:
		return coqResolveConstant(v.Constant, valKnowledgeMap)
	case typesEnumPrimitive:
		return coqResolvePrimitive(v.Primitive, valKnowledgeMap)
	case typesEnumEquation:
		return coqResolveEquation(v.Equation, valKnowledgeMap)
	}
	return "", fmt.Errorf("invalid value kind")
}

func coqPrintValue(a *Value) (string, error) {
	switch a.Kind {
	case typesEnumConstant:
		return coqPrintConstant(a.Constant)
	case typesEnumPrimitive:
		return coqPrintPrimitive(a.Primitive)
	case typesEnumEquation:
		return coqPrintEquation(a.Equation)
	}
	return "", fmt.Errorf("invalid value kind")
}

func coqPrintConstant(c *Constant) (string, error) {
	return fmt.Sprintf(
		"(const (cnstn \"%s\"))",
		c.Name), nil
}

func coqPrintPrimitive(p *Primitive) (string, error) {
	args := []string{}
	for _, arg := range p.Arguments {
		cpv, err := coqPrintValue(arg)
		if err != nil {
			return "", err
		}
		args = append(args, cpv)
	}
	primitiveStringName := ""
	if primitiveIsCorePrim(p.ID) {
		prim, _ := primitiveCoreGet(p.ID)
		primitiveStringName = prim.Name
	} else {
		prim, _ := primitiveGet(p.ID)
		primitiveStringName = prim.Name
	}
	switch p.ID {
	case primitiveEnumASSERT:
		return "", fmt.Errorf("unsupported primitive: %s", primitiveStringName)
	case primitiveEnumHASH, primitiveEnumPWHASH, primitiveEnumCONCAT,
		primitiveEnumSPLIT, primitiveEnumHKDF, primitiveEnumSHAMIRSPLIT:
		return fmt.Sprintf("(prim(%s%d %s))",
			primitiveStringName, len(p.Arguments), strings.Join(args, " ")), nil
	}
	return fmt.Sprintf("(prim(%s %s))",
		primitiveStringName, strings.Join(args, " ")), nil
}

func coqPrintEquation(e *Equation) (string, error) {
	switch len(e.Values) {
	case 2:
		cpv, err := coqPrintValue(e.Values[1])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(eq(PUBKEY G %s))", cpv), nil
	case 3:
		cpv1, err1 := coqPrintValue(e.Values[1])
		cpv2, err2 := coqPrintValue(e.Values[2])
		if err1 != nil {
			return "", err1
		}
		if err2 != nil {
			return "", err2
		}
		return fmt.Sprintf("(eq(DH G %s %s))", cpv1, cpv2), nil
	default:
		break
	}
	return "", fmt.Errorf("invalid equation")
}
