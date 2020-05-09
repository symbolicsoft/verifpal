/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 616bf0023a90ab68ba9e693bf9994779

package verifpal

import (
	"fmt"
	"os"
	"strings"
)

// Pv translates a Verifpal model into a ProVerif model.
func Pv(modelFile string) {
	m := libpegParseModel(modelFile, false)
	sanity(m)
	fmt.Fprint(os.Stdout, pvModel(m))
}

func pvConstantPrefix(valKnowledgeMap KnowledgeMap, principal string, c Constant) string {
	prefix := "const"
	i := valueGetKnowledgeMapIndexFromConstant(valKnowledgeMap, c)
	c = valKnowledgeMap.Constants[i]
	if valKnowledgeMap.Creator[i] == principal && c.Declaration == "assignment" {
		prefix = principal
	} else {
		for _, m := range valKnowledgeMap.KnownBy[i] {
			if p, ok := m[principal]; ok {
				if p != principal {
					prefix = p
				}
			}
		}
	}
	return prefix
}

func pvConstant(valKnowledgeMap KnowledgeMap, principal string, c Constant, valType string) string {
	prefix := pvConstantPrefix(valKnowledgeMap, principal, c)
	t := ""
	if len(valType) > 0 {
		t = fmt.Sprintf(":%s", valType)
	}
	return fmt.Sprintf("%s_%s%s", prefix, c.Name, t)
}

func pvConstants(valKnowledgeMap KnowledgeMap, principal string, c []Constant, valType string) string {
	consts := ""
	for i, v := range c {
		sep := ""
		if i != (len(c) - 1) {
			sep = ", "
		}
		consts = fmt.Sprintf("%s%s%s",
			consts, pvConstant(valKnowledgeMap, principal, v, valType), sep,
		)
	}
	return consts
}

func pvPrimitive(valKnowledgeMap KnowledgeMap, principal string, p Primitive, check bool) string {
	pname := p.Name
	checksuffix := ""
	switch check {
	case true:
		switch p.Name {
		case "AEAD_DEC":
			checksuffix = "_check"
		}
	}
	switch p.Name {
	case "HASH", "CONCAT", "SPLIT":
		pname = fmt.Sprintf("%s%d", p.Name, len(p.Arguments))
	}
	prim := fmt.Sprintf("%s%s(", pname, checksuffix)
	for i, arg := range p.Arguments {
		sep := ""
		if i != (len(p.Arguments) - 1) {
			sep = ", "
		}
		prim = fmt.Sprintf("%s%s%s",
			prim, pvValue(valKnowledgeMap, principal, arg), sep,
		)
	}
	prim = fmt.Sprintf("%s)", prim)
	return prim
}

func pvEquation(valKnowledgeMap KnowledgeMap, principal string, e Equation) string {
	eq := ""
	switch len(e.Values) {
	case 1:
		eq = fmt.Sprintf(
			"G(%s)",
			pvValue(valKnowledgeMap, principal, e.Values[0]),
		)
	case 2:
		eq = fmt.Sprintf(
			"exp(%s, %s)",
			pvValue(valKnowledgeMap, principal, e.Values[1]),
			pvValue(valKnowledgeMap, principal, e.Values[0]),
		)
	}
	return eq
}

func pvValue(valKnowledgeMap KnowledgeMap, principal string, a Value) string {
	switch a.Kind {
	case "constant":
		return pvConstant(valKnowledgeMap, principal, a.Constant, "")
	case "primitive":
		return pvPrimitive(valKnowledgeMap, principal, a.Primitive, false)
	case "equation":
		return pvEquation(valKnowledgeMap, principal, a.Equation)
	}
	return ""
}

func pvQuery(valKnowledgeMap KnowledgeMap, query Query) string {
	output := ""
	switch query.Kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"query attacker(const_%s).",
			query.Constants[0].Name,
		)
	case "authentication":
		output = fmt.Sprintf("%s ==> %s.",
			fmt.Sprintf("query event(RecvMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.Message.Sender, query.Message.Recipient, 0,
				pvConstant(valKnowledgeMap, "attacker", query.Message.Constants[0], ""),
			),
			fmt.Sprintf("event(SendMsg(principal_%s, principal_%s, phase_%d, %s))",
				query.Message.Sender, query.Message.Recipient, 0,
				pvConstant(valKnowledgeMap, "attacker", query.Message.Constants[0], ""),
			),
		)
	case "freshness":
		errorCritical("freshness queries are not yet supported in ProVerif model generation")
	case "unlinkability":
		errorCritical("unlinkability queries are not yet supported in ProVerif model generation")
	}
	if len(query.Options) > 0 {
		errorCritical("query options are not yet supported in ProVerif model generation")
	}
	return output
}

func pvPrincipal(
	valKnowledgeMap KnowledgeMap, block Block,
	procs string, consts string, pc int, cc int,
) (string, string, int, int) {
	procs = fmt.Sprintf(
		"%slet %s_%d() =\n",
		procs, block.Principal.Name, pc,
	)
	for _, expression := range block.Principal.Expressions {
		switch expression.Kind {
		case "leaks":
			for _, c := range expression.Constants {
				procs = fmt.Sprintf(
					"%s\tout(pub, (%s));\n",
					procs, pvConstant(valKnowledgeMap, block.Principal.Name, c, ""),
				)
			}
		case "assignment":
			c := valueGetConstantsFromValue(expression.Right)
			get := ""
			for _, cc := range c {
				prefix := pvConstantPrefix(valKnowledgeMap, block.Principal.Name, cc)
				if prefix == "const" {
					continue
				}
				if strings.HasPrefix(cc.Name, "unnamed_") {
					continue
				}
				get = fmt.Sprintf(
					"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
					get,
					prefix, block.Principal.Name,
					cc.Name,
					pvConstant(valKnowledgeMap, block.Principal.Name, cc, ""),
				)
			}
			if len(get) > 0 {
				procs = fmt.Sprintf(
					"%s%s",
					procs, get,
				)
			}
			valType := "bitstring"
			switch expression.Right.Kind {
			case "primitive":
				switch expression.Right.Primitive.Name {
				case "SIGNVERIF", "RINGSIGNVERIF":
					valType = "bool"
				}
				switch expression.Right.Primitive.Check {
				case true:
					procs = fmt.Sprintf("%s\tif %s = true then\n",
						procs,
						pvPrimitive(valKnowledgeMap, block.Principal.Name, expression.Right.Primitive, true),
					)
				}
			}
			procs = fmt.Sprintf(
				"%s\tlet (%s) = %s in\n",
				procs,
				pvConstants(valKnowledgeMap, block.Principal.Name, expression.Left, valType),
				pvValue(valKnowledgeMap, block.Principal.Name, expression.Right),
			)
			for _, l := range expression.Left {
				if strings.HasPrefix(l.Name, "unnamed_") {
					continue
				}
				procs = fmt.Sprintf(
					"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
					procs,
					block.Principal.Name, block.Principal.Name,
					l.Name,
					pvConstant(valKnowledgeMap, block.Principal.Name, l, ""),
				)
			}
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, consts, pc, cc
}

func pvMessage(
	valKnowledgeMap KnowledgeMap, block Block,
	procs string, pc int,
) (string, int) {
	procs = fmt.Sprintf(
		"%slet %s_to_%s_%d() =\n",
		procs, block.Message.Sender, block.Message.Recipient, pc,
	)
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tget valuestore(=principal_%s, =principal_%s, =const_%s, %s) in\n",
			procs, block.Message.Sender, block.Message.Sender,
			c.Name,
			pvConstant(valKnowledgeMap, block.Message.Sender, c, ""),
		)
	}
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tevent SendMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.Message.Sender, block.Message.Recipient,
			0, pvConstant(valKnowledgeMap, "", c, ""),
		)
	}
	for _, c := range block.Message.Constants {
		switch c.Guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tout(pub, %s);\n",
				procs, pvConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s_private, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				pvConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tout(chan_%s_to_%s, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				pvConstant(valKnowledgeMap, block.Message.Sender, c, ""),
			)
		}
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	procs = fmt.Sprintf(
		"%slet %s_from_%s_%d() =\n",
		procs, block.Message.Recipient, block.Message.Sender, pc,
	)
	for _, c := range block.Message.Constants {
		switch c.Guard {
		case true:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s_private, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				pvConstant(valKnowledgeMap, block.Message.Sender, c, "bitstring"),
			)
		case false:
			procs = fmt.Sprintf(
				"%s\tin(chan_%s_to_%s, (%s));\n",
				procs, block.Message.Sender, block.Message.Recipient,
				pvConstant(valKnowledgeMap, block.Message.Sender, c, "bitstring"),
			)
		}
	}
	for _, c := range block.Message.Constants {
		procs = fmt.Sprintf(
			"%s\tevent RecvMsg(principal_%s, principal_%s, phase_%d, %s);\n",
			procs, block.Message.Sender, block.Message.Recipient, 0,
			pvConstant(valKnowledgeMap, "", c, ""),
		)
		procs = fmt.Sprintf(
			"%s\tinsert valuestore(principal_%s, principal_%s, const_%s, %s);\n",
			procs,
			block.Message.Sender, block.Message.Recipient,
			c.Name,
			pvConstant(valKnowledgeMap, block.Message.Sender, c, ""),
		)
	}
	procs = procs + "\t0.\n"
	pc = pc + 1
	return procs, pc
}

func pvPhase(block Block) string {
	errorCritical("phases are not yet supported in ProVerif model generation")
	return fmt.Sprintf("phase %d;", block.Phase.Number)
}

func pvModel(m Model) string {
	pv := ""
	procs := ""
	consts := ""
	pc := 0
	cc := 0
	valKnowledgeMap := constructKnowledgeMap(m, sanityDeclaredPrincipals(m))
	for _, block := range m.Blocks {
		switch block.Kind {
		case "principal":
			procs, consts, pc, cc = pvPrincipal(
				valKnowledgeMap, block, procs, consts, pc, cc,
			)
		case "message":
			procs, pc = pvMessage(valKnowledgeMap, block, procs, pc)
		case "phase":
			pv = pv + pvPhase(block)
		}
	}
	pv = pv + libpv.Parameters(m.Attacker)
	pv = pv + libpv.Types()
	pv = pv + libpv.Constants(valKnowledgeMap, consts)
	pv = pv + libpv.CorePrims()
	pv = pv + libpv.Prims()
	pv = pv + libpv.Channels(valKnowledgeMap)
	pv = pv + libpv.Queries(valKnowledgeMap, m.Queries)
	pv = pv + procs
	pv = pv + libpv.TopLevel(m.Blocks)
	return pv
}
