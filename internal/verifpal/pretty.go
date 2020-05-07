/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 362636d0e0b1ba89495c376703a829e8

package verifpal

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

// PrettyPrint pretty-prints a Verifpal model based on a model loaded from a file.
func PrettyPrint(modelFile string) {
	m := libpegParseModel(modelFile, false)
	fmt.Fprint(os.Stdout, prettyModel(m))
}

// PrettyInfo prints a Verifpal status message.
func PrettyInfo(m string, t string, showAnalysis bool) {
	analysisCount := 0
	if showAnalysis {
		analysisCount = verifyAnalysisCountGet()
	}
	if colorOutputSupport() {
		PrettyInfoColor(m, t, analysisCount)
	} else {
		PrettyInfoRegular(m, t, analysisCount)
	}
}

func PrettyInfoRegular(m string, t string, analysisCount int) {
	infoString := ""
	if analysisCount > 0 {
		infoString = fmt.Sprintf("(Analysis %d)", analysisCount)
	}
	switch t {
	case "verifpal":
		fmt.Fprintf(os.Stdout,
			" Verifpal • %s %s\n", m, infoString,
		)
	case "info":
		fmt.Fprintf(os.Stdout,
			"     Info • %s %s\n", m, infoString,
		)
	case "analysis":
		fmt.Fprintf(os.Stdout,
			" Analysis • %s %s\n", m, infoString,
		)
	case "deduction":
		fmt.Fprintf(os.Stdout,
			"Deduction • %s %s\n", m, infoString,
		)
	case "result":
		fmt.Fprintf(os.Stdout,
			"   Result • %s %s\n", m, infoString,
		)
	case "warning":
		fmt.Fprintf(os.Stdout,
			"  Warning • %s %s\n", m, infoString,
		)
	default:
		errorCritical(fmt.Sprintf(
			"invalid log message type (%s)",
			t,
		))
	}
}

func PrettyInfoColor(m string, t string, analysisCount int) {
	infoString := ""
	if analysisCount > 0 {
		infoString = aurora.Faint(fmt.Sprintf(
			"(Analysis %d)", analysisCount,
		)).Italic().String()
	}
	switch t {
	case "verifpal":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			" ", aurora.Green("Verifpal").Bold(), " •", m, infoString,
		)
	case "info":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			"     ", aurora.Blue("Info").Bold(), " •", m, infoString,
		)
	case "analysis":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			" ", aurora.Blue("Analysis").Bold(), " •", m, infoString,
		)
	case "deduction":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			"", aurora.Magenta("Deduction").Bold(), " •", m, infoString,
		)
	case "result":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			"   ", aurora.Red("Result").Bold(), " •", m, infoString,
		)
	case "warning":
		fmt.Fprintf(os.Stdout,
			"%s%s%s %s %s\n",
			"  ", aurora.Red("Warning").Bold(), " •", m, infoString,
		)
	default:
		errorCritical(fmt.Sprintf(
			"invalid log message type (%s)",
			t,
		))
	}
}

func prettyVerifyResultSummary(
	mutated string, summary string, oResults []QueryOptionResult,
) string {
	mutatedIntro := ""
	optionsSummary := ""
	for _, oResult := range oResults {
		if !oResult.Resolved {
			continue
		}
		if len(optionsSummary) == 0 {
			optionsSummary = fmt.Sprintf(
				"%sFurthermore, the following options are contradicted:\n",
				"           ",
			)
		}
		optionsSummary = fmt.Sprintf(
			"%s%s%s\n",
			optionsSummary, "             - ", oResult.Summary,
		)
	}
	if len(mutated) > 0 {
		mutatedIntro = "When the following values are controlled by Attacker:"
	}
	if colorOutputSupport() {
		return fmt.Sprintf("%s%s\n           %s\n%s",
			aurora.Italic(mutatedIntro).String(),
			aurora.BrightYellow(mutated).Italic().String(),
			aurora.BgRed(summary).White().Italic().Bold().String(),
			aurora.Red(optionsSummary).Italic().String(),
		)
	}
	return fmt.Sprintf("%s%s\n           %s\n%s",
		mutatedIntro, mutated, summary, optionsSummary,
	)
}

func prettyConstant(c Constant) string {
	if c.Guard {
		return fmt.Sprintf("[%s]", c.Name)
	}
	if c.Name == "g" {
		return "G"
	}
	return c.Name
}

func prettyConstants(c []Constant) string {
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

func prettyPrimitive(p Primitive) string {
	pretty := fmt.Sprintf("%s(", p.Name)
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

func prettyEquation(e Equation) string {
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

func prettyValue(a Value) string {
	switch a.Kind {
	case "constant":
		return prettyConstant(a.Constant)
	case "primitive":
		return prettyPrimitive(a.Primitive)
	case "equation":
		return prettyEquation(a.Equation)
	}
	return ""
}

func prettyValues(a []Value) string {
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
	case "confidentiality":
		output = fmt.Sprintf(
			"%s? %s",
			query.Kind,
			prettyConstants(query.Constants),
		)
	case "authentication":
		output = fmt.Sprintf(
			"%s? %s -> %s: %s",
			query.Kind,
			query.Message.Sender,
			query.Message.Recipient,
			prettyConstants(query.Message.Constants),
		)
	case "freshness":
		output = fmt.Sprintf(
			"%s? %s",
			query.Kind,
			prettyConstants(query.Constants),
		)
	case "unlinkability":
		output = fmt.Sprintf(
			"%s %s",
			query.Kind,
			prettyConstants(query.Constants),
		)
	}
	if len(query.Options) > 0 {
		output = fmt.Sprintf("%s[", output)
	}
	for _, option := range query.Options {
		output = fmt.Sprintf(
			"%s\n\t\t%s[%s -> %s: %s]",
			output,
			option.Kind,
			option.Message.Sender,
			option.Message.Recipient,
			prettyConstants(option.Message.Constants),
		)
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
	case "knows":
		output = fmt.Sprintf(
			"%s %s %s",
			expression.Kind,
			expression.Qualifier,
			prettyConstants(expression.Constants),
		)
	case "generates":
		output = fmt.Sprintf(
			"%s %s",
			expression.Kind,
			prettyConstants(expression.Constants),
		)
	case "leaks":
		output = fmt.Sprintf(
			"%s %s",
			expression.Kind,
			prettyConstants(expression.Constants),
		)
	case "assignment":
		right := prettyValue(expression.Right)
		left := []Constant{}
		for i, c := range expression.Left {
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
		block.Message.Sender,
		block.Message.Recipient,
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

func prettyModel(m Model) string {
	sanity(m)
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
	return output
}

func prettyDiagram(m Model) string {
	sanity(m)
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
	return output
}

func prettyAnalysis(stage int) {
	a := ""
	analysisCount := verifyAnalysisCountGet()
	if analysisCount%10 != 0 {
		return
	}
	if colorOutputSupport() {
		a = aurora.Faint(fmt.Sprintf(
			" Stage %d, Analysis %d...", stage, analysisCount,
		)).Italic().String()
	} else {
		a = fmt.Sprintf(" Stage %d, Analysis %d...", stage, analysisCount)
	}
	fmt.Fprint(os.Stdout, a)
	fmt.Fprint(os.Stdout, "\r \r")
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
