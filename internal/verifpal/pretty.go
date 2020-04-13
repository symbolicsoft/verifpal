/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 362636d0e0b1ba89495c376703a829e8

package verifpal

import (
	"fmt"
	"os"

	"github.com/logrusorgru/aurora"
)

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
	mutated string, summary string, oResults []queryOptionResult,
) string {
	mutatedIntro := ""
	optionsSummary := ""
	for _, oResult := range oResults {
		if !oResult.resolved {
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
			optionsSummary, "             - ", oResult.summary,
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

func prettyConstant(c constant) string {
	if c.guard {
		return fmt.Sprintf("[%s]", c.name)
	}
	if c.name == "g" {
		return "G"
	}
	return c.name
}

func prettyConstants(c []constant) string {
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

func prettyPrimitive(p primitive) string {
	pretty := fmt.Sprintf("%s(", p.name)
	check := ""
	if p.check {
		check = "?"
	}
	for i, arg := range p.arguments {
		sep := ""
		if i != (len(p.arguments) - 1) {
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

func prettyEquation(e equation) string {
	pretty := ""
	for i, c := range e.values {
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

func prettyValue(a value) string {
	switch a.kind {
	case "constant":
		return prettyConstant(a.constant)
	case "primitive":
		return prettyPrimitive(a.primitive)
	case "equation":
		return prettyEquation(a.equation)
	}
	return ""
}

func prettyValues(a []value) string {
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

func prettyQuery(query query) string {
	output := ""
	switch query.kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"%s? %s",
			query.kind,
			prettyConstants(query.constants),
		)
	case "authentication":
		output = fmt.Sprintf(
			"%s? %s -> %s: %s",
			query.kind,
			query.message.sender,
			query.message.recipient,
			prettyConstants(query.message.constants),
		)
	case "freshness":
		output = fmt.Sprintf(
			"%s? %s",
			query.kind,
			prettyConstants(query.constants),
		)
	case "unlinkability":
		output = fmt.Sprintf(
			"%s %s",
			query.kind,
			prettyConstants(query.constants),
		)
	}
	if len(query.options) > 0 {
		output = fmt.Sprintf("%s[", output)
	}
	for _, option := range query.options {
		output = fmt.Sprintf(
			"%s\n\t\t%s[%s -> %s: %s]",
			output,
			option.kind,
			option.message.sender,
			option.message.recipient,
			prettyConstants(option.message.constants),
		)
	}
	if len(query.options) > 0 {
		output = fmt.Sprintf("%s\n\t]", output)
	}
	return output
}

func prettyPrincipal(block block) string {
	output := fmt.Sprintf(
		"principal %s[\n",
		block.principal.name,
	)
	for _, expression := range block.principal.expressions {
		switch expression.kind {
		case "knows":
			output = fmt.Sprintf(
				"%s\t%s %s %s\n",
				expression.kind,
				output,
				expression.qualifier,
				prettyConstants(expression.constants),
			)
		case "generates":
			output = fmt.Sprintf(
				"%s\t%s %s\n",
				expression.kind,
				output,
				prettyConstants(expression.constants),
			)
		case "leaks":
			output = fmt.Sprintf(
				"%s\t%s %s\n",
				expression.kind,
				output,
				prettyConstants(expression.constants),
			)
		case "assignment":
			right := prettyValue(expression.right)
			output = fmt.Sprintf(
				"%s\t%s = %s\n",
				output,
				prettyConstants(expression.left),
				right,
			)
		}
	}
	output = fmt.Sprintf("%s]\n\n", output)
	return output
}

func prettyMessage(block block) string {
	output := fmt.Sprintf(
		"%s -> %s: %s\n\n",
		block.message.sender,
		block.message.recipient,
		prettyConstants(block.message.constants),
	)
	return output
}

func prettyPhase(block block) string {
	output := fmt.Sprintf(
		"phase[%d]\n\n",
		block.phase.number,
	)
	return output
}

// PrettyPrint pretty-prints a Verifpal model based on a model loaded from a file.
func PrettyPrint(modelFile string) {
	m := parserParseModel(modelFile, false)
	sanity(m)
	output := fmt.Sprintf(
		"attacker [\n\t%s\n]\n\n",
		m.attacker,
	)
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			output = output + prettyPrincipal(block)
		case "message":
			output = output + prettyMessage(block)
		case "phase":
			output = output + prettyPhase(block)
		}
	}
	output = fmt.Sprintf("%squeries[\n", output)
	for _, query := range m.queries {
		output = fmt.Sprintf(
			"%s\t%s\n", output, prettyQuery(query),
		)
	}
	output = fmt.Sprintf("%s]", output)
	fmt.Fprint(os.Stdout, output)
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
