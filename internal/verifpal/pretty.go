/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 362636d0e0b1ba89495c376703a829e8

package verifpal

import (
	"fmt"
	"os"

	"github.com/logrusorgru/aurora"
)

func prettyMessage(m string, t string, showAnalysis bool) {
	analysisCount := 0
	if showAnalysis {
		analysisCount = verifyAnalysisCountGet()
	}
	if colorOutputSupport() {
		prettyMessageColor(m, t, analysisCount)
	} else {
		prettyMessageRegular(m, t, analysisCount)
	}
}

func prettyMessageRegular(m string, t string, analysisCount int) {
	var infoString string
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
	default:
		errorCritical(fmt.Sprintf(
			"invalid log message type (%s)",
			t,
		))
	}
}

func prettyMessageColor(m string, t string, analysisCount int) {
	var infoString string
	if analysisCount > 0 {
		infoString = aurora.Gray(15, fmt.Sprintf(
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
	default:
		errorCritical(fmt.Sprintf(
			"invalid log message type (%s)",
			t,
		))
	}
}

func prettyVerifyResultSummary(mutated string, summary string, attack bool) string {
	var mutatedIntro string
	if !attack {
		return summary
	}
	if len(mutated) > 0 {
		mutatedIntro = "When the following values are controlled by the attacker:"
	}
	if colorOutputSupport() {
		return fmt.Sprintf("%s%s\n           %s",
			aurora.Italic(mutatedIntro).String(),
			aurora.BrightYellow(mutated).Italic().String(),
			aurora.BrightRed(summary).Italic().Bold().String(),
		)
	}
	return fmt.Sprintf("%s%s\n           %s",
		mutatedIntro, mutated, summary,
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
	var pretty string
	for i, v := range c {
		var sep string
		if i == (len(c) - 1) {
			sep = ""
		} else {
			sep = ", "
		}
		pretty = fmt.Sprintf("%s%s%s",
			pretty,
			prettyConstant(v),
			sep,
		)
	}
	return pretty
}

func prettyEquation(e equation) string {
	var pretty string
	pretty = ""
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

func prettyPrimitive(p primitive) string {
	var pretty string
	var check string
	pretty = fmt.Sprintf("%s(", p.name)
	if p.check {
		check = "?"
	}
	for i, arg := range p.arguments {
		var sep string
		if i == (len(p.arguments) - 1) {
			sep = ""
		} else {
			sep = ", "
		}
		pretty = fmt.Sprintf("%s%s%s",
			pretty,
			prettyValue(arg),
			sep,
		)
	}
	return fmt.Sprintf("%s)%s",
		pretty, check,
	)
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
	var output string
	switch query.kind {
	case "confidentiality":
		output = fmt.Sprintf(
			"confidentiality? %s",
			prettyConstant(query.constant),
		)
	case "authentication":
		output = fmt.Sprintf(
			"authentication? %s -> %s: %s",
			query.message.sender,
			query.message.recipient,
			prettyConstants(query.message.constants),
		)
	}
	return output
}

// PrettyPrint pretty-prints a Verifpal model based on a model loaded from a file.
func PrettyPrint(modelFile string) string {
	m, _, _ := parserParseModel(modelFile)
	var output string
	output = fmt.Sprintf(
		"attacker [\n\t%s\n]\n\n",
		m.attacker,
	)
	for _, block := range m.blocks {
		switch block.kind {
		case "principal":
			output = fmt.Sprintf(
				"%sprincipal %s[\n",
				output, block.principal.name,
			)
			for _, expression := range block.principal.expressions {
				switch expression.kind {
				case "knows":
					output = fmt.Sprintf(
						"%s\tknows %s %s\n",
						output,
						expression.qualifier,
						prettyConstants(expression.constants),
					)
				case "generates":
					output = fmt.Sprintf(
						"%s\tgenerates %s\n",
						output,
						prettyConstants(expression.constants),
					)
				case "assignment":
					var right string
					right = fmt.Sprintf("%s%s",
						right,
						prettyValue(expression.right),
					)
					output = fmt.Sprintf(
						"%s\t%s = %s\n",
						output,
						prettyConstants(expression.left),
						right,
					)
				}
			}
			output = fmt.Sprintf("%s]\n\n", output)
		case "message":
			output = fmt.Sprintf(
				"%s%s -> %s: %s\n\n",
				output,
				block.message.sender,
				block.message.recipient,
				prettyConstants(block.message.constants),
			)
		}
	}
	output = fmt.Sprintf("%squeries[\n", output)
	for _, query := range m.queries {
		output = fmt.Sprintf(
			"%s\t%s\n", output, prettyQuery(query),
		)
	}
	output = fmt.Sprintf("%s]", output)
	return output
}

func prettyAnalysis(stage int) {
	var a string
	analysisCount := verifyAnalysisCountGet()
	if analysisCount%10 != 0 {
		return
	}
	if colorOutputSupport() {
		a = aurora.Gray(15, fmt.Sprintf(
			" Stage %d, Analysis %d...", stage, analysisCount,
		)).Italic().String()
	} else {
		a = fmt.Sprintf(" Stage %d, Analysis %d...", stage, analysisCount)
	}
	fmt.Fprint(os.Stdout, a)
	fmt.Fprint(os.Stdout, "\r \r")
}
