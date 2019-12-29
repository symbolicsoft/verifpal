/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 362636d0e0b1ba89495c376703a829e8

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/logrusorgru/aurora"
)

func prettyMessage(m string, analysis int, depth int, t string) {
	if runtime.GOOS == "windows" {
		prettyMessageRegular(m, analysis, depth, t)
	} else {
		prettyMessageColor(m, analysis, depth, t)
	}
}

func prettyMessageRegular(m string, analysis int, depth int, t string) {
	var infoString string
	if analysis+depth > 0 {
		infoString = fmt.Sprintf(
			"%s%s%s%s%s",
			" (analysis ", fmt.Sprintf("%d", analysis),
			", depth ", fmt.Sprintf("%d", depth), ")",
		)
	}
	if t == "verifpal" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n", " ", "Verifpal", "!", m, infoString,
		))
	}
	if t == "info" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n", "     ", "Info", "!", m, infoString,
		))
	}
	if t == "analysis" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n", " ", "Analysis", "!", m, infoString,
		))
	}
	if t == "deduction" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n", "", "Deduction", "!", m, infoString,
		))
	}
	if t == "result" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n", "   ", "Result", "!", m, infoString,
		))
	}
}

func prettyMessageColor(m string, analysis int, depth int, t string) {
	var infoString string
	if analysis+depth > 0 {
		infoString = fmt.Sprintf(
			"%s%s%s%s%s",
			aurora.Gray(15, " (analysis ").Italic(),
			aurora.Gray(15, fmt.Sprintf("%d", analysis)).Italic(),
			aurora.Gray(15, ", depth "),
			aurora.Gray(15, fmt.Sprintf("%d", depth)).Italic(),
			aurora.Gray(15, ")").Italic(),
		)
	}
	if t == "verifpal" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n",
			" ", aurora.Green("Verifpal").Bold(), "!", m, infoString,
		))
	}
	if t == "info" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n",
			"     ", aurora.Blue("Info").Bold(), "!", m, infoString,
		))
	}
	if t == "analysis" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n",
			" ", aurora.Blue("Analysis").Bold(), "!", m, infoString,
		))
	}
	if t == "deduction" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n",
			"", aurora.Magenta("Deduction").Bold(), "!", m, infoString,
		))
	}
	if t == "result" {
		fmt.Fprint(os.Stdout, fmt.Sprintf(
			"%s%s%s %s%s\n",
			"   ", aurora.Red("Result").Bold(), "!", m, infoString,
		))
	}
}

func prettyVerifyResultSummary(mutated string, summary string, attack bool) string {
	var mutatedIntro string
	if len(mutated) > 0 {
		mutatedIntro = "When the following values are mutated by the attacker:"
	}
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("%s%s\n           %s",
			mutatedIntro, mutated, summary,
		)
	}
	if attack {
		return fmt.Sprintf("%s%s\n           %s",
			aurora.Italic(mutatedIntro).String(),
			aurora.BrightYellow(mutated).Italic().String(),
			aurora.BrightRed(summary).Italic().Bold().String(),
		)
	}
	return summary
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

func prettyPrint(model *verifpal) string {
	var output string
	output = fmt.Sprintf(
		"attacker [\n\t%s\n]\n\n",
		model.attacker,
	)
	for _, block := range model.blocks {
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
	for _, query := range model.queries {
		output = fmt.Sprintf(
			"%s\t%s\n", output, prettyQuery(query),
		)
	}
	output = fmt.Sprintf("%s]", output)
	return output
}

func prettyAnalysis(analysis int, stage int) {
	if runtime.GOOS == "windows" {
		analysis := fmt.Sprintf(" Stage %d, Analysis %d...", stage, analysis)
		fmt.Fprint(os.Stdout, analysis)
	} else {
		analysis := aurora.Gray(15, fmt.Sprintf(" Stage %d, Analysis %d...", stage, analysis)).Italic()
		fmt.Fprint(os.Stdout, analysis)
	}
	fmt.Fprint(os.Stdout, "\r \r")
}
