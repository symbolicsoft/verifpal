/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

// InfoMessage prints a Verifpal status message either in color or non-color format,
// depending on what is supported by the terminal.
func InfoMessage(m string, t string, showAnalysis bool) {
	analysisCount := 0
	if showAnalysis {
		analysisCount = verifyAnalysisCountGet()
	}
	if colorOutputSupport() {
		InfoMessageColor(m, t, analysisCount)
	} else {
		InfoMessageRegular(m, t, analysisCount)
	}
}

// InfoMessageRegular prints a Verifpal status message in non-color format.
func InfoMessageRegular(m string, t string, analysisCount int) {
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
	}
}

// InfoMessageColor prints a Verifpal status message in color format.
func InfoMessageColor(m string, t string, analysisCount int) {
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
	}
}

func infoVerifyResultSummary(
	mutatedInfo string, summary string, oResults []QueryOptionResult,
) string {
	intro := ""
	optionsSummary := ""
	for _, oResult := range oResults {
		if !oResult.Resolved {
			continue
		}
		if len(optionsSummary) == 0 {
			optionsSummary = fmt.Sprintf(
				"%s Furthermore, the following options are contradicted:\n",
				"           ",
			)
		}
		optionsSummary = fmt.Sprintf(
			"%s%s%s\n",
			optionsSummary, "             - ", oResult.Summary,
		)
	}
	if len(mutatedInfo) > 0 {
		intro = "When:"
	}
	if colorOutputSupport() {
		return fmt.Sprintf("%s%s\n            %s\n%s",
			aurora.Italic(intro).String(), mutatedInfo,
			aurora.BgRed(summary).White().Italic().Bold().String(),
			aurora.Red(optionsSummary).Italic().String(),
		)
	}
	return fmt.Sprintf("%s%s\n           %s\n%s",
		intro, mutatedInfo, summary, optionsSummary,
	)
}

func infoAnalysis(stage int) {
	a := ""
	analysisCount := verifyAnalysisCountGet()
	switch {
	case analysisCount > 100000:
		if analysisCount%500 != 0 {
			return
		}
	case analysisCount > 10000:
		if analysisCount%100 != 0 {
			return
		}
	case analysisCount > 1000:
		if analysisCount%50 != 0 {
			return
		}
	case analysisCount > 100:
		if analysisCount%10 != 0 {
			return
		}
	}
	if colorOutputSupport() {
		a = aurora.Faint(fmt.Sprintf(
			" Stage %d, Analysis %d...", stage, analysisCount,
		)).Italic().String()
	} else {
		a = fmt.Sprintf(" Stage %d, Analysis %d...", stage, analysisCount)
	}
	fmt.Fprint(os.Stdout, a)
	fmt.Fprint(os.Stdout, "\r\r\r\r")
}

func infoLiteralNumber(n int) string {
	switch n {
	case 0:
		return "first"
	case 1:
		return "second"
	case 2:
		return "third"
	case 3:
		return "fourth"
	case 4:
		return "fifth"
	default:
		return fmt.Sprintf("%dth", n)
	}
}

func infoOutputText(revealed Value) string {
	outputText := prettyValue(revealed)
	switch revealed.Kind {
	case "constant":
		return outputText
	case "primitive":
		oneOutput := false
		if primitiveIsCorePrim(revealed.Primitive.Name) {
			prim, _ := primitiveCoreGet(revealed.Primitive.Name)
			oneOutput = prim.Output == 1
		} else {
			prim, _ := primitiveGet(revealed.Primitive.Name)
			oneOutput = prim.Output == 1
		}
		if oneOutput {
			return fmt.Sprintf("Output of %s", outputText)
		}
		prefix := fmt.Sprintf("%s output",
			strings.Title(infoLiteralNumber(revealed.Primitive.Output)),
		)
		return fmt.Sprintf("%s of %s", prefix, outputText)
	case "equation":
		return outputText
	default:
		return outputText
	}
}

func infoQueryMutatedValues(valKnowledgeMap KnowledgeMap, valPrincipalState PrincipalState) string {
	mutatedInfo := ""
	for i, a := range valPrincipalState.BeforeRewrite {
		if valueEquivalentValues(a, valKnowledgeMap.Assigned[i], false) {
			continue
		}
		pc := prettyConstant(valPrincipalState.Constants[i])
		pa := prettyValue(valPrincipalState.Assigned[i])
		if colorOutputSupport() {
			if valPrincipalState.Mutated[i] {
				mutatedInfo = fmt.Sprintf("%s\n            %s%s%s %s",
					mutatedInfo,
					aurora.BrightYellow(pc).Italic().Underline().String(),
					aurora.BrightYellow(" → ").Italic().Underline().String(),
					aurora.BrightYellow(pa).Italic().Underline().String(),
					aurora.Red("(mutated by attacker)").Italic().String(),
				)
			} else {
				mutatedInfo = fmt.Sprintf("%s\n            %s%s%s",
					mutatedInfo,
					aurora.BrightYellow(pc).Italic().String(),
					aurora.BrightYellow(" → ").Italic().String(),
					aurora.BrightYellow(pa).Italic().String(),
				)
			}
		} else {
			if valPrincipalState.Mutated[i] {
				mutatedInfo = fmt.Sprintf("%s\n            %s%s%s %s",
					mutatedInfo, pc, " → ", pa, "(mutated by attacker)",
				)
			} else {
				mutatedInfo = fmt.Sprintf("%s\n            %s%s%s",
					mutatedInfo, pc, " → ", pa,
				)
			}
		}
	}
	return mutatedInfo
}
