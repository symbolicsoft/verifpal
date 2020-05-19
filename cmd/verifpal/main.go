/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 8e05848fe7fc3fb8ed3ba50a825c5493

//go:generate pigeon -o ../../internal/verifpal/libpeg.go ../../internal/libpeg/libpeg.peg
//go:generate gofmt -s -w ../../internal/verifpal/libpeg.go
//go:generate go run ../../internal/libcoq/libcoqgen.go
//go:generate gofmt -s -w ../../internal/verifpal/libcoq.go
//go:generate goversioninfo -64=true -icon=../../assets/icon.ico ../../assets/versioninfo.json

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"verifpal.com/internal/verifpal"
)

var version = "0.13.5"

var rootCmd = &cobra.Command{
	Use:                   "verifpal",
	Short:                 fmt.Sprintf("Verifpal %s - https://verifpal.com", version),
	Long:                  fmt.Sprintf("Verifpal %s - https://verifpal.com", version),
	DisableFlagsInUseLine: true,
}

var cmdVerify = &cobra.Command{
	Use:     "verify [model.vp]",
	Example: "  verifpal verify examples/simple.pv",
	Short:   "Analyze Verifpal model",
	Long: strings.Join([]string{
		"`verify` loads a Verifpal model from the given file path and analyzes it using Verifpal's analysis logic.",
		"Output is displayed in the terminal as the model is being analyzed.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stdout, "Verifpal %s - https://verifpal.com", version)
		fmt.Fprintf(os.Stdout, "\n")
		verifpal.InfoMessage("Verifpal is experimental software.",
			"warning", false,
		)
		verifpal.Verify(args[0])
	},
}

var cmdTranslate = &cobra.Command{
	Use:     "translate [coq|go|pv] [model.vp]",
	Example: "  verifpal translate coq examples/simple.pv",
	Short:   "Translate Verifpal model into another language",
	Long: strings.Join([]string{
		"`translate` allows translating a Verifpal model into either a ProVerif model,",
		"a Coq model or a Go implementation based on the option given.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.Pv(args[0])
	},
}

var cmdTranslateCoq = &cobra.Command{
	Use:     "coq [model.vp]",
	Example: "  verifpal translate coq examples/simple.pv",
	Short:   "Translate Verifpal model into Coq model",
	Long: strings.Join([]string{
		"`translate coq` loads a Verifpal model from the given file path and translates it into a Coq template based",
		"on the Verifpal Coq library, which can then be used in order to produce a more refined and detailed",
		"model of your protocol within the Coq verification framework.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.Coq(args[0])
	},
}

var cmdTranslateGo = &cobra.Command{
	Use:     "go [model.vp]",
	Example: "  verifpal translate go examples/simple.pv",
	Short:   "Translate Verifpal model into Go implementation",
	Long: strings.Join([]string{
		"`translate go` loads a Verifpal model from the given file path",
		"and translates it into a Go implementation based",
		"on the Verifpal Go library, which can then be used in order to prototype",
		"and test your protocol in a real-world setting.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.Go(args[0])
	},
}

var cmdTranslatePv = &cobra.Command{
	Use:     "pv [model.vp]",
	Example: "  verifpal translate pv examples/simple.pv",
	Short:   "Translate Verifpal model into ProVerif model",
	Long: strings.Join([]string{
		"`translate pv` loads a Verifpal model from the given file path",
		"and translates it into a ProVerif model template based",
		"on the Verifpal ProVerif library, which can then be used in order to produce a more refined and detailed",
		"model of your protocol within the ProVerif verification framework.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.Pv(args[0])
	},
}

var cmdPretty = &cobra.Command{
	Use:     "pretty [model.vp]",
	Example: "  verifpal pretty examples/simple.pv",
	Short:   "Pretty-print Verifpal model",
	Long: strings.Join([]string{
		"`pretty` loads a Verifpal model from the given file path",
		"and outputs a pretty-printed version of that same model.",
	}, " "),
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.PrettyPrint(args[0])
	},
}

var cmdJson = &cobra.Command{
	Use:                   "internal-json [requestType]",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                true,
	Run: func(cmd *cobra.Command, args []string) {
		verifpal.Json(args[0])
	},
}

var cmdFriends = &cobra.Command{
	Use:                   "friends",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Hidden:                true,
	Run: func(cmd *cobra.Command, args []string) {
		f := []byte{
			0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x76, 0x65,
			0x72, 0x69, 0x66, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,
			0x2f, 0x72, 0x65, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x72, 0x61,
			0x2f, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x73,
		}
		verifpal.OpenBrowser(string(f))
	},
}

func main() {
	rootCmd.AddCommand(cmdVerify, cmdTranslate, cmdPretty, cmdJson, cmdFriends)
	cmdTranslate.AddCommand(cmdTranslateCoq, cmdTranslateGo, cmdTranslatePv)
	// nolint:errcheck
	rootCmd.Execute()
}
