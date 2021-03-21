/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 8e05848fe7fc3fb8ed3ba50a825c5493

//go:generate go run ../../internal/libcoq/libcoqgen.go
//go:generate pigeon -o ../../cmd/vplogic/libpeg.go ../../internal/libpeg/libpeg.peg
//go:generate gofmt -s -w ../../cmd/vplogic/libcoq.go
//go:generate gofmt -s -w ../../cmd/vplogic/libpeg.go
//go:generate goversioninfo -64=true -icon=../../assets/icon.ico ../../assets/versioninfo.json

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"verifpal.com/cmd/vplogic"
)

const version = "0.22.0"

var rootCmd = &cobra.Command{
	Use:     "verifpal",
	Version: version,
	Short:   fmt.Sprintf("Verifpal %s - https://verifpal.com", version),
	Long:    fmt.Sprintf("Verifpal %s - https://verifpal.com", version),
}

var cmdVerify = &cobra.Command{
	Use:     "verify [model.vp]",
	Example: "  verifpal verify examples/simple.vp",
	Short:   "Analyze Verifpal model",
	Long: strings.Join([]string{
		"`verify` loads a Verifpal model from the given file path and analyzes it using Verifpal's analysis logic.",
		"Output is displayed in the terminal as the model is being analyzed.",
	}, " "),
	Args:       cobra.ExactArgs(1),
	Hidden:     false,
	SuggestFor: []string{"analyze", "run"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stdout, "Verifpal %s - https://verifpal.com", version)
		fmt.Fprintf(os.Stdout, "\n")
		vplogic.InfoMessage("Verifpal is Beta software.",
			"warning", false,
		)
		vplogic.VerifHubScheduledShared, _ = cmd.Flags().GetBool("verifhub")
		_, _, err := vplogic.Verify(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var cmdTranslate = &cobra.Command{
	Use:     "translate [coq|pv] [model.vp]",
	Example: "  verifpal translate coq examples/simple.vp",
	Short:   "Translate Verifpal model into another language",
	Long: strings.Join([]string{
		"`translate` allows translating a Verifpal model into either a ProVerif model ",
		"or a Coq model implementation based on the option given.",
	}, " "),
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(1),
	ValidArgs:             []string{"coq", "pv"},
	Hidden:                false,
}

var cmdTranslateCoq = &cobra.Command{
	Use:     "coq [model.vp]",
	Example: "  verifpal translate coq examples/simple.vp",
	Short:   "Translate Verifpal model into Coq model",
	Long: strings.Join([]string{
		"`translate coq` loads a Verifpal model from the given file path and translates it into a Coq template based",
		"on the Verifpal Coq library, which can then be used in order to produce a more refined and detailed",
		"model of your protocol within the Coq verification framework.",
	}, " "),
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		err := vplogic.Coq(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var cmdTranslatePv = &cobra.Command{
	Use:     "pv [model.vp]",
	Example: "  verifpal translate pv examples/simple.vp",
	Short:   "Translate Verifpal model into ProVerif model",
	Long: strings.Join([]string{
		"`translate pv` loads a Verifpal model from the given file path",
		"and translates it into a ProVerif model template based",
		"on the Verifpal ProVerif library, which can then be used in order to produce a more refined and detailed",
		"model of your protocol within the ProVerif verification framework.",
	}, " "),
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		err := vplogic.Pv(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var cmdPretty = &cobra.Command{
	Use:     "pretty [model.vp]",
	Example: "  verifpal pretty examples/simple.vp",
	Short:   "Pretty-print Verifpal model",
	Long: strings.Join([]string{
		"`pretty` loads a Verifpal model from the given file path",
		"and outputs a pretty-printed version of that same model.",
	}, " "),
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		err := vplogic.PrettyPrint(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var cmdAbout = &cobra.Command{
	Use:     "about",
	Example: "  verifpal about",
	Short:   "About information for the Verifpal software",
	Long: strings.Join([]string{
		"`about` lists information about the Verifpal software's",
		"authors, contributors and testers.",
	}, " "),
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(0),
	Hidden:                false,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprint(os.Stdout, strings.Join([]string{
			fmt.Sprintf("Verifpal %s - https://verifpal.com\n", version),
			"Verifpal is authored by Nadim Kobeissi.",
			"The following individuals have contributed",
			"meaningful suggestions, bug reports, ideas",
			"or discussion to the Verifpal project:",
			"",
			"  - Angèle Bossuat",
			"  - Bruno Blanchet (Prof. Dr.)",
			"  - Fabian Drinck",
			"  - Friedrich Wiemer",
			"  - Georgio Nicolas",
			"  - Jean-Philippe Aumasson (Dr.)",
			"  - Laurent Grémy",
			"  - Loup Vaillant David",
			"  - Michiel Leenars",
			"  - \"Mike\" (pseudonym)",
			"  - Mukesh Tiwari (Dr.)",
			"  - Oleksandra \"Sasha\" Lapiha",
			"  - Renaud Lifchitz",
			"  - Sebastian R. Verschoor",
			"  - Tom Roeder",
		}, "\n"))
	},
}

var cmdJSON = &cobra.Command{
	Use:                   "internal-json [requestType]",
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.ExactArgs(1),
	Hidden:                true,
	Run: func(cmd *cobra.Command, args []string) {
		err := vplogic.JSON(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var cmdFriends = &cobra.Command{
	Use:                   "friends",
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
	Args:                  cobra.NoArgs,
	Hidden:                true,
	Run: func(cmd *cobra.Command, args []string) {
		f := []byte{
			0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x76, 0x65,
			0x72, 0x69, 0x66, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,
			0x2f, 0x72, 0x65, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x72, 0x61,
			0x2f, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x73,
		}
		err := vplogic.OpenBrowser(string(f))
		if err != nil {
			log.Fatal(err)
		}
	},
}

func main() {
	cmdVerify.Flags().BoolP("verifhub", "", false, "submit to VerifHub on analysis completion")
	cmdTranslate.AddCommand(cmdTranslateCoq, cmdTranslatePv)
	rootCmd.AddCommand(cmdVerify, cmdTranslate, cmdPretty, cmdAbout, cmdJSON, cmdFriends)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
