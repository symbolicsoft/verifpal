/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// This file is generated automatically from libpeg.peg.
// Do not modify.

package vplogic

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var libpegReserved = []string{
	"attacker", "passive", "active", "principal",
	"phase, public", "private", "password",
	"confidentiality", "authentication",
	"freshness", "unlinkability", "precondition",
	"ringsign", "ringsignverif",
	"primitive", "pw_hash", "hash", "hkdf",
	"aead_enc", "aead_dec", "enc", "dec",
	"mac", "assert", "sign", "signverif",
	"pke_enc", "pke_dec", "shamir_split",
	"shamir_join", "concat", "split",
	"g", "nil", "unnamed",
}

var libpegUnnamedCounter = 0

func libpegCheckIfReserved(s string) error {
	found := false
	switch {
	case strInSlice(s, libpegReserved):
		found = true
	case strings.HasPrefix(s, "attacker"):
		found = true
	case strings.HasPrefix(s, "unnamed"):
		found = true
	}
	if found {
		return fmt.Errorf("cannot use reserved keyword in Name: %s", s)
	}
	return nil
}

func libpegParseModel(filePath string, verbose bool) (Model, error) {
	fileName := filepath.Base(filePath)
	if len(fileName) > 64 {
		return Model{}, fmt.Errorf("model file name must be 64 characters or less")
	}
	if filepath.Ext(fileName) != ".vp" {
		return Model{}, fmt.Errorf("model file name must have a '.vp' extension")
	}
	if verbose {
		InfoMessage(fmt.Sprintf(
			"Parsing model '%s'...", fileName,
		), "verifpal", false)
	}
	parsed, err := ParseFile(filePath)
	if err != nil {
		return Model{}, err
	}
	m := parsed.(Model)
	m.FileName = fileName
	return m, nil
}

var g = &grammar{
	rules: []*rule{
		{
			name: "Model",
			pos:  position{line: 79, col: 1, offset: 1743},
			expr: &actionExpr{
				pos: position{line: 79, col: 10, offset: 1752},
				run: (*parser).callonModel1,
				expr: &seqExpr{
					pos: position{line: 79, col: 10, offset: 1752},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 79, col: 10, offset: 1752},
							expr: &ruleRefExpr{
								pos:  position{line: 79, col: 10, offset: 1752},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 79, col: 19, offset: 1761},
							label: "Attacker",
							expr: &zeroOrOneExpr{
								pos: position{line: 79, col: 28, offset: 1770},
								expr: &ruleRefExpr{
									pos:  position{line: 79, col: 28, offset: 1770},
									name: "Attacker",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 79, col: 38, offset: 1780},
							label: "Blocks",
							expr: &zeroOrOneExpr{
								pos: position{line: 79, col: 45, offset: 1787},
								expr: &oneOrMoreExpr{
									pos: position{line: 79, col: 46, offset: 1788},
									expr: &ruleRefExpr{
										pos:  position{line: 79, col: 46, offset: 1788},
										name: "Block",
									},
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 79, col: 55, offset: 1797},
							label: "Queries",
							expr: &zeroOrOneExpr{
								pos: position{line: 79, col: 63, offset: 1805},
								expr: &ruleRefExpr{
									pos:  position{line: 79, col: 63, offset: 1805},
									name: "Queries",
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 79, col: 72, offset: 1814},
							expr: &ruleRefExpr{
								pos:  position{line: 79, col: 72, offset: 1814},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 79, col: 81, offset: 1823},
							name: "EOF",
						},
					},
				},
			},
		},
		{
			name: "Attacker",
			pos:  position{line: 101, col: 1, offset: 2375},
			expr: &actionExpr{
				pos: position{line: 101, col: 13, offset: 2387},
				run: (*parser).callonAttacker1,
				expr: &seqExpr{
					pos: position{line: 101, col: 13, offset: 2387},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 101, col: 13, offset: 2387},
							val:        "attacker",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 101, col: 24, offset: 2398},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 101, col: 26, offset: 2400},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 101, col: 30, offset: 2404},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 101, col: 32, offset: 2406},
							label: "Type",
							expr: &ruleRefExpr{
								pos:  position{line: 101, col: 37, offset: 2411},
								name: "AttackerType",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 101, col: 50, offset: 2424},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 101, col: 52, offset: 2426},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 101, col: 56, offset: 2430},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "AttackerType",
			pos:  position{line: 105, col: 1, offset: 2455},
			expr: &actionExpr{
				pos: position{line: 105, col: 17, offset: 2471},
				run: (*parser).callonAttackerType1,
				expr: &choiceExpr{
					pos: position{line: 105, col: 18, offset: 2472},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 105, col: 18, offset: 2472},
							val:        "active",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 105, col: 27, offset: 2481},
							val:        "passive",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Block",
			pos:  position{line: 109, col: 1, offset: 2525},
			expr: &actionExpr{
				pos: position{line: 109, col: 10, offset: 2534},
				run: (*parser).callonBlock1,
				expr: &seqExpr{
					pos: position{line: 109, col: 10, offset: 2534},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 109, col: 10, offset: 2534},
							expr: &ruleRefExpr{
								pos:  position{line: 109, col: 10, offset: 2534},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 109, col: 19, offset: 2543},
							label: "Block",
							expr: &choiceExpr{
								pos: position{line: 109, col: 26, offset: 2550},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 109, col: 26, offset: 2550},
										name: "Principal",
									},
									&ruleRefExpr{
										pos:  position{line: 109, col: 36, offset: 2560},
										name: "Message",
									},
									&ruleRefExpr{
										pos:  position{line: 109, col: 44, offset: 2568},
										name: "Phase",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 109, col: 51, offset: 2575},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 109, col: 53, offset: 2577},
							expr: &ruleRefExpr{
								pos:  position{line: 109, col: 53, offset: 2577},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Principal",
			pos:  position{line: 113, col: 1, offset: 2610},
			expr: &actionExpr{
				pos: position{line: 113, col: 14, offset: 2623},
				run: (*parser).callonPrincipal1,
				expr: &seqExpr{
					pos: position{line: 113, col: 14, offset: 2623},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 113, col: 14, offset: 2623},
							val:        "principal",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 26, offset: 2635},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 113, col: 28, offset: 2637},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 113, col: 33, offset: 2642},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 47, offset: 2656},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 113, col: 49, offset: 2658},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 53, offset: 2662},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 113, col: 55, offset: 2664},
							label: "Expressions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 113, col: 68, offset: 2677},
								expr: &ruleRefExpr{
									pos:  position{line: 113, col: 68, offset: 2677},
									name: "Expression",
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 113, col: 81, offset: 2690},
							expr: &ruleRefExpr{
								pos:  position{line: 113, col: 81, offset: 2690},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 90, offset: 2699},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 113, col: 92, offset: 2701},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 96, offset: 2705},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 126, col: 1, offset: 2946},
			expr: &actionExpr{
				pos: position{line: 126, col: 18, offset: 2963},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 126, col: 18, offset: 2963},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 126, col: 23, offset: 2968},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Qualifier",
			pos:  position{line: 131, col: 1, offset: 3071},
			expr: &actionExpr{
				pos: position{line: 131, col: 14, offset: 3084},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 131, col: 15, offset: 3085},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 131, col: 15, offset: 3085},
							val:        "public",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 131, col: 24, offset: 3094},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 131, col: 34, offset: 3104},
							val:        "password",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 135, col: 1, offset: 3149},
			expr: &actionExpr{
				pos: position{line: 135, col: 12, offset: 3160},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 135, col: 12, offset: 3160},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 135, col: 12, offset: 3160},
							label: "Sender",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 19, offset: 3167},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 33, offset: 3181},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 135, col: 35, offset: 3183},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 40, offset: 3188},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 135, col: 42, offset: 3190},
							label: "Recipient",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 52, offset: 3200},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 66, offset: 3214},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 135, col: 68, offset: 3216},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 72, offset: 3220},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 135, col: 74, offset: 3222},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 84, offset: 3232},
								name: "MessageConstants",
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 146, col: 1, offset: 3421},
			expr: &actionExpr{
				pos: position{line: 146, col: 21, offset: 3441},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 146, col: 21, offset: 3441},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 146, col: 38, offset: 3458},
						expr: &choiceExpr{
							pos: position{line: 146, col: 39, offset: 3459},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 146, col: 39, offset: 3459},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 146, col: 55, offset: 3475},
									name: "Constant",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Expression",
			pos:  position{line: 156, col: 1, offset: 3639},
			expr: &actionExpr{
				pos: position{line: 156, col: 15, offset: 3653},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 156, col: 15, offset: 3653},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 156, col: 15, offset: 3653},
							expr: &ruleRefExpr{
								pos:  position{line: 156, col: 15, offset: 3653},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 156, col: 24, offset: 3662},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 156, col: 36, offset: 3674},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 156, col: 36, offset: 3674},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 42, offset: 3680},
										name: "Generates",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 52, offset: 3690},
										name: "Leaks",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 58, offset: 3696},
										name: "Assignment",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 156, col: 70, offset: 3708},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 156, col: 72, offset: 3710},
							expr: &ruleRefExpr{
								pos:  position{line: 156, col: 72, offset: 3710},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 160, col: 1, offset: 3748},
			expr: &actionExpr{
				pos: position{line: 160, col: 10, offset: 3757},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 160, col: 10, offset: 3757},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 160, col: 10, offset: 3757},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 160, col: 18, offset: 3765},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 160, col: 20, offset: 3767},
							label: "Qualifier",
							expr: &ruleRefExpr{
								pos:  position{line: 160, col: 30, offset: 3777},
								name: "Qualifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 160, col: 40, offset: 3787},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 160, col: 42, offset: 3789},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 160, col: 52, offset: 3799},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 168, col: 1, offset: 3929},
			expr: &actionExpr{
				pos: position{line: 168, col: 14, offset: 3942},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 168, col: 14, offset: 3942},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 168, col: 14, offset: 3942},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 168, col: 26, offset: 3954},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 168, col: 28, offset: 3956},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 168, col: 38, offset: 3966},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Leaks",
			pos:  position{line: 176, col: 1, offset: 4084},
			expr: &actionExpr{
				pos: position{line: 176, col: 10, offset: 4093},
				run: (*parser).callonLeaks1,
				expr: &seqExpr{
					pos: position{line: 176, col: 10, offset: 4093},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 176, col: 10, offset: 4093},
							val:        "leaks",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 176, col: 18, offset: 4101},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 176, col: 20, offset: 4103},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 176, col: 30, offset: 4113},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 184, col: 1, offset: 4227},
			expr: &actionExpr{
				pos: position{line: 184, col: 15, offset: 4241},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 184, col: 15, offset: 4241},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 184, col: 15, offset: 4241},
							label: "Left",
							expr: &ruleRefExpr{
								pos:  position{line: 184, col: 20, offset: 4246},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 184, col: 30, offset: 4256},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 184, col: 32, offset: 4258},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 184, col: 36, offset: 4262},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 184, col: 38, offset: 4264},
							label: "Right",
							expr: &ruleRefExpr{
								pos:  position{line: 184, col: 44, offset: 4270},
								name: "Value",
							},
						},
					},
				},
			},
		},
		{
			name: "Constant",
			pos:  position{line: 205, col: 1, offset: 4714},
			expr: &actionExpr{
				pos: position{line: 205, col: 13, offset: 4726},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 205, col: 13, offset: 4726},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 205, col: 13, offset: 4726},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 205, col: 19, offset: 4732},
								name: "Identifier",
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 205, col: 30, offset: 4743},
							expr: &seqExpr{
								pos: position{line: 205, col: 31, offset: 4744},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 205, col: 31, offset: 4744},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 205, col: 33, offset: 4746},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 205, col: 37, offset: 4750},
										name: "_",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Constants",
			pos:  position{line: 214, col: 1, offset: 4854},
			expr: &actionExpr{
				pos: position{line: 214, col: 14, offset: 4867},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 214, col: 14, offset: 4867},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 214, col: 24, offset: 4877},
						expr: &ruleRefExpr{
							pos:  position{line: 214, col: 24, offset: 4877},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "Phase",
			pos:  position{line: 226, col: 1, offset: 5120},
			expr: &actionExpr{
				pos: position{line: 226, col: 10, offset: 5129},
				run: (*parser).callonPhase1,
				expr: &seqExpr{
					pos: position{line: 226, col: 10, offset: 5129},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 226, col: 10, offset: 5129},
							val:        "phase",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 18, offset: 5137},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 226, col: 20, offset: 5139},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 24, offset: 5143},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 226, col: 26, offset: 5145},
							label: "Number",
							expr: &oneOrMoreExpr{
								pos: position{line: 226, col: 33, offset: 5152},
								expr: &charClassMatcher{
									pos:        position{line: 226, col: 33, offset: 5152},
									val:        "[0-9]",
									ranges:     []rune{'0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 40, offset: 5159},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 226, col: 42, offset: 5161},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 46, offset: 5165},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 239, col: 1, offset: 5387},
			expr: &actionExpr{
				pos: position{line: 239, col: 20, offset: 5406},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 239, col: 20, offset: 5406},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 239, col: 20, offset: 5406},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 239, col: 24, offset: 5410},
							label: "Guarded",
							expr: &ruleRefExpr{
								pos:  position{line: 239, col: 32, offset: 5418},
								name: "Identifier",
							},
						},
						&litMatcher{
							pos:        position{line: 239, col: 43, offset: 5429},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 239, col: 47, offset: 5433},
							expr: &seqExpr{
								pos: position{line: 239, col: 48, offset: 5434},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 239, col: 48, offset: 5434},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 239, col: 50, offset: 5436},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 239, col: 54, offset: 5440},
										name: "_",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Primitive",
			pos:  position{line: 250, col: 1, offset: 5610},
			expr: &actionExpr{
				pos: position{line: 250, col: 14, offset: 5623},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 250, col: 14, offset: 5623},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 250, col: 14, offset: 5623},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 250, col: 19, offset: 5628},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 250, col: 33, offset: 5642},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 250, col: 37, offset: 5646},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 250, col: 39, offset: 5648},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 250, col: 49, offset: 5658},
								expr: &ruleRefExpr{
									pos:  position{line: 250, col: 49, offset: 5658},
									name: "Value",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 250, col: 56, offset: 5665},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 250, col: 58, offset: 5667},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 250, col: 62, offset: 5671},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 250, col: 68, offset: 5677},
								expr: &litMatcher{
									pos:        position{line: 250, col: 68, offset: 5677},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 250, col: 73, offset: 5682},
							expr: &seqExpr{
								pos: position{line: 250, col: 74, offset: 5683},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 250, col: 74, offset: 5683},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 250, col: 76, offset: 5685},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 250, col: 80, offset: 5689},
										name: "_",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "PrimitiveName",
			pos:  position{line: 266, col: 1, offset: 5955},
			expr: &actionExpr{
				pos: position{line: 266, col: 18, offset: 5972},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 266, col: 18, offset: 5972},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 266, col: 23, offset: 5977},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Equation",
			pos:  position{line: 270, col: 1, offset: 6037},
			expr: &actionExpr{
				pos: position{line: 270, col: 13, offset: 6049},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 270, col: 13, offset: 6049},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 270, col: 13, offset: 6049},
							label: "First",
							expr: &ruleRefExpr{
								pos:  position{line: 270, col: 19, offset: 6055},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 270, col: 29, offset: 6065},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 270, col: 29, offset: 6065},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 270, col: 31, offset: 6067},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 270, col: 35, offset: 6071},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 270, col: 38, offset: 6074},
							label: "Second",
							expr: &ruleRefExpr{
								pos:  position{line: 270, col: 45, offset: 6081},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Value",
			pos:  position{line: 282, col: 1, offset: 6230},
			expr: &choiceExpr{
				pos: position{line: 282, col: 10, offset: 6239},
				alternatives: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 282, col: 10, offset: 6239},
						name: "Primitive",
					},
					&ruleRefExpr{
						pos:  position{line: 282, col: 20, offset: 6249},
						name: "Equation",
					},
					&ruleRefExpr{
						pos:  position{line: 282, col: 29, offset: 6258},
						name: "Constant",
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 284, col: 1, offset: 6269},
			expr: &actionExpr{
				pos: position{line: 284, col: 12, offset: 6280},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 284, col: 12, offset: 6280},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 284, col: 12, offset: 6280},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 22, offset: 6290},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 284, col: 24, offset: 6292},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 28, offset: 6296},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 284, col: 30, offset: 6298},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 284, col: 39, offset: 6307},
								expr: &ruleRefExpr{
									pos:  position{line: 284, col: 39, offset: 6307},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 284, col: 47, offset: 6315},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 51, offset: 6319},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 288, col: 1, offset: 6347},
			expr: &actionExpr{
				pos: position{line: 288, col: 10, offset: 6356},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 288, col: 10, offset: 6356},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 288, col: 10, offset: 6356},
							expr: &ruleRefExpr{
								pos:  position{line: 288, col: 10, offset: 6356},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 288, col: 19, offset: 6365},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 288, col: 26, offset: 6372},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 288, col: 26, offset: 6372},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 47, offset: 6393},
										name: "QueryAuthentication",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 67, offset: 6413},
										name: "QueryFreshness",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 82, offset: 6428},
										name: "QueryUnlinkability",
									},
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 288, col: 102, offset: 6448},
							expr: &ruleRefExpr{
								pos:  position{line: 288, col: 102, offset: 6448},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 292, col: 1, offset: 6482},
			expr: &actionExpr{
				pos: position{line: 292, col: 25, offset: 6506},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 292, col: 25, offset: 6506},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 292, col: 25, offset: 6506},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 44, offset: 6525},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 292, col: 46, offset: 6527},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 292, col: 52, offset: 6533},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 61, offset: 6542},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 292, col: 63, offset: 6544},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 292, col: 71, offset: 6552},
								expr: &ruleRefExpr{
									pos:  position{line: 292, col: 71, offset: 6552},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 85, offset: 6566},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 304, col: 1, offset: 6782},
			expr: &actionExpr{
				pos: position{line: 304, col: 24, offset: 6805},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 304, col: 24, offset: 6805},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 304, col: 24, offset: 6805},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 42, offset: 6823},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 304, col: 44, offset: 6825},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 304, col: 52, offset: 6833},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 60, offset: 6841},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 304, col: 62, offset: 6843},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 304, col: 70, offset: 6851},
								expr: &ruleRefExpr{
									pos:  position{line: 304, col: 70, offset: 6851},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 84, offset: 6865},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryFreshness",
			pos:  position{line: 316, col: 1, offset: 7074},
			expr: &actionExpr{
				pos: position{line: 316, col: 19, offset: 7092},
				run: (*parser).callonQueryFreshness1,
				expr: &seqExpr{
					pos: position{line: 316, col: 19, offset: 7092},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 316, col: 19, offset: 7092},
							val:        "freshness?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 32, offset: 7105},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 316, col: 34, offset: 7107},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 316, col: 40, offset: 7113},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 49, offset: 7122},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 316, col: 51, offset: 7124},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 316, col: 59, offset: 7132},
								expr: &ruleRefExpr{
									pos:  position{line: 316, col: 59, offset: 7132},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 73, offset: 7146},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryUnlinkability",
			pos:  position{line: 328, col: 1, offset: 7356},
			expr: &actionExpr{
				pos: position{line: 328, col: 23, offset: 7378},
				run: (*parser).callonQueryUnlinkability1,
				expr: &seqExpr{
					pos: position{line: 328, col: 23, offset: 7378},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 328, col: 23, offset: 7378},
							val:        "unlinkability?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 40, offset: 7395},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 328, col: 42, offset: 7397},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 328, col: 52, offset: 7407},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 62, offset: 7417},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 328, col: 64, offset: 7419},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 328, col: 72, offset: 7427},
								expr: &ruleRefExpr{
									pos:  position{line: 328, col: 72, offset: 7427},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 86, offset: 7441},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOptions",
			pos:  position{line: 340, col: 1, offset: 7643},
			expr: &actionExpr{
				pos: position{line: 340, col: 17, offset: 7659},
				run: (*parser).callonQueryOptions1,
				expr: &seqExpr{
					pos: position{line: 340, col: 17, offset: 7659},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 340, col: 17, offset: 7659},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 340, col: 21, offset: 7663},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 340, col: 23, offset: 7665},
							label: "Options",
							expr: &zeroOrMoreExpr{
								pos: position{line: 340, col: 32, offset: 7674},
								expr: &ruleRefExpr{
									pos:  position{line: 340, col: 32, offset: 7674},
									name: "QueryOption",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 340, col: 46, offset: 7688},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 340, col: 50, offset: 7692},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOption",
			pos:  position{line: 347, col: 1, offset: 7829},
			expr: &actionExpr{
				pos: position{line: 347, col: 16, offset: 7844},
				run: (*parser).callonQueryOption1,
				expr: &seqExpr{
					pos: position{line: 347, col: 16, offset: 7844},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 347, col: 16, offset: 7844},
							label: "OptionName",
							expr: &ruleRefExpr{
								pos:  position{line: 347, col: 27, offset: 7855},
								name: "Identifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 38, offset: 7866},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 347, col: 40, offset: 7868},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 44, offset: 7872},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 347, col: 46, offset: 7874},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 347, col: 54, offset: 7882},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 62, offset: 7890},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 347, col: 64, offset: 7892},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 68, offset: 7896},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Identifier",
			pos:  position{line: 354, col: 1, offset: 7999},
			expr: &actionExpr{
				pos: position{line: 354, col: 15, offset: 8013},
				run: (*parser).callonIdentifier1,
				expr: &labeledExpr{
					pos:   position{line: 354, col: 15, offset: 8013},
					label: "Identifier",
					expr: &oneOrMoreExpr{
						pos: position{line: 354, col: 26, offset: 8024},
						expr: &charClassMatcher{
							pos:        position{line: 354, col: 26, offset: 8024},
							val:        "[a-zA-Z0-9_]",
							chars:      []rune{'_'},
							ranges:     []rune{'a', 'z', 'A', 'Z', '0', '9'},
							ignoreCase: false,
							inverted:   false,
						},
					},
				},
			},
		},
		{
			name: "Comment",
			pos:  position{line: 359, col: 1, offset: 8114},
			expr: &seqExpr{
				pos: position{line: 359, col: 12, offset: 8125},
				exprs: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 359, col: 12, offset: 8125},
						name: "_",
					},
					&litMatcher{
						pos:        position{line: 359, col: 14, offset: 8127},
						val:        "//",
						ignoreCase: false,
					},
					&zeroOrMoreExpr{
						pos: position{line: 359, col: 19, offset: 8132},
						expr: &charClassMatcher{
							pos:        position{line: 359, col: 19, offset: 8132},
							val:        "[^\\n]",
							chars:      []rune{'\n'},
							ignoreCase: false,
							inverted:   true,
						},
					},
					&ruleRefExpr{
						pos:  position{line: 359, col: 26, offset: 8139},
						name: "_",
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 361, col: 1, offset: 8142},
			expr: &zeroOrMoreExpr{
				pos: position{line: 361, col: 19, offset: 8160},
				expr: &charClassMatcher{
					pos:        position{line: 361, col: 19, offset: 8160},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 363, col: 1, offset: 8172},
			expr: &notExpr{
				pos: position{line: 363, col: 8, offset: 8179},
				expr: &anyMatcher{
					line: 363, col: 9, offset: 8180,
				},
			},
		},
	},
}

func (c *current) onModel1(Attacker, Blocks, Queries interface{}) (interface{}, error) {
	switch {
	case Attacker == nil:
		return nil, errors.New("no `attacker` block defined")
	case Blocks == nil:
		return nil, errors.New("no principal or message blocks defined")
	case Queries == nil:
		return nil, errors.New("no `queries` block defined")
	}
	b := Blocks.([]interface{})
	q := Queries.([]interface{})
	db := make([]Block, len(b))
	dq := make([]Query, len(q))
	for i, v := range b {
		db[i] = v.(Block)
	}
	for i, v := range q {
		dq[i] = v.(Query)
	}
	return Model{
		Attacker: Attacker.(string),
		Blocks:   db,
		Queries:  dq,
	}, nil
}

func (p *parser) callonModel1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onModel1(stack["Attacker"], stack["Blocks"], stack["Queries"])
}

func (c *current) onAttacker1(Type interface{}) (interface{}, error) {
	return Type, nil
}

func (p *parser) callonAttacker1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onAttacker1(stack["Type"])
}

func (c *current) onAttackerType1() (interface{}, error) {
	return string(c.text), nil
}

func (p *parser) callonAttackerType1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onAttackerType1()
}

func (c *current) onBlock1(Block interface{}) (interface{}, error) {
	return Block, nil
}

func (p *parser) callonBlock1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onBlock1(stack["Block"])
}

func (c *current) onPrincipal1(Name, Expressions interface{}) (interface{}, error) {
	e := Expressions.([]interface{})
	de := make([]Expression, len(e))
	for i, v := range e {
		de[i] = v.(Expression)
	}
	return Block{
		Kind: "principal",
		Principal: Principal{
			Name:        Name.(string),
			Expressions: de,
		},
	}, nil
}

func (p *parser) callonPrincipal1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrincipal1(stack["Name"], stack["Expressions"])
}

func (c *current) onPrincipalName1(Name interface{}) (interface{}, error) {
	err := libpegCheckIfReserved(Name.(string))
	return strings.Title(Name.(string)), err
}

func (p *parser) callonPrincipalName1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrincipalName1(stack["Name"])
}

func (c *current) onQualifier1() (interface{}, error) {
	return string(c.text), nil
}

func (p *parser) callonQualifier1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQualifier1()
}

func (c *current) onMessage1(Sender, Recipient, Constants interface{}) (interface{}, error) {
	return Block{
		Kind: "message",
		Message: Message{
			Sender:    Sender.(string),
			Recipient: Recipient.(string),
			Constants: Constants.([]Constant),
		},
	}, nil
}

func (p *parser) callonMessage1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onMessage1(stack["Sender"], stack["Recipient"], stack["Constants"])
}

func (c *current) onMessageConstants1(MessageConstants interface{}) (interface{}, error) {
	var da []Constant
	a := MessageConstants.([]interface{})
	for _, v := range a {
		c := v.(Value).Constant
		da = append(da, c)
	}
	return da, nil
}

func (p *parser) callonMessageConstants1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onMessageConstants1(stack["MessageConstants"])
}

func (c *current) onExpression1(Expression interface{}) (interface{}, error) {
	return Expression, nil
}

func (p *parser) callonExpression1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onExpression1(stack["Expression"])
}

func (c *current) onKnows1(Qualifier, Constants interface{}) (interface{}, error) {
	return Expression{
		Kind:      "knows",
		Qualifier: Qualifier.(string),
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonKnows1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onKnows1(stack["Qualifier"], stack["Constants"])
}

func (c *current) onGenerates1(Constants interface{}) (interface{}, error) {
	return Expression{
		Kind:      "generates",
		Qualifier: "",
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonGenerates1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGenerates1(stack["Constants"])
}

func (c *current) onLeaks1(Constants interface{}) (interface{}, error) {
	return Expression{
		Kind:      "leaks",
		Qualifier: "",
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonLeaks1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onLeaks1(stack["Constants"])
}

func (c *current) onAssignment1(Left, Right interface{}) (interface{}, error) {
	switch Right.(Value).Kind {
	case "constant":
		err := errors.New("cannot assign value to value")
		return nil, err
	}
	consts := Left.([]Constant)
	for i, c := range consts {
		switch c.Name {
		case "_":
			consts[i].Name = fmt.Sprintf("unnamed_%d", libpegUnnamedCounter)
			libpegUnnamedCounter = libpegUnnamedCounter + 1
		}
	}
	return Expression{
		Kind:      "assignment",
		Constants: consts,
		Assigned:  Right.(Value),
	}, nil
}

func (p *parser) callonAssignment1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onAssignment1(stack["Left"], stack["Right"])
}

func (c *current) onConstant1(Const interface{}) (interface{}, error) {
	return Value{
		Kind: "constant",
		Constant: Constant{
			Name: Const.(string),
		},
	}, nil
}

func (p *parser) callonConstant1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onConstant1(stack["Const"])
}

func (c *current) onConstants1(Constants interface{}) (interface{}, error) {
	var da []Constant
	var err error
	a := Constants.([]interface{})
	for _, c := range a {
		err = libpegCheckIfReserved(c.(Value).Constant.Name)
		if err != nil {
			break
		}
		da = append(da, c.(Value).Constant)
	}
	return da, err
}

func (p *parser) callonConstants1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onConstants1(stack["Constants"])
}

func (c *current) onPhase1(Number interface{}) (interface{}, error) {
	a := Number.([]interface{})
	da := make([]uint8, len(a))
	for i, v := range a {
		da[i] = v.([]uint8)[0]
	}
	n, err := strconv.Atoi(b2s(da))
	return Block{
		Kind: "phase",
		Phase: Phase{
			Number: n,
		},
	}, err
}

func (p *parser) callonPhase1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPhase1(stack["Number"])
}

func (c *current) onGuardedConstant1(Guarded interface{}) (interface{}, error) {
	err := libpegCheckIfReserved(Guarded.(string))
	return Value{
		Kind: "constant",
		Constant: Constant{
			Name:  Guarded.(string),
			Guard: true,
		},
	}, err
}

func (p *parser) callonGuardedConstant1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGuardedConstant1(stack["Guarded"])
}

func (c *current) onPrimitive1(Name, Arguments, Check interface{}) (interface{}, error) {
	args := []Value{}
	for _, a := range Arguments.([]interface{}) {
		args = append(args, a.(Value))
	}
	return Value{
		Kind: "primitive",
		Primitive: Primitive{
			Name:      Name.(string),
			Arguments: args,
			Output:    0,
			Check:     Check != nil,
		},
	}, nil
}

func (p *parser) callonPrimitive1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrimitive1(stack["Name"], stack["Arguments"], stack["Check"])
}

func (c *current) onPrimitiveName1(Name interface{}) (interface{}, error) {
	return strings.ToUpper(Name.(string)), nil
}

func (p *parser) callonPrimitiveName1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrimitiveName1(stack["Name"])
}

func (c *current) onEquation1(First, Second interface{}) (interface{}, error) {
	return Value{
		Kind: "equation",
		Equation: Equation{
			Values: []Value{
				First.(Value),
				Second.(Value),
			},
		},
	}, nil
}

func (p *parser) callonEquation1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onEquation1(stack["First"], stack["Second"])
}

func (c *current) onQueries1(Queries interface{}) (interface{}, error) {
	return Queries, nil
}

func (p *parser) callonQueries1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueries1(stack["Queries"])
}

func (c *current) onQuery1(Query interface{}) (interface{}, error) {
	return Query, nil
}

func (p *parser) callonQuery1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQuery1(stack["Query"])
}

func (c *current) onQueryConfidentiality1(Const, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []QueryOption{}
	}
	return Query{
		Kind:      "confidentiality",
		Constants: []Constant{Const.(Value).Constant},
		Message:   Message{},
		Options:   Options.([]QueryOption),
	}, nil
}

func (p *parser) callonQueryConfidentiality1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryConfidentiality1(stack["Const"], stack["Options"])
}

func (c *current) onQueryAuthentication1(Message, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []QueryOption{}
	}
	return Query{
		Kind:      "authentication",
		Constants: []Constant{},
		Message:   (Message.(Block)).Message,
		Options:   Options.([]QueryOption),
	}, nil
}

func (p *parser) callonQueryAuthentication1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryAuthentication1(stack["Message"], stack["Options"])
}

func (c *current) onQueryFreshness1(Const, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []QueryOption{}
	}
	return Query{
		Kind:      "freshness",
		Constants: []Constant{Const.(Value).Constant},
		Message:   Message{},
		Options:   Options.([]QueryOption),
	}, nil
}

func (p *parser) callonQueryFreshness1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryFreshness1(stack["Const"], stack["Options"])
}

func (c *current) onQueryUnlinkability1(Constants, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []QueryOption{}
	}
	return Query{
		Kind:      "unlinkability",
		Constants: Constants.([]Constant),
		Message:   Message{},
		Options:   Options.([]QueryOption),
	}, nil
}

func (p *parser) callonQueryUnlinkability1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryUnlinkability1(stack["Constants"], stack["Options"])
}

func (c *current) onQueryOptions1(Options interface{}) (interface{}, error) {
	o := Options.([]interface{})
	do := make([]QueryOption, len(o))
	for i, v := range o {
		do[i] = v.(QueryOption)
	}
	return do, nil
}

func (p *parser) callonQueryOptions1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryOptions1(stack["Options"])
}

func (c *current) onQueryOption1(OptionName, Message interface{}) (interface{}, error) {
	return QueryOption{
		Kind:    OptionName.(string),
		Message: (Message.(Block)).Message,
	}, nil
}

func (p *parser) callonQueryOption1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryOption1(stack["OptionName"], stack["Message"])
}

func (c *current) onIdentifier1(Identifier interface{}) (interface{}, error) {
	identifier := strings.ToLower(string(c.text))
	return identifier, nil
}

func (p *parser) callonIdentifier1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onIdentifier1(stack["Identifier"])
}

var (
	// errNoRule is returned when the grammar to parse has no rule.
	errNoRule = errors.New("grammar has no rule")

	// errInvalidEncoding is returned when the source is not properly
	// utf8-encoded.
	errInvalidEncoding = errors.New("invalid encoding")

	// errNoMatch is returned if no match could be found.
	errNoMatch = errors.New("no match found")
)

// Option is a function that can set an option on the parser. It returns
// the previous setting as an Option.
type Option func(*parser) Option

// Debug creates an Option to set the debug flag to b. When set to true,
// debugging information is printed to stdout while parsing.
//
// The default is false.
func Debug(b bool) Option {
	return func(p *parser) Option {
		old := p.debug
		p.debug = b
		return Debug(old)
	}
}

// Memoize creates an Option to set the memoize flag to b. When set to true,
// the parser will cache all results so each expression is evaluated only
// once. This guarantees linear parsing time even for pathological cases,
// at the expense of more memory and slower times for typical cases.
//
// The default is false.
func Memoize(b bool) Option {
	return func(p *parser) Option {
		old := p.memoize
		p.memoize = b
		return Memoize(old)
	}
}

// Recover creates an Option to set the recover flag to b. When set to
// true, this causes the parser to recover from panics and convert it
// to an error. Setting it to false can be useful while debugging to
// access the full stack trace.
//
// The default is true.
func Recover(b bool) Option {
	return func(p *parser) Option {
		old := p.recover
		p.recover = b
		return Recover(old)
	}
}

// ParseFile parses the file identified by filename.
func ParseFile(filename string, opts ...Option) (interface{}, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseReader(filename, f, opts...)
}

// ParseReader parses the data from r using filename as information in the
// error messages.
func ParseReader(filename string, r io.Reader, opts ...Option) (interface{}, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return Parse(filename, b, opts...)
}

// Parse parses the data from b using filename as information in the
// error messages.
func Parse(filename string, b []byte, opts ...Option) (interface{}, error) {
	return newParser(filename, b, opts...).parse(g)
}

// position records a position in the text.
type position struct {
	line, col, offset int
}

func (p position) String() string {
	return fmt.Sprintf("%d:%d [%d]", p.line, p.col, p.offset)
}

// savepoint stores all state required to go back to this point in the
// parser.
type savepoint struct {
	position
	rn rune
	w  int
}

type current struct {
	pos  position // start position of the match
	text []byte   // raw text of the match
}

// the AST types...

type grammar struct {
	pos   position
	rules []*rule
}

type rule struct {
	pos         position
	name        string
	displayName string
	expr        interface{}
}

type choiceExpr struct {
	pos          position
	alternatives []interface{}
}

type actionExpr struct {
	pos  position
	expr interface{}
	run  func(*parser) (interface{}, error)
}

type seqExpr struct {
	pos   position
	exprs []interface{}
}

type labeledExpr struct {
	pos   position
	label string
	expr  interface{}
}

type expr struct {
	pos  position
	expr interface{}
}

type andExpr expr
type notExpr expr
type zeroOrOneExpr expr
type zeroOrMoreExpr expr
type oneOrMoreExpr expr

type ruleRefExpr struct {
	pos  position
	name string
}

type andCodeExpr struct {
	pos position
	run func(*parser) (bool, error)
}

type notCodeExpr struct {
	pos position
	run func(*parser) (bool, error)
}

type litMatcher struct {
	pos        position
	val        string
	ignoreCase bool
}

type charClassMatcher struct {
	pos        position
	val        string
	chars      []rune
	ranges     []rune
	classes    []*unicode.RangeTable
	ignoreCase bool
	inverted   bool
}

type anyMatcher position

// errList cumulates the errors found by the parser.
type errList []error

func (e *errList) add(err error) {
	*e = append(*e, err)
}

func (e errList) err() error {
	if len(e) == 0 {
		return nil
	}
	e.dedupe()
	return e
}

func (e *errList) dedupe() {
	var cleaned []error
	set := make(map[string]bool)
	for _, err := range *e {
		if msg := err.Error(); !set[msg] {
			set[msg] = true
			cleaned = append(cleaned, err)
		}
	}
	*e = cleaned
}

func (e errList) Error() string {
	switch len(e) {
	case 0:
		return ""
	case 1:
		return e[0].Error()
	default:
		var buf bytes.Buffer

		for i, err := range e {
			if i > 0 {
				buf.WriteRune('\n')
			}
			buf.WriteString(err.Error())
		}
		return buf.String()
	}
}

// parserError wraps an error with a prefix indicating the rule in which
// the error occurred. The original error is stored in the Inner field.
type parserError struct {
	Inner  error
	pos    position
	prefix string
}

// Error returns the error message.
func (p *parserError) Error() string {
	return p.prefix + ": " + p.Inner.Error()
}

// newParser creates a parser with the specified input source and options.
func newParser(filename string, b []byte, opts ...Option) *parser {
	p := &parser{
		filename: filename,
		errs:     new(errList),
		data:     b,
		pt:       savepoint{position: position{line: 1}},
		recover:  true,
	}
	p.setOptions(opts)
	return p
}

// setOptions applies the options to the parser.
func (p *parser) setOptions(opts []Option) {
	for _, opt := range opts {
		opt(p)
	}
}

type resultTuple struct {
	v   interface{}
	b   bool
	end savepoint
}

type parser struct {
	filename string
	pt       savepoint
	cur      current

	data []byte
	errs *errList

	recover bool
	debug   bool
	depth   int

	memoize bool
	// memoization table for the packrat algorithm:
	// map[offset in source] map[expression or rule] {value, match}
	memo map[int]map[interface{}]resultTuple

	// rules table, maps the rule identifier to the rule node
	rules map[string]*rule
	// variables stack, map of label to value
	vstack []map[string]interface{}
	// rule stack, allows identification of the current rule in errors
	rstack []*rule

	// stats
	exprCnt int
}

// push a variable set on the vstack.
func (p *parser) pushV() {
	if cap(p.vstack) == len(p.vstack) {
		// create new empty slot in the stack
		p.vstack = append(p.vstack, nil)
	} else {
		// slice to 1 more
		p.vstack = p.vstack[:len(p.vstack)+1]
	}

	// get the last args set
	m := p.vstack[len(p.vstack)-1]
	if m != nil && len(m) == 0 {
		// empty map, all good
		return
	}

	m = make(map[string]interface{})
	p.vstack[len(p.vstack)-1] = m
}

// pop a variable set from the vstack.
func (p *parser) popV() {
	// if the map is not empty, clear it
	m := p.vstack[len(p.vstack)-1]
	if len(m) > 0 {
		// GC that map
		p.vstack[len(p.vstack)-1] = nil
	}
	p.vstack = p.vstack[:len(p.vstack)-1]
}

func (p *parser) print(prefix, s string) string {
	if !p.debug {
		return s
	}

	fmt.Printf("%s %d:%d:%d: %s [%#U]\n",
		prefix, p.pt.line, p.pt.col, p.pt.offset, s, p.pt.rn)
	return s
}

func (p *parser) in(s string) string {
	p.depth++
	return p.print(strings.Repeat(" ", p.depth)+">", s)
}

func (p *parser) out(s string) string {
	p.depth--
	return p.print(strings.Repeat(" ", p.depth)+"<", s)
}

func (p *parser) addErr(err error) {
	p.addErrAt(err, p.pt.position)
}

func (p *parser) addErrAt(err error, pos position) {
	var buf bytes.Buffer
	if p.filename != "" {
		buf.WriteString(p.filename)
	}
	if buf.Len() > 0 {
		buf.WriteString(":")
	}
	buf.WriteString(fmt.Sprintf("%d:%d (%d)", pos.line, pos.col, pos.offset))
	if len(p.rstack) > 0 {
		if buf.Len() > 0 {
			buf.WriteString(": ")
		}
		rule := p.rstack[len(p.rstack)-1]
		if rule.displayName != "" {
			buf.WriteString("rule " + rule.displayName)
		} else {
			buf.WriteString("rule " + rule.name)
		}
	}
	pe := &parserError{Inner: err, pos: pos, prefix: buf.String()}
	p.errs.add(pe)
}

// read advances the parser to the next rune.
func (p *parser) read() {
	p.pt.offset += p.pt.w
	rn, n := utf8.DecodeRune(p.data[p.pt.offset:])
	p.pt.rn = rn
	p.pt.w = n
	p.pt.col++
	if rn == '\n' {
		p.pt.line++
		p.pt.col = 0
	}

	if rn == utf8.RuneError {
		if n == 1 {
			p.addErr(errInvalidEncoding)
		}
	}
}

// restore parser position to the savepoint pt.
func (p *parser) restore(pt savepoint) {
	if p.debug {
		defer p.out(p.in("restore"))
	}
	if pt.offset == p.pt.offset {
		return
	}
	p.pt = pt
}

// get the slice of bytes from the savepoint start to the current position.
func (p *parser) sliceFrom(start savepoint) []byte {
	return p.data[start.position.offset:p.pt.position.offset]
}

func (p *parser) getMemoized(node interface{}) (resultTuple, bool) {
	if len(p.memo) == 0 {
		return resultTuple{}, false
	}
	m := p.memo[p.pt.offset]
	if len(m) == 0 {
		return resultTuple{}, false
	}
	res, ok := m[node]
	return res, ok
}

func (p *parser) setMemoized(pt savepoint, node interface{}, tuple resultTuple) {
	if p.memo == nil {
		p.memo = make(map[int]map[interface{}]resultTuple)
	}
	m := p.memo[pt.offset]
	if m == nil {
		m = make(map[interface{}]resultTuple)
		p.memo[pt.offset] = m
	}
	m[node] = tuple
}

func (p *parser) buildRulesTable(g *grammar) {
	p.rules = make(map[string]*rule, len(g.rules))
	for _, r := range g.rules {
		p.rules[r.name] = r
	}
}

func (p *parser) parse(g *grammar) (val interface{}, err error) {
	if len(g.rules) == 0 {
		p.addErr(errNoRule)
		return nil, p.errs.err()
	}

	// TODO : not super critical but this could be generated
	p.buildRulesTable(g)

	if p.recover {
		// panic can be used in action code to stop parsing immediately
		// and return the panic as an error.
		defer func() {
			if e := recover(); e != nil {
				if p.debug {
					defer p.out(p.in("panic handler"))
				}
				val = nil
				switch e := e.(type) {
				case error:
					p.addErr(e)
				default:
					p.addErr(fmt.Errorf("%v", e))
				}
				err = p.errs.err()
			}
		}()
	}

	// start rule is rule [0]
	p.read() // advance to first rune
	val, ok := p.parseRule(g.rules[0])
	if !ok {
		if len(*p.errs) == 0 {
			// make sure this doesn't go out silently
			p.addErr(errNoMatch)
		}
		return nil, p.errs.err()
	}
	return val, p.errs.err()
}

func (p *parser) parseRule(rule *rule) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseRule " + rule.name))
	}

	if p.memoize {
		res, ok := p.getMemoized(rule)
		if ok {
			p.restore(res.end)
			return res.v, res.b
		}
	}

	start := p.pt
	p.rstack = append(p.rstack, rule)
	p.pushV()
	val, ok := p.parseExpr(rule.expr)
	p.popV()
	p.rstack = p.rstack[:len(p.rstack)-1]
	if ok && p.debug {
		p.print(strings.Repeat(" ", p.depth)+"MATCH", string(p.sliceFrom(start)))
	}

	if p.memoize {
		p.setMemoized(start, rule, resultTuple{val, ok, p.pt})
	}
	return val, ok
}

func (p *parser) parseExpr(expr interface{}) (interface{}, bool) {
	var pt savepoint
	var ok bool

	if p.memoize {
		res, ok := p.getMemoized(expr)
		if ok {
			p.restore(res.end)
			return res.v, res.b
		}
		pt = p.pt
	}

	p.exprCnt++
	var val interface{}
	switch expr := expr.(type) {
	case *actionExpr:
		val, ok = p.parseActionExpr(expr)
	case *andCodeExpr:
		val, ok = p.parseAndCodeExpr(expr)
	case *andExpr:
		val, ok = p.parseAndExpr(expr)
	case *anyMatcher:
		val, ok = p.parseAnyMatcher(expr)
	case *charClassMatcher:
		val, ok = p.parseCharClassMatcher(expr)
	case *choiceExpr:
		val, ok = p.parseChoiceExpr(expr)
	case *labeledExpr:
		val, ok = p.parseLabeledExpr(expr)
	case *litMatcher:
		val, ok = p.parseLitMatcher(expr)
	case *notCodeExpr:
		val, ok = p.parseNotCodeExpr(expr)
	case *notExpr:
		val, ok = p.parseNotExpr(expr)
	case *oneOrMoreExpr:
		val, ok = p.parseOneOrMoreExpr(expr)
	case *ruleRefExpr:
		val, ok = p.parseRuleRefExpr(expr)
	case *seqExpr:
		val, ok = p.parseSeqExpr(expr)
	case *zeroOrMoreExpr:
		val, ok = p.parseZeroOrMoreExpr(expr)
	case *zeroOrOneExpr:
		val, ok = p.parseZeroOrOneExpr(expr)
	default:
		panic(fmt.Sprintf("unknown expression type %T", expr))
	}
	if p.memoize {
		p.setMemoized(pt, expr, resultTuple{val, ok, p.pt})
	}
	return val, ok
}

func (p *parser) parseActionExpr(act *actionExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseActionExpr"))
	}

	start := p.pt
	val, ok := p.parseExpr(act.expr)
	if ok {
		p.cur.pos = start.position
		p.cur.text = p.sliceFrom(start)
		actVal, err := act.run(p)
		if err != nil {
			p.addErrAt(err, start.position)
		}
		val = actVal
	}
	if ok && p.debug {
		p.print(strings.Repeat(" ", p.depth)+"MATCH", string(p.sliceFrom(start)))
	}
	return val, ok
}

func (p *parser) parseAndCodeExpr(and *andCodeExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseAndCodeExpr"))
	}

	ok, err := and.run(p)
	if err != nil {
		p.addErr(err)
	}
	return nil, ok
}

func (p *parser) parseAndExpr(and *andExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseAndExpr"))
	}

	pt := p.pt
	p.pushV()
	_, ok := p.parseExpr(and.expr)
	p.popV()
	p.restore(pt)
	return nil, ok
}

func (p *parser) parseAnyMatcher(any *anyMatcher) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseAnyMatcher"))
	}

	if p.pt.rn != utf8.RuneError {
		start := p.pt
		p.read()
		return p.sliceFrom(start), true
	}
	return nil, false
}

func (p *parser) parseCharClassMatcher(chr *charClassMatcher) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseCharClassMatcher"))
	}

	cur := p.pt.rn
	// can't match EOF
	if cur == utf8.RuneError {
		return nil, false
	}
	start := p.pt
	if chr.ignoreCase {
		cur = unicode.ToLower(cur)
	}

	// try to match in the list of available chars
	for _, rn := range chr.chars {
		if rn == cur {
			if chr.inverted {
				return nil, false
			}
			p.read()
			return p.sliceFrom(start), true
		}
	}

	// try to match in the list of ranges
	for i := 0; i < len(chr.ranges); i += 2 {
		if cur >= chr.ranges[i] && cur <= chr.ranges[i+1] {
			if chr.inverted {
				return nil, false
			}
			p.read()
			return p.sliceFrom(start), true
		}
	}

	// try to match in the list of Unicode classes
	for _, cl := range chr.classes {
		if unicode.Is(cl, cur) {
			if chr.inverted {
				return nil, false
			}
			p.read()
			return p.sliceFrom(start), true
		}
	}

	if chr.inverted {
		p.read()
		return p.sliceFrom(start), true
	}
	return nil, false
}

func (p *parser) parseChoiceExpr(ch *choiceExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseChoiceExpr"))
	}

	for _, alt := range ch.alternatives {
		p.pushV()
		val, ok := p.parseExpr(alt)
		p.popV()
		if ok {
			return val, ok
		}
	}
	return nil, false
}

func (p *parser) parseLabeledExpr(lab *labeledExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseLabeledExpr"))
	}

	p.pushV()
	val, ok := p.parseExpr(lab.expr)
	p.popV()
	if ok && lab.label != "" {
		m := p.vstack[len(p.vstack)-1]
		m[lab.label] = val
	}
	return val, ok
}

func (p *parser) parseLitMatcher(lit *litMatcher) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseLitMatcher"))
	}

	start := p.pt
	for _, want := range lit.val {
		cur := p.pt.rn
		if lit.ignoreCase {
			cur = unicode.ToLower(cur)
		}
		if cur != want {
			p.restore(start)
			return nil, false
		}
		p.read()
	}
	return p.sliceFrom(start), true
}

func (p *parser) parseNotCodeExpr(not *notCodeExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseNotCodeExpr"))
	}

	ok, err := not.run(p)
	if err != nil {
		p.addErr(err)
	}
	return nil, !ok
}

func (p *parser) parseNotExpr(not *notExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseNotExpr"))
	}

	pt := p.pt
	p.pushV()
	_, ok := p.parseExpr(not.expr)
	p.popV()
	p.restore(pt)
	return nil, !ok
}

func (p *parser) parseOneOrMoreExpr(expr *oneOrMoreExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseOneOrMoreExpr"))
	}

	var vals []interface{}

	for {
		p.pushV()
		val, ok := p.parseExpr(expr.expr)
		p.popV()
		if !ok {
			if len(vals) == 0 {
				// did not match once, no match
				return nil, false
			}
			return vals, true
		}
		vals = append(vals, val)
	}
}

func (p *parser) parseRuleRefExpr(ref *ruleRefExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseRuleRefExpr " + ref.name))
	}

	if ref.name == "" {
		panic(fmt.Sprintf("%s: invalid rule: missing name", ref.pos))
	}

	rule := p.rules[ref.name]
	if rule == nil {
		p.addErr(fmt.Errorf("undefined rule: %s", ref.name))
		return nil, false
	}
	return p.parseRule(rule)
}

func (p *parser) parseSeqExpr(seq *seqExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseSeqExpr"))
	}

	var vals []interface{}

	pt := p.pt
	for _, expr := range seq.exprs {
		val, ok := p.parseExpr(expr)
		if !ok {
			p.restore(pt)
			return nil, false
		}
		vals = append(vals, val)
	}
	return vals, true
}

func (p *parser) parseZeroOrMoreExpr(expr *zeroOrMoreExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseZeroOrMoreExpr"))
	}

	var vals []interface{}

	for {
		p.pushV()
		val, ok := p.parseExpr(expr.expr)
		p.popV()
		if !ok {
			return vals, true
		}
		vals = append(vals, val)
	}
}

func (p *parser) parseZeroOrOneExpr(expr *zeroOrOneExpr) (interface{}, bool) {
	if p.debug {
		defer p.out(p.in("parseZeroOrOneExpr"))
	}

	p.pushV()
	val, _ := p.parseExpr(expr.expr)
	p.popV()
	// whether it matched or not, consider it a match
	return val, true
}

func rangeTable(class string) *unicode.RangeTable {
	if rt, ok := unicode.Categories[class]; ok {
		return rt
	}
	if rt, ok := unicode.Properties[class]; ok {
		return rt
	}
	if rt, ok := unicode.Scripts[class]; ok {
		return rt
	}

	// cannot happen
	panic(fmt.Sprintf("invalid Unicode class: %s", class))
}
