/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
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
						&ruleRefExpr{
							pos:  position{line: 113, col: 81, offset: 2690},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 113, col: 83, offset: 2692},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 87, offset: 2696},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 126, col: 1, offset: 2937},
			expr: &actionExpr{
				pos: position{line: 126, col: 18, offset: 2954},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 126, col: 18, offset: 2954},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 126, col: 23, offset: 2959},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Qualifier",
			pos:  position{line: 131, col: 1, offset: 3062},
			expr: &actionExpr{
				pos: position{line: 131, col: 14, offset: 3075},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 131, col: 15, offset: 3076},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 131, col: 15, offset: 3076},
							val:        "public",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 131, col: 24, offset: 3085},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 131, col: 34, offset: 3095},
							val:        "password",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 135, col: 1, offset: 3140},
			expr: &actionExpr{
				pos: position{line: 135, col: 12, offset: 3151},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 135, col: 12, offset: 3151},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 135, col: 12, offset: 3151},
							label: "Sender",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 19, offset: 3158},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 33, offset: 3172},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 135, col: 35, offset: 3174},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 40, offset: 3179},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 135, col: 42, offset: 3181},
							label: "Recipient",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 52, offset: 3191},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 66, offset: 3205},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 135, col: 68, offset: 3207},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 135, col: 72, offset: 3211},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 135, col: 74, offset: 3213},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 135, col: 84, offset: 3223},
								name: "MessageConstants",
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 146, col: 1, offset: 3412},
			expr: &actionExpr{
				pos: position{line: 146, col: 21, offset: 3432},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 146, col: 21, offset: 3432},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 146, col: 38, offset: 3449},
						expr: &choiceExpr{
							pos: position{line: 146, col: 39, offset: 3450},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 146, col: 39, offset: 3450},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 146, col: 55, offset: 3466},
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
			pos:  position{line: 156, col: 1, offset: 3630},
			expr: &actionExpr{
				pos: position{line: 156, col: 15, offset: 3644},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 156, col: 15, offset: 3644},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 156, col: 15, offset: 3644},
							expr: &ruleRefExpr{
								pos:  position{line: 156, col: 15, offset: 3644},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 156, col: 24, offset: 3653},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 156, col: 36, offset: 3665},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 156, col: 36, offset: 3665},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 42, offset: 3671},
										name: "Generates",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 52, offset: 3681},
										name: "Leaks",
									},
									&ruleRefExpr{
										pos:  position{line: 156, col: 58, offset: 3687},
										name: "Assignment",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 156, col: 70, offset: 3699},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 156, col: 72, offset: 3701},
							expr: &ruleRefExpr{
								pos:  position{line: 156, col: 72, offset: 3701},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 160, col: 1, offset: 3739},
			expr: &actionExpr{
				pos: position{line: 160, col: 10, offset: 3748},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 160, col: 10, offset: 3748},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 160, col: 10, offset: 3748},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 160, col: 18, offset: 3756},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 160, col: 20, offset: 3758},
							label: "Qualifier",
							expr: &ruleRefExpr{
								pos:  position{line: 160, col: 30, offset: 3768},
								name: "Qualifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 160, col: 40, offset: 3778},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 160, col: 42, offset: 3780},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 160, col: 52, offset: 3790},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 168, col: 1, offset: 3920},
			expr: &actionExpr{
				pos: position{line: 168, col: 14, offset: 3933},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 168, col: 14, offset: 3933},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 168, col: 14, offset: 3933},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 168, col: 26, offset: 3945},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 168, col: 28, offset: 3947},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 168, col: 38, offset: 3957},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Leaks",
			pos:  position{line: 176, col: 1, offset: 4075},
			expr: &actionExpr{
				pos: position{line: 176, col: 10, offset: 4084},
				run: (*parser).callonLeaks1,
				expr: &seqExpr{
					pos: position{line: 176, col: 10, offset: 4084},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 176, col: 10, offset: 4084},
							val:        "leaks",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 176, col: 18, offset: 4092},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 176, col: 20, offset: 4094},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 176, col: 30, offset: 4104},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 184, col: 1, offset: 4218},
			expr: &actionExpr{
				pos: position{line: 184, col: 15, offset: 4232},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 184, col: 15, offset: 4232},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 184, col: 15, offset: 4232},
							label: "Left",
							expr: &ruleRefExpr{
								pos:  position{line: 184, col: 20, offset: 4237},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 184, col: 30, offset: 4247},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 184, col: 32, offset: 4249},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 184, col: 36, offset: 4253},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 184, col: 38, offset: 4255},
							label: "Right",
							expr: &ruleRefExpr{
								pos:  position{line: 184, col: 44, offset: 4261},
								name: "Value",
							},
						},
					},
				},
			},
		},
		{
			name: "Constant",
			pos:  position{line: 205, col: 1, offset: 4697},
			expr: &actionExpr{
				pos: position{line: 205, col: 13, offset: 4709},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 205, col: 13, offset: 4709},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 205, col: 13, offset: 4709},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 205, col: 19, offset: 4715},
								name: "Identifier",
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 205, col: 30, offset: 4726},
							expr: &seqExpr{
								pos: position{line: 205, col: 31, offset: 4727},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 205, col: 31, offset: 4727},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 205, col: 33, offset: 4729},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 205, col: 37, offset: 4733},
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
			pos:  position{line: 214, col: 1, offset: 4837},
			expr: &actionExpr{
				pos: position{line: 214, col: 14, offset: 4850},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 214, col: 14, offset: 4850},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 214, col: 24, offset: 4860},
						expr: &ruleRefExpr{
							pos:  position{line: 214, col: 24, offset: 4860},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "Phase",
			pos:  position{line: 226, col: 1, offset: 5103},
			expr: &actionExpr{
				pos: position{line: 226, col: 10, offset: 5112},
				run: (*parser).callonPhase1,
				expr: &seqExpr{
					pos: position{line: 226, col: 10, offset: 5112},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 226, col: 10, offset: 5112},
							val:        "phase",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 18, offset: 5120},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 226, col: 20, offset: 5122},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 24, offset: 5126},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 226, col: 26, offset: 5128},
							label: "Number",
							expr: &oneOrMoreExpr{
								pos: position{line: 226, col: 33, offset: 5135},
								expr: &charClassMatcher{
									pos:        position{line: 226, col: 33, offset: 5135},
									val:        "[0-9]",
									ranges:     []rune{'0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 40, offset: 5142},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 226, col: 42, offset: 5144},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 46, offset: 5148},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 239, col: 1, offset: 5370},
			expr: &actionExpr{
				pos: position{line: 239, col: 20, offset: 5389},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 239, col: 20, offset: 5389},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 239, col: 20, offset: 5389},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 239, col: 24, offset: 5393},
							label: "Guarded",
							expr: &ruleRefExpr{
								pos:  position{line: 239, col: 32, offset: 5401},
								name: "Identifier",
							},
						},
						&litMatcher{
							pos:        position{line: 239, col: 43, offset: 5412},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 239, col: 47, offset: 5416},
							expr: &seqExpr{
								pos: position{line: 239, col: 48, offset: 5417},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 239, col: 48, offset: 5417},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 239, col: 50, offset: 5419},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 239, col: 54, offset: 5423},
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
			pos:  position{line: 250, col: 1, offset: 5593},
			expr: &actionExpr{
				pos: position{line: 250, col: 14, offset: 5606},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 250, col: 14, offset: 5606},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 250, col: 14, offset: 5606},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 250, col: 19, offset: 5611},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 250, col: 33, offset: 5625},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 250, col: 37, offset: 5629},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 250, col: 39, offset: 5631},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 250, col: 49, offset: 5641},
								expr: &ruleRefExpr{
									pos:  position{line: 250, col: 49, offset: 5641},
									name: "Value",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 250, col: 56, offset: 5648},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 250, col: 58, offset: 5650},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 250, col: 62, offset: 5654},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 250, col: 68, offset: 5660},
								expr: &litMatcher{
									pos:        position{line: 250, col: 68, offset: 5660},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 250, col: 73, offset: 5665},
							expr: &seqExpr{
								pos: position{line: 250, col: 74, offset: 5666},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 250, col: 74, offset: 5666},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 250, col: 76, offset: 5668},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 250, col: 80, offset: 5672},
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
			pos:  position{line: 266, col: 1, offset: 5938},
			expr: &actionExpr{
				pos: position{line: 266, col: 18, offset: 5955},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 266, col: 18, offset: 5955},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 266, col: 23, offset: 5960},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Equation",
			pos:  position{line: 270, col: 1, offset: 6020},
			expr: &actionExpr{
				pos: position{line: 270, col: 13, offset: 6032},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 270, col: 13, offset: 6032},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 270, col: 13, offset: 6032},
							label: "First",
							expr: &ruleRefExpr{
								pos:  position{line: 270, col: 19, offset: 6038},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 270, col: 29, offset: 6048},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 270, col: 29, offset: 6048},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 270, col: 31, offset: 6050},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 270, col: 35, offset: 6054},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 270, col: 38, offset: 6057},
							label: "Second",
							expr: &ruleRefExpr{
								pos:  position{line: 270, col: 45, offset: 6064},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Value",
			pos:  position{line: 282, col: 1, offset: 6213},
			expr: &choiceExpr{
				pos: position{line: 282, col: 10, offset: 6222},
				alternatives: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 282, col: 10, offset: 6222},
						name: "Primitive",
					},
					&ruleRefExpr{
						pos:  position{line: 282, col: 20, offset: 6232},
						name: "Equation",
					},
					&ruleRefExpr{
						pos:  position{line: 282, col: 29, offset: 6241},
						name: "Constant",
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 284, col: 1, offset: 6252},
			expr: &actionExpr{
				pos: position{line: 284, col: 12, offset: 6263},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 284, col: 12, offset: 6263},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 284, col: 12, offset: 6263},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 22, offset: 6273},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 284, col: 24, offset: 6275},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 28, offset: 6279},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 284, col: 30, offset: 6281},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 284, col: 39, offset: 6290},
								expr: &ruleRefExpr{
									pos:  position{line: 284, col: 39, offset: 6290},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 284, col: 47, offset: 6298},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 284, col: 51, offset: 6302},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 288, col: 1, offset: 6330},
			expr: &actionExpr{
				pos: position{line: 288, col: 10, offset: 6339},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 288, col: 10, offset: 6339},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 288, col: 10, offset: 6339},
							expr: &ruleRefExpr{
								pos:  position{line: 288, col: 10, offset: 6339},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 288, col: 19, offset: 6348},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 288, col: 26, offset: 6355},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 288, col: 26, offset: 6355},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 47, offset: 6376},
										name: "QueryAuthentication",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 67, offset: 6396},
										name: "QueryFreshness",
									},
									&ruleRefExpr{
										pos:  position{line: 288, col: 82, offset: 6411},
										name: "QueryUnlinkability",
									},
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 288, col: 102, offset: 6431},
							expr: &ruleRefExpr{
								pos:  position{line: 288, col: 102, offset: 6431},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 292, col: 1, offset: 6465},
			expr: &actionExpr{
				pos: position{line: 292, col: 25, offset: 6489},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 292, col: 25, offset: 6489},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 292, col: 25, offset: 6489},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 44, offset: 6508},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 292, col: 46, offset: 6510},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 292, col: 52, offset: 6516},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 61, offset: 6525},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 292, col: 63, offset: 6527},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 292, col: 71, offset: 6535},
								expr: &ruleRefExpr{
									pos:  position{line: 292, col: 71, offset: 6535},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 292, col: 85, offset: 6549},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 304, col: 1, offset: 6765},
			expr: &actionExpr{
				pos: position{line: 304, col: 24, offset: 6788},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 304, col: 24, offset: 6788},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 304, col: 24, offset: 6788},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 42, offset: 6806},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 304, col: 44, offset: 6808},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 304, col: 52, offset: 6816},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 60, offset: 6824},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 304, col: 62, offset: 6826},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 304, col: 70, offset: 6834},
								expr: &ruleRefExpr{
									pos:  position{line: 304, col: 70, offset: 6834},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 304, col: 84, offset: 6848},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryFreshness",
			pos:  position{line: 316, col: 1, offset: 7057},
			expr: &actionExpr{
				pos: position{line: 316, col: 19, offset: 7075},
				run: (*parser).callonQueryFreshness1,
				expr: &seqExpr{
					pos: position{line: 316, col: 19, offset: 7075},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 316, col: 19, offset: 7075},
							val:        "freshness?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 32, offset: 7088},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 316, col: 34, offset: 7090},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 316, col: 40, offset: 7096},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 49, offset: 7105},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 316, col: 51, offset: 7107},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 316, col: 59, offset: 7115},
								expr: &ruleRefExpr{
									pos:  position{line: 316, col: 59, offset: 7115},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 316, col: 73, offset: 7129},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryUnlinkability",
			pos:  position{line: 328, col: 1, offset: 7339},
			expr: &actionExpr{
				pos: position{line: 328, col: 23, offset: 7361},
				run: (*parser).callonQueryUnlinkability1,
				expr: &seqExpr{
					pos: position{line: 328, col: 23, offset: 7361},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 328, col: 23, offset: 7361},
							val:        "unlinkability?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 40, offset: 7378},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 328, col: 42, offset: 7380},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 328, col: 52, offset: 7390},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 62, offset: 7400},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 328, col: 64, offset: 7402},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 328, col: 72, offset: 7410},
								expr: &ruleRefExpr{
									pos:  position{line: 328, col: 72, offset: 7410},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 328, col: 86, offset: 7424},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOptions",
			pos:  position{line: 340, col: 1, offset: 7626},
			expr: &actionExpr{
				pos: position{line: 340, col: 17, offset: 7642},
				run: (*parser).callonQueryOptions1,
				expr: &seqExpr{
					pos: position{line: 340, col: 17, offset: 7642},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 340, col: 17, offset: 7642},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 340, col: 21, offset: 7646},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 340, col: 23, offset: 7648},
							label: "Options",
							expr: &zeroOrMoreExpr{
								pos: position{line: 340, col: 32, offset: 7657},
								expr: &ruleRefExpr{
									pos:  position{line: 340, col: 32, offset: 7657},
									name: "QueryOption",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 340, col: 46, offset: 7671},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 340, col: 50, offset: 7675},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOption",
			pos:  position{line: 347, col: 1, offset: 7812},
			expr: &actionExpr{
				pos: position{line: 347, col: 16, offset: 7827},
				run: (*parser).callonQueryOption1,
				expr: &seqExpr{
					pos: position{line: 347, col: 16, offset: 7827},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 347, col: 16, offset: 7827},
							label: "OptionName",
							expr: &ruleRefExpr{
								pos:  position{line: 347, col: 27, offset: 7838},
								name: "Identifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 38, offset: 7849},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 347, col: 40, offset: 7851},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 44, offset: 7855},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 347, col: 46, offset: 7857},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 347, col: 54, offset: 7865},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 62, offset: 7873},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 347, col: 64, offset: 7875},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 68, offset: 7879},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Identifier",
			pos:  position{line: 354, col: 1, offset: 7982},
			expr: &actionExpr{
				pos: position{line: 354, col: 15, offset: 7996},
				run: (*parser).callonIdentifier1,
				expr: &labeledExpr{
					pos:   position{line: 354, col: 15, offset: 7996},
					label: "Identifier",
					expr: &oneOrMoreExpr{
						pos: position{line: 354, col: 26, offset: 8007},
						expr: &charClassMatcher{
							pos:        position{line: 354, col: 26, offset: 8007},
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
			pos:  position{line: 359, col: 1, offset: 8097},
			expr: &seqExpr{
				pos: position{line: 359, col: 12, offset: 8108},
				exprs: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 359, col: 12, offset: 8108},
						name: "_",
					},
					&litMatcher{
						pos:        position{line: 359, col: 14, offset: 8110},
						val:        "//",
						ignoreCase: false,
					},
					&zeroOrMoreExpr{
						pos: position{line: 359, col: 19, offset: 8115},
						expr: &charClassMatcher{
							pos:        position{line: 359, col: 19, offset: 8115},
							val:        "[^\\n]",
							chars:      []rune{'\n'},
							ignoreCase: false,
							inverted:   true,
						},
					},
					&ruleRefExpr{
						pos:  position{line: 359, col: 26, offset: 8122},
						name: "_",
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 361, col: 1, offset: 8125},
			expr: &zeroOrMoreExpr{
				pos: position{line: 361, col: 19, offset: 8143},
				expr: &charClassMatcher{
					pos:        position{line: 361, col: 19, offset: 8143},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 363, col: 1, offset: 8155},
			expr: &notExpr{
				pos: position{line: 363, col: 8, offset: 8162},
				expr: &anyMatcher{
					line: 363, col: 9, offset: 8163,
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
		Kind:  "assignment",
		Left:  consts,
		Right: Right.(Value),
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
