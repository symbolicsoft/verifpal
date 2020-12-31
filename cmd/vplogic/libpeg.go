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
	"knows", "generates", "leaks",
	"phase", "public", "private", "password",
	"confidentiality", "authentication",
	"freshness", "unlinkability", "precondition",
	"ringsign", "ringsignverif",
	"primitive", "pw_hash", "hash", "hkdf",
	"aead_enc", "aead_dec", "enc", "dec",
	"mac", "assert", "sign", "signverif",
	"pke_enc", "pke_dec", "shamir_split",
	"shamir_join", "concat", "split",
	"g", "nil",
}

var libpegUnnamedCounter = 0

func libpegCheckIfReserved(s string) error {
	found := false
	switch {
	case strInSlice(s, libpegReserved):
		found = true
	case strings.HasPrefix(s, "attacker"):
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
			pos:  position{line: 78, col: 1, offset: 1712},
			expr: &actionExpr{
				pos: position{line: 78, col: 10, offset: 1721},
				run: (*parser).callonModel1,
				expr: &seqExpr{
					pos: position{line: 78, col: 10, offset: 1721},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 78, col: 10, offset: 1721},
							expr: &ruleRefExpr{
								pos:  position{line: 78, col: 10, offset: 1721},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 78, col: 19, offset: 1730},
							label: "Attacker",
							expr: &zeroOrOneExpr{
								pos: position{line: 78, col: 28, offset: 1739},
								expr: &ruleRefExpr{
									pos:  position{line: 78, col: 28, offset: 1739},
									name: "Attacker",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 78, col: 38, offset: 1749},
							label: "Blocks",
							expr: &zeroOrOneExpr{
								pos: position{line: 78, col: 45, offset: 1756},
								expr: &oneOrMoreExpr{
									pos: position{line: 78, col: 46, offset: 1757},
									expr: &ruleRefExpr{
										pos:  position{line: 78, col: 46, offset: 1757},
										name: "Block",
									},
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 78, col: 55, offset: 1766},
							label: "Queries",
							expr: &zeroOrOneExpr{
								pos: position{line: 78, col: 63, offset: 1774},
								expr: &ruleRefExpr{
									pos:  position{line: 78, col: 63, offset: 1774},
									name: "Queries",
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 78, col: 72, offset: 1783},
							expr: &ruleRefExpr{
								pos:  position{line: 78, col: 72, offset: 1783},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 78, col: 81, offset: 1792},
							name: "EOF",
						},
					},
				},
			},
		},
		{
			name: "Attacker",
			pos:  position{line: 100, col: 1, offset: 2344},
			expr: &actionExpr{
				pos: position{line: 100, col: 13, offset: 2356},
				run: (*parser).callonAttacker1,
				expr: &seqExpr{
					pos: position{line: 100, col: 13, offset: 2356},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 100, col: 13, offset: 2356},
							val:        "attacker",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 24, offset: 2367},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 100, col: 26, offset: 2369},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 30, offset: 2373},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 100, col: 32, offset: 2375},
							label: "Type",
							expr: &zeroOrOneExpr{
								pos: position{line: 100, col: 37, offset: 2380},
								expr: &ruleRefExpr{
									pos:  position{line: 100, col: 37, offset: 2380},
									name: "AttackerType",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 51, offset: 2394},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 100, col: 53, offset: 2396},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 57, offset: 2400},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "AttackerType",
			pos:  position{line: 107, col: 1, offset: 2524},
			expr: &actionExpr{
				pos: position{line: 107, col: 17, offset: 2540},
				run: (*parser).callonAttackerType1,
				expr: &choiceExpr{
					pos: position{line: 107, col: 18, offset: 2541},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 107, col: 18, offset: 2541},
							val:        "active",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 107, col: 27, offset: 2550},
							val:        "passive",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Block",
			pos:  position{line: 111, col: 1, offset: 2594},
			expr: &actionExpr{
				pos: position{line: 111, col: 10, offset: 2603},
				run: (*parser).callonBlock1,
				expr: &seqExpr{
					pos: position{line: 111, col: 10, offset: 2603},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 111, col: 10, offset: 2603},
							expr: &ruleRefExpr{
								pos:  position{line: 111, col: 10, offset: 2603},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 111, col: 19, offset: 2612},
							label: "Block",
							expr: &choiceExpr{
								pos: position{line: 111, col: 26, offset: 2619},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 111, col: 26, offset: 2619},
										name: "Phase",
									},
									&ruleRefExpr{
										pos:  position{line: 111, col: 32, offset: 2625},
										name: "Principal",
									},
									&ruleRefExpr{
										pos:  position{line: 111, col: 42, offset: 2635},
										name: "Message",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 111, col: 51, offset: 2644},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 111, col: 53, offset: 2646},
							expr: &ruleRefExpr{
								pos:  position{line: 111, col: 53, offset: 2646},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Principal",
			pos:  position{line: 115, col: 1, offset: 2679},
			expr: &actionExpr{
				pos: position{line: 115, col: 14, offset: 2692},
				run: (*parser).callonPrincipal1,
				expr: &seqExpr{
					pos: position{line: 115, col: 14, offset: 2692},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 115, col: 14, offset: 2692},
							val:        "principal",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 115, col: 26, offset: 2704},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 115, col: 28, offset: 2706},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 115, col: 33, offset: 2711},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 115, col: 47, offset: 2725},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 115, col: 49, offset: 2727},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 115, col: 53, offset: 2731},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 115, col: 55, offset: 2733},
							expr: &ruleRefExpr{
								pos:  position{line: 115, col: 55, offset: 2733},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 115, col: 64, offset: 2742},
							label: "Expressions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 115, col: 77, offset: 2755},
								expr: &ruleRefExpr{
									pos:  position{line: 115, col: 77, offset: 2755},
									name: "Expression",
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 115, col: 90, offset: 2768},
							expr: &ruleRefExpr{
								pos:  position{line: 115, col: 90, offset: 2768},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 115, col: 99, offset: 2777},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 115, col: 101, offset: 2779},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 115, col: 105, offset: 2783},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 130, col: 1, offset: 3078},
			expr: &actionExpr{
				pos: position{line: 130, col: 18, offset: 3095},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 130, col: 18, offset: 3095},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 130, col: 23, offset: 3100},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Qualifier",
			pos:  position{line: 135, col: 1, offset: 3203},
			expr: &actionExpr{
				pos: position{line: 135, col: 14, offset: 3216},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 135, col: 15, offset: 3217},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 135, col: 15, offset: 3217},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 135, col: 25, offset: 3227},
							val:        "public",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 135, col: 34, offset: 3236},
							val:        "password",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 146, col: 1, offset: 3424},
			expr: &actionExpr{
				pos: position{line: 146, col: 12, offset: 3435},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 146, col: 12, offset: 3435},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 146, col: 12, offset: 3435},
							label: "Sender",
							expr: &zeroOrOneExpr{
								pos: position{line: 146, col: 19, offset: 3442},
								expr: &ruleRefExpr{
									pos:  position{line: 146, col: 19, offset: 3442},
									name: "PrincipalName",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 146, col: 34, offset: 3457},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 146, col: 36, offset: 3459},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 146, col: 41, offset: 3464},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 146, col: 43, offset: 3466},
							label: "Recipient",
							expr: &zeroOrOneExpr{
								pos: position{line: 146, col: 53, offset: 3476},
								expr: &ruleRefExpr{
									pos:  position{line: 146, col: 53, offset: 3476},
									name: "PrincipalName",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 146, col: 68, offset: 3491},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 146, col: 70, offset: 3493},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 146, col: 74, offset: 3497},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 146, col: 76, offset: 3499},
							label: "Constants",
							expr: &zeroOrOneExpr{
								pos: position{line: 146, col: 86, offset: 3509},
								expr: &ruleRefExpr{
									pos:  position{line: 146, col: 86, offset: 3509},
									name: "MessageConstants",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 167, col: 1, offset: 4062},
			expr: &actionExpr{
				pos: position{line: 167, col: 21, offset: 4082},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 167, col: 21, offset: 4082},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 167, col: 38, offset: 4099},
						expr: &choiceExpr{
							pos: position{line: 167, col: 39, offset: 4100},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 167, col: 39, offset: 4100},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 167, col: 55, offset: 4116},
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
			pos:  position{line: 177, col: 1, offset: 4280},
			expr: &actionExpr{
				pos: position{line: 177, col: 15, offset: 4294},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 177, col: 15, offset: 4294},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 177, col: 15, offset: 4294},
							expr: &ruleRefExpr{
								pos:  position{line: 177, col: 15, offset: 4294},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 177, col: 24, offset: 4303},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 177, col: 36, offset: 4315},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 177, col: 36, offset: 4315},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 177, col: 42, offset: 4321},
										name: "Generates",
									},
									&ruleRefExpr{
										pos:  position{line: 177, col: 52, offset: 4331},
										name: "Leaks",
									},
									&ruleRefExpr{
										pos:  position{line: 177, col: 58, offset: 4337},
										name: "Assignment",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 177, col: 70, offset: 4349},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 177, col: 72, offset: 4351},
							expr: &ruleRefExpr{
								pos:  position{line: 177, col: 72, offset: 4351},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 181, col: 1, offset: 4389},
			expr: &actionExpr{
				pos: position{line: 181, col: 10, offset: 4398},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 181, col: 10, offset: 4398},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 181, col: 10, offset: 4398},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 181, col: 18, offset: 4406},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 181, col: 20, offset: 4408},
							label: "Qualifier",
							expr: &zeroOrOneExpr{
								pos: position{line: 181, col: 30, offset: 4418},
								expr: &ruleRefExpr{
									pos:  position{line: 181, col: 30, offset: 4418},
									name: "Qualifier",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 181, col: 41, offset: 4429},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 181, col: 43, offset: 4431},
							label: "Constants",
							expr: &zeroOrOneExpr{
								pos: position{line: 181, col: 53, offset: 4441},
								expr: &ruleRefExpr{
									pos:  position{line: 181, col: 53, offset: 4441},
									name: "Constants",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 195, col: 1, offset: 4792},
			expr: &actionExpr{
				pos: position{line: 195, col: 14, offset: 4805},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 195, col: 14, offset: 4805},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 195, col: 14, offset: 4805},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 195, col: 26, offset: 4817},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 195, col: 28, offset: 4819},
							label: "Constants",
							expr: &zeroOrOneExpr{
								pos: position{line: 195, col: 38, offset: 4829},
								expr: &ruleRefExpr{
									pos:  position{line: 195, col: 38, offset: 4829},
									name: "Constants",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Leaks",
			pos:  position{line: 206, col: 1, offset: 5073},
			expr: &actionExpr{
				pos: position{line: 206, col: 10, offset: 5082},
				run: (*parser).callonLeaks1,
				expr: &seqExpr{
					pos: position{line: 206, col: 10, offset: 5082},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 206, col: 10, offset: 5082},
							val:        "leaks",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 206, col: 18, offset: 5090},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 206, col: 20, offset: 5092},
							label: "Constants",
							expr: &zeroOrOneExpr{
								pos: position{line: 206, col: 30, offset: 5102},
								expr: &ruleRefExpr{
									pos:  position{line: 206, col: 30, offset: 5102},
									name: "Constants",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 217, col: 1, offset: 5338},
			expr: &actionExpr{
				pos: position{line: 217, col: 15, offset: 5352},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 217, col: 15, offset: 5352},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 217, col: 15, offset: 5352},
							label: "Left",
							expr: &zeroOrOneExpr{
								pos: position{line: 217, col: 20, offset: 5357},
								expr: &ruleRefExpr{
									pos:  position{line: 217, col: 20, offset: 5357},
									name: "Constants",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 217, col: 31, offset: 5368},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 217, col: 33, offset: 5370},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 217, col: 37, offset: 5374},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 217, col: 39, offset: 5376},
							label: "Right",
							expr: &zeroOrOneExpr{
								pos: position{line: 217, col: 45, offset: 5382},
								expr: &ruleRefExpr{
									pos:  position{line: 217, col: 45, offset: 5382},
									name: "Value",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Constant",
			pos:  position{line: 234, col: 1, offset: 5746},
			expr: &actionExpr{
				pos: position{line: 234, col: 13, offset: 5758},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 234, col: 13, offset: 5758},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 234, col: 13, offset: 5758},
							label: "Const",
							expr: &ruleRefExpr{
								pos:  position{line: 234, col: 19, offset: 5764},
								name: "Identifier",
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 234, col: 30, offset: 5775},
							expr: &seqExpr{
								pos: position{line: 234, col: 31, offset: 5776},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 234, col: 31, offset: 5776},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 234, col: 33, offset: 5778},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 234, col: 37, offset: 5782},
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
			pos:  position{line: 251, col: 1, offset: 6085},
			expr: &actionExpr{
				pos: position{line: 251, col: 14, offset: 6098},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 251, col: 14, offset: 6098},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 251, col: 24, offset: 6108},
						expr: &ruleRefExpr{
							pos:  position{line: 251, col: 24, offset: 6108},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "Phase",
			pos:  position{line: 263, col: 1, offset: 6351},
			expr: &actionExpr{
				pos: position{line: 263, col: 10, offset: 6360},
				run: (*parser).callonPhase1,
				expr: &seqExpr{
					pos: position{line: 263, col: 10, offset: 6360},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 263, col: 10, offset: 6360},
							val:        "phase",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 18, offset: 6368},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 263, col: 20, offset: 6370},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 24, offset: 6374},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 263, col: 26, offset: 6376},
							label: "Number",
							expr: &oneOrMoreExpr{
								pos: position{line: 263, col: 33, offset: 6383},
								expr: &charClassMatcher{
									pos:        position{line: 263, col: 33, offset: 6383},
									val:        "[0-9]",
									ranges:     []rune{'0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 40, offset: 6390},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 263, col: 42, offset: 6392},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 46, offset: 6396},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 276, col: 1, offset: 6618},
			expr: &actionExpr{
				pos: position{line: 276, col: 20, offset: 6637},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 276, col: 20, offset: 6637},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 276, col: 20, offset: 6637},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 276, col: 24, offset: 6641},
							label: "Guarded",
							expr: &ruleRefExpr{
								pos:  position{line: 276, col: 32, offset: 6649},
								name: "Constant",
							},
						},
						&litMatcher{
							pos:        position{line: 276, col: 41, offset: 6658},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 276, col: 45, offset: 6662},
							expr: &seqExpr{
								pos: position{line: 276, col: 46, offset: 6663},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 276, col: 46, offset: 6663},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 276, col: 48, offset: 6665},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 276, col: 52, offset: 6669},
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
			pos:  position{line: 289, col: 1, offset: 6888},
			expr: &actionExpr{
				pos: position{line: 289, col: 14, offset: 6901},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 289, col: 14, offset: 6901},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 289, col: 14, offset: 6901},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 289, col: 19, offset: 6906},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 289, col: 33, offset: 6920},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 289, col: 37, offset: 6924},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 289, col: 39, offset: 6926},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 289, col: 49, offset: 6936},
								expr: &ruleRefExpr{
									pos:  position{line: 289, col: 49, offset: 6936},
									name: "Value",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 289, col: 56, offset: 6943},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 289, col: 58, offset: 6945},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 289, col: 62, offset: 6949},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 289, col: 68, offset: 6955},
								expr: &litMatcher{
									pos:        position{line: 289, col: 68, offset: 6955},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 289, col: 73, offset: 6960},
							expr: &seqExpr{
								pos: position{line: 289, col: 74, offset: 6961},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 289, col: 74, offset: 6961},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 289, col: 76, offset: 6963},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 289, col: 80, offset: 6967},
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
			pos:  position{line: 306, col: 1, offset: 7283},
			expr: &actionExpr{
				pos: position{line: 306, col: 18, offset: 7300},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 306, col: 18, offset: 7300},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 306, col: 23, offset: 7305},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Equation",
			pos:  position{line: 310, col: 1, offset: 7365},
			expr: &actionExpr{
				pos: position{line: 310, col: 13, offset: 7377},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 310, col: 13, offset: 7377},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 310, col: 13, offset: 7377},
							label: "First",
							expr: &ruleRefExpr{
								pos:  position{line: 310, col: 19, offset: 7383},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 310, col: 29, offset: 7393},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 310, col: 29, offset: 7393},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 310, col: 31, offset: 7395},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 310, col: 35, offset: 7399},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 310, col: 38, offset: 7402},
							label: "Second",
							expr: &ruleRefExpr{
								pos:  position{line: 310, col: 45, offset: 7409},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Value",
			pos:  position{line: 322, col: 1, offset: 7565},
			expr: &choiceExpr{
				pos: position{line: 322, col: 10, offset: 7574},
				alternatives: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 322, col: 10, offset: 7574},
						name: "Primitive",
					},
					&ruleRefExpr{
						pos:  position{line: 322, col: 20, offset: 7584},
						name: "Equation",
					},
					&ruleRefExpr{
						pos:  position{line: 322, col: 29, offset: 7593},
						name: "Constant",
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 324, col: 1, offset: 7604},
			expr: &actionExpr{
				pos: position{line: 324, col: 12, offset: 7615},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 324, col: 12, offset: 7615},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 324, col: 12, offset: 7615},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 324, col: 22, offset: 7625},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 324, col: 24, offset: 7627},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 324, col: 28, offset: 7631},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 324, col: 30, offset: 7633},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 324, col: 39, offset: 7642},
								expr: &ruleRefExpr{
									pos:  position{line: 324, col: 39, offset: 7642},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 324, col: 47, offset: 7650},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 324, col: 51, offset: 7654},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 328, col: 1, offset: 7682},
			expr: &actionExpr{
				pos: position{line: 328, col: 10, offset: 7691},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 328, col: 10, offset: 7691},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 328, col: 10, offset: 7691},
							expr: &ruleRefExpr{
								pos:  position{line: 328, col: 10, offset: 7691},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 328, col: 19, offset: 7700},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 328, col: 26, offset: 7707},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 328, col: 26, offset: 7707},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 328, col: 47, offset: 7728},
										name: "QueryAuthentication",
									},
									&ruleRefExpr{
										pos:  position{line: 328, col: 67, offset: 7748},
										name: "QueryFreshness",
									},
									&ruleRefExpr{
										pos:  position{line: 328, col: 82, offset: 7763},
										name: "QueryUnlinkability",
									},
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 328, col: 102, offset: 7783},
							expr: &ruleRefExpr{
								pos:  position{line: 328, col: 102, offset: 7783},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 332, col: 1, offset: 7817},
			expr: &actionExpr{
				pos: position{line: 332, col: 25, offset: 7841},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 332, col: 25, offset: 7841},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 332, col: 25, offset: 7841},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 332, col: 44, offset: 7860},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 332, col: 46, offset: 7862},
							label: "Const",
							expr: &zeroOrOneExpr{
								pos: position{line: 332, col: 52, offset: 7868},
								expr: &ruleRefExpr{
									pos:  position{line: 332, col: 52, offset: 7868},
									name: "Constant",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 332, col: 62, offset: 7878},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 332, col: 64, offset: 7880},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 332, col: 72, offset: 7888},
								expr: &ruleRefExpr{
									pos:  position{line: 332, col: 72, offset: 7888},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 332, col: 86, offset: 7902},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 347, col: 1, offset: 8232},
			expr: &actionExpr{
				pos: position{line: 347, col: 24, offset: 8255},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 347, col: 24, offset: 8255},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 347, col: 24, offset: 8255},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 42, offset: 8273},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 347, col: 44, offset: 8275},
							label: "Message",
							expr: &zeroOrOneExpr{
								pos: position{line: 347, col: 52, offset: 8283},
								expr: &ruleRefExpr{
									pos:  position{line: 347, col: 52, offset: 8283},
									name: "Message",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 61, offset: 8292},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 347, col: 63, offset: 8294},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 347, col: 71, offset: 8302},
								expr: &ruleRefExpr{
									pos:  position{line: 347, col: 71, offset: 8302},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 347, col: 85, offset: 8316},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryFreshness",
			pos:  position{line: 362, col: 1, offset: 8639},
			expr: &actionExpr{
				pos: position{line: 362, col: 19, offset: 8657},
				run: (*parser).callonQueryFreshness1,
				expr: &seqExpr{
					pos: position{line: 362, col: 19, offset: 8657},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 362, col: 19, offset: 8657},
							val:        "freshness?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 362, col: 32, offset: 8670},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 362, col: 34, offset: 8672},
							label: "Const",
							expr: &zeroOrOneExpr{
								pos: position{line: 362, col: 40, offset: 8678},
								expr: &ruleRefExpr{
									pos:  position{line: 362, col: 40, offset: 8678},
									name: "Constant",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 362, col: 50, offset: 8688},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 362, col: 52, offset: 8690},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 362, col: 60, offset: 8698},
								expr: &ruleRefExpr{
									pos:  position{line: 362, col: 60, offset: 8698},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 362, col: 74, offset: 8712},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryUnlinkability",
			pos:  position{line: 377, col: 1, offset: 9030},
			expr: &actionExpr{
				pos: position{line: 377, col: 23, offset: 9052},
				run: (*parser).callonQueryUnlinkability1,
				expr: &seqExpr{
					pos: position{line: 377, col: 23, offset: 9052},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 377, col: 23, offset: 9052},
							val:        "unlinkability?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 377, col: 40, offset: 9069},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 377, col: 42, offset: 9071},
							label: "Consts",
							expr: &zeroOrOneExpr{
								pos: position{line: 377, col: 49, offset: 9078},
								expr: &ruleRefExpr{
									pos:  position{line: 377, col: 49, offset: 9078},
									name: "Constants",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 377, col: 60, offset: 9089},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 377, col: 62, offset: 9091},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 377, col: 70, offset: 9099},
								expr: &ruleRefExpr{
									pos:  position{line: 377, col: 70, offset: 9099},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 377, col: 84, offset: 9113},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOptions",
			pos:  position{line: 392, col: 1, offset: 9426},
			expr: &actionExpr{
				pos: position{line: 392, col: 17, offset: 9442},
				run: (*parser).callonQueryOptions1,
				expr: &seqExpr{
					pos: position{line: 392, col: 17, offset: 9442},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 392, col: 17, offset: 9442},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 392, col: 21, offset: 9446},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 392, col: 23, offset: 9448},
							label: "Options",
							expr: &zeroOrMoreExpr{
								pos: position{line: 392, col: 32, offset: 9457},
								expr: &ruleRefExpr{
									pos:  position{line: 392, col: 32, offset: 9457},
									name: "QueryOption",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 392, col: 46, offset: 9471},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 392, col: 50, offset: 9475},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOption",
			pos:  position{line: 399, col: 1, offset: 9612},
			expr: &actionExpr{
				pos: position{line: 399, col: 16, offset: 9627},
				run: (*parser).callonQueryOption1,
				expr: &seqExpr{
					pos: position{line: 399, col: 16, offset: 9627},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 399, col: 16, offset: 9627},
							label: "OptionName",
							expr: &ruleRefExpr{
								pos:  position{line: 399, col: 27, offset: 9638},
								name: "Identifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 399, col: 38, offset: 9649},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 399, col: 40, offset: 9651},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 399, col: 44, offset: 9655},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 399, col: 46, offset: 9657},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 399, col: 54, offset: 9665},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 399, col: 62, offset: 9673},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 399, col: 64, offset: 9675},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 399, col: 68, offset: 9679},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Identifier",
			pos:  position{line: 411, col: 1, offset: 9897},
			expr: &actionExpr{
				pos: position{line: 411, col: 15, offset: 9911},
				run: (*parser).callonIdentifier1,
				expr: &labeledExpr{
					pos:   position{line: 411, col: 15, offset: 9911},
					label: "Identifier",
					expr: &oneOrMoreExpr{
						pos: position{line: 411, col: 26, offset: 9922},
						expr: &charClassMatcher{
							pos:        position{line: 411, col: 26, offset: 9922},
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
			pos:  position{line: 416, col: 1, offset: 10012},
			expr: &seqExpr{
				pos: position{line: 416, col: 12, offset: 10023},
				exprs: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 416, col: 12, offset: 10023},
						name: "_",
					},
					&litMatcher{
						pos:        position{line: 416, col: 14, offset: 10025},
						val:        "//",
						ignoreCase: false,
					},
					&zeroOrMoreExpr{
						pos: position{line: 416, col: 19, offset: 10030},
						expr: &charClassMatcher{
							pos:        position{line: 416, col: 19, offset: 10030},
							val:        "[^\\n]",
							chars:      []rune{'\n'},
							ignoreCase: false,
							inverted:   true,
						},
					},
					&ruleRefExpr{
						pos:  position{line: 416, col: 26, offset: 10037},
						name: "_",
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 418, col: 1, offset: 10040},
			expr: &zeroOrMoreExpr{
				pos: position{line: 418, col: 19, offset: 10058},
				expr: &charClassMatcher{
					pos:        position{line: 418, col: 19, offset: 10058},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 420, col: 1, offset: 10070},
			expr: &notExpr{
				pos: position{line: 420, col: 8, offset: 10077},
				expr: &anyMatcher{
					line: 420, col: 9, offset: 10078,
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
	if Type == nil {
		return nil, errors.New("`attacker` is declared with missing attacker type")
	}
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
	id := principalNamesMapAdd(Name.(string))
	return Block{
		Kind: "principal",
		Principal: Principal{
			Name:        Name.(string),
			ID:          id,
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
	switch string(c.text) {
	default:
		return typesEnumPrivate, nil
	case "public":
		return typesEnumPublic, nil
	case "password":
		return typesEnumPassword, nil
	}
}

func (p *parser) callonQualifier1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQualifier1()
}

func (c *current) onMessage1(Sender, Recipient, Constants interface{}) (interface{}, error) {
	switch {
	case Sender == nil:
		return nil, errors.New("message sender is not defined")
	case Recipient == nil:
		return nil, errors.New("message recipient is not defined")
	case Constants == nil:
		return nil, errors.New("message constants are not defined")
	}
	senderID := principalNamesMapAdd(Sender.(string))
	recipientID := principalNamesMapAdd(Recipient.(string))
	return Block{
		Kind: "message",
		Message: Message{
			Sender:    senderID,
			Recipient: recipientID,
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
	switch {
	case Qualifier == nil:
		return nil, errors.New("`knows` declaration is missing qualifier")
	case Constants == nil:
		return nil, errors.New("`knows` declaration is missing constant name(s)")
	}
	return Expression{
		Kind:      typesEnumKnows,
		Qualifier: Qualifier.(typesEnum),
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonKnows1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onKnows1(stack["Qualifier"], stack["Constants"])
}

func (c *current) onGenerates1(Constants interface{}) (interface{}, error) {
	if Constants == nil {
		return nil, errors.New("`generates` declaration is missing constant name(s)")
	}
	return Expression{
		Kind:      typesEnumGenerates,
		Qualifier: typesEnumEmpty,
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonGenerates1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGenerates1(stack["Constants"])
}

func (c *current) onLeaks1(Constants interface{}) (interface{}, error) {
	if Constants == nil {
		return nil, errors.New("`leaks` declaration is missing constant name(s)")
	}
	return Expression{
		Kind:      typesEnumLeaks,
		Qualifier: typesEnumEmpty,
		Constants: Constants.([]Constant),
	}, nil
}

func (p *parser) callonLeaks1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onLeaks1(stack["Constants"])
}

func (c *current) onAssignment1(Left, Right interface{}) (interface{}, error) {
	if Left == nil || Right == nil {
		return nil, errors.New("invalid value assignment")
	}
	switch Right.(Value).Kind {
	case typesEnumConstant:
		err := errors.New("cannot assign value to value")
		return nil, err
	}
	consts := Left.([]Constant)
	return Expression{
		Kind:      typesEnumAssignment,
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
	name := Const.(string)
	switch name {
	case "_":
		name = fmt.Sprintf("unnamed_%d", libpegUnnamedCounter)
		libpegUnnamedCounter = libpegUnnamedCounter + 1
	}
	id := valueNamesMapAdd(name)
	return Value{
		Kind: typesEnumConstant,
		Constant: Constant{
			Name: name,
			ID:   id,
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
	g := Guarded.(Value)
	err := libpegCheckIfReserved(g.Constant.Name)
	return Value{
		Kind: typesEnumConstant,
		Constant: Constant{
			Name:  g.Constant.Name,
			ID:    g.Constant.ID,
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
	primEnum, err := primitiveGetEnum(Name.(string))
	return Value{
		Kind: typesEnumPrimitive,
		Primitive: Primitive{
			ID:        primEnum,
			Arguments: args,
			Output:    0,
			Check:     Check != nil,
		},
	}, err
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
		Kind: typesEnumEquation,
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
	switch {
	case Const == nil:
		return nil, errors.New("`confidentiality` query is missing constant")
	case Options == nil:
		Options = []QueryOption{}
	}
	return Query{
		Kind:      typesEnumConfidentiality,
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
	switch {
	case Message == nil:
		return nil, errors.New("`authentication` query is missing message")
	case Options == nil:
		Options = []QueryOption{}
	}
	return Query{
		Kind:      typesEnumAuthentication,
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
	switch {
	case Const == nil:
		return nil, errors.New("`freshness` query is missing constant")
	case Options == nil:
		Options = []QueryOption{}
	}
	return Query{
		Kind:      typesEnumFreshness,
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

func (c *current) onQueryUnlinkability1(Consts, Options interface{}) (interface{}, error) {
	switch {
	case Consts == nil:
		return nil, errors.New("`unlinkability` query is missing constants")
	case Options == nil:
		Options = []QueryOption{}
	}
	return Query{
		Kind:      typesEnumUnlinkability,
		Constants: Consts.([]Constant),
		Message:   Message{},
		Options:   Options.([]QueryOption),
	}, nil
}

func (p *parser) callonQueryUnlinkability1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryUnlinkability1(stack["Consts"], stack["Options"])
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
	optionEnum := typesEnumEmpty
	switch OptionName.(string) {
	case "precondition":
		optionEnum = typesEnumPrecondition
	}
	return QueryOption{
		Kind:    optionEnum,
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
