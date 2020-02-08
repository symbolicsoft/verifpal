/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// This file is generated automatically from verifpal.peg.
// Do not modify.

package verifpal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var parserReserved = []string{
	"attacker", "passive", "active", "principal",
	"phase, public", "private", "password",
	"confidentiality", "authentication", "precondition",
	"ringsign", "ringsignverif",
	"primitive", "pw_hash", "hash", "hkdf",
	"aead_enc", "aead_dec", "enc", "dec",
	"mac", "assert", "sign", "signverif",
	"pke_enc", "pke_dec", "shamir_split",
	"shamir_join", "g", "nil", "unnamed",
}

func parserCheckIfReserved(s string) error {
	found := false
	switch {
	case strInSlice(s, parserReserved):
		found = true
	case strings.HasPrefix(s, "attacker"):
		found = true
	case strings.HasPrefix(s, "unnamed"):
		found = true
	}
	if found {
		return fmt.Errorf("cannot use reserved keyword in name: %s", s)
	}
	return nil
}

func parserParseModel(filePath string) Model {
	fileName := path.Base(filePath)
	if len(fileName) > 64 {
		errorCritical("model file name must be 64 characters or less")
	}
	if filepath.Ext(fileName) != ".vp" {
		errorCritical("model file name must have a '.vp' extension")
	}
	PrettyMessage(fmt.Sprintf(
		"Parsing model '%s'...", fileName,
	), "verifpal", false)
	parsed, err := ParseFile(filePath)
	if err != nil {
		errorCritical(err.Error())
	}
	m := parsed.(Model)
	m.fileName = fileName
	return m
}

var g = &grammar{
	rules: []*rule{
		{
			name: "Verifpal",
			pos:  position{line: 74, col: 1, offset: 1604},
			expr: &actionExpr{
				pos: position{line: 74, col: 13, offset: 1616},
				run: (*parser).callonVerifpal1,
				expr: &seqExpr{
					pos: position{line: 74, col: 13, offset: 1616},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 74, col: 13, offset: 1616},
							expr: &ruleRefExpr{
								pos:  position{line: 74, col: 13, offset: 1616},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 74, col: 22, offset: 1625},
							label: "Attacker",
							expr: &ruleRefExpr{
								pos:  position{line: 74, col: 31, offset: 1634},
								name: "Attacker",
							},
						},
						&labeledExpr{
							pos:   position{line: 74, col: 40, offset: 1643},
							label: "Blocks",
							expr: &oneOrMoreExpr{
								pos: position{line: 74, col: 48, offset: 1651},
								expr: &ruleRefExpr{
									pos:  position{line: 74, col: 48, offset: 1651},
									name: "Block",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 74, col: 56, offset: 1659},
							label: "Queries",
							expr: &ruleRefExpr{
								pos:  position{line: 74, col: 64, offset: 1667},
								name: "Queries",
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 74, col: 72, offset: 1675},
							expr: &ruleRefExpr{
								pos:  position{line: 74, col: 72, offset: 1675},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 74, col: 81, offset: 1684},
							name: "EOF",
						},
					},
				},
			},
		},
		{
			name: "Attacker",
			pos:  position{line: 88, col: 1, offset: 1979},
			expr: &actionExpr{
				pos: position{line: 88, col: 13, offset: 1991},
				run: (*parser).callonAttacker1,
				expr: &seqExpr{
					pos: position{line: 88, col: 13, offset: 1991},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 88, col: 13, offset: 1991},
							val:        "attacker",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 88, col: 24, offset: 2002},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 88, col: 26, offset: 2004},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 88, col: 30, offset: 2008},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 88, col: 32, offset: 2010},
							label: "Type",
							expr: &ruleRefExpr{
								pos:  position{line: 88, col: 37, offset: 2015},
								name: "AttackerType",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 88, col: 50, offset: 2028},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 88, col: 52, offset: 2030},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 88, col: 56, offset: 2034},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "AttackerType",
			pos:  position{line: 92, col: 1, offset: 2059},
			expr: &actionExpr{
				pos: position{line: 92, col: 17, offset: 2075},
				run: (*parser).callonAttackerType1,
				expr: &choiceExpr{
					pos: position{line: 92, col: 18, offset: 2076},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 92, col: 18, offset: 2076},
							val:        "active",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 92, col: 27, offset: 2085},
							val:        "passive",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Block",
			pos:  position{line: 96, col: 1, offset: 2129},
			expr: &actionExpr{
				pos: position{line: 96, col: 10, offset: 2138},
				run: (*parser).callonBlock1,
				expr: &seqExpr{
					pos: position{line: 96, col: 10, offset: 2138},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 96, col: 10, offset: 2138},
							expr: &ruleRefExpr{
								pos:  position{line: 96, col: 10, offset: 2138},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 96, col: 19, offset: 2147},
							label: "Block",
							expr: &choiceExpr{
								pos: position{line: 96, col: 26, offset: 2154},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 96, col: 26, offset: 2154},
										name: "Principal",
									},
									&ruleRefExpr{
										pos:  position{line: 96, col: 36, offset: 2164},
										name: "Message",
									},
									&ruleRefExpr{
										pos:  position{line: 96, col: 44, offset: 2172},
										name: "Phase",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 96, col: 51, offset: 2179},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 96, col: 53, offset: 2181},
							expr: &ruleRefExpr{
								pos:  position{line: 96, col: 53, offset: 2181},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Principal",
			pos:  position{line: 100, col: 1, offset: 2214},
			expr: &actionExpr{
				pos: position{line: 100, col: 14, offset: 2227},
				run: (*parser).callonPrincipal1,
				expr: &seqExpr{
					pos: position{line: 100, col: 14, offset: 2227},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 100, col: 14, offset: 2227},
							val:        "principal",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 26, offset: 2239},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 100, col: 28, offset: 2241},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 100, col: 33, offset: 2246},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 47, offset: 2260},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 100, col: 49, offset: 2262},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 53, offset: 2266},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 100, col: 55, offset: 2268},
							label: "Expressions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 100, col: 68, offset: 2281},
								expr: &ruleRefExpr{
									pos:  position{line: 100, col: 68, offset: 2281},
									name: "Expression",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 81, offset: 2294},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 100, col: 83, offset: 2296},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 100, col: 87, offset: 2300},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 113, col: 1, offset: 2542},
			expr: &actionExpr{
				pos: position{line: 113, col: 18, offset: 2559},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 113, col: 18, offset: 2559},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 113, col: 23, offset: 2564},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Qualifier",
			pos:  position{line: 118, col: 1, offset: 2667},
			expr: &actionExpr{
				pos: position{line: 118, col: 14, offset: 2680},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 118, col: 15, offset: 2681},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 118, col: 15, offset: 2681},
							val:        "public",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 118, col: 24, offset: 2690},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 118, col: 34, offset: 2700},
							val:        "password",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 122, col: 1, offset: 2745},
			expr: &actionExpr{
				pos: position{line: 122, col: 12, offset: 2756},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 122, col: 12, offset: 2756},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 122, col: 12, offset: 2756},
							label: "Sender",
							expr: &ruleRefExpr{
								pos:  position{line: 122, col: 19, offset: 2763},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 122, col: 33, offset: 2777},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 122, col: 35, offset: 2779},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 122, col: 40, offset: 2784},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 122, col: 42, offset: 2786},
							label: "Recipient",
							expr: &ruleRefExpr{
								pos:  position{line: 122, col: 52, offset: 2796},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 122, col: 66, offset: 2810},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 122, col: 68, offset: 2812},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 122, col: 72, offset: 2816},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 122, col: 74, offset: 2818},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 122, col: 84, offset: 2828},
								name: "MessageConstants",
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 133, col: 1, offset: 3017},
			expr: &actionExpr{
				pos: position{line: 133, col: 21, offset: 3037},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 133, col: 21, offset: 3037},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 133, col: 38, offset: 3054},
						expr: &choiceExpr{
							pos: position{line: 133, col: 39, offset: 3055},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 133, col: 39, offset: 3055},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 133, col: 55, offset: 3071},
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
			pos:  position{line: 143, col: 1, offset: 3235},
			expr: &actionExpr{
				pos: position{line: 143, col: 15, offset: 3249},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 143, col: 15, offset: 3249},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 143, col: 15, offset: 3249},
							expr: &ruleRefExpr{
								pos:  position{line: 143, col: 15, offset: 3249},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 143, col: 24, offset: 3258},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 143, col: 36, offset: 3270},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 143, col: 36, offset: 3270},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 143, col: 42, offset: 3276},
										name: "Generates",
									},
									&ruleRefExpr{
										pos:  position{line: 143, col: 52, offset: 3286},
										name: "Leaks",
									},
									&ruleRefExpr{
										pos:  position{line: 143, col: 58, offset: 3292},
										name: "Assignment",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 143, col: 70, offset: 3304},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 143, col: 72, offset: 3306},
							expr: &ruleRefExpr{
								pos:  position{line: 143, col: 72, offset: 3306},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 147, col: 1, offset: 3344},
			expr: &actionExpr{
				pos: position{line: 147, col: 10, offset: 3353},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 147, col: 10, offset: 3353},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 147, col: 10, offset: 3353},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 147, col: 18, offset: 3361},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 147, col: 20, offset: 3363},
							label: "Qualifier",
							expr: &ruleRefExpr{
								pos:  position{line: 147, col: 30, offset: 3373},
								name: "Qualifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 147, col: 40, offset: 3383},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 147, col: 42, offset: 3385},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 147, col: 52, offset: 3395},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 155, col: 1, offset: 3525},
			expr: &actionExpr{
				pos: position{line: 155, col: 14, offset: 3538},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 155, col: 14, offset: 3538},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 155, col: 14, offset: 3538},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 155, col: 26, offset: 3550},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 155, col: 28, offset: 3552},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 155, col: 38, offset: 3562},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Leaks",
			pos:  position{line: 163, col: 1, offset: 3680},
			expr: &actionExpr{
				pos: position{line: 163, col: 10, offset: 3689},
				run: (*parser).callonLeaks1,
				expr: &seqExpr{
					pos: position{line: 163, col: 10, offset: 3689},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 163, col: 10, offset: 3689},
							val:        "leaks",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 163, col: 18, offset: 3697},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 163, col: 20, offset: 3699},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 163, col: 30, offset: 3709},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 171, col: 1, offset: 3823},
			expr: &actionExpr{
				pos: position{line: 171, col: 15, offset: 3837},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 171, col: 15, offset: 3837},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 171, col: 15, offset: 3837},
							label: "Left",
							expr: &ruleRefExpr{
								pos:  position{line: 171, col: 20, offset: 3842},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 171, col: 30, offset: 3852},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 171, col: 32, offset: 3854},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 171, col: 36, offset: 3858},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 171, col: 38, offset: 3860},
							label: "Right",
							expr: &ruleRefExpr{
								pos:  position{line: 171, col: 44, offset: 3866},
								name: "Value",
							},
						},
					},
				},
			},
		},
		{
			name: "Constant",
			pos:  position{line: 184, col: 1, offset: 4099},
			expr: &actionExpr{
				pos: position{line: 184, col: 13, offset: 4111},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 184, col: 13, offset: 4111},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 184, col: 13, offset: 4111},
							label: "Constant",
							expr: &ruleRefExpr{
								pos:  position{line: 184, col: 22, offset: 4120},
								name: "Identifier",
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 184, col: 33, offset: 4131},
							expr: &seqExpr{
								pos: position{line: 184, col: 34, offset: 4132},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 184, col: 34, offset: 4132},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 184, col: 36, offset: 4134},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 184, col: 40, offset: 4138},
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
			pos:  position{line: 193, col: 1, offset: 4245},
			expr: &actionExpr{
				pos: position{line: 193, col: 14, offset: 4258},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 193, col: 14, offset: 4258},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 193, col: 24, offset: 4268},
						expr: &ruleRefExpr{
							pos:  position{line: 193, col: 24, offset: 4268},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "Phase",
			pos:  position{line: 205, col: 1, offset: 4511},
			expr: &actionExpr{
				pos: position{line: 205, col: 10, offset: 4520},
				run: (*parser).callonPhase1,
				expr: &seqExpr{
					pos: position{line: 205, col: 10, offset: 4520},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 205, col: 10, offset: 4520},
							val:        "phase",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 205, col: 18, offset: 4528},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 205, col: 20, offset: 4530},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 205, col: 24, offset: 4534},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 205, col: 26, offset: 4536},
							label: "Number",
							expr: &oneOrMoreExpr{
								pos: position{line: 205, col: 33, offset: 4543},
								expr: &charClassMatcher{
									pos:        position{line: 205, col: 33, offset: 4543},
									val:        "[0-9]",
									ranges:     []rune{'0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 205, col: 40, offset: 4550},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 205, col: 42, offset: 4552},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 205, col: 46, offset: 4556},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 218, col: 1, offset: 4778},
			expr: &actionExpr{
				pos: position{line: 218, col: 20, offset: 4797},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 218, col: 20, offset: 4797},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 218, col: 20, offset: 4797},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 218, col: 24, offset: 4801},
							label: "Guarded",
							expr: &ruleRefExpr{
								pos:  position{line: 218, col: 32, offset: 4809},
								name: "Identifier",
							},
						},
						&litMatcher{
							pos:        position{line: 218, col: 43, offset: 4820},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 218, col: 47, offset: 4824},
							expr: &seqExpr{
								pos: position{line: 218, col: 48, offset: 4825},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 218, col: 48, offset: 4825},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 218, col: 50, offset: 4827},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 218, col: 54, offset: 4831},
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
			pos:  position{line: 229, col: 1, offset: 5001},
			expr: &actionExpr{
				pos: position{line: 229, col: 14, offset: 5014},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 229, col: 14, offset: 5014},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 229, col: 14, offset: 5014},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 229, col: 19, offset: 5019},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 229, col: 33, offset: 5033},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 229, col: 37, offset: 5037},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 229, col: 39, offset: 5039},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 229, col: 49, offset: 5049},
								expr: &ruleRefExpr{
									pos:  position{line: 229, col: 49, offset: 5049},
									name: "Value",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 229, col: 56, offset: 5056},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 229, col: 58, offset: 5058},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 229, col: 62, offset: 5062},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 229, col: 68, offset: 5068},
								expr: &litMatcher{
									pos:        position{line: 229, col: 68, offset: 5068},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 229, col: 73, offset: 5073},
							expr: &seqExpr{
								pos: position{line: 229, col: 74, offset: 5074},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 229, col: 74, offset: 5074},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 229, col: 76, offset: 5076},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 229, col: 80, offset: 5080},
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
			pos:  position{line: 245, col: 1, offset: 5346},
			expr: &actionExpr{
				pos: position{line: 245, col: 18, offset: 5363},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 245, col: 18, offset: 5363},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 245, col: 23, offset: 5368},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Equation",
			pos:  position{line: 249, col: 1, offset: 5428},
			expr: &actionExpr{
				pos: position{line: 249, col: 13, offset: 5440},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 249, col: 13, offset: 5440},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 249, col: 13, offset: 5440},
							label: "First",
							expr: &ruleRefExpr{
								pos:  position{line: 249, col: 19, offset: 5446},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 249, col: 29, offset: 5456},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 249, col: 29, offset: 5456},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 249, col: 31, offset: 5458},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 249, col: 35, offset: 5462},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 249, col: 38, offset: 5465},
							label: "Second",
							expr: &ruleRefExpr{
								pos:  position{line: 249, col: 45, offset: 5472},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Value",
			pos:  position{line: 261, col: 1, offset: 5621},
			expr: &choiceExpr{
				pos: position{line: 261, col: 10, offset: 5630},
				alternatives: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 261, col: 10, offset: 5630},
						name: "Primitive",
					},
					&ruleRefExpr{
						pos:  position{line: 261, col: 20, offset: 5640},
						name: "Equation",
					},
					&ruleRefExpr{
						pos:  position{line: 261, col: 29, offset: 5649},
						name: "Constant",
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 263, col: 1, offset: 5660},
			expr: &actionExpr{
				pos: position{line: 263, col: 12, offset: 5671},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 263, col: 12, offset: 5671},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 263, col: 12, offset: 5671},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 22, offset: 5681},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 263, col: 24, offset: 5683},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 28, offset: 5687},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 263, col: 30, offset: 5689},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 263, col: 39, offset: 5698},
								expr: &ruleRefExpr{
									pos:  position{line: 263, col: 39, offset: 5698},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 263, col: 47, offset: 5706},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 263, col: 51, offset: 5710},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 267, col: 1, offset: 5738},
			expr: &actionExpr{
				pos: position{line: 267, col: 10, offset: 5747},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 267, col: 10, offset: 5747},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 267, col: 10, offset: 5747},
							expr: &ruleRefExpr{
								pos:  position{line: 267, col: 10, offset: 5747},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 267, col: 19, offset: 5756},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 267, col: 26, offset: 5763},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 267, col: 26, offset: 5763},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 267, col: 47, offset: 5784},
										name: "QueryAuthentication",
									},
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 267, col: 68, offset: 5805},
							expr: &ruleRefExpr{
								pos:  position{line: 267, col: 68, offset: 5805},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 271, col: 1, offset: 5839},
			expr: &actionExpr{
				pos: position{line: 271, col: 25, offset: 5863},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 271, col: 25, offset: 5863},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 271, col: 25, offset: 5863},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 271, col: 44, offset: 5882},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 271, col: 46, offset: 5884},
							label: "Constant",
							expr: &ruleRefExpr{
								pos:  position{line: 271, col: 55, offset: 5893},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 271, col: 64, offset: 5902},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 271, col: 66, offset: 5904},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 271, col: 74, offset: 5912},
								expr: &ruleRefExpr{
									pos:  position{line: 271, col: 74, offset: 5912},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 271, col: 88, offset: 5926},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 283, col: 1, offset: 6132},
			expr: &actionExpr{
				pos: position{line: 283, col: 24, offset: 6155},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 283, col: 24, offset: 6155},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 283, col: 24, offset: 6155},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 283, col: 42, offset: 6173},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 283, col: 44, offset: 6175},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 283, col: 52, offset: 6183},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 283, col: 60, offset: 6191},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 283, col: 62, offset: 6193},
							label: "Options",
							expr: &zeroOrOneExpr{
								pos: position{line: 283, col: 70, offset: 6201},
								expr: &ruleRefExpr{
									pos:  position{line: 283, col: 70, offset: 6201},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 283, col: 84, offset: 6215},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOptions",
			pos:  position{line: 295, col: 1, offset: 6421},
			expr: &actionExpr{
				pos: position{line: 295, col: 17, offset: 6437},
				run: (*parser).callonQueryOptions1,
				expr: &seqExpr{
					pos: position{line: 295, col: 17, offset: 6437},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 295, col: 17, offset: 6437},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 295, col: 21, offset: 6441},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 295, col: 23, offset: 6443},
							label: "Options",
							expr: &zeroOrMoreExpr{
								pos: position{line: 295, col: 32, offset: 6452},
								expr: &ruleRefExpr{
									pos:  position{line: 295, col: 32, offset: 6452},
									name: "QueryOption",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 295, col: 46, offset: 6466},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 295, col: 50, offset: 6470},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOption",
			pos:  position{line: 302, col: 1, offset: 6607},
			expr: &actionExpr{
				pos: position{line: 302, col: 16, offset: 6622},
				run: (*parser).callonQueryOption1,
				expr: &seqExpr{
					pos: position{line: 302, col: 16, offset: 6622},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 302, col: 16, offset: 6622},
							label: "OptionName",
							expr: &ruleRefExpr{
								pos:  position{line: 302, col: 27, offset: 6633},
								name: "Identifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 302, col: 38, offset: 6644},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 302, col: 40, offset: 6646},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 302, col: 44, offset: 6650},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 302, col: 46, offset: 6652},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 302, col: 54, offset: 6660},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 302, col: 62, offset: 6668},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 302, col: 64, offset: 6670},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 302, col: 68, offset: 6674},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Identifier",
			pos:  position{line: 309, col: 1, offset: 6777},
			expr: &actionExpr{
				pos: position{line: 309, col: 15, offset: 6791},
				run: (*parser).callonIdentifier1,
				expr: &labeledExpr{
					pos:   position{line: 309, col: 15, offset: 6791},
					label: "Identifier",
					expr: &oneOrMoreExpr{
						pos: position{line: 309, col: 26, offset: 6802},
						expr: &charClassMatcher{
							pos:        position{line: 309, col: 26, offset: 6802},
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
			pos:  position{line: 314, col: 1, offset: 6892},
			expr: &seqExpr{
				pos: position{line: 314, col: 12, offset: 6903},
				exprs: []interface{}{
					&ruleRefExpr{
						pos:  position{line: 314, col: 12, offset: 6903},
						name: "_",
					},
					&litMatcher{
						pos:        position{line: 314, col: 14, offset: 6905},
						val:        "//",
						ignoreCase: false,
					},
					&zeroOrMoreExpr{
						pos: position{line: 314, col: 19, offset: 6910},
						expr: &charClassMatcher{
							pos:        position{line: 314, col: 19, offset: 6910},
							val:        "[^\\n]",
							chars:      []rune{'\n'},
							ignoreCase: false,
							inverted:   true,
						},
					},
					&ruleRefExpr{
						pos:  position{line: 314, col: 26, offset: 6917},
						name: "_",
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 316, col: 1, offset: 6920},
			expr: &zeroOrMoreExpr{
				pos: position{line: 316, col: 19, offset: 6938},
				expr: &charClassMatcher{
					pos:        position{line: 316, col: 19, offset: 6938},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 318, col: 1, offset: 6950},
			expr: &notExpr{
				pos: position{line: 318, col: 8, offset: 6957},
				expr: &anyMatcher{
					line: 318, col: 9, offset: 6958,
				},
			},
		},
	},
}

func (c *current) onVerifpal1(Attacker, Blocks, Queries interface{}) (interface{}, error) {
	b := Blocks.([]interface{})
	q := Queries.([]interface{})
	db := make([]block, len(b))
	dq := make([]query, len(q))
	for i, v := range b {
		db[i] = v.(block)
	}
	for i, v := range q {
		dq[i] = v.(query)
	}
	return Model{
		attacker: Attacker.(string),
		blocks:   db,
		queries:  dq,
	}, nil
}

func (p *parser) callonVerifpal1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onVerifpal1(stack["Attacker"], stack["Blocks"], stack["Queries"])
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
	de := make([]expression, len(e))
	for i, v := range e {
		de[i] = v.(expression)
	}
	return block{
		kind: "principal",
		principal: principal{
			name:        Name.(string),
			expressions: de,
		},
	}, nil
}

func (p *parser) callonPrincipal1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrincipal1(stack["Name"], stack["Expressions"])
}

func (c *current) onPrincipalName1(Name interface{}) (interface{}, error) {
	err := parserCheckIfReserved(Name.(string))
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
	return block{
		kind: "message",
		message: message{
			sender:    Sender.(string),
			recipient: Recipient.(string),
			constants: Constants.([]constant),
		},
	}, nil
}

func (p *parser) callonMessage1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onMessage1(stack["Sender"], stack["Recipient"], stack["Constants"])
}

func (c *current) onMessageConstants1(MessageConstants interface{}) (interface{}, error) {
	var da []constant
	a := MessageConstants.([]interface{})
	for _, v := range a {
		c := v.(value).constant
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
	return expression{
		kind:      "knows",
		qualifier: Qualifier.(string),
		constants: Constants.([]constant),
	}, nil
}

func (p *parser) callonKnows1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onKnows1(stack["Qualifier"], stack["Constants"])
}

func (c *current) onGenerates1(Constants interface{}) (interface{}, error) {
	return expression{
		kind:      "generates",
		qualifier: "",
		constants: Constants.([]constant),
	}, nil
}

func (p *parser) callonGenerates1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGenerates1(stack["Constants"])
}

func (c *current) onLeaks1(Constants interface{}) (interface{}, error) {
	return expression{
		kind:      "leaks",
		qualifier: "",
		constants: Constants.([]constant),
	}, nil
}

func (p *parser) callonLeaks1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onLeaks1(stack["Constants"])
}

func (c *current) onAssignment1(Left, Right interface{}) (interface{}, error) {
	switch Right.(value).kind {
	case "constant":
		err := errors.New("cannot assign value to value")
		return nil, err
	}
	return expression{
		kind:  "assignment",
		left:  Left.([]constant),
		right: Right.(value),
	}, nil
}

func (p *parser) callonAssignment1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onAssignment1(stack["Left"], stack["Right"])
}

func (c *current) onConstant1(Constant interface{}) (interface{}, error) {
	return value{
		kind: "constant",
		constant: constant{
			name: Constant.(string),
		},
	}, nil
}

func (p *parser) callonConstant1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onConstant1(stack["Constant"])
}

func (c *current) onConstants1(Constants interface{}) (interface{}, error) {
	var da []constant
	var err error
	a := Constants.([]interface{})
	for _, c := range a {
		err = parserCheckIfReserved(c.(value).constant.name)
		if err != nil {
			break
		}
		da = append(da, c.(value).constant)
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
	return block{
		kind: "phase",
		phase: phase{
			number: n,
		},
	}, err
}

func (p *parser) callonPhase1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPhase1(stack["Number"])
}

func (c *current) onGuardedConstant1(Guarded interface{}) (interface{}, error) {
	err := parserCheckIfReserved(Guarded.(string))
	return value{
		kind: "constant",
		constant: constant{
			name:  Guarded.(string),
			guard: true,
		},
	}, err
}

func (p *parser) callonGuardedConstant1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGuardedConstant1(stack["Guarded"])
}

func (c *current) onPrimitive1(Name, Arguments, Check interface{}) (interface{}, error) {
	args := []value{}
	for _, a := range Arguments.([]interface{}) {
		args = append(args, a.(value))
	}
	return value{
		kind: "primitive",
		primitive: primitive{
			name:      Name.(string),
			arguments: args,
			output:    0,
			check:     Check != nil,
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
	return value{
		kind: "equation",
		equation: equation{
			values: []value{
				First.(value),
				Second.(value),
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

func (c *current) onQueryConfidentiality1(Constant, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []queryOption{}
	}
	return query{
		kind:     "confidentiality",
		constant: Constant.(value).constant,
		message:  message{},
		options:  Options.([]queryOption),
	}, nil
}

func (p *parser) callonQueryConfidentiality1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryConfidentiality1(stack["Constant"], stack["Options"])
}

func (c *current) onQueryAuthentication1(Message, Options interface{}) (interface{}, error) {
	if Options == nil {
		Options = []queryOption{}
	}
	return query{
		kind:     "authentication",
		constant: constant{},
		message:  (Message.(block)).message,
		options:  Options.([]queryOption),
	}, nil
}

func (p *parser) callonQueryAuthentication1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryAuthentication1(stack["Message"], stack["Options"])
}

func (c *current) onQueryOptions1(Options interface{}) (interface{}, error) {
	o := Options.([]interface{})
	do := make([]queryOption, len(o))
	for i, v := range o {
		do[i] = v.(queryOption)
	}
	return do, nil
}

func (p *parser) callonQueryOptions1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryOptions1(stack["Options"])
}

func (c *current) onQueryOption1(OptionName, Message interface{}) (interface{}, error) {
	return queryOption{
		kind:    OptionName.(string),
		message: (Message.(block)).message,
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
