/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// This file is generated automatically from api/grammar/verifpal.peg. Do not modify.

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

func parserParseModel(filePath string) (Model, knowledgeMap, []principalState) {
	var m Model
	fileName := path.Base(filePath)
	if len(fileName) > 64 {
		errorCritical("model file name must be 64 characters or less")
	}
	if filepath.Ext(fileName) != ".vp" {
		errorCritical("model file name must have a '.vp' extension")
	}
	prettyMessage(fmt.Sprintf(
		"Parsing model '%s'...", fileName,
	), "verifpal", false)
	parsed, err := ParseFile(filePath)
	if err != nil {
		errorCritical(err.Error())
	}
	m = parsed.(Model)
	m.fileName = fileName
	valKnowledgeMap, valPrincipalStates := sanity(m)
	return m, valKnowledgeMap, valPrincipalStates
}

var parserReserved = []string{
	"attacker",
	"passive",
	"active",
	"principal",
	"phase",
	"public",
	"private",
	"password",
	"queries",
	"confidentiality",
	"authentication",
	"primitive",
	"pw_hash",
	"hash",
	"hkdf",
	"aead_enc",
	"aead_dec",
	"enc",
	"dec",
	"mac",
	"assert",
	"sign",
	"signverif",
	"pke_enc",
	"pke_dec",
	"shamir_split",
	"shamir_join",
	"g",
	"nil",
	"unnamed",
}

func parserCheckIfReserved(s string) error {
	found := false
	switch {
	case strInSlice(s, parserReserved):
		found = true
	case strings.HasPrefix(strings.ToLower(s), "attacker"):
		found = true
	case strings.HasPrefix(strings.ToLower(s), "unnamed"):
		found = true
	}
	if found {
		return fmt.Errorf("cannot use reserved keyword in name: %s", s)
	}
	return nil
}

var g = &grammar{
	rules: []*rule{
		{
			name: "Verifpal",
			pos:  position{line: 96, col: 1, offset: 1893},
			expr: &actionExpr{
				pos: position{line: 97, col: 2, offset: 1906},
				run: (*parser).callonVerifpal1,
				expr: &seqExpr{
					pos: position{line: 97, col: 2, offset: 1906},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 97, col: 2, offset: 1906},
							expr: &ruleRefExpr{
								pos:  position{line: 97, col: 2, offset: 1906},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 98, col: 2, offset: 1916},
							label: "Attacker",
							expr: &ruleRefExpr{
								pos:  position{line: 98, col: 11, offset: 1925},
								name: "Attacker",
							},
						},
						&labeledExpr{
							pos:   position{line: 99, col: 2, offset: 1935},
							label: "Blocks",
							expr: &oneOrMoreExpr{
								pos: position{line: 99, col: 10, offset: 1943},
								expr: &ruleRefExpr{
									pos:  position{line: 99, col: 10, offset: 1943},
									name: "Block",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 100, col: 2, offset: 1952},
							label: "Queries",
							expr: &ruleRefExpr{
								pos:  position{line: 100, col: 10, offset: 1960},
								name: "Queries",
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 101, col: 2, offset: 1969},
							expr: &ruleRefExpr{
								pos:  position{line: 101, col: 2, offset: 1969},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 102, col: 2, offset: 1979},
							name: "EOF",
						},
					},
				},
			},
		},
		{
			name: "Attacker",
			pos:  position{line: 117, col: 1, offset: 2274},
			expr: &actionExpr{
				pos: position{line: 118, col: 2, offset: 2287},
				run: (*parser).callonAttacker1,
				expr: &seqExpr{
					pos: position{line: 118, col: 2, offset: 2287},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 118, col: 2, offset: 2287},
							val:        "attacker",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 118, col: 13, offset: 2298},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 118, col: 15, offset: 2300},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 118, col: 19, offset: 2304},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 118, col: 21, offset: 2306},
							label: "Type",
							expr: &ruleRefExpr{
								pos:  position{line: 118, col: 26, offset: 2311},
								name: "AttackerType",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 118, col: 39, offset: 2324},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 118, col: 41, offset: 2326},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 118, col: 45, offset: 2330},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "AttackerType",
			pos:  position{line: 123, col: 1, offset: 2355},
			expr: &actionExpr{
				pos: position{line: 124, col: 2, offset: 2372},
				run: (*parser).callonAttackerType1,
				expr: &choiceExpr{
					pos: position{line: 124, col: 3, offset: 2373},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 124, col: 3, offset: 2373},
							val:        "active",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 124, col: 12, offset: 2382},
							val:        "passive",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Block",
			pos:  position{line: 129, col: 1, offset: 2426},
			expr: &actionExpr{
				pos: position{line: 130, col: 2, offset: 2436},
				run: (*parser).callonBlock1,
				expr: &seqExpr{
					pos: position{line: 130, col: 2, offset: 2436},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 130, col: 2, offset: 2436},
							expr: &ruleRefExpr{
								pos:  position{line: 130, col: 2, offset: 2436},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 131, col: 2, offset: 2446},
							label: "Block",
							expr: &choiceExpr{
								pos: position{line: 131, col: 9, offset: 2453},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 131, col: 9, offset: 2453},
										name: "Principal",
									},
									&ruleRefExpr{
										pos:  position{line: 131, col: 19, offset: 2463},
										name: "Message",
									},
									&ruleRefExpr{
										pos:  position{line: 131, col: 27, offset: 2471},
										name: "Phase",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 131, col: 34, offset: 2478},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 132, col: 2, offset: 2481},
							expr: &ruleRefExpr{
								pos:  position{line: 132, col: 2, offset: 2481},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Principal",
			pos:  position{line: 137, col: 1, offset: 2514},
			expr: &actionExpr{
				pos: position{line: 138, col: 2, offset: 2528},
				run: (*parser).callonPrincipal1,
				expr: &seqExpr{
					pos: position{line: 138, col: 2, offset: 2528},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 138, col: 2, offset: 2528},
							val:        "principal",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 138, col: 14, offset: 2540},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 138, col: 16, offset: 2542},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 138, col: 21, offset: 2547},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 138, col: 35, offset: 2561},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 138, col: 37, offset: 2563},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 138, col: 41, offset: 2567},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 138, col: 43, offset: 2569},
							label: "Expressions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 138, col: 56, offset: 2582},
								expr: &ruleRefExpr{
									pos:  position{line: 138, col: 56, offset: 2582},
									name: "Expression",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 138, col: 69, offset: 2595},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 138, col: 71, offset: 2597},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 138, col: 75, offset: 2601},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 154, col: 1, offset: 2926},
			expr: &actionExpr{
				pos: position{line: 155, col: 2, offset: 2944},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 155, col: 2, offset: 2944},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 155, col: 7, offset: 2949},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Qualifier",
			pos:  position{line: 160, col: 1, offset: 3007},
			expr: &actionExpr{
				pos: position{line: 161, col: 2, offset: 3021},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 161, col: 3, offset: 3022},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 161, col: 3, offset: 3022},
							val:        "public",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 161, col: 12, offset: 3031},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 161, col: 22, offset: 3041},
							val:        "password",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 166, col: 1, offset: 3086},
			expr: &actionExpr{
				pos: position{line: 167, col: 2, offset: 3098},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 167, col: 2, offset: 3098},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 167, col: 2, offset: 3098},
							label: "Sender",
							expr: &ruleRefExpr{
								pos:  position{line: 167, col: 9, offset: 3105},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 167, col: 23, offset: 3119},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 167, col: 25, offset: 3121},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 167, col: 30, offset: 3126},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 167, col: 32, offset: 3128},
							label: "Recipient",
							expr: &ruleRefExpr{
								pos:  position{line: 167, col: 42, offset: 3138},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 167, col: 56, offset: 3152},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 167, col: 58, offset: 3154},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 167, col: 62, offset: 3158},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 167, col: 64, offset: 3160},
							label: "MessageConstants",
							expr: &ruleRefExpr{
								pos:  position{line: 167, col: 81, offset: 3177},
								name: "MessageConstants",
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 188, col: 1, offset: 3610},
			expr: &actionExpr{
				pos: position{line: 189, col: 2, offset: 3631},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 189, col: 2, offset: 3631},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 189, col: 19, offset: 3648},
						expr: &choiceExpr{
							pos: position{line: 189, col: 20, offset: 3649},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 189, col: 20, offset: 3649},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 189, col: 36, offset: 3665},
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
			pos:  position{line: 202, col: 1, offset: 3882},
			expr: &actionExpr{
				pos: position{line: 203, col: 2, offset: 3897},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 203, col: 2, offset: 3897},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 203, col: 2, offset: 3897},
							expr: &ruleRefExpr{
								pos:  position{line: 203, col: 2, offset: 3897},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 204, col: 2, offset: 3907},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 204, col: 14, offset: 3919},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 204, col: 14, offset: 3919},
										name: "Assignment",
									},
									&ruleRefExpr{
										pos:  position{line: 204, col: 25, offset: 3930},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 204, col: 31, offset: 3936},
										name: "Generates",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 204, col: 42, offset: 3947},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 205, col: 2, offset: 3950},
							expr: &ruleRefExpr{
								pos:  position{line: 205, col: 2, offset: 3950},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 210, col: 1, offset: 3988},
			expr: &actionExpr{
				pos: position{line: 211, col: 2, offset: 3998},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 211, col: 2, offset: 3998},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 211, col: 2, offset: 3998},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 211, col: 10, offset: 4006},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 211, col: 12, offset: 4008},
							label: "Qualifier",
							expr: &ruleRefExpr{
								pos:  position{line: 211, col: 22, offset: 4018},
								name: "Qualifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 211, col: 32, offset: 4028},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 211, col: 34, offset: 4030},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 211, col: 44, offset: 4040},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 220, col: 1, offset: 4170},
			expr: &actionExpr{
				pos: position{line: 221, col: 2, offset: 4184},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 221, col: 2, offset: 4184},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 221, col: 2, offset: 4184},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 221, col: 14, offset: 4196},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 221, col: 16, offset: 4198},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 221, col: 26, offset: 4208},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 230, col: 1, offset: 4326},
			expr: &actionExpr{
				pos: position{line: 231, col: 2, offset: 4341},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 231, col: 2, offset: 4341},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 231, col: 2, offset: 4341},
							label: "Left",
							expr: &ruleRefExpr{
								pos:  position{line: 231, col: 7, offset: 4346},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 231, col: 17, offset: 4356},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 231, col: 19, offset: 4358},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 231, col: 23, offset: 4362},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 231, col: 25, offset: 4364},
							label: "Right",
							expr: &choiceExpr{
								pos: position{line: 231, col: 32, offset: 4371},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 231, col: 32, offset: 4371},
										name: "Primitive",
									},
									&ruleRefExpr{
										pos:  position{line: 231, col: 42, offset: 4381},
										name: "Equation",
									},
									&ruleRefExpr{
										pos:  position{line: 231, col: 51, offset: 4390},
										name: "Constant",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Constant",
			pos:  position{line: 248, col: 1, offset: 4666},
			expr: &actionExpr{
				pos: position{line: 249, col: 2, offset: 4679},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 249, col: 2, offset: 4679},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 249, col: 2, offset: 4679},
							label: "Constant",
							expr: &ruleRefExpr{
								pos:  position{line: 249, col: 11, offset: 4688},
								name: "Identifier",
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 249, col: 22, offset: 4699},
							expr: &seqExpr{
								pos: position{line: 249, col: 23, offset: 4700},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 249, col: 23, offset: 4700},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 249, col: 25, offset: 4702},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 249, col: 29, offset: 4706},
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
			pos:  position{line: 259, col: 1, offset: 4831},
			expr: &actionExpr{
				pos: position{line: 260, col: 2, offset: 4845},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 260, col: 2, offset: 4845},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 260, col: 12, offset: 4855},
						expr: &ruleRefExpr{
							pos:  position{line: 260, col: 12, offset: 4855},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "Phase",
			pos:  position{line: 272, col: 1, offset: 5079},
			expr: &actionExpr{
				pos: position{line: 273, col: 2, offset: 5089},
				run: (*parser).callonPhase1,
				expr: &seqExpr{
					pos: position{line: 273, col: 2, offset: 5089},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 273, col: 2, offset: 5089},
							val:        "phase",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 273, col: 10, offset: 5097},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 273, col: 12, offset: 5099},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 273, col: 16, offset: 5103},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 273, col: 18, offset: 5105},
							label: "Number",
							expr: &oneOrMoreExpr{
								pos: position{line: 273, col: 25, offset: 5112},
								expr: &charClassMatcher{
									pos:        position{line: 273, col: 25, offset: 5112},
									val:        "[0-9]",
									ranges:     []rune{'0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 273, col: 32, offset: 5119},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 273, col: 34, offset: 5121},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 273, col: 38, offset: 5125},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 288, col: 1, offset: 5362},
			expr: &actionExpr{
				pos: position{line: 289, col: 2, offset: 5382},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 289, col: 2, offset: 5382},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 289, col: 2, offset: 5382},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 289, col: 6, offset: 5386},
							label: "GuardedConstant",
							expr: &ruleRefExpr{
								pos:  position{line: 289, col: 22, offset: 5402},
								name: "Identifier",
							},
						},
						&litMatcher{
							pos:        position{line: 289, col: 33, offset: 5413},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 289, col: 37, offset: 5417},
							expr: &seqExpr{
								pos: position{line: 289, col: 38, offset: 5418},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 289, col: 38, offset: 5418},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 289, col: 40, offset: 5420},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 289, col: 44, offset: 5424},
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
			pos:  position{line: 300, col: 1, offset: 5571},
			expr: &actionExpr{
				pos: position{line: 301, col: 2, offset: 5585},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 301, col: 2, offset: 5585},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 301, col: 2, offset: 5585},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 301, col: 7, offset: 5590},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 301, col: 21, offset: 5604},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 301, col: 25, offset: 5608},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 301, col: 27, offset: 5610},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 301, col: 37, offset: 5620},
								expr: &choiceExpr{
									pos: position{line: 301, col: 38, offset: 5621},
									alternatives: []interface{}{
										&ruleRefExpr{
											pos:  position{line: 301, col: 38, offset: 5621},
											name: "Primitive",
										},
										&ruleRefExpr{
											pos:  position{line: 301, col: 48, offset: 5631},
											name: "Equation",
										},
										&ruleRefExpr{
											pos:  position{line: 301, col: 57, offset: 5640},
											name: "Constant",
										},
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 301, col: 68, offset: 5651},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 301, col: 70, offset: 5653},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 301, col: 74, offset: 5657},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 301, col: 80, offset: 5663},
								expr: &litMatcher{
									pos:        position{line: 301, col: 80, offset: 5663},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 301, col: 85, offset: 5668},
							expr: &seqExpr{
								pos: position{line: 301, col: 86, offset: 5669},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 301, col: 86, offset: 5669},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 301, col: 88, offset: 5671},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 301, col: 92, offset: 5675},
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
			pos:  position{line: 318, col: 1, offset: 5941},
			expr: &actionExpr{
				pos: position{line: 319, col: 2, offset: 5959},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 319, col: 2, offset: 5959},
					label: "Name",
					expr: &ruleRefExpr{
						pos:  position{line: 319, col: 7, offset: 5964},
						name: "Identifier",
					},
				},
			},
		},
		{
			name: "Equation",
			pos:  position{line: 324, col: 1, offset: 6024},
			expr: &actionExpr{
				pos: position{line: 325, col: 2, offset: 6037},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 325, col: 2, offset: 6037},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 325, col: 2, offset: 6037},
							label: "FirstConstant",
							expr: &ruleRefExpr{
								pos:  position{line: 325, col: 16, offset: 6051},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 325, col: 26, offset: 6061},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 325, col: 26, offset: 6061},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 325, col: 28, offset: 6063},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 325, col: 32, offset: 6067},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 325, col: 35, offset: 6070},
							label: "SecondConstant",
							expr: &ruleRefExpr{
								pos:  position{line: 325, col: 50, offset: 6085},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 338, col: 1, offset: 6251},
			expr: &actionExpr{
				pos: position{line: 339, col: 2, offset: 6263},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 339, col: 2, offset: 6263},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 339, col: 2, offset: 6263},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 339, col: 12, offset: 6273},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 339, col: 14, offset: 6275},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 339, col: 18, offset: 6279},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 339, col: 20, offset: 6281},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 339, col: 29, offset: 6290},
								expr: &ruleRefExpr{
									pos:  position{line: 339, col: 29, offset: 6290},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 339, col: 37, offset: 6298},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 339, col: 41, offset: 6302},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 344, col: 1, offset: 6330},
			expr: &actionExpr{
				pos: position{line: 345, col: 2, offset: 6340},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 345, col: 2, offset: 6340},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 345, col: 2, offset: 6340},
							expr: &ruleRefExpr{
								pos:  position{line: 345, col: 2, offset: 6340},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 346, col: 2, offset: 6350},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 346, col: 9, offset: 6357},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 346, col: 9, offset: 6357},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 346, col: 30, offset: 6378},
										name: "QueryAuthentication",
									},
								},
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 347, col: 2, offset: 6400},
							expr: &ruleRefExpr{
								pos:  position{line: 347, col: 2, offset: 6400},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 352, col: 1, offset: 6434},
			expr: &actionExpr{
				pos: position{line: 353, col: 2, offset: 6459},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 353, col: 2, offset: 6459},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 353, col: 2, offset: 6459},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 353, col: 21, offset: 6478},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 353, col: 23, offset: 6480},
							label: "Constant",
							expr: &ruleRefExpr{
								pos:  position{line: 353, col: 32, offset: 6489},
								name: "Constant",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 353, col: 41, offset: 6498},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 353, col: 43, offset: 6500},
							label: "QueryOptions",
							expr: &zeroOrOneExpr{
								pos: position{line: 353, col: 56, offset: 6513},
								expr: &ruleRefExpr{
									pos:  position{line: 353, col: 56, offset: 6513},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 353, col: 70, offset: 6527},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 366, col: 1, offset: 6748},
			expr: &actionExpr{
				pos: position{line: 367, col: 2, offset: 6772},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 367, col: 2, offset: 6772},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 367, col: 2, offset: 6772},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 367, col: 20, offset: 6790},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 367, col: 22, offset: 6792},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 367, col: 30, offset: 6800},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 367, col: 38, offset: 6808},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 367, col: 40, offset: 6810},
							label: "QueryOptions",
							expr: &zeroOrOneExpr{
								pos: position{line: 367, col: 53, offset: 6823},
								expr: &ruleRefExpr{
									pos:  position{line: 367, col: 53, offset: 6823},
									name: "QueryOptions",
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 367, col: 67, offset: 6837},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOptions",
			pos:  position{line: 380, col: 1, offset: 7058},
			expr: &actionExpr{
				pos: position{line: 381, col: 2, offset: 7075},
				run: (*parser).callonQueryOptions1,
				expr: &seqExpr{
					pos: position{line: 381, col: 2, offset: 7075},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 381, col: 2, offset: 7075},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 381, col: 6, offset: 7079},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 381, col: 8, offset: 7081},
							label: "QueryOptions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 381, col: 22, offset: 7095},
								expr: &ruleRefExpr{
									pos:  position{line: 381, col: 22, offset: 7095},
									name: "QueryOption",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 381, col: 36, offset: 7109},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 381, col: 40, offset: 7113},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "QueryOption",
			pos:  position{line: 389, col: 1, offset: 7255},
			expr: &actionExpr{
				pos: position{line: 390, col: 2, offset: 7271},
				run: (*parser).callonQueryOption1,
				expr: &seqExpr{
					pos: position{line: 390, col: 2, offset: 7271},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 390, col: 2, offset: 7271},
							label: "OptionName",
							expr: &ruleRefExpr{
								pos:  position{line: 390, col: 13, offset: 7282},
								name: "Identifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 390, col: 24, offset: 7293},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 390, col: 26, offset: 7295},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 390, col: 30, offset: 7299},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 390, col: 32, offset: 7301},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 390, col: 40, offset: 7309},
								name: "Message",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 390, col: 48, offset: 7317},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 390, col: 50, offset: 7319},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 390, col: 54, offset: 7323},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Identifier",
			pos:  position{line: 402, col: 1, offset: 7573},
			expr: &actionExpr{
				pos: position{line: 403, col: 2, offset: 7588},
				run: (*parser).callonIdentifier1,
				expr: &labeledExpr{
					pos:   position{line: 403, col: 2, offset: 7588},
					label: "Identifier",
					expr: &oneOrMoreExpr{
						pos: position{line: 403, col: 13, offset: 7599},
						expr: &charClassMatcher{
							pos:        position{line: 403, col: 13, offset: 7599},
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
			pos:  position{line: 408, col: 1, offset: 7647},
			expr: &actionExpr{
				pos: position{line: 409, col: 2, offset: 7659},
				run: (*parser).callonComment1,
				expr: &seqExpr{
					pos: position{line: 409, col: 2, offset: 7659},
					exprs: []interface{}{
						&ruleRefExpr{
							pos:  position{line: 409, col: 2, offset: 7659},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 409, col: 4, offset: 7661},
							val:        "//",
							ignoreCase: false,
						},
						&zeroOrMoreExpr{
							pos: position{line: 409, col: 9, offset: 7666},
							expr: &charClassMatcher{
								pos:        position{line: 409, col: 9, offset: 7666},
								val:        "[^\\n]",
								chars:      []rune{'\n'},
								ignoreCase: false,
								inverted:   true,
							},
						},
						&ruleRefExpr{
							pos:  position{line: 409, col: 16, offset: 7673},
							name: "_",
						},
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 414, col: 1, offset: 7697},
			expr: &zeroOrMoreExpr{
				pos: position{line: 414, col: 19, offset: 7715},
				expr: &charClassMatcher{
					pos:        position{line: 414, col: 19, offset: 7715},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 416, col: 1, offset: 7727},
			expr: &notExpr{
				pos: position{line: 416, col: 8, offset: 7734},
				expr: &anyMatcher{
					line: 416, col: 9, offset: 7735,
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
	name := strings.ToLower(Name.(string))
	err := parserCheckIfReserved(name)
	return block{
		kind: "principal",
		principal: principal{
			name:        strings.Title(name),
			expressions: de,
		},
	}, err
}

func (p *parser) callonPrincipal1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onPrincipal1(stack["Name"], stack["Expressions"])
}

func (c *current) onPrincipalName1(Name interface{}) (interface{}, error) {
	return strings.Title(Name.(string)), nil
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

func (c *current) onMessage1(Sender, Recipient, MessageConstants interface{}) (interface{}, error) {
	var err error
	sender := strings.ToLower(Sender.(string))
	recipient := strings.ToLower(Recipient.(string))
	for _, s := range []string{sender, recipient} {
		err = parserCheckIfReserved(s)
		if err != nil {
			break
		}
	}
	return block{
		kind: "message",
		message: message{
			sender:    strings.Title(sender),
			recipient: strings.Title(recipient),
			constants: MessageConstants.([]constant),
		},
	}, err
}

func (p *parser) callonMessage1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onMessage1(stack["Sender"], stack["Recipient"], stack["MessageConstants"])
}

func (c *current) onMessageConstants1(MessageConstants interface{}) (interface{}, error) {
	var da []constant
	var err error
	a := MessageConstants.([]interface{})
	for _, v := range a {
		c := v.(value).constant
		err = parserCheckIfReserved(c.name)
		da = append(da, c)
	}
	return da, err
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

func (c *current) onAssignment1(Left, Right interface{}) (interface{}, error) {
	var err error
	right := value{}
	switch Right.(value).kind {
	case "constant":
		err = errors.New("cannot assign value to value")
	default:
		right = Right.(value)
	}
	return expression{
		kind:  "assignment",
		left:  Left.([]constant),
		right: right,
	}, err
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
			name: strings.ToLower(Constant.(string)),
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
		da = append(da, c.(value).constant)
	}
	for _, c := range da {
		err = parserCheckIfReserved(c.name)
	}
	return da, err
}

func (p *parser) callonConstants1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onConstants1(stack["Constants"])
}

func (c *current) onPhase1(Number interface{}) (interface{}, error) {
	var err error
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

func (c *current) onGuardedConstant1(GuardedConstant interface{}) (interface{}, error) {
	return value{
		kind: "constant",
		constant: constant{
			name:  strings.ToLower(GuardedConstant.(string)),
			guard: true,
		},
	}, nil
}

func (p *parser) callonGuardedConstant1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onGuardedConstant1(stack["GuardedConstant"])
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

func (c *current) onEquation1(FirstConstant, SecondConstant interface{}) (interface{}, error) {
	return value{
		kind: "equation",
		equation: equation{
			values: []value{
				FirstConstant.(value),
				SecondConstant.(value),
			},
		},
	}, nil
}

func (p *parser) callonEquation1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onEquation1(stack["FirstConstant"], stack["SecondConstant"])
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

func (c *current) onQueryConfidentiality1(Constant, QueryOptions interface{}) (interface{}, error) {
	if QueryOptions == nil {
		QueryOptions = []queryOption{}
	}
	return query{
		kind:     "confidentiality",
		constant: Constant.(value).constant,
		message:  message{},
		options:  QueryOptions.([]queryOption),
	}, nil
}

func (p *parser) callonQueryConfidentiality1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryConfidentiality1(stack["Constant"], stack["QueryOptions"])
}

func (c *current) onQueryAuthentication1(Message, QueryOptions interface{}) (interface{}, error) {
	if QueryOptions == nil {
		QueryOptions = []queryOption{}
	}
	return query{
		kind:     "authentication",
		constant: constant{},
		message:  (Message.(block)).message,
		options:  QueryOptions.([]queryOption),
	}, nil
}

func (p *parser) callonQueryAuthentication1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryAuthentication1(stack["Message"], stack["QueryOptions"])
}

func (c *current) onQueryOptions1(QueryOptions interface{}) (interface{}, error) {
	o := QueryOptions.([]interface{})
	do := make([]queryOption, len(o))
	for i, v := range o {
		do[i] = v.(queryOption)
	}
	return do, nil
}

func (p *parser) callonQueryOptions1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryOptions1(stack["QueryOptions"])
}

func (c *current) onQueryOption1(OptionName, Message interface{}) (interface{}, error) {
	kind := strings.ToLower(OptionName.(string))
	if kind != "precondition" {
		fmt.Errorf("invalid query option kind: %s", kind)
	}
	return queryOption{
		kind:    strings.ToLower(OptionName.(string)),
		message: (Message.(block)).message,
	}, nil
}

func (p *parser) callonQueryOption1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryOption1(stack["OptionName"], stack["Message"])
}

func (c *current) onIdentifier1(Identifier interface{}) (interface{}, error) {
	return string(c.text), nil
}

func (p *parser) callonIdentifier1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onIdentifier1(stack["Identifier"])
}

func (c *current) onComment1() (interface{}, error) {
	return nil, nil
}

func (p *parser) callonComment1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onComment1()
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
