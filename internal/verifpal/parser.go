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
	"strings"
	"unicode"
	"unicode/utf8"
)

func parserParseModel(filename string) (Model, knowledgeMap, []principalState) {
	var m Model
	prettyMessage(fmt.Sprintf(
		"Parsing model \"%s\"...",
		path.Base(filename),
	), 0, "verifpal")
	parsed, err := ParseFile(filename)
	if err != nil {
		errorCritical(err.Error())
	}
	m = parsed.(Model)
	valKnowledgeMap, valPrincipalStates := sanity(m)
	return m, valKnowledgeMap, valPrincipalStates
}

func reserved() []string {
	return []string{
		"attacker",
		"passive",
		"active",
		"principal",
		"public",
		"private",
		"queries",
		"confidentiality",
		"authentication",
		"primitive",
		"dh",
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
}

var g = &grammar{
	rules: []*rule{
		{
			name: "Verifpal",
			pos:  position{line: 71, col: 1, offset: 1213},
			expr: &actionExpr{
				pos: position{line: 72, col: 2, offset: 1226},
				run: (*parser).callonVerifpal1,
				expr: &seqExpr{
					pos: position{line: 72, col: 2, offset: 1226},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 72, col: 2, offset: 1226},
							expr: &ruleRefExpr{
								pos:  position{line: 72, col: 2, offset: 1226},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 73, col: 2, offset: 1236},
							label: "Attacker",
							expr: &ruleRefExpr{
								pos:  position{line: 73, col: 11, offset: 1245},
								name: "Attacker",
							},
						},
						&labeledExpr{
							pos:   position{line: 74, col: 2, offset: 1255},
							label: "Blocks",
							expr: &oneOrMoreExpr{
								pos: position{line: 74, col: 10, offset: 1263},
								expr: &ruleRefExpr{
									pos:  position{line: 74, col: 10, offset: 1263},
									name: "Block",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 75, col: 2, offset: 1272},
							label: "Queries",
							expr: &ruleRefExpr{
								pos:  position{line: 75, col: 10, offset: 1280},
								name: "Queries",
							},
						},
						&zeroOrMoreExpr{
							pos: position{line: 76, col: 2, offset: 1289},
							expr: &ruleRefExpr{
								pos:  position{line: 76, col: 2, offset: 1289},
								name: "Comment",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 77, col: 2, offset: 1299},
							name: "EOF",
						},
					},
				},
			},
		},
		{
			name: "Attacker",
			pos:  position{line: 91, col: 1, offset: 1606},
			expr: &actionExpr{
				pos: position{line: 92, col: 2, offset: 1619},
				run: (*parser).callonAttacker1,
				expr: &seqExpr{
					pos: position{line: 92, col: 2, offset: 1619},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 92, col: 2, offset: 1619},
							val:        "attacker",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 92, col: 13, offset: 1630},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 92, col: 15, offset: 1632},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 92, col: 19, offset: 1636},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 93, col: 2, offset: 1639},
							label: "Type",
							expr: &ruleRefExpr{
								pos:  position{line: 93, col: 7, offset: 1644},
								name: "AttackerType",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 93, col: 20, offset: 1657},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 94, col: 2, offset: 1660},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 94, col: 6, offset: 1664},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "AttackerType",
			pos:  position{line: 98, col: 1, offset: 1691},
			expr: &actionExpr{
				pos: position{line: 99, col: 2, offset: 1708},
				run: (*parser).callonAttackerType1,
				expr: &choiceExpr{
					pos: position{line: 99, col: 3, offset: 1709},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 99, col: 3, offset: 1709},
							val:        "active",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 99, col: 12, offset: 1718},
							val:        "passive",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Block",
			pos:  position{line: 103, col: 1, offset: 1764},
			expr: &actionExpr{
				pos: position{line: 104, col: 2, offset: 1774},
				run: (*parser).callonBlock1,
				expr: &seqExpr{
					pos: position{line: 104, col: 2, offset: 1774},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 104, col: 2, offset: 1774},
							expr: &ruleRefExpr{
								pos:  position{line: 104, col: 2, offset: 1774},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 105, col: 2, offset: 1784},
							label: "Block",
							expr: &choiceExpr{
								pos: position{line: 105, col: 9, offset: 1791},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 105, col: 9, offset: 1791},
										name: "Principal",
									},
									&ruleRefExpr{
										pos:  position{line: 105, col: 19, offset: 1801},
										name: "Message",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 105, col: 28, offset: 1810},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 106, col: 2, offset: 1813},
							expr: &ruleRefExpr{
								pos:  position{line: 106, col: 2, offset: 1813},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Principal",
			pos:  position{line: 110, col: 1, offset: 1848},
			expr: &actionExpr{
				pos: position{line: 111, col: 2, offset: 1862},
				run: (*parser).callonPrincipal1,
				expr: &seqExpr{
					pos: position{line: 111, col: 2, offset: 1862},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 111, col: 2, offset: 1862},
							val:        "principal",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 111, col: 14, offset: 1874},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 111, col: 16, offset: 1876},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 111, col: 21, offset: 1881},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 111, col: 35, offset: 1895},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 111, col: 37, offset: 1897},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 111, col: 41, offset: 1901},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 112, col: 2, offset: 1904},
							label: "Expressions",
							expr: &zeroOrMoreExpr{
								pos: position{line: 112, col: 15, offset: 1917},
								expr: &ruleRefExpr{
									pos:  position{line: 112, col: 15, offset: 1917},
									name: "Expression",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 113, col: 2, offset: 1931},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 113, col: 6, offset: 1935},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "PrincipalName",
			pos:  position{line: 136, col: 1, offset: 2467},
			expr: &actionExpr{
				pos: position{line: 137, col: 2, offset: 2485},
				run: (*parser).callonPrincipalName1,
				expr: &labeledExpr{
					pos:   position{line: 137, col: 2, offset: 2485},
					label: "Name",
					expr: &oneOrMoreExpr{
						pos: position{line: 137, col: 7, offset: 2490},
						expr: &charClassMatcher{
							pos:        position{line: 137, col: 7, offset: 2490},
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
			name: "Qualifier",
			pos:  position{line: 144, col: 1, offset: 2655},
			expr: &actionExpr{
				pos: position{line: 145, col: 2, offset: 2669},
				run: (*parser).callonQualifier1,
				expr: &choiceExpr{
					pos: position{line: 145, col: 3, offset: 2670},
					alternatives: []interface{}{
						&litMatcher{
							pos:        position{line: 145, col: 3, offset: 2670},
							val:        "private",
							ignoreCase: false,
						},
						&litMatcher{
							pos:        position{line: 145, col: 13, offset: 2680},
							val:        "public",
							ignoreCase: false,
						},
					},
				},
			},
		},
		{
			name: "Message",
			pos:  position{line: 149, col: 1, offset: 2725},
			expr: &actionExpr{
				pos: position{line: 150, col: 2, offset: 2737},
				run: (*parser).callonMessage1,
				expr: &seqExpr{
					pos: position{line: 150, col: 2, offset: 2737},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 150, col: 2, offset: 2737},
							label: "Sender",
							expr: &ruleRefExpr{
								pos:  position{line: 150, col: 9, offset: 2744},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 150, col: 23, offset: 2758},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 151, col: 2, offset: 2761},
							val:        "->",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 151, col: 7, offset: 2766},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 152, col: 2, offset: 2769},
							label: "Recipient",
							expr: &ruleRefExpr{
								pos:  position{line: 152, col: 12, offset: 2779},
								name: "PrincipalName",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 152, col: 26, offset: 2793},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 153, col: 2, offset: 2796},
							val:        ":",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 153, col: 6, offset: 2800},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 154, col: 2, offset: 2803},
							label: "MessageConstants",
							expr: &ruleRefExpr{
								pos:  position{line: 154, col: 19, offset: 2820},
								name: "MessageConstants",
							},
						},
					},
				},
			},
		},
		{
			name: "MessageConstants",
			pos:  position{line: 178, col: 1, offset: 3449},
			expr: &actionExpr{
				pos: position{line: 179, col: 2, offset: 3470},
				run: (*parser).callonMessageConstants1,
				expr: &labeledExpr{
					pos:   position{line: 179, col: 2, offset: 3470},
					label: "MessageConstants",
					expr: &oneOrMoreExpr{
						pos: position{line: 179, col: 19, offset: 3487},
						expr: &choiceExpr{
							pos: position{line: 179, col: 20, offset: 3488},
							alternatives: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 179, col: 20, offset: 3488},
									name: "GuardedConstant",
								},
								&ruleRefExpr{
									pos:  position{line: 179, col: 36, offset: 3504},
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
			pos:  position{line: 198, col: 1, offset: 3923},
			expr: &actionExpr{
				pos: position{line: 199, col: 2, offset: 3938},
				run: (*parser).callonExpression1,
				expr: &seqExpr{
					pos: position{line: 199, col: 2, offset: 3938},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 199, col: 2, offset: 3938},
							expr: &ruleRefExpr{
								pos:  position{line: 199, col: 2, offset: 3938},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 200, col: 2, offset: 3948},
							label: "Expression",
							expr: &choiceExpr{
								pos: position{line: 200, col: 14, offset: 3960},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 200, col: 14, offset: 3960},
										name: "Assignment",
									},
									&ruleRefExpr{
										pos:  position{line: 200, col: 25, offset: 3971},
										name: "Knows",
									},
									&ruleRefExpr{
										pos:  position{line: 200, col: 31, offset: 3977},
										name: "Generates",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 200, col: 42, offset: 3988},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 201, col: 2, offset: 3991},
							expr: &ruleRefExpr{
								pos:  position{line: 201, col: 2, offset: 3991},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "Knows",
			pos:  position{line: 205, col: 1, offset: 4031},
			expr: &actionExpr{
				pos: position{line: 206, col: 2, offset: 4041},
				run: (*parser).callonKnows1,
				expr: &seqExpr{
					pos: position{line: 206, col: 2, offset: 4041},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 206, col: 2, offset: 4041},
							val:        "knows",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 206, col: 10, offset: 4049},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 207, col: 2, offset: 4053},
							label: "Qualifier",
							expr: &ruleRefExpr{
								pos:  position{line: 207, col: 12, offset: 4063},
								name: "Qualifier",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 207, col: 22, offset: 4073},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 208, col: 2, offset: 4077},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 208, col: 12, offset: 4087},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Generates",
			pos:  position{line: 216, col: 1, offset: 4223},
			expr: &actionExpr{
				pos: position{line: 217, col: 2, offset: 4237},
				run: (*parser).callonGenerates1,
				expr: &seqExpr{
					pos: position{line: 217, col: 2, offset: 4237},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 217, col: 2, offset: 4237},
							val:        "generates",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 217, col: 14, offset: 4249},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 217, col: 16, offset: 4251},
							label: "Constants",
							expr: &ruleRefExpr{
								pos:  position{line: 217, col: 26, offset: 4261},
								name: "Constants",
							},
						},
					},
				},
			},
		},
		{
			name: "Assignment",
			pos:  position{line: 225, col: 1, offset: 4385},
			expr: &actionExpr{
				pos: position{line: 226, col: 2, offset: 4400},
				run: (*parser).callonAssignment1,
				expr: &seqExpr{
					pos: position{line: 226, col: 2, offset: 4400},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 226, col: 2, offset: 4400},
							label: "Left",
							expr: &ruleRefExpr{
								pos:  position{line: 226, col: 7, offset: 4405},
								name: "Constants",
							},
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 17, offset: 4415},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 226, col: 19, offset: 4417},
							val:        "=",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 226, col: 23, offset: 4421},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 226, col: 25, offset: 4423},
							label: "Right",
							expr: &choiceExpr{
								pos: position{line: 226, col: 32, offset: 4430},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 226, col: 32, offset: 4430},
										name: "Primitive",
									},
									&ruleRefExpr{
										pos:  position{line: 226, col: 42, offset: 4440},
										name: "Equation",
									},
									&ruleRefExpr{
										pos:  position{line: 226, col: 51, offset: 4449},
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
			pos:  position{line: 242, col: 1, offset: 4739},
			expr: &actionExpr{
				pos: position{line: 243, col: 2, offset: 4752},
				run: (*parser).callonConstant1,
				expr: &seqExpr{
					pos: position{line: 243, col: 2, offset: 4752},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 243, col: 2, offset: 4752},
							label: "Constant",
							expr: &oneOrMoreExpr{
								pos: position{line: 243, col: 11, offset: 4761},
								expr: &charClassMatcher{
									pos:        position{line: 243, col: 11, offset: 4761},
									val:        "[a-zA-Z0-9_]",
									chars:      []rune{'_'},
									ranges:     []rune{'a', 'z', 'A', 'Z', '0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 243, col: 25, offset: 4775},
							expr: &seqExpr{
								pos: position{line: 243, col: 26, offset: 4776},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 243, col: 26, offset: 4776},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 243, col: 28, offset: 4778},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 243, col: 32, offset: 4782},
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
			pos:  position{line: 255, col: 1, offset: 5016},
			expr: &actionExpr{
				pos: position{line: 256, col: 2, offset: 5030},
				run: (*parser).callonConstants1,
				expr: &labeledExpr{
					pos:   position{line: 256, col: 2, offset: 5030},
					label: "Constants",
					expr: &oneOrMoreExpr{
						pos: position{line: 256, col: 12, offset: 5040},
						expr: &ruleRefExpr{
							pos:  position{line: 256, col: 12, offset: 5040},
							name: "Constant",
						},
					},
				},
			},
		},
		{
			name: "GuardedConstant",
			pos:  position{line: 271, col: 1, offset: 5448},
			expr: &actionExpr{
				pos: position{line: 272, col: 2, offset: 5468},
				run: (*parser).callonGuardedConstant1,
				expr: &seqExpr{
					pos: position{line: 272, col: 2, offset: 5468},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 272, col: 2, offset: 5468},
							val:        "[",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 272, col: 6, offset: 5472},
							label: "GuardedConstant",
							expr: &oneOrMoreExpr{
								pos: position{line: 272, col: 22, offset: 5488},
								expr: &charClassMatcher{
									pos:        position{line: 272, col: 22, offset: 5488},
									val:        "[a-zA-Z0-9_]",
									chars:      []rune{'_'},
									ranges:     []rune{'a', 'z', 'A', 'Z', '0', '9'},
									ignoreCase: false,
									inverted:   false,
								},
							},
						},
						&litMatcher{
							pos:        position{line: 272, col: 36, offset: 5502},
							val:        "]",
							ignoreCase: false,
						},
						&zeroOrOneExpr{
							pos: position{line: 272, col: 40, offset: 5506},
							expr: &seqExpr{
								pos: position{line: 272, col: 41, offset: 5507},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 272, col: 41, offset: 5507},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 272, col: 43, offset: 5509},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 272, col: 47, offset: 5513},
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
			pos:  position{line: 285, col: 1, offset: 5771},
			expr: &actionExpr{
				pos: position{line: 286, col: 2, offset: 5785},
				run: (*parser).callonPrimitive1,
				expr: &seqExpr{
					pos: position{line: 286, col: 2, offset: 5785},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 286, col: 2, offset: 5785},
							label: "Name",
							expr: &ruleRefExpr{
								pos:  position{line: 286, col: 7, offset: 5790},
								name: "PrimitiveName",
							},
						},
						&litMatcher{
							pos:        position{line: 286, col: 21, offset: 5804},
							val:        "(",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 286, col: 25, offset: 5808},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 286, col: 27, offset: 5810},
							label: "Arguments",
							expr: &oneOrMoreExpr{
								pos: position{line: 286, col: 37, offset: 5820},
								expr: &choiceExpr{
									pos: position{line: 286, col: 38, offset: 5821},
									alternatives: []interface{}{
										&ruleRefExpr{
											pos:  position{line: 286, col: 38, offset: 5821},
											name: "Primitive",
										},
										&ruleRefExpr{
											pos:  position{line: 286, col: 48, offset: 5831},
											name: "Equation",
										},
										&ruleRefExpr{
											pos:  position{line: 286, col: 57, offset: 5840},
											name: "Constant",
										},
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 286, col: 68, offset: 5851},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 286, col: 70, offset: 5853},
							val:        ")",
							ignoreCase: false,
						},
						&labeledExpr{
							pos:   position{line: 286, col: 74, offset: 5857},
							label: "Check",
							expr: &zeroOrOneExpr{
								pos: position{line: 286, col: 80, offset: 5863},
								expr: &litMatcher{
									pos:        position{line: 286, col: 80, offset: 5863},
									val:        "?",
									ignoreCase: false,
								},
							},
						},
						&zeroOrOneExpr{
							pos: position{line: 286, col: 85, offset: 5868},
							expr: &seqExpr{
								pos: position{line: 286, col: 86, offset: 5869},
								exprs: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 286, col: 86, offset: 5869},
										name: "_",
									},
									&litMatcher{
										pos:        position{line: 286, col: 88, offset: 5871},
										val:        ",",
										ignoreCase: false,
									},
									&ruleRefExpr{
										pos:  position{line: 286, col: 92, offset: 5875},
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
			pos:  position{line: 302, col: 1, offset: 6155},
			expr: &actionExpr{
				pos: position{line: 303, col: 2, offset: 6173},
				run: (*parser).callonPrimitiveName1,
				expr: &labeledExpr{
					pos:   position{line: 303, col: 2, offset: 6173},
					label: "Name",
					expr: &oneOrMoreExpr{
						pos: position{line: 303, col: 7, offset: 6178},
						expr: &charClassMatcher{
							pos:        position{line: 303, col: 7, offset: 6178},
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
			name: "Equation",
			pos:  position{line: 310, col: 1, offset: 6345},
			expr: &actionExpr{
				pos: position{line: 311, col: 2, offset: 6358},
				run: (*parser).callonEquation1,
				expr: &seqExpr{
					pos: position{line: 311, col: 2, offset: 6358},
					exprs: []interface{}{
						&labeledExpr{
							pos:   position{line: 311, col: 2, offset: 6358},
							label: "FirstConstant",
							expr: &ruleRefExpr{
								pos:  position{line: 311, col: 16, offset: 6372},
								name: "Constant",
							},
						},
						&seqExpr{
							pos: position{line: 311, col: 26, offset: 6382},
							exprs: []interface{}{
								&ruleRefExpr{
									pos:  position{line: 311, col: 26, offset: 6382},
									name: "_",
								},
								&litMatcher{
									pos:        position{line: 311, col: 28, offset: 6384},
									val:        "^",
									ignoreCase: false,
								},
								&ruleRefExpr{
									pos:  position{line: 311, col: 32, offset: 6388},
									name: "_",
								},
							},
						},
						&labeledExpr{
							pos:   position{line: 311, col: 35, offset: 6391},
							label: "SecondConstant",
							expr: &ruleRefExpr{
								pos:  position{line: 311, col: 50, offset: 6406},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "Queries",
			pos:  position{line: 323, col: 1, offset: 6582},
			expr: &actionExpr{
				pos: position{line: 324, col: 2, offset: 6594},
				run: (*parser).callonQueries1,
				expr: &seqExpr{
					pos: position{line: 324, col: 2, offset: 6594},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 324, col: 2, offset: 6594},
							val:        "queries",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 324, col: 12, offset: 6604},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 325, col: 2, offset: 6607},
							val:        "[",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 325, col: 6, offset: 6611},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 326, col: 2, offset: 6614},
							label: "Queries",
							expr: &zeroOrMoreExpr{
								pos: position{line: 326, col: 11, offset: 6623},
								expr: &ruleRefExpr{
									pos:  position{line: 326, col: 11, offset: 6623},
									name: "Query",
								},
							},
						},
						&litMatcher{
							pos:        position{line: 327, col: 2, offset: 6632},
							val:        "]",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 327, col: 6, offset: 6636},
							name: "_",
						},
					},
				},
			},
		},
		{
			name: "Query",
			pos:  position{line: 331, col: 1, offset: 6666},
			expr: &actionExpr{
				pos: position{line: 332, col: 2, offset: 6676},
				run: (*parser).callonQuery1,
				expr: &seqExpr{
					pos: position{line: 332, col: 2, offset: 6676},
					exprs: []interface{}{
						&zeroOrMoreExpr{
							pos: position{line: 332, col: 2, offset: 6676},
							expr: &ruleRefExpr{
								pos:  position{line: 332, col: 2, offset: 6676},
								name: "Comment",
							},
						},
						&labeledExpr{
							pos:   position{line: 333, col: 2, offset: 6686},
							label: "Query",
							expr: &choiceExpr{
								pos: position{line: 333, col: 9, offset: 6693},
								alternatives: []interface{}{
									&ruleRefExpr{
										pos:  position{line: 333, col: 9, offset: 6693},
										name: "QueryConfidentiality",
									},
									&ruleRefExpr{
										pos:  position{line: 333, col: 30, offset: 6714},
										name: "QueryAuthentication",
									},
								},
							},
						},
						&ruleRefExpr{
							pos:  position{line: 333, col: 51, offset: 6735},
							name: "_",
						},
						&zeroOrMoreExpr{
							pos: position{line: 334, col: 2, offset: 6738},
							expr: &ruleRefExpr{
								pos:  position{line: 334, col: 2, offset: 6738},
								name: "Comment",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryConfidentiality",
			pos:  position{line: 338, col: 1, offset: 6774},
			expr: &actionExpr{
				pos: position{line: 339, col: 2, offset: 6799},
				run: (*parser).callonQueryConfidentiality1,
				expr: &seqExpr{
					pos: position{line: 339, col: 2, offset: 6799},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 339, col: 2, offset: 6799},
							val:        "confidentiality?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 339, col: 21, offset: 6818},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 339, col: 23, offset: 6820},
							label: "Constant",
							expr: &ruleRefExpr{
								pos:  position{line: 339, col: 32, offset: 6829},
								name: "Constant",
							},
						},
					},
				},
			},
		},
		{
			name: "QueryAuthentication",
			pos:  position{line: 347, col: 1, offset: 6960},
			expr: &actionExpr{
				pos: position{line: 348, col: 2, offset: 6984},
				run: (*parser).callonQueryAuthentication1,
				expr: &seqExpr{
					pos: position{line: 348, col: 2, offset: 6984},
					exprs: []interface{}{
						&litMatcher{
							pos:        position{line: 348, col: 2, offset: 6984},
							val:        "authentication?",
							ignoreCase: false,
						},
						&ruleRefExpr{
							pos:  position{line: 348, col: 20, offset: 7002},
							name: "_",
						},
						&labeledExpr{
							pos:   position{line: 348, col: 22, offset: 7004},
							label: "Message",
							expr: &ruleRefExpr{
								pos:  position{line: 348, col: 30, offset: 7012},
								name: "Message",
							},
						},
					},
				},
			},
		},
		{
			name: "Comment",
			pos:  position{line: 356, col: 1, offset: 7142},
			expr: &actionExpr{
				pos: position{line: 357, col: 2, offset: 7154},
				run: (*parser).callonComment1,
				expr: &seqExpr{
					pos: position{line: 357, col: 2, offset: 7154},
					exprs: []interface{}{
						&ruleRefExpr{
							pos:  position{line: 357, col: 2, offset: 7154},
							name: "_",
						},
						&litMatcher{
							pos:        position{line: 357, col: 4, offset: 7156},
							val:        "//",
							ignoreCase: false,
						},
						&zeroOrMoreExpr{
							pos: position{line: 357, col: 9, offset: 7161},
							expr: &charClassMatcher{
								pos:        position{line: 357, col: 9, offset: 7161},
								val:        "[^\\n]",
								chars:      []rune{'\n'},
								ignoreCase: false,
								inverted:   true,
							},
						},
						&ruleRefExpr{
							pos:  position{line: 357, col: 16, offset: 7168},
							name: "_",
						},
					},
				},
			},
		},
		{
			name:        "_",
			displayName: "\"whitespace\"",
			pos:         position{line: 361, col: 1, offset: 7194},
			expr: &zeroOrMoreExpr{
				pos: position{line: 361, col: 19, offset: 7212},
				expr: &charClassMatcher{
					pos:        position{line: 361, col: 19, offset: 7212},
					val:        "[ \\t\\n\\r]",
					chars:      []rune{' ', '\t', '\n', '\r'},
					ignoreCase: false,
					inverted:   false,
				},
			},
		},
		{
			name: "EOF",
			pos:  position{line: 363, col: 1, offset: 7224},
			expr: &notExpr{
				pos: position{line: 363, col: 8, offset: 7231},
				expr: &anyMatcher{
					line: 363, col: 9, offset: 7232,
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
	var err error
	e := Expressions.([]interface{})
	de := make([]expression, len(e))
	for i, v := range e {
		de[i] = v.(expression)
	}
	name := strings.ToLower(Name.(string))
	if strInSlice(name, reserved()) ||
		strings.HasPrefix(name, "attacker") ||
		strings.HasPrefix(name, "unnamed") {
		err = fmt.Errorf(
			"cannot use reserved keyword as principal name: %s",
			name,
		)
	}
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
	a := Name.([]interface{})
	da := make([]uint8, len(a))
	for i, v := range a {
		da[i] = v.([]uint8)[0]
	}
	return strings.Title(b2s(da)), nil

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
		if strInSlice(s, reserved()) ||
			strings.HasPrefix(strings.ToLower(s), "attacker") ||
			strings.HasPrefix(strings.ToLower(s), "unnamed") {
			err = fmt.Errorf(
				"cannot use reserved keyword as principal name: %s",
				s,
			)
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
		if strInSlice(c.name, reserved()) ||
			strings.HasPrefix(c.name, "attacker") ||
			strings.HasPrefix(c.name, "unnamed") {
			err = fmt.Errorf(
				"cannot use reserved keyword as constant name: %s",
				c.name,
			)
		}
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
	a := Constant.([]interface{})
	da := make([]uint8, len(a))
	for i, c := range a {
		da[i] = c.([]uint8)[0]
	}
	return value{
		kind: "constant",
		constant: constant{
			name: strings.ToLower(b2s(da)),
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
		if strInSlice(c.name, reserved()) ||
			strings.HasPrefix(c.name, "attacker") ||
			strings.HasPrefix(c.name, "unnamed") {
			err = fmt.Errorf("cannot use reserved keyword as constant name: %s", c.name)
		}
	}
	return da, err

}

func (p *parser) callonConstants1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onConstants1(stack["Constants"])
}

func (c *current) onGuardedConstant1(GuardedConstant interface{}) (interface{}, error) {
	a := GuardedConstant.([]interface{})
	da := make([]uint8, len(a))
	for i, c := range a {
		da[i] = c.([]uint8)[0]
	}
	return value{
		kind: "constant",
		constant: constant{
			name:  strings.ToLower(b2s(da)),
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
	a := Name.([]interface{})
	da := make([]uint8, len(a))
	for i, v := range a {
		da[i] = v.([]uint8)[0]
	}
	return strings.ToUpper(b2s(da)), nil

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

func (c *current) onQueryConfidentiality1(Constant interface{}) (interface{}, error) {
	return query{
		kind:     "confidentiality",
		constant: Constant.(value).constant,
		message:  message{},
	}, nil

}

func (p *parser) callonQueryConfidentiality1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryConfidentiality1(stack["Constant"])
}

func (c *current) onQueryAuthentication1(Message interface{}) (interface{}, error) {
	return query{
		kind:     "authentication",
		constant: constant{},
		message:  (Message.(block)).message,
	}, nil

}

func (p *parser) callonQueryAuthentication1() (interface{}, error) {
	stack := p.vstack[len(p.vstack)-1]
	_ = stack
	return p.cur.onQueryAuthentication1(stack["Message"])
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
