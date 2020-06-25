/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 6dc5ca957dc5760bba97d4d8a0fe4adf

package main

// Model is the main parsed representation of the Verifpal model.
type Model struct {
	FileName string
	Attacker string
	Blocks   []Block
	Queries  []Query
}
type VerifyResult struct {
	Query    Query
	Resolved bool
	Summary  string
	Options  []QueryOptionResult
}

type Block struct {
	Kind      string
	Principal Principal
	Message   Message
	Phase     Phase
}

type Principal struct {
	Name        string
	Expressions []Expression
}

type Message struct {
	Sender    string
	Recipient string
	Constants []Constant
}

type Phase struct {
	Number int
}

type Query struct {
	Kind      string
	Constants []Constant
	Message   Message
	Options   []QueryOption
}

type QueryOption struct {
	Kind    string
	Message Message
}

type QueryOptionResult struct {
	Option   QueryOption
	Resolved bool
	Summary  string
}

type Expression struct {
	Kind      string
	Qualifier string
	Constants []Constant
	Left      []Constant
	Right     Value
}

type Value struct {
	Kind      string
	Constant  Constant
	Primitive Primitive
	Equation  Equation
}

type Constant struct {
	Guard       bool
	Fresh       bool
	Leaked      bool
	Name        string
	Declaration string
	Qualifier   string
}

type Primitive struct {
	Name      string
	Arguments []Value
	Output    int
	Check     bool
}

type Equation struct {
	Values []Value
}

type KnowledgeMap struct {
	Principals []string
	Constants  []Constant
	Assigned   []Value
	Creator    []string
	KnownBy    [][]map[string]string
	DeclaredAt []int
	Phase      [][]int
	MaxPhase   int
}

type DecomposeRule struct {
	HasRule bool
	Given   []int
	Reveal  int
	Filter  func(Primitive, Value, int) (Value, bool)
}

type RecomposeRule struct {
	HasRule bool
	Given   [][]int
	Reveal  int
	Filter  func(Primitive, Value, int) (Value, bool)
}

type RewriteRule struct {
	HasRule  bool
	Name     string
	From     int
	To       func(Primitive) Value
	Matching map[int][]int
	Filter   func(Primitive, Value, int) (Value, bool)
}

type RebuildRule struct {
	HasRule bool
	Name    string
	Given   [][]int
	Reveal  int
	Filter  func(Primitive, Value, int) (Value, bool)
}

type PrimitiveCoreSpec struct {
	Name       string
	Arity      []int
	Output     int
	HasRule    bool
	CoreRule   func(Primitive) (bool, []Value)
	Check      bool
	Injectable bool
	Explosive  bool
}

type PrimitiveSpec struct {
	Name            string
	Arity           []int
	Output          int
	Decompose       DecomposeRule
	Recompose       RecomposeRule
	Rewrite         RewriteRule
	Rebuild         RebuildRule
	Check           bool
	Injectable      bool
	Explosive       bool
	PasswordHashing []int
}

type PrincipalState struct {
	Name          string
	Constants     []Constant
	Assigned      []Value
	Guard         []bool
	Known         []bool
	Wire          [][]string
	KnownBy       [][]map[string]string
	Creator       []string
	Sender        []string
	Rewritten     []bool
	BeforeRewrite []Value
	Mutated       []bool
	MutatableTo   [][]string
	BeforeMutate  []Value
	Phase         [][]int
	Lock          int
}

type AttackerState struct {
	Active       bool
	CurrentPhase int
	Known        []Value
}

type MutationMap struct {
	Initialized    bool
	OutOfMutations bool
	LastIncrement  int
	Constants      []Constant
	Mutations      [][]Value
	Combination    []Value
	DepthIndex     []int
}

type PvTemplate struct {
	Parameters func(string) string
	Types      func() string
	Constants  func(KnowledgeMap, string) string
	CorePrims  func() string
	Prims      func() string
	Channels   func(KnowledgeMap) string
	Queries    func(KnowledgeMap, []Query) string
	TopLevel   func([]Block) string
}
