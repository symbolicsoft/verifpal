/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 6dc5ca957dc5760bba97d4d8a0fe4adf

package verifpal

// Model is the main parsed representation of the Verifpal model.
type Model struct {
	attacker string
	blocks   []block
	queries  []query
}
type verifyResult struct {
	query    query
	resolved bool
	summary  string
}

type block struct {
	kind      string
	principal principal
	message   message
}

type principal struct {
	name        string
	expressions []expression
}

type message struct {
	sender    string
	recipient string
	constants []constant
}

type query struct {
	kind     string
	constant constant
	message  message
}

type expression struct {
	kind      string
	qualifier string
	constants []constant
	left      []constant
	right     value
}

type value struct {
	kind      string
	constant  constant
	primitive primitive
	equation  equation
}

type constant struct {
	name        string
	guard       bool
	declaration string
	qualifier   string
	fresh       bool
}

type primitive struct {
	name      string
	arguments []value
	output    int
	check     bool
}

type equation struct {
	values []value
}

type knowledgeMap struct {
	principals     []string
	constants      []constant
	assigned       []value
	creator        []string
	knownBy        [][]map[string]string
	unnamedCounter int
}

type decomposeRule struct {
	hasRule bool
	given   []int
	reveal  int
	filter  func(value, int, principalState) (value, bool)
}

type recomposeRule struct {
	hasRule bool
	given   [][]int
	reveal  int
	filter  func(value, int, principalState) (value, bool)
}

type rewriteRule struct {
	hasRule  bool
	name     string
	from     int
	to       int
	matching []int
	filter   func(value, int, principalState) (value, bool)
}

type rebuildRule struct {
	hasRule bool
	name    string
	given   [][]int
	reveal  int
	filter  func(value, int, principalState) (value, bool)
}

type primitiveSpec struct {
	name            string
	arity           int
	output          int
	decompose       decomposeRule
	recompose       recomposeRule
	rewrite         rewriteRule
	rebuild         rebuildRule
	check           bool
	injectable      bool
	passwordHashing bool
}

type principalState struct {
	name          string
	constants     []constant
	assigned      []value
	guard         []bool
	known         []bool
	creator       []string
	sender        []string
	wasRewritten  []bool
	beforeRewrite []value
	wasMutated    []bool
	beforeMutate  []value
	lock          int
}

type attackerState struct {
	active    bool
	known     []value
	wire      []bool
	mutatedTo [][]string
}

type attackerStateWrite struct {
	known     value
	wire      bool
	mutatedTo []string
}

type attackerStateMutatedToUpdate struct {
	i         int
	principal string
}

type replacementMap struct {
	initialized       bool
	constants         []constant
	replacements      [][]value
	combination       []value
	depthIndex        []int
	lastIncrement     int
	outOfReplacements bool
}
