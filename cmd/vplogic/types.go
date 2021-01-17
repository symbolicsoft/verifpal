/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 6dc5ca957dc5760bba97d4d8a0fe4adf

package vplogic

type typesEnum uint8

const (
	typesEnumEmpty           typesEnum = iota
	typesEnumConstant        typesEnum = iota
	typesEnumPrimitive       typesEnum = iota
	typesEnumEquation        typesEnum = iota
	typesEnumPrivate         typesEnum = iota
	typesEnumPublic          typesEnum = iota
	typesEnumPassword        typesEnum = iota
	typesEnumKnows           typesEnum = iota
	typesEnumGenerates       typesEnum = iota
	typesEnumAssignment      typesEnum = iota
	typesEnumLeaks           typesEnum = iota
	typesEnumConfidentiality typesEnum = iota
	typesEnumAuthentication  typesEnum = iota
	typesEnumFreshness       typesEnum = iota
	typesEnumUnlinkability   typesEnum = iota
	typesEnumPrecondition    typesEnum = iota
)

type valueEnum uint16

type principalEnum uint8

// Model is the main parsed representation of the Verifpal model.
type Model struct {
	FileName string
	Attacker string
	Blocks   []Block
	Queries  []Query
}

//VerifyResult contains the verification results for a particular query.
type VerifyResult struct {
	Query    Query
	Resolved bool
	Summary  string
	Options  []QueryOptionResult
}

// Block represents a principal, message or phase declaration in a Verifpal model.
type Block struct {
	Kind      string
	Principal Principal
	Message   Message
	Phase     Phase
}

// Principal represents a principal declaration in a Verifpal model.
type Principal struct {
	Name        string
	ID          principalEnum
	Expressions []Expression
}

// Message represents a message declaration in a Verifpal model.
type Message struct {
	Sender    principalEnum
	Recipient principalEnum
	Constants []*Constant
}

// Phase represents a phase declaration in a Verifpal model.
type Phase struct {
	Number int
}

// Query represents a query declaration in a Verifpal model.
type Query struct {
	Kind      typesEnum
	Constants []*Constant
	Message   Message
	Options   []QueryOption
}

// QueryOption represents a query option (i.e. precondition) declaration in a Verifpal model.
type QueryOption struct {
	Kind    typesEnum
	Message Message
}

// QueryOptionResult represents the analysis result of a QueryOption.
type QueryOptionResult struct {
	Option   QueryOption
	Resolved bool
	Summary  string
}

// Expression represents one of the following kinds of expressions:
// - "knows": `knows [qualifier] [constants]`, eg. "knows private x"
// - "generates": `generates [constants]`, eg. "generates x, y"
// - "assignment": `[constants] = [value]`, eg. "x, y = HKDF(a, b, c)"
// - "leaks": `leaks [constants]`, eg. "leaks x"
type Expression struct {
	Kind      typesEnum
	Qualifier typesEnum
	Constants []*Constant
	Assigned  *Value
}

// Value represents either a constant, primitive or equation expression.
type Value struct {
	Kind typesEnum
	Data interface{}
}

// Constant represents a constant expression:
// - Name indicates the name of the constant.
// - ID indicates an internal ID for the constant.
// - Guard indicates if this is a guarded constant.
// - Fresh indicates if this is a "fresh" (i.e. generated) constant.
// - Leaked indicates if this constant has been leaked.
// - Declaration indicates how the constant was declared.
// - Qualifier indicates the "knows" qualifier (eg. "private").
type Constant struct {
	Name        string
	ID          valueEnum
	Guard       bool
	Fresh       bool
	Leaked      bool
	Declaration typesEnum
	Qualifier   typesEnum
}

// Primitive represents a primitive expression:
// - ID indicates the internal enum ID of the primitives.
// - Arguments indicates the arguments of the primitive.
// - Output indicates which output value of the primitive this copy should rewrite to (starts at 0).
// - Check indicates whether this has been a checked primitive.
type Primitive struct {
	ID        primitiveEnum
	Arguments []*Value
	Output    int
	Check     bool
}

// Equation represents an equation expression.
type Equation struct {
	Values []*Value
}

// KnowledgeMap represents Verifpal's internal map of knowledge of the model.
// It is constructed at the very beginning before Verifpal analysis commences
// and after the model is checked to be parseable, sane and error-free.
// After it is created, the KnowledgeMap structure is never changed.
// In what follows, Constants, Assigned, Creator, KnownBy, DeclaredAt and Phase
// operate as related columns, i.e. the n'th slice element in each of them
// corresponds to the n'th slice element in the other.
// - Principals contains the names of all model principals.
// - Constants contains all the constants within the model.
// - Assigned represents the values to which constants are assigned.
// - Creator represents the name of the principal who first declared the constant.
// - KnownBy is a map documenting from whom each principal came to know the constant.
// - DeclaredAt documents how many messages had passed before the constant was declared.
// - MaxDeclaredAt documents the maximum possible value for DeclaredAt.
// - Phase documents at which phase the constant was declared.
// - MaxPhase documents the maximum possible phase in the model.
type KnowledgeMap struct {
	Principals    []string
	PrincipalIDs  []principalEnum
	Constants     []*Constant
	Assigned      []*Value
	Creator       []principalEnum
	KnownBy       [][]map[principalEnum]principalEnum
	DeclaredAt    []int
	MaxDeclaredAt int
	Phase         [][]int
	MaxPhase      int
}

// PrincipalState represents the discrete state of each principal in a model.
// Each principal has their own PrincipalState, which continuously may be mutated
// by the active attacker under a set of rules as analysis progresses.
// Verifpal generates a new PrincipalState for each principal at each stage of the analysis.
// In that follows, Constants, Assigned, Guard, Known, Wire, KnownBy, DeclaredAt,
// Creator, Sender, Rewritten, BeforeRewrite, Mutated, MutatableTo, BeforeMutate and Phase
// operate as related columns, i.e. the n'th slice element in each of them
// corresponds to the n'th slice element in the other.
// - Name contains the name of the principal for whom this PrincipalState belongs to.
// - Constants contains all the constants within the model.
// - Assigned represents the values to which constants are assigned.
//   This may be mutated by the active attacker during analysis.
// - Guard represents whether this value was guarded when this principal received it.
// - Known represents whether this principal ever gains knowledge of this value.
// - Wire represents the list of principals who received this constant over the wire (as a message).
// - KnownBy is a map documenting from whom each principal came to know the constant.
// - DeclaredAt documents how many messages had passed before the constant was declared.
// - MaxDeclaredAt documents the maximum possible value for DeclaredAt.
// - Creator represents the name of the principal who first declared the constant.
// - Sender represents which principal it was who sent this constant to this principal.
// - Rewritten tracks whether this value could be rewritten (eg. from `DEC(k,ENC(k,m))` to `m`).
//   The rewritten value is then stored in Assigned.
// - BeforeRewrite tracks the value before it was rewritten.
// - Mutated tracks whether this value could be mutated by the active attacker (eg. from `G^a` to `G^nil`).
//   The mutated value is then stored in Assigned.
// - MutatableTo tracks the principal for whom it is possible for this value to ever be mutated.
// - BeforeMutate tracks the value before it was mutated.
// - Phase documents at which phase the constant was declared.
type PrincipalState struct {
	Name          string
	ID            principalEnum
	Constants     []*Constant
	Assigned      []*Value
	Guard         []bool
	Known         []bool
	Wire          [][]principalEnum
	KnownBy       [][]map[principalEnum]principalEnum
	DeclaredAt    []int
	MaxDeclaredAt int
	Creator       []principalEnum
	Sender        []principalEnum
	Rewritten     []bool
	BeforeRewrite []*Value
	Mutated       []bool
	MutatableTo   [][]principalEnum
	BeforeMutate  []*Value
	Phase         [][]int
}

// DecomposeRule contains a primitive's DecomposeRule.
type DecomposeRule struct {
	HasRule bool
	Given   []int
	Reveal  int
	Filter  func(*Primitive, *Value, int) (*Value, bool)
}

// RecomposeRule contains a primitive's RecomposeRule.
type RecomposeRule struct {
	HasRule bool
	Given   [][]int
	Reveal  int
	Filter  func(*Primitive, *Value, int) (*Value, bool)
}

// RewriteRule contains a primitive's RewriteRule.
type RewriteRule struct {
	HasRule  bool
	ID       primitiveEnum
	From     int
	To       func(*Primitive) *Value
	Matching map[int][]int
	Filter   func(*Primitive, *Value, int) (*Value, bool)
}

// RebuildRule contains a primitive's RebuildRule.
type RebuildRule struct {
	HasRule bool
	ID      primitiveEnum
	Given   [][]int
	Reveal  int
	Filter  func(*Primitive, *Value, int) (*Value, bool)
}

// PrimitiveCoreSpec contains the definition of a core primitive.
type PrimitiveCoreSpec struct {
	Name      string
	ID        primitiveEnum
	Arity     []int
	Output    []int
	HasRule   bool
	CoreRule  func(*Primitive) (bool, []*Value)
	Check     bool
	Explosive bool
}

// PrimitiveSpec contains the definition of a primitive.
type PrimitiveSpec struct {
	Name            string
	ID              primitiveEnum
	Arity           []int
	Output          []int
	Decompose       DecomposeRule
	Recompose       RecomposeRule
	Rewrite         RewriteRule
	Rebuild         RebuildRule
	Check           bool
	Explosive       bool
	PasswordHashing []int
}

// AttackerState contains the attacker's state during model analysis.
// In what follows, Known and PrincipalState operate as related columns,
// i.e. the n'th slice element in each of them corresponds to the n'th
// slice element in the other:
// - Active tracks whether this is an active attacker.
// - CurrentPhase tracks the phase at which the analysis is currently occurring.
// - Known tracks the values learned by the attacker.
// - PrincipalState contains a snapshot of the principal's PrincipalState at the moment
//   where the corresponding value in Known was learned by the attacker.
type AttackerState struct {
	Active         bool
	CurrentPhase   int
	Exhausted      bool
	Known          []*Value
	PrincipalState []*PrincipalState
}

// MutationMap contains the map of mutations that the attacker plans to
// apply to a PrincipalState.
// In what follows, Constants, Mutations and Combination operate as
// related columns, i.e. the n'th slice element in each of them
// corresponds to the n'th slice element in the other:
// - Initialized tracks whether this MutationMap has been populated.
// - OutOfMutations tracks whether all of the mutations in this map
//   have been applied to its corresponding PrincipalState.
// - Constants tracks the constant which will be mutated.
// - Mutations tracks the possible mutations for this constant in
//   the PrincipalState.
// Combination and DepthIndex are internal values to track the
// combinatorial state of the MutationMAp.
type MutationMap struct {
	Initialized    bool
	OutOfMutations bool
	LastIncrement  int
	Constants      []*Constant
	Mutations      [][]*Value
	Combination    []*Value
	DepthIndex     []int
}

// PvTemplate is a structure that helps contain parts of the
// ProVerif model which may be generated by Verifpal.
type PvTemplate struct {
	Parameters func(string) string
	Types      func() string
	Constants  func(*KnowledgeMap, string) string
	CorePrims  func() string
	Prims      func() string
	Channels   func(*KnowledgeMap) string
	Queries    func(*KnowledgeMap, []Query) (string, error)
	TopLevel   func([]Block) string
}
