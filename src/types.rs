/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) enum VerifpalError {
	Parse(Cow<'static, str>),
	Sanity(Cow<'static, str>),
	Resolution(Cow<'static, str>),
	Internal(Cow<'static, str>),
}

impl fmt::Display for VerifpalError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			VerifpalError::Parse(s) => write!(f, "parse error: {}", s),
			VerifpalError::Sanity(s) => write!(f, "sanity error: {}", s),
			VerifpalError::Resolution(s) => write!(f, "resolution error: {}", s),
			VerifpalError::Internal(s) => write!(f, "{}", s),
		}
	}
}

impl std::error::Error for VerifpalError {}

impl From<String> for VerifpalError {
	fn from(s: String) -> Self {
		VerifpalError::Internal(s.into())
	}
}

impl From<&'static str> for VerifpalError {
	fn from(s: &'static str) -> Self {
		VerifpalError::Internal(s.into())
	}
}

pub(crate) type VResult<T> = Result<T, VerifpalError>;

pub(crate) type PrincipalId = u8;
pub(crate) type ValueId = u32;
pub(crate) type PrimitiveId = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Qualifier {
	Public,
	Private,
	Password,
}

impl fmt::Display for Qualifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Qualifier::Public => f.write_str("public"),
			Qualifier::Private => f.write_str("private"),
			Qualifier::Password => f.write_str("password"),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Declaration {
	Knows,
	Generates,
	Assignment,
	Leaks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum QueryKind {
	Confidentiality,
	Authentication,
	Freshness,
	Unlinkability,
	Equivalence,
}

impl QueryKind {
	pub(crate) fn name(self) -> &'static str {
		match self {
			QueryKind::Confidentiality => "confidentiality",
			QueryKind::Authentication => "authentication",
			QueryKind::Freshness => "freshness",
			QueryKind::Unlinkability => "unlinkability",
			QueryKind::Equivalence => "equivalence",
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum QueryOptionKind {
	Precondition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum InfoLevel {
	Verifpal,
	Info,
	Analysis,
	Deduction,
	Result,
	Pass,
	Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AttackerKind {
	Active,
	Passive,
}

impl std::fmt::Display for AttackerKind {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AttackerKind::Active => write!(f, "active"),
			AttackerKind::Passive => write!(f, "passive"),
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) enum Value {
	Constant(Constant),
	Primitive(Arc<Primitive>),
	Equation(Arc<Equation>),
}

impl Value {
	pub(crate) fn as_constant(&self) -> Option<&Constant> {
		match self {
			Value::Constant(c) => Some(c),
			_ => None,
		}
	}

	pub(crate) fn as_primitive(&self) -> Option<&Primitive> {
		match self {
			Value::Primitive(p) => Some(p),
			_ => None,
		}
	}

	pub(crate) fn as_equation(&self) -> Option<&Equation> {
		match self {
			Value::Equation(e) => Some(e),
			_ => None,
		}
	}

	pub(crate) fn as_primitive_mut(&mut self) -> Option<&mut Primitive> {
		match self {
			Value::Primitive(p) => Some(Arc::make_mut(p)),
			_ => None,
		}
	}

	#[allow(dead_code)]
	pub(crate) fn try_as_constant(&self) -> VResult<&Constant> {
		match self {
			Value::Constant(c) => Ok(c),
			_ => Err(VerifpalError::Internal(
				format!("expected Constant, got {}", self.variant_name()).into(),
			)),
		}
	}

	pub(crate) fn try_as_primitive(&self) -> VResult<&Primitive> {
		match self {
			Value::Primitive(p) => Ok(p),
			_ => Err(VerifpalError::Internal(
				format!("expected Primitive, got {}", self.variant_name()).into(),
			)),
		}
	}

	pub(crate) fn try_as_equation(&self) -> VResult<&Equation> {
		match self {
			Value::Equation(e) => Ok(e),
			_ => Err(VerifpalError::Internal(
				format!("expected Equation, got {}", self.variant_name()).into(),
			)),
		}
	}

	#[allow(dead_code)]
	pub(crate) fn try_as_primitive_mut(&mut self) -> VResult<&mut Primitive> {
		match self {
			Value::Primitive(p) => Ok(Arc::make_mut(p)),
			_ => Err(VerifpalError::Internal(
				format!("expected Primitive, got {}", self.variant_name()).into(),
			)),
		}
	}

	fn variant_name(&self) -> &'static str {
		match self {
			Value::Constant(_) => "Constant",
			Value::Primitive(_) => "Primitive",
			Value::Equation(_) => "Equation",
		}
	}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Constant {
	pub name: Arc<str>,
	pub id: ValueId,
	pub guard: bool,
	pub fresh: bool,
	pub leaked: bool,
	pub declaration: Option<Declaration>,
	pub qualifier: Option<Qualifier>,
}

#[derive(Clone, Debug)]
pub(crate) struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub instance_check: bool,
}

impl Primitive {
	/// Create a copy with different arguments, preserving id/output/instance_check.
	pub(crate) fn with_arguments(&self, arguments: Vec<Value>) -> Self {
		Primitive {
			id: self.id,
			arguments,
			output: self.output,
			instance_check: self.instance_check,
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Equation {
	pub values: Vec<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct Model {
	pub file_name: String,
	pub attacker: AttackerKind,
	pub blocks: Vec<Block>,
	pub queries: Vec<Query>,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifyResult {
	pub query: Query,
	pub query_index: usize,
	pub resolved: bool,
	pub summary: String,
	pub options: Vec<QueryOptionResult>,
}

impl VerifyResult {
	pub(crate) fn new(query: &Query, query_index: usize) -> Self {
		VerifyResult {
			query: query.clone(),
			query_index,
			resolved: false,
			summary: String::new(),
			options: vec![],
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) enum Block {
	Principal(Principal),
	Message(Message),
	Phase(Phase),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Principal {
	pub name: String,
	pub id: PrincipalId,
	pub expressions: Vec<Expression>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Message {
	pub sender: PrincipalId,
	pub recipient: PrincipalId,
	pub constants: Vec<Constant>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Phase {
	pub number: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct Query {
	pub kind: QueryKind,
	pub constants: Vec<Constant>,
	pub message: Message,
	pub options: Vec<QueryOption>,
}

#[derive(Clone, Debug)]
pub(crate) struct QueryOption {
	pub kind: QueryOptionKind,
	pub message: Message,
}

#[derive(Clone, Debug)]
pub(crate) struct QueryOptionResult {
	pub resolved: bool,
	pub summary: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Expression {
	pub kind: Declaration,
	pub qualifier: Option<Qualifier>,
	pub constants: Vec<Constant>,
	pub assigned: Option<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct TraceSlot {
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	pub known_by: Vec<HashMap<PrincipalId, PrincipalId>>,
	pub declared_at: i32,
	pub phases: Vec<i32>,
}

impl TraceSlot {
	pub(crate) fn known_by_principal(&self, pid: PrincipalId) -> bool {
		self.creator == pid || self.known_by.iter().any(|m| m.contains_key(&pid))
	}
}

#[derive(Clone, Debug)]
pub(crate) struct ProtocolTrace {
	pub principals: Vec<String>,
	pub principal_ids: Vec<PrincipalId>,
	pub slots: Vec<TraceSlot>,
	pub index: HashMap<ValueId, usize>,
	pub max_declared_at: i32,
	pub max_phase: i32,
	pub used_by: HashMap<ValueId, HashMap<PrincipalId, bool>>,
}

/// Immutable per-constant metadata (shared via Arc across clones).
#[derive(Clone, Debug)]
pub(crate) struct SlotMeta {
	pub constant: Constant,
	pub guard: bool,
	pub known: bool,
	pub wire: Vec<PrincipalId>,
	pub known_by: Vec<HashMap<PrincipalId, PrincipalId>>,
	pub declared_at: i32,
	pub mutatable_to: Vec<PrincipalId>,
	pub phase: Vec<i32>,
}

/// Mutable per-constant values (deep-cloned for each active attacker stage).
///
/// The three value fields track different points in the value's lifecycle:
///
/// - **`before_mutate`**: the value as originally computed by the protocol,
///   before the active attacker tampered with it.  This is what the principal
///   "thinks" the value is — used during resolution for values the principal
///   created itself or hasn't received over a wire (see `should_use_before_mutate`).
///
/// - **`before_rewrite`**: the value after attacker mutation but before
///   cryptographic rewriting (e.g. `AEAD_DEC(k, AEAD_ENC(k, m, ad), ad)` is
///   not yet rewritten to `m`).  Used for forensic tracing and narrative output.
///
/// - **`assigned`**: the fully resolved current value after mutation and
///   rewriting.  This is what the verification engine uses for analysis.
///
/// The distinction between `before_mutate` and `assigned` is critical for
/// correctness: without it, principals would "see" the attacker's mutations
/// in their own locally-computed values, causing false positives in
/// authentication queries.
#[derive(Clone, Debug)]
pub(crate) struct SlotValues {
	pub assigned: Value,
	pub before_rewrite: Value,
	pub before_mutate: Value,
	pub mutated: bool,
	pub rewritten: bool,
	pub creator: PrincipalId,
	pub sender: PrincipalId,
}

impl SlotValues {
	/// Set `assigned` and, if the slot has not been mutated, also `before_mutate`.
	pub(crate) fn set_assigned(&mut self, v: Value) {
		if !self.mutated {
			self.before_mutate = v.clone();
		}
		self.assigned = v;
	}

	/// Unconditionally override all value fields (assigned, before_rewrite, before_mutate).
	pub(crate) fn override_all(&mut self, v: Value) {
		self.before_mutate = v.clone();
		self.before_rewrite = v.clone();
		self.assigned = v;
	}
}

#[derive(Clone, Debug)]
pub(crate) struct PrincipalState {
	pub name: String,
	pub id: PrincipalId,
	pub max_declared_at: i32,
	pub meta: Arc<Vec<SlotMeta>>,
	pub values: Vec<SlotValues>,
	pub index: Arc<HashMap<ValueId, usize>>,
}

impl PrincipalState {
	/// Whether slot `i` should resolve to `before_mutate` rather than `assigned`.
	/// Returns true for values that the principal perceives as original:
	/// - created by this principal itself
	/// - not known to this principal
	/// - not received over a wire by this principal
	/// - not actually mutated by the attacker
	pub(crate) fn should_use_before_mutate(&self, i: usize) -> bool {
		self.values[i].creator == self.id
			|| !self.meta[i].known
			|| !self.meta[i].wire.contains(&self.id)
			|| !self.values[i].mutated
	}

	/// The value that this principal perceives for slot `i`.
	pub(crate) fn effective_value(&self, i: usize) -> &Value {
		if self.should_use_before_mutate(i) {
			&self.values[i].before_mutate
		} else {
			&self.values[i].assigned
		}
	}
}

/// A single slot that differs from the protocol trace initial value.
/// Captured at the time the attacker learns a value, for forensic tracing.
#[derive(Clone, Debug)]
pub(crate) struct SlotDiff {
	pub index: usize,
	pub constant: Constant,
	pub assigned: Value,
	pub mutated: bool,
}

/// Compact forensic record stored alongside each attacker-known value.
/// Records only the slots where the PrincipalState differed from the
/// protocol trace at the time the value was learned by the attacker.
#[derive(Clone, Debug)]
pub(crate) struct MutationRecord {
	pub diffs: Vec<SlotDiff>,
}

#[derive(Clone, Debug)]
pub(crate) struct AttackerState {
	pub current_phase: i32,
	pub exhausted: bool,
	pub known: Arc<Vec<Value>>,
	pub known_map: Arc<HashMap<u64, Vec<usize>>>,
	pub skeleton_hashes: Arc<HashSet<u64>>,
	pub mutation_records: Arc<Vec<MutationRecord>>,
}

impl Default for AttackerState {
	fn default() -> Self {
		AttackerState {
			current_phase: 0,
			exhausted: false,
			known: Arc::new(vec![]),
			known_map: Arc::new(HashMap::new()),
			skeleton_hashes: Arc::new(HashSet::new()),
			mutation_records: Arc::new(vec![]),
		}
	}
}

impl AttackerState {
	pub(crate) fn new() -> Self {
		Self::default()
	}
}

#[derive(Clone, Debug)]
pub(crate) struct MutationMap {
	pub out_of_mutations: bool,
	pub constants: Vec<Constant>,
	pub mutations: Vec<Vec<Value>>,
	pub combination: Vec<Value>,
	pub depth_index: Vec<usize>,
}

/// Result of a successful decomposition: the revealed value and the
/// attacker-known values that were used to perform the decomposition.
pub(crate) struct DecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

/// Result of a successful recomposition: the revealed value and the
/// attacker-known values that were used to perform the recomposition.
pub(crate) struct RecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

/// Result of rewriting a primitive or equation value.
pub(crate) struct RewriteResult {
	/// Primitives whose rewrite rules failed (checked primitives that
	/// did not pass their instance check).
	pub failed_rewrites: Vec<Primitive>,
	/// Whether any rewriting actually occurred.
	pub rewritten: bool,
	/// The (possibly rewritten) value.
	pub value: Value,
}
