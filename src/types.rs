/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum VerifpalError {
	Parse(String),
	Sanity(String),
	Resolution(String),
	Internal(String),
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
		VerifpalError::Internal(s)
	}
}

pub type VResult<T> = Result<T, VerifpalError>;

pub type PrincipalId = u8;
pub type ValueId = u32;
pub type PrimitiveId = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Qualifier {
	Public,
	Private,
	Password,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Declaration {
	Knows,
	Generates,
	Assignment,
	Leaks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryKind {
	Confidentiality,
	Authentication,
	Freshness,
	Unlinkability,
	Equivalence,
}

impl QueryKind {
	pub fn name(self) -> &'static str {
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
pub enum QueryOptionKind {
	Precondition,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InfoLevel {
	Verifpal,
	Info,
	Analysis,
	Deduction,
	Result,
	Pass,
	Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttackerKind {
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
pub enum Value {
	Constant(Constant),
	Primitive(Arc<Primitive>),
	Equation(Arc<Equation>),
}

impl Value {
	pub fn as_constant(&self) -> Option<&Constant> {
		match self {
			Value::Constant(c) => Some(c),
			_ => None,
		}
	}

	pub fn as_primitive(&self) -> Option<&Primitive> {
		match self {
			Value::Primitive(p) => Some(p),
			_ => None,
		}
	}

	pub fn as_equation(&self) -> Option<&Equation> {
		match self {
			Value::Equation(e) => Some(e),
			_ => None,
		}
	}

	pub fn as_primitive_mut(&mut self) -> Option<&mut Primitive> {
		match self {
			Value::Primitive(p) => Some(Arc::make_mut(p)),
			_ => None,
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct Constant {
	pub name: Arc<str>,
	pub id: ValueId,
	pub guard: bool,
	pub fresh: bool,
	pub leaked: bool,
	pub declaration: Option<Declaration>,
	pub qualifier: Option<Qualifier>,
}

impl Constant {
	pub fn empty() -> Self {
		Constant {
			name: Arc::from(""),
			id: 0,
			guard: false,
			fresh: false,
			leaked: false,
			declaration: None,
			qualifier: None,
		}
	}
}

#[derive(Clone, Debug)]
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub check: bool,
}

impl Primitive {
	/// Create a copy with different arguments, preserving id/output/check.
	pub fn with_arguments(&self, arguments: Vec<Value>) -> Self {
		Primitive {
			id: self.id,
			arguments,
			output: self.output,
			check: self.check,
		}
	}
}

#[derive(Clone, Debug)]
pub struct Equation {
	pub values: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct Model {
	pub file_name: String,
	pub attacker: AttackerKind,
	pub blocks: Vec<Block>,
	pub queries: Vec<Query>,
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
	pub query: Query,
	pub query_index: usize,
	pub resolved: bool,
	pub summary: String,
	pub options: Vec<QueryOptionResult>,
}

impl VerifyResult {
	pub fn new(query: &Query, query_index: usize) -> Self {
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
pub enum Block {
	Principal(Principal),
	Message(Message),
	Phase(Phase),
}

#[derive(Clone, Debug, Default)]
pub struct Principal {
	pub name: String,
	pub id: PrincipalId,
	pub expressions: Vec<Expression>,
}

#[derive(Clone, Debug, Default)]
pub struct Message {
	pub sender: PrincipalId,
	pub recipient: PrincipalId,
	pub constants: Vec<Constant>,
}

#[derive(Clone, Debug, Default)]
pub struct Phase {
	pub number: i32,
}

#[derive(Clone, Debug)]
pub struct Query {
	pub kind: QueryKind,
	pub constants: Vec<Constant>,
	pub message: Message,
	pub options: Vec<QueryOption>,
}

#[derive(Clone, Debug)]
pub struct QueryOption {
	pub kind: QueryOptionKind,
	pub message: Message,
}

#[derive(Clone, Debug)]
pub struct QueryOptionResult {
	pub resolved: bool,
	pub summary: String,
}

#[derive(Clone, Debug)]
pub struct Expression {
	pub kind: Declaration,
	pub qualifier: Option<Qualifier>,
	pub constants: Vec<Constant>,
	pub assigned: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct TraceSlot {
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	pub known_by: Vec<HashMap<PrincipalId, PrincipalId>>,
	pub declared_at: i32,
	pub phases: Vec<i32>,
}

impl TraceSlot {
	pub fn known_by_principal(&self, pid: PrincipalId) -> bool {
		self.creator == pid || self.known_by.iter().any(|m| m.contains_key(&pid))
	}
}

#[derive(Clone, Debug)]
pub struct ProtocolTrace {
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
pub struct SlotMeta {
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
#[derive(Clone, Debug)]
pub struct SlotValues {
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
	pub fn set_assigned(&mut self, v: Value) {
		if !self.mutated {
			self.before_mutate = v.clone();
		}
		self.assigned = v;
	}

	/// Unconditionally override all value fields (assigned, before_rewrite, before_mutate).
	pub fn override_all(&mut self, v: Value) {
		self.before_mutate = v.clone();
		self.before_rewrite = v.clone();
		self.assigned = v;
	}
}

#[derive(Clone, Debug)]
pub struct PrincipalState {
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
	pub fn should_use_before_mutate(&self, i: usize) -> bool {
		self.values[i].creator == self.id
			|| !self.meta[i].known
			|| !self.meta[i].wire.contains(&self.id)
			|| !self.values[i].mutated
	}

	/// The value that this principal perceives for slot `i`.
	pub fn effective_value(&self, i: usize) -> &Value {
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
pub struct SlotDiff {
	pub index: usize,
	pub constant: Constant,
	pub assigned: Value,
	pub mutated: bool,
}

/// Compact forensic record stored alongside each attacker-known value.
/// Records only the slots where the PrincipalState differed from the
/// protocol trace at the time the value was learned by the attacker.
#[derive(Clone, Debug)]
pub struct MutationRecord {
	pub diffs: Vec<SlotDiff>,
}

#[derive(Clone, Debug)]
pub struct AttackerState {
	pub current_phase: i32,
	pub exhausted: bool,
	pub known: Arc<Vec<Value>>,
	pub known_map: Arc<HashMap<u64, Vec<usize>>>,
	pub skeleton_hashes: Arc<HashSet<u64>>,
	pub mutation_records: Arc<Vec<MutationRecord>>,
}

impl AttackerState {
	pub fn new() -> Self {
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

#[derive(Clone, Debug)]
pub struct MutationMap {
	pub out_of_mutations: bool,
	pub constants: Vec<Constant>,
	pub mutations: Vec<Vec<Value>>,
	pub combination: Vec<Value>,
	pub depth_index: Vec<usize>,
}
