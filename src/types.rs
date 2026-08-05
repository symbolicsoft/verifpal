/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

/// A half-open byte range in the model source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
	pub start: usize,
	pub end: usize,
}

impl Span {
	pub fn new(start: usize, end: usize) -> Self {
		Span { start, end }
	}

	pub fn at(pos: usize) -> Self {
		Span {
			start: pos,
			end: pos,
		}
	}

	/// One-based line and column of `start` within `source`. The column counts
	/// characters, not bytes, so it matches what an editor shows.
	pub fn line_col(&self, source: &str) -> (usize, usize) {
		let (line, start, _) = self.line_bounds(source);
		let col = source[start..self.start.min(source.len())].chars().count() + 1;
		(line, col)
	}

	/// `(one-based line, byte offset of its start, byte offset of its end)`.
	fn line_bounds(&self, source: &str) -> (usize, usize, usize) {
		let at = self.start.min(source.len());
		let upto = &source.as_bytes()[..at];
		let line = upto.iter().filter(|&&b| b == b'\n').count() + 1;
		let start = upto
			.iter()
			.rposition(|&b| b == b'\n')
			.map(|i| i + 1)
			.unwrap_or(0);
		let end = source[at..]
			.find('\n')
			.map(|i| at + i)
			.unwrap_or(source.len());
		(line, start, end)
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
	Parse,
	Sanity,
	Resolution,
	Internal,
}

impl ErrorKind {
	pub fn label(self) -> &'static str {
		match self {
			ErrorKind::Parse => "parse error",
			ErrorKind::Sanity => "sanity error",
			ErrorKind::Resolution => "resolution error",
			ErrorKind::Internal => "internal error",
		}
	}
}

#[derive(Clone, Debug)]
pub struct VerifpalError {
	pub kind: ErrorKind,
	pub message: Cow<'static, str>,
	pub span: Option<Span>,
	/// Set once the source is in hand, so `Display` can show file, line and
	/// column to callers that only ever print the error.
	rendered: Option<String>,
}

impl VerifpalError {
	pub fn parse(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Parse, message)
	}

	pub fn sanity(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Sanity, message)
	}

	pub fn resolution(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Resolution, message)
	}

	pub fn internal(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Internal, message)
	}

	fn of(kind: ErrorKind, message: Cow<'static, str>) -> Self {
		VerifpalError {
			kind,
			message,
			span: None,
			rendered: None,
		}
	}

	pub fn at(mut self, span: Span) -> Self {
		self.span = Some(span);
		self
	}

	/// Attach `span` only if the error does not already carry a narrower one,
	/// so an inner error keeps its own position as the stack unwinds.
	pub fn or_span(mut self, span: Span) -> Self {
		self.span.get_or_insert(span);
		self
	}

	/// Fold the source location into the message, so plain `Display` shows it.
	pub fn located(mut self, file_name: &str, source: &str) -> Self {
		self.rendered = Some(self.render(file_name, source));
		self
	}

	/// `file:line:col: kind: message`, with the offending line and a caret.
	pub fn render(&self, file_name: &str, source: &str) -> String {
		let Some(span) = self.span else {
			return format!("{}: {}: {}", file_name, self.kind.label(), self.message);
		};
		let (line, col) = span.line_col(source);
		let mut out = format!(
			"{}:{}:{}: {}: {}",
			file_name,
			line,
			col,
			self.kind.label(),
			self.message
		);
		// Tabs are shown as one space and the caret padding counts characters,
		// so the caret lands under the span even on a tab-indented line.
		let (_, line_start, line_end) = span.line_bounds(source);
		let text = &source[line_start..line_end];
		let at = span.start.min(source.len());
		let lead = source[line_start..at].chars().count();
		let width = source[at..span.end.min(line_end)].chars().count().max(1);
		out.push_str(&format!(
			"\n  {}\n  {}{}",
			text.replace('\t', " "),
			" ".repeat(lead),
			"^".repeat(width)
		));
		out
	}
}

impl fmt::Display for VerifpalError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if let Some(rendered) = &self.rendered {
			return write!(f, "{}", rendered);
		}
		match self.kind {
			ErrorKind::Internal => write!(f, "{}", self.message),
			kind => write!(f, "{}: {}", kind.label(), self.message),
		}
	}
}

impl std::error::Error for VerifpalError {}

impl From<String> for VerifpalError {
	fn from(s: String) -> Self {
		VerifpalError::internal(s.into())
	}
}

impl From<&'static str> for VerifpalError {
	fn from(s: &'static str) -> Self {
		VerifpalError::internal(s.into())
	}
}

pub type VResult<T> = Result<T, VerifpalError>;

/// An index into a principal's slots — equivalently, into `ProtocolTrace::slots`,
/// which every `PrincipalState` is built parallel to.
///
/// Distinct from [`KnownIdx`] so the two index spaces cannot be swapped: a
/// mutation record stores slot indices but is *found* by a knowledge index, and
/// both used to be a bare `usize`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotIdx(pub usize);

impl SlotIdx {
	pub fn get(self) -> usize {
		self.0
	}
}

impl fmt::Display for SlotIdx {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// An index into `AttackerState::known` and the arrays parallel to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KnownIdx(pub usize);

impl KnownIdx {
	pub fn get(self) -> usize {
		self.0
	}
}

pub type PrincipalId = u8;
pub type ValueId = u32;
pub type PrimitiveId = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Qualifier {
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
pub enum CommentStyle {
	Line,
	Block,
}

#[derive(Clone, Debug)]
pub struct Comment {
	pub text: String,
	pub style: CommentStyle,
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

	pub fn try_as_primitive(&self) -> VResult<&Primitive> {
		match self {
			Value::Primitive(p) => Ok(p),
			_ => Err(VerifpalError::internal(
				format!("expected Primitive, got {}", self.variant_name()).into(),
			)),
		}
	}

	pub fn try_as_equation(&self) -> VResult<&Equation> {
		match self {
			Value::Equation(e) => Ok(e),
			_ => Err(VerifpalError::internal(
				format!("expected Equation, got {}", self.variant_name()).into(),
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
pub struct Constant {
	pub name: Arc<str>,
	pub id: ValueId,
	pub guard: bool,
	pub fresh: bool,
	pub leaked: bool,
	pub declaration: Option<Declaration>,
	pub qualifier: Option<Qualifier>,
}

#[derive(Clone, Debug)]
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub instance_check: bool,
}

impl Primitive {
	pub fn with_arguments(&self, arguments: Vec<Value>) -> Self {
		Primitive {
			id: self.id,
			arguments,
			output: self.output,
			instance_check: self.instance_check,
		}
	}

	/// Rebuild with `f` applied to each argument, returning `None` when every
	/// argument was unchanged.
	///
	/// `f` returns `Some` only for an argument it actually changed, so a caller
	/// that cares about a subset — rewriting only touches nested primitives —
	/// pays nothing for the rest.
	pub fn map_arguments(&self, mut f: impl FnMut(&Value) -> Option<Value>) -> Option<Primitive> {
		let mut changed: Option<Vec<Value>> = None;
		for (i, a) in self.arguments.iter().enumerate() {
			if let Some(mapped) = f(a) {
				changed.get_or_insert_with(|| self.arguments.clone())[i] = mapped;
			}
		}
		changed.map(|arguments| self.with_arguments(arguments))
	}

	/// As [`Self::map_arguments`], for a mapping that can fail.
	pub fn try_map_arguments(
		&self,
		mut f: impl FnMut(&Value) -> VResult<Option<Value>>,
	) -> VResult<Option<Primitive>> {
		let mut changed: Option<Vec<Value>> = None;
		for (i, a) in self.arguments.iter().enumerate() {
			if let Some(mapped) = f(a)? {
				changed.get_or_insert_with(|| self.arguments.clone())[i] = mapped;
			}
		}
		Ok(changed.map(|arguments| self.with_arguments(arguments)))
	}
}

#[derive(Clone, Debug)]
pub struct Equation {
	pub values: Vec<Value>,
}

/// Model source text. Debug-prints as a size so that dumping a `Model` does
/// not dump the whole file.
#[derive(Clone, Default)]
pub struct Source(pub Arc<str>);

impl fmt::Debug for Source {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "<{} bytes>", self.0.len())
	}
}

impl std::ops::Deref for Source {
	type Target = str;
	fn deref(&self) -> &str {
		&self.0
	}
}

impl From<&str> for Source {
	fn from(s: &str) -> Self {
		Source(Arc::from(s))
	}
}

#[derive(Clone, Debug)]
pub struct Model {
	pub file_name: String,
	/// The text this model was parsed from, so an error can quote its own line.
	pub source: Source,
	pub attacker: AttackerKind,
	pub blocks: Vec<Block>,
	pub queries: Vec<Query>,
	pub pre_attacker_comments: Vec<Comment>,
	pub attacker_trailing: Option<Comment>,
	pub queries_leading_comments: Vec<Comment>,
	pub queries_header_trailing: Option<Comment>,
	pub queries_tail_comments: Vec<Comment>,
	pub queries_closing_trailing: Option<Comment>,
	pub tail_comments: Vec<Comment>,
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

	/// Produce a compact result code string (e.g. `"c1a0f1"`).
	/// One char per query type + `1` (attack found) or `0` (holds).
	pub fn results_code(results: &[VerifyResult]) -> String {
		let mut code = String::with_capacity(results.len() * 2);
		for r in results {
			code.push(match r.query.kind {
				QueryKind::Confidentiality => 'c',
				QueryKind::Authentication => 'a',
				QueryKind::Freshness => 'f',
				QueryKind::Unlinkability => 'u',
				QueryKind::Equivalence => 'e',
			});
			code.push(if r.resolved { '1' } else { '0' });
		}
		code
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
	pub span: Span,
	pub expressions: Vec<Expression>,
	pub leading_comments: Vec<Comment>,
	pub header_trailing: Option<Comment>,
	pub tail_comments: Vec<Comment>,
	pub closing_trailing: Option<Comment>,
}

/// Names ride alongside the ids so rendering never needs a process-wide
/// id-to-name table; `Display for Query` in particular cannot take one.
#[derive(Clone, Debug)]
pub struct Message {
	pub span: Span,
	pub sender: PrincipalId,
	pub sender_name: Arc<str>,
	pub recipient: PrincipalId,
	pub recipient_name: Arc<str>,
	pub constants: Vec<Constant>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}

impl Default for Message {
	fn default() -> Self {
		Message {
			span: Span::default(),
			sender: 0,
			sender_name: Arc::from(""),
			recipient: 0,
			recipient_name: Arc::from(""),
			constants: Vec::new(),
			leading_comments: Vec::new(),
			trailing_comment: None,
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct Phase {
	pub number: i32,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}

#[derive(Clone, Debug)]
pub struct Query {
	pub span: Span,
	pub kind: QueryKind,
	pub constants: Vec<Constant>,
	pub message: Message,
	pub options: Vec<QueryOption>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}

impl Query {
	/// Errors rather than indexing: a violated invariant must not become a
	/// query that silently reports as holding.
	pub fn subject(&self) -> VResult<&Constant> {
		self.constants.first().ok_or_else(|| {
			VerifpalError::internal(
				format!("{} query carries no constant", self.kind.name()).into(),
			)
		})
	}
}

impl Message {
	pub fn constant(&self) -> VResult<&Constant> {
		self.constants
			.first()
			.ok_or_else(|| VerifpalError::internal("query message carries no constant".into()))
	}
}

#[derive(Clone, Debug)]
pub struct QueryOption {
	pub kind: QueryOptionKind,
	pub message: Message,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}

#[derive(Clone, Debug)]
pub struct QueryOptionResult {
	pub resolved: bool,
	pub summary: String,
}

#[derive(Clone, Debug)]
pub struct Expression {
	pub span: Span,
	pub kind: Declaration,
	pub qualifier: Option<Qualifier>,
	pub constants: Vec<Constant>,
	pub assigned: Option<Value>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}

#[derive(Clone, Debug)]
pub struct TraceSlot {
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	/// Each entry is (recipient, sender): "recipient learned this value from sender."
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub declared_at: i32,
	pub phases: Vec<i32>,
}

impl TraceSlot {
	pub fn known_by_principal(&self, pid: PrincipalId) -> bool {
		self.creator == pid || self.known_by.iter().any(|&(recipient, _)| recipient == pid)
	}
}

#[derive(Clone, Debug, Default)]
pub struct ProtocolTrace {
	pub principals: Vec<String>,
	pub principal_ids: Vec<PrincipalId>,
	pub slots: Vec<TraceSlot>,
	pub index: HashMap<ValueId, usize>,
	pub max_declared_at: i32,
	pub max_phase: i32,
	pub used_by: HashMap<ValueId, HashMap<PrincipalId, bool>>,
	pub leaks: Arc<Vec<LeakEvent>>,
}

#[derive(Clone, Debug)]
pub struct LeakEvent {
	pub constant_id: ValueId,
	pub principal_id: PrincipalId,
	pub declared_at: i32,
	pub phase: i32,
}

/// Immutable per-constant metadata (shared via Arc across clones).
#[derive(Clone, Debug)]
pub struct SlotMeta {
	pub constant: Constant,
	pub guard: bool,
	pub known: bool,
	pub wire: Vec<PrincipalId>,
	/// Each entry is (recipient, sender): "recipient learned this value from sender."
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub declared_at: i32,
	pub mutatable_to: Vec<PrincipalId>,
	pub phase: Vec<i32>,
}

#[derive(Clone, Debug)]
pub struct Provenance {
	/// Principal who originally computed/generated this value.
	pub creator: PrincipalId,
	/// Principal who sent this value to the current principal.
	/// Equals creator if the value was never communicated.
	/// Equals ATTACKER_ID if the attacker injected a replacement.
	pub sender: PrincipalId,
	pub attacker_tainted: bool,
	/// Whether the attacker put its own key here to defeat a guard it could
	/// bypass — the man-in-the-middle on a signed or guarded public key.
	///
	/// Kept apart from `attacker_tainted` deliberately.  Taint decides which
	/// value a principal perceives (`should_use_original`), and a guard bypass
	/// must not change that: the principal genuinely computed with what it was
	/// handed.  This flag exists so the substitution is still *reportable* —
	/// without it the single most important step of a MITM trace, the attacker
	/// swapping in its own long-term key, is invisible to the narrator.
	pub bypass_injected: bool,
}

/// The three points in a slot's lifecycle that the engine has to tell apart:
///
/// - `original`: what the protocol honestly computed, before the attacker
///   tampered with it — what the principal believes the value is.
/// - `pre_rewrite`: after mutation, before cryptographic rewriting, so
///   `AEAD_DEC(k, AEAD_ENC(k, m, ad), ad)` still reads as itself. Narration
///   quotes this.
/// - `value`: after mutation and rewriting. Analysis uses this.
///
/// Conflating `original` and `value` is what causes false authentication
/// attacks: principals would "see" the attacker's tampering inside their own
/// locally-computed values.
#[derive(Clone, Debug)]
pub struct SlotValues {
	pub value: Value,
	pub pre_rewrite: Value,
	pub original: Value,
	pub rewritten: bool,
	pub provenance: Provenance,
}

impl SlotValues {
	/// Set `value` and, if the slot has not been tainted, also `original`.
	pub fn set_value(&mut self, v: Value) {
		if !self.provenance.attacker_tainted {
			self.original = v.clone();
		}
		self.value = v;
	}

	pub fn override_all(&mut self, v: Value) {
		self.original = v.clone();
		self.pre_rewrite = v.clone();
		self.value = v;
	}

	/// As [`Self::override_all`], marking the slot as a guard the attacker
	/// bypassed by supplying its own key.  Reporting only — see
	/// [`Provenance::bypass_injected`].
	pub fn override_all_bypassed(&mut self, v: Value) {
		self.override_all(v);
		self.provenance.bypass_injected = true;
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
	/// All `leaks` declarations in the protocol, shared read-only across
	/// principal states.  Used by `rule_equivalize` to suppress leaks that
	/// follow a halted-at point.
	pub leaks: Arc<Vec<LeakEvent>>,
	/// If set, the `declared_at` of the earliest checked-primitive failure
	/// encountered after attacker mutation.  Any `leaks` with a strictly
	/// greater `declared_at` by this same principal is treated as never
	/// having fired.  `None` means the principal executed cleanly.
	pub halted_at: Option<i32>,
}

impl PrincipalState {
	/// Whether slot `i` should resolve to `original` rather than `value`.
	pub fn should_use_original(&self, i: usize) -> bool {
		!self.values[i].provenance.attacker_tainted
			|| self.values[i].provenance.creator == self.id
			|| !self.meta[i].known
			|| !self.meta[i].wire.contains(&self.id)
	}

	/// The value that this principal perceives for slot `i`.
	pub fn effective_value(&self, i: usize) -> &Value {
		if self.should_use_original(i) {
			&self.values[i].original
		} else {
			&self.values[i].value
		}
	}
}

/// A single slot that differs from the protocol trace's initial value.
#[derive(Clone, Debug)]
pub struct SlotDiff {
	pub index: SlotIdx,
	pub constant: Constant,
	pub value: Value,
	pub tainted: bool,
}

/// The slots that had to differ for the attacker to hold a value, and whose
/// session they differed in — narration needs both to attribute a set of
/// mutations to a run.
#[derive(Clone, Debug)]
pub struct MutationRecord {
	pub diffs: Vec<SlotDiff>,
	pub principal_id: PrincipalId,
	pub phase: i32,
}

/// How the attacker came to hold a value.
///
/// Each deduction rule already renders exactly this into its `Deduction ›`
/// line; recording it lets the narrator walk the real derivation instead of
/// reconstructing a plausible one.  Slot indices refer to the
/// `PrincipalState` the value was learned from.
#[derive(Clone, Debug)]
pub enum DerivationRecord {
	/// Public, declared, or otherwise held from the start of the phase.
	Initial,
	/// Handed over by a `leaks` declaration.
	Leaked { slot: SlotIdx },
	/// Read off the wire, or equivalized against a slot's resolution.
	Obtained { slot: SlotIdx },
	/// Recovered from inside `of` using the values in `using`.
	Decomposed { of: Value, using: Vec<Value> },
	/// Rebuilt from `from`, all of which the attacker already held.
	Reconstructed { from: Vec<Value> },
	/// Recovered by combining enough shares of `of`.
	Recomposed { of: Value, using: Vec<Value> },
	/// A password used without a password hash inside `from`.
	PasswordExtracted { from: Value },
	/// A fragment of a concatenation, which reveals its arguments.
	ConcatFragment { of: Value },
	/// A skeleton template injected so the attacker can shape a forgery.
	Injected,
}

impl DerivationRecord {
	/// The attacker-held values this derivation consumed.
	pub fn ingredients(&self) -> Vec<&Value> {
		match self {
			DerivationRecord::Decomposed { of, using }
			| DerivationRecord::Recomposed { of, using } => {
				let mut v = vec![of];
				v.extend(using.iter());
				v
			}
			DerivationRecord::Reconstructed { from } => from.iter().collect(),
			DerivationRecord::PasswordExtracted { from } => vec![from],
			DerivationRecord::ConcatFragment { of } => vec![of],
			DerivationRecord::Initial
			| DerivationRecord::Leaked { .. }
			| DerivationRecord::Obtained { .. }
			| DerivationRecord::Injected => vec![],
		}
	}

	/// Whether the state the attacker was looking at is part of why this value
	/// became derivable.
	///
	/// Reading a value out of a principal's state — off the wire, from a leak,
	/// or by rebuilding a term whose *shape* that state defines — depends on
	/// the substitutions in force there.  Combining values the attacker already
	/// holds does not: a decryption needs the ciphertext and the key, and the
	/// substitutions that earned those are recorded against them.
	pub fn reads_from_state(&self) -> bool {
		matches!(
			self,
			DerivationRecord::Leaked { .. }
				| DerivationRecord::Obtained { .. }
				| DerivationRecord::Reconstructed { .. }
		)
	}
}

#[derive(Clone, Debug)]
pub struct AttackerState {
	pub current_phase: i32,
	pub known: Arc<Vec<Value>>,
	pub known_map: Arc<HashMap<u64, Vec<usize>>>,
	pub skeleton_hashes: Arc<HashSet<u64>>,
	pub mutation_records: Arc<Vec<Arc<MutationRecord>>>,
	/// Parallel to `known`: how each value was derived.
	pub derivations: Arc<Vec<DerivationRecord>>,
}

impl Default for AttackerState {
	fn default() -> Self {
		AttackerState {
			current_phase: 0,
			known: Arc::new(vec![]),
			known_map: Arc::new(HashMap::new()),
			skeleton_hashes: Arc::new(HashSet::new()),
			mutation_records: Arc::new(vec![]),
			derivations: Arc::new(vec![]),
		}
	}
}

impl AttackerState {
	pub fn new() -> Self {
		Self::default()
	}
}

/// Result of a successful decomposition: the revealed value and the
/// attacker-known values that were used to perform the decomposition.
pub struct DecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

/// Result of a successful recomposition: the revealed value and the
/// attacker-known values that were used to perform the recomposition.
pub struct RecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

/// Result of rewriting a primitive or equation value.
pub struct RewriteResult {
	/// Primitives whose rewrite rules failed (checked primitives that
	/// did not pass their instance check).
	pub failed_rewrites: Vec<Primitive>,
	/// Whether any rewriting actually occurred.
	pub rewritten: bool,
	/// The (possibly rewritten) value.
	pub value: Value,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;
	use crate::value::*;
	use std::sync::Arc;

	#[test]
	fn value_accessors() {
		let c = make_constant("acc_c");
		let p = make_primitive(PRIM_HASH, vec![c.clone()], 0);
		let e = make_equation(vec![value_g(), c.clone()]);

		assert!(c.as_constant().is_some());
		assert!(c.as_primitive().is_none());
		assert!(c.as_equation().is_none());

		assert!(p.as_primitive().is_some());
		assert!(p.as_constant().is_none());

		assert!(e.as_equation().is_some());
		assert!(e.as_constant().is_none());
	}

	#[test]
	fn value_try_accessors() {
		let c = make_constant("try_c");
		assert!(c.as_constant().is_some());
		assert!(c.try_as_primitive().is_err());
		assert!(c.try_as_equation().is_err());
	}

	#[test]
	fn principal_state_should_use_original_creator() {
		let c = Constant {
			name: Arc::from("ps_fbm_a"),
			id: test_value_id("ps_fbm_a"),
			..Constant::default()
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&make_constant("ps_fbm_a"), 0)]; // creator == self.id
		let ps = make_principal_state("Alice", 0, meta, values);
		assert!(ps.should_use_original(0)); // creator == self
	}

	#[test]
	fn principal_state_effective_value_not_mutated() {
		let c = Constant {
			name: Arc::from("ps_ev_a"),
			id: test_value_id("ps_ev_a"),
			..Constant::default()
		};
		let val = make_constant("ps_ev_a");
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		assert!(ps.effective_value(0).equivalent(&val, true));
	}

	#[test]
	fn principal_state_effective_value_mutated() {
		let c = Constant {
			name: Arc::from("ps_evm_a"),
			id: test_value_id("ps_evm_a"),
			..Constant::default()
		};
		let original = make_constant("ps_evm_a");
		let mutated = make_constant("ps_evm_mutated");
		let mut meta = make_slot_meta(&c, false);
		meta.wire = vec![1]; // received by principal 1
		let mut sv = make_slot_values(&mutated, 0);
		sv.original = original.clone();
		sv.provenance.attacker_tainted = true;
		sv.provenance.creator = 0; // different from ps.id=1
		let ps = make_principal_state("Bob", 1, vec![meta], vec![sv]);
		// Bob (id=1) received this on wire, and it was mutated
		// Since creator(0) != self(1), known=true, wire contains self(1), and mutated=true,
		// should_use_original returns false, so effective_value = value (tainted)
		assert!(ps.effective_value(0).equivalent(&mutated, true));
	}

	#[test]
	fn primitive_with_arguments() {
		let a = make_constant("pwa_a");
		let b = make_constant("pwa_b");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![a],
			output: 0,
			instance_check: true,
		};
		let p2 = p.with_arguments(vec![b.clone()]);
		assert_eq!(p2.id, PRIM_ENC);
		assert_eq!(p2.output, 0);
		assert!(p2.instance_check);
		assert!(p2.arguments[0].equivalent(&b, true));
	}

	#[test]
	fn slot_values_set_value_not_tainted() {
		let v1 = make_constant("sv_v1");
		let v2 = make_constant("sv_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.set_value(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v2, true)); // also updated when not tainted
	}

	#[test]
	fn slot_values_set_value_tainted() {
		let v1 = make_constant("svm_v1");
		let v2 = make_constant("svm_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.provenance.attacker_tainted = true;
		sv.set_value(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v1, true)); // NOT updated when tainted
	}

	#[test]
	fn slot_values_override_all() {
		let v1 = make_constant("svo_v1");
		let v2 = make_constant("svo_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.provenance.attacker_tainted = true;
		sv.override_all(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.pre_rewrite.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v2, true)); // overridden regardless of tainted
	}

	#[test]
	fn error_display() {
		let e = VerifpalError::parse("bad input".into());
		assert_eq!(format!("{}", e), "parse error: bad input");
		let e2 = VerifpalError::resolution("not found".into());
		assert_eq!(format!("{}", e2), "resolution error: not found");
	}

	#[test]
	fn trace_slot_known_by_creator() {
		let c = Constant {
			name: Arc::from("ts_a"),
			id: test_value_id("ts_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(0)); // creator
		assert!(!slot.known_by_principal(1)); // not creator, not in known_by
	}

	#[test]
	fn trace_slot_known_by_receiver() {
		let c = Constant {
			name: Arc::from("ts2_a"),
			id: test_value_id("ts2_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![(1, 0)],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(1)); // in known_by
	}

	#[test]
	fn mutation_record_empty() {
		let record = MutationRecord {
			diffs: vec![],
			principal_id: 0,
			phase: 0,
		};
		assert!(record.diffs.is_empty());
	}

	#[test]
	fn query_kind_names() {
		assert_eq!(QueryKind::Confidentiality.name(), "confidentiality");
		assert_eq!(QueryKind::Authentication.name(), "authentication");
		assert_eq!(QueryKind::Freshness.name(), "freshness");
		assert_eq!(QueryKind::Unlinkability.name(), "unlinkability");
		assert_eq!(QueryKind::Equivalence.name(), "equivalence");
	}
}

#[cfg(test)]
mod span_tests {
	use super::*;

	const SRC: &str = "attacker[active]\n\nprincipal Alice[\n\tknows private m\n]\n";

	#[test]
	fn line_col_is_one_based_and_counts_characters() {
		assert_eq!(Span::at(0).line_col(SRC), (1, 1));
		assert_eq!(Span::at(17).line_col(SRC), (2, 1));
		// Byte 18 is the start of line 3.
		assert_eq!(Span::at(18).line_col(SRC), (3, 1));
		let unicode = "principal Amélié[\n\tknows private m\n]\n";
		// The column counts characters, so the accented name does not shift it.
		let after_name = unicode.find('[').expect("bracket");
		assert_eq!(Span::at(after_name).line_col(unicode).1, 17);
	}

	#[test]
	fn render_points_a_caret_at_the_span() {
		let at_knows = SRC.find("knows").expect("knows");
		let e = VerifpalError::sanity("bad".into()).at(Span::new(at_knows, at_knows + 5));
		let rendered = e.render("m.vp", SRC);
		assert!(
			rendered.starts_with("m.vp:4:2: sanity error: bad"),
			"{rendered}"
		);
		let caret_line = rendered.lines().last().expect("caret line");
		// Two spaces of gutter, one for the tab, then the caret under `knows`.
		assert_eq!(caret_line, "   ^^^^^");
	}

	#[test]
	fn an_error_without_a_span_still_renders() {
		let e = VerifpalError::sanity("bad".into());
		assert_eq!(e.render("m.vp", SRC), "m.vp: sanity error: bad");
	}

	#[test]
	fn or_span_keeps_the_narrower_inner_location() {
		let inner = VerifpalError::parse("inner".into()).at(Span::at(5));
		let outer = inner.or_span(Span::at(99));
		assert_eq!(outer.span, Some(Span::at(5)));
	}

	#[test]
	fn located_errors_display_with_their_position() {
		let e = VerifpalError::sanity("bad".into())
			.at(Span::at(0))
			.located("m.vp", SRC);
		assert!(e.to_string().starts_with("m.vp:1:1: sanity error: bad"));
	}
}
