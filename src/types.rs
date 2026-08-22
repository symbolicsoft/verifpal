/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

pub use crate::capability::{Capabilities, Capability, CapabilityIndex, Reach};

#[derive(Default)]
pub struct IdHasher(u64);

impl Hasher for IdHasher {
	fn finish(&self) -> u64 {
		self.0
	}
	fn write(&mut self, bytes: &[u8]) {
		for &b in bytes {
			self.write_u64(b as u64);
		}
	}
	fn write_u8(&mut self, i: u8) {
		self.write_u64(i as u64);
	}
	fn write_u32(&mut self, i: u32) {
		self.write_u64(i as u64);
	}
	fn write_usize(&mut self, i: usize) {
		self.write_u64(i as u64);
	}
	fn write_u64(&mut self, i: u64) {
		let mut x = self.0.rotate_left(11) ^ i;
		x ^= x >> 33;
		x = x.wrapping_mul(0xff51afd7ed558ccd);
		x ^= x >> 33;
		x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
		self.0 = x ^ (x >> 33);
	}
}

pub type IdMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<IdHasher>>;
pub type IdSet<K> = std::collections::HashSet<K, BuildHasherDefault<IdHasher>>;

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

	pub fn line_col(&self, source: &str) -> (usize, usize) {
		let (line, start, _) = self.line_bounds(source);
		let col = source[start..self.start.min(source.len())].chars().count() + 1;
		(line, col)
	}

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

fn last_line_with_text(source: &str) -> Option<(usize, usize, usize)> {
	let trimmed = source.trim_end();
	if trimmed.is_empty() {
		return None;
	}
	let end = trimmed.len();
	let start = trimmed.rfind('\n').map(|i| i + 1).unwrap_or(0);
	let line = source.as_bytes()[..start]
		.iter()
		.filter(|&&b| b == b'\n')
		.count()
		+ 1;
	Some((line, start, end))
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

#[derive(Clone, Debug, Default)]
struct Diagnostic {
	narrow: Option<Cow<'static, str>>,
	narrow_index: usize,
	primary_label: Option<Cow<'static, str>>,
	labels: Vec<(Span, Cow<'static, str>)>,
	notes: Vec<Cow<'static, str>>,
	helps: Vec<Cow<'static, str>>,
}

#[derive(Clone, Debug)]
pub struct VerifpalError {
	pub kind: ErrorKind,
	pub message: Cow<'static, str>,
	pub span: Option<Span>,
	extra: Option<Box<Diagnostic>>,
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
			extra: None,
			rendered: None,
		}
	}

	fn extra_mut(&mut self) -> &mut Diagnostic {
		self.extra.get_or_insert_with(Box::default)
	}

	pub fn at(mut self, span: Span) -> Self {
		self.span = Some(span);
		self
	}

	pub fn marking(mut self, span: Span, message: impl Into<Cow<'static, str>>) -> Self {
		self.span = Some(span);
		self.extra_mut().primary_label = Some(message.into());
		self
	}

	pub fn narrow(mut self, needle: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().narrow = Some(needle.into());
		self
	}

	pub fn narrow_occurrence(mut self, needle: impl Into<Cow<'static, str>>, index: usize) -> Self {
		let extra = self.extra_mut();
		extra.narrow = Some(needle.into());
		extra.narrow_index = index;
		self
	}

	pub fn labelled(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().primary_label = Some(message.into());
		self
	}

	pub fn label(mut self, span: Span, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().labels.push((span, message.into()));
		self
	}

	pub fn note(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().notes.push(message.into());
		self
	}

	pub fn help(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().helps.push(message.into());
		self
	}

	pub fn suggest(self, candidate: Option<String>) -> Self {
		match candidate {
			Some(name) => self.help(format!("did you mean `{}`?", name)),
			None => self,
		}
	}

	pub fn has_labels(&self) -> bool {
		self.extra.as_ref().is_some_and(|e| !e.labels.is_empty())
	}

	pub fn or_span(mut self, span: Span) -> Self {
		self.span.get_or_insert(span);
		self
	}

	pub fn located(mut self, file_name: &str, source: &str) -> Self {
		self.rendered = Some(self.render(file_name, source));
		self
	}

	pub fn render(&self, file_name: &str, source: &str) -> String {
		let header = match self.kind {
			ErrorKind::Internal => self.message.to_string(),
			kind => format!("{}: {}", kind.label(), self.message),
		};
		let empty = Diagnostic::default();
		let extra = self.extra.as_deref().unwrap_or(&empty);
		let Some(span) = self.span else {
			let mut out = format!("{}\n --> {}", header, file_name);
			self.render_footnotes(&mut out, 1);
			return out;
		};
		let span = extra
			.narrow
			.as_deref()
			.and_then(|needle| narrow_span(span, source, needle, extra.narrow_index))
			.unwrap_or(span);
		let primary = anchored_placement(span, source);
		let mut placements = vec![Placement {
			message: extra.primary_label.as_deref().unwrap_or_default(),
			primary: true,
			..primary
		}];
		for (label_span, message) in &extra.labels {
			placements.push(Placement {
				message,
				primary: false,
				..placement_of(*label_span, source)
			});
		}
		placements.sort_by_key(|p| (p.line, p.column, !p.primary));

		let width = placements
			.iter()
			.map(|p| p.line.to_string().len())
			.max()
			.unwrap_or(1);
		let gutter = " ".repeat(width);
		let mut out = format!(
			"{}\n{}--> {}:{}:{}\n{} |",
			header, gutter, file_name, primary.line, primary.column, gutter
		);

		let mut last_line = 0usize;
		let mut index = 0usize;
		while index < placements.len() {
			let line = placements[index].line;
			if last_line != 0 && line > last_line + 1 {
				out.push_str("\n...");
			}
			out.push_str(&format!(
				"\n{:>width$} | {}",
				line,
				placements[index].text,
				width = width
			));
			while index < placements.len() && placements[index].line == line {
				let p = &placements[index];
				let marker = if p.primary { "^" } else { "-" };
				let tail = if p.message.is_empty() {
					String::new()
				} else {
					format!(" {}", p.message)
				};
				out.push_str(&format!(
					"\n{} | {}{}{}",
					gutter,
					" ".repeat(p.marker_column - 1),
					marker.repeat(p.marker_width),
					tail
				));
				index += 1;
			}
			last_line = line;
		}

		self.render_footnotes(&mut out, width);
		out
	}

	fn render_footnotes(&self, out: &mut String, width: usize) {
		let empty = Diagnostic::default();
		let extra = self.extra.as_deref().unwrap_or(&empty);
		if extra.notes.is_empty() && extra.helps.is_empty() {
			return;
		}
		let gutter = " ".repeat(width);
		if self.span.is_some() {
			out.push_str(&format!("\n{} |", gutter));
		}
		for (tag, entries) in [("note", &extra.notes), ("help", &extra.helps)] {
			for entry in entries.iter() {
				let continuation = format!("\n{}   {}", gutter, " ".repeat(tag.len() + 2));
				let body = entry.replace('\n', &continuation);
				out.push_str(&format!("\n{} = {}: {}", gutter, tag, body));
			}
		}
	}
}

struct Placement<'a> {
	line: usize,
	column: usize,
	marker_column: usize,
	marker_width: usize,
	text: String,
	message: &'a str,
	primary: bool,
}

fn expand_tabs(text: &str) -> String {
	text.replace('\t', "    ")
}

fn narrow_span(span: Span, source: &str, needle: &str, index: usize) -> Option<Span> {
	if needle.is_empty() {
		return None;
	}
	let start = span.start.min(source.len());
	let end = span.end.max(start).min(source.len());
	if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
		return None;
	}
	let haystack = &source[start..end];
	let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
	let bytes = haystack.as_bytes();
	let mut from = 0usize;
	let mut seen = 0usize;
	while let Some(found) = haystack[from..].find(needle) {
		let at = from + found;
		let after = at + needle.len();
		let before_ok = at == 0 || !is_word(bytes[at - 1]);
		let after_ok = after >= bytes.len() || !is_word(bytes[after]);
		if before_ok && after_ok {
			if seen == index {
				return Some(Span::new(start + at, start + after));
			}
			seen += 1;
		}
		from = at + needle.len();
		if from >= haystack.len() {
			break;
		}
	}
	None
}

fn placement_of(span: Span, source: &str) -> Placement<'static> {
	let (line, line_start, line_end) = span.line_bounds(source);
	build_placement(span, source, line, line_start, line_end)
}

fn anchored_placement(span: Span, source: &str) -> Placement<'static> {
	let (line, line_start, line_end) = span.line_bounds(source);
	let at = span.start.min(source.len());
	if source[line_start..line_end].trim().is_empty()
		&& at >= source.trim_end().len()
		&& let Some((anchor_line, anchor_start, anchor_end)) = last_line_with_text(source)
	{
		return build_placement(
			Span::at(anchor_end),
			source,
			anchor_line,
			anchor_start,
			anchor_end,
		);
	}
	build_placement(span, source, line, line_start, line_end)
}

fn build_placement(
	span: Span,
	source: &str,
	line: usize,
	line_start: usize,
	line_end: usize,
) -> Placement<'static> {
	let at = span.start.min(source.len()).max(line_start).min(line_end);
	let upto = span.end.min(line_end).max(at);
	Placement {
		line,
		column: source[line_start..at].chars().count() + 1,
		marker_column: expand_tabs(&source[line_start..at]).chars().count() + 1,
		marker_width: expand_tabs(&source[at..upto]).chars().count().max(1),
		text: expand_tabs(&source[line_start..line_end]),
		message: "",
		primary: false,
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
}

impl Value {
	pub fn primitive(id: PrimitiveId, arguments: Vec<Value>, output: usize) -> Value {
		Value::Primitive(Arc::new(Primitive::new(id, arguments, output)))
	}

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

	pub fn try_as_primitive(&self) -> VResult<&Primitive> {
		match self {
			Value::Primitive(p) => Ok(p),
			_ => Err(VerifpalError::internal(
				format!("expected Primitive, got {}", self.variant_name()).into(),
			)),
		}
	}

	fn variant_name(&self) -> &'static str {
		match self {
			Value::Constant(_) => "Constant",
			Value::Primitive(_) => "Primitive",
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

#[derive(Debug, Default)]
pub struct HashCell(std::sync::atomic::AtomicU64);

impl Clone for HashCell {
	fn clone(&self) -> Self {
		HashCell(std::sync::atomic::AtomicU64::new(
			self.0.load(std::sync::atomic::Ordering::Relaxed),
		))
	}
}

impl HashCell {
	pub fn get(&self) -> Option<u64> {
		match self.0.load(std::sync::atomic::Ordering::Relaxed) {
			0 => None,
			cached => Some(cached),
		}
	}
	pub fn set(&self, hash: u64) {
		self.0.store(hash, std::sync::atomic::Ordering::Relaxed);
	}
	pub fn clear(&self) {
		self.0.store(0, std::sync::atomic::Ordering::Relaxed);
	}
}

#[derive(Clone, Debug)]
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub instance_check: bool,
	pub capabilities: Capabilities,
	pub hash: HashCell,
}

impl Primitive {
	pub fn new(id: PrimitiveId, arguments: Vec<Value>, output: usize) -> Self {
		Primitive {
			id,
			arguments,
			output,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		}
	}

	pub fn with_arguments(&self, arguments: Vec<Value>) -> Self {
		Primitive {
			id: self.id,
			arguments,
			output: self.output,
			instance_check: self.instance_check,
			capabilities: self.capabilities,
			hash: HashCell::default(),
		}
	}

	pub fn with_output(&self, output: usize) -> Self {
		Primitive {
			id: self.id,
			arguments: self.arguments.clone(),
			output,
			instance_check: self.instance_check,
			capabilities: self.capabilities,
			hash: HashCell::default(),
		}
	}

	pub fn map_arguments(&self, mut f: impl FnMut(&Value) -> Option<Value>) -> Option<Primitive> {
		let mut changed: Option<Vec<Value>> = None;
		for (i, a) in self.arguments.iter().enumerate() {
			if let Some(mapped) = f(a) {
				changed.get_or_insert_with(|| self.arguments.clone())[i] = mapped;
			}
		}
		changed.map(|arguments| self.with_arguments(arguments))
	}

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

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct ResultWitness {
	pub installs: Vec<(SlotIdx, Value)>,
	pub narrated: Vec<SlotIdx>,
	pub principal: PrincipalId,
	pub phase: i32,
	pub reproduced: bool,
	pub shares: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
	pub query: Query,
	pub query_index: usize,
	pub resolved: bool,
	pub summary: String,
	pub conclusion: String,
	pub trace: Vec<String>,
	pub options: Vec<QueryOptionResult>,
	/// Per-session instantiations of `query` under `--sessions`, evaluated
	/// under the same `query_index`: an attack on any session resolves the
	/// query the user wrote. Empty at one session. `results_put` leaves this
	/// and `query` untouched, so display always shows the user's own query.
	pub variants: Vec<Query>,
}

impl VerifyResult {
	pub fn new(query: &Query, query_index: usize) -> Self {
		VerifyResult {
			query: query.clone(),
			query_index,
			resolved: false,
			summary: String::new(),
			conclusion: String::new(),
			trace: vec![],
			options: vec![],
			variants: vec![],
		}
	}

	pub fn set_summary(&mut self, mutated_info: &str, conclusion: &str) {
		self.trace = mutated_info
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty())
			.map(str::to_string)
			.collect();
		self.conclusion = conclusion.to_string();
		self.summary =
			crate::info::info_verify_result_summary(mutated_info, conclusion, &self.options);
	}

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
	pub span: Span,
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
	pub declared_span: Span,
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub sent_by: Vec<(PrincipalId, i32)>,
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
	pub index: IdMap<ValueId, usize>,
	pub max_phase: i32,
	pub used_by: IdMap<ValueId, IdMap<PrincipalId, bool>>,
	pub leaks: Arc<Vec<LeakEvent>>,
	/// Session-sibling groups under `--sessions`: every cloned constant (and
	/// its base) maps to the full `[base, base#2, ..]` id group. Empty at one
	/// session. Read by the authentication replay carve-out in `query.rs`.
	pub session_siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
}

#[derive(Clone, Debug)]
pub struct LeakEvent {
	pub constant_id: ValueId,
	pub principal_id: PrincipalId,
	pub declared_at: i32,
	pub phase: i32,
}

#[derive(Clone, Debug)]
pub struct SlotMeta {
	pub constant: Constant,
	pub guard: bool,
	pub known: bool,
	pub wire: Vec<PrincipalId>,
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub sent_at: Option<i32>,
	pub declared_at: i32,
	pub mutatable_to: Vec<PrincipalId>,
	pub phase: Vec<i32>,
}

#[derive(Clone, Debug)]
pub struct Provenance {
	pub creator: PrincipalId,
	pub sender: PrincipalId,
	pub attacker_tainted: bool,
	pub bypass_injected: bool,
}

#[derive(Clone, Debug)]
pub struct SlotValues {
	pub value: Value,
	pub pre_rewrite: Value,
	pub original: Value,
	/// The key a defeated guard was made to accept, when one was.
	///
	/// A guard bypass has to be visible to the principal — that is the whole
	/// point of it, since the principal really did check against the key it was
	/// handed. It used to be written into `original`, which gave that field two
	/// meanings and left a bypassed slot impossible to purify: the field
	/// purification restores from no longer held what the protocol honestly
	/// computed. Keeping it here costs one `Option` per slot and lets `original`
	/// mean exactly what the semantics say it means.
	pub bypassed: Option<Value>,
	pub provenance: Provenance,
}

impl SlotValues {
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

	/// Install `v` as the key a defeated guard accepts, leaving `original`
	/// holding what the protocol honestly computed.
	pub fn override_all_bypassed(&mut self, v: Value) {
		self.pre_rewrite = v.clone();
		self.value = v.clone();
		self.bypassed = Some(v);
		self.provenance.bypass_injected = true;
	}

	/// What the principal perceives at this slot: the bypassed key where a guard
	/// was defeated, and otherwise what it honestly computed.
	pub fn perceived(&self) -> &Value {
		self.bypassed.as_ref().unwrap_or(&self.original)
	}
}

#[derive(Clone, Debug)]
pub struct PrincipalState {
	pub name: String,
	pub id: PrincipalId,
	pub meta: Arc<Vec<SlotMeta>>,
	pub values: Vec<SlotValues>,
	pub index: Arc<IdMap<ValueId, usize>>,
	pub leaks: Arc<Vec<LeakEvent>>,
	pub halted_at: Option<i32>,
	pub foreign_halts: Vec<(PrincipalId, usize)>,
	pub capabilities: Arc<CapabilityIndex>,
}

impl PrincipalState {
	pub fn slot_unreached(&self, i: usize) -> bool {
		let Some(sv) = self.values.get(i) else {
			return false;
		};
		let creator = sv.provenance.creator;
		self.foreign_halts
			.iter()
			.any(|&(principal, at)| principal == creator && i >= at)
	}

	pub fn should_use_original(&self, i: usize) -> bool {
		!self.values[i].provenance.attacker_tainted
			|| self.values[i].provenance.creator == self.id
			|| !self.meta[i].known
			|| !self.meta[i].wire.contains(&self.id)
	}

	pub fn effective_value(&self, i: usize) -> &Value {
		if self.should_use_original(i) {
			self.values[i].perceived()
		} else {
			&self.values[i].value
		}
	}
}

#[derive(Clone, Debug)]
pub struct SlotDiff {
	pub index: SlotIdx,
	pub constant: Constant,
	pub value: Value,
	pub tainted: bool,
}

#[derive(Clone, Debug)]
pub struct MutationRecord {
	pub diffs: Vec<SlotDiff>,
	pub principal_id: PrincipalId,
	pub phase: i32,
}

#[derive(Clone, Debug)]
pub enum DerivationRecord {
	Initial,
	Leaked {
		slot: SlotIdx,
	},
	Obtained {
		slot: SlotIdx,
	},
	Decomposed {
		of: Value,
		using: Vec<Value>,
	},
	Reconstructed {
		from: Vec<Value>,
	},
	Recomposed {
		of: Value,
		using: Vec<Value>,
	},
	PasswordExtracted {
		from: Value,
	},
	ConcatFragment {
		of: Value,
	},
	Broken {
		of: Value,
		capability: Capability,
		using: Vec<Value>,
	},
	Injected,
}

impl DerivationRecord {
	pub fn ingredients(&self) -> Vec<&Value> {
		match self {
			DerivationRecord::Decomposed { of, using }
			| DerivationRecord::Recomposed { of, using }
			| DerivationRecord::Broken { of, using, .. } => {
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
	pub known_map: Arc<IdMap<u64, Vec<usize>>>,
	pub skeleton_hashes: Arc<IdSet<u64>>,
	pub mutation_records: Arc<Vec<Arc<MutationRecord>>>,
	pub derivations: Arc<Vec<DerivationRecord>>,
}

impl Default for AttackerState {
	fn default() -> Self {
		AttackerState {
			current_phase: 0,
			known: Arc::new(vec![]),
			known_map: Arc::new(IdMap::default()),
			skeleton_hashes: Arc::new(IdSet::default()),
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

pub struct DecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

pub struct ReconstructResult {
	pub from: Vec<Value>,
	pub forged: Option<Capability>,
}

pub struct RecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

pub struct RewriteResult {
	pub failed_rewrites: Vec<Primitive>,
	pub rewritten: bool,
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

		assert!(c.as_constant().is_some());
		assert!(c.as_primitive().is_none());

		assert!(p.as_primitive().is_some());
		assert!(p.as_constant().is_none());
	}

	#[test]
	fn value_try_accessors() {
		let c = make_constant("try_c");
		assert!(c.as_constant().is_some());
		assert!(c.try_as_primitive().is_err());
	}

	#[test]
	fn principal_state_should_use_original_creator() {
		let c = Constant {
			name: Arc::from("ps_fbm_a"),
			id: test_value_id("ps_fbm_a"),
			..Constant::default()
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&make_constant("ps_fbm_a"), 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		assert!(ps.should_use_original(0));
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
		meta.wire = vec![1];
		let mut sv = make_slot_values(&mutated, 0);
		sv.original = original.clone();
		sv.provenance.attacker_tainted = true;
		sv.provenance.creator = 0;
		let ps = make_principal_state("Bob", 1, vec![meta], vec![sv]);
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
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
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
		assert!(sv.original.equivalent(&v2, true));
	}

	#[test]
	fn slot_values_set_value_tainted() {
		let v1 = make_constant("svm_v1");
		let v2 = make_constant("svm_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.provenance.attacker_tainted = true;
		sv.set_value(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v1, true));
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
		assert!(sv.original.equivalent(&v2, true));
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
			declared_span: Span::default(),
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![],
			sent_by: vec![],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(0));
		assert!(!slot.known_by_principal(1));
	}

	#[test]
	fn trace_slot_known_by_receiver() {
		let c = Constant {
			name: Arc::from("ts2_a"),
			id: test_value_id("ts2_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			declared_span: Span::default(),
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![(1, 0)],
			sent_by: vec![(0, 1)],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(1));
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
		assert_eq!(Span::at(18).line_col(SRC), (3, 1));
		let unicode = "principal Amélié[\n\tknows private m\n]\n";
		let after_name = unicode.find('[').expect("bracket");
		assert_eq!(Span::at(after_name).line_col(unicode).1, 17);
	}

	#[test]
	fn render_points_a_caret_at_the_span() {
		let at_knows = SRC.find("knows").expect("knows");
		let e = VerifpalError::sanity("bad".into()).at(Span::new(at_knows, at_knows + 5));
		let rendered = e.render("m.vp", SRC);
		assert_eq!(
			rendered,
			concat!(
				"sanity error: bad\n",
				" --> m.vp:4:2\n",
				"  |\n",
				"4 |     knows private m\n",
				"  |     ^^^^^"
			),
			"{rendered}"
		);
	}

	#[test]
	fn render_places_a_secondary_label_on_its_own_line() {
		let at_knows = SRC.find("knows").expect("knows");
		let at_principal = SRC.find("principal").expect("principal");
		let e = VerifpalError::sanity("bad".into())
			.at(Span::new(at_knows, at_knows + 5))
			.labelled("here")
			.label(Span::new(at_principal, at_principal + 9), "and here")
			.note("why")
			.help("do this");
		let rendered = e.render("m.vp", SRC);
		assert_eq!(
			rendered,
			concat!(
				"sanity error: bad\n",
				" --> m.vp:4:2\n",
				"  |\n",
				"3 | principal Alice[\n",
				"  | --------- and here\n",
				"4 |     knows private m\n",
				"  |     ^^^^^ here\n",
				"  |\n",
				"  = note: why\n",
				"  = help: do this"
			),
			"{rendered}"
		);
	}

	#[test]
	fn render_narrows_the_primary_span_to_a_named_identifier() {
		let e = VerifpalError::sanity("bad".into())
			.at(Span::new(0, SRC.len()))
			.narrow("private");
		let rendered = e.render("m.vp", SRC);
		assert!(rendered.contains(" --> m.vp:4:8"), "{rendered}");
		assert!(rendered.ends_with("^^^^^^^"), "{rendered}");
	}

	#[test]
	fn render_narrows_to_a_later_occurrence_when_asked() {
		let source = "equivalence? x, x\n";
		let first = VerifpalError::sanity("bad".into())
			.at(Span::new(0, source.len()))
			.narrow_occurrence("x", 0)
			.render("m.vp", source);
		let second = VerifpalError::sanity("bad".into())
			.at(Span::new(0, source.len()))
			.narrow_occurrence("x", 1)
			.render("m.vp", source);
		assert!(first.contains(" --> m.vp:1:14"), "{first}");
		assert!(second.contains(" --> m.vp:1:17"), "{second}");
	}

	#[test]
	fn render_elides_a_gap_between_distant_labels() {
		let source = "one\ntwo\nthree\nfour\nfive\n";
		let e = VerifpalError::sanity("bad".into())
			.at(Span::new(
				source.find("five").expect("five"),
				source.len() - 1,
			))
			.label(Span::new(0, 3), "start");
		let rendered = e.render("m.vp", source);
		assert!(rendered.contains("\n...\n"), "{rendered}");
	}

	#[test]
	fn an_error_at_end_of_input_anchors_past_the_last_line_with_text() {
		let source = "principal Alice[\n\tknows private m\n";
		let e = VerifpalError::parse("expected `]`".into()).at(Span::at(source.len()));
		let rendered = e.render("m.vp", source);
		assert_eq!(
			rendered,
			concat!(
				"parse error: expected `]`\n",
				" --> m.vp:2:17\n",
				"  |\n",
				"2 |     knows private m\n",
				"  |                    ^"
			),
			"{rendered}"
		);
	}

	#[test]
	fn an_error_inside_the_source_is_not_moved_to_the_last_line() {
		let at_knows = SRC.find("knows").expect("knows");
		let e = VerifpalError::sanity("bad".into()).at(Span::new(at_knows, at_knows + 5));
		let rendered = e.render("m.vp", SRC);
		assert!(rendered.contains(" --> m.vp:4:2"), "{rendered}");
	}

	#[test]
	fn an_error_without_a_span_still_renders() {
		let e = VerifpalError::sanity("bad".into()).help("try this");
		assert_eq!(
			e.render("m.vp", SRC),
			"sanity error: bad\n --> m.vp\n  = help: try this"
		);
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
		assert!(e.to_string().contains(" --> m.vp:1:1"), "{}", e);
	}
}
