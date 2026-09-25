/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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
		let col = source
			.get(start..self.start.min(source.len()))
			.map_or(0, |line| line.chars().count())
			+ 1;
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
	Cancelled,
}

impl ErrorKind {
	pub fn label(self) -> &'static str {
		match self {
			ErrorKind::Parse => "parse error",
			ErrorKind::Sanity => "sanity error",
			ErrorKind::Resolution => "resolution error",
			ErrorKind::Internal => "internal error",
			ErrorKind::Cancelled => "cancelled",
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

	pub fn cancelled() -> Self {
		Self::of(ErrorKind::Cancelled, "analysis cancelled".into())
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

	pub fn labels(&self) -> &[(Span, Cow<'static, str>)] {
		match self.extra.as_deref() {
			Some(extra) => &extra.labels,
			None => &[],
		}
	}

	pub fn notes(&self) -> Vec<&str> {
		self.extra
			.as_deref()
			.map(|e| e.notes.iter().map(|n| n.as_ref()).collect())
			.unwrap_or_default()
	}

	pub fn helps(&self) -> Vec<&str> {
		self.extra
			.as_deref()
			.map(|e| e.helps.iter().map(|h| h.as_ref()).collect())
			.unwrap_or_default()
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

	pub fn narrowed_span(&self, source: &str) -> Option<Span> {
		let span = self.span?;
		let Some(extra) = self.extra.as_deref() else {
			return Some(span);
		};
		Some(
			extra
				.narrow
				.as_deref()
				.and_then(|needle| narrow_span(span, source, needle, extra.narrow_index))
				.unwrap_or(span),
		)
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
		let span = self.narrowed_span(source).unwrap_or(span);
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
	find_word(haystack, needle, index)
		.or_else(|| {
			find_word(
				&haystack.to_ascii_lowercase(),
				&needle.to_ascii_lowercase(),
				index,
			)
		})
		.map(|(at, after)| Span::new(start + at, start + after))
}

fn find_word(haystack: &str, needle: &str, index: usize) -> Option<(usize, usize)> {
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
				return Some((at, after));
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
}

impl fmt::Display for Qualifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Qualifier::Public => f.write_str("public"),
			Qualifier::Private => f.write_str("private"),
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

#[derive(Clone, Debug, Default)]
pub struct LineComments {
	pub leading: Vec<Comment>,
	pub trailing: Option<Comment>,
}

#[derive(Clone, Debug, Default)]
pub struct BracketComments {
	pub leading: Vec<Comment>,
	pub opening: Option<Comment>,
	pub tail: Vec<Comment>,
	pub closing: Option<Comment>,
}

impl BracketComments {
	pub fn is_empty(&self) -> bool {
		self.leading.is_empty()
			&& self.opening.is_none()
			&& self.tail.is_empty()
			&& self.closing.is_none()
	}
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
	pub const ALL: [QueryKind; 5] = [
		QueryKind::Confidentiality,
		QueryKind::Authentication,
		QueryKind::Freshness,
		QueryKind::Unlinkability,
		QueryKind::Equivalence,
	];

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
pub struct HashCell(AtomicU64, AtomicU8);

impl Clone for HashCell {
	fn clone(&self) -> Self {
		HashCell(
			AtomicU64::new(self.0.load(Ordering::Relaxed)),
			AtomicU8::new(self.1.load(Ordering::Relaxed)),
		)
	}
}

impl HashCell {
	pub fn get(&self) -> Option<u64> {
		match self.0.load(Ordering::Relaxed) {
			0 => None,
			cached => Some(cached),
		}
	}
	pub fn set(&self, hash: u64) {
		self.0.store(hash, Ordering::Relaxed);
	}
	pub fn clear(&self) {
		self.0.store(0, Ordering::Relaxed);
	}
	pub fn has_variables(&self) -> Option<bool> {
		match self.1.load(Ordering::Relaxed) {
			0 => None,
			1 => Some(false),
			_ => Some(true),
		}
	}
	pub fn set_has_variables(&self, has: bool) {
		self.1.store(if has { 2 } else { 1 }, Ordering::Relaxed);
	}
}

#[derive(Clone, Debug)]
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub threshold: usize,
	pub instance: ValueId,
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
			threshold: 0,
			instance: 0,
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
			threshold: self.threshold,
			instance: self.instance,
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
			threshold: self.threshold,
			instance: self.instance,
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
pub struct Scenario {
	pub span: Span,
	pub principal: PrincipalId,
	pub principal_name: Arc<str>,
	pub bindings: Vec<(Constant, Constant)>,
	pub comments: LineComments,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSummary {
	pub principal: Arc<str>,
	pub bindings: Vec<(Arc<str>, Arc<str>)>,
	pub corrupt_from: Option<i32>,
}

pub(crate) fn peer_description(corrupt_from: Option<i32>) -> String {
	match corrupt_from {
		None => "honest peer".to_string(),
		Some(0) => "corrupt peer".to_string(),
		Some(phase) => format!("peer corrupt from phase {phase}"),
	}
}

impl std::fmt::Display for ScenarioSummary {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}[", self.principal)?;
		for (i, (target, value)) in self.bindings.iter().enumerate() {
			if i > 0 {
				write!(f, ", ")?;
			}
			write!(f, "{target} = {value}")?;
		}
		write!(f, "]")
	}
}

#[derive(Clone, Debug)]
pub struct Model {
	pub file_name: String,
	pub source: Source,
	pub attacker: AttackerKind,
	pub attacker_comments: LineComments,
	pub blocks: Vec<Block>,
	pub scenarios: Vec<Scenario>,
	pub scenarios_comments: BracketComments,
	pub queries: Vec<Query>,
	pub queries_comments: BracketComments,
	pub tail_comments: Vec<Comment>,
}

impl Model {
	pub fn declared_principals(&self) -> Vec<(PrincipalId, String)> {
		let mut out: Vec<(PrincipalId, String)> = Vec::new();
		for block in &self.blocks {
			if let Block::Principal(p) = block
				&& !out.iter().any(|(id, _)| *id == p.id)
			{
				out.push((p.id, p.name.clone()));
			}
		}
		out
	}

	pub fn freshened_constants(&self) -> IdSet<ValueId> {
		let mut out = IdSet::default();
		for block in &self.blocks {
			let Block::Principal(p) = block else {
				continue;
			};
			for expr in &p.expressions {
				if matches!(expr.kind, Declaration::Generates | Declaration::Assignment) {
					for c in &expr.constants {
						out.insert(c.id);
					}
				}
			}
		}
		out
	}

	pub fn highest_referenced_principal(&self) -> PrincipalId {
		let mut highest = 0;
		for block in &self.blocks {
			match block {
				Block::Principal(p) => highest = highest.max(p.id),
				Block::Message(msg) => highest = highest.max(msg.sender).max(msg.recipient),
				Block::Phase(_) => {}
			}
		}
		for query in &self.queries {
			highest = highest
				.max(query.message.sender)
				.max(query.message.recipient);
			for option in &query.options {
				highest = highest
					.max(option.message.sender)
					.max(option.message.recipient);
			}
		}
		for scenario in &self.scenarios {
			highest = highest.max(scenario.principal);
		}
		highest
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceStep {
	pub kind: &'static str,
	pub text: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sender: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub recipient: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub principal: Option<String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub values: Vec<TraceValue>,
}

impl TraceStep {
	pub fn new(kind: &'static str, text: String) -> TraceStep {
		TraceStep {
			kind,
			text,
			sender: None,
			recipient: None,
			principal: None,
			values: vec![],
		}
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceValue {
	pub name: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub installed: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub was: Option<String>,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub guarded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Truncation {
	TermDepth,
	SolverVariables,
}

impl Truncation {
	pub fn name(self) -> &'static str {
		match self {
			Truncation::TermDepth => "term depth",
			Truncation::SolverVariables => "solver variables",
		}
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
	pub sessions: u8,
	pub truncations: Vec<Truncation>,
}

impl Envelope {
	pub fn exhausted(&self) -> bool {
		self.truncations.is_empty()
	}

	pub fn summary(&self) -> String {
		if self.exhausted() {
			return format!(
				"search exhausted at {} session{}",
				self.sessions,
				crate::util::plural(self.sessions.into())
			);
		}
		let reasons: Vec<&str> = self.truncations.iter().map(|t| t.name()).collect();
		format!("search truncated: {}", reasons.join(", "))
	}

	pub fn qualifier(&self) -> String {
		format!("  [{}]", self.summary())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subtype {
	AttackerSuppliedValue,
	DuplicateAcceptance,
	ReplayableFirstFlight,
}

impl Subtype {
	pub fn name(self) -> &'static str {
		match self {
			Subtype::AttackerSuppliedValue => "attacker-supplied value",
			Subtype::DuplicateAcceptance => "duplicate acceptance",
			Subtype::ReplayableFirstFlight => {
				"duplicate acceptance: no recipient-generated context"
			}
		}
	}

	pub fn qualifier(self) -> String {
		format!("  [{}]", self.name())
	}
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
	pub query: Query,
	pub query_index: usize,
	pub resolved: bool,
	pub envelope: Envelope,
	pub summary: String,
	pub conclusion: String,
	pub subtype: Option<Subtype>,
	pub trace: Vec<String>,
	pub notes: Vec<String>,
	pub steps: Vec<TraceStep>,
	pub options: Vec<QueryOptionResult>,
	pub variants: Vec<Query>,
}

impl VerifyResult {
	pub fn new(query: &Query, query_index: usize) -> Self {
		VerifyResult {
			query: query.clone(),
			query_index,
			resolved: false,
			envelope: Envelope::default(),
			summary: String::new(),
			conclusion: String::new(),
			subtype: None,
			trace: vec![],
			notes: vec![],
			steps: vec![],
			options: vec![],
			variants: vec![],
		}
	}

	pub fn set_summary(&mut self, mutated_info: &str, steps: Vec<TraceStep>, conclusion: &str) {
		let (notes, trace): (Vec<&str>, Vec<&str>) = mutated_info
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty())
			.partition(|line| line.starts_with("Note: "));
		self.trace = trace.into_iter().map(str::to_string).collect();
		self.notes = notes
			.into_iter()
			.map(|line| line.trim_start_matches("Note: ").to_string())
			.collect();
		self.steps = steps;
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
	pub comments: BracketComments,
}

#[derive(Clone, Debug, Default)]
pub struct Message {
	pub span: Span,
	pub sender: PrincipalId,
	pub sender_name: Arc<str>,
	pub recipient: PrincipalId,
	pub recipient_name: Arc<str>,
	pub constants: Vec<Constant>,
	pub comments: LineComments,
}

#[derive(Clone, Debug, Default)]
pub struct Phase {
	pub span: Span,
	pub number: i32,
	pub comments: LineComments,
}

#[derive(Clone, Debug)]
pub struct Query {
	pub span: Span,
	pub kind: QueryKind,
	pub constants: Vec<Constant>,
	pub message: Message,
	pub options: Vec<QueryOption>,
	pub comments: LineComments,
}

impl Query {
	pub(crate) fn same_shape(&self, other: &Query) -> bool {
		self.constants.len() == other.constants.len()
			&& self
				.constants
				.iter()
				.zip(&other.constants)
				.all(|(x, y)| x.id == y.id)
			&& self.message.same_shape(&other.message)
			&& self.options.len() == other.options.len()
			&& self
				.options
				.iter()
				.zip(&other.options)
				.all(|(x, y)| x.message.same_shape(&y.message))
	}

	pub fn subject(&self) -> VResult<&Constant> {
		self.constants.first().ok_or_else(|| {
			VerifpalError::internal(
				format!("{} query carries no constant", self.kind.name()).into(),
			)
		})
	}
}

impl Message {
	pub(crate) fn same_shape(&self, other: &Message) -> bool {
		self.sender == other.sender
			&& self.recipient == other.recipient
			&& self.constants.len() == other.constants.len()
			&& self
				.constants
				.iter()
				.zip(&other.constants)
				.all(|(x, y)| x.id == y.id)
	}

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
	pub comments: LineComments,
}

#[derive(Clone, Debug)]
pub struct QueryOptionResult {
	pub summary: String,
}

#[derive(Clone, Debug)]
pub struct Expression {
	pub span: Span,
	pub kind: Declaration,
	pub qualifier: Option<Qualifier>,
	pub constants: Vec<Constant>,
	pub assigned: Option<Value>,
	pub comments: LineComments,
}

impl Expression {
	pub(crate) fn declares_secret(&self) -> bool {
		match self.kind {
			Declaration::Generates => true,
			Declaration::Knows => self.qualifier == Some(Qualifier::Private),
			Declaration::Assignment | Declaration::Leaks => false,
		}
	}
}

#[derive(Clone, Debug)]
pub struct TraceSlot {
	pub declared_span: Span,
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub sent_by: Vec<SendEvent>,
	pub declared_at: i32,
	pub phases: Vec<i32>,
	pub mutatable_to: Vec<PrincipalId>,
	pub delivery_phase: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendEvent {
	pub sender: PrincipalId,
	pub recipient: PrincipalId,
	pub declared_at: i32,
	pub phase: i32,
	pub guarded: bool,
}

impl TraceSlot {
	pub fn known_by_principal(&self, pid: PrincipalId) -> bool {
		self.creator == pid || self.known_by.iter().any(|&(recipient, _)| recipient == pid)
	}

	pub(crate) fn sender_to(&self, pid: PrincipalId) -> PrincipalId {
		self.known_by
			.iter()
			.find(|&&(recipient, _)| recipient == pid)
			.map_or(self.creator, |&(_, from)| from)
	}

	pub(crate) fn guarded_for(&self, pid: PrincipalId) -> bool {
		self.sent_by
			.iter()
			.any(|event| event.guarded && (event.recipient == pid || self.creator == pid))
	}

	pub(crate) fn sent_from(&self, pid: PrincipalId) -> bool {
		self.sent_by.iter().any(|event| event.sender == pid)
	}

	pub(crate) fn disclosed(&self) -> bool {
		!self.sent_by.is_empty() || self.constant.leaked
	}

	pub(crate) fn mutation_reaches(&self, pid: PrincipalId) -> bool {
		self.mutatable_to.contains(&pid)
	}

	pub(crate) fn substitution_phase(&self, recipient: PrincipalId) -> Option<i32> {
		self.substitution_phase_from(recipient, &mut Vec::new())
	}

	fn substitution_phase_from(
		&self,
		recipient: PrincipalId,
		visiting: &mut Vec<PrincipalId>,
	) -> Option<i32> {
		if visiting.contains(&recipient) {
			return None;
		}
		visiting.push(recipient);
		let earliest = self
			.sent_by
			.iter()
			.filter(|event| event.recipient == recipient)
			.filter_map(|event| {
				if event.guarded {
					self.substitution_phase_from(event.sender, visiting)
				} else {
					Some(event.phase)
				}
			})
			.min();
		visiting.pop();
		earliest
	}
}

#[derive(Clone, Debug, Default)]
pub struct ProtocolTrace {
	pub principals: Vec<String>,
	pub principal_ids: Vec<PrincipalId>,
	pub slots: Vec<TraceSlot>,
	pub index: IdMap<ValueId, usize>,
	pub max_phase: i32,
	pub used_by: IdMap<ValueId, IdSet<PrincipalId>>,
	pub leaks: Vec<LeakEvent>,
	pub session_siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub copy_siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub interchangeable: IdMap<PrincipalId, PrincipalId>,
	pub actors: IdMap<PrincipalId, PrincipalId>,
	pub scenario_bound: IdSet<ValueId>,
	pub equivalence_queried: IdSet<ValueId>,
	pub capabilities: CapabilityIndex,
}

impl ProtocolTrace {
	pub fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index.get(&c.id).copied()
	}

	pub fn principal_name(&self, id: PrincipalId) -> &str {
		if id == crate::principal::ATTACKER_ID {
			return crate::principal::ATTACKER_NAME;
		}
		self.principal_ids
			.iter()
			.position(|&p| p == id)
			.and_then(|i| self.principals.get(i))
			.map(String::as_str)
			.unwrap_or("")
	}

	pub fn constant_used_by(&self, principal_id: PrincipalId, c: &Constant) -> bool {
		self.used_by
			.get(&c.id)
			.is_some_and(|principals| principals.contains(&principal_id))
	}

	pub(crate) fn same_actor(&self, a: PrincipalId, b: PrincipalId) -> bool {
		Self::grouped(&self.actors, a, b)
	}

	pub(crate) fn sibling_slots(&self, slot: usize) -> Vec<usize> {
		let id = self.slots[slot].constant.id;
		let mut out = vec![slot];
		for group in [&self.session_siblings, &self.copy_siblings]
			.into_iter()
			.filter_map(|groups| groups.get(&id))
		{
			for &at in group.iter().filter_map(|sid| self.index.get(sid)) {
				if !out.contains(&at) {
					out.push(at);
				}
			}
		}
		out
	}

	pub(crate) fn interchangeable_for(&self, a: PrincipalId, b: PrincipalId, slot: usize) -> bool {
		if Self::grouped(&self.interchangeable, a, b) {
			return true;
		}
		if !self.same_actor(a, b) || self.scenario_bound.is_empty() {
			return false;
		}
		let Some(trace_slot) = self.slots.get(slot) else {
			return false;
		};
		!crate::value::resolve_trace_constant(&trace_slot.constant, self)
			.constant_leaves()
			.any(|c| {
				self.scenario_bound
					.contains(&crate::value::copy_index_of(c.id).1)
			})
	}

	fn grouped(map: &IdMap<PrincipalId, PrincipalId>, a: PrincipalId, b: PrincipalId) -> bool {
		a == b || map.get(&a).copied().unwrap_or(a) == map.get(&b).copied().unwrap_or(b)
	}
}

#[derive(Clone, Debug)]
pub struct LeakEvent {
	pub constant_id: ValueId,
	pub principal_id: PrincipalId,
	pub declared_at: i32,
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
	Combined {
		from: Vec<Value>,
	},
	Recomposed {
		of: Value,
		using: Vec<Value>,
	},
	Fragment {
		of: Value,
	},
	Rewritten {
		of: Value,
		using: Vec<Value>,
		built: bool,
	},
	Broken {
		of: Value,
		capability: Capability,
		using: Vec<Value>,
	},
	Reused {
		of: Value,
		with: Value,
	},
	ReusedForge {
		with: [Value; 2],
		using: Vec<Value>,
	},
}

impl DerivationRecord {
	pub fn ingredients(&self) -> Vec<&Value> {
		match self {
			DerivationRecord::Decomposed { of, using } => {
				let mut v = vec![of];
				v.extend(using.iter());
				v
			}
			DerivationRecord::Recomposed { using, .. }
			| DerivationRecord::Rewritten { using, .. } => using.iter().collect(),
			DerivationRecord::Broken {
				of,
				using,
				capability,
			} => {
				let mut v = Vec::new();
				if matches!(capability, Capability::Weak | Capability::Malleable) {
					v.push(of);
				}
				v.extend(using.iter());
				v
			}
			DerivationRecord::Reused { of, with } => vec![of, with],
			DerivationRecord::ReusedForge { with, using } => {
				let mut v: Vec<&Value> = with.iter().collect();
				v.extend(using.iter());
				v
			}
			DerivationRecord::Reconstructed { from } | DerivationRecord::Combined { from } => {
				from.iter().collect()
			}
			DerivationRecord::Fragment { of } => vec![of],
			DerivationRecord::Initial
			| DerivationRecord::Leaked { .. }
			| DerivationRecord::Obtained { .. } => vec![],
		}
	}
}

#[derive(Clone, Debug)]
pub struct AttackerState {
	pub current_phase: i32,
	pub known: Arc<Vec<Value>>,
	pub known_map: Arc<IdMap<u64, Vec<usize>>>,
	pub derivations: Arc<Vec<DerivationRecord>>,
	pub reused: Arc<Vec<[Value; 2]>>,
	pub chain: u64,
}

static CHAINS: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_chain() -> u64 {
	CHAINS.fetch_add(1, Ordering::Relaxed)
}

impl Default for AttackerState {
	fn default() -> Self {
		AttackerState {
			current_phase: 0,
			known: Arc::new(vec![]),
			known_map: Arc::new(IdMap::default()),
			derivations: Arc::new(vec![]),
			reused: Arc::new(vec![]),
			chain: next_chain(),
		}
	}
}

pub struct DecomposeResult {
	pub revealed: Vec<Value>,
	pub used: Vec<Value>,
}

pub enum Forged {
	Assumption { capability: Capability, of: Value },
	Reuse([Value; 2]),
}

pub struct ReconstructResult {
	pub from: Vec<Value>,
	pub forged: Option<Forged>,
	pub combined: bool,
}

pub struct RecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;
	use crate::value::*;
	use std::sync::Arc;

	#[test]
	fn nonce_reuse_records_list_both_ciphertexts_as_ingredients() {
		let k = make_constant("nrr_k");
		let n = make_constant("nrr_n");
		let ad = make_constant("nrr_ad");
		let e1 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("nrr_m1"), ad.clone()],
			0,
		);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k, n, make_constant("nrr_m2"), ad.clone()],
			0,
		);
		let reuse = DerivationRecord::Reused {
			of: e1.clone(),
			with: e2.clone(),
		};
		assert_eq!(reuse.ingredients().len(), 2);
		let forged = DerivationRecord::ReusedForge {
			with: [e1, e2],
			using: vec![ad],
		};
		assert_eq!(forged.ingredients().len(), 3);
	}

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
	fn primitive_with_arguments() {
		let a = make_constant("pwa_a");
		let b = make_constant("pwa_b");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![a],
			output: 0,
			instance: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let p2 = p.with_arguments(vec![b.clone()]);
		assert_eq!(p2.id, PRIM_ENC);
		assert_eq!(p2.output, 0);
		assert!(p2.instance_check);
		assert!(p2.arguments[0].equivalent(&b, true));
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
		let slot = make_trace_slot(&Value::Constant(c), &value_nil(), 0);
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
			known_by: vec![(1, 0)],
			sent_by: vec![SendEvent {
				sender: 0,
				recipient: 1,
				declared_at: 1,
				phase: 0,
				guarded: false,
			}],
			..make_trace_slot(&Value::Constant(c), &value_nil(), 0)
		};
		assert!(slot.known_by_principal(1));
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
