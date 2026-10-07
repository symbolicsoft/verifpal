/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct Span {
	pub(crate) start: usize,
	pub(crate) end: usize,
}

impl Span {
	pub(crate) fn new(start: usize, end: usize) -> Self {
		Span { start, end }
	}

	pub(crate) fn at(pos: usize) -> Self {
		Span {
			start: pos,
			end: pos,
		}
	}

	pub(crate) fn line_col(&self, source: &str) -> (usize, usize) {
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
pub(crate) enum ErrorKind {
	Parse,
	Sanity,
	Internal,
	Cancelled,
}

impl ErrorKind {
	pub(crate) fn label(self) -> &'static str {
		match self {
			ErrorKind::Parse => "parse error",
			ErrorKind::Sanity => "sanity error",
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
	pub(crate) kind: ErrorKind,
	pub(crate) message: Cow<'static, str>,
	pub(crate) span: Option<Span>,
	extra: Option<Box<Diagnostic>>,
	rendered: Option<String>,
}

impl VerifpalError {
	pub(crate) fn parse(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Parse, message)
	}

	pub(crate) fn sanity(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Sanity, message)
	}

	pub(crate) fn internal(message: Cow<'static, str>) -> Self {
		Self::of(ErrorKind::Internal, message)
	}

	pub(crate) fn cancelled() -> Self {
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

	pub(crate) fn at(mut self, span: Span) -> Self {
		self.span = Some(span);
		self
	}

	pub(crate) fn marking(mut self, span: Span, message: impl Into<Cow<'static, str>>) -> Self {
		self.span = Some(span);
		self.extra_mut().primary_label = Some(message.into());
		self
	}

	pub(crate) fn narrow(mut self, needle: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().narrow = Some(needle.into());
		self
	}

	pub(crate) fn narrow_occurrence(
		mut self,
		needle: impl Into<Cow<'static, str>>,
		index: usize,
	) -> Self {
		let extra = self.extra_mut();
		extra.narrow = Some(needle.into());
		extra.narrow_index = index;
		self
	}

	pub(crate) fn labelled(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().primary_label = Some(message.into());
		self
	}

	pub(crate) fn label(mut self, span: Span, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().labels.push((span, message.into()));
		self
	}

	pub(crate) fn note(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().notes.push(message.into());
		self
	}

	pub(crate) fn help(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.extra_mut().helps.push(message.into());
		self
	}

	pub(crate) fn suggest(self, candidate: Option<String>) -> Self {
		match candidate {
			Some(name) => self.help(format!("did you mean `{}`?", name)),
			None => self,
		}
	}

	pub(crate) fn labels(&self) -> &[(Span, Cow<'static, str>)] {
		match self.extra.as_deref() {
			Some(extra) => &extra.labels,
			None => &[],
		}
	}

	pub(crate) fn notes(&self) -> Vec<&str> {
		self.extra
			.as_deref()
			.map(|e| e.notes.iter().map(|n| n.as_ref()).collect())
			.unwrap_or_default()
	}

	pub(crate) fn helps(&self) -> Vec<&str> {
		self.extra
			.as_deref()
			.map(|e| e.helps.iter().map(|h| h.as_ref()).collect())
			.unwrap_or_default()
	}

	pub(crate) fn has_labels(&self) -> bool {
		self.extra.as_ref().is_some_and(|e| !e.labels.is_empty())
	}

	pub(crate) fn or_span(mut self, span: Span) -> Self {
		self.span.get_or_insert(span);
		self
	}

	pub(crate) fn located(mut self, file_name: &str, source: &str) -> Self {
		self.rendered = Some(self.render(file_name, source));
		self
	}

	pub(crate) fn narrowed_span(&self, source: &str) -> Option<Span> {
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

	pub(crate) fn render(&self, file_name: &str, source: &str) -> String {
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

pub(crate) type VResult<T> = Result<T, VerifpalError>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn error_display() {
		let e = VerifpalError::parse("bad input".into());
		assert_eq!(format!("{}", e), "parse error: bad input");
		let e2 = VerifpalError::sanity("not found".into());
		assert_eq!(format!("{}", e2), "sanity error: not found");
	}

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
