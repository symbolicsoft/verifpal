/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) struct Dialect {
	pub(crate) open: &'static str,
	pub(crate) close: &'static str,
	pub(crate) escape: fn(&mut String, &str),
	pub(crate) partial: fn(&str) -> Option<&'static Template>,
}

pub(crate) enum Val {
	Text(String),
	Raw(String),
	Flag(bool),
	List(Vec<Ctx>),
}

#[derive(Default)]
pub(crate) struct Ctx {
	fields: Vec<(&'static str, Val)>,
}

impl Ctx {
	pub(crate) fn new() -> Ctx {
		Ctx::default()
	}

	pub(crate) fn text(mut self, key: &'static str, value: impl Into<String>) -> Ctx {
		self.fields.push((key, Val::Text(value.into())));
		self
	}

	pub(crate) fn raw(mut self, key: &'static str, value: impl Into<String>) -> Ctx {
		self.fields.push((key, Val::Raw(value.into())));
		self
	}

	pub(crate) fn num(mut self, key: &'static str, value: impl std::fmt::Display) -> Ctx {
		self.fields.push((key, Val::Text(value.to_string())));
		self
	}

	pub(crate) fn flag(mut self, key: &'static str, value: bool) -> Ctx {
		self.fields.push((key, Val::Flag(value)));
		self
	}

	pub(crate) fn list(mut self, key: &'static str, value: Vec<Ctx>) -> Ctx {
		self.fields.push((key, Val::List(value)));
		self
	}

	fn get(&self, key: &str) -> Option<&Val> {
		self.fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
	}
}

enum Node {
	Lit(&'static str),
	Var(&'static str),
	Section {
		key: &'static str,
		inverted: bool,
		body: Vec<Node>,
	},
	Partial(&'static str),
}

pub(crate) struct Template {
	name: &'static str,
	nodes: Vec<Node>,
	dialect: &'static Dialect,
}

impl Template {
	pub(crate) fn parse(
		name: &'static str,
		raw: &'static str,
		dialect: &'static Dialect,
	) -> Template {
		let mut at = 0usize;
		let (nodes, closing) = parse_block(name, strip_header(raw), &mut at, dialect);
		if let Some(closing) = closing {
			panic!("template '{name}' closes section '{closing}' without opening it");
		}
		Template {
			name,
			nodes,
			dialect,
		}
	}

	#[cfg(test)]
	pub(crate) fn name(&self) -> &'static str {
		self.name
	}

	#[cfg(test)]
	pub(crate) fn is_empty(&self) -> bool {
		self.nodes.is_empty()
	}

	#[cfg(test)]
	pub(crate) fn partials(&self) -> Vec<&'static str> {
		fn walk(nodes: &[Node], out: &mut Vec<&'static str>) {
			for node in nodes {
				match node {
					Node::Partial(name) => out.push(name),
					Node::Section { body, .. } => walk(body, out),
					_ => {}
				}
			}
		}
		let mut out = Vec::new();
		walk(&self.nodes, &mut out);
		out
	}
}

fn strip_header(raw: &'static str) -> &'static str {
	let trimmed = raw.trim_start();
	if let Some(after) = trimmed.strip_prefix("<!--") {
		return after
			.split_once("-->")
			.map(|(_, tail)| tail)
			.unwrap_or(raw)
			.trim_ascii();
	}
	if let Some(after) = trimmed.strip_prefix("/*") {
		return after
			.split_once("*/")
			.map(|(_, tail)| tail)
			.unwrap_or(raw)
			.trim_ascii();
	}
	let mut rest = trimmed;
	while rest.starts_with('%') {
		let (line, tail) = rest.split_once('\n').unwrap_or((rest, ""));
		if !line.contains("SPDX") {
			break;
		}
		rest = tail.trim_start_matches([' ', '\t']);
	}
	rest.trim_ascii()
}

fn parse_block(
	name: &'static str,
	src: &'static str,
	at: &mut usize,
	dialect: &'static Dialect,
) -> (Vec<Node>, Option<&'static str>) {
	let (open, close) = (dialect.open, dialect.close);
	let mut nodes: Vec<Node> = Vec::new();
	while *at < src.len() {
		let rest = &src[*at..];
		let Some(start) = rest.find(open) else {
			nodes.push(Node::Lit(rest));
			*at = src.len();
			break;
		};
		if start > 0 {
			nodes.push(Node::Lit(&rest[..start]));
		}
		let after = &rest[start + open.len()..];
		let Some(end) = after.find(close) else {
			panic!("template '{name}' has an unclosed '{open}' tag");
		};
		let tag = after[..end].trim();
		*at += start + end + open.len() + close.len();
		match tag.as_bytes().first() {
			Some(b'#') | Some(b'^') => {
				let inverted = tag.starts_with('^');
				let key = tag[1..].trim();
				let (body, closing) = parse_block(name, src, at, dialect);
				match closing {
					Some(closing) if closing == key => {}
					Some(closing) => {
						panic!("template '{name}' opens section '{key}' but closes '{closing}'")
					}
					None => panic!("template '{name}' never closes section '{key}'"),
				}
				nodes.push(Node::Section {
					key,
					inverted,
					body,
				});
			}
			Some(b'/') => return (nodes, Some(tag[1..].trim())),
			Some(b'>') => nodes.push(Node::Partial(tag[1..].trim())),
			_ => nodes.push(Node::Var(tag)),
		}
	}
	(nodes, None)
}

pub(crate) fn render(template: &Template, ctx: &Ctx) -> String {
	let mut out = String::with_capacity(1024);
	audit(template, &template.nodes, ctx);
	emit(template, &template.nodes, &[ctx], &mut out, 0);
	out
}

fn emit(owner: &Template, nodes: &[Node], stack: &[&Ctx], out: &mut String, depth: usize) {
	for node in nodes {
		match node {
			Node::Lit(text) => out.push_str(text),
			Node::Var(key) => match lookup(owner, stack, key) {
				Some(Val::Text(text)) => (owner.dialect.escape)(out, text),
				Some(Val::Raw(markup)) => out.push_str(markup),
				_ => {}
			},
			Node::Section {
				key,
				inverted,
				body,
			} => {
				let found = lookup(owner, stack, key);
				let held = found.map(truthy).unwrap_or(false);
				if *inverted {
					if !held {
						emit(owner, body, stack, out, depth);
					}
					continue;
				}
				match found {
					Some(Val::List(items)) => {
						for item in items {
							audit(owner, body, item);
							let mut inner: Vec<&Ctx> = stack.to_vec();
							inner.push(item);
							emit(owner, body, &inner, out, depth);
						}
					}
					Some(_) if held => emit(owner, body, stack, out, depth),
					_ => {}
				}
			}
			Node::Partial(name) => {
				if depth >= 32 {
					continue;
				}
				if let Some(part) = (owner.dialect.partial)(name) {
					emit(part, &part.nodes, stack, out, depth + 1);
				}
			}
		}
	}
}

fn truthy(value: &Val) -> bool {
	match value {
		Val::Text(text) | Val::Raw(text) => !text.is_empty(),
		Val::Flag(held) => *held,
		Val::List(items) => !items.is_empty(),
	}
}

fn lookup<'a>(owner: &Template, stack: &[&'a Ctx], key: &str) -> Option<&'a Val> {
	for ctx in stack.iter().rev() {
		if let Some(value) = ctx.get(key) {
			return Some(value);
		}
	}
	if cfg!(test) {
		let (name, open, close) = (owner.name, owner.dialect.open, owner.dialect.close);
		panic!("template '{name}' reads {open}{key}{close} but nothing supplies it");
	}
	None
}

fn audit(owner: &Template, nodes: &[Node], ctx: &Ctx) {
	if !cfg!(test) {
		return;
	}
	let mut read: Vec<&'static str> = Vec::new();
	collect(owner.dialect, nodes, &mut read, &mut Vec::new());
	for (key, _) in &ctx.fields {
		assert!(
			read.contains(key),
			"template '{}' is supplied '{key}' but never reads it",
			owner.name
		);
	}
}

fn collect(
	dialect: &'static Dialect,
	nodes: &[Node],
	out: &mut Vec<&'static str>,
	seen: &mut Vec<&'static str>,
) {
	for node in nodes {
		match node {
			Node::Lit(_) => {}
			Node::Var(key) => out.push(key),
			Node::Section { key, body, .. } => {
				out.push(key);
				collect(dialect, body, out, seen);
			}
			Node::Partial(name) => {
				if seen.contains(name) {
					continue;
				}
				seen.push(name);
				if let Some(part) = (dialect.partial)(name) {
					collect(dialect, &part.nodes, out, seen);
				}
			}
		}
	}
}

pub(crate) fn escape_html(out: &mut String, text: &str) {
	for c in text.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			_ => out.push(c),
		}
	}
}

pub(crate) fn escape_tex(out: &mut String, text: &str) {
	for c in text.chars() {
		match c {
			'\\' => out.push_str("\\textbackslash{}"),
			'{' => out.push_str("\\{"),
			'}' => out.push_str("\\}"),
			'$' => out.push_str("\\$"),
			'&' => out.push_str("\\&"),
			'%' => out.push_str("\\%"),
			'#' => out.push_str("\\#"),
			'_' => out.push_str("\\_"),
			'~' => out.push_str("\\textasciitilde{}"),
			'^' => out.push_str("\\textasciicircum{}"),
			'<' => out.push_str("\\textless{}"),
			'>' => out.push_str("\\textgreater{}"),
			'|' => out.push_str("\\textbar{}"),
			'"' => out.push_str("\\textquotedbl{}"),
			c if c.is_ascii() => out.push(c),
			c => match tex_spelling(c) {
				Some(spelling) => out.push_str(spelling),
				None => out.push(c),
			},
		}
	}
}

pub(crate) fn escaped_tex(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	escape_tex(&mut out, text);
	out
}

pub(crate) fn tex_spelling(c: char) -> Option<&'static str> {
	Some(match c {
		'\u{00a0}' => "~",
		'\u{00a9}' => "\\textcopyright{}",
		'\u{00b7}' => "\\textperiodcentered{}",
		'\u{00d7}' => "\\ensuremath{\\times}",
		'\u{00e8}' => "\\`{e}",
		'\u{00e9}' => "\\'{e}",
		'\u{2013}' => "--",
		'\u{2014}' => "---",
		'\u{2018}' => "`",
		'\u{2019}' => "'",
		'\u{201c}' => "``",
		'\u{201d}' => "''",
		'\u{2020}' => "\\ensuremath{\\dagger}",
		'\u{2022}' => "\\textbullet{}",
		'\u{2026}' => "\\ldots{}",
		'\u{2192}' => "\\ensuremath{\\rightarrow}",
		'\u{203a}' => "\\guilsinglright{}",
		'\u{2713}' => "\\ensuremath{\\checkmark}",
		'\u{2717}' => "\\ensuremath{\\times}",
		_ => return None,
	})
}

macro_rules! templates {
	($dialect:path, $($konst:ident $short:literal = $file:literal),* $(,)?) => {
		$(
			pub(crate) static $konst: std::sync::LazyLock<crate::template::Template> =
				std::sync::LazyLock::new(|| {
					crate::template::Template::parse($short, include_str!($file), &$dialect)
				});
		)*

		pub(crate) fn partial(name: &str) -> Option<&'static crate::template::Template> {
			match name {
				$($short => Some(&*$konst),)*
				_ => None,
			}
		}

		#[cfg(test)]
		pub(crate) fn every_template() -> Vec<&'static crate::template::Template> {
			vec![$(&*$konst),*]
		}
	};
}

pub(crate) use templates;

#[cfg(test)]
mod tests {
	use super::*;

	fn none(_: &str) -> Option<&'static Template> {
		None
	}

	static HTML: Dialect = Dialect {
		open: "{{",
		close: "}}",
		escape: escape_html,
		partial: none,
	};

	static ALT: Dialect = Dialect {
		open: "<<",
		close: ">>",
		escape: escape_html,
		partial: none,
	};

	#[test]
	fn a_text_value_is_escaped_and_a_raw_value_is_not() {
		let tpl = Template::parse("t", "<p>{{a}}|{{b}}</p>", &HTML);
		let out = render(
			&tpl,
			&Ctx::new().text("a", "<i>&x</i>").raw("b", "<i>ok</i>"),
		);
		assert_eq!(out, "<p>&lt;i&gt;&amp;x&lt;/i&gt;|<i>ok</i></p>");
	}

	#[test]
	fn a_list_section_repeats_its_body_once_per_item() {
		let tpl = Template::parse("t", "{{#rows}}[{{n}}]{{/rows}}", &HTML);
		let rows = vec![Ctx::new().num("n", 1), Ctx::new().num("n", 2)];
		assert_eq!(render(&tpl, &Ctx::new().list("rows", rows)), "[1][2]");
	}

	#[test]
	fn an_empty_list_renders_nothing_and_its_inverse_renders_instead() {
		let tpl = Template::parse("t", "{{#rows}}x{{/rows}}{{^rows}}none{{/rows}}", &HTML);
		assert_eq!(render(&tpl, &Ctx::new().list("rows", vec![])), "none");
	}

	#[test]
	fn a_flag_section_renders_its_body_once() {
		let tpl = Template::parse("t", "{{#on}}yes{{/on}}{{^on}}no{{/on}}", &HTML);
		assert_eq!(render(&tpl, &Ctx::new().flag("on", true)), "yes");
		assert_eq!(render(&tpl, &Ctx::new().flag("on", false)), "no");
	}

	#[test]
	fn a_list_item_falls_back_to_the_enclosing_context() {
		let tpl = Template::parse("t", "{{#rows}}{{model}}-{{n}} {{/rows}}", &HTML);
		let rows = vec![Ctx::new().num("n", 1), Ctx::new().num("n", 2)];
		let ctx = Ctx::new().num("model", 7).list("rows", rows);
		assert_eq!(render(&tpl, &ctx), "7-1 7-2 ");
	}

	#[test]
	fn a_value_carrying_template_syntax_is_never_rescanned() {
		let tpl = Template::parse("t", "{{a}}", &HTML);
		assert_eq!(render(&tpl, &Ctx::new().text("a", "{{b}}")), "{{b}}");
	}

	#[test]
	fn the_spdx_header_is_stripped_once_at_parse_time() {
		let tpl = Template::parse(
			"t",
			"<!-- SPDX-License-Identifier: X -->\n<p>hi</p>\n",
			&HTML,
		);
		assert_eq!(render(&tpl, &Ctx::new()), "<p>hi</p>");
	}

	#[test]
	fn a_percent_comment_header_is_stripped_but_an_ordinary_comment_is_kept() {
		let tpl = Template::parse("t", "% SPDX-License-Identifier: X\n%% keep\nbody\n", &ALT);
		assert_eq!(render(&tpl, &Ctx::new()), "%% keep\nbody");
	}

	#[test]
	fn a_dialect_reads_its_own_delimiters_and_ignores_the_other_ones() {
		let tpl = Template::parse("t", "<<n>> {{n}}", &ALT);
		assert_eq!(render(&tpl, &Ctx::new().num("n", 3)), "3 {{n}}");
	}

	#[test]
	#[should_panic(expected = "opens section 'rows' but closes 'items'")]
	fn mismatched_section_names_are_rejected() {
		Template::parse("t", "{{#rows}}x{{/items}}", &HTML);
	}

	#[test]
	#[should_panic(expected = "never closes section 'rows'")]
	fn unclosed_sections_are_rejected() {
		Template::parse("t", "{{#rows}}x", &HTML);
	}

	#[test]
	#[should_panic(expected = "closes section 'rows' without opening it")]
	fn unmatched_closing_sections_are_rejected() {
		Template::parse("t", "{{/rows}}", &HTML);
	}

	#[test]
	#[should_panic(expected = "has an unclosed '{{' tag")]
	fn unclosed_tags_are_rejected() {
		Template::parse("t", "before {{value", &HTML);
	}

	#[test]
	#[should_panic(expected = "nothing supplies it")]
	fn a_placeholder_nothing_supplies_is_a_hard_error_under_test() {
		let tpl = Template::parse("t", "{{missing}}", &HTML);
		render(&tpl, &Ctx::new());
	}

	#[test]
	#[should_panic(expected = "never reads it")]
	fn a_supplied_value_the_template_ignores_is_a_hard_error_under_test() {
		let tpl = Template::parse("t", "<p>ok</p>", &HTML);
		render(&tpl, &Ctx::new().text("stray", "x"));
	}
}
