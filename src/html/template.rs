/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::LazyLock;

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
}

impl Template {
	fn parse(name: &'static str, raw: &'static str) -> Template {
		let mut at = 0usize;
		let nodes = parse_block(strip_header(raw), &mut at);
		Template { name, nodes }
	}
}

fn strip_header(raw: &'static str) -> &'static str {
	let trimmed = raw.trim_start();
	let body = if let Some(after) = trimmed.strip_prefix("<!--") {
		after.split_once("-->").map(|(_, tail)| tail)
	} else if let Some(after) = trimmed.strip_prefix("/*") {
		after.split_once("*/").map(|(_, tail)| tail)
	} else {
		None
	};
	body.unwrap_or(raw).trim_ascii()
}

fn parse_block(src: &'static str, at: &mut usize) -> Vec<Node> {
	let mut nodes: Vec<Node> = Vec::new();
	while *at < src.len() {
		let rest = &src[*at..];
		let Some(open) = rest.find("{{") else {
			nodes.push(Node::Lit(rest));
			*at = src.len();
			break;
		};
		if open > 0 {
			nodes.push(Node::Lit(&rest[..open]));
		}
		let after = &rest[open + 2..];
		let Some(close) = after.find("}}") else {
			nodes.push(Node::Lit(&rest[open..]));
			*at = src.len();
			break;
		};
		let tag = after[..close].trim();
		*at += open + close + 4;
		match tag.as_bytes().first() {
			Some(b'#') | Some(b'^') => {
				let inverted = tag.starts_with('^');
				let key = tag[1..].trim();
				let body = parse_block(src, at);
				nodes.push(Node::Section {
					key,
					inverted,
					body,
				});
			}
			Some(b'/') => return nodes,
			Some(b'>') => nodes.push(Node::Partial(tag[1..].trim())),
			_ => nodes.push(Node::Var(tag)),
		}
	}
	nodes
}

pub(crate) fn render(template: &Template, ctx: &Ctx) -> String {
	let mut out = String::with_capacity(1024);
	audit(template.name, &template.nodes, ctx);
	emit(template, &template.nodes, &[ctx], &mut out, 0);
	out
}

fn emit(owner: &Template, nodes: &[Node], stack: &[&Ctx], out: &mut String, depth: usize) {
	for node in nodes {
		match node {
			Node::Lit(text) => out.push_str(text),
			Node::Var(key) => match lookup(owner.name, stack, key) {
				Some(Val::Text(text)) => push_escaped(out, text),
				Some(Val::Raw(markup)) => out.push_str(markup),
				_ => {}
			},
			Node::Section {
				key,
				inverted,
				body,
			} => {
				let found = lookup(owner.name, stack, key);
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
							audit(owner.name, body, item);
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
				if let Some(part) = partial(name) {
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

fn lookup<'a>(owner: &str, stack: &[&'a Ctx], key: &str) -> Option<&'a Val> {
	for ctx in stack.iter().rev() {
		if let Some(value) = ctx.get(key) {
			return Some(value);
		}
	}
	if cfg!(test) {
		panic!("template '{owner}' reads {{{{{key}}}}} but nothing supplies it");
	}
	None
}

fn audit(owner: &str, nodes: &[Node], ctx: &Ctx) {
	if !cfg!(test) {
		return;
	}
	let mut read: Vec<&'static str> = Vec::new();
	collect(nodes, &mut read, &mut Vec::new());
	for (key, _) in &ctx.fields {
		assert!(
			read.contains(key),
			"template '{owner}' is supplied '{key}' but never reads it"
		);
	}
}

fn collect(nodes: &[Node], out: &mut Vec<&'static str>, seen: &mut Vec<&'static str>) {
	for node in nodes {
		match node {
			Node::Lit(_) => {}
			Node::Var(key) => out.push(key),
			Node::Section { key, body, .. } => {
				out.push(key);
				collect(body, out, seen);
			}
			Node::Partial(name) => {
				if seen.contains(name) {
					continue;
				}
				seen.push(name);
				if let Some(part) = partial(name) {
					collect(&part.nodes, out, seen);
				}
			}
		}
	}
}

fn push_escaped(out: &mut String, text: &str) {
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

macro_rules! templates {
	($($konst:ident $short:literal = $file:literal),* $(,)?) => {
		$(
			pub(crate) static $konst: LazyLock<Template> =
				LazyLock::new(|| Template::parse($short, include_str!(concat!("tpl/", $file))));
		)*

		fn partial(name: &str) -> Option<&'static Template> {
			match name {
				$($short => Some(&*$konst),)*
				_ => None,
			}
		}

		#[cfg(test)]
		pub(crate) fn every_template() -> Vec<&'static Template> {
			vec![$(&*$konst),*]
		}
	};
}

templates! {
	PAGE "page" = "page.html",
	RUN_INDEX "run_index" = "run_index.html",
	MODEL "model" = "model.html",
	ERROR "error" = "error.html",
	SCOPE "scope" = "scope.html",
	VERDICTS "verdicts" = "verdicts.html",
	VERDICT "verdict" = "verdict.html",
	CALLOUTS "callouts" = "callouts.html",
	TRACE "trace" = "trace.html",
	TRACE_STEP "trace_step" = "trace_step.html",
	TRACE_VALUE "trace_value" = "trace_value.html",
	SOURCE "source" = "source.html",
	SOURCE_CHUNK "source_chunk" = "source_chunk.html",
	DIAGRAM "diagram" = "diagram.html",
	DIAGRAM_ROW "diagram_row" = "diagram_row.html",
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_text_value_is_escaped_and_a_raw_value_is_not() {
		let tpl = Template::parse("t", "<p>{{a}}|{{b}}</p>");
		let out = render(
			&tpl,
			&Ctx::new().text("a", "<i>&x</i>").raw("b", "<i>ok</i>"),
		);
		assert_eq!(out, "<p>&lt;i&gt;&amp;x&lt;/i&gt;|<i>ok</i></p>");
	}

	#[test]
	fn a_list_section_repeats_its_body_once_per_item() {
		let tpl = Template::parse("t", "{{#rows}}[{{n}}]{{/rows}}");
		let rows = vec![Ctx::new().num("n", 1), Ctx::new().num("n", 2)];
		assert_eq!(render(&tpl, &Ctx::new().list("rows", rows)), "[1][2]");
	}

	#[test]
	fn an_empty_list_renders_nothing_and_its_inverse_renders_instead() {
		let tpl = Template::parse("t", "{{#rows}}x{{/rows}}{{^rows}}none{{/rows}}");
		assert_eq!(render(&tpl, &Ctx::new().list("rows", vec![])), "none");
	}

	#[test]
	fn a_flag_section_renders_its_body_once() {
		let tpl = Template::parse("t", "{{#on}}yes{{/on}}{{^on}}no{{/on}}");
		assert_eq!(render(&tpl, &Ctx::new().flag("on", true)), "yes");
		assert_eq!(render(&tpl, &Ctx::new().flag("on", false)), "no");
	}

	#[test]
	fn a_list_item_falls_back_to_the_enclosing_context() {
		let tpl = Template::parse("t", "{{#rows}}{{model}}-{{n}} {{/rows}}");
		let rows = vec![Ctx::new().num("n", 1), Ctx::new().num("n", 2)];
		let ctx = Ctx::new().num("model", 7).list("rows", rows);
		assert_eq!(render(&tpl, &ctx), "7-1 7-2 ");
	}

	#[test]
	fn a_value_carrying_template_syntax_is_never_rescanned() {
		let tpl = Template::parse("t", "{{a}}");
		assert_eq!(render(&tpl, &Ctx::new().text("a", "{{b}}")), "{{b}}");
	}

	#[test]
	fn the_spdx_header_is_stripped_once_at_parse_time() {
		let tpl = Template::parse("t", "<!-- SPDX-License-Identifier: X -->\n<p>hi</p>\n");
		assert_eq!(render(&tpl, &Ctx::new()), "<p>hi</p>");
	}

	#[test]
	#[should_panic(expected = "nothing supplies it")]
	fn a_placeholder_nothing_supplies_is_a_hard_error_under_test() {
		let tpl = Template::parse("t", "{{missing}}");
		render(&tpl, &Ctx::new());
	}

	#[test]
	#[should_panic(expected = "never reads it")]
	fn a_supplied_value_the_template_ignores_is_a_hard_error_under_test() {
		let tpl = Template::parse("t", "<p>ok</p>");
		render(&tpl, &Ctx::new().text("stray", "x"));
	}

	#[test]
	fn every_shipped_template_parses_to_something() {
		for template in every_template() {
			assert!(
				!template.nodes.is_empty(),
				"{} parsed to nothing",
				template.name
			);
		}
	}

	#[test]
	fn every_partial_reference_names_a_template_that_exists() {
		fn walk(nodes: &[Node], owner: &str) {
			for node in nodes {
				match node {
					Node::Partial(name) => assert!(
						partial(name).is_some(),
						"{owner} includes unknown partial '{name}'"
					),
					Node::Section { body, .. } => walk(body, owner),
					_ => {}
				}
			}
		}
		for template in every_template() {
			walk(&template.nodes, template.name);
		}
	}
}
