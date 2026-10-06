/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;
use std::sync::Arc;

use super::{Span, VResult, VerifpalError};
use crate::term::{Constant, Value, ValueId, copy_index_of};
use crate::util::IdSet;

pub type PrincipalId = u8;

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

	pub(crate) fn outputs(&self) -> impl Iterator<Item = (&Constant, Value)> + '_ {
		self.assigned.iter().flat_map(move |assigned| {
			self.constants.iter().enumerate().map(move |(output, c)| {
				let Value::Primitive(p) = assigned else {
					return (c, assigned.clone());
				};
				let mut projected = p.with_output(output);
				if crate::primitive::primitive_get(projected.id)
					.is_ok_and(|spec| spec.distinct_per_assignment)
					&& let Some(first) = self.constants.first()
				{
					projected.instance = copy_index_of(first.id).1;
				}
				(c, Value::Primitive(Arc::new(projected)))
			})
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn query_kind_names() {
		assert_eq!(QueryKind::Confidentiality.name(), "confidentiality");
		assert_eq!(QueryKind::Authentication.name(), "authentication");
		assert_eq!(QueryKind::Freshness.name(), "freshness");
		assert_eq!(QueryKind::Unlinkability.name(), "unlinkability");
		assert_eq!(QueryKind::Equivalence.name(), "equivalence");
	}
}
