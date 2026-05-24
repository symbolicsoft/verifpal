# Preserve Comments in `--pretty` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verifpal pretty <model>` round-trip the user's `//` and `/* */` comments instead of stripping them.

**Architecture:** Trivia attached to AST nodes. Parser captures comments into a `pending_leading: Vec<Comment>` buffer, drains it into the next AST node's `leading_comments`. A separate `try_take_trailing` captures same-line comments after a node. Comments before a container's closing `]` become `tail_comments`. The pretty-printer renders these in order.

**Tech Stack:** Rust (edition 2021), `cargo test --release`, existing `Parser` + `pretty_model` codepaths in `src/parser.rs` and `src/pretty.rs`.

**Spec:** `docs/superpowers/specs/2026-05-24-pretty-preserve-comments-design.md`

**File structure:**
| File | Role | Touched in |
|---|---|---|
| `src/types.rs` | Adds `Comment`, `CommentStyle`, AST comment fields | Task 1 |
| `src/parser.rs` | Replaces `skip_whitespace_and_comments` with `consume_trivia`; drains buffers into nodes | Tasks 2–7 |
| `src/pretty.rs` | Adds `render_leading` / `render_trailing` / `render_block_comment`; emits comments in `pretty_model` and `pretty_principal` | Task 8 |
| `src/main.rs` (`unit_tests` mod) | All new tests (per-position parse, idempotence, golden, edge cases) | Tasks 9–11 |
| `examples/test/golden_pretty/*.vp` | Golden formatted output for round-trip checks | Task 10 |

`src/sanity.rs`, `src/verify.rs`, `src/json.rs`, `src/lib.rs`, `src/main.rs` (CLI bits) are **not** touched — they ignore the new fields.

---

## Task 1: Data model — `Comment`, `CommentStyle`, AST fields

**Files:**
- Modify: `src/types.rs` (add `Comment`, `CommentStyle`, fields on `Model`, `Principal`, `Message`, `Phase`, `Expression`, `Query`, `QueryOption`)
- Modify: `src/parser.rs` (update struct literals at lines 285, 331, 360, 460, 472, 489, 663, 692, 721, 739, 820 to include the new fields defaulted to `Vec::new()` / `None`)

- [ ] **Step 1: Add `Comment` and `CommentStyle` types**

Edit `src/types.rs`. After the existing `Qualifier` enum (around line 50), before `Declaration`, add:

```rust
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
```

- [ ] **Step 2: Add fields to `Model`**

Edit `src/types.rs`. The `Model` struct (line 226) becomes:

```rust
#[derive(Clone, Debug)]
pub struct Model {
	pub file_name: String,
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
```

- [ ] **Step 3: Add fields to `Principal`**

The `Principal` struct (line 279) becomes:

```rust
#[derive(Clone, Debug, Default)]
pub struct Principal {
	pub name: String,
	pub id: PrincipalId,
	pub expressions: Vec<Expression>,
	pub leading_comments: Vec<Comment>,
	pub header_trailing: Option<Comment>,
	pub tail_comments: Vec<Comment>,
	pub closing_trailing: Option<Comment>,
}
```

- [ ] **Step 4: Add fields to `Message`, `Phase`, `Expression`, `Query`, `QueryOption`**

`Message` (line 286):
```rust
#[derive(Clone, Debug, Default)]
pub struct Message {
	pub sender: PrincipalId,
	pub recipient: PrincipalId,
	pub constants: Vec<Constant>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}
```

`Phase` (line 293):
```rust
#[derive(Clone, Debug, Default)]
pub struct Phase {
	pub number: i32,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}
```

`Expression` (line 318):
```rust
#[derive(Clone, Debug)]
pub struct Expression {
	pub kind: Declaration,
	pub qualifier: Option<Qualifier>,
	pub constants: Vec<Constant>,
	pub assigned: Option<Value>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}
```

`Query` (line 298):
```rust
#[derive(Clone, Debug)]
pub struct Query {
	pub kind: QueryKind,
	pub constants: Vec<Constant>,
	pub message: Message,
	pub options: Vec<QueryOption>,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}
```

`QueryOption` (line 306):
```rust
#[derive(Clone, Debug)]
pub struct QueryOption {
	pub kind: QueryOptionKind,
	pub message: Message,
	pub leading_comments: Vec<Comment>,
	pub trailing_comment: Option<Comment>,
}
```

- [ ] **Step 5: Update parser struct literals**

Edit `src/parser.rs`. Each existing literal needs the new fields appended with empty defaults. The full list:

`parse_model` (line 285):
```rust
Ok(Model {
	file_name: String::new(),
	attacker: attacker_type,
	blocks,
	queries,
	pre_attacker_comments: Vec::new(),
	attacker_trailing: None,
	queries_leading_comments: Vec::new(),
	queries_header_trailing: None,
	queries_tail_comments: Vec::new(),
	queries_closing_trailing: None,
	tail_comments: Vec::new(),
})
```

`parse_principal` (line 331):
```rust
Ok(Block::Principal(Principal {
	name,
	id,
	expressions,
	leading_comments: Vec::new(),
	header_trailing: None,
	tail_comments: Vec::new(),
	closing_trailing: None,
}))
```

`parse_message_block` (line 360):
```rust
Ok(Block::Message(Message {
	sender: sender_id,
	recipient: recipient_id,
	constants,
	leading_comments: Vec::new(),
	trailing_comment: None,
}))
```

`parse_knows`, `parse_simple_expression`, `parse_assignment` (lines 460, 472, 489): each `Ok(Expression { ... })` gets `leading_comments: Vec::new(), trailing_comment: None,` appended.

`parse_phase` (line 663):
```rust
Ok(Block::Phase(Phase {
	number,
	leading_comments: Vec::new(),
	trailing_comment: None,
}))
```

`parse_query_single_constant` (line 692), `parse_query_authentication` (line 721), `parse_query_multi_constant` (line 739): each `Ok(Query { ... })` gets `leading_comments: Vec::new(), trailing_comment: None,` appended.

`try_parse_query_options` (line 820): the `options.push(QueryOption { ... })` gets `leading_comments: Vec::new(), trailing_comment: None,` appended.

The two `message: Message::default()` calls in `parse_query_single_constant` and `parse_query_multi_constant` already pick up the new fields via `Default`. The two inline `message: Message { sender, recipient, constants }` literals (lines 724, 822) inside `parse_query_authentication` and `try_parse_query_options` need explicit `leading_comments: Vec::new(), trailing_comment: None,` appended.

- [ ] **Step 6: Confirm compilation and test pass**

Run: `cargo build --release`
Expected: clean build, no errors.

Run: `cargo test --release`
Expected: all 147 existing tests pass (we have not changed any behavior yet — only added empty fields).

- [ ] **Step 7: Commit**

```bash
git add src/types.rs src/parser.rs
git commit -m "types: add Comment/CommentStyle and AST comment fields

Pure-additive change. All comment fields default to empty (Vec::new() /
None); parser construction sites updated to match. No behavior change."
```

---

## Task 2: Parser — capture line comments and drain as leading

**Files:**
- Modify: `src/parser.rs` (Parser struct, replace `skip_whitespace_and_comments`, add `take_leading`)
- Modify: `src/main.rs` (add test in `unit_tests` mod)

- [ ] **Step 1: Write a failing test for leading-comment capture**

Edit `src/main.rs`. Find the end of the `unit_tests` mod (the closing `}` near line 1361). Just before that closing brace, add:

```rust
	// -----------------------------------------------------------------------
	// 32. Comment preservation: leading comments
	// -----------------------------------------------------------------------

	use verifpal::parser::parse_string;
	use verifpal::pretty::pretty_model;

	#[test]
	fn comment_capture_pre_attacker_line() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1, "expected 1 pre-attacker comment");
		assert_eq!(m.pre_attacker_comments[0].text, " hello");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Line
		));
	}
```

Run: `cargo test --release comment_capture_pre_attacker_line`
Expected: FAIL with assertion failure ("expected 1 pre-attacker comment, got 0") — the parser still drops the comment.

- [ ] **Step 2: Extend `Parser` struct with `pending_leading` buffer**

Edit `src/parser.rs`. Replace the `Parser` struct definition (line 104) with:

```rust
struct Parser<'a> {
	input: &'a [u8],
	pos: usize,
	pending_leading: Vec<Comment>,
}
```

Update `Parser::new` (line 110):

```rust
fn new(input: &'a str) -> Self {
	Parser {
		input: input.as_bytes(),
		pos: 0,
		pending_leading: Vec::new(),
	}
}
```

Add `use crate::types::Comment;` and `use crate::types::CommentStyle;` to the imports at the top of `src/parser.rs` (the existing `use crate::types::*;` already covers this; verify by checking line 6).

- [ ] **Step 3: Replace `skip_whitespace_and_comments` with `consume_trivia`**

In `src/parser.rs`, replace the existing `skip_whitespace_and_comments` (lines 154-169) with:

```rust
	/// Consume whitespace and comments. Captures comments into
	/// `pending_leading` so they can be attached to the next AST node
	/// via `take_leading`.
	fn consume_trivia(&mut self) {
		self.consume_trivia_inner(true);
	}

	/// Internal trivia consumer. When `capture` is false, comments are
	/// recognized and skipped but not stored — used for positions where
	/// comments are disallowed (inside primitive args, etc.).
	fn consume_trivia_inner(&mut self, capture: bool) {
		loop {
			self.skip_whitespace();
			if self.pos + 1 < self.input.len()
				&& self.input[self.pos] == b'/'
				&& self.input[self.pos + 1] == b'/'
			{
				// Line comment: capture text after `//` until end of line.
				let start = self.pos + 2;
				while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
					self.pos += 1;
				}
				if capture {
					let text = std::str::from_utf8(&self.input[start..self.pos])
						.unwrap_or("")
						.to_string();
					self.pending_leading.push(Comment {
						text,
						style: CommentStyle::Line,
					});
				}
			} else {
				break;
			}
		}
	}
```

- [ ] **Step 4: Update all call sites from `skip_whitespace_and_comments` to `consume_trivia`**

In `src/parser.rs`, find all 20 call sites (lines 218, 239, 244, 256, 266, 272, 275, 282, 294, 317, 320, 326, 329, 357, 431, 662, 667, 775, 780). Each `self.skip_whitespace_and_comments();` becomes `self.consume_trivia();`.

Use `sed` for speed:
```bash
sed -i '' 's/skip_whitespace_and_comments/consume_trivia/g' src/parser.rs
```

Also update the inline `//`-detection in `parse_message_constants` (line 379), `parse_constants` (line 529), `parse_query_constant_list` (line 761): those `rem.starts_with("//")` checks are still correct (they break the loop when a comment appears) — leave them alone.

- [ ] **Step 5: Add `take_leading` helper**

In `src/parser.rs`, just below `consume_trivia_inner`, add:

```rust
	/// Drain and return any pending leading comments. Called at the
	/// start of building each AST node.
	fn take_leading(&mut self) -> Vec<Comment> {
		std::mem::take(&mut self.pending_leading)
	}
```

- [ ] **Step 6: Drain `pending_leading` into `Model.pre_attacker_comments`**

In `src/parser.rs`, modify `parse_model` (line 217). Right before parsing the `attacker` keyword, drain the buffer into `pre_attacker_comments`. Replace:

```rust
	fn parse_model(&mut self) -> VResult<Model> {
		self.consume_trivia();

		// Parse attacker
		if !self.try_expect("attacker") {
```

with:

```rust
	fn parse_model(&mut self) -> VResult<Model> {
		self.consume_trivia();
		let pre_attacker_comments = self.take_leading();

		// Parse attacker
		if !self.try_expect("attacker") {
```

Then in the `Ok(Model { ... })` construction at the end of `parse_model`, replace `pre_attacker_comments: Vec::new(),` with `pre_attacker_comments,`.

- [ ] **Step 7: Run the test, confirm it passes**

Run: `cargo test --release comment_capture_pre_attacker_line`
Expected: PASS.

Run: `cargo test --release`
Expected: all tests still pass.

- [ ] **Step 8: Drain into block-level leading_comments**

Now wire up leading_comments for blocks and queries.

In `src/parser.rs`, modify `parse_block` (line 293). Replace:

```rust
	fn parse_block(&mut self) -> VResult<Block> {
		self.consume_trivia();

		if starts_with_keyword(self.remaining(), "phase") {
```

with:

```rust
	fn parse_block(&mut self) -> VResult<Block> {
		self.consume_trivia();
		let leading = self.take_leading();

		let mut block = if starts_with_keyword(self.remaining(), "phase") {
			self.parse_phase()?
		} else if starts_with_keyword(self.remaining(), "principal") {
			self.parse_principal()?
		} else {
			self.parse_message_block()?
		};
		match &mut block {
			Block::Principal(p) => p.leading_comments = leading,
			Block::Message(m) => m.leading_comments = leading,
			Block::Phase(p) => p.leading_comments = leading,
		}
		Ok(block)
	}
```

Remove the existing if/else returns inside `parse_block`. (The body is now entirely replaced.)

Inside `parse_principal` (line 310), at the top of the loop body that builds expressions (line 319-327), wire leading_comments per expression. Replace:

```rust
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let expr = self.parse_expression()?;
			expressions.push(expr);
			self.consume_trivia();
		}
```

with:

```rust
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let leading = self.take_leading();
			let mut expr = self.parse_expression()?;
			expr.leading_comments = leading;
			expressions.push(expr);
			self.consume_trivia();
		}
```

For queries, modify the `parse_model` queries loop (around line 273-283). Replace:

```rust
		self.consume_trivia();
		if !self.try_expect("queries") {
			return Err(VerifpalError::Parse("no `queries` block defined".into()));
		}
		self.skip_whitespace();
		self.expect("[")?;
		self.consume_trivia();
		let mut queries = Vec::new();
		while !self.at_end() {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				self.advance();
				break;
			}
			let query = self.parse_query()?;
			queries.push(query);
			self.consume_trivia();
		}
```

with:

```rust
		self.consume_trivia();
		let queries_leading_comments = self.take_leading();
		if !self.try_expect("queries") {
			return Err(VerifpalError::Parse("no `queries` block defined".into()));
		}
		self.skip_whitespace();
		self.expect("[")?;
		self.consume_trivia();
		let mut queries = Vec::new();
		while !self.at_end() {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				self.advance();
				break;
			}
			let leading = self.take_leading();
			let mut query = self.parse_query()?;
			query.leading_comments = leading;
			queries.push(query);
			self.consume_trivia();
		}
```

And in the final `Ok(Model { ... })`, replace `queries_leading_comments: Vec::new(),` with `queries_leading_comments,`.

- [ ] **Step 9: Add tests for each leading-comment position**

Add to `unit_tests` mod in `src/main.rs`, just after `comment_capture_pre_attacker_line`:

```rust
	#[test]
	fn comment_capture_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.blocks.len(), 1);
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert_eq!(p.leading_comments[0].text, " before alice");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term key\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.expressions.len(), 1);
				assert_eq!(p.expressions[0].leading_comments.len(), 1);
				assert_eq!(p.expressions[0].leading_comments[0].text, " long-term key");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries.len(), 1);
		assert_eq!(m.queries[0].leading_comments.len(), 1);
		assert_eq!(m.queries[0].leading_comments[0].text, " primary goal");
	}

	#[test]
	fn comment_capture_leading_on_queries_keyword() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// verify these\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_leading_comments.len(), 1);
		assert_eq!(m.queries_leading_comments[0].text, " verify these");
	}

	#[test]
	fn comment_capture_multiple_lines() {
		let src = "// line 1\n// line 2\n// line 3\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 3);
		assert_eq!(m.pre_attacker_comments[0].text, " line 1");
		assert_eq!(m.pre_attacker_comments[1].text, " line 2");
		assert_eq!(m.pre_attacker_comments[2].text, " line 3");
	}
```

Run: `cargo test --release comment_capture_`
Expected: all 5 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: capture // comments as leading on AST nodes

Replaces skip_whitespace_and_comments with consume_trivia, which buffers
captured comments into pending_leading. take_leading() drains the buffer
into Model.pre_attacker_comments, Model.queries_leading_comments, and the
leading_comments field of each block, expression, and query."
```

---

## Task 3: Parser — `/* */` block comments

**Files:**
- Modify: `src/parser.rs` (extend `consume_trivia_inner` to recognize `/* */`)
- Modify: `src/main.rs` (add tests)

- [ ] **Step 1: Write failing tests for block comments**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn comment_capture_block_pre_attacker() {
		let src = "/* hello */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(m.pre_attacker_comments[0].text, " hello ");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Block
		));
	}

	#[test]
	fn comment_capture_block_multiline() {
		let src = "/* line1\n   line2\n   line3 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(
			m.pre_attacker_comments[0].text,
			" line1\n   line2\n   line3 "
		);
	}

	#[test]
	fn comment_capture_block_unterminated_errors() {
		let src = "/* never closed\nattacker[active]\n";
		assert!(parse_string("t.vp", src).is_err());
	}
```

Run: `cargo test --release comment_capture_block_`
Expected: 3 FAILS — current parser doesn't recognize `/* */`.

- [ ] **Step 2: Extend `consume_trivia_inner` to handle `/* */`**

In `src/parser.rs`, replace `consume_trivia_inner` with:

```rust
	fn consume_trivia_inner(&mut self, capture: bool) {
		loop {
			self.skip_whitespace();
			let two = if self.pos + 1 < self.input.len() {
				(self.input[self.pos], self.input[self.pos + 1])
			} else {
				(0, 0)
			};
			if two == (b'/', b'/') {
				let start = self.pos + 2;
				while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
					self.pos += 1;
				}
				if capture {
					let text = std::str::from_utf8(&self.input[start..self.pos])
						.unwrap_or("")
						.to_string();
					self.pending_leading.push(Comment {
						text,
						style: CommentStyle::Line,
					});
				}
			} else if two == (b'/', b'*') {
				let open = self.pos;
				self.pos += 2;
				let start = self.pos;
				loop {
					if self.pos + 1 >= self.input.len() {
						// Unterminated — record by leaving self.pos at end
						// and emitting nothing; the caller will surface the
						// error via the expect/at_end check that follows.
						// To make this explicit, we set a sentinel flag via
						// the input position so parse_model can detect.
						// Simpler: surface here by panicking via Err path.
						// But consume_trivia returns (). Instead, we set
						// `self.pos = self.input.len()` and queue an
						// "unterminated" marker we'll surface on next call.
						// For simplicity: produce a Comment with sentinel
						// text and let a later check error out.
						//
						// Cleaner: return a Result. But changing signature
						// ripples through every call site. Instead, store
						// an `unterminated_block_at: Option<usize>` on the
						// Parser and check it after each consume_trivia.
						self.pos = self.input.len();
						self.unterminated_block_at = Some(open);
						return;
					}
					if self.input[self.pos] == b'*' && self.input[self.pos + 1] == b'/' {
						let end = self.pos;
						self.pos += 2;
						if capture {
							let text = std::str::from_utf8(&self.input[start..end])
								.unwrap_or("")
								.to_string();
							self.pending_leading.push(Comment {
								text,
								style: CommentStyle::Block,
							});
						}
						break;
					}
					self.pos += 1;
				}
			} else {
				break;
			}
		}
	}
```

Add `unterminated_block_at: Option<usize>` to the `Parser` struct:

```rust
struct Parser<'a> {
	input: &'a [u8],
	pos: usize,
	pending_leading: Vec<Comment>,
	unterminated_block_at: Option<usize>,
}
```

Update `Parser::new`:

```rust
fn new(input: &'a str) -> Self {
	Parser {
		input: input.as_bytes(),
		pos: 0,
		pending_leading: Vec::new(),
		unterminated_block_at: None,
	}
}
```

Add a check helper:

```rust
	fn check_unterminated_block(&self) -> VResult<()> {
		if let Some(pos) = self.unterminated_block_at {
			return Err(VerifpalError::Parse(
				format!("unterminated block comment starting at byte {}", pos).into(),
			));
		}
		Ok(())
	}
```

In `parse_model`, immediately after the very first `self.consume_trivia();` (before parsing `attacker`), call `self.check_unterminated_block()?;` and also at the end of `parse_model` (just before constructing the `Model`).

- [ ] **Step 3: Run tests, confirm pass**

Run: `cargo test --release comment_capture_block_`
Expected: all 3 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: recognize /* */ block comments

consume_trivia_inner now captures block comments alongside line comments.
Unterminated /* surfaces as a parse error via a deferred-check pattern,
keeping consume_trivia's () return type unchanged."
```

---

## Task 4: Parser — trailing comments

**Files:**
- Modify: `src/parser.rs` (add `try_take_trailing`, wire it after each node's last token)
- Modify: `src/main.rs` (tests)

- [ ] **Step 1: Write failing tests for trailing comments**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn comment_capture_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term key\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_some());
				assert_eq!(
					p.expressions[0].trailing_comment.as_ref().unwrap().text,
					" long-term key"
				);
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_trailing_on_attacker() {
		let src = "attacker[active] // active model\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.attacker_trailing.is_some());
		assert_eq!(m.attacker_trailing.as_ref().unwrap().text, " active model");
	}

	#[test]
	fn comment_capture_trailing_on_message() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // initial flight\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let msg = m.blocks.iter().find_map(|b| match b {
			Block::Message(m) => Some(m),
			_ => None,
		}).expect("message");
		assert!(msg.trailing_comment.is_some());
		assert_eq!(msg.trailing_comment.as_ref().unwrap().text, " initial flight");
	}

	#[test]
	fn comment_capture_trailing_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a // primary\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries[0].trailing_comment.is_some());
		assert_eq!(m.queries[0].trailing_comment.as_ref().unwrap().text, " primary");
	}

	#[test]
	fn comment_capture_block_trailing_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				let t = p.expressions[0].trailing_comment.as_ref().expect("trailing");
				assert_eq!(t.text, " lt ");
				assert!(matches!(t.style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_block_trailing_multiline_promoted_to_leading() {
		// Block comment that opens on same line as expression but closes
		// on a later line — must NOT be a trailing; should attach as
		// leading on the next node.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* multi\n\tline */\n\tknows private b\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_none());
				assert_eq!(p.expressions[1].leading_comments.len(), 1);
				assert_eq!(p.expressions[1].leading_comments[0].text, " multi\n\tline ");
			}
			_ => panic!(),
		}
	}
```

Run: `cargo test --release comment_capture_trailing_ comment_capture_block_trailing_`
Expected: 6 FAILS.

- [ ] **Step 2: Add `try_take_trailing` to `Parser`**

In `src/parser.rs`, after `take_leading`:

```rust
	/// Try to capture a same-line trailing comment after the node's
	/// last token. Skips inline whitespace (spaces/tabs only) and
	/// returns a Comment if one opens and (for block style) closes
	/// before the next newline. Leaves `self.pos` past the comment
	/// if captured, or unchanged if not.
	fn try_take_trailing(&mut self) -> Option<Comment> {
		let saved = self.pos;
		self.skip_inline_whitespace();
		if self.pos + 1 >= self.input.len() {
			self.pos = saved;
			return None;
		}
		let two = (self.input[self.pos], self.input[self.pos + 1]);
		if two == (b'/', b'/') {
			let start = self.pos + 2;
			self.pos += 2;
			while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
				self.pos += 1;
			}
			let text = std::str::from_utf8(&self.input[start..self.pos])
				.unwrap_or("")
				.to_string();
			Some(Comment {
				text,
				style: CommentStyle::Line,
			})
		} else if two == (b'/', b'*') {
			// Scan for `*/` BEFORE the next newline. If we hit a newline
			// first, this is NOT a trailing comment — restore pos and
			// return None so the next consume_trivia picks it up as a
			// leading comment of the next node.
			let probe_start = self.pos + 2;
			let mut probe = probe_start;
			loop {
				if probe + 1 >= self.input.len() {
					// Unterminated — leave for consume_trivia to flag.
					self.pos = saved;
					return None;
				}
				let c = self.input[probe];
				if c == b'\n' {
					self.pos = saved;
					return None;
				}
				if c == b'*' && self.input[probe + 1] == b'/' {
					let text = std::str::from_utf8(&self.input[probe_start..probe])
						.unwrap_or("")
						.to_string();
					self.pos = probe + 2;
					return Some(Comment {
						text,
						style: CommentStyle::Block,
					});
				}
				probe += 1;
			}
		} else {
			self.pos = saved;
			None
		}
	}
```

- [ ] **Step 3: Wire `try_take_trailing` after each node's last token**

We attach trailing comments at the moment a node finishes parsing — typically right after we've consumed the final token and before the next `consume_trivia` call.

**Attacker trailing** (in `parse_model`, around line 238): after `self.expect("]")?;` for the attacker block, do:

```rust
		self.skip_whitespace();
		self.expect("]")?;
		let attacker_trailing = self.try_take_trailing();
		self.consume_trivia();
```

Pass `attacker_trailing` through to the final `Ok(Model { ... attacker_trailing, ... })`.

**Expression trailing** (in `parse_principal` around line 322): change

```rust
			let leading = self.take_leading();
			let mut expr = self.parse_expression()?;
			expr.leading_comments = leading;
			expressions.push(expr);
```

to:

```rust
			let leading = self.take_leading();
			let mut expr = self.parse_expression()?;
			expr.leading_comments = leading;
			expr.trailing_comment = self.try_take_trailing();
			expressions.push(expr);
```

**Message trailing** (in `parse_message_block` around line 357): change

```rust
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		self.consume_trivia();
```

to:

```rust
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		let trailing = self.try_take_trailing();
		self.consume_trivia();
```

Update the final `Ok(Block::Message(Message { ... }))` to include `trailing_comment: trailing,`.

But `parse_message_constants` itself stops at newline/keyword. To attach trailing, we need it to NOT consume the trailing newline before we run `try_take_trailing`. Let me inspect: `parse_message_constants` (line 367) breaks on `Some(b'\n')` without advancing past — good. So after returning we're at the newline (or at a comment that we'd otherwise skip). We can call `try_take_trailing` right then.

**Phase trailing** (in `parse_phase` around line 661): change

```rust
		self.skip_whitespace();
		self.expect("]")?;
		self.consume_trivia();
		Ok(Block::Phase(Phase { ... }))
```

to:

```rust
		self.skip_whitespace();
		self.expect("]")?;
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		Ok(Block::Phase(Phase {
			number,
			leading_comments: Vec::new(),
			trailing_comment: trailing,
		}))
```

**Query trailing** is captured by the loop body in `parse_model`, NOT inside `parse_query_*`, to stay consistent with how `Expression` trailing is captured in `parse_principal`'s loop body. Modify the queries loop in `parse_model` (set up in Task 2 step 8) to add the trailing capture:

```rust
		while !self.at_end() {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				self.advance();
				break;
			}
			let leading = self.take_leading();
			let mut query = self.parse_query()?;
			query.leading_comments = leading;
			query.trailing_comment = self.try_take_trailing();
			queries.push(query);
			self.consume_trivia();
		}
```

(Do NOT modify `parse_query_single_constant`, `parse_query_authentication`, or `parse_query_multi_constant` — their `Ok(Query { ... trailing_comment: None, ... })` literals stay as initialized.)

For trailing comments on the `attacker[active]` line, we also need `try_take_trailing` to NOT cross a newline for line comments. The current implementation reads until newline for `//`, which is fine — it consumes up to but not past the `\n`. Good.

Edge: an inline `// foo` comment naturally consumes to end of line, so the comment IS still on the same line — even though we read through to `\n`. The "same line" test is: is there a newline between the node's last token and the comment's start? Since `try_take_trailing` only skips spaces/tabs (`skip_inline_whitespace`), if there's a `\n` between the node and the `//`, we won't reach the `//` — the `\n` is not inline whitespace and we'll return `None`. Correct.

- [ ] **Step 4: Run tests, confirm pass**

Run: `cargo test --release comment_capture_trailing_ comment_capture_block_trailing_`
Expected: all 6 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: capture trailing same-line comments

try_take_trailing peeks for // or single-line /* */ on the same line as
the node's last token, attaching to expression / message / phase / query
trailing_comment fields. Multi-line block comments that open on the
node's line but close later are NOT trailing — they fall through to the
next consume_trivia call as leading comments."
```

---

## Task 5: Parser — tail comments and closing-line trailings

**Files:**
- Modify: `src/parser.rs` (drain pending_leading into container tail_comments at close; capture closing_trailing)
- Modify: `src/main.rs` (tests)

- [ ] **Step 1: Write failing tests**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn comment_capture_tail_in_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO add more\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.tail_comments.len(), 1);
				assert_eq!(p.tail_comments[0].text, " TODO add more");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_closing_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n] // end of Alice\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.closing_trailing.is_some());
				assert_eq!(p.closing_trailing.as_ref().unwrap().text, " end of Alice");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_header_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[ // initiator\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.header_trailing.is_some());
				assert_eq!(p.header_trailing.as_ref().unwrap().text, " initiator");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_queries() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n\t// done\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_tail_comments.len(), 1);
		assert_eq!(m.queries_tail_comments[0].text, " done");
	}

	#[test]
	fn comment_capture_queries_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n] // end\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_closing_trailing.is_some());
		assert_eq!(m.queries_closing_trailing.as_ref().unwrap().text, " end");
	}

	#[test]
	fn comment_capture_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF tail\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.tail_comments.len(), 1);
		assert_eq!(m.tail_comments[0].text, " EOF tail");
	}

	#[test]
	fn comment_capture_queries_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_header_trailing.is_some());
		assert_eq!(m.queries_header_trailing.as_ref().unwrap().text, " start");
	}
```

Run: `cargo test --release comment_capture_tail_ comment_capture_closing_trailing_ comment_capture_header_trailing_ comment_capture_queries_ comment_capture_eof_`
Expected: 7 FAILS.

- [ ] **Step 2: Drain `pending_leading` into `Principal.tail_comments`**

In `src/parser.rs`, `parse_principal` (line 310):

```rust
	fn parse_principal(&mut self) -> VResult<Block> {
		self.expect("principal")?;
		self.skip_whitespace();
		let name = self.parse_identifier()?;
		let name = title_case(&name);
		self.skip_whitespace();
		self.expect("[")?;
		let header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let leading = self.take_leading();
			let mut expr = self.parse_expression()?;
			expr.leading_comments = leading;
			expr.trailing_comment = self.try_take_trailing();
			expressions.push(expr);
			self.consume_trivia();
		}
		let tail_comments = self.take_leading();
		self.expect("]")?;
		let closing_trailing = self.try_take_trailing();
		self.consume_trivia();
		let id = principal_names_map_add(&name);
		Ok(Block::Principal(Principal {
			name,
			id,
			expressions,
			leading_comments: Vec::new(),
			header_trailing,
			tail_comments,
			closing_trailing,
		}))
	}
```

- [ ] **Step 3: Drain into `Model.queries_tail_comments`, `queries_header_trailing`, `queries_closing_trailing`**

In `src/parser.rs`, modify the queries-parsing section of `parse_model`. Replace the corresponding block with:

```rust
		// Parse queries
		self.consume_trivia();
		let queries_leading_comments = self.take_leading();
		if !self.try_expect("queries") {
			return Err(VerifpalError::Parse("no `queries` block defined".into()));
		}
		self.skip_whitespace();
		self.expect("[")?;
		let queries_header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut queries = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			if self.at_end() {
				break;
			}
			let leading = self.take_leading();
			let mut query = self.parse_query()?;
			query.leading_comments = leading;
			query.trailing_comment = self.try_take_trailing();
			queries.push(query);
			self.consume_trivia();
		}
		let queries_tail_comments = self.take_leading();
		let queries_closing_trailing = if self.peek() == Some(b']') {
			self.advance();
			self.try_take_trailing()
		} else {
			None
		};
		self.consume_trivia();
		let tail_comments = self.take_leading();
		self.check_unterminated_block()?;
```

Note: Task 4 already added `query.trailing_comment = self.try_take_trailing();` to the loop body. Task 5's loop above preserves that line unchanged — we only added the queries_tail_comments / queries_closing_trailing / tail_comments handling around it.

Update the final `Ok(Model { ... })`:

```rust
		Ok(Model {
			file_name: String::new(),
			attacker: attacker_type,
			blocks,
			queries,
			pre_attacker_comments,
			attacker_trailing,
			queries_leading_comments,
			queries_header_trailing,
			queries_tail_comments,
			queries_closing_trailing,
			tail_comments,
		})
```

- [ ] **Step 4: Run tests, confirm pass**

Run: `cargo test --release comment_capture_`
Expected: all comment_capture_ tests PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: capture tail and closing-line trailing comments

Drains pending_leading into Principal.tail_comments / Model.queries_tail_comments
/ Model.tail_comments at container close / EOF. Adds header_trailing and
closing_trailing capture for principal[...] and queries[...] blocks."
```

---

## Task 6: Parser — lookahead-safe rollback

**Files:**
- Modify: `src/parser.rs`
- Modify: `src/main.rs` (tests)

**Why this matters:** `parse_message_constants` (line 386) does an identifier lookahead to decide whether the next thing is a new message vs another constant. If the lookahead crosses a comment, that comment gets captured into `pending_leading`; when the lookahead rolls back (`self.pos = saved`), the comment stays in the buffer and gets misattached to the wrong node.

- [ ] **Step 1: Write failing test**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn comment_lookahead_does_not_leak() {
		// The parse_message_constants lookahead inspects what comes
		// after a comma. If a comment sits between the message and the
		// next block, the lookahead must NOT capture it into the
		// previous message's leading comments after rollback.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a\n// next block\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		// "// next block" must attach to the Bob principal block,
		// not the previous Alice -> Bob message.
		let msg = m.blocks.iter().find_map(|b| match b {
			Block::Message(m) => Some(m),
			_ => None,
		}).expect("message");
		assert!(msg.trailing_comment.is_none());
		let bob = m.blocks.iter().find_map(|b| match b {
			Block::Principal(p) if p.name == "Bob" => Some(p),
			_ => None,
		}).expect("bob");
		assert_eq!(bob.leading_comments.len(), 1);
		assert_eq!(bob.leading_comments[0].text, " next block");
	}
```

Run: `cargo test --release comment_lookahead_does_not_leak`
Expected: depends on current behavior — may incidentally pass if `parse_message_constants` lookahead doesn't cross the comment line. Run to confirm.

If it passes, we still need the safety measure for correctness — there are other lookahead sites. Continue to step 2.

- [ ] **Step 2: Add snapshot/restore helpers**

In `src/parser.rs`, add helpers below `take_leading`:

```rust
	/// Snapshot the parser state for a potentially-aborted lookahead.
	fn snapshot(&self) -> (usize, usize) {
		(self.pos, self.pending_leading.len())
	}

	/// Restore parser state from a snapshot, discarding any comments
	/// captured during the rolled-back lookahead.
	fn restore(&mut self, (pos, leading_len): (usize, usize)) {
		self.pos = pos;
		self.pending_leading.truncate(leading_len);
	}
```

- [ ] **Step 3: Update lookahead call sites to use snapshot/restore**

Find every `let saved = self.pos;` / `self.pos = saved;` pattern in `src/parser.rs`. There are three:

1. `parse_message_constants` (line 386): change

```rust
				let saved = self.pos;
				if let Ok(_id) = self.parse_identifier() {
					self.skip_whitespace();
					if self.remaining().starts_with("->") || self.remaining().starts_with("\u{2192}") {
						self.pos = saved;
						break;
					}
					self.pos = saved;
				} else {
					self.pos = saved;
				}
```

to:

```rust
				let saved = self.snapshot();
				if let Ok(_id) = self.parse_identifier() {
					self.skip_whitespace();
					if self.remaining().starts_with("->") || self.remaining().starts_with("\u{2192}") {
						self.restore(saved);
						break;
					}
					self.restore(saved);
				} else {
					self.restore(saved);
				}
```

2. `parse_value` (line 575): change `let saved = self.pos;` and the subsequent `self.pos = saved;` lines analogously to use `snapshot()` / `restore()`.

3. Any other site found via `grep -n "self\.pos = saved" src/parser.rs`. Apply the same transformation.

- [ ] **Step 4: Run all tests**

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: lookahead-safe comment rollback

snapshot()/restore() capture pending_leading.len() alongside pos so that
a rolled-back lookahead doesn't leave comments captured by the lookahead
in the buffer to be misattached to a later node."
```

---

## Task 7: Parser — disallowed-position drop

**Files:**
- Modify: `src/parser.rs` (thread `allow_comments` into disallowed-position parse helpers)
- Modify: `src/main.rs` (tests)

**Disallowed positions:** inside primitive args, between equation halves, inside `attacker[...]` / `phase[N]` / option `[...]` brackets.

- [ ] **Step 1: Write failing tests**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn comment_dropped_in_primitive_args() {
		// Comment between primitive arguments is silently dropped.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tx = ENC(/* secret */ a, a)\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		// No AST field contains "secret".
		let serialized = format!("{:?}", m);
		assert!(!serialized.contains("secret"), "dropped comment must not appear in AST");
	}

	#[test]
	fn comment_dropped_in_equation() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tg = G ^ /* exp */ a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let serialized = format!("{:?}", m);
		assert!(!serialized.contains("exp"), "dropped comment must not appear in AST");
	}
```

Run: `cargo test --release comment_dropped_`
Expected: 2 FAILS — comment from inside primitive args ends up captured somewhere.

- [ ] **Step 2: Add `consume_trivia_nocapture` to Parser**

In `src/parser.rs`, add:

```rust
	/// Same as `consume_trivia`, but discards any comments encountered
	/// rather than buffering them. Used in disallowed-comment positions
	/// (inside primitive args, equation halves, attacker[]/phase[]
	/// brackets, query option brackets).
	fn consume_trivia_nocapture(&mut self) {
		self.consume_trivia_inner(false);
	}
```

- [ ] **Step 3: Use `consume_trivia_nocapture` at disallowed-position sites**

Search-and-replace selectively. The sites:

- `parse_primitive` (lines 600-633): every `self.skip_whitespace();` becomes `self.consume_trivia_nocapture();` *except* the one right before the optional comma (line 622) — that's outside the args list. Let me be precise: lines 605, 613, 616 are inside the args loop. Replace all three.

Specifically:
```rust
	fn parse_primitive(&mut self) -> VResult<Value> {
		let name = self.parse_identifier()?;
		let prim_name = name.to_uppercase();
		self.skip_whitespace();
		self.expect("(")?;
		self.consume_trivia_nocapture();
		let mut arguments = Vec::new();
		while self.peek() != Some(b')') {
			if self.at_end() {
				return Err(VerifpalError::Parse("unterminated primitive".into()));
			}
			let arg = self.parse_value()?;
			arguments.push(arg);
			self.consume_trivia_nocapture();
			if self.peek() == Some(b',') {
				self.advance();
				self.consume_trivia_nocapture();
			}
		}
		self.expect(")")?;
		let check = self.try_expect("?");
		// Consume optional comma — keep skip_whitespace here (outside the args list).
		self.skip_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		let prim_id = primitive_get_enum(&prim_name)?;
		Ok(Value::Primitive(Arc::new(Primitive {
			id: prim_id,
			arguments,
			output: 0,
			instance_check: check,
		})))
	}
```

- `parse_equation` (line 635): the two `self.skip_whitespace();` calls (lines 637 and 639) between the two halves and around the `^`. These are NOT trivia points (they only skip whitespace, not comments). But a `/* */` comment between `G` and `^` or between `^` and `a` would currently fail to parse. To match the spec (silently drop), change them to `consume_trivia_nocapture()`:

```rust
	fn parse_equation(&mut self) -> VResult<Value> {
		let first = self.parse_constant_value()?;
		self.consume_trivia_nocapture();
		self.expect("^")?;
		self.consume_trivia_nocapture();
		let second = self.parse_constant_value()?;
		Ok(Value::Equation(Arc::new(Equation {
			values: vec![first, second],
		})))
	}
```

- `parse_phase` (line 646): the `self.skip_whitespace();` calls around the brackets (lines 648, 650, 660) — change to `consume_trivia_nocapture()` to drop comments inside `[N]`:

```rust
	fn parse_phase(&mut self) -> VResult<Block> {
		self.expect("phase")?;
		self.consume_trivia_nocapture();
		self.expect("[")?;
		self.consume_trivia_nocapture();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		// ... (unchanged)
		self.consume_trivia_nocapture();
		self.expect("]")?;
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		Ok(Block::Phase(Phase {
			number,
			leading_comments: Vec::new(),
			trailing_comment: trailing,
		}))
	}
```

- `parse_model` attacker brackets (around line 224-238): same — the `self.skip_whitespace();` between `[` and `]` for `attacker[...]` should drop comments. Replace those three `skip_whitespace` calls with `consume_trivia_nocapture()`. Be careful: don't break the very first `consume_trivia()` at line 218 that captures pre_attacker_comments.

```rust
		self.consume_trivia();
		let pre_attacker_comments = self.take_leading();
		self.check_unterminated_block()?;

		// Parse attacker
		if !self.try_expect("attacker") {
			return Err(VerifpalError::Parse("no `attacker` block defined".into()));
		}
		self.consume_trivia_nocapture();
		self.expect("[")?;
		self.consume_trivia_nocapture();
		let attacker_str = self.parse_identifier()?;
		// ... (unchanged)
		self.consume_trivia_nocapture();
		self.expect("]")?;
		let attacker_trailing = self.try_take_trailing();
		self.consume_trivia();
```

- `try_parse_query_options` (line 774): comments inside the option brackets `[precondition[...]]` are disallowed. Replace the `consume_trivia()` calls inside the brackets (lines 780, 786, 808) with `consume_trivia_nocapture()`:

```rust
	fn try_parse_query_options(&mut self) -> VResult<Vec<QueryOption>> {
		self.consume_trivia();
		if self.peek() != Some(b'[') {
			return Ok(vec![]);
		}
		self.advance(); // [
		self.consume_trivia_nocapture();
		let mut options = Vec::new();
		while self.peek() != Some(b']') {
			if self.at_end() {
				break;
			}
			self.consume_trivia_nocapture();
			// ... rest unchanged but with consume_trivia → consume_trivia_nocapture
		}
		// ...
	}
```

Actually wait — the spec says `QueryOption` itself has `leading_comments` and `trailing_comment`. So comments BETWEEN query options (between `precondition[A -> B: x]` and the next `precondition[...]`) ARE allowed. Only comments INSIDE the inner `[...]` of one precondition are disallowed.

Looking at `try_parse_query_options` more carefully: the outer `[` is the QueryOption list opener, the inner `[` of each `precondition[message]` brackets the message. Comments between options are fine; comments inside `precondition[message]` are disallowed.

Adjusted: keep `consume_trivia()` for the BETWEEN-options spots; use `consume_trivia_nocapture()` only inside each individual option's `[message]` brackets.

To keep this manageable, the spec is more permissive than strict — we can be flexible. I'll keep `consume_trivia()` (capturing) between options, and the inner brackets just call `skip_whitespace()` (which they already do — comments inside aren't supported anyway). Don't introduce nocapture at all for query options; leave the existing skip_whitespace in place inside individual option brackets.

Revised: in `try_parse_query_options`, change ONLY the outer `[` opener and the between-options trivia consumption to add leading-comment/trailing-comment capture:

```rust
	fn try_parse_query_options(&mut self) -> VResult<Vec<QueryOption>> {
		self.consume_trivia();
		if self.peek() != Some(b'[') {
			return Ok(vec![]);
		}
		self.advance(); // [
		self.consume_trivia();
		let mut options = Vec::new();
		while self.peek() != Some(b']') {
			if self.at_end() {
				break;
			}
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let leading = self.take_leading();
			let option_name = self.parse_identifier()?;
			self.skip_whitespace();
			self.expect("[")?;
			self.skip_whitespace();
			let sender_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			if !self.try_expect("->") && !self.try_expect("\u{2192}") {
				return Err(VerifpalError::Parse("expected '->' in query option".into()));
			}
			self.skip_whitespace();
			let recipient_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			self.expect(":")?;
			self.skip_whitespace();
			let constant = self.parse_constant()?;
			self.skip_whitespace();
			self.expect("]")?;
			let trailing = self.try_take_trailing();
			self.consume_trivia();

			let option_kind = match option_name.as_str() {
				"precondition" => QueryOptionKind::Precondition,
				_ => {
					return Err(VerifpalError::Parse(
						format!("unknown query option: {}", option_name).into(),
					));
				}
			};
			let sender_id = principal_names_map_add(&sender_name);
			let recipient_id = principal_names_map_add(&recipient_name);
			options.push(QueryOption {
				kind: option_kind,
				message: Message {
					sender: sender_id,
					recipient: recipient_id,
					constants: vec![constant],
					leading_comments: Vec::new(),
					trailing_comment: None,
				},
				leading_comments: leading,
				trailing_comment: trailing,
			});
		}
		if self.peek() == Some(b']') {
			self.advance();
		}
		self.skip_whitespace();
		Ok(options)
	}
```

- [ ] **Step 4: Run tests, confirm pass**

Run: `cargo test --release comment_dropped_`
Expected: PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parser.rs src/main.rs
git commit -m "parser: drop comments at disallowed positions

Inside primitive args, equation halves, attacker[]/phase[] brackets,
and the inner brackets of query options, comments are silently
dropped via consume_trivia_nocapture (matches the spec)."
```

---

## Task 8: Pretty-printer — render comments

**Files:**
- Modify: `src/pretty.rs`
- Modify: `src/main.rs` (basic emission tests)

- [ ] **Step 1: Write failing emission tests**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn pretty_emits_pre_attacker_comments() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.starts_with("// hello\n\nattacker[active]"));
	}

	#[test]
	fn pretty_emits_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("// before alice\nprincipal Alice["));
	}

	#[test]
	fn pretty_emits_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // lt\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a // lt"));
	}

	#[test]
	fn pretty_emits_block_comment_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a /* lt */"));
	}

	#[test]
	fn pretty_emits_block_comment_multiline() {
		let src = "/* line1\n   line2 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("/* line1\n   line2 */"), "got:\n{}", out);
	}
```

Run: `cargo test --release pretty_emits_`
Expected: 5 FAILS.

- [ ] **Step 2: Add render helpers to `pretty.rs`**

Edit `src/pretty.rs`. Add helpers after the `impl fmt::Display for Value` (around line 67):

```rust
/// Render a single comment without surrounding context.
/// For a Line comment: returns "// <text>".
/// For a single-line Block comment: returns "/* <text> */".
/// For a multi-line Block comment: returns "/* <text> */" with original
/// line breaks preserved; continuation lines are re-indented to align
/// with `indent` plus 3 (the width of "/* ").
fn render_comment(c: &Comment, indent: &str) -> String {
	match c.style {
		CommentStyle::Line => format!("//{}", c.text),
		CommentStyle::Block => {
			if !c.text.contains('\n') {
				format!("/*{}*/", c.text)
			} else {
				// Re-indent continuation lines.
				let cont_indent: String = format!("{}   ", indent);
				let mut out = String::from("/*");
				for (i, line) in c.text.split('\n').enumerate() {
					if i == 0 {
						out.push_str(line);
					} else {
						out.push('\n');
						out.push_str(&cont_indent);
						out.push_str(line.trim_start());
					}
				}
				out.push_str("*/");
				out
			}
		}
	}
}

/// Render a slice of leading comments, each on its own line at the
/// given indent. Returns "" if the slice is empty.
fn render_leading(comments: &[Comment], indent: &str) -> String {
	if comments.is_empty() {
		return String::new();
	}
	let mut s = String::new();
	for c in comments {
		s.push_str(indent);
		s.push_str(&render_comment(c, indent));
		s.push('\n');
	}
	s
}

/// Render a trailing comment with one leading space. Returns "" if None.
fn render_trailing(comment: Option<&Comment>) -> String {
	match comment {
		Some(c) => format!(" {}", render_comment(c, "")),
		None => String::new(),
	}
}
```

- [ ] **Step 3: Update `pretty_model` to emit comments**

Replace the existing `pretty_model` (line 189) with:

```rust
pub fn pretty_model(m: &Model) -> VResult<String> {
	sanity(m)?;
	let mut output = String::new();

	// 1. pre-attacker header comments
	if !m.pre_attacker_comments.is_empty() {
		output.push_str(&render_leading(&m.pre_attacker_comments, ""));
		output.push('\n');
	}

	// 2-3. attacker line (with optional trailing) + blank line
	output.push_str(&format!(
		"attacker[{}]{}\n\n",
		m.attacker,
		render_trailing(m.attacker_trailing.as_ref())
	));

	// 4. each block: leading_comments (no indent) + block + \n\n
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				output.push_str(&render_leading(&p.leading_comments, ""));
				output.push_str(&pretty_principal(p));
			}
			Block::Message(msg) => {
				output.push_str(&render_leading(&msg.leading_comments, ""));
				output.push_str(&pretty_message(msg));
				output.push_str(&render_trailing(msg.trailing_comment.as_ref()));
				output.push_str("\n\n");
			}
			Block::Phase(ph) => {
				output.push_str(&render_leading(&ph.leading_comments, ""));
				output.push_str(&format!(
					"phase[{}]{}\n\n",
					ph.number,
					render_trailing(ph.trailing_comment.as_ref())
				));
			}
		}
	}

	// 5-6. queries leading + header line + optional header trailing
	output.push_str(&render_leading(&m.queries_leading_comments, ""));
	output.push_str("queries[");
	output.push_str(&render_trailing(m.queries_header_trailing.as_ref()));
	output.push('\n');

	// 7. each query: leading + query + optional trailing
	for query in &m.queries {
		output.push_str(&render_leading(&query.leading_comments, "\t"));
		output.push_str(&format!(
			"\t{}{}\n",
			query,
			render_trailing(query.trailing_comment.as_ref())
		));
	}

	// 8-9. queries tail comments + closing ] + optional closing trailing
	output.push_str(&render_leading(&m.queries_tail_comments, "\t"));
	output.push(']');
	output.push_str(&render_trailing(m.queries_closing_trailing.as_ref()));
	output.push('\n');

	// 10. EOF tail comments
	if !m.tail_comments.is_empty() {
		output.push('\n');
		for c in &m.tail_comments {
			output.push_str(&render_comment(c, ""));
			output.push('\n');
		}
	}

	Ok(output)
}
```

- [ ] **Step 4: Update `pretty_principal` to emit comments**

Replace `pretty_principal` (line 167):

```rust
pub fn pretty_principal(principal: &Principal) -> String {
	let mut output = format!("principal {}[", principal.name);
	output.push_str(&render_trailing(principal.header_trailing.as_ref()));
	output.push('\n');
	for expression in &principal.expressions {
		output.push_str(&render_leading(&expression.leading_comments, "\t"));
		output.push_str(&format!(
			"\t{}{}\n",
			expression,
			render_trailing(expression.trailing_comment.as_ref())
		));
	}
	output.push_str(&render_leading(&principal.tail_comments, "\t"));
	output.push(']');
	output.push_str(&render_trailing(principal.closing_trailing.as_ref()));
	output.push_str("\n\n");
	output
}
```

- [ ] **Step 5: Run emission tests**

Run: `cargo test --release pretty_emits_`
Expected: all 5 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 6: Manual smoke check on a commented file**

Run: `cargo run --release -- pretty examples/test/aead_leak.vp`

Expected output starts with:
```
// AEAD associated data is an input to encryption but is NOT part of the
// ciphertext output. The attacker cannot extract the AD from observing
// the ciphertext — the protocol must send it separately for it to leak.
// * protocol: simple Diffie-Hellman (DH) with authenticated long-term keys only;
// * author: Stefano Berlato (sberlato@fbk.eu).

attacker[passive]
```

Visually inspect that the comments are placed where they should be.

- [ ] **Step 7: Commit**

```bash
git add src/pretty.rs src/main.rs
git commit -m "pretty: render comments at all node positions

render_leading / render_trailing / render_comment emit captured comments
at the indent of their attached node. pretty_model and pretty_principal
walk the comment slots in spec order; multi-line block comments are
re-indented at the column after the opening /*."
```

---

## Task 9: Tests — idempotence round-trip

**Files:**
- Modify: `src/main.rs` (round-trip helper + per-position idempotence tests)

- [ ] **Step 1: Add a round-trip helper**

In `src/main.rs`, just before the per-position idempotence tests, add:

```rust
	/// Parse `src`, pretty-print, parse the result, pretty-print again,
	/// and assert the two outputs are byte-equal. This is the canonical
	/// "preserves comments" check.
	fn assert_round_trip_idempotent(src: &str) {
		let m1 = parse_string("rt.vp", src).expect("parse 1");
		let s1 = pretty_model(&m1).expect("pretty 1");
		let m2 = parse_string("rt.vp", &s1).expect("parse 2");
		let s2 = pretty_model(&m2).expect("pretty 2");
		assert_eq!(s1, s2, "not idempotent\n--- s1 ---\n{}\n--- s2 ---\n{}", s1, s2);
	}
```

- [ ] **Step 2: Add idempotence tests**

```rust
	#[test]
	fn round_trip_simple() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_pre_attacker_comment() {
		let src = "// SPDX header\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_trailing_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_block() {
		let src = "attacker[active]\n\n// initiator\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_pre_attacker() {
		let src = "/* SPDX header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_multiline() {
		let src = "/* multi\n   line\n   header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_message_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // flight 1\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_query_trailing_and_leading() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a // payload only\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_phase_with_leading_and_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// handshake done\nphase[1] // post-handshake\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_closing_and_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[ // header\n\tknows private a\n] // closing\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_queries_header_and_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n] // end\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF\n";
		assert_round_trip_idempotent(src);
	}
```

- [ ] **Step 3: Run all round-trip tests**

Run: `cargo test --release round_trip_`
Expected: all 14 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "test: idempotence round-trip for each comment position

Parse -> pretty -> parse -> pretty must reach a fixed point in one pass.
14 tests cover every comment slot defined in the spec."
```

---

## Task 10: Tests — golden files

**Files:**
- Create: `examples/test/golden_pretty/aead_leak.vp`
- Create: `examples/test/golden_pretty/assert_junglegym.vp`
- Create: `examples/test/golden_pretty/auth_with_signing.vp`
- Create: `examples/test/golden_pretty/concat_bomb.vp`
- Create: `examples/test/golden_pretty/simple.vp`
- Modify: `src/main.rs` (golden tests)

- [ ] **Step 1: Generate golden files from current pretty output**

Run the pretty-printer on each input and save the output to `examples/test/golden_pretty/`. From repo root:

```bash
mkdir -p examples/test/golden_pretty
cargo run --release -- pretty examples/test/aead_leak.vp > examples/test/golden_pretty/aead_leak.vp
cargo run --release -- pretty examples/test/assert_junglegym.vp > examples/test/golden_pretty/assert_junglegym.vp
cargo run --release -- pretty examples/test/auth_with_signing.vp > examples/test/golden_pretty/auth_with_signing.vp
cargo run --release -- pretty examples/test/concat_bomb.vp > examples/test/golden_pretty/concat_bomb.vp
cargo run --release -- pretty examples/simple.vp > examples/test/golden_pretty/simple.vp
```

- [ ] **Step 2: Manually inspect each golden file**

For each file, open it and verify:
- Comments appear in the expected positions
- Indentation looks right (tabs for inner content)
- Blank lines between blocks are present
- No comments dropped that shouldn't have been

If anything looks wrong, the bug is in the pretty-printer (not the golden) — fix and regenerate.

- [ ] **Step 3: Add golden-file tests**

Add to `src/main.rs` `unit_tests` mod:

```rust
	fn assert_golden(input: &str, golden: &str) {
		let m = parse_string("g.vp", input).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert_eq!(
			out, golden,
			"golden mismatch\n--- expected ---\n{}\n--- got ---\n{}",
			golden, out
		);
	}

	#[test]
	fn golden_aead_leak() {
		assert_golden(
			include_str!("../examples/test/aead_leak.vp"),
			include_str!("../examples/test/golden_pretty/aead_leak.vp"),
		);
	}

	#[test]
	fn golden_assert_junglegym() {
		assert_golden(
			include_str!("../examples/test/assert_junglegym.vp"),
			include_str!("../examples/test/golden_pretty/assert_junglegym.vp"),
		);
	}

	#[test]
	fn golden_auth_with_signing() {
		assert_golden(
			include_str!("../examples/test/auth_with_signing.vp"),
			include_str!("../examples/test/golden_pretty/auth_with_signing.vp"),
		);
	}

	#[test]
	fn golden_concat_bomb() {
		assert_golden(
			include_str!("../examples/test/concat_bomb.vp"),
			include_str!("../examples/test/golden_pretty/concat_bomb.vp"),
		);
	}

	#[test]
	fn golden_simple() {
		assert_golden(
			include_str!("../examples/simple.vp"),
			include_str!("../examples/test/golden_pretty/simple.vp"),
		);
	}
```

- [ ] **Step 4: Run golden tests**

Run: `cargo test --release golden_`
Expected: all 5 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add examples/test/golden_pretty/ src/main.rs
git commit -m "test: golden-file round-trip on 5 commented example models

Snapshots the formatted output of aead_leak.vp, assert_junglegym.vp,
auth_with_signing.vp, concat_bomb.vp, and simple.vp under
examples/test/golden_pretty/. Tests assert byte-equality between
pretty_model(parse_string(input)) and the stored golden."
```

---

## Task 11: Tests — block-comment edge cases

**Files:**
- Modify: `src/main.rs` (extra block-comment tests)

- [ ] **Step 1: Add edge-case tests**

Add to `unit_tests` mod in `src/main.rs`:

```rust
	#[test]
	fn block_comment_unterminated_errors_with_position() {
		let src = "/* never closed\nattacker[active]\n";
		let err = parse_string("t.vp", src).unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("unterminated block comment"),
			"got: {}",
			msg
		);
	}

	#[test]
	fn block_comment_nested_first_close_wins() {
		// /* /* */ */
		// Outer /* opens. First */ closes. The trailing  */ becomes
		// stray tokens after the comment which produce a parse error
		// (because they're not valid syntax at the model start).
		let src = "/* /* */ */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let result = parse_string("t.vp", src);
		assert!(result.is_err(), "expected parse error from stray */");
	}

	#[test]
	fn block_comment_multiline_in_leading_position_renders() {
		let src = "attacker[active]\n\n/* multi\n   line\n   header */\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		// Expect the block comment intact in the output, with content
		// re-indented to align continuation lines.
		assert!(out.contains("/* multi"), "missing /* multi in:\n{}", out);
		assert!(out.contains("line"), "missing 'line':\n{}", out);
		assert!(out.contains("header */"), "missing 'header */':\n{}", out);
		// Re-parse to verify the comment survived
		let m2 = parse_string("t.vp", &out).expect("re-parse");
		match &m2.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert!(matches!(p.leading_comments[0].style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --release block_comment_`
Expected: all 3 PASS.

Run: `cargo test --release`
Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "test: block-comment edge cases

Unterminated /* surfaces a clear error; nested /* /* */ */ closes at
the first */ leaving the trailing */ as a stray-token parse error;
multi-line block comments in leading positions survive parse->pretty->parse."
```

---

## Task 12: Final verification

**Files:** none

- [ ] **Step 1: Full release test suite**

Run: `cargo test --release`
Expected: all tests pass — 147 existing + new comment-preservation tests.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --release --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 3: Manual smoke on a non-trivial commented file**

Run: `cargo run --release -- pretty examples/test/aead_leak.vp | head -20`

Expected: header SPDX-like comments at top, blank line, `attacker[passive]`, blank line, body comments preceding the principal blocks.

Run: `cargo run --release -- pretty examples/test/assert_junglegym.vp | head -20`

Expected: multi-paragraph leading comments preserved above `attacker[active]`.

- [ ] **Step 4: Build wasm target sanity check**

Run: `cargo build --release --no-default-features --features wasm` (only if wasm-pack/the wasm target is normally built in this repo — check `scripts/` or skip if not standard).

If the wasm build is part of CI, run it; if not, skip this step.

- [ ] **Step 5: Final commit if any fixes were needed**

If the previous steps surfaced any issues that needed code changes, commit them. Otherwise skip.

```bash
git status
# If clean, no commit needed.
# If dirty, fix and commit with a short descriptive message.
```

---

## Self-review notes

- **Spec coverage**: Each comment position in the design's "Where comments can appear in Verifpal source" table maps to: Task 1 (data model), Tasks 2–7 (parser capture), Task 8 (pretty emit), Task 9 (idempotence), Task 10 (golden). The disallowed-position rule is Task 7. The block-comment edge cases are Task 11. The 147-test regression is verified continuously and finalized in Task 12.
- **Placeholder scan**: No TBDs / "implement later" / "add appropriate error handling". Every code step shows actual code.
- **Type consistency**: `Comment` has fields `text: String` and `style: CommentStyle`; field name `pending_leading` and helpers `take_leading` / `try_take_trailing` / `consume_trivia` / `consume_trivia_nocapture` / `snapshot` / `restore` are referenced identically across tasks.
- **Naming**: `golden_pretty/` (not `pretty_golden/` from spec — chosen so `golden_` prefix groups in directory listings). Spec is loose on the exact directory name; this choice is consistent across plan tasks.
