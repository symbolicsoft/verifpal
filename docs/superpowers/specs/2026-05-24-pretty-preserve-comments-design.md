# Design: Preserve Comments in `--pretty`

**Date**: 2026-05-24
**Status**: Approved, pending implementation plan

## Goal

Make `verifpal pretty <model>` (and the equivalent `internal-json prettyPrint`
and WASM `wasm_pretty` entry points) round-trip user comments. Today, the
parser discards every `//` comment via `Parser::skip_whitespace_and_comments`,
and the AST has no place to store them, so the pretty-printer emits a
canonically-formatted but comment-free version of the model. After this
change, the pretty-printer must emit comments in positions semantically
equivalent to where the user wrote them.

In addition, the parser will learn to recognize `/* ... */` block comments,
which it currently does not.

## Non-goals

- Preserving the user's exact column positions, indentation widths, or
  trailing whitespace on non-comment lines. The pretty-printer's existing
  canonical formatting still applies to code; only comments are preserved.
- Preserving blank lines **inside** a `principal[...]` or `queries[...]`
  block. Those are collapsed to the canonical layout, same as today.
  Blank lines **between** top-level blocks remain (current behavior).
- Preserving comments at fine-grained positions inside an expression
  (between primitive arguments, between equation halves, inside
  `attacker[...]` brackets, etc.). These positions are silently dropped
  with a stderr warning.
- Nested block comments. `/* /* */ */` parses as one comment closed by
  the first `*/`; the trailing ` */` becomes a syntax error.
- Blank lines **within** a sequence of leading comments. If the user
  writes a blank line between two `//` comment groups that both attach
  to the same node (or both sit at the file header before `attacker`),
  the blank line is dropped — the resulting comments are emitted
  contiguously. This is a small, intentional canonicalization. Adding
  blank-line trivia between comments is straightforward to add later if
  it turns out to matter.

## Background

### Today's flow

```
verifpal pretty foo.vp
  -> pretty::pretty_print(file)
  -> parser::parse_file(file)                  // discards comments
  -> pretty::pretty_model(&Model)              // emits canonical text
```

The parser's `skip_whitespace_and_comments` (`src/parser.rs:154-169`)
detects `//` and skips to end of line. There is no recognition of
`/* ... */`. Comments are not stored anywhere.

The same `pretty_model(&Model)` is used by:
- the CLI's `verifpal pretty <file>` subcommand,
- `internal-json prettyPrint` (used by IDE integrations),
- `wasm_pretty` (used by the web playground).

All three callers benefit equally from this change.

### Where comments can appear in Verifpal source

| Position | Example |
|---|---|
| File header, before `attacker[...]` | `// SPDX header\nattacker[active]` |
| Trailing on the `attacker[active]` line | `attacker[active]   // active model` |
| Between top-level blocks | `]\n\n// next block\nprincipal Bob[` |
| Trailing on `principal X[` opening line | `principal Alice[   // initiator` |
| Inside a principal block, leading an expression | `    // long-term key\n    knows private a` |
| Trailing on an expression | `    knows private a   // long-term key` |
| Tail of a principal block (just before `]`) | `    knows private a\n    // TODO\n]` |
| Trailing on the closing `]` of a principal | `]   // end of Alice` |
| Trailing on a message | `Alice -> Bob: x   // initial flight` |
| Trailing on a `phase[N]` | `phase[1]   // post-handshake` |
| Leading on the `queries` keyword | `// verify these properties\nqueries[` |
| Trailing on `queries[` line | `queries[   // start of queries` |
| Leading on a query | `    // primary goal\n    confidentiality? m` |
| Trailing on a query | `    confidentiality? m   // payload only` |
| Leading on a query option | `    [   // options follow\n        precondition[...]` |
| Trailing on a query option | `        precondition[A -> B: x]   // setup` |
| Tail of the queries block (before `]`) | `    confidentiality? m\n    // done\n]` |
| Trailing on closing `]` of queries | `]   // end of file` |
| File trailer, after `queries[...]`'s `]` | `]\n\n// EOF` |

Two comment forms are recognized: `// ...` line comments and `/* ... */`
block comments. Block comments may span multiple lines.

## Design

### Approach

Trivia attached to AST nodes (the standard formatter pattern used by
rustfmt, prettier, gofmt). The parser captures comments into a per-node
`leading_comments: Vec<Comment>` and `trailing_comment: Option<Comment>`,
plus container-level `tail_comments: Vec<Comment>` for comments that
appear just before a closing bracket. The pretty-printer renders these
in source-faithful positions.

The AST surface grows, but the additions are all defaulted to empty,
so verify / sanity / json paths are unaffected — they read existing
fields and ignore the new ones. Only `pretty.rs` consumes the comment
fields.

### Data model

In `src/types.rs`:

```rust
#[derive(Clone, Debug)]
pub struct Comment {
    pub text: String,          // body without delimiters, interior whitespace verbatim
    pub style: CommentStyle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentStyle {
    Line,    // // ...
    Block,   // /* ... */
}
```

The body is stored without the `//` or `/* */` delimiters and without the
leading single space that conventionally follows `//`. The pretty-printer
re-adds delimiters and a single space on emit. Block comment line endings
are normalized to `\n` on capture, re-emitted as `\n`.

### AST additions

All fields are `#[derive(Default)]`-compatible (`Vec::new()` /
`Option::None`). Existing struct-literal call sites that don't use a
`Default` impl will be updated to include the new fields explicitly.

| Type | New fields |
|---|---|
| `Model` | `pre_attacker_comments: Vec<Comment>` |
| `Model` | `attacker_trailing: Option<Comment>` |
| `Model` | `queries_leading_comments: Vec<Comment>` |
| `Model` | `queries_header_trailing: Option<Comment>` |
| `Model` | `queries_tail_comments: Vec<Comment>` |
| `Model` | `queries_closing_trailing: Option<Comment>` |
| `Model` | `tail_comments: Vec<Comment>` (EOF tail) |
| `Principal` | `leading_comments: Vec<Comment>` |
| `Principal` | `header_trailing: Option<Comment>` (on `principal X[` line) |
| `Principal` | `tail_comments: Vec<Comment>` (before closing `]`) |
| `Principal` | `closing_trailing: Option<Comment>` (after `]` on same line) |
| `Message` | `leading_comments: Vec<Comment>` |
| `Message` | `trailing_comment: Option<Comment>` |
| `Phase` | `leading_comments: Vec<Comment>` |
| `Phase` | `trailing_comment: Option<Comment>` |
| `Expression` | `leading_comments: Vec<Comment>` |
| `Expression` | `trailing_comment: Option<Comment>` |
| `Query` | `leading_comments: Vec<Comment>` |
| `Query` | `trailing_comment: Option<Comment>` |
| `QueryOption` | `leading_comments: Vec<Comment>` |
| `QueryOption` | `trailing_comment: Option<Comment>` |

`Constant`, `Primitive`, `Value`, and `Equation` get **no** comment
fields. Comments at sub-expression granularity are out of scope (see
Non-goals).

### Parser changes

Replace `skip_whitespace_and_comments` with `consume_trivia`. The new
function adds two fields to the `Parser` struct:

```rust
struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    pending_leading: Vec<Comment>,
    last_node_end_line: Option<usize>,   // for trailing-comment detection
}
```

**`consume_trivia`** loops over whitespace and comments:

- Whitespace (spaces, tabs, newlines, carriage returns) is skipped.
- `// ...` to end-of-line is captured as `Comment { text, style: Line }`
  and pushed onto `pending_leading`.
- `/* ... */` is captured as `Comment { text, style: Block }` and pushed
  onto `pending_leading`. Line endings inside are normalized to `\n`.
  Unterminated block comments produce a parse error with the byte
  position of the opening `/*`.
- Loops until it hits a non-trivia byte.

**`take_leading()`**: drains and returns `pending_leading`. Called at the
start of building each AST node.

**`try_take_trailing()`**: called immediately after the parser has
consumed the last token of a node. Skips only inline whitespace (spaces
and tabs, NOT newlines). If the next bytes are `//` or `/* ... */` that
opens and closes on the same line, captures and returns
`Some(Comment)`. Otherwise returns `None`. The first newline ends the
trailing-comment window.

A `/* ... */` block comment that opens on the same line as the node but
closes on a later line is **not** trailing — `try_take_trailing` leaves
it alone, and the next `consume_trivia` call picks it up as a leading
comment of the next node.

**Lookahead safety**: existing lookaheads use a `saved = self.pos`
pattern and rewind with `self.pos = saved`. These must also snapshot
`pending_leading.len()` and truncate on rewind, so a rolled-back
lookahead doesn't leak comments into the wrong node.

**Tail comments**: when the parser is about to consume a closing `]` of
a container (principal block or queries block) and `pending_leading` is
non-empty, it drains the buffer into the container's `tail_comments`
field instead of leaving them for a (nonexistent) next node. Same for
EOF: any remaining `pending_leading` after the model is fully parsed
becomes `Model.tail_comments`.

**Disallowed positions**: comments inside the argument list of a
primitive, the values of an equation, or inside `attacker[...]` /
`phase[N]` / option `[...]` brackets are dropped. We do not surface a
warning to the user (these positions are rare, and emitting from a
library function called by WASM/JSON would add unwanted output to those
interfaces). Instead, the relevant `parse_*` helpers gain a small
`allow_comments: bool` flag (default `true`; set `false` at the
disallowed call sites); when `false`, `consume_trivia` discards any
comments it finds rather than buffering them. Tests verify the parse
succeeds and that no AST field contains the dropped comment.

### Pretty-printer changes

In `src/pretty.rs`:

```rust
fn render_leading(comments: &[Comment], indent: &str) -> String;
fn render_trailing(comment: Option<&Comment>) -> String;
fn render_block_comment(text: &str, indent: &str) -> String;
```

**Rules**:

- Leading comments are emitted before the node, each on its own line,
  at the node's indent. Multiple leading comments are emitted contiguously
  with no blank line between them.
- A trailing comment is emitted on the same line as the node's last
  token, preceded by exactly one space. Line comments render as
  ` // text`. Block comments render as ` /* text */`.
- A multi-line block comment in a leading or tail position has its
  continuation lines re-indented to align with the column of its
  opening `/*`. We do not preserve the original column from the source.
- Blank line between top-level blocks: kept (current behavior is
  `\n\n` after each block). When the next block has leading comments,
  the blank line is emitted **before** the leading comments, not
  between them and the block. The current code's trailing `\n\n` on
  each block already produces this layout naturally — we just need to
  emit leading comments before the next block's content rather than
  inserting a new blank line.

**`pretty_model` ordering**:

1. `pre_attacker_comments` (no indent). If non-empty, follow with one
   blank line before `attacker[...]`. (This matches the file-header
   convention in `simple.vp` and most existing examples. Even if the
   source has no blank line between header and `attacker[...]`, the
   pretty-printer inserts one — a small, intentional canonicalization.)
2. `attacker[KIND]` + optional ` // attacker_trailing`
3. blank line
4. for each `Block`:
   - emit `leading_comments` (no indent) — no blank line between them
     and the block; the blank line that separates this block from the
     previous one comes from the previous block's trailing `\n\n`.
   - emit the block (which itself emits its own header_trailing,
     interior expressions with their comments, tail_comments,
     closing_trailing as applicable)
   - emit blank line
5. `queries_leading_comments` (no indent)
6. `queries[` + optional ` // queries_header_trailing`
7. for each `Query`:
   - emit `leading_comments` (one-tab indent)
   - emit the query (with its trailing if any)
8. `queries_tail_comments` (one-tab indent)
9. `]` + optional ` // queries_closing_trailing`
10. If `Model.tail_comments` is non-empty, emit one blank line, then the
    `tail_comments` (no indent), then a final `\n`. Otherwise just `\n`.

**`pretty_principal` ordering**:

1. `principal NAME[` + optional ` // header_trailing`
2. for each `Expression`:
   - emit `leading_comments` (one-tab indent)
   - emit the expression (with its trailing)
3. `tail_comments` (one-tab indent)
4. `]` + optional ` // closing_trailing`

(No change to `pretty_constants` / `pretty_values` / `pretty_arity` —
those operate below the comment-attachment level.)

### Effect on existing modules

| Module | Effect |
|---|---|
| `src/types.rs` | Add `Comment`, `CommentStyle`; add fields to listed AST types; bump `Default` impls. |
| `src/parser.rs` | Rewrite `skip_whitespace_and_comments` -> `consume_trivia`; thread `pending_leading` / `take_leading` / `try_take_trailing` through every node constructor; add lookahead-safe rollback; add `/* */` recognition; add `allow_comments` flag to disallowed-position helpers. |
| `src/pretty.rs` | Add `render_leading` / `render_trailing` / `render_block_comment`; update `pretty_model` and `pretty_principal` (and the inline emits for queries) to call them in the right order. |
| `src/sanity.rs` | No change — sanity does not read new fields. |
| `src/verify.rs`, `verifyactive.rs`, `query.rs`, `inject.rs`, etc. | No change — they don't read comment fields. |
| `src/json.rs` | No change — JSON output already calls `pretty_model`, which now preserves comments. The `prettyPrint` JSON command inherits the new behavior. |
| `src/lib.rs` (WASM) | No change — `wasm_pretty` already calls `pretty::pretty_model`. |
| `src/main.rs` | No CLI change. Test additions only. |

## Testing

All tests added to the `unit_tests` module in `src/main.rs`.

### Unit tests — comment positions

One test per position from the table in "Where comments can appear":
build a model string with a comment at that position, parse it, assert
the comment landed in the expected AST field.

### Round-trip / idempotence

For each position above, plus a few combined cases:

```
let s1 = pretty_model(&parse_string("t.vp", input)?)?;
let s2 = pretty_model(&parse_string("t.vp", &s1)?)?;
assert_eq!(s1, s2);
```

The pretty-printer must reach a fixed point in one pass. This is the
canonical "preserves comments" check.

### Golden-file tests

Snapshot the formatted output of 5 heavily-commented examples:
`examples/test/aead_leak.vp`, `examples/test/assert_junglegym.vp`,
`examples/test/auth_with_signing.vp`, `examples/test/concat_bomb.vp`,
plus `examples/simple.vp`. Store expected output under
`examples/test/pretty_golden/<name>.expected`. Tests assert
byte-equality between `pretty_print(file)` and the stored golden.

### Block-comment edge cases

- Single-line `/* x */` in leading position → renders as `/* x */`
  on its own line.
- Single-line `/* x */` in trailing position → renders inline as
  ` /* x */`.
- Multi-line block in leading position → continuation lines aligned to
  the column of the opening `/*`.
- Unterminated `/* ...` → parse error with byte position.
- `/* /* */ */` → first `*/` closes the comment; second ` */` produces
  a parse error.

### Disallowed positions

- Comment between primitive arguments → parse succeeds; the resulting
  AST contains no `Comment` whose text matches the disallowed-position
  comment (i.e. it is silently dropped).
- Comment inside `attacker[...]` brackets → same.
- Comment between equation halves → same.
- Round-trip stability is **not** required for disallowed positions —
  the dropped comment is gone after one pass.

### Regression

All 147 existing tests (70 unit + 77 integration in `src/main.rs`)
continue to pass unchanged. Comment-preservation additions are
purely additive on the AST.

### CLI smoke

Manual: `cargo run --release -- pretty examples/test/aead_leak.vp`
produces output visually identical to the source modulo the
canonical reformatting of code (indentation, spacing).

## Open questions

None at design-doc time. Edge cases are documented in the rules
above; any further ambiguity surfaces during implementation and
should be resolved in the implementation plan.
