/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use lsp_types::{Position, PositionEncodingKind, Range};

use crate::types::Span;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Units {
	Utf8,
	Utf16,
}

pub(crate) struct LineIndex {
	starts: Vec<usize>,
	text: String,
	units: Units,
}

impl LineIndex {
	pub(crate) fn new(source: &str, encoding: &PositionEncodingKind) -> LineIndex {
		let mut starts = vec![0usize];
		for (i, b) in source.bytes().enumerate() {
			if b == b'\n' {
				starts.push(i + 1);
			}
		}
		LineIndex {
			starts,
			text: source.to_string(),
			units: if *encoding == PositionEncodingKind::UTF8 {
				Units::Utf8
			} else {
				Units::Utf16
			},
		}
	}

	pub(crate) fn position(&self, offset: usize) -> Position {
		let offset = self.clamp(offset);
		let line = self.starts.partition_point(|&s| s <= offset).max(1) - 1;
		let start = self.starts[line];
		let character = self.width(&self.text[start..offset]);
		Position::new(line as u32, character as u32)
	}

	pub(crate) fn offset(&self, position: Position) -> usize {
		let line = position.line as usize;
		let Some(&start) = self.starts.get(line) else {
			return self.text.len();
		};
		let mut end = self
			.starts
			.get(line + 1)
			.copied()
			.unwrap_or(self.text.len());
		let bytes = self.text.as_bytes();
		if end > start && bytes[end - 1] == b'\n' {
			end -= 1;
		}
		if end > start && bytes[end - 1] == b'\r' {
			end -= 1;
		}
		let slice = &self.text[start..end];
		let mut wanted = position.character as usize;
		for (i, c) in slice.char_indices() {
			if wanted == 0 {
				return start + i;
			}
			let w = match self.units {
				Units::Utf8 => c.len_utf8(),
				Units::Utf16 => c.len_utf16(),
			};
			if w > wanted {
				return start + i;
			}
			wanted -= w;
		}
		end
	}

	pub(crate) fn range(&self, span: Span) -> Range {
		Range::new(self.position(span.start), self.position(span.end))
	}

	pub(crate) fn end(&self) -> Position {
		self.position(self.text.len())
	}

	fn width(&self, slice: &str) -> usize {
		match self.units {
			Units::Utf8 => slice.len(),
			Units::Utf16 => slice.chars().map(char::len_utf16).sum(),
		}
	}

	fn clamp(&self, offset: usize) -> usize {
		let mut offset = offset.min(self.text.len());
		while !self.text.is_char_boundary(offset) {
			offset -= 1;
		}
		offset
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const SRC: &str = "attacker[active]\nprincipal Alice[\n\tknows private m\n]\n";

	#[test]
	fn an_offset_maps_to_its_line_and_column() {
		let index = LineIndex::new(SRC, &PositionEncodingKind::UTF8);
		let at = SRC.find("principal").expect("in the source");
		assert_eq!(index.position(at), Position::new(1, 0));
		let at = SRC.find("private").expect("in the source");
		assert_eq!(index.position(at), Position::new(2, 7));
	}

	#[test]
	fn a_position_maps_back_to_its_offset() {
		let index = LineIndex::new(SRC, &PositionEncodingKind::UTF8);
		for at in 0..SRC.len() {
			if !SRC.is_char_boundary(at) {
				continue;
			}
			assert_eq!(index.offset(index.position(at)), at, "offset {at}");
		}
	}

	#[test]
	fn utf16_counts_code_units_not_bytes() {
		let src = "principal Ang\u{e8}le[\n\tknows private m\n]\n";
		let at = src.find('[').expect("in the source");
		let utf8 = LineIndex::new(src, &PositionEncodingKind::UTF8);
		let utf16 = LineIndex::new(src, &PositionEncodingKind::UTF16);
		assert_eq!(utf8.position(at).character, 17);
		assert_eq!(utf16.position(at).character, 16);
	}

	#[test]
	fn an_astral_character_is_two_utf16_units() {
		let src = "principal A\u{1F600}B[\n]\n";
		let at = src.find('[').expect("in the source");
		let utf16 = LineIndex::new(src, &PositionEncodingKind::UTF16);
		assert_eq!(utf16.position(at).character, 14);
	}

	#[test]
	fn a_span_becomes_a_range() {
		let index = LineIndex::new(SRC, &PositionEncodingKind::UTF8);
		let start = SRC.find("knows").expect("in the source");
		let range = index.range(Span::new(start, start + 5));
		assert_eq!(range.start, Position::new(2, 1));
		assert_eq!(range.end, Position::new(2, 6));
	}

	#[test]
	fn an_out_of_range_offset_clamps_to_the_end() {
		let index = LineIndex::new(SRC, &PositionEncodingKind::UTF8);
		let position = index.position(SRC.len() + 500);
		assert_eq!(index.offset(position), SRC.len());
	}

	#[test]
	fn a_position_past_the_last_line_clamps() {
		let index = LineIndex::new(SRC, &PositionEncodingKind::UTF8);
		assert_eq!(index.offset(Position::new(999, 0)), SRC.len());
		assert_eq!(index.offset(Position::new(0, 999)), 16);
	}

	#[test]
	fn crlf_line_endings_do_not_shift_columns() {
		let src = "attacker[active]\r\nprincipal Alice[\r\n]\r\n";
		let index = LineIndex::new(src, &PositionEncodingKind::UTF8);
		let at = src.find("principal").expect("in the source");
		assert_eq!(index.position(at), Position::new(1, 0));
	}
}
