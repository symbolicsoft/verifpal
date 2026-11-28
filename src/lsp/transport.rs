/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::Sender;
use lsp_server::{Connection, ErrorCode, Message, RequestId};

pub(crate) struct Threads {
	reader: JoinHandle<io::Result<()>>,
	writer: JoinHandle<io::Result<()>>,
}

impl Threads {
	pub(crate) fn join(self) -> io::Result<()> {
		joined(self.reader)?;
		joined(self.writer)
	}
}

fn joined(thread: JoinHandle<io::Result<()>>) -> io::Result<()> {
	thread
		.join()
		.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

pub(crate) fn connect(
	input: impl Read + Send + 'static,
	output: impl Write + Send + 'static,
) -> (Connection, Threads) {
	let output = Arc::new(Mutex::new(output));
	let replies = Arc::clone(&output);
	let (sender, outgoing) = crossbeam_channel::bounded::<Message>(0);
	let (incoming, receiver) = crossbeam_channel::bounded::<Message>(0);
	let writer = std::thread::spawn(move || {
		outgoing.into_iter().try_for_each(|message| {
			let mut frame = Vec::new();
			message.write(&mut frame)?;
			deliver(&output, &frame)
		})
	});
	let reader = std::thread::spawn(move || {
		read(BufReader::new(input), &incoming, |reply| {
			let text = reply.to_string();
			let frame = format!("Content-Length: {}\r\n\r\n{text}", text.len());
			deliver(&replies, frame.as_bytes())
		})
	});
	(Connection { sender, receiver }, Threads { reader, writer })
}

fn deliver(output: &Mutex<impl Write>, frame: &[u8]) -> io::Result<()> {
	let mut output = output.lock().unwrap_or_else(|e| e.into_inner());
	output.write_all(frame)?;
	output.flush()
}

fn read(
	mut input: impl BufRead,
	incoming: &Sender<Message>,
	mut reject: impl FnMut(serde_json::Value) -> io::Result<()>,
) -> io::Result<()> {
	while let Some(body) = frame(&mut input)? {
		match serde_json::from_slice::<Message>(&body) {
			Ok(message) => {
				let last = matches!(&message, Message::Notification(note) if note.method == "exit");
				incoming.send(message).map_err(io::Error::other)?;
				if last {
					break;
				}
			}
			Err(error) => reject(rejection(&body, &error))?,
		}
	}
	Ok(())
}

fn frame(input: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
	let mut length = None;
	let mut line = String::new();
	loop {
		line.clear();
		if input.read_line(&mut line)? == 0 {
			return Ok(None);
		}
		let header = line
			.strip_suffix("\r\n")
			.ok_or_else(|| malformed(format!("malformed header: {line:?}")))?;
		if header.is_empty() {
			break;
		}
		let (name, value) = header
			.split_once(": ")
			.ok_or_else(|| malformed(format!("malformed header: {header:?}")))?;
		if name.eq_ignore_ascii_case("Content-Length") {
			length = Some(value.parse::<u64>().map_err(malformed)?);
		}
	}
	let length = length.ok_or_else(|| malformed("no Content-Length"))?;
	let mut body = Vec::new();
	input.take(length).read_to_end(&mut body)?;
	if (body.len() as u64) < length {
		return Err(io::ErrorKind::UnexpectedEof.into());
	}
	Ok(Some(body))
}

fn malformed(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, error)
}

fn rejection(body: &[u8], error: &serde_json::Error) -> serde_json::Value {
	#[derive(serde::Deserialize)]
	struct Request {
		id: RequestId,
		#[serde(rename = "method")]
		_method: serde::de::IgnoredAny,
	}
	let id = serde_json::from_slice::<Request>(body)
		.ok()
		.map(|request| request.id);
	let (code, message) = if error.is_data() {
		(
			ErrorCode::InvalidRequest,
			"the message is not a request, a response or a notification".to_string(),
		)
	} else {
		(ErrorCode::ParseError, error.to_string())
	};
	serde_json::json!({
		"jsonrpc": "2.0",
		"id": id,
		"error": {"code": code as i32, "message": message},
	})
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	#[derive(Clone, Default)]
	pub(crate) struct Sink(Arc<Mutex<Vec<u8>>>);

	impl Write for Sink {
		fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
			self.0
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.extend_from_slice(bytes);
			Ok(bytes.len())
		}

		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	impl Sink {
		pub(crate) fn messages(&self) -> Vec<serde_json::Value> {
			let written = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
			let mut input = io::Cursor::new(written);
			let mut messages = Vec::new();
			while let Some(body) = frame(&mut input).expect("the server writes whole frames") {
				messages.push(serde_json::from_slice(&body).expect("the server writes JSON"));
			}
			messages
		}
	}

	pub(crate) fn framed(body: impl AsRef<[u8]>) -> Vec<u8> {
		let body = body.as_ref();
		[
			format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes(),
			body,
		]
		.concat()
	}

	fn read_all(input: Vec<u8>) -> (io::Result<()>, Vec<Message>, Vec<serde_json::Value>) {
		let (incoming, received) = crossbeam_channel::unbounded();
		let mut replies = Vec::new();
		let outcome = read(io::Cursor::new(input), &incoming, |reply| {
			replies.push(reply);
			Ok(())
		});
		drop(incoming);
		(outcome, received.iter().collect(), replies)
	}

	const HOVER: &str = r#"{"jsonrpc":"2.0","id":5,"method":"textDocument/hover","params":{}}"#;

	#[test]
	fn a_frame_that_cannot_be_read_is_rejected_and_the_next_one_is_delivered() {
		let null = serde_json::Value::Null;
		let unreadable: [(&[u8], serde_json::Value, ErrorCode); 8] = [
			(
				br#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"text":"\ud83d\n"}}"#,
				null.clone(),
				ErrorCode::ParseError,
			),
			(
				br#"{"jsonrpc":"2.0","id":77,"method":"textDocument/hover","params":{"x":"\udc00"}}"#,
				serde_json::json!(77),
				ErrorCode::ParseError,
			),
			(
				b"{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"x\",\"params\":\"\xff\"}",
				serde_json::json!("a"),
				ErrorCode::ParseError,
			),
			(
				br#"{"jsonrpc":"2.0","method":"#,
				null.clone(),
				ErrorCode::ParseError,
			),
			(b"{nope", null.clone(), ErrorCode::ParseError),
			(
				br#"[{"jsonrpc":"2.0","method":"initialized","params":{}}]"#,
				null.clone(),
				ErrorCode::InvalidRequest,
			),
			(
				br#"{"jsonrpc":"2.0","id":3}"#,
				null.clone(),
				ErrorCode::InvalidRequest,
			),
			(
				br#"{"jsonrpc":"2.0","id":4,"method":5}"#,
				serde_json::json!(4),
				ErrorCode::InvalidRequest,
			),
		];
		for (body, id, code) in unreadable {
			let shown = String::from_utf8_lossy(body);
			let (outcome, delivered, replies) = read_all([framed(body), framed(HOVER)].concat());
			outcome.expect("the stream stays readable");
			assert_eq!(replies.len(), 1, "{shown}: {replies:?}");
			assert_eq!(replies[0]["jsonrpc"], "2.0", "{shown}");
			assert_eq!(replies[0]["id"], id, "{shown}: {}", replies[0]);
			assert_eq!(
				replies[0]["error"]["code"], code as i32,
				"{shown}: {}",
				replies[0]
			);
			assert!(
				matches!(delivered.as_slice(), [Message::Request(next)] if next.method == "textDocument/hover"),
				"{shown}: {delivered:?}"
			);
		}
	}

	#[test]
	fn well_formed_frames_are_delivered_in_order_until_exit() {
		let mut input = Vec::new();
		input.extend(framed(HOVER));
		input.extend(
			format!(
				"content-length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{HOVER}",
				HOVER.len()
			)
			.into_bytes(),
		);
		input.extend(framed(r#"{"jsonrpc":"2.0","id":1,"result":null}"#));
		input.extend(framed(r#"{"jsonrpc":"2.0","method":"exit"}"#));
		input.extend(framed(HOVER));
		let (outcome, delivered, replies) = read_all(input);
		outcome.expect("reads");
		assert!(replies.is_empty(), "{replies:?}");
		assert!(
			matches!(
				delivered.as_slice(),
				[
					Message::Request(_),
					Message::Request(_),
					Message::Response(_),
					Message::Notification(exit),
				] if exit.method == "exit"
			),
			"nothing is read past `exit`: {delivered:?}"
		);
	}

	#[test]
	fn a_frame_of_unknown_length_ends_the_stream_with_an_error() {
		for head in [
			"\r\n{}",
			"Content-Length:2\r\n\r\n{}",
			"Content-Length: 99999999999999999999\r\n\r\n{}",
			"Content-Length: 2\n\n{}",
		] {
			let (outcome, delivered, replies) = read_all(head.as_bytes().to_vec());
			let error = outcome.expect_err("the frame has no usable length");
			assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{head:?}");
			assert!(delivered.is_empty() && replies.is_empty(), "{head:?}");
		}
		let (outcome, _, _) = read_all(b"Content-Length: 9\r\n\r\n{}".to_vec());
		assert_eq!(
			outcome.expect_err("the body is cut short").kind(),
			io::ErrorKind::UnexpectedEof
		);
		let (outcome, delivered, _) = read_all(Vec::new());
		outcome.expect("the end of input is not an error");
		assert!(delivered.is_empty());
	}
}
