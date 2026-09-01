/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod analysis;
pub(crate) mod diagnostics;
pub(crate) mod docs;
pub(crate) mod language;
pub(crate) mod line;
pub(crate) mod proto;
pub(crate) mod state;

use std::error::Error;

use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::{
	CodeActionParams, CodeLensParams, CompletionParams, DidChangeTextDocumentParams,
	DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentFormattingParams,
	DocumentHighlightParams, DocumentSymbolParams, ExecuteCommandParams, FoldingRangeParams,
	GotoDefinitionParams, InitializeParams, InlayHintParams, OneOf, PositionEncodingKind,
	ReferenceParams, RenameParams, SemanticTokensParams, ServerCapabilities, SignatureHelpParams,
	TextDocumentPositionParams, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit,
};

type Fallible = Result<(), Box<dyn Error + Sync + Send>>;

const TICK: std::time::Duration = std::time::Duration::from_millis(100);

pub fn run() -> Fallible {
	let (connection, io_threads) = Connection::stdio();
	let outcome = serve(&connection);
	drop(connection);
	io_threads.join()?;
	outcome
}

pub(crate) fn serve(connection: &Connection) -> Fallible {
	crate::info::set_verbosity(crate::info::Verbosity::Silent);
	let (id, params) = connection.initialize_start()?;
	let params: InitializeParams = serde_json::from_value(params)?;
	let encoding = negotiate_encoding(&params);
	connection.initialize_finish(
		id,
		serde_json::json!({
			"capabilities": capabilities(&encoding),
			"serverInfo": {
				"name": "verifpal",
				"version": env!("CARGO_PKG_VERSION"),
			},
		}),
	)?;
	let mut server = Server::new(connection.sender.clone(), encoding);
	server.main_loop(connection)
}

fn negotiate_encoding(params: &InitializeParams) -> PositionEncodingKind {
	let offered = params
		.capabilities
		.general
		.as_ref()
		.and_then(|g| g.position_encodings.as_ref());
	match offered {
		Some(kinds) if kinds.contains(&PositionEncodingKind::UTF8) => PositionEncodingKind::UTF8,
		_ => PositionEncodingKind::UTF16,
	}
}

fn capabilities(encoding: &PositionEncodingKind) -> ServerCapabilities {
	ServerCapabilities {
		position_encoding: Some(encoding.clone()),
		text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
		document_formatting_provider: Some(OneOf::Left(true)),
		hover_provider: Some(lsp_types::HoverProviderCapability::Simple(true)),
		definition_provider: Some(OneOf::Left(true)),
		references_provider: Some(OneOf::Left(true)),
		document_highlight_provider: Some(OneOf::Left(true)),
		document_symbol_provider: Some(OneOf::Left(true)),
		folding_range_provider: Some(lsp_types::FoldingRangeProviderCapability::Simple(true)),
		rename_provider: Some(OneOf::Right(lsp_types::RenameOptions {
			prepare_provider: Some(true),
			work_done_progress_options: Default::default(),
		})),
		completion_provider: Some(lsp_types::CompletionOptions {
			trigger_characters: Some(vec!["[".to_string(), ",".to_string(), " ".to_string()]),
			..Default::default()
		}),
		signature_help_provider: Some(lsp_types::SignatureHelpOptions {
			trigger_characters: Some(vec!["(".to_string(), ",".to_string()]),
			retrigger_characters: None,
			work_done_progress_options: Default::default(),
		}),
		semantic_tokens_provider: Some(
			lsp_types::SemanticTokensServerCapabilities::SemanticTokensOptions(
				lsp_types::SemanticTokensOptions {
					legend: lsp_types::SemanticTokensLegend {
						token_types: crate::lsp::language::TOKEN_TYPES
							.iter()
							.map(|t| lsp_types::SemanticTokenType::new(t))
							.collect(),
						token_modifiers: crate::lsp::language::TOKEN_MODIFIERS
							.iter()
							.map(|m| lsp_types::SemanticTokenModifier::new(m))
							.collect(),
					},
					full: Some(lsp_types::SemanticTokensFullOptions::Bool(true)),
					range: None,
					work_done_progress_options: Default::default(),
				},
			),
		),
		inlay_hint_provider: Some(OneOf::Left(true)),
		code_lens_provider: Some(lsp_types::CodeLensOptions {
			resolve_provider: Some(false),
		}),
		code_action_provider: Some(lsp_types::CodeActionProviderCapability::Simple(true)),
		execute_command_provider: Some(lsp_types::ExecuteCommandOptions {
			commands: vec![
				"verifpal.analyze".to_string(),
				"verifpal.cancelAnalysis".to_string(),
				"verifpal.diagram".to_string(),
			],
			..Default::default()
		}),
		..Default::default()
	}
}

pub(crate) struct Server {
	sender: crossbeam_channel::Sender<Message>,
	docs: crate::lsp::state::Documents,
	dirty: std::collections::HashSet<String>,
	runner: crate::lsp::analysis::Runner,
	next_token: u64,
	encoding: PositionEncodingKind,
}

impl Server {
	fn new(sender: crossbeam_channel::Sender<Message>, encoding: PositionEncodingKind) -> Server {
		Server {
			sender: sender.clone(),
			docs: crate::lsp::state::Documents::new(encoding.clone()),
			dirty: std::collections::HashSet::new(),
			runner: crate::lsp::analysis::Runner::new(sender),
			next_token: 0,
			encoding,
		}
	}

	fn main_loop(&mut self, connection: &Connection) -> Fallible {
		loop {
			match connection.receiver.recv_timeout(TICK) {
				Ok(Message::Request(req)) => {
					if connection.handle_shutdown(&req)? {
						self.runner.cancel_all();
						return Ok(());
					}
					self.on_request(req);
				}
				Ok(Message::Notification(note)) => self.on_notification(note),
				Ok(Message::Response(_)) => {}
				Err(e) if e.is_disconnected() => {
					self.runner.cancel_all();
					return Ok(());
				}
				Err(_) => self.on_tick(),
			}
		}
	}

	fn on_request(&mut self, req: Request) {
		match req.method.as_str() {
			"textDocument/formatting" => {
				let response = match serde_json::from_value::<DocumentFormattingParams>(req.params)
				{
					Ok(p) => Response::new_ok(req.id, self.format(p.text_document.uri.as_str())),
					Err(e) => Response::new_err(
						req.id,
						lsp_server::ErrorCode::InvalidParams as i32,
						e.to_string(),
					),
				};
				self.respond(response);
			}
			"textDocument/hover" => self.answer::<TextDocumentPositionParams, _>(req, |s, p| {
				s.with_doc(p.text_document.uri.as_str(), |doc| {
					crate::lsp::language::hover(doc, p.position)
				})
				.flatten()
			}),
			"textDocument/definition" => self.answer::<GotoDefinitionParams, _>(req, |s, p| {
				let uri = p.text_document_position_params.text_document.uri.clone();
				s.with_doc(uri.as_str(), |doc| {
					crate::lsp::language::definition(
						doc,
						p.text_document_position_params.position,
						&uri,
					)
				})
				.flatten()
			}),
			"textDocument/references" => self.answer::<ReferenceParams, _>(req, |s, p| {
				let uri = p.text_document_position.text_document.uri.clone();
				s.with_doc(uri.as_str(), |doc| {
					crate::lsp::language::references(doc, p.text_document_position.position, &uri)
				})
				.unwrap_or_default()
			}),
			"textDocument/documentHighlight" => {
				self.answer::<DocumentHighlightParams, _>(req, |s, p| {
					s.with_doc(
						p.text_document_position_params.text_document.uri.as_str(),
						|doc| {
							crate::lsp::language::highlights(
								doc,
								p.text_document_position_params.position,
							)
						},
					)
					.unwrap_or_default()
				})
			}
			"textDocument/documentSymbol" => self.answer::<DocumentSymbolParams, _>(req, |s, p| {
				s.with_doc(p.text_document.uri.as_str(), |doc| {
					crate::lsp::language::document_symbols(doc)
				})
				.unwrap_or_default()
			}),
			"textDocument/foldingRange" => self.answer::<FoldingRangeParams, _>(req, |s, p| {
				s.with_doc(p.text_document.uri.as_str(), |doc| {
					crate::lsp::language::folding_ranges(doc)
				})
				.unwrap_or_default()
			}),
			"textDocument/completion" => self.answer::<CompletionParams, _>(req, |s, p| {
				s.with_doc(p.text_document_position.text_document.uri.as_str(), |doc| {
					crate::lsp::language::completions(doc, p.text_document_position.position)
				})
				.unwrap_or_default()
			}),
			"textDocument/signatureHelp" => self.answer::<SignatureHelpParams, _>(req, |s, p| {
				s.with_doc(
					p.text_document_position_params.text_document.uri.as_str(),
					|doc| {
						crate::lsp::language::signature_help(
							doc,
							p.text_document_position_params.position,
						)
					},
				)
				.flatten()
			}),
			"textDocument/semanticTokens/full" => {
				self.answer::<SemanticTokensParams, _>(req, |s, p| {
					s.with_doc(
						p.text_document.uri.as_str(),
						|doc| serde_json::json!({"data": crate::lsp::language::semantic_tokens(doc)}),
					)
					.unwrap_or(serde_json::Value::Null)
				})
			}
			"textDocument/inlayHint" => self.answer::<InlayHintParams, _>(req, |s, p| {
				s.with_doc(p.text_document.uri.as_str(), |doc| {
					crate::lsp::language::inlay_hints(doc, p.range)
				})
				.unwrap_or_default()
			}),
			"textDocument/prepareRename" => {
				self.answer::<TextDocumentPositionParams, _>(req, |s, p| {
					s.with_doc(p.text_document.uri.as_str(), |doc| {
						crate::lsp::language::prepare_rename(doc, p.position)
					})
					.flatten()
				})
			}
			"textDocument/rename" => self.answer::<RenameParams, _>(req, |s, p| {
				let uri = p.text_document_position.text_document.uri.clone();
				let edits = s
					.with_doc(uri.as_str(), |doc| {
						crate::lsp::language::rename(
							doc,
							p.text_document_position.position,
							&p.new_name,
						)
					})
					.flatten();
				edits.map(|edits| lsp_types::WorkspaceEdit {
					changes: Some(std::collections::HashMap::from([(uri, edits)])),
					..Default::default()
				})
			}),
			"textDocument/codeLens" => self.answer::<CodeLensParams, _>(req, |s, p| {
				s.code_lenses(p.text_document.uri.as_str())
			}),
			"textDocument/codeAction" => {
				self.answer::<CodeActionParams, _>(req, |s, p| s.code_actions(&p))
			}
			"workspace/executeCommand" => {
				let response = match serde_json::from_value::<ExecuteCommandParams>(req.params) {
					Ok(p) => Response::new_ok(req.id, self.command(&p)),
					Err(e) => Response::new_err(
						req.id,
						lsp_server::ErrorCode::InvalidParams as i32,
						e.to_string(),
					),
				};
				self.respond(response);
			}
			method => {
				let message = format!("unhandled request: {method}");
				self.respond(Response::new_err(
					req.id,
					lsp_server::ErrorCode::MethodNotFound as i32,
					message,
				));
			}
		}
	}

	fn on_notification(&mut self, note: Notification) {
		match note.method.as_str() {
			"textDocument/didOpen" => {
				if let Ok(p) = serde_json::from_value::<DidOpenTextDocumentParams>(note.params) {
					let uri = p.text_document.uri.as_str().to_string();
					let name = crate::lsp::state::file_name(&p.text_document.uri);
					self.docs.open(
						uri.clone(),
						name,
						p.text_document.version,
						p.text_document.text,
					);
					self.dirty.insert(uri);
				}
			}
			"textDocument/didChange" => {
				if let Ok(p) = serde_json::from_value::<DidChangeTextDocumentParams>(note.params) {
					let uri = p.text_document.uri.as_str().to_string();
					if let Some(change) = p.content_changes.into_iter().next_back() {
						self.runner.cancel(&uri);
						self.docs.change(&uri, p.text_document.version, change.text);
						self.dirty.insert(uri);
					}
				}
			}
			"textDocument/didClose" => {
				if let Ok(p) = serde_json::from_value::<DidCloseTextDocumentParams>(note.params) {
					let parsed = p.text_document.uri;
					let uri = parsed.as_str();
					self.runner.cancel(uri);
					self.dirty.remove(uri);
					self.docs.close(uri);
					self.notify(
						"textDocument/publishDiagnostics",
						lsp_types::PublishDiagnosticsParams {
							uri: parsed,
							diagnostics: Vec::new(),
							version: None,
						},
					);
				}
			}
			_ => {}
		}
	}

	fn on_tick(&mut self) {
		if self.dirty.is_empty() {
			return;
		}
		for uri in std::mem::take(&mut self.dirty) {
			self.publish(&uri);
		}
	}

	fn publish(&self, uri: &str) {
		let Some(doc) = self.docs.get(uri) else {
			return;
		};
		let Ok(parsed) = <lsp_types::Uri as std::str::FromStr>::from_str(uri) else {
			return;
		};
		let diagnostics = crate::lsp::diagnostics::for_document(doc, &parsed);
		self.notify(
			"textDocument/publishDiagnostics",
			lsp_types::PublishDiagnosticsParams {
				uri: parsed,
				diagnostics,
				version: Some(doc.version),
			},
		);
	}

	fn answer<P, R>(&mut self, req: Request, f: impl FnOnce(&mut Server, P) -> R)
	where
		P: serde::de::DeserializeOwned,
		R: serde::Serialize,
	{
		let response = match serde_json::from_value::<P>(req.params) {
			Ok(p) => Response::new_ok(req.id, f(self, p)),
			Err(e) => Response::new_err(
				req.id,
				lsp_server::ErrorCode::InvalidParams as i32,
				e.to_string(),
			),
		};
		self.respond(response);
	}

	fn with_doc<R>(
		&self,
		uri: &str,
		f: impl FnOnce(&crate::lsp::state::Document) -> R,
	) -> Option<R> {
		self.docs.get(uri).map(f)
	}

	fn code_lenses(&self, uri: &str) -> Vec<lsp_types::CodeLens> {
		let Some(doc) = self.docs.get(uri) else {
			return Vec::new();
		};
		let Ok(model) = &doc.model else {
			return Vec::new();
		};
		let Some(first) = model.queries.first() else {
			return Vec::new();
		};
		vec![lsp_types::CodeLens {
			range: doc
				.line
				.range(crate::types::Span::new(first.span.start, first.span.start)),
			command: Some(lsp_types::Command {
				title: "Run attacker analysis".to_string(),
				command: "verifpal.analyze".to_string(),
				arguments: Some(vec![serde_json::json!({"uri": uri})]),
			}),
			data: None,
		}]
	}

	fn code_actions(&self, params: &CodeActionParams) -> Vec<lsp_types::CodeActionOrCommand> {
		let uri = params.text_document.uri.as_str();
		let Some(doc) = self.docs.get(uri) else {
			return Vec::new();
		};
		let needs_queries = params
			.context
			.diagnostics
			.iter()
			.any(|d| d.message.contains("no `queries` block"));
		if !needs_queries {
			return Vec::new();
		}
		let end = doc.line.end();
		let edit = TextEdit {
			range: lsp_types::Range::new(end, end),
			new_text: "\nqueries[\n\t\n]\n".to_string(),
		};
		vec![lsp_types::CodeActionOrCommand::CodeAction(
			lsp_types::CodeAction {
				title: "Add a queries block".to_string(),
				kind: Some(lsp_types::CodeActionKind::QUICKFIX),
				edit: Some(lsp_types::WorkspaceEdit {
					changes: Some(std::collections::HashMap::from([(
						params.text_document.uri.clone(),
						vec![edit],
					)])),
					..Default::default()
				}),
				..Default::default()
			},
		)]
	}

	fn command(&mut self, params: &ExecuteCommandParams) -> serde_json::Value {
		let first = params.arguments.first().cloned().unwrap_or_default();
		match params.command.as_str() {
			"verifpal.analyze" => match serde_json::from_value::<proto::AnalyzeArgs>(first) {
				Ok(args) => self.analyze(args),
				Err(_) => serde_json::json!(proto::Accepted {
					accepted: false,
					token: String::new()
				}),
			},
			"verifpal.cancelAnalysis" => match serde_json::from_value::<proto::UriArg>(first) {
				Ok(args) => serde_json::json!(proto::Cancelled {
					cancelled: self.runner.cancel(&args.uri)
				}),
				Err(_) => serde_json::json!(proto::Cancelled { cancelled: false }),
			},
			"verifpal.diagram" => match serde_json::from_value::<proto::UriArg>(first) {
				Ok(args) => self.diagram(&args.uri),
				Err(_) => serde_json::Value::Null,
			},
			_ => serde_json::Value::Null,
		}
	}

	fn analyze(&mut self, args: proto::AnalyzeArgs) -> serde_json::Value {
		let Some(doc) = self.docs.get(&args.uri) else {
			return serde_json::json!(proto::Accepted {
				accepted: false,
				token: String::new()
			});
		};
		self.next_token += 1;
		let token = format!("verifpal-analysis-{}", self.next_token);
		let sessions = args
			.sessions
			.unwrap_or(crate::sessions::DEFAULT_SESSIONS)
			.clamp(1, crate::sessions::MAX_SESSIONS);
		self.runner.start(
			args.uri.clone(),
			doc.name.clone(),
			doc.text.clone(),
			doc.version,
			sessions,
			token.clone(),
			self.encoding.clone(),
		);
		serde_json::json!(proto::Accepted {
			accepted: true,
			token
		})
	}

	fn diagram(&self, uri: &str) -> serde_json::Value {
		let Some(doc) = self.docs.get(uri) else {
			return serde_json::Value::Null;
		};
		let Ok(model) = &doc.model else {
			return serde_json::Value::Null;
		};
		let Ok(readable) = crate::pretty::pretty_diagram(model) else {
			return serde_json::Value::Null;
		};
		let mermaid = crate::pretty::mermaid_of(&readable);
		serde_json::json!(proto::DiagramResult { mermaid, readable })
	}

	fn format(&self, uri: &str) -> Vec<TextEdit> {
		let Some(doc) = self.docs.get(uri) else {
			return Vec::new();
		};
		let Ok(model) = &doc.model else {
			return Vec::new();
		};
		let text = crate::pretty::pretty_model(model);
		if text == doc.text {
			return Vec::new();
		}
		vec![TextEdit {
			range: lsp_types::Range::new(lsp_types::Position::new(0, 0), doc.line.end()),
			new_text: text,
		}]
	}

	fn respond(&self, response: Response) {
		let _ = self.sender.send(Message::Response(response));
	}

	fn notify(&self, method: &str, params: impl serde::Serialize) {
		let _ = self.sender.send(Message::Notification(Notification::new(
			method.to_string(),
			params,
		)));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use lsp_server::RequestId;
	use lsp_types::{ClientCapabilities, GeneralClientCapabilities};

	pub(crate) fn start(
		client_caps: ClientCapabilities,
	) -> (Connection, std::thread::JoinHandle<()>, serde_json::Value) {
		let (server, client) = Connection::memory();
		let handle = std::thread::spawn(move || {
			serve(&server).expect("the server runs");
		});
		client
			.sender
			.send(Message::Request(Request::new(
				RequestId::from(0),
				"initialize".to_string(),
				serde_json::json!({
					"processId": null,
					"rootUri": null,
					"capabilities": serde_json::to_value(&client_caps).expect("caps serialize"),
				}),
			)))
			.expect("sends initialize");
		let result = match client.receiver.recv().expect("initialize is answered") {
			Message::Response(r) => r.response_result.expect("initialize succeeds"),
			other => panic!("expected a response, got {:?}", other),
		};
		client
			.sender
			.send(Message::Notification(Notification::new(
				"initialized".to_string(),
				serde_json::json!({}),
			)))
			.expect("sends initialized");
		(client, handle, result)
	}

	pub(crate) fn stop(client: Connection, handle: std::thread::JoinHandle<()>) {
		client
			.sender
			.send(Message::Request(Request::new(
				RequestId::from(9999),
				"shutdown".to_string(),
				serde_json::json!(null),
			)))
			.expect("sends shutdown");
		client
			.sender
			.send(Message::Notification(Notification::new(
				"exit".to_string(),
				serde_json::json!(null),
			)))
			.expect("sends exit");
		drop(client);
		handle.join().expect("the server exits cleanly");
	}

	pub(crate) fn open(client: &Connection, uri: &str, text: &str) {
		client
			.sender
			.send(Message::Notification(Notification::new(
				"textDocument/didOpen".to_string(),
				serde_json::json!({
					"textDocument": {
						"uri": uri,
						"languageId": "verifpal",
						"version": 1,
						"text": text,
					}
				}),
			)))
			.expect("sends didOpen");
	}

	pub(crate) fn await_notification(client: &Connection, method: &str) -> serde_json::Value {
		loop {
			match client
				.receiver
				.recv_timeout(std::time::Duration::from_secs(60))
			{
				Ok(Message::Notification(n)) if n.method == method => return n.params,
				Ok(_) => continue,
				Err(e) => panic!("no {method} arrived: {e:?}"),
			}
		}
	}

	pub(crate) fn request(
		client: &Connection,
		id: i32,
		method: &str,
		params: serde_json::Value,
	) -> serde_json::Value {
		client
			.sender
			.send(Message::Request(Request::new(
				RequestId::from(id),
				method.to_string(),
				params,
			)))
			.expect("sends the request");
		loop {
			match client
				.receiver
				.recv_timeout(std::time::Duration::from_secs(60))
			{
				Ok(Message::Response(r)) if r.id == RequestId::from(id) => {
					return r.response_result.expect("a successful response");
				}
				Ok(_) => continue,
				Err(e) => panic!("no response to {method}: {e:?}"),
			}
		}
	}

	const VALID: &str = "attacker[passive]\n\
		principal Alice[\n\
		knows private e2k_m\n\
		e2k_h = HASH(e2k_m)\n\
		]\n\
		Alice -> Bob: e2k_h\n\
		principal Bob[\n\
		_ = HASH(e2k_h)\n\
		]\n\
		queries[\n\
		confidentiality? e2k_m\n\
		]\n";

	#[test]
	fn opening_a_broken_model_publishes_a_diagnostic() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(
			&client,
			"file:///e2e.vp",
			"attacker[active]\nprincipal Alice[\nknows private e2e_a\n",
		);
		let params = await_notification(&client, "textDocument/publishDiagnostics");
		let diagnostics = params["diagnostics"].as_array().expect("an array");
		assert_eq!(diagnostics.len(), 1, "{params}");
		assert_eq!(diagnostics[0]["source"], "verifpal");
		stop(client, handle);
	}

	#[test]
	fn opening_a_valid_model_publishes_an_empty_list() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(&client, "file:///ok.vp", VALID);
		let params = await_notification(&client, "textDocument/publishDiagnostics");
		assert_eq!(params["diagnostics"].as_array().expect("array").len(), 0);
		stop(client, handle);
	}

	#[test]
	fn closing_a_document_discards_its_pending_diagnostics() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		server.on_notification(Notification::new(
			"textDocument/didOpen".to_string(),
			serde_json::json!({
				"textDocument": {
					"uri": "file:///closed.vp",
					"languageId": "verifpal",
					"version": 1,
					"text": VALID,
				}
			}),
		));
		assert!(server.docs.get("file:///closed.vp").is_some());
		assert!(server.dirty.contains("file:///closed.vp"));
		server.on_notification(Notification::new(
			"textDocument/didClose".to_string(),
			serde_json::json!({"textDocument": {"uri": "file:///closed.vp"}}),
		));
		assert!(server.docs.get("file:///closed.vp").is_none());
		assert!(!server.dirty.contains("file:///closed.vp"));
		let Message::Notification(cleared) = receiver.recv().expect("diagnostics are cleared")
		else {
			panic!("expected a notification");
		};
		assert_eq!(cleared.method, "textDocument/publishDiagnostics");
		assert_eq!(cleared.params["diagnostics"], serde_json::json!([]));
	}

	#[test]
	fn formatting_returns_one_edit_covering_the_document() {
		let (client, handle, _) = start(ClientCapabilities::default());
		let ugly = "attacker[passive]\n\
			principal Alice[\n\
			knows private fmt_m\n\
			fmt_h    =    HASH(fmt_m)\n\
			]\n\
			Alice -> Bob: fmt_h\n\
			principal Bob[\n\
			_ = HASH(fmt_h)\n\
			]\n\
			queries[\n\
			confidentiality? fmt_m\n\
			]\n";
		open(&client, "file:///fmt.vp", ugly);
		let result = request(
			&client,
			1,
			"textDocument/formatting",
			serde_json::json!({
				"textDocument": {"uri": "file:///fmt.vp"},
				"options": {"tabSize": 4, "insertSpaces": false},
			}),
		);
		let edits = result.as_array().expect("an array of edits");
		assert_eq!(edits.len(), 1, "{result}");
		let text = edits[0]["newText"].as_str().expect("new text");
		assert!(text.contains("fmt_h = HASH(fmt_m)"), "{text}");
		assert_eq!(edits[0]["range"]["start"]["line"], 0);
		stop(client, handle);
	}

	#[test]
	fn formatting_a_broken_model_returns_no_edits() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(
			&client,
			"file:///bad.vp",
			"attacker[active]\nprincipal Alice[\n",
		);
		let result = request(
			&client,
			1,
			"textDocument/formatting",
			serde_json::json!({
				"textDocument": {"uri": "file:///bad.vp"},
				"options": {"tabSize": 4, "insertSpaces": false},
			}),
		);
		assert_eq!(result.as_array().expect("an array").len(), 0, "{result}");
		stop(client, handle);
	}

	#[test]
	fn analyzing_a_model_reports_the_attack() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(
			&client,
			"file:///a.vp",
			"attacker[active]\n\
			principal Alice[\n\
			knows private ee_a\n\
			ee_ga = PUBKEY(ee_a)\n\
			]\n\
			Alice -> Bob: ee_ga\n\
			principal Bob[\n\
			knows private ee_b\n\
			ee_gb = PUBKEY(ee_b)\n\
			ee_k = DH_KEX(ee_ga, ee_b)\n\
			generates ee_m\n\
			ee_e = AEAD_ENC(ee_k, ee_m, nil)\n\
			]\n\
			Bob -> Alice: ee_gb, ee_e\n\
			queries[\n\
			confidentiality? ee_m\n\
			]\n",
		);
		let accepted = request(
			&client,
			1,
			"workspace/executeCommand",
			serde_json::json!({
				"command": "verifpal.analyze",
				"arguments": [{"uri": "file:///a.vp", "sessions": 1}],
			}),
		);
		assert_eq!(accepted["accepted"], true, "{accepted}");
		let report = await_notification(&client, "verifpal/analysisReport");
		assert_eq!(report["ok"], true, "{report}");
		assert_eq!(report["code"], "c1", "{report}");
		let queries = report["queries"].as_array().expect("queries");
		assert_eq!(queries.len(), 1);
		assert_eq!(queries[0]["resolved"], true);
		assert!(!queries[0]["steps"].as_array().expect("steps").is_empty());
		stop(client, handle);
	}

	#[test]
	fn an_out_of_range_session_count_is_clamped_rather_than_reported_as_run() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(&client, "file:///s.vp", VALID);
		for (asked, ran) in [(0u8, 1u8), (200u8, crate::sessions::MAX_SESSIONS)] {
			let accepted = request(
				&client,
				1,
				"workspace/executeCommand",
				serde_json::json!({
					"command": "verifpal.analyze",
					"arguments": [{"uri": "file:///s.vp", "sessions": asked}],
				}),
			);
			assert_eq!(accepted["accepted"], true, "{accepted}");
			let report = await_notification(&client, "verifpal/analysisReport");
			assert_eq!(report["ok"], true, "{report}");
			assert_eq!(
				report["sessions"], ran,
				"asking for {asked} sessions must report the count actually analyzed: {report}"
			);
		}
		stop(client, handle);
	}

	#[test]
	fn the_diagram_command_returns_both_renderings() {
		let (client, handle, _) = start(ClientCapabilities::default());
		open(&client, "file:///d.vp", VALID);
		let result = request(
			&client,
			1,
			"workspace/executeCommand",
			serde_json::json!({
				"command": "verifpal.diagram",
				"arguments": [{"uri": "file:///d.vp"}],
			}),
		);
		let mermaid = result["mermaid"].as_str().expect("mermaid source");
		assert!(mermaid.starts_with("sequenceDiagram\n"), "{mermaid}");
		assert!(
			result["readable"]
				.as_str()
				.expect("readable")
				.contains("Alice")
		);
		stop(client, handle);
	}

	#[test]
	fn the_server_initializes_and_shuts_down() {
		let (client, handle, _) = start(ClientCapabilities::default());
		stop(client, handle);
	}

	#[test]
	fn a_client_offering_utf8_is_answered_in_utf8() {
		let caps = ClientCapabilities {
			general: Some(GeneralClientCapabilities {
				position_encodings: Some(vec![
					PositionEncodingKind::UTF8,
					PositionEncodingKind::UTF16,
				]),
				..Default::default()
			}),
			..Default::default()
		};
		let (client, handle, result) = start(caps);
		assert_eq!(
			result["capabilities"]["positionEncoding"].as_str(),
			Some("utf-8")
		);
		stop(client, handle);
	}

	#[test]
	fn a_client_that_says_nothing_is_answered_in_utf16() {
		let (client, handle, result) = start(ClientCapabilities::default());
		assert_eq!(
			result["capabilities"]["positionEncoding"].as_str(),
			Some("utf-16")
		);
		stop(client, handle);
	}
}
