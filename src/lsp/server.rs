/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::{HashMap, HashSet};
use std::error::Error;

use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use lsp_types::{
	CodeActionParams, CodeLensParams, CompletionParams, DidChangeTextDocumentParams,
	DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
	DocumentFormattingParams, DocumentHighlightParams, DocumentSymbolParams, ExecuteCommandParams,
	FoldingRangeParams, GotoDefinitionParams, InitializeParams, InlayHintParams, OneOf,
	PositionEncodingKind, ReferenceParams, RenameParams, SemanticTokensParams, ServerCapabilities,
	SignatureHelpParams, TextDocumentPositionParams, TextDocumentSyncCapability,
	TextDocumentSyncKind, TextDocumentSyncOptions, TextDocumentSyncSaveOptions, TextEdit,
};

use crate::lsp::language;
use crate::lsp::proto;
use crate::lsp::state::Document;

type Fallible = Result<(), Box<dyn Error + Sync + Send>>;

const TICK: std::time::Duration = std::time::Duration::from_millis(100);

pub fn run() -> Fallible {
	let (connection, io_threads) = Connection::stdio();
	let outcome = serve(&connection);
	drop(connection);
	io_threads.join()?;
	outcome
}

fn serve(connection: &Connection) -> Fallible {
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
	server.progress_supported = params
		.capabilities
		.window
		.as_ref()
		.and_then(|w| w.work_done_progress)
		.unwrap_or(false);
	let workspace = params.capabilities.workspace.as_ref();
	server.inlay_refresh = workspace
		.and_then(|w| w.inlay_hint.as_ref())
		.and_then(|i| i.refresh_support)
		.unwrap_or(false);
	server.code_lens_refresh = workspace
		.and_then(|w| w.code_lens.as_ref())
		.and_then(|c| c.refresh_support)
		.unwrap_or(false);
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
		text_document_sync: Some(TextDocumentSyncCapability::Options(
			TextDocumentSyncOptions {
				open_close: Some(true),
				change: Some(TextDocumentSyncKind::FULL),
				save: Some(TextDocumentSyncSaveOptions::Supported(true)),
				..Default::default()
			},
		)),
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
						token_types: language::TOKEN_TYPES
							.iter()
							.map(|t| lsp_types::SemanticTokenType::new(t))
							.collect(),
						token_modifiers: language::TOKEN_MODIFIERS
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Settings {
	validate_on_type: bool,
	passing: bool,
	inlay_hints: bool,
	code_lens: bool,
}

impl Default for Settings {
	fn default() -> Settings {
		Settings {
			validate_on_type: true,
			passing: true,
			inlay_hints: true,
			code_lens: true,
		}
	}
}

impl Settings {
	fn updated(self, params: &serde_json::Value) -> Settings {
		let section = &params["settings"]["verifpal"];
		let flag = |keys: &[&str], current: bool| {
			let mut value = section;
			for key in keys {
				value = &value[*key];
			}
			value.as_bool().unwrap_or(current)
		};
		Settings {
			validate_on_type: flag(&["validateOnType"], self.validate_on_type),
			passing: flag(&["diagnostics", "passing"], self.passing),
			inlay_hints: flag(&["inlayHints", "argumentNames"], self.inlay_hints),
			code_lens: flag(&["codeLens"], self.code_lens),
		}
	}
}

struct Server {
	sender: crossbeam_channel::Sender<Message>,
	docs: HashMap<String, Document>,
	dirty: HashSet<String>,
	runner: crate::lsp::analysis::Runner,
	next_token: u64,
	next_request_id: i32,
	encoding: PositionEncodingKind,
	settings: Settings,
	progress_supported: bool,
	inlay_refresh: bool,
	code_lens_refresh: bool,
	dirty_since: Option<std::time::Instant>,
	shut_down: bool,
}

impl Server {
	fn new(sender: crossbeam_channel::Sender<Message>, encoding: PositionEncodingKind) -> Server {
		Server {
			sender: sender.clone(),
			docs: HashMap::new(),
			dirty: HashSet::new(),
			runner: crate::lsp::analysis::Runner::new(sender),
			next_token: 0,
			next_request_id: 0,
			encoding,
			settings: Settings::default(),
			progress_supported: false,
			inlay_refresh: false,
			code_lens_refresh: false,
			dirty_since: None,
			shut_down: false,
		}
	}

	fn main_loop(&mut self, connection: &Connection) -> Fallible {
		loop {
			match connection.receiver.recv_timeout(TICK) {
				Ok(Message::Request(req)) => {
					if req.method == "shutdown" {
						self.runner.cancel_all();
						self.shut_down = true;
						self.respond(Response::new_ok(req.id, serde_json::Value::Null));
					} else if self.shut_down {
						self.respond(Response::new_err(
							req.id,
							lsp_server::ErrorCode::InvalidRequest as i32,
							"the server has been shut down and accepts only `exit`".to_string(),
						));
					} else {
						self.on_request(req);
					}
				}
				Ok(Message::Notification(note)) => {
					if note.method == "exit" {
						self.runner.cancel_all();
						return if self.shut_down {
							Ok(())
						} else {
							Err("`exit` received before `shutdown`".into())
						};
					}
					if !self.shut_down {
						self.on_notification(note);
					}
				}
				Ok(Message::Response(_)) => {}
				Err(e) if e.is_disconnected() => {
					self.runner.cancel_all();
					return Ok(());
				}
				Err(_) => {}
			}
			self.tick_if_due();
		}
	}

	fn mark_dirty(&mut self, uri: String) {
		self.dirty.insert(uri);
		self.dirty_since.get_or_insert_with(std::time::Instant::now);
	}

	fn tick_if_due(&mut self) {
		if self
			.dirty_since
			.is_some_and(|since| since.elapsed() >= TICK)
		{
			self.on_tick();
		}
	}

	fn on_request(&mut self, req: Request) {
		match req.method.as_str() {
			"textDocument/formatting" => {
				self.on_document(req, |_, doc, _: DocumentFormattingParams| format(doc))
			}
			"textDocument/hover" => self
				.on_document(req, |_, doc, p: TextDocumentPositionParams| {
					language::hover(doc, p.position)
				}),
			"textDocument/definition" => {
				self.on_document(req, |_, doc, p: GotoDefinitionParams| {
					language::definition(doc, p.text_document_position_params.position)
				})
			}
			"textDocument/references" => self.on_document(req, |_, doc, p: ReferenceParams| {
				language::references(doc, p.text_document_position.position)
			}),
			"textDocument/documentHighlight" => {
				self.on_document(req, |_, doc, p: DocumentHighlightParams| {
					language::highlights(doc, p.text_document_position_params.position)
				})
			}
			"textDocument/documentSymbol" => self
				.on_document(req, |_, doc, _: DocumentSymbolParams| {
					language::document_symbols(doc)
				}),
			"textDocument/foldingRange" => self
				.on_document(req, |_, doc, _: FoldingRangeParams| {
					language::folding_ranges(doc)
				}),
			"textDocument/completion" => self.on_document(req, |_, doc, p: CompletionParams| {
				language::completions(doc, p.text_document_position.position)
			}),
			"textDocument/signatureHelp" => {
				self.on_document(req, |_, doc, p: SignatureHelpParams| {
					language::signature_help(doc, p.text_document_position_params.position)
				})
			}
			"textDocument/semanticTokens/full" => self.on_document(
				req,
				|_, doc, _: SemanticTokensParams| serde_json::json!({"data": language::semantic_tokens(doc)}),
			),
			"textDocument/inlayHint" => self.on_document(req, |s, doc, p: InlayHintParams| {
				if s.settings.inlay_hints {
					language::inlay_hints(doc, p.range)
				} else {
					Vec::new()
				}
			}),
			"textDocument/prepareRename" => self
				.on_document(req, |_, doc, p: TextDocumentPositionParams| {
					language::prepare_rename(doc, p.position)
				}),
			"textDocument/rename" => self.on_document(req, |_, doc, p: RenameParams| {
				language::rename(doc, p.text_document_position.position, &p.new_name)
					.map(|edits| workspace_edit(doc, edits))
			}),
			"textDocument/codeLens" => self.on_document(req, |s, doc, _: CodeLensParams| {
				if s.settings.code_lens {
					code_lenses(doc)
				} else {
					Vec::new()
				}
			}),
			"textDocument/codeAction" => {
				self.on_document(req, |_, doc, p: CodeActionParams| code_actions(doc, &p))
			}
			"workspace/executeCommand" => {
				self.answer(req, |s, p: ExecuteCommandParams| s.command(&p))
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
					let doc = Document::new(
						p.text_document.uri,
						p.text_document.version,
						p.text_document.text,
						&self.encoding,
					);
					self.docs.insert(uri.clone(), doc);
					self.mark_dirty(uri);
				}
			}
			"textDocument/didChange" => {
				if let Ok(p) = serde_json::from_value::<DidChangeTextDocumentParams>(note.params)
					&& let Some(change) = p.content_changes.into_iter().next_back()
				{
					let uri = p.text_document.uri.as_str().to_string();
					self.runner.discard(&uri);
					if let Some(doc) = self.docs.get_mut(&uri) {
						*doc = Document::new(
							p.text_document.uri,
							p.text_document.version,
							change.text,
							&self.encoding,
						);
					}
					if self.settings.validate_on_type {
						self.mark_dirty(uri);
					}
				}
			}
			"textDocument/didSave" => {
				if let Ok(p) = serde_json::from_value::<DidSaveTextDocumentParams>(note.params) {
					let uri = p.text_document.uri.as_str().to_string();
					if !self.settings.validate_on_type && self.docs.contains_key(&uri) {
						self.mark_dirty(uri);
					}
				}
			}
			"textDocument/didClose" => {
				if let Ok(p) = serde_json::from_value::<DidCloseTextDocumentParams>(note.params) {
					let uri = p.text_document.uri;
					self.runner.discard(uri.as_str());
					self.dirty.remove(uri.as_str());
					self.docs.remove(uri.as_str());
					self.notify(
						"textDocument/publishDiagnostics",
						lsp_types::PublishDiagnosticsParams {
							uri,
							diagnostics: Vec::new(),
							version: None,
						},
					);
				}
			}
			"workspace/didChangeConfiguration" => self.apply_settings(&note.params),
			"window/workDoneProgress/cancel" => {
				if let Some(token) = note.params["token"].as_str() {
					self.runner.cancel_token(token);
				}
			}
			_ => {}
		}
	}

	fn apply_settings(&mut self, params: &serde_json::Value) {
		let next = self.settings.updated(params);
		if next == self.settings {
			return;
		}
		let previous = std::mem::replace(&mut self.settings, next);
		if previous.passing != next.passing {
			let open: Vec<String> = self.docs.keys().cloned().collect();
			for uri in open {
				self.mark_dirty(uri);
			}
		}
		if previous.inlay_hints != next.inlay_hints && self.inlay_refresh {
			self.request("workspace/inlayHint/refresh", serde_json::Value::Null);
		}
		if previous.code_lens != next.code_lens && self.code_lens_refresh {
			self.request("workspace/codeLens/refresh", serde_json::Value::Null);
		}
	}

	fn on_tick(&mut self) {
		self.dirty_since = None;
		for uri in std::mem::take(&mut self.dirty) {
			self.publish(&uri);
		}
	}

	fn publish(&self, uri: &str) {
		let Some(doc) = self.docs.get(uri) else {
			return;
		};
		let mut diagnostics = crate::lsp::diagnostics::for_document(doc);
		if let Some(verdicts) = self.runner.verdicts(uri, doc.version) {
			diagnostics.extend(crate::lsp::diagnostics::shown(
				&verdicts,
				self.settings.passing,
			));
		}
		self.notify(
			"textDocument/publishDiagnostics",
			lsp_types::PublishDiagnosticsParams {
				uri: doc.uri.clone(),
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

	fn on_document<P, R>(&mut self, req: Request, f: impl FnOnce(&Server, &Document, P) -> R)
	where
		P: serde::de::DeserializeOwned,
		R: serde::Serialize + Default,
	{
		let uri = req.params["textDocument"]["uri"]
			.as_str()
			.unwrap_or_default()
			.to_string();
		self.answer(req, |s, p| match s.docs.get(&uri) {
			Some(doc) => f(s, doc, p),
			None => R::default(),
		})
	}

	fn command(&mut self, params: &ExecuteCommandParams) -> serde_json::Value {
		let first = params.arguments.first().cloned().unwrap_or_default();
		match params.command.as_str() {
			"verifpal.analyze" => match serde_json::from_value::<proto::AnalyzeArgs>(first) {
				Ok(args) => self.analyze(args),
				Err(e) => declined(format!("malformed arguments: {e}")),
			},
			"verifpal.cancelAnalysis" => match serde_json::from_value::<proto::UriArg>(first) {
				Ok(args) => serde_json::json!(proto::Cancelled {
					cancelled: self.runner.cancel(&args.uri)
				}),
				Err(_) => serde_json::json!(proto::Cancelled { cancelled: false }),
			},
			"verifpal.diagram" => match serde_json::from_value::<proto::UriArg>(first) {
				Ok(args) => serde_json::json!(self.docs.get(&args.uri).and_then(diagram)),
				Err(_) => serde_json::Value::Null,
			},
			_ => serde_json::Value::Null,
		}
	}

	fn analyze(&mut self, args: proto::AnalyzeArgs) -> serde_json::Value {
		let Some(doc) = self.docs.get(&args.uri) else {
			return declined(format!("{} is not an open document", args.uri));
		};
		self.next_token += 1;
		let token = format!("verifpal-analysis-{}", self.next_token);
		let sessions = args
			.sessions
			.map_or(crate::sessions::DEFAULT_SESSIONS, |s| {
				s.round()
					.clamp(1.0, f64::from(crate::sessions::MAX_SESSIONS)) as u8
			});
		let job = crate::lsp::analysis::Job {
			uri: doc.uri.clone(),
			version: doc.version,
			line: doc.line.clone(),
			sessions,
			token: token.clone(),
			progress: self.progress_supported,
			passing: self.settings.passing,
		};
		if self.progress_supported {
			self.request(
				"window/workDoneProgress/create",
				serde_json::json!({"token": token}),
			);
		}
		self.runner.start(job);
		serde_json::json!(proto::Accepted {
			accepted: true,
			token,
			reason: None,
		})
	}

	fn respond(&self, response: Response) {
		let _ = self.sender.send(Message::Response(response));
	}

	fn request(&mut self, method: &str, params: impl serde::Serialize) {
		self.next_request_id += 1;
		let _ = self.sender.send(Message::Request(Request::new(
			RequestId::from(self.next_request_id),
			method.to_string(),
			params,
		)));
	}

	fn notify(&self, method: &str, params: impl serde::Serialize) {
		proto::notify(&self.sender, method, params);
	}
}

fn format(doc: &Document) -> Vec<TextEdit> {
	let Some(model) = &doc.model else {
		return Vec::new();
	};
	let mut text = crate::pretty::pretty_model(model).replace("\r\n", "\n");
	if doc.text().contains("\r\n") {
		text = text.replace('\n', "\r\n");
	}
	if text == doc.text() {
		return Vec::new();
	}
	vec![TextEdit {
		range: lsp_types::Range::new(lsp_types::Position::new(0, 0), doc.line.end()),
		new_text: text,
	}]
}

fn workspace_edit(doc: &Document, edits: Vec<TextEdit>) -> lsp_types::WorkspaceEdit {
	lsp_types::WorkspaceEdit {
		changes: Some(HashMap::from([(doc.uri.clone(), edits)])),
		..Default::default()
	}
}

fn code_lenses(doc: &Document) -> Vec<lsp_types::CodeLens> {
	let Some(first) = doc.model.as_ref().and_then(|m| m.queries.first()) else {
		return Vec::new();
	};
	vec![lsp_types::CodeLens {
		range: doc
			.line
			.range(crate::types::Span::new(first.span.start, first.span.start)),
		command: Some(lsp_types::Command {
			title: "Run attacker analysis".to_string(),
			command: "verifpal.analyze".to_string(),
			arguments: Some(vec![serde_json::json!({"uri": doc.uri.as_str()})]),
		}),
		data: None,
	}]
}

fn code_actions(doc: &Document, params: &CodeActionParams) -> Vec<lsp_types::CodeActionOrCommand> {
	let wanted = params.context.only.as_ref().is_none_or(|only| {
		only.iter().any(|kind| {
			kind.as_str().is_empty()
				|| lsp_types::CodeActionKind::QUICKFIX
					.as_str()
					.starts_with(kind.as_str())
		})
	});
	let needs_queries = params
		.context
		.diagnostics
		.iter()
		.any(|d| d.message.contains("no `queries` block"));
	if !wanted || !needs_queries {
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
			edit: Some(workspace_edit(doc, vec![edit])),
			..Default::default()
		},
	)]
}

fn diagram(doc: &Document) -> Option<proto::DiagramResult> {
	let model = doc.model.as_ref()?;
	Some(proto::DiagramResult {
		mermaid: crate::pretty::mermaid_of(model),
		readable: crate::pretty::pretty_diagram(model),
	})
}

fn declined(reason: String) -> serde_json::Value {
	serde_json::json!(proto::Accepted {
		accepted: false,
		token: String::new(),
		reason: Some(reason),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use lsp_types::{ClientCapabilities, GeneralClientCapabilities};

	fn start(
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

	fn stop(client: Connection, handle: std::thread::JoinHandle<()>) {
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

	fn open(client: &Connection, uri: &str, text: &str) {
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

	fn await_notification(client: &Connection, method: &str) -> serde_json::Value {
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

	fn request(
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
		assert!(server.docs.contains_key("file:///closed.vp"));
		assert!(server.dirty.contains("file:///closed.vp"));
		server.on_notification(Notification::new(
			"textDocument/didClose".to_string(),
			serde_json::json!({"textDocument": {"uri": "file:///closed.vp"}}),
		));
		assert!(!server.docs.contains_key("file:///closed.vp"));
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
			generates ee_m, ee_n\n\
			ee_e = AEAD_ENC(ee_k, ee_n, ee_m, nil)\n\
			]\n\
			Bob -> Alice: ee_gb, ee_n, ee_e\n\
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

	fn open_here(server: &mut Server, uri: &str, text: &str) {
		server.on_notification(Notification::new(
			"textDocument/didOpen".to_string(),
			serde_json::json!({
				"textDocument": {
					"uri": uri,
					"languageId": "verifpal",
					"version": 1,
					"text": text,
				}
			}),
		));
	}

	fn analyze_params(argument: serde_json::Value) -> ExecuteCommandParams {
		ExecuteCommandParams {
			command: "verifpal.analyze".to_string(),
			arguments: vec![argument],
			work_done_progress_params: Default::default(),
		}
	}

	fn await_report_here(receiver: &crossbeam_channel::Receiver<Message>) -> serde_json::Value {
		loop {
			match receiver
				.recv_timeout(std::time::Duration::from_secs(60))
				.expect("the worker reports")
			{
				Message::Notification(n) if n.method == "verifpal/analysisReport" => {
					return n.params;
				}
				_ => continue,
			}
		}
	}

	#[test]
	fn a_tick_after_an_analysis_keeps_its_verdicts() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		open_here(&mut server, "file:///tick.vp", VALID);
		let accepted = server.command(&analyze_params(
			serde_json::json!({"uri": "file:///tick.vp", "sessions": 1}),
		));
		assert_eq!(accepted["accepted"], true, "{accepted}");
		let report = await_report_here(&receiver);
		assert_eq!(report["token"], accepted["token"], "{report}");
		server.on_tick();
		let Message::Notification(published) = receiver.recv().expect("the tick publishes") else {
			panic!("expected a notification");
		};
		assert_eq!(published.method, "textDocument/publishDiagnostics");
		let diagnostics = published.params["diagnostics"].as_array().expect("array");
		assert_eq!(diagnostics.len(), 1, "{}", published.params);
		assert_eq!(diagnostics[0]["code"], "confidentiality");
	}

	#[test]
	fn a_refresh_is_not_requested_from_a_client_that_did_not_offer_it() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		open_here(&mut server, "file:///norefresh.vp", VALID);
		server.on_notification(Notification::new(
			"workspace/didChangeConfiguration".to_string(),
			serde_json::json!({"settings": {"verifpal": {
				"codeLens": false,
				"inlayHints": {"argumentNames": false},
			}}}),
		));
		let requests: Vec<String> = receiver
			.try_iter()
			.filter_map(|message| match message {
				Message::Request(r) => Some(r.method),
				_ => None,
			})
			.collect();
		assert!(
			requests.is_empty(),
			"a client that advertised neither refreshSupport must not be sent a refresh \
			 request it will answer with MethodNotFound: {requests:?}"
		);
	}

	#[test]
	fn settings_turn_features_off_and_ask_the_client_to_refresh() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		server.inlay_refresh = true;
		server.code_lens_refresh = true;
		open_here(&mut server, "file:///cfg.vp", VALID);
		assert_eq!(code_lenses(&server.docs["file:///cfg.vp"]).len(), 1);
		server.on_notification(Notification::new(
			"workspace/didChangeConfiguration".to_string(),
			serde_json::json!({"settings": {"verifpal": {
				"codeLens": false,
				"inlayHints": {"argumentNames": false},
				"diagnostics": {"passing": false},
				"validateOnType": false,
			}}}),
		));
		assert_eq!(
			server.settings,
			Settings {
				validate_on_type: false,
				passing: false,
				inlay_hints: false,
				code_lens: false,
			}
		);
		server.on_request(Request::new(
			RequestId::from(8),
			"textDocument/codeLens".to_string(),
			serde_json::json!({"textDocument": {"uri": "file:///cfg.vp"}}),
		));
		server.on_request(Request::new(
			RequestId::from(7),
			"textDocument/inlayHint".to_string(),
			serde_json::json!({
				"textDocument": {"uri": "file:///cfg.vp"},
				"range": {"start": {"line": 0, "character": 0}, "end": {"line": 30, "character": 0}},
			}),
		));
		let mut refreshes = Vec::new();
		let mut hints = None;
		let mut lenses = None;
		for message in receiver.try_iter() {
			match message {
				Message::Request(r) => refreshes.push(r.method),
				Message::Response(r) if r.id == RequestId::from(7) => {
					hints = r.response_result.ok();
				}
				Message::Response(r) if r.id == RequestId::from(8) => {
					lenses = r.response_result.ok();
				}
				_ => {}
			}
		}
		assert_eq!(hints, Some(serde_json::json!([])));
		assert_eq!(lenses, Some(serde_json::json!([])));
		assert!(
			refreshes.contains(&"workspace/inlayHint/refresh".to_string()),
			"{refreshes:?}"
		);
		assert!(
			refreshes.contains(&"workspace/codeLens/refresh".to_string()),
			"{refreshes:?}"
		);
		server.on_notification(Notification::new(
			"workspace/didChangeConfiguration".to_string(),
			serde_json::json!({"settings": {"verifpal": {"codeLens": true}}}),
		));
		assert!(server.settings.code_lens);
		assert!(!server.settings.inlay_hints);
	}

	#[test]
	fn with_validation_on_save_only_a_change_waits_for_the_save() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		open_here(&mut server, "file:///save.vp", VALID);
		server.on_tick();
		server.on_notification(Notification::new(
			"workspace/didChangeConfiguration".to_string(),
			serde_json::json!({"settings": {"verifpal": {"validateOnType": false}}}),
		));
		let _ = receiver.try_iter().count();
		server.on_notification(Notification::new(
			"textDocument/didChange".to_string(),
			serde_json::json!({
				"textDocument": {"uri": "file:///save.vp", "version": 2},
				"contentChanges": [{"text": "attacker[active]\nprincipal Alice[\n"}],
			}),
		));
		server.on_tick();
		assert!(
			receiver.try_recv().is_err(),
			"nothing is published while the user types"
		);
		server.on_notification(Notification::new(
			"textDocument/didSave".to_string(),
			serde_json::json!({"textDocument": {"uri": "file:///save.vp"}}),
		));
		server.on_tick();
		let Message::Notification(published) = receiver.recv().expect("the save publishes") else {
			panic!("expected a notification");
		};
		assert_eq!(published.method, "textDocument/publishDiagnostics");
		assert_eq!(published.params["version"], 2);
		assert_eq!(
			published.params["diagnostics"]
				.as_array()
				.expect("array")
				.len(),
			1
		);
	}

	#[test]
	fn a_decline_says_why_and_a_fractional_session_count_is_rounded() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		let declined = server.command(&analyze_params(
			serde_json::json!({"uri": "file:///nope.vp"}),
		));
		assert_eq!(declined["accepted"], false);
		assert!(
			declined["reason"]
				.as_str()
				.is_some_and(|r| r.contains("not an open document")),
			"{declined}"
		);
		let malformed = server.command(&analyze_params(serde_json::json!({"sessions": 1})));
		assert!(
			malformed["reason"]
				.as_str()
				.is_some_and(|r| r.contains("malformed")),
			"{malformed}"
		);
		open_here(&mut server, "file:///frac.vp", VALID);
		let accepted = server.command(&analyze_params(
			serde_json::json!({"uri": "file:///frac.vp", "sessions": 1.4}),
		));
		assert_eq!(accepted["accepted"], true, "{accepted}");
		let report = await_report_here(&receiver);
		assert_eq!(report["sessions"], 1, "{report}");
	}

	#[test]
	fn formatting_keeps_crlf_line_endings_and_leaves_a_formatted_file_alone() {
		let (sender, _receiver) = crossbeam_channel::unbounded();
		let mut server = Server::new(sender, PositionEncodingKind::UTF8);
		let model = crate::parser::parse_string("crlf.vp", VALID).expect("parses");
		let canonical = crate::pretty::pretty_model(&model).replace('\n', "\r\n");
		open_here(&mut server, "file:///crlf.vp", &canonical);
		assert!(format(&server.docs["file:///crlf.vp"]).is_empty());
		open_here(&mut server, "file:///ugly.vp", &VALID.replace('\n', "\r\n"));
		let edits = format(&server.docs["file:///ugly.vp"]);
		assert_eq!(edits.len(), 1);
		assert!(edits[0].new_text.contains("\r\n"));
		assert!(!edits[0].new_text.contains("\r\r"));
		assert!(
			!edits[0].new_text.contains("\n\n\n"),
			"{}",
			edits[0].new_text
		);
	}

	fn analyze_and_collect(caps: ClientCapabilities) -> Vec<String> {
		let (client, handle, _) = start(caps);
		open(&client, "file:///prog.vp", VALID);
		client
			.sender
			.send(Message::Request(Request::new(
				RequestId::from(1),
				"workspace/executeCommand".to_string(),
				serde_json::json!({
					"command": "verifpal.analyze",
					"arguments": [{"uri": "file:///prog.vp", "sessions": 1}],
				}),
			)))
			.expect("sends the request");
		let mut order = Vec::new();
		loop {
			match client
				.receiver
				.recv_timeout(std::time::Duration::from_secs(60))
				.expect("messages keep coming until the report")
			{
				Message::Request(r) => {
					order.push(r.method.clone());
					client
						.sender
						.send(Message::Response(Response::new_ok(
							r.id,
							serde_json::Value::Null,
						)))
						.expect("responds");
				}
				Message::Notification(n) => {
					let done = n.method == "verifpal/analysisReport";
					order.push(n.method);
					if done {
						break;
					}
				}
				Message::Response(_) => order.push("response".to_string()),
			}
		}
		stop(client, handle);
		order
	}

	#[test]
	fn a_progress_token_is_created_before_it_is_reported() {
		let caps = ClientCapabilities {
			window: Some(lsp_types::WindowClientCapabilities {
				work_done_progress: Some(true),
				..Default::default()
			}),
			..Default::default()
		};
		let order = analyze_and_collect(caps);
		let create = order
			.iter()
			.position(|m| m == "window/workDoneProgress/create")
			.expect("the token is created");
		let begin = order
			.iter()
			.position(|m| m == "$/progress")
			.expect("progress is reported");
		assert!(create < begin, "{order:?}");
	}

	#[test]
	fn a_client_without_progress_support_hears_no_progress() {
		let order = analyze_and_collect(ClientCapabilities::default());
		assert!(!order.iter().any(|m| m == "$/progress"), "{order:?}");
		assert!(
			!order.iter().any(|m| m == "window/workDoneProgress/create"),
			"{order:?}"
		);
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
