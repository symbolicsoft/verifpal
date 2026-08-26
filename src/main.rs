/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use clap::{Parser, Subcommand, ValueEnum};
use verifpal::{
	ColorChoice, InfoLevel, Run, SATURATE_MAX, Verbosity, VerifyReport, diagram, html_report,
	info_banner, info_message, pretty_print, saturation_sessions, set_color_choice, set_verbosity,
	update_check_report, update_check_start, verify_report_with_source_opts,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const EXIT_ERROR: i32 = 1;
const EXIT_ATTACK: i32 = 2;

#[derive(Parser)]
#[command(
	name = "verifpal",
	version = VERSION,
	about = format!("Verifpal {} - https://verifpal.com", VERSION),
	long_about = "Verifpal is a symbolic formal verification tool for cryptographic \
	              protocols. You describe a protocol in the Verifpal language: the \
	              principals taking part, the values they know, generate and compute, \
	              and the messages they send one another. You then state security \
	              queries about it, and Verifpal searches for an attack that breaks \
	              them, printing the trace of any attack it finds.\n\n\
	              Analysis is bounded. Every principal is analyzed as running two \
	              concurrent sessions of the protocol by default, so a query reported \
	              as holding means that no attack was found within that bound, not \
	              that no attack exists. The engine is sound but incomplete: every \
	              attack it reports is genuine, and it may still miss attacks it \
	              cannot reach.\n\n\
	              The language itself is documented in the Verifpal User Manual, at \
	              https://verifpal.com.\n\n\
	              Exit status is 0 on success, 1 if a model could not be read, parsed \
	              or analyzed, and 2 if an attack was found and 'verify \
	              --fail-on-attack' was given.",
	after_long_help = "Examples:\n  \
	                   verifpal verify protocol.vp\n  \
	                   verifpal verify protocol.vp --sessions 3 --fail-on-attack\n  \
	                   verifpal verify protocol.vp --format html > report.html\n  \
	                   verifpal pretty protocol.vp --write\n  \
	                   verifpal diagram protocol.vp\n\n\
	                   Run 'verifpal help <COMMAND>' for the full documentation of a \
	                   command.",
	max_term_width = 100
)]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorArg {
	Auto,
	Always,
	Never,
}

impl From<ColorArg> for ColorChoice {
	fn from(arg: ColorArg) -> Self {
		match arg {
			ColorArg::Auto => ColorChoice::Auto,
			ColorArg::Always => ColorChoice::Always,
			ColorArg::Never => ColorChoice::Never,
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
	Text,
	Json,
	Html,
}

#[derive(Subcommand)]
enum Commands {
	#[command(
		arg_required_else_help = true,
		about = "Analyze protocol models and report attacks against their queries",
		long_about = "Analyze one or more Verifpal models and report the verdict of \
		              every query in each of them.\n\n\
		              For each model, Verifpal parses the file, validates it, and then \
		              runs the analysis its 'attacker[passive]' or 'attacker[active]' \
		              declaration asks for. A passive attacker only observes the wire \
		              and deduces what it can from what it sees; an active attacker \
		              may additionally substitute the values carried by any message \
		              not written inside guard brackets. Every query is then reported \
		              as holding or as broken, and each broken query is printed \
		              together with a minimized attack trace: the wire substitutions \
		              the attacker made, the cryptographic checks it defeated, and the \
		              step-by-step derivation by which it obtained the value in \
		              question.\n\n\
		              Several models may be given at once. They are analyzed in order \
		              and independently of one another, and one of them failing to \
		              parse does not stop the rest.\n\n\
		              Finding an attack is a result and not an error, so the exit \
		              status is 0 even when queries are broken, unless \
		              --fail-on-attack says otherwise.",
		after_long_help = "The environment variable VERIFPAL_SOLVE_DEBUG=1 logs every \
		                   substitution the active-attacker search proposed to stderr, \
		                   including the ones it rejected. It is the first thing to \
		                   reach for when an active-attacker verdict is surprising."
	)]
	Verify {
		#[arg(
			required = true,
			num_args = 1..,
			value_name = "MODELS",
			help = "Paths of the .vp model files to analyze",
			long_help = "One or more paths to Verifpal model files. A model file's \
			             name must end in '.vp' and be at most 64 characters long.\n\n\
			             Models are analyzed in the order given and independently of \
			             one another, with their text reports separated by a blank \
			             line. If one of them cannot be read, parsed or validated, the \
			             error is printed and the remaining models are analyzed \
			             anyway; the run then ends with exit status 1. When more than \
			             one model is given, --result-code prefixes each code with the \
			             path of the model it belongs to."
		)]
		models: Vec<String>,
		#[arg(
			long,
			default_value_t = false,
			help = "Print the compact one-letter-per-query result code",
			long_help = "Print the verdicts as a compact result code, and suppress the \
			             banner.\n\n\
			             The code carries one letter and one digit per query, in the \
			             order the queries appear in the model: 'c' for \
			             confidentiality, 'a' for authentication, 'f' for freshness, \
			             'u' for unlinkability and 'e' for equivalence, each followed \
			             by '0' if the query holds or '1' if an attack was found. \
			             'c1a0', for instance, says that the model's first query, a \
			             confidentiality one, was broken, while its second, an \
			             authentication one, held.\n\n\
			             The rest of the analysis is still printed and the code is the \
			             last line of output, so 'verifpal verify model.vp \
			             --result-code | tail -1' gets the code by itself; adding \
			             --quiet silences everything else instead. When more than one \
			             model is given, each line is prefixed with that model's path.\n\n\
			             This is the form Verifpal's own test suite uses to pin the \
			             expected verdicts of a model, and the most convenient one to \
			             compare two runs against each other."
		)]
		result_code: bool,
		#[arg(
			long,
			default_value_t = 2,
			value_parser = clap::value_parser!(u8).range(1..=16),
			help = "Concurrent sessions to analyze per principal [1-16]",
			long_help = "Analyze every principal as running this many concurrent \
			             sessions of the protocol, rather than the default of two.\n\n\
			             Verifpal implements this by rewriting the model before \
			             analysis: each principal and each message block is replicated \
			             the given number of times, with generated and computed values \
			             freshened per session while values a principal merely knows \
			             stay shared between them. The expanded model is one you could \
			             have written by hand, so nothing about the analysis itself \
			             changes; the attacker simply gains the ability to carry values \
			             between concurrent runs.\n\n\
			             That is what makes replay attacks reachable. Authentication \
			             queries in Verifpal ask for injective agreement, so a message \
			             the attacker lifts out of one session and delivers into \
			             another breaks one even though nothing was forged. At \
			             --sessions 1 there is no sibling run to replay from, and no \
			             such attack can be reported at all.\n\n\
			             The count is also the bound the verdicts are relative to. \
			             Raising it strengthens a query that still holds and can only \
			             ever reveal more attacks, never fewer, but it is expensive: \
			             cost grows steeply with the number of replicated principals. \
			             Start at the default and raise it deliberately, or let \
			             --saturate find the point at which the verdicts stop moving. \
			             Accepted values run from 1 to 16."
		)]
		sessions: u8,
		#[arg(
			long,
			default_value_t = false,
			help = "Exit with status 2 if any query was broken",
			long_help = "Exit with status 2 when an attack was found against any query \
			             in any of the given models, instead of the usual status 0.\n\n\
			             By default a discovered attack is a normal result rather than \
			             a failure, because for most models an attack is precisely the \
			             answer the user was looking for, and Verifpal reports it and \
			             exits successfully. This flag is for scripting and continuous \
			             integration, where a model is expected to verify and a newly \
			             appearing attack should fail the build.\n\n\
			             Status 1 continues to mean that the run itself failed, on a \
			             file that could not be read, parsed or validated, and takes \
			             precedence over status 2."
		)]
		fail_on_attack: bool,
		#[arg(
			long,
			default_value_t = false,
			help = "Replace the model's queries with a generated set",
			long_help = "Discard the model's own queries block and analyze a generated \
			             set of queries in its place.\n\n\
			             Verifpal derives a confidentiality query for every secret in \
			             the model that actually takes part in the protocol, meaning \
			             everything a principal generates and everything it knows \
			             privately or as a password; an authentication query for every \
			             sender and recipient pair where the recipient both receives a \
			             value and goes on to use it inside a primitive; and a \
			             freshness query for every value that travels over the wire and \
			             is used somewhere. The model's own queries block must still be \
			             present and valid, since the model is parsed and validated \
			             before its queries are replaced.\n\n\
			             This asks what a model gives you rather than checking what you \
			             expected of it, which makes it useful for a first look at an \
			             unfamiliar protocol, for turning up a property you had not \
			             thought to write down, and for putting two models on equal \
			             footing by asking exactly the same questions of both. It does \
			             not replace a hand-written queries block, which remains the \
			             only way to state a property the generator does not cover: \
			             unlinkability, equivalence, and any query carrying a \
			             precondition option."
		)]
		auto_queries: bool,
		#[arg(
			long,
			default_value_t = false,
			help = "Raise the session count until the verdicts stop changing",
			long_help = "Find the session count at which the model's verdicts \
			             stabilize, and report the analysis from there.\n\n\
			             Verifpal analyzes the model at one session, then at two, and \
			             so on up to four, stopping at the first count whose result \
			             code is identical to the previous count's. That count is the \
			             one whose analysis is reported, and a line saying that the \
			             verdicts stopped changing there is printed before it. Since \
			             an attack \
			             requiring k concurrent runs first appears at k sessions and \
			             persists above it, a code that stopped changing is evidence, \
			             though not proof, that the model has stopped yielding new \
			             attacks.\n\n\
			             This overrides --sessions. It costs the sum of every analysis \
			             it runs and so is considerably slower than a single one; the \
			             intermediate runs print nothing.\n\n\
			             Giving the attacker another session can only ever give it more \
			             to work with, so an attack found at a lower count must still \
			             be found at a higher one. If one disappears, that is a bug in \
			             Verifpal and not a fact about the protocol, and a warning \
			             saying so is printed on stderr."
		)]
		saturate: bool,
		#[arg(
			long,
			value_enum,
			default_value_t = FormatArg::Text,
			help = "Report as text, JSON or a self-contained HTML page",
			long_help = "Choose how the analysis is reported.\n\n\
			             'text', the default, is the human-readable report printed as \
			             the analysis proceeds: the banner, the progress of the search, \
			             and each query's verdict followed by the trace of any attack \
			             against it.\n\n\
			             'json' prints one machine-readable object describing the whole \
			             run to stdout: every model with its source, every query with \
			             its verdict and position in the file, and every attack trace \
			             as structured steps rather than as prose. This is what the \
			             editor integrations consume, and what to parse if you are \
			             building something on top of Verifpal.\n\n\
			             'html' prints a single self-contained page to stdout, with no \
			             external scripts, styles or images, so redirecting it into a \
			             file yields a report that can be opened or sent on as it \
			             stands. It carries a sequence diagram of the protocol, the \
			             model source syntax-highlighted, and a diagram of each attack \
			             beside its trace.\n\n\
			             Both structured formats suppress the ordinary progress output \
			             and disable color, neither of which belongs in the middle of a \
			             document. A model that fails is reported inside the document \
			             rather than on stderr, so nothing is lost by redirecting \
			             stdout alone."
		)]
		format: FormatArg,
		#[arg(
			short,
			long,
			default_value_t = false,
			conflicts_with = "verbose",
			help = "Print query verdicts and warnings only",
			long_help = "Print only what the analysis concluded: each query's verdict, \
			             each attack trace, and any warning. The banner, the live \
			             progress indicator and the running commentary about what is \
			             being analyzed are all suppressed.\n\n\
			             Together with --result-code this silences everything but the \
			             code itself, which is the form to use in a script. Conflicts \
			             with --verbose."
		)]
		quiet: bool,
		#[arg(
			short,
			long,
			default_value_t = false,
			help = "Print every deduction and analysis step",
			long_help = "Print the individual steps the engine takes, which the normal \
			             report leaves out: every value the attacker deduced along with \
			             the rule that yielded it, and every principal and query being \
			             analyzed as it is reached.\n\n\
			             This is the flag to reach for when a verdict is surprising and \
			             you want to see the knowledge the attacker accumulated on the \
			             way to it. It is verbose in proportion to the model, and on a \
			             large one the deduction log is capped after a thousand \
			             messages, with a line saying so; the analysis itself continues \
			             in full. Conflicts with --quiet."
		)]
		verbose: bool,
		#[arg(
			long,
			value_enum,
			default_value_t = ColorArg::Auto,
			help = "When to color the output: auto, always or never",
			long_help = "Control whether the report is printed with ANSI color and \
			             styling.\n\n\
			             'auto', the default, colors the output when stdout is a \
			             terminal and leaves it plain when it is redirected into a file \
			             or a pipe. It also honors the surrounding environment: NO_COLOR \
			             or TERM=dumb turns color off, and CLICOLOR_FORCE or FORCE_COLOR \
			             turns it on.\n\n\
			             'always' colors the output whatever stdout is, which is what \
			             you want when piping into a pager that understands escape \
			             sequences. 'never' disables color outright.\n\n\
			             The JSON and HTML reports are never colored, whatever this is \
			             set to."
		)]
		color: ColorArg,
	},
	#[command(
		arg_required_else_help = true,
		about = "Reformat models into the canonical Verifpal style",
		long_about = "Print each model back in Verifpal's canonical formatting: one \
		              canonical spelling for every declaration, message and query, \
		              uniform indentation and spacing, and the blocks laid out the way \
		              the User Manual writes them.\n\n\
		              Comments are preserved and travel with the construct they were \
		              written against, so formatting a file does not lose the prose in \
		              it. The exceptions are the few positions where a comment cannot \
		              be placed again unambiguously, and which are therefore dropped: \
		              inside a primitive's argument list, inside the brackets of an \
		              attacker or phase declaration, and inside the inner brackets of a \
		              query option.\n\n\
		              Formatting only requires that the model parse. A model that \
		              parses but fails validation is formatted all the same, since \
		              refusing would mean refusing at exactly the moment the user is \
		              fixing the error.\n\n\
		              By default the formatted model goes to stdout and the file is \
		              left alone. --write edits files in place, and --check reports \
		              what would change without touching anything."
	)]
	Pretty {
		#[arg(
			required = true,
			num_args = 1..,
			value_name = "MODELS",
			help = "Paths of the .vp model files to format",
			long_help = "One or more paths to Verifpal model files. Each is formatted \
			             independently, and unless --write or --check is given, each is \
			             printed to stdout one after another, so redirecting the output \
			             of several models at once concatenates them into a file that \
			             is no longer a valid model.\n\n\
			             A file that cannot be read or parsed is reported on stderr and \
			             skipped, and the run ends with exit status 1."
		)]
		models: Vec<String>,
		#[arg(
			short,
			long,
			default_value_t = false,
			conflicts_with = "check",
			help = "Rewrite the files in place instead of printing",
			long_help = "Write the formatted model back over the file it came from, \
			             rather than printing it to stdout.\n\n\
			             Files already in canonical form are left untouched, and the \
			             path of every file that was rewritten is printed. The output \
			             is therefore a list of what changed, and silence means nothing \
			             needed changing. Conflicts with --check."
		)]
		write: bool,
		#[arg(
			long,
			default_value_t = false,
			help = "Report which files are not canonically formatted",
			long_help = "Report which files are not in canonical form, without \
			             modifying any of them. The path of every file that would \
			             change is printed, and the exit status is 1 if there was at \
			             least one; nothing else goes to stdout.\n\n\
			             This is the form for continuous integration or a pre-commit \
			             hook, to keep a collection of models consistently formatted. \
			             Conflicts with --write."
		)]
		check: bool,
	},
	#[command(
		arg_required_else_help = true,
		about = "Emit a Mermaid sequence diagram of a model",
		long_about = "Print a Mermaid sequence diagram describing the model, to \
		              stdout.\n\n\
		              Every principal becomes a participant; every message between two \
		              principals becomes an arrow labeled with the values it carries, \
		              guarded ones in the brackets the model wrote them with; \
		              everything a principal knows, generates or computes becomes a \
		              note over that principal; and every phase boundary becomes a note \
		              marking where in the protocol it falls.\n\n\
		              The output is Mermaid source rather than a picture. Paste it into \
		              a Mermaid renderer, into a Markdown file on a host that renders \
		              Mermaid, or into the Mermaid live editor to see the diagram. Only \
		              the structure of the protocol is drawn: queries are not, and \
		              neither is anything about an analysis, since none is run. For a \
		              rendered diagram of the protocol together with the attacks found \
		              against it, use 'verify --format html' instead.\n\n\
		              The model only needs to parse; it is neither validated nor \
		              verified."
	)]
	Diagram {
		#[arg(
			value_name = "MODEL",
			help = "Path of the .vp model file to diagram",
			long_help = "The path of the Verifpal model file to draw. Unlike verify \
			             and pretty, this command takes exactly one model, because its \
			             output is a single diagram and two of them concatenated would \
			             not be valid Mermaid source."
		)]
		model: String,
		#[arg(
			long,
			value_enum,
			default_value_t = ColorArg::Auto,
			help = "When to color the output: auto, always or never",
			long_help = "Control whether ANSI color and styling are used.\n\n\
			             The Mermaid source itself is never colored, being \
			             machine-readable output meant to be piped into a renderer, so \
			             this only governs how a failure to read or parse the model is \
			             presented. 'auto', the default, styles it when the terminal \
			             accepts styling and leaves it plain when the output is \
			             redirected, honoring NO_COLOR, TERM=dumb, CLICOLOR_FORCE and \
			             FORCE_COLOR as the verify command does. 'always' styles it \
			             regardless, and 'never' disables styling outright."
		)]
		color: ColorArg,
	},
	#[command(
		about = "Print version, homepage and contributor credits",
		long_about = "Print the Verifpal banner, being the version you are running and \
		              the project's homepage, followed by its author and by the people \
		              who have contributed meaningful suggestions, bug reports, ideas \
		              or discussion to it over the years.\n\n\
		              This command also performs the same release check that verify \
		              does, printing one line on stderr if a newer version of Verifpal \
		              has been tagged. It takes no options and reads no files."
	)]
	About,
	#[command(
		name = "lsp",
		about = "Run the Verifpal language server over stdio",
		long_about = "Run Verifpal as a Language Server Protocol server, speaking LSP \
		              over stdin and stdout.\n\n\
		              This is not meant to be run by hand. It is what an editor \
		              extension launches in the background, and typing it at a shell \
		              leaves a process waiting for JSON-RPC traffic that will never \
		              arrive; interrupt it to get your terminal back.\n\n\
		              The server reparses and revalidates each open document as it is \
		              edited, publishing diagnostics for parse and validation errors, \
		              and runs a full analysis on a debounce, publishing its result so \
		              that query verdicts and attack traces appear against the model as \
		              you write it. It also serves hover documentation for every \
		              primitive and language construct, go-to-definition and \
		              find-references over constants and principals, document symbols \
		              and folding ranges, completion and signature help, semantic \
		              tokens for highlighting, inlay hints, formatting, and rename.\n\n\
		              Documents live only in memory, keyed by the URI the editor gave \
		              them: the server never reads or writes the filesystem, so an \
		              unsaved buffer is analyzed exactly as it currently stands. \
		              Editor integrations built on it are available for Visual Studio \
		              Code and for Neovim."
	)]
	Lsp {
		#[arg(
			long,
			default_value_t = false,
			help = "Accepted for compatibility; stdio is the only transport",
			long_help = "Accepted and ignored.\n\n\
			             Language server clients conventionally pass --stdio to select \
			             the transport, and Verifpal accepts it so that such a client \
			             works without special-casing. Stdio is the only transport the \
			             server speaks, however, and it behaves identically with or \
			             without the flag; there is no socket or named-pipe mode."
		)]
		stdio: bool,
	},
}

fn verify_verbosity(structured: bool, result_code: bool, quiet: bool, verbose: bool) -> Verbosity {
	if structured || (result_code && quiet) {
		return Verbosity::Silent;
	}
	if verbose {
		return Verbosity::Verbose;
	}
	if quiet {
		return Verbosity::Quiet;
	}
	Verbosity::Normal
}

#[allow(clippy::too_many_arguments)]
fn run_verify(
	models: Vec<String>,
	result_code: bool,
	sessions: u8,
	fail_on_attack: bool,
	auto_queries: bool,
	saturate: bool,
	format: FormatArg,
	quiet: bool,
	verbose: bool,
	color: ColorArg,
) -> i32 {
	let structured = format != FormatArg::Text;
	set_color_choice(if structured {
		ColorChoice::Never
	} else {
		color.into()
	});
	set_verbosity(verify_verbosity(structured, result_code, quiet, verbose));

	let update_check = update_check_start(VERSION);
	if !result_code && !structured {
		info_banner(VERSION);
	}

	let single = models.len() == 1;
	let mut outcomes: Vec<(String, Result<VerifyReport, String>)> = Vec::new();
	let mut sources: Vec<String> = Vec::new();
	let mut had_error = false;
	let mut had_attack = false;

	for (index, model) in models.iter().enumerate() {
		if index > 0 && !structured && !result_code {
			println!();
		}
		let mut effective = sessions;
		if saturate {
			match saturation_sessions(model, SATURATE_MAX, auto_queries) {
				Ok((point, regressed)) => {
					effective = point;
					if !structured && !result_code {
						if regressed {
							eprintln!(
								"warning: an attack found at a lower session count \
								 disappeared at a higher one; that is an engine bug, \
								 not a protocol result"
							);
						}
						info_message(
							&format!(
								"Verdicts stopped changing at {} session{}; analyzing there.",
								point,
								if point == 1 { "" } else { "s" }
							),
							InfoLevel::Info,
							false,
						);
					}
				}
				Err(e) => {
					had_error = true;
					if !structured {
						eprintln!("{}", e);
					}
					outcomes.push((model.clone(), Err(e.to_string())));
					sources.push(String::new());
					continue;
				}
			}
		}
		match verify_report_with_source_opts(model, effective, auto_queries) {
			Ok((report, source)) => {
				had_attack |= report.results.iter().any(|r| r.resolved);
				if result_code {
					if single {
						println!("{}", report.code);
					} else {
						println!("{} {}", model, report.code);
					}
				}
				outcomes.push((model.clone(), Ok(report)));
				sources.push(source);
			}
			Err(e) => {
				had_error = true;
				let text = e.to_string();
				if !structured {
					eprintln!("{}", text);
				}
				outcomes.push((model.clone(), Err(text)));
				sources.push(String::new());
			}
		}
	}

	match format {
		FormatArg::Text => {}
		FormatArg::Json => {
			let run = Run::of(VERSION, &outcomes, &sources);
			match serde_json::to_string(&run) {
				Ok(text) => println!("{}", text),
				Err(e) => {
					eprintln!("could not serialize the report: {}", e);
					return EXIT_ERROR;
				}
			}
		}
		FormatArg::Html => {
			let run = Run::of(VERSION, &outcomes, &sources);
			print!("{}", html_report(&run, &sources));
		}
	}
	update_check_report(&update_check);

	if had_error {
		return EXIT_ERROR;
	}
	if fail_on_attack && had_attack {
		return EXIT_ATTACK;
	}
	0
}

fn run_pretty(models: Vec<String>, write: bool, check: bool) -> i32 {
	let mut changed: Vec<String> = Vec::new();
	let mut status = 0;
	for model in &models {
		let output = match pretty_print(model) {
			Ok(output) => output,
			Err(e) => {
				eprintln!("{}", e);
				status = EXIT_ERROR;
				continue;
			}
		};
		if !write && !check {
			print!("{}", output);
			continue;
		}
		let current = std::fs::read_to_string(model).unwrap_or_default();
		if current == output {
			continue;
		}
		changed.push(model.clone());
		if write && let Err(e) = std::fs::write(model, &output) {
			eprintln!("{}: {}", model, e);
			status = EXIT_ERROR;
		}
	}
	for model in &changed {
		println!("{}", model);
	}
	if check && !changed.is_empty() {
		return EXIT_ERROR;
	}
	status
}

fn main() {
	let cli = Cli::parse();
	let status = match cli.command {
		Commands::Verify {
			models,
			result_code,
			sessions,
			fail_on_attack,
			auto_queries,
			saturate,
			format,
			quiet,
			verbose,
			color,
		} => run_verify(
			models,
			result_code,
			sessions,
			fail_on_attack,
			auto_queries,
			saturate,
			format,
			quiet,
			verbose,
			color,
		),
		Commands::Pretty {
			models,
			write,
			check,
		} => run_pretty(models, write, check),
		Commands::Lsp { stdio: _ } => match verifpal::lsp_run() {
			Ok(()) => 0,
			Err(e) => {
				eprintln!("{}", e);
				EXIT_ERROR
			}
		},
		Commands::Diagram { model, color } => {
			set_color_choice(color.into());
			match diagram(&model) {
				Ok(output) => {
					print!("{}", output);
					0
				}
				Err(e) => {
					eprintln!("{}", e);
					EXIT_ERROR
				}
			}
		}
		Commands::About => {
			let update_check = update_check_start(VERSION);
			info_banner(VERSION);
			println!("Verifpal is authored by Nadim Kobeissi.");
			println!("The following individuals have contributed");
			println!("meaningful suggestions, bug reports, ideas");
			println!("or discussion to the Verifpal project:");
			println!();
			println!("  - Angèle Bossuat");
			println!("  - Bruno Blanchet (Prof. Dr.)");
			println!("  - Fabian Drinck");
			println!("  - Friedrich Wiemer");
			println!("  - Georgio Nicolas");
			println!("  - Jean-Philippe Aumasson (Dr.)");
			println!("  - Laurent Grémy");
			println!("  - Loup Vaillant David");
			println!("  - Michiel Leenars");
			println!("  - \"Mike\" (pseudonym)");
			println!("  - Mukesh Tiwari (Dr.)");
			println!("  - Oleksandra \"Sasha\" Lapiha");
			println!("  - Oskar Goldhahn");
			println!("  - Renaud Lifchitz");
			println!("  - Sebastian R. Verschoor");
			println!("  - Tom Roeder");
			update_check_report(&update_check);
			0
		}
	};
	if status != 0 {
		std::process::exit(status);
	}
}
