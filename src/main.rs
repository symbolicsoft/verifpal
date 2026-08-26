/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use clap::{Parser, Subcommand, ValueEnum};
use verifpal::{
	ColorChoice, Run, SATURATE_MAX, Verbosity, VerifyReport, diagram, html_report, info_banner,
	pretty_print, saturation_sessions, set_color_choice, set_verbosity, update_check_report,
	update_check_start, verify_report_with_source_opts,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const EXIT_ERROR: i32 = 1;
const EXIT_ATTACK: i32 = 2;

#[derive(Parser)]
#[command(name = "verifpal", version = VERSION, about = format!("Verifpal {} - https://verifpal.com", VERSION))]
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
	#[command(arg_required_else_help = true)]
	Verify {
		#[arg(required = true, num_args = 1..)]
		models: Vec<String>,
		#[arg(long, default_value_t = false)]
		result_code: bool,
		#[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=16))]
		sessions: u8,
		#[arg(long, default_value_t = false)]
		fail_on_attack: bool,
		#[arg(long, default_value_t = false)]
		auto_queries: bool,
		#[arg(long, default_value_t = false)]
		saturate: bool,
		#[arg(long, value_enum, default_value_t = FormatArg::Text)]
		format: FormatArg,
		#[arg(short, long, default_value_t = false, conflicts_with = "verbose")]
		quiet: bool,
		#[arg(short, long, default_value_t = false)]
		verbose: bool,
		#[arg(long, value_enum, default_value_t = ColorArg::Auto)]
		color: ColorArg,
	},
	#[command(arg_required_else_help = true)]
	Pretty {
		#[arg(required = true, num_args = 1..)]
		models: Vec<String>,
		#[arg(short, long, default_value_t = false, conflicts_with = "check")]
		write: bool,
		#[arg(long, default_value_t = false)]
		check: bool,
	},
	#[command(arg_required_else_help = true)]
	Diagram {
		model: String,
		#[arg(long, value_enum, default_value_t = ColorArg::Auto)]
		color: ColorArg,
	},
	About,
	#[command(name = "lsp")]
	Lsp {
		#[arg(long, default_value_t = false)]
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
						println!(
							"Verdicts stable from {} session{} onward.",
							point,
							if point == 1 { "" } else { "s" }
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
