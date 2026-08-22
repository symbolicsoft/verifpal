/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::Read;

use clap::{Parser, Subcommand, ValueEnum};
use verifpal::{
	ColorChoice, Verbosity, VerifyReport, diagram, info_banner, json_report, pretty_print,
	set_color_choice, set_verbosity, update_check_report, update_check_start, verify_report,
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
	#[command(name = "internal-json", arg_required_else_help = true)]
	InternalJson {
		subcommand: String,
	},
}

fn read_stdin() -> String {
	let mut input: Vec<u8> = Vec::new();
	let mut buf = [0u8; 4096];
	let stdin = std::io::stdin();
	let mut handle = stdin.lock();
	loop {
		match handle.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => {
				if let Some(eot) = buf[..n].iter().position(|&b| b == 0x04) {
					input.extend_from_slice(&buf[..eot]);
					break;
				}
				input.extend_from_slice(&buf[..n]);
			}
			Err(_) => break,
		}
	}
	String::from_utf8_lossy(&input).into_owned()
}

fn verify_verbosity(json: bool, result_code: bool, quiet: bool, verbose: bool) -> Verbosity {
	if json || (result_code && quiet) {
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
	format: FormatArg,
	quiet: bool,
	verbose: bool,
	color: ColorArg,
) -> i32 {
	let json = format == FormatArg::Json;
	set_color_choice(if json {
		ColorChoice::Never
	} else {
		color.into()
	});
	set_verbosity(verify_verbosity(json, result_code, quiet, verbose));

	let update_check = update_check_start(VERSION);
	if !result_code && !json {
		info_banner(VERSION);
	}

	let single = models.len() == 1;
	let mut outcomes: Vec<(String, Result<VerifyReport, String>)> = Vec::new();
	let mut had_error = false;
	let mut had_attack = false;

	for (index, model) in models.iter().enumerate() {
		if index > 0 && !json && !result_code {
			println!();
		}
		match verify_report(model, sessions) {
			Ok(report) => {
				had_attack |= report.results.iter().any(|r| r.resolved);
				if result_code {
					if single {
						println!("{}", report.code);
					} else {
						println!("{} {}", model, report.code);
					}
				}
				outcomes.push((model.clone(), Ok(report)));
			}
			Err(e) => {
				had_error = true;
				let text = e.to_string();
				if !json {
					eprintln!("Error: {}", text);
				}
				outcomes.push((model.clone(), Err(text)));
			}
		}
	}

	if json {
		println!("{}", json_report(VERSION, &outcomes));
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
				eprintln!("Error: {}", e);
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
			eprintln!("Error: {}: {}", model, e);
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
			format,
			quiet,
			verbose,
			color,
		} => run_verify(
			models,
			result_code,
			sessions,
			fail_on_attack,
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
		Commands::Diagram { model, color } => {
			set_color_choice(color.into());
			match diagram(&model) {
				Ok(output) => {
					print!("{}", output);
					0
				}
				Err(e) => {
					eprintln!("Error: {}", e);
					EXIT_ERROR
				}
			}
		}
		Commands::InternalJson { subcommand } => {
			let input = read_stdin();
			verifpal::handle_internal_json(&subcommand, &input);
			0
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
