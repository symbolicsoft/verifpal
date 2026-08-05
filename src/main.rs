/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::Read;

use clap::{Parser, Subcommand};
use verifpal::{InfoLevel, info_banner, info_message, pretty_print, verify};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "verifpal", version = VERSION, about = format!("Verifpal {} - https://verifpal.com", VERSION))]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	/// Analyze a Verifpal model
	#[command(arg_required_else_help = true)]
	Verify {
		/// Path to the Verifpal model file
		model: String,
		/// Output only the result code (for testing)
		#[arg(long, default_value_t = false)]
		result_code: bool,
	},
	/// Pretty-print a Verifpal model
	#[command(arg_required_else_help = true)]
	Pretty {
		/// Path to the Verifpal model file
		model: String,
	},
	/// About information for the Verifpal software
	About,
	/// Internal JSON interface for IDE integrations
	#[command(name = "internal-json", arg_required_else_help = true)]
	InternalJson {
		/// Subcommand: knowledgeMap, verify, prettyPrint, prettyDiagram
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
				// The editor sends EOT rather than closing the pipe.
				if let Some(eot) = buf[..n].iter().position(|&b| b == 0x04) {
					input.extend_from_slice(&buf[..eot]);
					break;
				}
				input.extend_from_slice(&buf[..n]);
			}
			Err(_) => break,
		}
	}
	// Decode once, at the end: pushing `b as char` per byte would turn every
	// multi-byte UTF-8 sequence in a comment into mojibake.
	String::from_utf8_lossy(&input).into_owned()
}

fn main() {
	let cli = Cli::parse();
	match cli.command {
		Commands::Verify { model, result_code } => {
			if !result_code {
				info_banner(VERSION);
				info_message("Verifpal is Beta software.", InfoLevel::Warning, false);
			}
			match verify(&model) {
				Ok((_, code)) => {
					if result_code {
						println!("{}", code);
					}
				}
				Err(e) => {
					eprintln!("Error: {}", e);
					std::process::exit(1);
				}
			}
		}
		Commands::Pretty { model } => match pretty_print(&model) {
			Ok(output) => print!("{}", output),
			Err(e) => {
				eprintln!("Error: {}", e);
				std::process::exit(1);
			}
		},
		Commands::InternalJson { subcommand } => {
			let input = read_stdin();
			verifpal::handle_internal_json(&subcommand, &input);
		}
		Commands::About => {
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
		}
	}
}
