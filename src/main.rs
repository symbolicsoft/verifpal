/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::Read;

use clap::{Parser, Subcommand};
use verifpal::{InfoLevel, info_banner, info_message, pretty_print, verify_with_sessions};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "verifpal", version = VERSION, about = format!("Verifpal {} - https://verifpal.com", VERSION))]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	#[command(arg_required_else_help = true)]
	Verify {
		model: String,
		#[arg(long, default_value_t = false)]
		result_code: bool,
		#[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=16))]
		sessions: u8,
	},
	#[command(arg_required_else_help = true)]
	Pretty {
		model: String,
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

fn main() {
	let cli = Cli::parse();
	match cli.command {
		Commands::Verify {
			model,
			result_code,
			sessions,
		} => {
			if !result_code {
				info_banner(VERSION);
				info_message("Verifpal is Beta software.", InfoLevel::Warning, false);
			}
			match verify_with_sessions(&model, sessions) {
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
