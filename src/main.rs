/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::Read;

use clap::{Parser, Subcommand};
use verifpal::{
	InfoLevel, info_banner, info_message, pretty_print, set_character, set_tui_mode, verify,
};

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
		/// Attacker character voice (jevil, spamton)
		#[arg(long)]
		character: Option<String>,
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
	let mut input = String::new();
	let mut buf = [0u8; 4096];
	let stdin = std::io::stdin();
	let mut handle = stdin.lock();
	loop {
		match handle.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => {
				for &b in &buf[..n] {
					if b == 0x04 {
						return input;
					}
					input.push(b as char);
				}
			}
			Err(_) => break,
		}
	}
	input
}

fn main() {
	let cli = Cli::parse();
	match cli.command {
		Commands::Verify {
			model,
			result_code,
			character,
		} => {
			if let Some(ref ch) = character
				&& let Err(e) = set_character(ch)
			{
				eprintln!("Error: {}", e);
				std::process::exit(1);
			}
			if !result_code {
				set_tui_mode(true);
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
			verifpal::json::handle_internal_json(&subcommand, &input);
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

#[cfg(test)]
mod unit_tests {
	use std::collections::HashMap;
	use std::sync::Arc;

	use verifpal::equivalence::*;
	use verifpal::hashing::*;
	use verifpal::inject::{primitive_skeleton_depth, primitive_skeleton_hash};
	use verifpal::possible::*;
	use verifpal::primitive::*;
	use verifpal::types::*;
	use verifpal::value::*;

	// -----------------------------------------------------------------------
	// Test helpers
	// -----------------------------------------------------------------------

	fn make_constant(name: &str) -> Value {
		Value::Constant(Constant {
			name: Arc::from(name),
			id: value_names_map_add(name),
			guard: false,
			fresh: false,
			leaked: false,
			declaration: Some(Declaration::Knows),
			qualifier: Some(Qualifier::Public),
		})
	}

	fn make_password(name: &str) -> Value {
		Value::Constant(Constant {
			name: Arc::from(name),
			id: value_names_map_add(name),
			guard: false,
			fresh: false,
			leaked: false,
			declaration: Some(Declaration::Knows),
			qualifier: Some(Qualifier::Password),
		})
	}

	fn make_equation(values: Vec<Value>) -> Value {
		Value::Equation(Arc::new(Equation { values }))
	}

	fn make_primitive(id: PrimitiveId, args: Vec<Value>, output: usize) -> Value {
		Value::Primitive(Arc::new(Primitive {
			id,
			arguments: args,
			output,
			instance_check: false,
		}))
	}

	fn make_attacker_state(known: Vec<Value>) -> AttackerState {
		let mut known_map: HashMap<u64, Vec<usize>> = HashMap::new();
		for (i, v) in known.iter().enumerate() {
			known_map.entry(v.hash_value()).or_default().push(i);
		}
		AttackerState {
			current_phase: 0,
			exhausted: false,
			known: Arc::new(known),
			known_map: Arc::new(known_map),
			skeleton_hashes: Arc::new(std::collections::HashSet::new()),
			mutation_records: Arc::new(vec![]),
		}
	}

	fn make_principal_state(
		name: &str,
		id: PrincipalId,
		meta: Vec<SlotMeta>,
		values: Vec<SlotValues>,
	) -> PrincipalState {
		let mut index = HashMap::new();
		for (i, m) in meta.iter().enumerate() {
			index.insert(m.constant.id, i);
		}
		PrincipalState {
			name: name.to_string(),
			id,
			max_declared_at: 0,
			meta: Arc::new(meta),
			values,
			index: Arc::new(index),
			leaks: Arc::new(Vec::new()),
			halted_at: None,
		}
	}

	fn make_slot_meta(c: &Constant, creator_is_self: bool) -> SlotMeta {
		SlotMeta {
			constant: c.clone(),
			guard: false,
			known: true,
			wire: if creator_is_self { vec![] } else { vec![0] },
			known_by: vec![],
			declared_at: 0,
			mutatable_to: vec![],
			phase: vec![0],
		}
	}

	fn make_slot_values(v: &Value, creator: PrincipalId) -> SlotValues {
		SlotValues {
			value: v.clone(),
			pre_rewrite: v.clone(),
			original: v.clone(),
			rewritten: false,
			provenance: Provenance {
				creator,
				sender: creator,
				attacker_tainted: false,
			},
		}
	}

	// -----------------------------------------------------------------------
	// 1. Value equivalence: constants
	// -----------------------------------------------------------------------

	#[test]
	fn constant_equivalence_same_id() {
		let a = make_constant("test_const_a");
		let b = make_constant("test_const_a"); // same name → same id
		assert!(a.equivalent(&b, true));
	}

	#[test]
	fn constant_equivalence_different_id() {
		let a = make_constant("eq_const_x");
		let b = make_constant("eq_const_y");
		assert!(!a.equivalent(&b, true));
	}

	// -----------------------------------------------------------------------
	// 2. Equation equivalence: commutative DH
	// -----------------------------------------------------------------------

	#[test]
	fn equation_equivalence_2_element() {
		let a = make_constant("eq2_a");
		let b = make_constant("eq2_b");
		let e1 = make_equation(vec![value_g(), a.clone()]);
		let e2 = make_equation(vec![value_g(), a.clone()]);
		assert!(e1.equivalent(&e2, true));
		// Different exponent
		let e3 = make_equation(vec![value_g(), b]);
		assert!(!e1.equivalent(&e3, true));
	}

	#[test]
	fn equation_equivalence_3_element_commutative() {
		// G^a^b == G^b^a (Diffie-Hellman commutativity)
		let a = make_constant("dh_a");
		let b = make_constant("dh_b");
		let e1 = make_equation(vec![value_g(), a.clone(), b.clone()]);
		let e2 = make_equation(vec![value_g(), b, a]);
		assert!(e1.equivalent(&e2, true));
	}

	#[test]
	fn equation_equivalence_3_element_not_equal() {
		let a = make_constant("dh_ne_a");
		let b = make_constant("dh_ne_b");
		let c = make_constant("dh_ne_c");
		let e1 = make_equation(vec![value_g(), a.clone(), b]);
		let e2 = make_equation(vec![value_g(), a, c]);
		assert!(!e1.equivalent(&e2, true));
	}

	#[test]
	fn equation_equivalence_empty() {
		let e1 = make_equation(vec![]);
		let e2 = make_equation(vec![]);
		// Empty equations are not equivalent (equivalence returns false for empty)
		assert!(!e1.equivalent(&e2, true));
	}

	// -----------------------------------------------------------------------
	// 3. Equation flattening
	// -----------------------------------------------------------------------

	#[test]
	fn equation_flatten_nested() {
		let a = make_constant("flat_a");
		let b = make_constant("flat_b");
		let inner = Equation {
			values: vec![value_g(), a.clone()],
		};
		let outer = Equation {
			values: vec![Value::Equation(Arc::new(inner)), b.clone()],
		};
		assert!(!equation_is_flat(&outer));
		let flat = flatten_equation(&outer);
		assert!(equation_is_flat(&flat));
		assert_eq!(flat.values.len(), 3); // g, a, b
	}

	#[test]
	fn equation_already_flat() {
		let a = make_constant("aflat_a");
		let eq = Equation {
			values: vec![value_g(), a],
		};
		assert!(equation_is_flat(&eq));
	}

	// -----------------------------------------------------------------------
	// 3b. Parser: content after the queries block is a hard error
	// -----------------------------------------------------------------------

	#[test]
	fn parse_rejects_content_after_queries() {
		// A phase declared after the queries block would silently disable
		// forward secrecy analysis. The parser now refuses to run when it
		// finds any content after the `queries` block.
		let model = concat!(
			"attacker[active]\n",
			"principal Alice[ knows private x ]\n",
			"Alice -> Bob: x\n",
			"principal Bob[]\n",
			"queries[ confidentiality? x ]\n",
			"phase[1]\n",
			"principal Alice[ leaks x ]\n",
		);
		assert!(verifpal::parser::parse_string("after_queries.vp", model).is_err());
	}

	#[test]
	fn parse_accepts_phase_before_queries() {
		let model = concat!(
			"attacker[active]\n",
			"principal Alice[ knows private x ]\n",
			"Alice -> Bob: x\n",
			"principal Bob[]\n",
			"phase[1]\n",
			"principal Alice[ leaks x ]\n",
			"queries[ confidentiality? x ]\n",
		);
		assert!(verifpal::parser::parse_string("before_queries.vp", model).is_ok());
	}

	// -----------------------------------------------------------------------
	// 4. Primitive equivalence
	// -----------------------------------------------------------------------

	#[test]
	fn primitive_equivalence_same() {
		let a = make_constant("peq_a");
		let b = make_constant("peq_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		assert!(equivalent_primitives(&p1, &p2, true).equivalent);
	}

	#[test]
	fn primitive_equivalence_different_id() {
		let a = make_constant("pdiff_a");
		let b = make_constant("pdiff_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_DEC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
	}

	#[test]
	fn primitive_equivalence_different_output() {
		let a = make_constant("pout_a");
		let p1 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a],
			output: 1,
			instance_check: false,
		};
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
		let pm = equivalent_primitives(&p1, &p2, false);
		assert!(pm.equivalent); // ignoring output they're equivalent
		assert_eq!(pm.output_left, 0);
		assert_eq!(pm.output_right, 1);
	}

	// -----------------------------------------------------------------------
	// 5. Value hashing consistency with equivalence
	// -----------------------------------------------------------------------

	#[test]
	fn hash_equal_constants() {
		let a = make_constant("hash_eq_a");
		let b = make_constant("hash_eq_a"); // same name → same id
		assert_eq!(a.hash_value(), b.hash_value());
	}

	#[test]
	fn hash_commutative_dh() {
		// Commutative DH equations must hash the same
		let a = make_constant("hash_dh_a");
		let b = make_constant("hash_dh_b");
		let e1 = make_equation(vec![value_g(), a.clone(), b.clone()]);
		let e2 = make_equation(vec![value_g(), b, a]);
		assert_eq!(e1.hash_value(), e2.hash_value());
	}

	#[test]
	fn hash_different_values() {
		let a = make_constant("hash_d_a");
		let b = make_constant("hash_d_b");
		// Very likely different hashes (not guaranteed but extremely probable)
		assert_ne!(a.hash_value(), b.hash_value());
	}

	#[test]
	fn hash_primitive_includes_output() {
		let a = make_constant("hash_po_a");
		let p1 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a.clone()], 0);
		let p2 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a], 1);
		// Different outputs should produce different hashes
		assert_ne!(p1.hash_value(), p2.hash_value());
	}

	// -----------------------------------------------------------------------
	// 6. Canonical values
	// -----------------------------------------------------------------------

	#[test]
	fn canonical_g_nil_equivalence() {
		let g = value_g();
		let nil = value_nil();
		assert!(g.equivalent(&value_g(), true));
		assert!(nil.equivalent(&value_nil(), true));
		assert!(!g.equivalent(&nil, true));
	}

	#[test]
	fn canonical_g_nil_equation() {
		let gn = value_g_nil();
		let expected = make_equation(vec![value_g(), value_nil()]);
		assert!(gn.equivalent(&expected, true));
	}

	#[test]
	fn canonical_g_nil_nil_equation() {
		let gnn = value_g_nil_nil();
		let expected = make_equation(vec![value_g(), value_nil(), value_nil()]);
		assert!(gnn.equivalent(&expected, true));
	}

	// -----------------------------------------------------------------------
	// 7. Value name map
	// -----------------------------------------------------------------------

	#[test]
	fn name_map_idempotent() {
		let id1 = value_names_map_add("name_map_test_xyz");
		let id2 = value_names_map_add("name_map_test_xyz");
		assert_eq!(id1, id2);
	}

	#[test]
	fn name_map_unique() {
		let id1 = value_names_map_add("name_map_unique_a");
		let id2 = value_names_map_add("name_map_unique_b");
		assert_ne!(id1, id2);
	}

	// -----------------------------------------------------------------------
	// 8. find_equivalent and push_unique_value
	// -----------------------------------------------------------------------

	#[test]
	fn find_equivalent_in_slice() {
		let a = make_constant("find_a");
		let b = make_constant("find_b");
		let c = make_constant("find_a"); // same as a
		let slice = vec![a.clone(), b.clone()];
		assert_eq!(find_equivalent(&c, &slice), Some(0));
		let d = make_constant("find_d");
		assert_eq!(find_equivalent(&d, &slice), None);
	}

	#[test]
	fn push_unique_no_duplicates() {
		let a = make_constant("push_a");
		let b = make_constant("push_b");
		let mut v = vec![];
		assert!(push_unique_value(&mut v, a.clone()));
		assert!(push_unique_value(&mut v, b));
		assert!(!push_unique_value(&mut v, a)); // duplicate
		assert_eq!(v.len(), 2);
	}

	// -----------------------------------------------------------------------
	// 9. Constant helpers
	// -----------------------------------------------------------------------

	#[test]
	fn constant_is_g_or_nil() {
		let g = value_g();
		let nil = value_nil();
		let other = make_constant("not_g_or_nil");
		assert!(g.as_constant().unwrap().is_g_or_nil());
		assert!(nil.as_constant().unwrap().is_g_or_nil());
		assert!(!other.as_constant().unwrap().is_g_or_nil());
	}

	// -----------------------------------------------------------------------
	// 10. Value variant accessors
	// -----------------------------------------------------------------------

	#[test]
	fn value_accessors() {
		let c = make_constant("acc_c");
		let p = make_primitive(PRIM_HASH, vec![c.clone()], 0);
		let e = make_equation(vec![value_g(), c.clone()]);

		assert!(c.as_constant().is_some());
		assert!(c.as_primitive().is_none());
		assert!(c.as_equation().is_none());

		assert!(p.as_primitive().is_some());
		assert!(p.as_constant().is_none());

		assert!(e.as_equation().is_some());
		assert!(e.as_constant().is_none());
	}

	#[test]
	fn value_try_accessors() {
		let c = make_constant("try_c");
		assert!(c.as_constant().is_some());
		assert!(c.try_as_primitive().is_err());
		assert!(c.try_as_equation().is_err());
	}

	// -----------------------------------------------------------------------
	// 11. Primitive definition trait
	// -----------------------------------------------------------------------

	#[test]
	fn primitive_def_core() {
		let def = primitive_def(PRIM_ASSERT).unwrap();
		assert_eq!(def.name(), "ASSERT");
		assert!(def.definition_check());
		assert!(def.has_rewrite_rule());
		assert!(!def.is_explosive());
	}

	#[test]
	fn primitive_def_non_core() {
		let def = primitive_def(PRIM_AEAD_ENC).unwrap();
		assert_eq!(def.name(), "AEAD_ENC");
		assert!(!def.definition_check());
		assert!(!def.has_rewrite_rule());
	}

	#[test]
	fn primitive_def_check_property() {
		// AEAD_DEC has definition_check = true (it's a verification primitive)
		let dec = primitive_def(PRIM_AEAD_DEC).unwrap();
		assert!(dec.definition_check());
		// ENC has definition_check = false
		let enc = primitive_def(PRIM_ENC).unwrap();
		assert!(!enc.definition_check());
	}

	#[test]
	fn primitive_is_core_check() {
		assert!(primitive_is_core(PRIM_ASSERT));
		assert!(primitive_is_core(PRIM_CONCAT));
		assert!(primitive_is_core(PRIM_SPLIT));
		assert!(!primitive_is_core(PRIM_HASH));
		assert!(!primitive_is_core(PRIM_AEAD_ENC));
	}

	#[test]
	fn primitive_name_lookup() {
		assert_eq!(primitive_name(PRIM_HASH), "HASH");
		assert_eq!(primitive_name(PRIM_SIGN), "SIGN");
		assert_eq!(primitive_name(PRIM_CONCAT), "CONCAT");
	}

	#[test]
	fn primitive_get_enum_roundtrip() {
		let id = primitive_get_enum("AEAD_ENC").unwrap();
		assert_eq!(id, PRIM_AEAD_ENC);
		let id2 = primitive_get_enum("SPLIT").unwrap();
		assert_eq!(id2, PRIM_SPLIT);
		assert!(primitive_get_enum("NONEXISTENT").is_err());
	}

	// -----------------------------------------------------------------------
	// 12. Skeleton depth and hash
	// -----------------------------------------------------------------------

	#[test]
	fn skeleton_depth_flat() {
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![make_constant("sd_a"), make_constant("sd_b")],
			output: 0,
			instance_check: false,
		};
		let d = primitive_skeleton_depth(&p, 0);
		assert_eq!(d, 1);
	}

	#[test]
	fn skeleton_depth_nested() {
		let inner = make_primitive(PRIM_HASH, vec![make_constant("sd_n_a")], 0);
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![make_constant("sd_n_k"), inner],
			output: 0,
			instance_check: false,
		};
		let d = primitive_skeleton_depth(&p, 0);
		assert_eq!(d, 3); // outer=1+max(inner=1+1, leaf)=3
	}

	#[test]
	fn skeleton_hash_same_structure() {
		let a = make_constant("sh_a");
		let b = make_constant("sh_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![b, a],
			output: 0,
			instance_check: false,
		};
		// Same structure (constants are normalized to nil in skeleton)
		assert_eq!(primitive_skeleton_hash(&p1), primitive_skeleton_hash(&p2));
	}

	// -----------------------------------------------------------------------
	// 13. AttackerState knows
	// -----------------------------------------------------------------------

	#[test]
	fn attacker_knows_value() {
		let a = make_constant("ak_a");
		let b = make_constant("ak_b");
		let c = make_constant("ak_c");
		let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
		assert!(attacker.knows(&a).is_some());
		assert!(attacker.knows(&b).is_some());
		assert!(attacker.knows(&c).is_none());
	}

	#[test]
	fn attacker_knows_equation() {
		let a = make_constant("ake_a");
		let eq = make_equation(vec![value_g(), a]);
		let attacker = make_attacker_state(vec![eq.clone()]);
		assert!(attacker.knows(&eq).is_some());
	}

	// -----------------------------------------------------------------------
	// 14. PrincipalState helpers
	// -----------------------------------------------------------------------

	#[test]
	fn principal_state_index_of() {
		let c = Constant {
			name: Arc::from("ps_idx_a"),
			id: value_names_map_add("ps_idx_a"),
			..Constant::default()
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&make_constant("ps_idx_a"), 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		assert_eq!(ps.index_of(&c), Some(0));

		let other = Constant {
			name: Arc::from("ps_idx_b"),
			id: value_names_map_add("ps_idx_b"),
			..Constant::default()
		};
		assert_eq!(ps.index_of(&other), None);
	}

	#[test]
	fn principal_state_should_use_original_creator() {
		let c = Constant {
			name: Arc::from("ps_fbm_a"),
			id: value_names_map_add("ps_fbm_a"),
			..Constant::default()
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&make_constant("ps_fbm_a"), 0)]; // creator == self.id
		let ps = make_principal_state("Alice", 0, meta, values);
		assert!(ps.should_use_original(0)); // creator == self
	}

	#[test]
	fn principal_state_effective_value_not_mutated() {
		let c = Constant {
			name: Arc::from("ps_ev_a"),
			id: value_names_map_add("ps_ev_a"),
			..Constant::default()
		};
		let val = make_constant("ps_ev_a");
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		assert!(ps.effective_value(0).equivalent(&val, true));
	}

	#[test]
	fn principal_state_effective_value_mutated() {
		let c = Constant {
			name: Arc::from("ps_evm_a"),
			id: value_names_map_add("ps_evm_a"),
			..Constant::default()
		};
		let original = make_constant("ps_evm_a");
		let mutated = make_constant("ps_evm_mutated");
		let mut meta = make_slot_meta(&c, false);
		meta.wire = vec![1]; // received by principal 1
		let mut sv = make_slot_values(&mutated, 0);
		sv.original = original.clone();
		sv.provenance.attacker_tainted = true;
		sv.provenance.creator = 0; // different from ps.id=1
		let ps = make_principal_state("Bob", 1, vec![meta], vec![sv]);
		// Bob (id=1) received this on wire, and it was mutated
		// Since creator(0) != self(1), known=true, wire contains self(1), and mutated=true,
		// should_use_original returns false, so effective_value = value (tainted)
		assert!(ps.effective_value(0).equivalent(&mutated, true));
	}

	// -----------------------------------------------------------------------
	// 15. can_rewrite (possible.rs)
	// -----------------------------------------------------------------------

	#[test]
	fn can_rewrite_split_concat() {
		// SPLIT(CONCAT(a, b)) should rewrite to [a, b]
		let a = make_constant("cr_a");
		let b = make_constant("cr_b");
		let concat = Primitive {
			id: PRIM_CONCAT,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let split = Primitive {
			id: PRIM_SPLIT,
			arguments: vec![Value::Primitive(Arc::new(concat))],
			output: 0,
			instance_check: false,
		};
		let c_dummy = Constant {
			name: Arc::from("cr_dummy"),
			id: value_names_map_add("cr_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, values) = can_rewrite(&split, &ps, 0);
		assert!(rewritten);
		assert_eq!(values.len(), 2);
		assert!(values[0].equivalent(&a, true));
		assert!(values[1].equivalent(&b, true));
	}

	#[test]
	fn can_rewrite_assert_matching() {
		// ASSERT(x, x) should succeed
		let a = make_constant("cra_a");
		let assert_prim = Primitive {
			id: PRIM_ASSERT,
			arguments: vec![a.clone(), a.clone()],
			output: 0,
			instance_check: false,
		};
		let c_dummy = Constant {
			name: Arc::from("cra_dummy"),
			id: value_names_map_add("cra_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, _) = can_rewrite(&assert_prim, &ps, 0);
		assert!(rewritten);
	}

	#[test]
	fn can_rewrite_assert_mismatch() {
		// ASSERT(x, y) should fail
		let a = make_constant("cram_a");
		let b = make_constant("cram_b");
		let assert_prim = Primitive {
			id: PRIM_ASSERT,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		let c_dummy = Constant {
			name: Arc::from("cram_dummy"),
			id: value_names_map_add("cram_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, _) = can_rewrite(&assert_prim, &ps, 0);
		assert!(!rewritten);
	}

	// -----------------------------------------------------------------------
	// 16. can_reconstruct_equation
	// -----------------------------------------------------------------------

	#[test]
	fn can_reconstruct_equation_2_element() {
		let a = make_constant("cre_a");
		let eq = Equation {
			values: vec![value_g(), a.clone()],
		};
		let attacker = make_attacker_state(vec![a]);
		let result = can_reconstruct_equation(&eq, &attacker);
		assert!(result.is_some());
		assert_eq!(result.unwrap().len(), 1);
	}

	#[test]
	fn can_reconstruct_equation_3_element_both_exponents() {
		let a = make_constant("cre3_a");
		let b = make_constant("cre3_b");
		let eq = Equation {
			values: vec![value_g(), a.clone(), b.clone()],
		};
		let attacker = make_attacker_state(vec![a, b]);
		let result = can_reconstruct_equation(&eq, &attacker);
		assert!(result.is_some());
		assert_eq!(result.unwrap().len(), 2);
	}

	#[test]
	fn can_reconstruct_equation_missing_exponent() {
		let a = make_constant("crem_a");
		let b = make_constant("crem_b");
		let eq = Equation {
			values: vec![value_g(), a.clone(), b],
		};
		let attacker = make_attacker_state(vec![a]); // only knows a, not b
		assert!(can_reconstruct_equation(&eq, &attacker).is_none());
	}

	// -----------------------------------------------------------------------
	// 17. passively_decompose
	// -----------------------------------------------------------------------

	#[test]
	fn passive_decompose_aead_enc() {
		// AEAD_ENC has no passive_reveal — the AD is not part of the ciphertext
		let key = make_constant("pd_key");
		let msg = make_constant("pd_msg");
		let ad = make_constant("pd_ad");
		let p = Primitive {
			id: PRIM_AEAD_ENC,
			arguments: vec![key, msg, ad.clone()],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert_eq!(revealed.len(), 0);
	}

	#[test]
	fn passive_decompose_hash_no_rule() {
		// HASH has no decompose rule
		let a = make_constant("pd_hash_a");
		let p = Primitive {
			id: PRIM_HASH,
			arguments: vec![a],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert!(revealed.is_empty());
	}

	#[test]
	fn passive_decompose_core_primitive() {
		// Core primitives return empty
		let a = make_constant("pd_core_a");
		let b = make_constant("pd_core_b");
		let p = Primitive {
			id: PRIM_CONCAT,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert!(revealed.is_empty());
	}

	// -----------------------------------------------------------------------
	// 18. can_decompose
	// -----------------------------------------------------------------------

	#[test]
	fn can_decompose_enc_with_key() {
		// ENC has decompose: given=[0] (key), reveal=1 (plaintext)
		let key = make_constant("cd_key");
		let msg = make_constant("cd_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key.clone(), msg.clone()],
			output: 0,
			instance_check: false,
		};
		let c_dummy = Constant {
			name: Arc::from("cd_dummy"),
			id: value_names_map_add("cd_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![key]);
		let result = can_decompose(&p, &ps, &attacker, 0);
		assert!(result.is_some());
		assert!(result.unwrap().revealed.equivalent(&msg, true));
	}

	#[test]
	fn can_decompose_enc_without_key() {
		let key = make_constant("cd_nk_key");
		let msg = make_constant("cd_nk_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key, msg],
			output: 0,
			instance_check: false,
		};
		let c_dummy = Constant {
			name: Arc::from("cd_nk_dummy"),
			id: value_names_map_add("cd_nk_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![]); // doesn't know the key
		assert!(can_decompose(&p, &ps, &attacker, 0).is_none());
	}

	// -----------------------------------------------------------------------
	// 19. Primitive with_arguments
	// -----------------------------------------------------------------------

	#[test]
	fn primitive_with_arguments() {
		let a = make_constant("pwa_a");
		let b = make_constant("pwa_b");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![a],
			output: 0,
			instance_check: true,
		};
		let p2 = p.with_arguments(vec![b.clone()]);
		assert_eq!(p2.id, PRIM_ENC);
		assert_eq!(p2.output, 0);
		assert!(p2.instance_check);
		assert!(p2.arguments[0].equivalent(&b, true));
	}

	// -----------------------------------------------------------------------
	// 20. SlotValues set_value / override_all
	// -----------------------------------------------------------------------

	#[test]
	fn slot_values_set_value_not_tainted() {
		let v1 = make_constant("sv_v1");
		let v2 = make_constant("sv_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.set_value(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v2, true)); // also updated when not tainted
	}

	#[test]
	fn slot_values_set_value_tainted() {
		let v1 = make_constant("svm_v1");
		let v2 = make_constant("svm_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.provenance.attacker_tainted = true;
		sv.set_value(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v1, true)); // NOT updated when tainted
	}

	#[test]
	fn slot_values_override_all() {
		let v1 = make_constant("svo_v1");
		let v2 = make_constant("svo_v2");
		let mut sv = make_slot_values(&v1, 0);
		sv.provenance.attacker_tainted = true;
		sv.override_all(v2.clone());
		assert!(sv.value.equivalent(&v2, true));
		assert!(sv.pre_rewrite.equivalent(&v2, true));
		assert!(sv.original.equivalent(&v2, true)); // overridden regardless of tainted
	}

	// -----------------------------------------------------------------------
	// 21. collect_constants
	// -----------------------------------------------------------------------

	#[test]
	fn collect_constants_from_primitive() {
		let a = make_constant("cc_a");
		let b = make_constant("cc_b");
		let p = make_primitive(PRIM_ENC, vec![a, b], 0);
		let mut out = Vec::new();
		p.collect_constants(&mut out);
		assert_eq!(out.len(), 2);
	}

	#[test]
	fn collect_constants_from_equation() {
		let a = make_constant("cce_a");
		let eq = make_equation(vec![value_g(), a]);
		let mut out = Vec::new();
		eq.collect_constants(&mut out);
		assert_eq!(out.len(), 2); // g and a
	}

	// -----------------------------------------------------------------------
	// 22. VerifpalError
	// -----------------------------------------------------------------------

	#[test]
	fn error_display() {
		let e = VerifpalError::Parse("bad input".into());
		assert_eq!(format!("{}", e), "parse error: bad input");
		let e2 = VerifpalError::Resolution("not found".into());
		assert_eq!(format!("{}", e2), "resolution error: not found");
	}

	// -----------------------------------------------------------------------
	// 23. find_obtainable_passwords
	// -----------------------------------------------------------------------

	#[test]
	fn find_obtainable_passwords_direct() {
		let pw = make_password("fop_pw");
		let pw_c = pw.as_constant().unwrap().clone();
		let meta = vec![make_slot_meta(&pw_c, true)];
		let values = vec![make_slot_values(&pw, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let mut out = Vec::new();
		find_obtainable_passwords(&pw, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 1);
	}

	#[test]
	fn find_obtainable_passwords_known_sibling() {
		// ENC(pwd, msg): attacker knows msg → can verify pwd guesses → obtainable
		let pw = make_password("fop2_pw");
		let msg = make_constant("fop2_msg");
		let pw_c = pw.as_constant().unwrap().clone();
		let msg_c = msg.as_constant().unwrap().clone();
		let enc = make_primitive(PRIM_ENC, vec![pw.clone(), msg.clone()], 0);
		let meta = vec![make_slot_meta(&pw_c, true), make_slot_meta(&msg_c, false)];
		let values = vec![make_slot_values(&pw, 0), make_slot_values(&msg, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![msg]);
		let mut out = Vec::new();
		find_obtainable_passwords(&enc, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 1);
	}

	#[test]
	fn find_obtainable_passwords_unknown_sibling() {
		// ENC(pwd, secret): attacker does NOT know secret → cannot verify → safe
		let pw = make_password("fop3_pw");
		let secret = make_constant("fop3_secret");
		let pw_c = pw.as_constant().unwrap().clone();
		let secret_c = secret.as_constant().unwrap().clone();
		let enc = make_primitive(PRIM_ENC, vec![pw.clone(), secret.clone()], 0);
		let meta = vec![
			make_slot_meta(&pw_c, true),
			make_slot_meta(&secret_c, false),
		];
		let values = vec![make_slot_values(&pw, 0), make_slot_values(&secret, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let mut out = Vec::new();
		find_obtainable_passwords(&enc, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 0);
	}

	// -----------------------------------------------------------------------
	// 24. compute_slot_diffs
	// -----------------------------------------------------------------------

	#[test]
	fn compute_slot_diffs_no_changes() {
		let c = Constant {
			name: Arc::from("csd_a"),
			id: value_names_map_add("csd_a"),
			..Constant::default()
		};
		let val = make_constant("csd_a");
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string()],
			principal_ids: vec![0],
			slots: vec![TraceSlot {
				constant: c.clone(),
				initial_value: val.clone(),
				creator: 0,
				known_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = HashMap::new();
				m.insert(c.id, 0);
				m
			},
			max_declared_at: 0,
			max_phase: 0,
			used_by: HashMap::new(),
			leaks: Arc::new(Vec::new()),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let record = compute_slot_diffs(&ps, &trace);
		assert!(record.diffs.is_empty());
	}

	#[test]
	fn compute_slot_diffs_with_changes() {
		let c = Constant {
			name: Arc::from("csd2_a"),
			id: value_names_map_add("csd2_a"),
			..Constant::default()
		};
		let original = make_constant("csd2_a");
		let mutated = make_constant("csd2_mutated");
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string()],
			principal_ids: vec![0],
			slots: vec![TraceSlot {
				constant: c.clone(),
				initial_value: original.clone(),
				creator: 0,
				known_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = HashMap::new();
				m.insert(c.id, 0);
				m
			},
			max_declared_at: 0,
			max_phase: 0,
			used_by: HashMap::new(),
			leaks: Arc::new(Vec::new()),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let mut sv = make_slot_values(&mutated, 0);
		sv.provenance.attacker_tainted = true;
		let ps = make_principal_state("Alice", 0, meta, vec![sv]);
		let record = compute_slot_diffs(&ps, &trace);
		assert_eq!(record.diffs.len(), 1);
		assert_eq!(record.diffs[0].index, 0);
		assert!(record.diffs[0].tainted);
	}

	// -----------------------------------------------------------------------
	// 25. Explosive primitives
	// -----------------------------------------------------------------------

	#[test]
	fn explosive_primitives() {
		assert!(primitive_is_explosive(PRIM_CONCAT));
		assert!(primitive_is_explosive(PRIM_HASH));
		assert!(primitive_is_explosive(PRIM_HKDF));
		assert!(!primitive_is_explosive(PRIM_ENC));
		assert!(!primitive_is_explosive(PRIM_SIGN));
	}

	// -----------------------------------------------------------------------
	// 26. Single output check
	// -----------------------------------------------------------------------

	#[test]
	fn primitive_single_output() {
		assert!(primitive_has_single_output(PRIM_HASH));
		assert!(primitive_has_single_output(PRIM_ENC));
		assert!(!primitive_has_single_output(PRIM_SPLIT)); // output: [1,2,3,4,5]
		assert!(!primitive_has_single_output(PRIM_HKDF)); // output: [1,2,3,4,5]
	}

	// -----------------------------------------------------------------------
	// 27. TraceSlot known_by_principal
	// -----------------------------------------------------------------------

	#[test]
	fn trace_slot_known_by_creator() {
		let c = Constant {
			name: Arc::from("ts_a"),
			id: value_names_map_add("ts_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(0)); // creator
		assert!(!slot.known_by_principal(1)); // not creator, not in known_by
	}

	#[test]
	fn trace_slot_known_by_receiver() {
		let c = Constant {
			name: Arc::from("ts2_a"),
			id: value_names_map_add("ts2_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			constant: c,
			initial_value: value_nil(),
			creator: 0,
			known_by: vec![(1, 0)],
			declared_at: 0,
			phases: vec![0],
		};
		assert!(slot.known_by_principal(1)); // in known_by
	}

	// -----------------------------------------------------------------------
	// 28. MutationRecord and SlotDiff
	// -----------------------------------------------------------------------

	#[test]
	fn mutation_record_empty() {
		let record = MutationRecord { diffs: vec![] };
		assert!(record.diffs.is_empty());
	}

	// -----------------------------------------------------------------------
	// 29. Equation hash consistency with flattening
	// -----------------------------------------------------------------------

	#[test]
	fn equation_hash_flat_vs_nested() {
		let a = make_constant("ehf_a");
		let b = make_constant("ehf_b");
		// Flat: G^a^b
		let flat = Equation {
			values: vec![value_g(), a.clone(), b.clone()],
		};
		// Nested: (G^a)^b  (same thing when flattened)
		let inner = Equation {
			values: vec![value_g(), a],
		};
		let nested = Equation {
			values: vec![Value::Equation(Arc::new(inner)), b],
		};
		// Both should hash the same after flattening
		assert_eq!(equation_hash(&flat), equation_hash(&nested));
	}

	// -----------------------------------------------------------------------
	// 30. Primitive rewrite has_rule checks
	// -----------------------------------------------------------------------

	#[test]
	fn primitive_has_rewrite_rule_checks() {
		// Primitives with rewrite rules
		assert!(primitive_has_rewrite_rule(PRIM_AEAD_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_SIGNVERIF));
		assert!(primitive_has_rewrite_rule(PRIM_PKE_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_ASSERT));
		assert!(primitive_has_rewrite_rule(PRIM_SPLIT));
		// Primitives without rewrite rules
		assert!(!primitive_has_rewrite_rule(PRIM_HASH));
		assert!(!primitive_has_rewrite_rule(PRIM_ENC));
		assert!(!primitive_has_rewrite_rule(PRIM_SIGN));
		assert!(!primitive_has_rewrite_rule(PRIM_MAC));
	}

	// -----------------------------------------------------------------------
	// 31. QueryKind names
	// -----------------------------------------------------------------------

	#[test]
	fn query_kind_names() {
		assert_eq!(QueryKind::Confidentiality.name(), "confidentiality");
		assert_eq!(QueryKind::Authentication.name(), "authentication");
		assert_eq!(QueryKind::Freshness.name(), "freshness");
		assert_eq!(QueryKind::Unlinkability.name(), "unlinkability");
		assert_eq!(QueryKind::Equivalence.name(), "equivalence");
	}

	// -----------------------------------------------------------------------
	// 32. Comment preservation: leading comments
	// -----------------------------------------------------------------------

	use verifpal::parser::parse_string;
	use verifpal::pretty::pretty_model;

	#[test]
	fn comment_capture_pre_attacker_line() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(
			m.pre_attacker_comments.len(),
			1,
			"expected 1 pre-attacker comment"
		);
		assert_eq!(m.pre_attacker_comments[0].text, " hello");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Line
		));
	}

	#[test]
	fn comment_capture_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.blocks.len(), 1);
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert_eq!(p.leading_comments[0].text, " before alice");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term key\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.expressions.len(), 1);
				assert_eq!(p.expressions[0].leading_comments.len(), 1);
				assert_eq!(p.expressions[0].leading_comments[0].text, " long-term key");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries.len(), 1);
		assert_eq!(m.queries[0].leading_comments.len(), 1);
		assert_eq!(m.queries[0].leading_comments[0].text, " primary goal");
	}

	#[test]
	fn comment_capture_leading_on_queries_keyword() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// verify these\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_leading_comments.len(), 1);
		assert_eq!(m.queries_leading_comments[0].text, " verify these");
	}

	#[test]
	fn comment_capture_multiple_lines() {
		let src = "// line 1\n// line 2\n// line 3\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 3);
		assert_eq!(m.pre_attacker_comments[0].text, " line 1");
		assert_eq!(m.pre_attacker_comments[1].text, " line 2");
		assert_eq!(m.pre_attacker_comments[2].text, " line 3");
	}

	#[test]
	fn comment_capture_block_pre_attacker() {
		let src = "/* hello */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(m.pre_attacker_comments[0].text, " hello ");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Block
		));
	}

	#[test]
	fn comment_capture_block_multiline() {
		let src = "/* line1\n   line2\n   line3 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(
			m.pre_attacker_comments[0].text,
			" line1\n   line2\n   line3 "
		);
	}

	#[test]
	fn comment_capture_block_unterminated_errors() {
		let src = "/* never closed\nattacker[active]\n";
		assert!(parse_string("t.vp", src).is_err());
	}

	#[test]
	fn comment_capture_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term key\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_some());
				assert_eq!(
					p.expressions[0].trailing_comment.as_ref().unwrap().text,
					" long-term key"
				);
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_trailing_on_attacker() {
		let src = "attacker[active] // active model\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.attacker_trailing.is_some());
		assert_eq!(m.attacker_trailing.as_ref().unwrap().text, " active model");
	}

	#[test]
	fn comment_capture_trailing_on_message() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // initial flight\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let msg = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Message(m) => Some(m),
				_ => None,
			})
			.expect("message");
		assert!(msg.trailing_comment.is_some());
		assert_eq!(
			msg.trailing_comment.as_ref().unwrap().text,
			" initial flight"
		);
	}

	#[test]
	fn comment_capture_trailing_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a // primary\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries[0].trailing_comment.is_some());
		assert_eq!(
			m.queries[0].trailing_comment.as_ref().unwrap().text,
			" primary"
		);
	}

	#[test]
	fn comment_capture_block_trailing_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				let t = p.expressions[0]
					.trailing_comment
					.as_ref()
					.expect("trailing");
				assert_eq!(t.text, " lt ");
				assert!(matches!(t.style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_block_trailing_multiline_promoted_to_leading() {
		// Block comment that opens on same line as expression but closes
		// on a later line — must NOT be a trailing; should attach as
		// leading on the next node.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* multi\n\tline */\n\tknows private b\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_none());
				assert_eq!(p.expressions[1].leading_comments.len(), 1);
				assert_eq!(p.expressions[1].leading_comments[0].text, " multi\n\tline ");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO add more\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.tail_comments.len(), 1);
				assert_eq!(p.tail_comments[0].text, " TODO add more");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_closing_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n] // end of Alice\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.closing_trailing.is_some());
				assert_eq!(p.closing_trailing.as_ref().unwrap().text, " end of Alice");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_header_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[ // initiator\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.header_trailing.is_some());
				assert_eq!(p.header_trailing.as_ref().unwrap().text, " initiator");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_queries() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n\t// done\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_tail_comments.len(), 1);
		assert_eq!(m.queries_tail_comments[0].text, " done");
	}

	#[test]
	fn comment_capture_queries_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n] // end\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_closing_trailing.is_some());
		assert_eq!(m.queries_closing_trailing.as_ref().unwrap().text, " end");
	}

	#[test]
	fn comment_capture_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF tail\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.tail_comments.len(), 1);
		assert_eq!(m.tail_comments[0].text, " EOF tail");
	}

	#[test]
	fn comment_capture_queries_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_header_trailing.is_some());
		assert_eq!(m.queries_header_trailing.as_ref().unwrap().text, " start");
	}

	#[test]
	fn comment_lookahead_does_not_leak() {
		// The parse_message_constants lookahead inspects what comes
		// after a comma. If a comment sits between the message and the
		// next block, the lookahead must NOT capture it into the
		// previous message's leading comments after rollback.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a\n// next block\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		// "// next block" must attach to the Bob principal block,
		// not the previous Alice -> Bob message.
		let msg = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Message(m) => Some(m),
				_ => None,
			})
			.expect("message");
		assert!(msg.trailing_comment.is_none());
		let bob = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Principal(p) if p.name == "Bob" => Some(p),
				_ => None,
			})
			.expect("bob");
		assert_eq!(bob.leading_comments.len(), 1);
		assert_eq!(bob.leading_comments[0].text, " next block");
	}

	#[test]
	fn comment_dropped_in_primitive_args() {
		// Comment between primitive arguments is silently dropped.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tx = ENC(/* secret */ a, a)\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		// No AST field contains "secret".
		let serialized = format!("{:?}", m);
		assert!(
			!serialized.contains("secret"),
			"dropped comment must not appear in AST"
		);
	}

	#[test]
	fn comment_dropped_in_equation() {
		// Use a comment string that does not appear in any AST field name.
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tg = G ^ /* xzqrhs */ a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let serialized = format!("{:?}", m);
		assert!(
			!serialized.contains("xzqrhs"),
			"dropped comment must not appear in AST"
		);
	}

	// -----------------------------------------------------------------------
	// 33. Comment preservation: emission tests
	// -----------------------------------------------------------------------

	#[test]
	fn pretty_emits_pre_attacker_comments() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(
			out.starts_with("// hello\n\nattacker[active]"),
			"got: {}",
			out
		);
	}

	#[test]
	fn pretty_emits_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(
			out.contains("// before alice\nprincipal Alice["),
			"got: {}",
			out
		);
	}

	#[test]
	fn pretty_emits_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // lt\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a // lt"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a /* lt */"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_multiline() {
		let src = "/* line1\n   line2 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("/* line1"), "missing /* line1 in:\n{}", out);
		assert!(out.contains("line2 */"), "missing 'line2 */':\n{}", out);
	}

	// -----------------------------------------------------------------------
	// 34. Comment preservation: idempotence round-trip tests
	// -----------------------------------------------------------------------

	/// Parse `src`, pretty-print, parse the result, pretty-print again,
	/// and assert the two outputs are byte-equal. This is the canonical
	/// "preserves comments" check.
	fn assert_round_trip_idempotent(src: &str) {
		let m1 = parse_string("rt.vp", src).expect("parse 1");
		let s1 = pretty_model(&m1).expect("pretty 1");
		let m2 = parse_string("rt.vp", &s1).expect("parse 2");
		let s2 = pretty_model(&m2).expect("pretty 2");
		assert_eq!(
			s1, s2,
			"not idempotent\n--- s1 ---\n{}\n--- s2 ---\n{}",
			s1, s2
		);
	}

	#[test]
	fn round_trip_simple() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_pre_attacker_comment() {
		let src = "// SPDX header\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_trailing_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_block() {
		let src = "attacker[active]\n\n// initiator\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_pre_attacker() {
		let src = "/* SPDX header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_multiline() {
		let src = "/* multi\n   line\n   header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn block_comment_unterminated_errors_with_position() {
		let src = "/* never closed\nattacker[active]\n";
		let err = parse_string("t.vp", src).unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("unterminated block comment"), "got: {}", msg);
	}

	#[test]
	fn block_comment_nested_first_close_wins() {
		// /* /* */ */
		// Outer /* opens. First */ closes. The trailing */ becomes
		// stray tokens after the comment which produce a parse error
		// (because they're not valid syntax at the model start).
		let src = "/* /* */ */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let result = parse_string("t.vp", src);
		assert!(result.is_err(), "expected parse error from stray */");
	}

	#[test]
	fn block_comment_multiline_in_leading_position_renders() {
		let src = "attacker[active]\n\n/* multi\n   line\n   header */\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		// Expect the block comment intact in the output.
		assert!(out.contains("/* multi"), "missing /* multi in:\n{}", out);
		assert!(out.contains("line"), "missing 'line':\n{}", out);
		assert!(out.contains("header */"), "missing 'header */':\n{}", out);
		// Re-parse to verify the comment survived
		let m2 = parse_string("t.vp", &out).expect("re-parse");
		match &m2.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert!(matches!(p.leading_comments[0].style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}

	#[test]
	fn round_trip_message_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // flight 1\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_query_trailing_and_leading() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a // payload only\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_phase_with_leading_and_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// handshake done\nphase[1] // post-handshake\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_closing_and_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[ // header\n\tknows private a\n] // closing\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_queries_header_and_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n] // end\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF\n";
		assert_round_trip_idempotent(src);
	}

	// -----------------------------------------------------------------------
	// 33. Golden-file tests: assert byte-equality with stored pretty output
	// -----------------------------------------------------------------------

	fn assert_golden(input: &str, golden: &str) {
		let m = parse_string("g.vp", input).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert_eq!(
			out, golden,
			"golden mismatch\n--- expected ---\n{}\n--- got ---\n{}",
			golden, out
		);
	}

	#[test]
	fn golden_aead_leak() {
		assert_golden(
			include_str!("../examples/test/aead_leak.vp"),
			include_str!("../examples/test/golden_pretty/aead_leak.vp"),
		);
	}

	#[test]
	fn golden_assert_junglegym() {
		assert_golden(
			include_str!("../examples/test/assert_junglegym.vp"),
			include_str!("../examples/test/golden_pretty/assert_junglegym.vp"),
		);
	}

	#[test]
	fn golden_auth_with_signing() {
		assert_golden(
			include_str!("../examples/test/auth_with_signing.vp"),
			include_str!("../examples/test/golden_pretty/auth_with_signing.vp"),
		);
	}

	#[test]
	fn golden_concat_bomb() {
		assert_golden(
			include_str!("../examples/test/concat_bomb.vp"),
			include_str!("../examples/test/golden_pretty/concat_bomb.vp"),
		);
	}

	#[test]
	fn golden_simple() {
		assert_golden(
			include_str!("../examples/simple.vp"),
			include_str!("../examples/test/golden_pretty/simple.vp"),
		);
	}
}

#[cfg(test)]
mod tests {
	fn run_model(model: &str, expected: &str) {
		let file_name = format!("examples/test/{}", model);
		let (_, results_code) = verifpal::verify::verify(&file_name)
			.unwrap_or_else(|e| panic!("ERROR • {} ({})", model, e));
		assert_eq!(
			results_code, expected,
			"FAIL • {} (expected {}, got {})",
			model, expected, results_code
		);
	}

	#[test]
	fn test_challengeresponse() {
		run_model("challengeresponse.vp", "a0a1");
	}
	#[test]
	fn test_checked_aead() {
		run_model("checked_aead.vp", "c0a0a0");
	}
	#[test]
	fn test_ephemerals_sign() {
		run_model("ephemerals_sign.vp", "c1a1");
	}
	#[test]
	fn test_hmac_ok() {
		run_model("hmac_ok.vp", "c0a0");
	}
	#[test]
	fn test_hmac_unchecked_assert() {
		run_model("hmac_unchecked_assert.vp", "c0a1");
	}
	#[test]
	fn test_hmac_unguarded_alice() {
		run_model("hmac_unguarded_alice.vp", "c0a1");
	}
	#[test]
	fn test_hmac_unguarded_bob() {
		run_model("hmac_unguarded_bob.vp", "c1a0");
	}
	#[test]
	fn test_ok() {
		run_model("ok.vp", "c0a0a0");
	}
	#[test]
	fn test_pke() {
		run_model("pke.vp", "c0a0");
	}
	#[test]
	fn test_pke_unguarded_alice() {
		run_model("pke_unguarded_alice.vp", "c0a1");
	}
	#[test]
	fn test_pke_unguarded_bob() {
		run_model("pke_unguarded_bob.vp", "c1a0");
	}
	#[test]
	fn test_pke_unchecked_assert() {
		run_model("pke_unchecked_assert.vp", "c0a1");
	}
	#[test]
	fn test_assert_junglegym() {
		run_model("assert_junglegym.vp", "c0");
	}
	#[test]
	fn test_pw_hash() {
		run_model("pw_hash.vp", "c0c0c0c0c0c0");
	}
	#[test]
	fn test_pw_hash2() {
		run_model("pw_hash2.vp", "c0");
	}
	#[test]
	fn test_shamir() {
		run_model("shamir.vp", "c1");
	}
	#[test]
	fn test_subkey() {
		run_model("subkey.vp", "c1");
	}
	#[test]
	fn test_subkey_hash() {
		run_model("subkey_hash.vp", "c1");
	}
	#[test]
	fn test_subkey_hkdf() {
		run_model("subkey_hkdf.vp", "c1");
	}
	#[test]
	fn test_trivial() {
		run_model("trivial.vp", "c1a1");
	}
	#[test]
	fn test_unchecked_aead() {
		run_model("unchecked_aead.vp", "c0a1a1");
	}
	#[test]
	fn test_unguarded_alice() {
		run_model("unguarded_alice.vp", "c0a1a1");
	}
	#[test]
	fn test_unguarded_bob() {
		run_model("unguarded_bob.vp", "c1a0a0e1");
	}
	#[test]
	fn test_signal_small_nophase() {
		run_model("signal_small_nophase.vp", "c1a1");
	}
	#[test]
	fn test_signal_small_unguarded() {
		run_model("signal_small_unguarded.vp", "c1a1");
	}
	#[test]
	fn test_auth_with_signing() {
		run_model("auth_with_signing.vp", "c1a1a1");
	}
	#[test]
	fn test_auth_with_signing_false_attack() {
		run_model("auth_with_signing_false-attack.vp", "c0a1a0");
	}
	#[test]
	fn test_hmac_verif() {
		run_model("hmac_verif.vp", "a1a1");
	}
	#[test]
	fn test_sign_ciphertext() {
		run_model("sign_ciphertext.vp", "c0a0");
	}
	#[test]
	fn test_signature() {
		run_model("signature.vp", "c0a0a0");
	}
	#[test]
	fn test_precondition() {
		run_model("precondition.vp", "a1");
	}
	#[test]
	fn test_e_collection_key() {
		run_model("e_collection_key.vp", "c0a1");
	}
	#[test]
	fn test_ringsign() {
		run_model("ringsign.vp", "a0");
	}
	#[test]
	fn test_ringsign_substitute() {
		run_model("ringsign_substitute.vp", "a1a0a1a1");
	}
	#[test]
	fn test_ringsign_unguarded() {
		run_model("ringsign_unguarded.vp", "a1");
	}
	#[test]
	fn test_saltchannel() {
		run_model("saltchannel.vp", "c1");
	}
	#[test]
	fn test_concat1() {
		run_model("concat1.vp", "c1");
	}
	#[test]
	fn test_concat2() {
		run_model("concat2.vp", "c0");
	}
	#[test]
	fn test_freshness() {
		run_model("freshness.vp", "f1f0");
	}
	#[test]
	fn test_unlinkability() {
		run_model("unlinkability.vp", "u1u1u0");
	}
	#[test]
	fn test_needham_schroeder_pk() {
		run_model("needham-schroeder-pk.vp", "a1a1c1c1");
	}
	#[test]
	fn test_needham_schroeder_pk_withfix() {
		run_model("needham-schroeder-pk-withfix.vp", "a1a1c1c0");
	}
	#[test]
	fn test_fullresolution() {
		run_model("fullresolution.vp", "c1c1c1c1c0");
	}
	#[test]
	fn test_ql() {
		run_model("ql.vp", "c0");
	}
	#[test]
	fn test_escore_old() {
		run_model("escore_old.vp", "c1c1");
	}
	#[test]
	fn test_test1() {
		run_model("test1.vp", "c1c1c1a1a1a1");
	}
	#[test]
	fn test_test2() {
		run_model("test2.vp", "c0c0c0a0a1a1");
	}
	#[test]
	fn test_test3() {
		run_model("test3.vp", "c1c1c1a1a1a1");
	}
	#[test]
	fn test_test4() {
		run_model("test4.vp", "c0c0c0a0a1a1e0");
	}
	#[test]
	fn test_test5() {
		run_model("test5.vp", "c1c1c1a1a1a1");
	}
	#[test]
	fn test_ffgg() {
		run_model("ffgg.vp", "c1");
	}
	#[test]
	fn test_exa() {
		run_model("exa.vp", "c1");
	}
	#[test]
	fn test_exa2() {
		run_model("exa2.vp", "c1");
	}
	#[test]
	fn test_fakeauth() {
		run_model("fakeauth.vp", "a0");
	}
	#[test]
	fn test_replay_simple() {
		run_model("replay-simple.vp", "a0f0");
	}
	#[test]
	fn test_mwe() {
		run_model("mwe.vp", "c0");
	}
	#[test]
	fn test_password() {
		run_model("password.vp", "c1c1c1c1");
	}
	#[test]
	fn test_dh_equiv() {
		run_model("dh_equiv.vp", "c1c1c1e0");
	}
	#[test]
	fn test_melanie_bugs() {
		run_model("melanie_bugs.vp", "c1c1c1c1c1a1");
	}
	#[test]
	fn test_simple_equiv() {
		run_model("simple_equiv.vp", "e0");
	}
	#[test]
	fn test_ordering_a() {
		run_model("ordering_a.vp", "c1a1");
	}
	#[test]
	fn test_ordering_b() {
		run_model("ordering_b.vp", "c1a1");
	}
	#[test]
	fn test_aead_leak() {
		run_model("aead_leak.vp", "c0");
	}
	#[test]
	fn test_deep_nesting() {
		run_model("deep_nesting.vp", "c0c0c0e1a1");
	}
	#[test]
	fn test_triple_dh() {
		run_model("triple_dh.vp", "c0c0a0e1");
	}
	#[test]
	fn test_key_ratchet() {
		run_model("key_ratchet.vp", "c0c0c0a1a1a0");
	}
	#[test]
	fn test_four_party() {
		run_model("four_party.vp", "c1a0a1a1");
	}
	#[test]
	fn test_phase_forward_secrecy() {
		run_model("phase_forward_secrecy.vp", "c0a0e1");
	}
	#[test]
	fn test_shamir_reconstruction() {
		run_model("shamir_reconstruction.vp", "c1c1e1");
	}
	#[test]
	fn test_blind_signature() {
		run_model("blind_signature.vp", "c0c0a1");
	}
	#[test]
	fn test_concat_bomb() {
		run_model("concat_bomb.vp", "c0c0c0c0c0a0");
	}
	#[test]
	fn test_concat_bomb_leak() {
		run_model("concat_bomb_leak.vp", "c1c1c1c1c1a1");
	}
	#[test]
	fn test_concat_bomb_unguarded() {
		run_model("concat_bomb_unguarded.vp", "c0c0c0c0c0a1");
	}
	#[test]
	fn test_concat_bomb_equiv() {
		run_model("concat_bomb_equiv.vp", "e1e1e1e1e1f0");
	}
	#[test]
	fn test_passive_dh_chain() {
		run_model("passive_dh_chain.vp", "c0c0c0e0");
	}
	#[test]
	fn test_double_ratchet() {
		run_model("double_ratchet.vp", "c0c0a0a0e1e1");
	}
	#[test]
	fn test_many_principals() {
		run_model("many_principals.vp", "c1a0a0a0a0a0f0");
	}
	#[test]
	fn test_psk_with_dh() {
		run_model("psk_with_dh.vp", "c0c0a1a1");
	}
	#[test]
	fn test_concat_password() {
		run_model("concat_password.vp", "c0c0c0");
	}
	#[test]
	fn test_password_aead() {
		run_model("password_aead.vp", "c0");
	}
	#[test]
	fn test_password_underspec() {
		run_model("password_underspec.vp", "c0c1c0c0c0c1c0c1c0c0c1c0");
	}
}
