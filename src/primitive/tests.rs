/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::protocol::SlotIdx;
use crate::util::index::Idx;

#[test]
fn solver_variables_are_not_admissible_messages() {
	for variable in [
		crate::solve::vars::attacker_var(SlotIdx::new(0)),
		crate::solve::vars::free_var(0),
	] {
		assert!(!admissible(&variable));
		let term = Value::primitive(PRIM_HASH, vec![variable], 0);
		assert!(!admissible(&term));
		assert!(admissible(&crate::solve::vars::ground_free(
			&Value::primitive(PRIM_HASH, vec![crate::solve::vars::free_var(0)], 0)
		)));
	}
}

#[test]
fn admissibility_visits_shared_terms_once() {
	let key = crate::testing::make_private("admissible_dag_key");
	let public = Value::primitive(PRIM_PUBKEY, vec![key], 0);
	let mut term = public.clone();
	for _ in 0..40 {
		term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
	}
	assert!(admissible(&term));
	let invalid = Value::primitive(PRIM_PUBKEY, vec![public], 0);
	let wrapped = Value::primitive(PRIM_HASH, vec![term, invalid], 0);
	assert!(!admissible(&wrapped));
}

#[test]
fn pubkey_and_dh_kex_resolve_by_name() {
	assert!(id_of("PUBKEY").is_ok());
	assert!(id_of("DH_KEX").is_ok());
}

#[test]
fn identifying_positions_table() {
	assert_eq!(
		super::spec(PRIM_SIGNVERIF).unwrap().identifying_positions,
		vec![0]
	);
	assert_eq!(
		super::spec(PRIM_AEAD_DEC).unwrap().identifying_positions,
		vec![0]
	);
	assert_eq!(
		super::spec(PRIM_KEM_DECAP).unwrap().identifying_positions,
		vec![0]
	);
	assert!(
		super::spec(PRIM_RINGSIGNVERIF)
			.unwrap()
			.identifying_positions
			.is_empty()
	);
}

#[test]
fn pubkey_is_the_key_derivation_constructor() {
	assert!(is_key_derivation(id_of("PUBKEY").unwrap()));
	assert!(!is_key_derivation(id_of("DH_KEX").unwrap()));
	assert!(!is_key_derivation(PRIM_HASH));
}

#[test]
fn neither_new_primitive_may_be_checked() {
	for name in ["PUBKEY", "DH_KEX"] {
		let id = id_of(name).unwrap();
		assert!(!definition(id).unwrap().definition_check());
	}
}

#[test]
fn new_primitive_arities_come_from_the_spec() {
	let pk = definition(id_of("PUBKEY").unwrap()).unwrap();
	assert_eq!(pk.arity(), &[1]);
	let dh = definition(id_of("DH_KEX").unwrap()).unwrap();
	assert_eq!(dh.arity(), &[2]);
}

#[test]
fn primitive_def_core() {
	let def = definition(PRIM_ASSERT).unwrap();
	assert_eq!(def.name(), "ASSERT");
	assert!(def.definition_check());
}

#[test]
fn primitive_def_non_core() {
	let def = definition(PRIM_AEAD_ENC).unwrap();
	assert_eq!(def.name(), "AEAD_ENC");
	assert!(!def.definition_check());
}

#[test]
fn primitive_def_check_property() {
	let dec = definition(PRIM_AEAD_DEC).unwrap();
	assert!(dec.definition_check());
	let enc = definition(PRIM_ENC).unwrap();
	assert!(!enc.definition_check());
}

#[test]
fn primitive_is_core_check() {
	assert!(is_core(PRIM_ASSERT));
	assert!(is_core(PRIM_CONCAT));
	assert!(is_core(PRIM_SPLIT));
	assert!(!is_core(PRIM_HASH));
	assert!(!is_core(PRIM_AEAD_ENC));
}

#[test]
fn primitive_name_lookup() {
	assert_eq!(name(PRIM_HASH), "HASH");
	assert_eq!(name(PRIM_SIGN), "SIGN");
	assert_eq!(name(PRIM_CONCAT), "CONCAT");
}

#[test]
fn primitive_get_enum_roundtrip() {
	let id = id_of("AEAD_ENC").unwrap();
	assert_eq!(id, PRIM_AEAD_ENC);
	let id2 = id_of("SPLIT").unwrap();
	assert_eq!(id2, PRIM_SPLIT);
	assert!(id_of("NONEXISTENT").is_err());
}

#[test]
fn primitive_single_output() {
	assert!(has_single_output(PRIM_HASH));
	assert!(has_single_output(PRIM_ENC));
	assert!(!has_single_output(PRIM_SPLIT));
	assert!(!has_single_output(PRIM_HKDF));
}

#[test]
fn normalisation_collapses_an_exchange_of_two_public_keys() {
	use crate::testing::*;
	let a = make_constant("nrm_a");
	let b = make_constant("nrm_b");
	let ga = make_primitive(PRIM_PUBKEY, vec![a], 0);
	let gb = make_primitive(PRIM_PUBKEY, vec![b.clone()], 0);
	let normalised = normalise_arguments(PRIM_DH_KEX, vec![ga.clone(), gb]);
	assert!(normalised[0].equivalent(&ga, true));
	assert!(
		normalised[1].equivalent(&b, true),
		"the forbidden PUBKEY at the bare position is peeled away"
	);
	let twice = normalise_arguments(PRIM_DH_KEX, normalised.clone());
	assert!(twice[0].equivalent(&normalised[0], true));
	assert!(twice[1].equivalent(&normalised[1], true));
	let gga = normalise_arguments(PRIM_PUBKEY, vec![ga.clone()]);
	assert!(gga[0].equivalent(&make_constant("nrm_a"), true));
}

#[test]
fn a_commutativity_rule_exchanges_positions_with_equal_restrictions() {
	for spec in prim_specs() {
		let Some(rule) = &spec.commutativity else {
			continue;
		};
		let bare: Vec<PrimitiveId> = argument_restrictions(spec.id)
			.iter()
			.find(|restriction| restriction.position == rule.bare)
			.map(|restriction| restriction.banned.clone())
			.unwrap_or_default();
		let wrapped: Vec<PrimitiveId> = argument_restrictions(rule.constructor)
			.iter()
			.find(|restriction| restriction.position == 0)
			.map(|restriction| restriction.banned.clone())
			.unwrap_or_default();
		let mut bare = bare;
		let mut wrapped = wrapped;
		bare.sort_unstable();
		wrapped.sort_unstable();
		assert_eq!(
			bare,
			wrapped,
			"{}'s bare position and {}'s argument must forbid the same heads",
			spec.name,
			name(rule.constructor)
		);
	}
}

#[test]
fn normalisation_does_not_enforce_the_unpeelable_restrictions() {
	use crate::testing::*;
	let a = make_constant("adm_a");
	let b = make_constant("adm_b");
	let ga = make_primitive(PRIM_PUBKEY, vec![a.clone()], 0);
	let shared = make_primitive(PRIM_DH_KEX, vec![ga.clone(), b.clone()], 0);
	let nested = normalise_arguments(PRIM_PUBKEY, vec![shared.clone()]);
	assert!(nested[0].equivalent(&shared, true), "not peeled");
	let violating = make_primitive(PRIM_PUBKEY, vec![shared.clone()], 0);
	assert!(!admissible(&violating));
	let stacked = make_primitive(PRIM_DH_KEX, vec![shared.clone(), b], 0);
	assert!(!admissible(&stacked));
	assert!(admissible(&shared));
	assert!(admissible(&ga));
	assert!(admissible(&a));
}

#[test]
fn a_check_key_is_declared_only_on_a_primitive_that_can_be_checked() {
	for spec in super::spec::build_primitive_specs() {
		assert!(
			spec.check_key.is_none() || spec.definition_check,
			"{} declares a checking key but cannot take `?`",
			spec.name
		);
	}
}

#[test]
fn a_checkable_primitive_fails_only_through_its_declared_rule() {
	for spec in prim_specs().filter(|spec| spec.definition_check) {
		assert!(
			spec.rewrite.is_some(),
			"{} can take `?` but declares no rewrite rule; the judge reads a failed check \
			 as the run halting at that slot, which only a rule can cause",
			spec.name
		);
	}
	for spec in core_specs().filter(|spec| spec.definition_check) {
		assert!(
			spec.core_rule.is_some(),
			"{} can take `?` but declares no core rule",
			spec.name
		);
	}
}

#[test]
fn every_spec_index_is_within_the_primitive_it_is_declared_on() {
	fn narrowest(arity: &[i32]) -> usize {
		arity.iter().copied().min().unwrap_or(0).max(0) as usize
	}
	fn widest(arity: &[i32]) -> usize {
		arity.iter().copied().max().unwrap_or(0).max(0) as usize
	}

	for spec in prim_specs() {
		let name = spec.name;
		let least = narrowest(&spec.arity);
		let most = widest(&spec.arity);
		let outputs = widest(&spec.output);
		assert!(least > 0, "{name} declares no arity");

		let must = |what: &str, i: usize| {
			assert!(
				i < least,
				"{name}.{what} is argument {i}, but a {name} call may have as few as \
				 {least} arguments, and the engine indexes this position directly"
			);
		};
		let may = |what: &str, i: usize| {
			assert!(
				i < most,
				"{name}.{what} is argument {i}, but {name} takes at most {most} \
				 arguments, so this entry can never apply"
			);
		};
		let out = |what: &str, i: usize| {
			assert!(
				i < outputs,
				"{name}.{what} is output {i}, but {name} has {outputs} outputs"
			);
		};

		if let Some(rule) = &spec.decompose {
			if let Some(output) = rule.output {
				assert!(
					output < outputs,
					"{name}.decompose.output is output {output}, but {name} has \
					 {outputs} outputs"
				);
			}
			for reveal in &rule.reveals {
				match *reveal {
					Reveal::Argument(i) => must("decompose.reveal", i),
					Reveal::Output(i) => out("decompose.reveal_output", i),
				}
			}
			for &i in &rule.given {
				may("decompose.given", i);
			}
		}

		if let Some(rule) = &spec.recompose {
			must("recompose.reveal", rule.reveal);
			assert!(
				spec.threshold.is_some(),
				"{name} recomposes from its outputs, so it needs a threshold to count them against"
			);
		}

		if let Some(rule) = &spec.rewrite {
			must("rewrite.from", rule.from);
			let inner = super::spec(rule.id)
				.unwrap_or_else(|_| panic!("{name}.rewrite.id is not a primitive"));
			if let Some(output) = rule.from_output {
				assert!(
					output < widest(&inner.output),
					"{name}.rewrite.from_output is output {output} of {}, which has \
					 {} outputs",
					inner.name,
					widest(&inner.output)
				);
			}
			for (outer, inners) in &rule.matching {
				may("rewrite.matching", *outer);
				for &i in inners {
					assert!(
						i < widest(&inner.arity),
						"{name}.rewrite.matching points at argument {i} of {}, which \
						 takes at most {} arguments",
						inner.name,
						widest(&inner.arity)
					);
				}
			}
		}

		if let Some(rule) = &spec.rebuild {
			let inner = super::spec(rule.id)
				.unwrap_or_else(|_| panic!("{name}.rebuild.id is not a primitive"));
			assert!(
				rule.reveal < narrowest(&inner.arity),
				"{name}.rebuild.reveal is argument {} of {}, which may have as few \
				 as {} arguments, and the engine indexes it directly",
				rule.reveal,
				inner.name,
				narrowest(&inner.arity)
			);
			assert!(
				inner.threshold.is_some(),
				"{name}.rebuild counts shares of {}, which declares no threshold",
				inner.name
			);
		}

		for rule in &spec.combine {
			let partial = super::spec(rule.partial)
				.unwrap_or_else(|_| panic!("{name}.combine.partial is not a primitive"));
			let split = super::spec(rule.split)
				.unwrap_or_else(|_| panic!("{name}.combine.split is not a primitive"));
			let whole = super::spec(rule.whole)
				.unwrap_or_else(|_| panic!("{name}.combine.whole is not a primitive"));
			let fewest = narrowest(&partial.arity);
			for binding in &rule.bindings {
				assert!(binding.argument < fewest && binding.list < fewest);
				assert!(super::spec(binding.wrapper).unwrap().arity.contains(&1));
				assert!(is_core(binding.sequence));
			}
			for (what, i) in std::iter::once(("combine.share", rule.share))
				.chain(rule.agree.iter().map(|&i| ("combine.agree", i)))
				.chain(rule.carry.iter().map(|&i| ("combine.carry", i)))
			{
				assert!(
					i < fewest,
					"{name}.{what} is argument {i} of {}, which may have as few as {fewest} \
					 arguments, and the engine indexes it directly",
					partial.name
				);
			}
			assert!(
				!rule.agree.contains(&rule.share) && !rule.carry.contains(&rule.share),
				"{name}.combine names the share position as one that agrees or carries"
			);
			assert!(
				split.threshold.is_some(),
				"{name}.combine counts shares of {}, which declares no threshold",
				split.name
			);
			assert!(
				whole.arity.contains(&((1 + rule.carry.len()) as i32)),
				"{name}.combine builds {} from the secret and {} carried arguments, \
				 which is not an arity it takes",
				whole.name,
				rule.carry.len()
			);
		}

		match spec.check_key {
			Some(CheckKeyKind::Direct(i)) => must("check_key", i),
			Some(CheckKeyKind::Derived {
				arg: i,
				constructor,
			}) => {
				must("check_key", i);
				assert!(
					super::spec(constructor).is_ok(),
					"{name}.check_key names a constructor that is not a primitive"
				);
			}
			None => {}
		}

		if let Some(rule) = &spec.commutativity {
			must("commutativity.wrapped", rule.wrapped);
			must("commutativity.bare", rule.bare);
			assert!(
				super::spec(rule.constructor).is_ok(),
				"{name}.commutativity names a constructor that is not a primitive"
			);
		}

		for reveal in &spec.weak_reveals {
			match *reveal {
				Reveal::Argument(i) => may("weak_reveals", i),
				Reveal::Output(i) => out("weak_reveals_output", i),
			}
		}
		if let Some(i) = spec.forgeable_secret {
			may("forgeable_secret", i);
		}
		for &i in &spec.malleable_vary {
			may("malleable_vary", i);
		}
		for &i in &spec.identifying_positions {
			may("identifying_positions", i);
		}
		if let Some(rule) = &spec.reuse {
			for &i in &rule.fixed {
				must("reuse.fixed", i);
			}
			for &i in &rule.forgeable {
				must("reuse.forgeable", i);
			}
			for reveal in &rule.reveals {
				match *reveal {
					Reveal::Argument(i) => must("reuse.reveal", i),
					Reveal::Output(i) => out("reuse.reveal_output", i),
				}
			}
		}

		if let Some((arity, help)) = spec.arity_help {
			assert!(
				!spec.arity.contains(&arity) && !help.is_empty(),
				"{name}.arity_help names an arity the primitive accepts, or says nothing"
			);
		}

		for restriction in &spec.argument_restrictions {
			may("argument_restrictions", restriction.position);
			for &id in &restriction.banned {
				assert!(
					super::spec(id).is_ok() || core_spec(id).is_ok(),
					"{name}.argument_restrictions bans an id that is not a primitive"
				);
			}
		}

		assert_eq!(
			spec.arg_names.len(),
			most,
			"{name} names {} arguments but takes up to {most}",
			spec.arg_names.len(),
		);
	}

	for spec in core_specs() {
		assert_eq!(
			spec.arg_names.len(),
			widest(&spec.arity),
			"{} names {} arguments but takes up to {}",
			spec.name,
			spec.arg_names.len(),
			widest(&spec.arity),
		);
	}
}

#[test]
fn the_engine_names_no_primitive_outside_its_spec() {
	let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	let names = names();
	let mut offenders: Vec<String> = Vec::new();
	let mut scanned = 0usize;
	let mut stack = vec![root.clone()];
	while let Some(dir) = stack.pop() {
		for entry in std::fs::read_dir(&dir).expect("read src") {
			let path = entry.expect("entry").path();
			if path.is_dir() {
				stack.push(path);
				continue;
			}
			if path.extension().is_none_or(|e| e != "rs") {
				continue;
			}
			let rel = path
				.strip_prefix(&root)
				.expect("under src")
				.to_string_lossy()
				.replace('\\', "/");
			if rel.starts_with("primitive/")
				|| rel.starts_with("testing/")
				|| rel.rsplit('/').next() == Some("tests.rs")
			{
				continue;
			}
			let text = std::fs::read_to_string(&path).expect("read");
			let code = crate::testing::shipping_code(&rel, &text);
			scanned += 1;
			for (n, line) in code.lines().enumerate() {
				let line = line.trim();
				if line.starts_with("//") {
					continue;
				}
				let quotes_one = names.iter().any(|name| {
					line.contains(&format!("\"{name}\""))
						|| line.contains(&format!("\"{}\"", name.to_lowercase()))
				});
				if line.contains("PRIM_") || quotes_one {
					offenders.push(format!("{rel}:{}: {line}", n + 1));
				}
			}
		}
	}
	assert!(
		scanned > 0,
		"the scan found no engine source under {}",
		root.display()
	);
	assert!(
		offenders.is_empty(),
		"a primitive is declared once, in src/primitive/spec.rs, and the engine \
		 interprets what the spec says; a line that names one by id or by name is \
		 semantics the spec should carry as a field the engine reads generically. \
		 Add the field, not the branch:\n  {}",
		offenders.join("\n  ")
	);
}
