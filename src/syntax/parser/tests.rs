/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::primitive::Capability;
use crate::syntax::{AttackerKind, Block, CommentStyle};
use crate::term::{Primitive, Value};

#[test]
fn only_the_optional_parse_accepts_a_model_without_queries() {
	let body = "attacker[passive]\nprincipal Alice[\n\tknows private oq_m\n]\n";
	for source in [
		body.to_string(),
		format!("{body}queries[]\n"),
		format!("{body}queries[\n\t// none yet\n]\n"),
	] {
		assert!(parse_string("oq.vp", &source).is_err(), "{source:?}");
		let m = parse_string_queries_optional("oq.vp", &source).expect("parses");
		assert!(m.queries.is_empty());
	}
	for source in [
		format!("{body}queries[\n"),
		format!("{body}queries[]\nphase[1]\n"),
		"attacker[passive]\nqueries[]\n".to_string(),
	] {
		assert!(
			parse_string_queries_optional("oq.vp", &source).is_err(),
			"{source:?}"
		);
	}
	let asked = format!("{body}queries[\n\tconfidentiality? oq_m\n]\n");
	assert_eq!(
		parse_string_queries_optional("oq.vp", &asked)
			.expect("parses")
			.queries
			.len(),
		1
	);
}

#[test]
fn spans_end_at_their_last_character() {
	let src = "attacker[passive]\n\nprincipal Alice[\n\tknows private sp_a\n\tsp_ga = PUBKEY(sp_a)\n]\n\nAlice -> Bob: sp_ga\n\nprincipal Bob[\n\tknows private sp_b\n\t_ = HASH(sp_ga)\n]\n\nqueries[\n\tconfidentiality? sp_a\n\tequivalence? sp_a, sp_b\n\tconfidentiality? sp_b[\n\t\tprecondition[Alice -> Bob: sp_ga]\n\t]\n]\n";
	let m = parse_string("sp.vp", src).expect("parses");
	let text = |span: Span| &src[span.start..span.end];
	let Block::Principal(alice) = &m.blocks[0] else {
		panic!("Alice comes first");
	};
	assert!(text(alice.span).ends_with(']'), "{:?}", text(alice.span));
	assert_eq!(text(alice.expressions[0].span), "knows private sp_a");
	assert_eq!(text(alice.expressions[1].span), "sp_ga = PUBKEY(sp_a)");
	let Block::Message(message) = &m.blocks[1] else {
		panic!("then the message");
	};
	assert_eq!(text(message.span), "Alice -> Bob: sp_ga");
	assert_eq!(text(m.queries[0].span), "confidentiality? sp_a");
	assert_eq!(text(m.queries[1].span), "equivalence? sp_a, sp_b");
	assert_eq!(
		text(m.queries[2].span),
		"confidentiality? sp_b[\n\t\tprecondition[Alice -> Bob: sp_ga]\n\t]"
	);
}

#[test]
fn a_scenarios_block_binds_a_constant_per_principal_instance() {
	let src = "attacker[active]\n\
		principal Alice[\n\
		knows public scn_gpeer\n\
		knows private scn_a\n\
		scn_e = ENC(scn_gpeer, scn_a)\n\
		]\n\
		scenarios[\n\
		Alice[scn_gpeer = scn_gb]\n\
		Alice[scn_gpeer = scn_gm]\n\
		]\n\
		queries[\n\
		confidentiality? scn_a\n\
		]\n";
	let m = parse_string("scn.vp", src).expect("parses");
	assert_eq!(m.scenarios.len(), 2);
	assert_eq!(m.scenarios[0].bindings.len(), 1);
	assert_eq!(&*m.scenarios[0].principal_name, "Alice");
	assert_eq!(&*m.scenarios[0].bindings[0].0.name, "scn_gpeer");
	assert_eq!(&*m.scenarios[0].bindings[0].1.name, "scn_gb");
	assert_eq!(&*m.scenarios[1].bindings[0].1.name, "scn_gm");
}

#[test]
fn a_model_without_scenarios_has_none() {
	let src = "attacker[active]\n\
		principal Alice[\n\
		knows private nsc_a\n\
		]\n\
		queries[\n\
		confidentiality? nsc_a\n\
		]\n";
	let m = parse_string("nsc.vp", src).expect("parses");
	assert!(m.scenarios.is_empty());
}

fn first_assigned(m: &Model) -> String {
	let Block::Principal(p) = &m.blocks[0] else {
		panic!("expected a principal block");
	};
	format!(
		"{:?}",
		p.expressions
			.iter()
			.find_map(|e| e.assigned.as_ref())
			.expect("an assignment")
	)
}

fn first_primitive(m: &Model) -> Option<Primitive> {
	let Block::Principal(p) = &m.blocks[0] else {
		return None;
	};
	p.expressions
		.iter()
		.find_map(|e| match e.assigned.as_ref() {
			Some(Value::Primitive(p)) => Some((**p).clone()),
			_ => None,
		})
}

#[test]
fn parses_a_threshold_parameter() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private thp_k\n\tthp_a, thp_b, thp_c, thp_d, thp_e = THRESHOLD_SPLIT[3](thp_k)\n]\nqueries[\n\tconfidentiality? thp_k\n]\n";
	let m = parse_string("thp.vp", src).expect("parses");
	let p = first_primitive(&m).expect("a primitive");
	assert_eq!(p.threshold, 3);
	assert!(p.capabilities.is_empty());
}

#[test]
fn a_threshold_may_share_its_bracket_with_a_capability() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private thc_k\n\tknows private thc_n\n\tknows private thc_c\n\tknows private thc_m\n\tthc_a, thc_b, thc_c2 = THRESHOLD_SPLIT[2](thc_k)\n\tthc_p = THRESHOLD_SIGN[forgeable](thc_a, thc_n, thc_c, thc_m)\n]\nqueries[\n\tconfidentiality? thc_k\n]\n";
	let m = parse_string("thc.vp", src).expect("parses");
	let Block::Principal(principal) = &m.blocks[0] else {
		panic!("a principal");
	};
	let Some(Value::Primitive(p)) = principal.expressions[5].assigned.as_ref() else {
		panic!("a primitive");
	};
	assert!(p.capabilities.has(Capability::Forgeable));
	assert_eq!(p.threshold, 0);
}

#[test]
fn a_split_without_a_threshold_is_refused() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private thm_k\n\tthm_a, thm_b, thm_c = THRESHOLD_SPLIT(thm_k)\n]\nqueries[\n\tconfidentiality? thm_k\n]\n";
	let err = parse_string("thm.vp", src).expect_err("should reject");
	let text = format!("{}", err);
	assert!(text.contains("threshold"), "got: {}", text);
	assert!(text.contains("THRESHOLD_SPLIT[2]"), "got: {}", text);
}

#[test]
fn a_threshold_on_a_primitive_that_takes_none_is_refused() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private thn_m\n\tthn_h = HASH[3](thn_m)\n]\nqueries[\n\tconfidentiality? thn_m\n]\n";
	let err = parse_string("thn.vp", src).expect_err("should reject");
	let text = format!("{}", err);
	assert!(
		text.contains("HASH") && text.contains("threshold"),
		"got: {}",
		text
	);
}

#[test]
fn a_threshold_declared_twice_is_refused() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private tht_k\n\ttht_a, tht_b, tht_c = THRESHOLD_SPLIT[2, 3](tht_k)\n]\nqueries[\n\tconfidentiality? tht_k\n]\n";
	let err = parse_string("tht.vp", src).expect_err("should reject");
	let text = format!("{}", err);
	assert!(text.contains("twice"), "got: {}", text);
}

#[test]
fn the_old_shamir_names_point_at_their_replacements() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private ths_k\n\tths_a, ths_b, ths_c = SHAMIR_SPLIT(ths_k)\n]\nqueries[\n\tconfidentiality? ths_k\n]\n";
	let err = parse_string("ths.vp", src).expect_err("should reject");
	let text = format!("{}", err);
	assert!(text.contains("THRESHOLD_SPLIT"), "got: {}", text);
}

#[test]
fn parses_primitive_capabilities() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap1_sk\n\tknows private cap1_m\n\tcap1_s = SIGN[forgeable](cap1_sk, cap1_m)\n]\nqueries[\n\tconfidentiality? cap1_m\n]\n";
	let m = parse_string("cap1.vp", src).expect("parses");
	let p = first_primitive(&m).expect("a primitive");
	assert!(p.capabilities.has(Capability::Forgeable));
	assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
	assert!(!p.capabilities.has(Capability::Weak));
}

#[test]
fn parses_capability_with_phase_onset() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap2_k\n\tknows private cap2_m\n\tknows private cap2_ad\n\tknows private cap2_n\n\tcap2_e = AEAD_ENC[forgeable, weak from phase 2](cap2_k, cap2_n, cap2_m, cap2_ad)\n]\nqueries[\n\tconfidentiality? cap2_m\n]\n";
	let m = parse_string("cap2.vp", src).expect("parses");
	let p = first_primitive(&m).expect("a primitive");
	assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
	assert_eq!(p.capabilities.onset(Capability::Weak), Some(2));
}

#[test]
fn rejects_unknown_capability() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap3_m\n\tcap3_h = HASH[bogus](cap3_m)\n]\nqueries[\n\tconfidentiality? cap3_m\n]\n";
	let err = parse_string("cap3.vp", src).expect_err("should reject");
	assert!(
		format!("{}", err).contains("unknown weakening assumption"),
		"got: {}",
		err
	);
}

#[test]
fn rejects_duplicate_capability() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap4_m\n\tcap4_h = HASH[weak, weak](cap4_m)\n]\nqueries[\n\tconfidentiality? cap4_m\n]\n";
	let err = parse_string("cap4.vp", src).expect_err("should reject");
	assert!(
		format!("{}", err).contains("is declared twice on this primitive"),
		"got: {}",
		err
	);
}

#[test]
fn pubkey_parses_to_a_primitive() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private brg_a\n\tbrg_ga = PUBKEY(brg_a)\n]\n\nqueries[\n\tconfidentiality? brg_a\n]\n";
	let m = parse_string("new.vp", src).expect("parses");
	assert!(first_assigned(&m).starts_with("Primitive"));
}

#[test]
fn nested_dh_kex_parses_as_a_nested_primitive() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private brn_a\n\tknows private brn_b\n\tbrn_k = DH_KEX(PUBKEY(brn_a), brn_b)\n]\n\nqueries[\n\tconfidentiality? brn_k\n]\n";
	let m = parse_string("new.vp", src).expect("new parses");
	let Block::Principal(p) = &m.blocks[0] else {
		panic!("expected a principal block");
	};
	let assigned = p
		.expressions
		.iter()
		.find_map(|e| e.assigned.as_ref())
		.expect("an assignment");
	let Value::Primitive(outer) = assigned else {
		panic!("expected a primitive, got {:?}", assigned);
	};
	assert_eq!(outer.id, primitive_get_enum("DH_KEX").unwrap());
	assert_eq!(outer.arguments.len(), 2);
	let Value::Primitive(inner) = &outer.arguments[0] else {
		panic!("expected PUBKEY in argument 0");
	};
	assert_eq!(inner.id, primitive_get_enum("PUBKEY").unwrap());
}

fn model_error(src: &str) -> String {
	let m = match parse_string("diag.vp", src) {
		Ok(m) => m,
		Err(e) => return e.to_string(),
	};
	crate::protocol::sanity::sanity(&m)
		.err()
		.map(|e| e.located(&m.file_name, &m.source).to_string())
		.unwrap_or_default()
}

#[test]
fn an_error_narrows_to_a_name_written_in_another_case() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private nc_m\n]\nqueries[\n\tconfidentiality? NC_UNKNOWN\n]\n",
	);
	assert!(text.contains("diag.vp:6:19"), "{text}");
}

#[test]
fn a_query_line_opening_with_a_multibyte_character_is_a_parse_error() {
	let src =
		"attacker[active]\nprincipal Alice[\n\tknows private mb_m\n]\nqueries[\n\t€x? mb_m\n]\n";
	let error = parse_string("mb.vp", src).expect_err("not a query");
	let text = error.render("mb.vp", src);
	assert!(text.contains("expected a query"), "{text}");
	assert!(text.contains("mb.vp:6:2"), "{text}");
}

#[test]
fn a_mistyped_primitive_is_a_parse_error_that_suggests_the_real_one() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private dm_m\n\tdm_e = AEAD_ENCC(dm_m, dm_m, dm_m)\n]\nqueries[\n\tconfidentiality? dm_m\n]\n",
	);
	assert!(
		text.contains("parse error: unknown primitive `AEAD_ENCC`"),
		"{text}"
	);
	assert!(text.contains("diag.vp:4:9"), "{text}");
	assert!(text.contains("did you mean `AEAD_ENC`?"), "{text}");
}

#[test]
fn a_wrong_arity_names_the_primitive_signature() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private wa_m\n\twa_e = AEAD_ENC(wa_m, wa_m, wa_m)\n]\nqueries[\n\tconfidentiality? wa_m\n]\n",
	);
	assert!(
		text.contains("`AEAD_ENC` takes 4 arguments, but 3 were given"),
		"{text}"
	);
	assert!(
		text.contains("its signature is `AEAD_ENC(key, nonce, plaintext, ad)`"),
		"{text}"
	);
	assert!(
		text.contains("take a nonce as their second argument"),
		"{text}"
	);
}

fn scenario_model(tail: &str) -> String {
	format!(
		"attacker[active]\n\
		 principal Bob[\n\
		 knows private sb_b\n\
		 sb_gb = PUBKEY(sb_b)\n\
		 ]\n\
		 Bob -> Alice: [sb_gb]\n\
		 principal Alice[\n\
		 knows public sb_gpeer\n\
		 knows private sb_m\n\
		 sb_e = PKE_ENC(sb_gpeer, sb_m)\n\
		 ]\n\
		 Alice -> Bob: sb_e\n\
		 principal Bob[\n\
		 _ = HASH(sb_e)\n\
		 ]\n{tail}"
	)
}

#[test]
fn a_model_declares_at_most_one_scenarios_block() {
	let src = scenario_model(
		"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
		 scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
		 queries[\nconfidentiality? sb_m\n]\n",
	);
	let error = parse_string("sb.vp", &src).expect_err("two blocks are refused");
	assert!(
		error.message.contains("at most one `scenarios` block"),
		"got: {}",
		error.message
	);
}

#[test]
fn a_scenarios_block_comes_directly_before_queries() {
	for tail in [
		// Something between the block and `queries`.
		"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
		 principal Bob[\n_ = HASH(sb_gb)\n]\n\
		 queries[\nconfidentiality? sb_m\n]\n",
		// The block after `queries`, which closes the model.
		"queries[\nconfidentiality? sb_m\n]\n\
		 scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n",
	] {
		let error = parse_string("sb.vp", &scenario_model(tail)).expect_err("misplaced block");
		assert!(
			error
				.message
				.contains("must come directly before `queries`"),
			"got: {}",
			error.message
		);
	}
}

#[test]
fn one_scenarios_block_directly_before_queries_is_accepted() {
	let src = scenario_model(
		"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
		 queries[\nconfidentiality? sb_m\n]\n",
	);
	let m = parse_string("sb.vp", &src).expect("the one legal placement");
	assert_eq!(m.scenarios.len(), 1);
}

#[test]
fn a_block_comment_may_follow_a_multi_constant_query() {
	let src = "attacker[passive]\n\
		principal Alice[\n\
		knows private bc_k1\n\
		knows private bc_k2\n\
		_ = HASH(bc_k1, bc_k2)\n\
		]\n\
		queries[\n\
		equivalence? bc_k1, bc_k2\n\
		/* between two queries */\n\
		freshness? bc_k1\n\
		]\n";
	let m = parse_string("bc.vp", src).expect("a block comment ends a query's constant list");
	assert_eq!(m.queries.len(), 2);
}

#[test]
fn every_keyword_is_recognised_whatever_its_case() {
	let src = "ATTACKER[passive]\n\
		PRINCIPAL Alice[\n\
		KNOWS private ci_m\n\
		GENERATES ci_n\n\
		ci_h = HASH(ci_m, ci_n)\n\
		LEAKS ci_m\n\
		]\n\
		Alice -> Bob: ci_h\n\
		PRINCIPAL Bob[\n\
		_ = HASH(ci_h)\n\
		]\n\
		PHASE[1]\n\
		PRINCIPAL Bob[\n\
		_ = HASH(nil)\n\
		]\n\
		QUERIES[\n\
		CONFIDENTIALITY? ci_m\n\
		FRESHNESS? ci_n\n\
		AUTHENTICATION? Alice -> Bob: ci_h\n\
		]\n";
	let m = parse_string("ci.vp", src)
		.expect("identifiers are case-insensitive, and so are the keywords around them");
	assert_eq!(m.queries.len(), 3);
	assert_eq!(m.attacker, AttackerKind::Passive);
	assert!(
		m.blocks
			.iter()
			.any(|b| matches!(b, Block::Phase(p) if p.number == 1)),
		"`PHASE[1]` declares a phase"
	);
	let declarations: Vec<Declaration> = m
		.blocks
		.iter()
		.filter_map(|b| match b {
			Block::Principal(p) => Some(p.expressions.iter().map(|e| e.kind)),
			_ => None,
		})
		.flatten()
		.collect();
	assert!(declarations.contains(&Declaration::Knows));
	assert!(declarations.contains(&Declaration::Generates));
	assert!(declarations.contains(&Declaration::Leaks));
}

#[test]
fn every_primitive_name_is_reserved() {
	let shadowable: Vec<&str> = crate::primitive::primitive_names()
		.into_iter()
		.filter(|name| check_reserved(&name.to_lowercase()).is_ok())
		.collect();
	assert!(
		shadowable.is_empty(),
		"a primitive whose name is not reserved can be shadowed by a constant, \
		 so the same identifier means one thing at a call site and another as a \
		 value; the reserved check reads the registry, so a new primitive is \
		 reserved by declaring it: {shadowable:?}"
	);
}

#[test]
fn a_mistyped_constant_suggests_one_that_exists() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private mc_secret\n\tmc_x = HASH(mc_secret)\n]\nqueries[\n\tconfidentiality? mc_secrt\n]\n",
	);
	assert!(text.contains("unknown constant `mc_secrt`"), "{text}");
	assert!(text.contains("did you mean `mc_secret`?"), "{text}");
}

#[test]
fn a_rebound_constant_points_at_both_assignments() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private rb_m\n\trb_x = HASH(rb_m)\n\trb_x = HASH(rb_x)\n]\nqueries[\n\tconfidentiality? rb_m\n]\n",
	);
	assert!(text.contains("`rb_x` is assigned twice"), "{text}");
	assert!(text.contains("already assigned here"), "{text}");
	assert!(text.contains("assigned again here"), "{text}");
	assert!(text.contains("\n4 |"), "{text}");
	assert!(text.contains("\n5 |"), "{text}");
}

#[test]
fn an_unclosed_delimiter_is_pointed_at_from_where_parsing_failed() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private ud_m\n\tud_x = HASH(ud_m\n]\nqueries[\n\tconfidentiality? ud_m\n]\n",
	);
	assert!(text.contains("this `(` is never closed"), "{text}");
	assert!(text.contains("add the missing `)`"), "{text}");
}

#[test]
fn an_unterminated_block_comment_is_named_rather_than_its_consequence() {
	let text = model_error(
		"attacker[active]\n/* never closed\nprincipal Alice[\n\tknows private ub_m\n]\n",
	);
	assert!(text.contains("unterminated block comment"), "{text}");
	assert!(text.contains("this `/*` is never closed"), "{text}");
}

#[test]
fn a_message_a_principal_sends_to_itself_names_that_rule() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private sm_m\n]\nAlice -> Alice: sm_m\nqueries[\n\tconfidentiality? sm_m\n]\n",
	);
	assert!(
		text.contains("Alice both sends and receives this message"),
		"{text}"
	);
	assert!(
		text.contains("a message travels between two different principals"),
		"{text}"
	);
}

#[test]
fn a_closed_delimiter_is_never_reported_as_unclosed() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private cd_m\n\tcd_x = NOTAPRIM(cd_m)\n]\nqueries[\n\tconfidentiality? cd_m\n]\n",
	);
	assert!(text.contains("unknown primitive `NOTAPRIM`"), "{text}");
	assert!(!text.contains("is never closed"), "{text}");
}

#[test]
fn an_undeclared_principal_is_named_where_it_is_used() {
	let text = model_error(
		"attacker[active]\nprincipal Alice[\n\tknows private up_m\n\tup_x = HASH(up_m)\n]\nAlice -> Bobb: up_x\nqueries[\n\tconfidentiality? up_m\n]\n",
	);
	assert!(
		text.contains("`Bobb` is never declared as a principal"),
		"{text}"
	);
	assert!(text.contains("no block declares this principal"), "{text}");
}

fn sanity_error_for(assignment: &str) -> String {
	let src = format!(
		"attacker[active]\n\nprincipal Alice[\n\tknows private brc_a\n\t{}\n]\n\nqueries[\n\tconfidentiality? brc_a\n]\n",
		assignment
	);
	let m = parse_string("bad.vp", &src).expect("parses");
	crate::protocol::sanity::sanity(&m)
		.err()
		.map(|e| e.to_string())
		.unwrap_or_default()
}

#[test]
fn bridged_primitives_reject_checking_like_any_other() {
	for assignment in [
		"brc_x = HASH(brc_a)?",
		"brc_x = PUBKEY(brc_a)?",
		"brc_x = DH_KEX(brc_a, brc_a)?",
	] {
		let error = sanity_error_for(assignment);
		assert!(
			error.contains("cannot be checked with `?`"),
			"got: {}",
			error
		);
	}
}

#[test]
fn bridged_primitives_reject_bad_arity_from_the_spec() {
	assert!(
		sanity_error_for("brc_x = PUBKEY(brc_a, brc_a)")
			.contains("takes 1 argument, but 2 were given")
	);
	assert!(
		sanity_error_for("brc_x = DH_KEX(brc_a)").contains("takes 2 arguments, but 1 was given")
	);
}

#[test]
fn parse_rejects_content_after_queries() {
	let model = concat!(
		"attacker[active]\n",
		"principal Alice[ knows private x ]\n",
		"Alice -> Bob: x\n",
		"principal Bob[]\n",
		"queries[ confidentiality? x ]\n",
		"phase[1]\n",
		"principal Alice[ leaks x ]\n",
	);
	assert!(crate::syntax::parser::parse_string("after_queries.vp", model).is_err());
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
	assert!(crate::syntax::parser::parse_string("before_queries.vp", model).is_ok());
}

#[test]
fn comment_capture_pre_attacker_line() {
	let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(
		m.attacker_comments.leading.len(),
		1,
		"expected 1 pre-attacker comment"
	);
	assert_eq!(m.attacker_comments.leading[0].text, " hello");
	assert!(matches!(
		m.attacker_comments.leading[0].style,
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
			assert_eq!(p.comments.leading.len(), 1);
			assert_eq!(p.comments.leading[0].text, " before alice");
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
			assert_eq!(p.expressions[0].comments.leading.len(), 1);
			assert_eq!(p.expressions[0].comments.leading[0].text, " long-term key");
		}
		_ => panic!("expected Principal block"),
	}
}

#[test]
fn comment_capture_leading_on_query() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.queries.len(), 1);
	assert_eq!(m.queries[0].comments.leading.len(), 1);
	assert_eq!(m.queries[0].comments.leading[0].text, " primary goal");
}

#[test]
fn comment_capture_leading_on_queries_keyword() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// verify these\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.queries_comments.leading.len(), 1);
	assert_eq!(m.queries_comments.leading[0].text, " verify these");
}

#[test]
fn comment_capture_multiple_lines() {
	let src = "// line 1\n// line 2\n// line 3\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.attacker_comments.leading.len(), 3);
	assert_eq!(m.attacker_comments.leading[0].text, " line 1");
	assert_eq!(m.attacker_comments.leading[1].text, " line 2");
	assert_eq!(m.attacker_comments.leading[2].text, " line 3");
}

#[test]
fn comment_capture_block_pre_attacker() {
	let src = "/* hello */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.attacker_comments.leading.len(), 1);
	assert_eq!(m.attacker_comments.leading[0].text, " hello ");
	assert!(matches!(
		m.attacker_comments.leading[0].style,
		CommentStyle::Block
	));
}

#[test]
fn comment_capture_block_multiline() {
	let src = "/* line1\n   line2\n   line3 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.attacker_comments.leading.len(), 1);
	assert_eq!(
		m.attacker_comments.leading[0].text,
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
			assert!(p.expressions[0].comments.trailing.is_some());
			assert_eq!(
				p.expressions[0].comments.trailing.as_ref().unwrap().text,
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
	assert!(m.attacker_comments.trailing.is_some());
	assert_eq!(
		m.attacker_comments.trailing.as_ref().unwrap().text,
		" active model"
	);
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
	assert!(msg.comments.trailing.is_some());
	assert_eq!(
		msg.comments.trailing.as_ref().unwrap().text,
		" initial flight"
	);
}

#[test]
fn comment_capture_trailing_on_query() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a // primary\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert!(m.queries[0].comments.trailing.is_some());
	assert_eq!(
		m.queries[0].comments.trailing.as_ref().unwrap().text,
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
				.comments
				.trailing
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
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* multi\n\tline */\n\tknows private b\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	match &m.blocks[0] {
		Block::Principal(p) => {
			assert!(p.expressions[0].comments.trailing.is_none());
			assert_eq!(p.expressions[1].comments.leading.len(), 1);
			assert_eq!(p.expressions[1].comments.leading[0].text, " multi\n\tline ");
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
			assert_eq!(p.comments.tail.len(), 1);
			assert_eq!(p.comments.tail[0].text, " TODO add more");
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
			assert!(p.comments.closing.is_some());
			assert_eq!(p.comments.closing.as_ref().unwrap().text, " end of Alice");
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
			assert!(p.comments.opening.is_some());
			assert_eq!(p.comments.opening.as_ref().unwrap().text, " initiator");
		}
		_ => panic!(),
	}
}

#[test]
fn comment_capture_tail_in_queries() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n\t// done\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert_eq!(m.queries_comments.tail.len(), 1);
	assert_eq!(m.queries_comments.tail[0].text, " done");
}

#[test]
fn comment_capture_queries_closing_trailing() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n] // end\n";
	let m = parse_string("t.vp", src).expect("parse");
	assert!(m.queries_comments.closing.is_some());
	assert_eq!(m.queries_comments.closing.as_ref().unwrap().text, " end");
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
	assert!(m.queries_comments.opening.is_some());
	assert_eq!(m.queries_comments.opening.as_ref().unwrap().text, " start");
}

#[test]
fn comment_lookahead_does_not_leak() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a\n// next block\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	let msg = m
		.blocks
		.iter()
		.find_map(|b| match b {
			Block::Message(m) => Some(m),
			_ => None,
		})
		.expect("message");
	assert!(msg.comments.trailing.is_none());
	let bob = m
		.blocks
		.iter()
		.find_map(|b| match b {
			Block::Principal(p) if p.name == "Bob" => Some(p),
			_ => None,
		})
		.expect("bob");
	assert_eq!(bob.comments.leading.len(), 1);
	assert_eq!(bob.comments.leading[0].text, " next block");
}

#[test]
fn comment_in_primitive_args_is_kept_on_the_expression() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tx = ENC(/* secret */ a, a)\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
	let m = parse_string("t.vp", src).expect("parse");
	let Block::Principal(alice) = &m.blocks[0] else {
		panic!("Alice's block");
	};
	let comments = &alice.expressions[1].comments.leading;
	assert_eq!(comments.len(), 1, "{comments:?}");
	assert_eq!(comments[0].text.trim(), "secret");
}

#[test]
fn caret_is_rejected() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private crj_a\n\tcrj_ga = G^crj_a\n]\n\nqueries[\n\tconfidentiality? crj_a\n]\n";
	assert!(parse_string("old.vp", src).is_err());
}

#[test]
fn kem_primitive_names_are_reserved() {
	for name in ["kem_encap", "kem_decap"] {
		let src = format!(
			"attacker[active]\n\nprincipal Alice[\n\tknows private {}\n]\n\nqueries[\n\tconfidentiality? {}\n]\n",
			name, name
		);
		assert!(parse_string("reserved.vp", &src).is_err());
	}
}

#[test]
fn bare_generator_is_rejected() {
	let src = "attacker[active]\n\nprincipal Alice[\n\tknows private crk_a\n\tcrk_x = HASH(G)\n]\n\nqueries[\n\tconfidentiality? crk_a\n]\n";
	assert!(parse_string("old.vp", src).is_err());
}

#[test]
fn file_name_limit_counts_characters_instead_of_bytes() {
	let accepted = format!("{}.vp", "é".repeat(61));
	let rejected = format!("{}.vp", "é".repeat(62));
	assert_eq!(accepted.chars().count(), 64);
	assert!(accepted.len() > 64);
	assert!(validate_file_name(&accepted, &accepted).is_ok());
	assert!(validate_file_name(&rejected, &rejected).is_err());
}

#[test]
fn a_line_comment_token_stops_before_a_carriage_return() {
	let src = "// note\r\nattacker[active]\r\nprincipal Alice[\r\n\tknows public pc_crlf\r\n]\r\n\
	           queries[\r\n\tconfidentiality? pc_crlf\r\n]\r\n";
	let (model, index) = parse_string_indexed("crlf.vp", src);
	model.expect("parses");
	let token = index.at(0).expect("the comment token");
	assert_eq!(&src[token.span.start..token.span.end], "// note");
}

#[test]
fn a_leading_byte_order_mark_is_skipped() {
	let src = "\u{FEFF}attacker[active]\nprincipal Alice[\n\tknows public pc_bom\n]\n\
	           queries[\n\tconfidentiality? pc_bom\n]\n";
	parse_string("bom.vp", src).expect("a BOM is not part of the model");
}
