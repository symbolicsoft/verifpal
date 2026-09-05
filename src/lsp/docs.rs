/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: CC-BY-SA-4.0 */

use std::sync::LazyLock;

pub(crate) struct Entry {
	pub name: &'static str,
	pub eg: &'static str,
	pub help: &'static str,
}

pub(crate) static PRIMITIVES: LazyLock<Vec<Entry>> = LazyLock::new(|| {
	crate::primitive::primitive_docs()
		.into_iter()
		.map(|(name, doc)| Entry {
			name,
			eg: doc.example,
			help: doc.help,
		})
		.collect()
});

pub(crate) static CAPABILITIES: LazyLock<Vec<Entry>> = LazyLock::new(capability_entries);

fn capability_entries() -> Vec<Entry> {
	use crate::primitive::{primitive_is_key_derivation, primitives_supporting};
	use crate::types::Capability;
	fn leak(text: String) -> &'static str {
		Box::leak(text.into_boxed_str())
	}
	fn list(names: Vec<&str>) -> String {
		match names.len() {
			0 => "no primitive".to_string(),
			1 => names[0].to_string(),
			n => format!("{} and {}", names[..n - 1].join(", "), names[n - 1]),
		}
	}
	let supporting =
		|cap: Capability| primitives_supporting(|id| crate::capability::supports(id, cap));
	let declared_for = |cap: Capability| list(supporting(cap).iter().map(|s| s.name).collect());
	let example = |cap: Capability| {
		supporting(cap)
			.first()
			.map(|s| {
				leak(format!(
					"{}[{}]({})",
					s.name,
					cap.name(),
					s.arg_names.join(", ")
				))
			})
			.unwrap_or("")
	};
	let delayed = primitives_supporting(primitive_is_key_derivation)
		.first()
		.map(|s| {
			leak(format!(
				"{}[weak from phase 1]({})",
				s.name,
				s.arg_names.join(", ")
			))
		})
		.unwrap_or("");
	vec![
		Entry {
			name: "weak",
			eg: example(Capability::Weak),
			help: leak(format!(
				"Declared weakening assumption: this primitive loses confidentiality, so holding the term is enough to recover what it protects, which is whatever its definition marks as revealed under `weak`. Declared for {}. Append `from phase N` to delay it.",
				declared_for(Capability::Weak)
			)),
		},
		Entry {
			name: "forgeable",
			eg: example(Capability::Forgeable),
			help: leak(format!(
				"Declared weakening assumption: this primitive loses authenticity, so the term becomes constructible without its secret argument. Declared for {}. Kept separate from `weak` so that an authenticated cipher can be forgeable while its contents stay unreadable. Append `from phase N` to delay it.",
				declared_for(Capability::Forgeable)
			)),
		},
		Entry {
			name: "malleable",
			eg: example(Capability::Malleable),
			help: leak(format!(
				"Declared weakening assumption: a ciphertext the attacker already holds can be retargeted into another the recipient still accepts, which is the symbolic shape of a bit-flipping attack. Declared for {}, over the positions its definition marks malleable: holding one such term the attacker may vary those positions to anything it can construct, under a key it never learns. It licenses reshaping a ciphertext, not conjuring one, so the attacker must already hold a term of the same shape. Because malleability is an authenticity loss, an authenticated primitive is pointed at `forgeable` instead. Append `from phase N` to delay it.",
				declared_for(Capability::Malleable)
			)),
		},
		Entry {
			name: "from",
			eg: delayed,
			help: "Delays a weakening assumption: it is not in force until the named phase, and holds from there onward. Cryptanalysis does not un-happen, which is why this reads `from` a phase rather than `in` one. A capability that arrives later than the message it would act on is no capability at all, since phases still govern when a value may be substituted.",
		},
	]
}

pub(crate) const QUERIES: &[Entry] = &[
	Entry {
		name: "confidentiality",
		eg: "confidentiality? a",
		help: "Checks whether a given value can be obtained by the attacker.",
	},
	Entry {
		name: "authentication",
		eg: "authentication? Alice -> Bob: m",
		help: "Checks that Bob only uses m in a meaningful way (verifying a signature, decrypting authentically) if Alice really sent it to him, in this very session. This is injective agreement, so it fails both when the attacker can forge m and when the attacker can replay an m Alice sent once and make Bob accept it twice. Replays need two runs to appear, so analyze more than one session per principal to catch them.",
	},
	Entry {
		name: "freshness",
		eg: "freshness? a",
		help: "Checks that a value differs from session to session, which is what stops an old message from being reused as a new one. Against a passive attacker, this simply asks whether the value contains something freshly generated. Against an active attacker, it also asks whether the attacker can force the value to stay the same across sessions and then get it accepted again.",
	},
	Entry {
		name: "unlinkability",
		eg: "unlinkability? a, b, c",
		help: "Checks whether the attacker can link two of the given values: by observing them equal, by a check such as a decryption or a signature verification that succeeds over both under one participant's key, by a secret they share as their origin, or by a secret it can confirm sits inside both. If any pair links, the query fails. Takes at least two distinct constants.",
	},
	Entry {
		name: "equivalence",
		eg: "equivalence? ss_a, ss_b",
		help: "Checks whether any protocol scenario can be derived such that the given values are not equivalent to one another. This query could be useful for checking if all parties derived the same shared secret, for example. Takes at least two distinct constants.",
	},
	Entry {
		name: "precondition",
		eg: "confidentiality? k[ precondition[ Alice -> Bob: done ] ]",
		help: "An option that may be attached to any query. It restricts the query to the executions in which the named message is sent: the query is contradicted only where its own condition fails and the sender still reaches that send, so the property must hold whenever the sender goes on to send the value. The event is the send itself, not its receipt or its authentication. The model must contain the message, or it is rejected.",
	},
];

pub(crate) const KEYWORDS: &[Entry] = &[
	Entry {
		name: "attacker",
		eg: "attacker[active]",
		help: "Declares the attacker model, and must be the first statement in a model. `active` lets the attacker inject and replace unguarded values on the wire; `passive` lets it only observe.",
	},
	Entry {
		name: "active",
		eg: "attacker[active]",
		help: "The attacker may observe every message, and may also inject or replace any value that is not guarded with `[ ]`.",
	},
	Entry {
		name: "passive",
		eg: "attacker[passive]",
		help: "The attacker may observe every message but may not modify or inject anything.",
	},
	Entry {
		name: "principal",
		eg: "principal Alice[ ... ]",
		help: "Declares a block of operations performed by one principal. A principal may be declared more than once; the blocks run in the order they appear. Principal names are title-cased, and a model may declare at most 128 of them.",
	},
	Entry {
		name: "knows",
		eg: "knows private a",
		help: "Declares a value the principal holds before the protocol begins. Qualify it with `public` or `private`.",
	},
	Entry {
		name: "generates",
		eg: "generates a",
		help: "Declares a fresh value, generated by this principal at this point in the protocol. Freshly generated values are what freshness queries are built on.",
	},
	Entry {
		name: "leaks",
		eg: "leaks a",
		help: "Hands a value the principal knows to the attacker. Useful for modelling key compromise, and for post-compromise properties when combined with phases.",
	},
	Entry {
		name: "public",
		eg: "knows public c0",
		help: "The value is known to every principal, and to the attacker.",
	},
	Entry {
		name: "private",
		eg: "knows private m",
		help: "The value is known only to the principals that declare it.",
	},
	Entry {
		name: "phase",
		eg: "phase[1]",
		help: "Opens a new phase. Values sent in an earlier phase cannot be replaced using knowledge the attacker only obtains in a later one, which is what makes post-compromise properties expressible. Phases must increment by exactly one.",
	},
	Entry {
		name: "scenarios",
		eg: "scenarios[ Alice[gpeer = gb] Alice[gpeer = gm] ]",
		help: "Runs the protocol once per declared peer configuration, cloning every principal and message and substituting the bindings in the named principal. A scenario whose bound values are reachable from a `leaks` declaration is a corrupt-peer run: it is analyzed, because it is where the attacker learns things, but its own checked primitives may fail without that being a model error. Scenarios multiply with sessions, and the block goes before `queries`.",
	},
	Entry {
		name: "queries",
		eg: "queries[ confidentiality? m ]",
		help: "The block of security queries to check. It must exist, and nothing may follow it: a statement after the queries block is a hard error rather than something silently ignored.",
	},
	Entry {
		name: "nil",
		eg: "nil",
		help: "The empty value. Known to the attacker from the start, and the usual way to say no associated data.",
	},
];

fn find(table: &'static [Entry], word: &str) -> Option<&'static Entry> {
	table.iter().find(|e| e.name.eq_ignore_ascii_case(word))
}

pub(crate) fn primitive(word: &str) -> Option<&'static Entry> {
	find(PRIMITIVES.as_slice(), word)
}

pub(crate) fn capability(word: &str) -> Option<&'static Entry> {
	find(CAPABILITIES.as_slice(), word)
}

pub(crate) fn query(word: &str) -> Option<&'static Entry> {
	find(QUERIES, word)
}

pub(crate) fn keyword(word: &str) -> Option<&'static Entry> {
	find(KEYWORDS, word)
}

pub(crate) fn any(word: &str) -> Option<&'static Entry> {
	primitive(word)
		.or_else(|| query(word))
		.or_else(|| capability(word))
		.or_else(|| keyword(word))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_primitive_declares_its_documentation() {
		for (name, doc) in crate::primitive::primitive_docs() {
			assert!(
				!doc.example.is_empty() && !doc.help.is_empty(),
				"{name} declares no documentation"
			);
			assert!(
				doc.example.contains(name),
				"{name}'s example does not show it"
			);
			assert!(
				primitive(name).is_some(),
				"{name} is not served to the editor"
			);
		}
	}

	#[test]
	fn every_capability_is_documented() {
		for cap in crate::types::Capability::ALL {
			assert!(
				capability(cap.name()).is_some(),
				"{} has no documentation entry",
				cap.name()
			);
		}
	}

	#[test]
	fn every_query_kind_is_documented() {
		for kind in [
			"confidentiality",
			"authentication",
			"freshness",
			"unlinkability",
			"equivalence",
		] {
			assert!(query(kind).is_some(), "{kind} has no documentation entry");
		}
	}

	#[test]
	fn lookup_is_case_insensitive() {
		assert!(primitive("pubkey").is_some());
		assert!(primitive("PUBKEY").is_some());
		assert!(keyword("KNOWS").is_some());
		assert!(any("weak").is_some());
		assert!(any("nonsense").is_none());
	}

	#[test]
	fn every_entry_has_an_example_and_help() {
		for table in [
			PRIMITIVES.as_slice(),
			CAPABILITIES.as_slice(),
			QUERIES,
			KEYWORDS,
		] {
			for entry in table {
				assert!(!entry.eg.is_empty(), "{} has no example", entry.name);
				assert!(!entry.help.is_empty(), "{} has no help", entry.name);
			}
		}
	}
}
