/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: CC-BY-SA-4.0 */

use std::sync::LazyLock;

pub(crate) struct Entry {
	pub name: &'static str,
	pub eg: &'static str,
	pub help: &'static str,
}

impl Entry {
	pub(crate) fn markdown(&self) -> String {
		format!("```verifpal\n{}\n```\n\n{}", self.eg, self.help)
	}
}

static PRIMITIVES: LazyLock<Vec<Entry>> = LazyLock::new(|| {
	crate::primitive::docs()
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
	use crate::primitive::Capability;
	fn leak(text: String) -> &'static str {
		Box::leak(text.into_boxed_str())
	}
	fn list(names: Vec<&str>) -> String {
		if names.is_empty() {
			return "no primitive".to_string();
		}
		crate::util::text::and_list(&names)
	}
	let supporting = |cap: Capability| {
		crate::primitive::supporting(|id| crate::primitive::capability::supports(id, cap))
	};
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
	let delayed = crate::primitive::supporting(crate::primitive::is_key_derivation)
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
				"Declared weakening assumption: the primitive loses confidentiality, so holding the term reveals what its definition marks as revealed under `weak`. Declared for {}. Append `from phase N` to delay it.",
				declared_for(Capability::Weak)
			)),
		},
		Entry {
			name: "forgeable",
			eg: example(Capability::Forgeable),
			help: leak(format!(
				"Declared weakening assumption: the primitive loses authenticity, so the attacker can build the term without its secret argument. Declared for {}. It is separate from `weak` so that an authenticated cipher can be forgeable while its contents stay secret. Append `from phase N` to delay it.",
				declared_for(Capability::Forgeable)
			)),
		},
		Entry {
			name: "malleable",
			eg: example(Capability::Malleable),
			help: leak(format!(
				"Declared weakening assumption: the attacker can turn a ciphertext it holds into another that the recipient still accepts, the symbolic form of a bit-flipping attack. Declared for {}. The attacker sets the positions the definition marks malleable to anything it can construct, under a key it never learns, but it needs a ciphertext of the same shape to start from. Malleability is a loss of authenticity, so an authenticated primitive takes `forgeable` instead. Append `from phase N` to delay it.",
				declared_for(Capability::Malleable)
			)),
		},
		Entry {
			name: "from",
			eg: delayed,
			help: "Delays a weakening assumption until the named phase, after which it stays in force: cryptanalysis cannot be undone, so it reads `from` a phase rather than `in` one. An assumption that takes effect after a message was sent cannot change that message, since phases still decide when a value may be substituted.",
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
		help: "Checks that Bob uses m in a meaningful way (verifying a signature, decrypting authentically) only if Alice sent it to him, and that Bob's runs accept it no more often than Alice's runs sent it. This is injective agreement: it fails when the attacker can forge m, and when it can replay an m that Alice sent once so that Bob accepts it twice. A replay needs two runs, so analyze more than one session per principal to find one.",
	},
	Entry {
		name: "freshness",
		eg: "freshness? a",
		help: "Checks that a value differs from session to session, which is what stops an old message from being reused as a new one. Against a passive attacker, it asks whether the value contains something freshly generated. Against an active attacker, it also asks whether the attacker can force the value to stay the same across sessions and then get it accepted again.",
	},
	Entry {
		name: "unlinkability",
		eg: "unlinkability? a, b, c",
		help: "Checks whether the attacker can link two of the given values: by seeing that they are equal, by a check under one participant's key, such as a decryption or a signature verification, that succeeds on both, by a secret both were made from, or by a secret it can confirm is inside both. The query fails if any pair links. Takes at least two distinct constants.",
	},
	Entry {
		name: "equivalence",
		eg: "equivalence? ss_a, ss_b",
		help: "Checks whether the attacker can bring about an execution in which the given values differ, for example to check that all parties derived the same shared secret. Takes at least two distinct constants.",
	},
	Entry {
		name: "precondition",
		eg: "confidentiality? k[ precondition[ Alice -> Bob: done ] ]",
		help: "An option that can be attached to any query. It restricts the query to the executions in which the named message is sent, so the property must hold whenever the sender goes on to send it. The event is the send itself, not its receipt or its authentication. The model must contain the message.",
	},
];

pub(crate) const KEYWORDS: &[Entry] = &[
	Entry {
		name: "attacker",
		eg: "attacker[active]",
		help: "Declares the attacker model, and must be the first statement in a model. `active` lets the attacker inject and replace unguarded values on the wire and drop any value, guarded or not; `passive` lets it only observe.",
	},
	Entry {
		name: "active",
		eg: "attacker[active]",
		help: "The attacker may observe every message, may inject or replace any value that is not guarded with `[ ]`, and may drop any value of any message, guarded or not.",
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
		help: "Opens a new phase. Values sent in an earlier phase cannot be replaced using knowledge the attacker only obtains in a later one, which is what makes post-compromise properties expressible. Every query is judged at the end of each phase against what has happened by then. Phases must increment by exactly one.",
	},
	Entry {
		name: "scenarios",
		eg: "scenarios[ Alice[gpeer = gb] Alice[gpeer = gm] ]",
		help: "Runs the protocol once per declared peer configuration, cloning every principal and message and substituting each binding in its named principal. A scenario becomes a corrupt peer from the first phase at whose end the attacker holds the binding's key material, however it learned it. A corrupt scenario still runs, so the attacker can learn from it, but its queries are no longer claimed and its failed checks are not model errors. Scenarios multiply with sessions. The block goes just before `queries`.",
	},
	Entry {
		name: "queries",
		eg: "queries[ confidentiality? m ]",
		help: "The block of security queries to check. Every model needs one, and nothing may follow it: a statement after it is an error, not something ignored.",
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
		for (name, doc) in crate::primitive::docs() {
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
		for cap in crate::primitive::Capability::ALL {
			assert!(
				capability(cap.name()).is_some(),
				"{} has no documentation entry",
				cap.name()
			);
		}
	}

	#[test]
	fn every_query_kind_is_documented() {
		for kind in crate::syntax::QueryKind::ALL {
			assert!(
				query(kind.name()).is_some(),
				"{} has no documentation entry",
				kind.name()
			);
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
