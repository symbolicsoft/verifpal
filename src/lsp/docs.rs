/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: CC-BY-SA-4.0 */

pub(crate) struct Entry {
	pub name: &'static str,
	pub eg: &'static str,
	pub help: &'static str,
}

pub(crate) const PRIMITIVES: &[Entry] = &[
	Entry {
		name: "ASSERT",
		eg: "ASSERT(MAC(key, message), MAC(key, message)): unused",
		help: "Checks the equality of two values, and especially useful for checking MAC equality. Output value is not used. May be suffixed with `?` to halt the principal if the check fails.",
	},
	Entry {
		name: "CONCAT",
		eg: "CONCAT(a, b...): c",
		help: "Concatenates between two and five values into one value. For example, the concatenation of the strings `cat` and `dog` would be `catdog`.",
	},
	Entry {
		name: "SPLIT",
		eg: "SPLIT(CONCAT(a, b)): a, b",
		help: "Splits a concatenation back to its component values, producing between one and five outputs. Must contain a CONCAT primitive as input; otherwise, Verifpal will output an error. May be suffixed with `?` to halt the principal if the check fails.",
	},
	Entry {
		name: "HASH",
		eg: "HASH(a, b...): x",
		help: "Secure hash function, similar in practice to, for example, BLAKE2s. Takes between one and five input arguments, and returns one output.",
	},
	Entry {
		name: "MAC",
		eg: "MAC(key, message): h",
		help: "Keyed hash function. Useful for message authentication and for some other protocol constructions.",
	},
	Entry {
		name: "HKDF",
		eg: "HKDF(salt, ikm, info): a, b...",
		help: "Hash-based key derivation function inspired by the Krawczyk HKDF scheme. Essentially, HKDF is used to extract more than one key out a single secret value. salt and info help contextualize derived keys. Takes exactly three arguments and produces between one and five outputs.",
	},
	Entry {
		name: "PW_HASH",
		eg: "PW_HASH(a...): x",
		help: "Password hashing function, similar in practice to, for example, Scrypt or Argon2. Hashes passwords and produces output that is suitable for use as a private key, secret key or other sensitive key material. Takes between one and five arguments. Useful in conjunction with values declared using `knows password a`.",
	},
	Entry {
		name: "ENC",
		eg: "ENC(key, plaintext): ciphertext",
		help: "Symmetric encryption, similar for example to AES-CBC or to ChaCha20. Unauthenticated, which is why it is the one primitive that accepts `malleable`.",
	},
	Entry {
		name: "DEC",
		eg: "DEC(key, ENC(key, plaintext)): plaintext",
		help: "Symmetric decryption.",
	},
	Entry {
		name: "AEAD_ENC",
		eg: "AEAD_ENC(key, plaintext, ad): ciphertext",
		help: "Authenticated encryption with associated data. `ad` represents an additional payload that is not encrypted, but that must be provided exactly in the decryption function for authenticated decryption to succeed. Similar for example to AES-GCM or to ChaCha20-Poly1305.",
	},
	Entry {
		name: "AEAD_DEC",
		eg: "AEAD_DEC(key, AEAD_ENC(key, plaintext, ad), ad): plaintext",
		help: "Authenticated decryption with associated data. May be suffixed with `?` to halt the principal if decryption fails.",
	},
	Entry {
		name: "PUBKEY",
		eg: "PUBKEY(private_key): public_key",
		help: "Derives the public key corresponding to a private key. The same constructor is used for Diffie-Hellman, signatures, public-key encryption and ring signatures. Its argument may not itself be a public key or a shared secret.",
	},
	Entry {
		name: "DH_KEX",
		eg: "DH_KEX(PUBKEY(a), b): shared_secret",
		help: "Diffie-Hellman key exchange. DH_KEX(PUBKEY(a), b) and DH_KEX(PUBKEY(b), a) yield the same shared secret. The first argument is the peer's public key and the second is your own private value: the second argument may not be a public key, and neither argument may itself be a DH_KEX, since the attacker cannot compute a shared secret from two public keys.",
	},
	Entry {
		name: "KEM_ENCAP",
		eg: "ss, ct = KEM_ENCAP(PUBKEY(dk), r)",
		help: "Key encapsulation, as in a post-quantum KEM such as ML-KEM. Takes the recipient's encapsulation key `PUBKEY(dk)` and a random value, and binds two outputs: the shared secret and the encapsulation ciphertext that transports it. The random value should be freshly generated, since encapsulating twice under the same randomness yields the same shared secret. The random value may not be a public key, and the encapsulation key may not itself be a shared secret. A KEM says nothing about who performed the encapsulation: authenticate the ciphertext separately if the recipient needs to know who it came from.",
	},
	Entry {
		name: "KEM_DECAP",
		eg: "KEM_DECAP(dk, ct): ss",
		help: "Key decapsulation. Recovers the shared secret from an encapsulation ciphertext using the private decapsulation key `dk` matching the `PUBKEY(dk)` used to encapsulate. May be suffixed with `?` to halt the principal if decapsulation fails.",
	},
	Entry {
		name: "PKE_ENC",
		eg: "PKE_ENC(PUBKEY(key), plaintext): ciphertext",
		help: "Public-key encryption.",
	},
	Entry {
		name: "PKE_DEC",
		eg: "PKE_DEC(key, PKE_ENC(PUBKEY(key), plaintext)): plaintext",
		help: "Public-key decryption.",
	},
	Entry {
		name: "SIGN",
		eg: "SIGN(key, message): signature",
		help: "Classic signature primitive. Here, `key` is a private key, for example `a`.",
	},
	Entry {
		name: "SIGNVERIF",
		eg: "SIGNVERIF(PUBKEY(key), message, SIGN(key, message)): verified",
		help: "Verifies if signature can be authenticated. If key a was used for SIGN, then SIGNVERIF will expect `PUBKEY(a)` as the key value. May be suffixed with `?` to halt the principal if verification fails.",
	},
	Entry {
		name: "RINGSIGN",
		eg: "RINGSIGN(key_a, PUBKEY(key_b), PUBKEY(key_c), message): signature",
		help: "Ring signature. In ring signatures, one of three parties (Alice, Bob and Charlie) signs a message. The resulting signature can be verified using the public key of any of the three parties, and the signature does not reveal the signatory, only that they are a member of the signing ring (Alice, Bob or Charlie). The first key must be the private key of the actual signer, while the subsequent two keys must be the public keys of the other potential signers.",
	},
	Entry {
		name: "RINGSIGNVERIF",
		eg: "RINGSIGNVERIF(PUBKEY(a), PUBKEY(b), PUBKEY(c), m, RINGSIGN(a, PUBKEY(b), PUBKEY(c), m)): verified",
		help: "Verifies if a ring signature can be authenticated. The signer's public key must match one or more of the public keys provided, but the public keys may be provided in any order and not necessarily in the order used during the RINGSIGN operation. May be suffixed with `?` to halt the principal if verification fails.",
	},
	Entry {
		name: "BLIND",
		eg: "BLIND(k, m): b",
		help: "Message blinding primitive, useful for the implementation of blind signatures. Here, the sender uses the secret \\\"blinding factor\\\" `k` in order to blind message `m`, which can then be sent to the signer, who will be able to produce a signature on `m` without knowing `m`. Used in conjunction with UNBLIND -- see UNBLIND's documentation for more information.",
	},
	Entry {
		name: "UNBLIND",
		eg: "UNBLIND(k, m, SIGN(a, BLIND(k, m))): SIGN(a, m)",
		help: "Once `BLIND(k, m)` is signed by the signer, the sender can convert `SIGN(a, BLIND(k, m))` to `SIGN(a, m)` by unblinding the message using their secret blinding factor `k`. The resulting unblinded signature can then be used as if it were a regular signature by `a` over `m`.",
	},
	Entry {
		name: "SHAMIR_SPLIT",
		eg: "SHAMIR_SPLIT(k): s1, s2, s3",
		help: "In Verifpal, we allow splitting the key into three shares such that only two shares are required to reconstitute it.",
	},
	Entry {
		name: "SHAMIR_JOIN",
		eg: "SHAMIR_JOIN(sa, sb): k",
		help: "Here, sa and sb must be two distinct elements out of the set (s1, s2, s3) in order to obtain k.",
	},
];

pub(crate) const CAPABILITIES: &[Entry] = &[
	Entry {
		name: "weak",
		eg: "AEAD_ENC[weak](key, plaintext, ad)",
		help: "Declared weakening assumption: this primitive loses confidentiality, so holding the term is enough to recover what it protects. Declared for HASH and PW_HASH (a preimage, recovering every argument), AEAD_ENC, ENC and PKE_ENC (the plaintext), KEM_ENCAP (the shared secret), and PUBKEY (the private key, which is the discrete logarithm problem falling and makes every DH_KEX built on that key computable). Append `from phase N` to delay it.",
	},
	Entry {
		name: "forgeable",
		eg: "SIGN[forgeable](private_key, message)",
		help: "Declared weakening assumption: this primitive loses authenticity, so the term becomes constructible without its secret argument. Declared for SIGN, MAC, RINGSIGN and AEAD_ENC. Kept separate from `weak` so that AEAD_ENC[forgeable] can say the attacker may manufacture a ciphertext the recipient accepts while still being unable to read yours. Append `from phase N` to delay it.",
	},
	Entry {
		name: "malleable",
		eg: "ENC[malleable](key, plaintext)",
		help: "Declared weakening assumption: a ciphertext the attacker already holds can be retargeted into another the recipient still accepts, which is the symbolic shape of a bit-flipping attack. Declared only for ENC, the unauthenticated cipher this models, and only over its plaintext position: holding one `ENC(k, m)` the attacker may build `ENC(k, m')` for any `m'` it can construct, under a key it never learns. It licenses reshaping a ciphertext, not conjuring one, so the attacker must already hold a term of the same shape. Because malleability is an authenticity loss, an authenticated primitive is pointed at `forgeable` instead. Append `from phase N` to delay it.",
	},
	Entry {
		name: "from",
		eg: "PUBKEY[weak from phase 1](private_key)",
		help: "Delays a weakening assumption: it is not in force until the named phase, and holds from there onward. Cryptanalysis does not un-happen, which is why this reads `from` a phase rather than `in` one. A capability that arrives later than the message it would act on is no capability at all, since phases still govern when a value may be substituted.",
	},
];

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
		help: "Checks whether all given values satisfy freshness. If they do, checks whether the attacker can determine them as being the output of the same primitive or as otherwise having a common source. If any of these checks fail, the query fails. Takes at least two distinct constants.",
	},
	Entry {
		name: "equivalence",
		eg: "equivalence? ss_a, ss_b",
		help: "Checks whether any protocol scenario can be derived such that the given values are not equivalent to one another. This query could be useful for checking if all parties derived the same shared secret, for example. Takes at least two distinct constants.",
	},
	Entry {
		name: "precondition",
		eg: "confidentiality? m[ precondition[ Bob -> Alice: ack ] ]",
		help: "An option that may be attached to any query. When the query fails, the result is additionally annotated to note that the message described in the precondition is sent despite the query failing. The sender must know the constant, the recipient must receive it, and the recipient must actually use it inside a primitive, or the model is rejected.",
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
		help: "Declares a value the principal holds before the protocol begins. Qualify it with `public`, `private` or `password`.",
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
		name: "password",
		eg: "knows password pw",
		help: "A low-entropy private value. The attacker may brute-force it unless it is passed through PW_HASH before use.",
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
		eg: "AEAD_ENC(k, m, nil)",
		help: "The empty value. Known to the attacker from the start, and the usual way to say no associated data.",
	},
];

fn find(table: &'static [Entry], word: &str) -> Option<&'static Entry> {
	table.iter().find(|e| e.name.eq_ignore_ascii_case(word))
}

pub(crate) fn primitive(word: &str) -> Option<&'static Entry> {
	find(PRIMITIVES, word)
}

pub(crate) fn capability(word: &str) -> Option<&'static Entry> {
	find(CAPABILITIES, word)
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
	fn every_engine_primitive_is_documented() {
		for name in crate::primitive::primitive_names() {
			assert!(
				primitive(name).is_some(),
				"{name} has no documentation entry"
			);
		}
	}

	#[test]
	fn no_documented_primitive_is_unknown_to_the_engine() {
		for entry in PRIMITIVES {
			assert!(
				crate::primitive::primitive_get_enum(entry.name).is_ok(),
				"{} is documented but not a primitive",
				entry.name
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
		for table in [PRIMITIVES, CAPABILITIES, QUERIES, KEYWORDS] {
			for entry in table {
				assert!(!entry.eg.is_empty(), "{} has no example", entry.name);
				assert!(!entry.help.is_empty(), "{} has no help", entry.name);
			}
		}
	}
}
