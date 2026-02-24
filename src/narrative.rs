/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::atomic::{AtomicU8, Ordering};

use crate::types::*;

// ── Character selection ──────────────────────────────────────────────────

/// 0 = Default, 1 = Jevil, 2 = Spamton
static CHARACTER: AtomicU8 = AtomicU8::new(0);

pub fn reset() {
	CHARACTER.store(0, Ordering::Relaxed);
}

pub fn set_character(name: &str) -> VResult<()> {
	match name.to_lowercase().as_str() {
		"jevil" => {
			CHARACTER.store(1, Ordering::Relaxed);
			Ok(())
		}
		"spamton" => {
			CHARACTER.store(2, Ordering::Relaxed);
			Ok(())
		}
		other => Err(VerifpalError::Internal(
			format!("Unknown character '{}'. Available: jevil, spamton", other).into(),
		)),
	}
}

fn character() -> u8 {
	CHARACTER.load(Ordering::Relaxed)
}

// ── Narrative pools ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub enum NarrativeContext {
	Init,
	Mutation,
	Escalation,
	Deduction,
	Passive,
	QueryPass,
	QueryFail,
	Finished,
}

// ── Default narratives ──────────────────────────────────────────────────

const DEFAULT_INIT: &[&str] = &[
	"Positioning on the network, observing all unencrypted traffic...",
	"Network reconnaissance initiated. All public values compromised.",
	"Intercepting all protocol messages between principals...",
	"Passive observation established. Analyzing traffic patterns...",
	"Enumerating visible constants and public key material...",
	"Initial handshake observed. Cataloguing protocol structure...",
];

const DEFAULT_MUTATION: &[&str] = &[
	"Intercepting {P}'s channel, probing constructions for weaknesses...",
	"Crafting replacement values for {P}'s session...",
	"Targeting {P}'s encrypted channel with modified payloads...",
	"Injecting crafted primitives into {P}'s message flow...",
	"Testing mutation combinations against {P}'s protocol state...",
	"Replacing {P}'s received values with attacker-controlled data...",
	"Forging {P}'s session tokens with controlled nonces...",
	"Substituting {P}'s key material with attacker-derived values...",
];

const DEFAULT_ESCALATION: &[&str] = &[
	"Escalating attack sophistication \u{2500} expanding search space...",
	"Deeper analysis initiated \u{2500} probing higher-order mutations...",
	"Increasing mutation complexity \u{2500} recursive injection active...",
	"Expanding attacker capabilities \u{2500} new strategies engaged...",
	"Broadening attack surface \u{2500} combinatorial injection underway...",
	"Intensifying cryptographic pressure \u{2500} layered mutations active...",
];

const DEFAULT_DEDUCTION: &[&str] = &[
	"New knowledge extracted \u{2500} the attacker's power grows.",
	"Value obtained through cryptographic analysis.",
	"Attack surface expanded with newly derived material.",
	"The attacker leverages structural weakness in the protocol.",
	"Derived key material exposes further protocol internals.",
	"Cryptographic relation exploited \u{2500} new value deduced.",
];

const DEFAULT_PASSIVE: &[&str] = &[
	"Passive observation mode \u{2500} no message manipulation permitted.",
	"Monitoring all wire traffic without active interference.",
	"Eavesdropping on protocol exchanges between all principals...",
	"Silent interception \u{2500} recording all observable values...",
];

const DEFAULT_QUERY_PASS: &[&str] = &[
	"Query holds under analysis.",
	"No attack vector found for this property.",
	"Security property verified.",
];

const DEFAULT_QUERY_FAIL: &[&str] = &[
	"Security property violated.",
	"Attack vector discovered.",
	"The attacker breaks this guarantee.",
];

const DEFAULT_FINISHED: &[&str] = &[
	"Analysis complete.",
	"Verification finished.",
	"All queries resolved.",
];

// ── Jevil narratives ────────────────────────────────────────────────────

const JEVIL_INIT: &[&str] = &[
	"BOO HOO, BOO HOO, UEE HEE HEE! SO LONELY WITHOUT TRAFFIC TO SEE!",
	"UEE HEE! VISITORS, VISITORS! NOW WE CAN PLAY, PLAY!",
	"I CAN DO ANYTHING! ...INCLUDING READING YOUR LITTLE PACKETS!",
	"OH? NEW PRINCIPALS STANDING INSIDE? WHO ARE YOU FEW?",
	"THE WORLD IS SPINNING, SPINNING! AND ALL YOUR TRAFFIC FLOWS THROUGH ME!",
	"I AM THE ONLY FREE ONE. YOUR NETWORK IS MY LITTLE FREEDOM!",
	"A GAME, A GAME! IT'S JUST A SIMPLE NUMBERS GAME!",
	"UEE HEE HEE! YOUR PUBLIC KEYS CANNOT BE HIDDEN FROM THE EYES!",
];

const JEVIL_MUTATION: &[&str] = &[
	"I CAN DO ANYTHING! EVEN REPLACE {P}'S PRECIOUS LITTLE VALUES!",
	"UEE HEE HEE! {P}'S MESSAGES GO ROUND AND ROUND AND WRONG!",
	"A CHAOS, CHAOS! {P}'S CIPHERTEXT BECOMES MY CIPHERTEXT!",
	"METAMORPHOSIS! {P}'S VALUES ARE SOMETHING ELSE ENTIRELY NOW!",
	"PIIP PIIP! LET'S RIDE {P}'S SESSION LIKE A CAROUSEL GAME!",
	"{P} THINKS THEY'RE FREE? THINGS DON'T SEEM SUCH FROM HERE!",
	"HA, HA, LET'S MAKE THE DEVILSKNIFE THROUGH {P}'S LITTLE CHANNEL!",
	"WHO KEEPS SPINNING {P}'S KEYS AROUND? IT'S ME, ME, ME!",
	"SHALL WE PLAY THE RING-AROUND WITH {P}'S NONCE? UEE HEE!",
];

const JEVIL_ESCALATION: &[&str] = &[
	"IT'S SO EXCITING... I CAN'T TAKE IT!!!",
	"I CAN DO ANYTHING! AND NOW I'LL DO EVEN MORE, MORE!",
	"THE CAROUSEL SPINS FASTER, FASTER! UEE HEE HEE!",
	"KIDDING!! HERE'S MY NEXT CHAOS!",
	"DEEPER, DEEPER! I'M FAST, FAST, CLEVER, CLEVER!",
	"NU-HA!! I NEVER HAD SUCH FUN, FUN!! MORE PIECES ON THE BOARD!",
	"HEARTS, DIAMONDS, I CAN DO ANYTHING! THE GAME EVOLVES!",
	"THESE CURTAINS ARE REALLY ON FIRE! THE SEARCH GROWS WIDER!",
];

const JEVIL_DEDUCTION: &[&str] = &[
	"UEE HEE HEE! A SECRET FALLS INTO MY TINY HANDS!",
	"I CAN DO ANYTHING! AND NOW I KNOW THIS, TOO!",
	"A NEW TOY, A NEW TOY! A MARVELLOUS FUN BREAKS FREE!",
	"THE CHAOS GROWS! ANOTHER PIECE OF THE PUZZLE, PUZZLE!",
	"FREEDOM TASTES LIKE FRESHLY STOLEN KEY MATERIAL!",
	"YOUR SECRETS ARE JUST CARDS IN MY DECK! HEARTS, DIAMONDS!",
	"A BEAUTY IS JOYING IN MY HEART! ANOTHER VALUE JOINS THE FUN!",
	"I PLUCKED THAT VALUE RIGHT FROM THE SPINNING WORLD!",
];

const JEVIL_PASSIVE: &[&str] = &[
	"SO LONELY, LONELY, I BE... JUST WATCHING, WATCHING!",
	"I CAN SEE ANYTHING! EVEN WITHOUT TOUCHING, I LEARN!",
	"PLEASE, IT'S JUST A SIMPLE CHAOS. JUST WATCHING FOR NOW!",
	"THE WORLD KEEPS SPINNING ON ITS OWN! I JUST OBSERVE!",
	"BOO HOO! CANNOT TOUCH, ONLY WATCH, WATCH, WATCH!",
];

const JEVIL_QUERY_PASS: &[&str] = &[
	"TCH! THIS ONE'S NO FUN, NO FUN AT ALL!",
	"THE GAME IS RIGGED! I CANNOT BREAK THIS ONE!",
	"UEE... HEE... YOUR PROTOCOL WINS THIS ROUND, ROUND!",
	"HMPH! EVEN CHAOS HAS LIMITS... UNFORTUNATELY!",
];

const JEVIL_QUERY_FAIL: &[&str] = &[
	"UEE HEE HEE HEE! WHEN YOUR HP DROPS TO 0, YOU LOSE!",
	"A CHAOS, CHAOS! YOUR PROTOCOL CRUMBLES, CRUMBLES!",
	"I CAN DO ANYTHING! AND I JUST DID!",
	"THE GAME IS OVER! SHARK-TO-SHARK, AND I WON!",
	"YOUR SECURITY WAS JUST A SIMPLE NUMBERS GAME!",
];

const JEVIL_FINISHED: &[&str] = &[
	"WHAT FUN!!! I'M EXHAUSTED!!! THE GAME TIRED ME UP!!",
	"A MISCHIEF-MISCHIEF, A CHAOS-CHAOS! THE FINAL CURTAIN FALLS!",
	"I CAN DO ANYTHING! ...AND NOW I'VE DONE EVERYTHING!",
	"UEE HEE HEE! NOW I WILL SLEEP FOR THE OTHER 100 YEARS!",
	"THE CAROUSEL STOPS... EITHER WAY, CHAOS IS FOREVER!",
];

// ── Spamton narratives ──────────────────────────────────────────────────

const SPAMTON_INIT: &[&str] = &[
	"HEY EVERY   !! IT'S ME, YOUR FAVORITE [[Network Attacker]]!",
	"NOW'S YOUR CHANCE TO BE A [[Big Shot]] PROTOCOL ANALYST!!",
	"WELCOME TO THE [[Packet Inspection Hypermart]]! DEALS DEALS DEALS!",
	"I USED TO BE NOTHING. BUT NOW I'M [[Intercepting Your Traffic]]!!",
	"YOU WANT [[Public Keys]]?? I'VE GOT [[Public Keys]] COMING OUT OF MY [[Ears]]!!",
	"IT'S A BEAUTIFUL DAY TO [[Steal Your Constants]]!! KRIS!!",
	"SPAMTON G. SPAMTON'S [[Protocol Breaking]] EMPORIUM IS NOW [OPEN]!!",
	"[[Hyperlink Blocked]] ... I MEAN, [[Network Attached]]!!",
];

const SPAMTON_MUTATION: &[&str] = &[
	"HEY {P}!! WANT SOME [[Slightly Used]] REPLACEMENT VALUES?? ONLY 3 [[Kromer]]!!",
	"{P}'S VALUES?? MORE LIKE {P}'S [[Former]] VALUES!! NOW THEY'RE MINE MINE MINE!!",
	"INJECTING [[Premium Quality]] MUTATIONS INTO {P}'s CHANNEL!! [[Satisfaction Guaranteed]]!!",
	"ATTENTION {P}!! YOUR [[Session Tokens]] HAVE BEEN [[Repossessed]]!!",
	"{P} DIDN'T READ THE [[Terms and Conditions]]!! NOW I OWN THEIR CIPHERTEXT!!",
	"CRAFTING [[Artisanal Hand-Forged]] PAYLOADS FOR {P}'S [[Inbox]]!!",
	"BIG SHOT {P}!! YOUR NONCES ARE NOW [[Buy 1 Get 1 Free]]!!",
	"{P}'S KEY EXCHANGE?? [[Error: Too Weak. Please Upgrade to Premium.]]",
	"EVERY [[Value]] {P} SENDS GOES THROUGH MY [[Toll Booth]]!!",
];

const SPAMTON_ESCALATION: &[&str] = &[
	"NOW I'M [[Ascending]] TO THE NEXT LEVEL!! BIG SHOT BIG SHOT!!",
	"YOU THOUGHT THAT WAS MY FINAL [[Offer]]?? THINK AGAIN, THINK AGAIN!!",
	"UPGRADING ATTACK TO [[Premium Deluxe NEO]] EDITION!!",
	"I'M GOING [[Super Saiyan]] BUT FOR [[Packet Injection]]!!",
	"THE [[Strings]] ARE PULLING ME HIGHER!! MORE [[Mutations]]!!",
	"BIGGER!! STRONGER!! MORE [[Aggressive Pricing]]!!",
	"ENTERING [[Hard Mode]]!! YOUR PROTOCOL WILL [[Beg for Mercy]]!!",
	"NOW'S MY CHANCE TO BE A [[BIG SHOT]] AT [[Stage {S}]]!!",
];

const SPAMTON_DEDUCTION: &[&str] = &[
	"I JUST GOT A [[Free Sample]] OF YOUR SECRET!! THANKS SUCKER!!",
	"ANOTHER [[Value]] FOR MY COLLECTION!! I'M BECOMING A [[Big Shot]]!!",
	"YOUR KEY MATERIAL IS NOW [[On Sale]] IN MY KNOWLEDGE BASE!!",
	"KR1MER!! I MEAN, [[Cryptographic Material]] ACQUIRED!!",
	"I DIDN'T EVEN NEED A [[Coupon Code]] TO GET THAT VALUE!!",
	"ADD TO [[Cart]]!! YOUR SECRETS ARE [[Buy One Get All Free]]!!",
	"[[Cha-Ching!!]] ANOTHER DEDUCTION IN THE [[Profit Margin]]!!",
	"THE [[Phone]] IS RINGING AND IT'S TELLING ME YOUR SECRETS!!",
];

const SPAMTON_PASSIVE: &[&str] = &[
	"JUST [[Window Shopping]] YOUR PACKETS!! NO TOUCHING... YET!!",
	"PASSIVE MODE?? MORE LIKE [[Free Market Research]]!!",
	"I'M WATCHING YOUR TRAFFIC LIKE A [[Hawk]] AT A [[Yard Sale]]!!",
	"CAN'T TOUCH... ONLY LOOK... THE [[Worst Deal]] I EVER MADE!!",
	"STANDING HERE... OBSERVING... LIKE A [[Mannequin]] WITH [[Dreams]]!!",
];

const SPAMTON_QUERY_PASS: &[&str] = &[
	"THIS [[Deal]] IS [[Too Good]]... I CAN'T CRACK IT!!",
	"N-NO!! THIS PROPERTY IS [[Out of My Price Range]]!!",
	"I... I COULDN'T BREAK IT... AM I STILL A [[Big Shot]]??",
	"[[Transaction Failed]]!! YOUR PROTOCOL IS [[Refund-Proof]]!!",
];

const SPAMTON_QUERY_FAIL: &[&str] = &[
	"NOW'S YOUR CHANCE TO [[Die]]!! I MEAN [[Lose Your Security]]!!",
	"[[DEAL OF A LIFETIME]]!! YOUR PROTOCOL IS [[Bankrupt]]!!",
	"I'M FINALLY A [[Big Shot]]!! YOUR QUERY [[Bounced]]!!",
	"YOUR SECURITY?? [[Return to Sender]]!! ADDRESS [[Unknown]]!!",
	"[[CRITICAL VULNERABILITY]] ON [[SALE NOW]]!! EVERYTHING MUST GO!!",
];

const SPAMTON_FINISHED: &[&str] = &[
	"THANK YOU FOR SHOPPING AT [[Spamton's Protocol Analysis]]!!",
	"THAT'S A [[Wrap]]!! COME AGAIN FOR MORE [[Deals]]!!",
	"THE [[Store Is Closing]]!! ALL QUERIES [[Resolved]]!!",
	"I WAS A [[Big Shot]] ALL ALONG!! ANALYSIS [[Complete]]!!",
	"[[Receipt]] PRINTED!! ANOTHER SATISFIED [[Victim]] I MEAN [[Customer]]!!",
];

// ── Public API ──────────────────────────────────────────────────────────

fn pool(ctx: NarrativeContext) -> &'static [&'static str] {
	match character() {
		1 => match ctx {
			NarrativeContext::Init => JEVIL_INIT,
			NarrativeContext::Mutation => JEVIL_MUTATION,
			NarrativeContext::Escalation => JEVIL_ESCALATION,
			NarrativeContext::Deduction => JEVIL_DEDUCTION,
			NarrativeContext::Passive => JEVIL_PASSIVE,
			NarrativeContext::QueryPass => JEVIL_QUERY_PASS,
			NarrativeContext::QueryFail => JEVIL_QUERY_FAIL,
			NarrativeContext::Finished => JEVIL_FINISHED,
		},
		2 => match ctx {
			NarrativeContext::Init => SPAMTON_INIT,
			NarrativeContext::Mutation => SPAMTON_MUTATION,
			NarrativeContext::Escalation => SPAMTON_ESCALATION,
			NarrativeContext::Deduction => SPAMTON_DEDUCTION,
			NarrativeContext::Passive => SPAMTON_PASSIVE,
			NarrativeContext::QueryPass => SPAMTON_QUERY_PASS,
			NarrativeContext::QueryFail => SPAMTON_QUERY_FAIL,
			NarrativeContext::Finished => SPAMTON_FINISHED,
		},
		_ => match ctx {
			NarrativeContext::Init => DEFAULT_INIT,
			NarrativeContext::Mutation => DEFAULT_MUTATION,
			NarrativeContext::Escalation => DEFAULT_ESCALATION,
			NarrativeContext::Deduction => DEFAULT_DEDUCTION,
			NarrativeContext::Passive => DEFAULT_PASSIVE,
			NarrativeContext::QueryPass => DEFAULT_QUERY_PASS,
			NarrativeContext::QueryFail => DEFAULT_QUERY_FAIL,
			NarrativeContext::Finished => DEFAULT_FINISHED,
		},
	}
}

/// Pick a narrative line for the given context, using `seed` to vary selection.
pub fn pick_narrative(ctx: NarrativeContext, seed: u64) -> String {
	let p = pool(ctx);
	let idx = (seed as usize) % p.len();
	p[idx].to_string()
}

/// Pick a mutation narrative with `{P}` replaced by the principal name.
pub fn narrative_for_mutation(principal: &str, seed: u64) -> String {
	let p = pool(NarrativeContext::Mutation);
	let idx = (seed as usize) % p.len();
	p[idx].replace("{P}", principal)
}
