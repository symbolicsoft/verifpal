<!---
# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-SA-4.0
-->

# [Verifpal](https://verifpal.com)

[![CI](https://github.com/symbolicsoft/verifpal/actions/workflows/main.yml/badge.svg)](https://github.com/symbolicsoft/verifpal/actions/workflows/main.yml)

<img src="https://verifpal.com/res/img/png/pose1.png" alt="" align="left" height="265" style="margin:10px" />

Verifpal is software for verifying the security of cryptographic protocols. It comes out of the same symbolic verification tradition as [ProVerif](https://proverif.inria.fr) and [Tamarin](https://tamarin-prover.github.io), but is written for practitioners and students rather than for specialists.

You describe a protocol roughly the way you would describe it out loud, and the description is still precise enough to analyze. Primitives are built in rather than user-defined, which removes a common source of modeling error. The attacker is active: it reads the network and tampers with anything you have not explicitly guarded. Queries cover forward secrecy, key compromise impersonation and other properties that depend on fresh values.

Every principal runs two concurrent sessions by default, so you get cross-session attacks (a nonce swapped between two instances of a role, a message replayed from one session into another) without duplicating principals by hand. Set the count with `verifpal verify model.vp --sessions k`.

When a query is contradicted, Verifpal minimizes the attack and then narrates what remains as numbered causal steps, using the names your model gave the values. If the analysis ran under declared weakening assumptions, or the search declined a branch, the output says so.

Verifpal has been used to verify security properties for Signal, Scuttlebutt, TLS 1.3, Telegram and other protocols.

## Scientific Paper

[*Verifpal Seven Years Later: Can a Toy Become an Instrument?*](https://eprint.iacr.org/2026/1654) documents the semantics, the deduction rules, the search, the soundness theorem, the termination bound and the session model, along with what each of them does not cover.

## Sound, but Incomplete

Any attack Verifpal reports should be genuine; its search may still miss one. Soundness is structural rather than argued. The solver can only *propose* a substitution. Every proposal is then materialized into real principal state, re-executed through the ordinary analysis pipeline, and re-checked against actual attacker knowledge before it is allowed to resolve. A solver bug therefore costs you a missed attack and cannot manufacture a false one.

A passing query means "this search found no attack", which is weaker than a proof. Verifpal supports neither observational equivalence nor user-defined equational theories, and it always terminates instead of offering unbounded session replication. If you are designing a protocol for production, cross-check it with ProVerif and Tamarin.

## Getting Started

Read the [Verifpal User Manual](https://static.verifpal.com/manual.pdf) first.

On Windows, install through [Scoop](https://scoop.sh):

```
scoop bucket add verifpal https://github.com/symbolicsoft/verifpal.git
scoop install verifpal
```

On Linux and macOS, install through [Homebrew](https://brew.sh):

```
brew tap verifpal.com/source https://github.com/symbolicsoft/verifpal
brew install verifpal
```

Both give you automatic updates. Otherwise, grab a [release](https://github.com/symbolicsoft/verifpal/releases) for Windows, Linux, macOS or FreeBSD, or build from source.

### Building from Source

With [Rust](https://www.rust-lang.org/tools/install) installed, `cargo build --release` produces the binary under `target/release/`. `cargo test --release` runs the full test suite.

### Editor Support

Verifpal ships a language server (`verifpal lsp`), and the project maintains an extension for each of these editors on top of it:

- [Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=symbolicsoft.verifpal) ([source](https://github.com/symbolicsoft/verifpal-vscode)): syntax highlighting, automatic formatting, live query analysis and protocol diagrams as you write the model. Search for "Verifpal" from inside Visual Studio Code to install it.
- [Neovim](https://github.com/symbolicsoft/verifpal-nvim): syntax highlighting, verification diagnostics on each query line, formatting and hover documentation.
- [Zed](https://github.com/symbolicsoft/verifpal-zed): syntax highlighting, live error checking and attacker analysis.

## License

Verifpal and its editor extensions are published by Symbolic Software as free and open source software under the [GNU General Public License, version 3](https://www.gnu.org/licenses/gpl-3.0.en.html). The Verifpal User Manual is provided under the [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)](https://creativecommons.org/licenses/by-nc-nd/4.0/) license.

© Copyright 2019-2026 Nadim Kobeissi. All Rights Reserved. “Verifpal” and the “Verifpal” logo/mascot are registered trademarks of Nadim Kobeissi.
