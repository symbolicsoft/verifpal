<!---
# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-SA-4.0
-->

[![CI](https://github.com/symbolicsoft/verifpal/actions/workflows/main.yml/badge.svg)](https://github.com/symbolicsoft/verifpal/actions/workflows/main.yml)

# [Verifpal](https://verifpal.com)

## What is Verifpal?
<img src="https://verifpal.com/res/img/png/pose1.png" alt="" align="left" height="300" style="margin:10px" />

Verifpal is new software for verifying the security of cryptographic protocols. Building upon contemporary research in symbolic formal verification, Verifpal’s main aim is to appeal more to real-world practitioners, students and engineers without sacrificing comprehensive formal verification features.

In order to achieve this, Verifpal introduces a new, intuitive language for modeling protocols that is much easier to write and understand than the languages employed by existing tools. At the same time, Verifpal models an active attacker that can read the network and tamper with any value you have not explicitly guarded, reasons about fresh values, and supports queries for advanced security properties such as forward secrecy and key compromise impersonation. Verifpal's goal-directed search solves backwards from each query, so an attack requiring several simultaneous substitutions is found without any search budget having to afford it.

**Every principal you declare runs two concurrent sessions by default.** Concurrency is what deployment looks like, and a single run of each role cannot even express an attack that needs two of that role's fresh values to coexist. Each session draws its own `generates` values and assignment outputs while long-term material (`knows`) is shared, and the attacker may route any session's traffic into any other — so cross-session attacks are found by default: an oracle in one session forging something another session accepts, a nonce swapped between two instances of a role, a message from one session replayed into another under the same long-term key.

None of this changes the modeling language. Session replication is exactly the hand-written `Alice2`/`na2` duplication that modelers already do, performed for you, and the expanded model is one you could have written yourself. `verifpal verify model.vp --sessions k` sets the count: `--sessions 1` restores single-session analysis when a large model needs the speed back, and higher values go further. Two sessions costs roughly 4× — almost every shipped example still analyzes in under five seconds.

This is more coverage, not a proof. A passing query under `k` sessions means no attack was found within `k` sessions, never that none exists — unlike the unbounded session replication offered by [ProVerif](https://proverif.inria.fr) and [Tamarin](https://tamarin-prover.github.io), which buy that guarantee at the cost of possible non-termination and a third "cannot be proved" verdict. Verifpal instead always terminates and reports only attacks it has concretely reproduced.

Verifpal has already been used to verify security properties for Signal, Scuttlebutt, TLS 1.3, Telegram and other protocols. It is a community-focused project, and available under a GPLv3 license.

#### An Intuitive Protocol Modeling Language
The Verifpal language is meant to illustrate protocols close to how one may describe them in an informal conversation, while still being precise and expressive enough for formal modeling. Verifpal reasons about the protocol model with explicit principals: Alice and Bob exist and have independent states.

#### Modeling that Avoids User Error
Verifpal does not allow users to define their own cryptographic primitives. Instead, it comes with built-in cryptographic functions — this is meant to remove the potential for users to define fundamental cryptographic operations incorrectly.

#### Easy to Understand Analysis Output
When a contradiction is found for a query, Verifpal first minimizes the attack — dropping every substitution the attack did not actually need — and then narrates what remains as numbered causal steps, in the order the attacker would have to carry them out. Each step is one of three kinds: a substitution on the wire, a checked primitive that passed on attacker-controlled input, or a derivation. Values are named using the names your own model gave them, so the trace reads in your vocabulary rather than the engine's.

When an analysis is performed under declared weakening assumptions, or when the search deliberately declines to explore a branch, Verifpal says so in the output rather than leaving it implicit.

#### Friendly and Integrated Software
Verifpal comes with a Visual Studio Code extension that offers syntax highlighting, automatic formatting, live analysis, diagram visualizations and much more, allowing developers to obtain insights on their model as they are writing it.

## Sound, but Incomplete
Verifpal is sound but incomplete by design: any attack it reports should be genuine, but its search may still miss one. Soundness is enforced structurally rather than argued. Nothing in the solver can record a query result; it can only *propose* a substitution. Every proposal is materialized into a real principal state, re-executed through the ordinary analysis pipeline, and re-checked against actual attacker knowledge before anything is allowed to resolve. A bug in the solver therefore costs a missed attack and cannot manufacture a false one.

Know what a passing query does and does not tell you. It means "this search found no attack", which is weaker than a proof; Verifpal does not support observational equivalence or user-defined equational theories. For production protocol design, cross-checking with [ProVerif](https://proverif.inria.fr) and [Tamarin](https://tamarin-prover.github.io) remains good practice.

An earlier release shipped a Coq formalization of Verifpal's syntax, semantics and *passive* attacker analysis. That layer covered the half of the tool where little could go wrong and did not reach the active search, where every false attack in the project's history originated; it has been retired in favor of the propose-and-validate architecture described above.

## Getting Started

### Verifpal User Manual
The [Verifpal User Manual](https://static.verifpal.com/manual.pdf) is an essential guide to getting started with cryptographic protocol analysis using Verifpal. It is strongly recommended that you read the Verifpal User Manual before starting work with Verifpal.

### Getting a Copy of Verifpal
On Windows, the best way to install Verifpal is through the [Scoop](https://scoop.sh) package manager, since you'll also get automatic updates:

```
scoop bucket add verifpal https://github.com/symbolicsoft/verifpal.git
scoop install verifpal
```

On Linux and macOS, the best way to install Verifpal is through the [Homebrew](https://brew.sh) package manager, since you'll also get automatic updates:

```
brew tap verifpal.com/source https://github.com/symbolicsoft/verifpal
brew install verifpal
```

Otherwise, you can:

- *Download and install a release manually*: Releases for Windows, Linux, macOS and FreeBSD are available [here](https://github.com/symbolicsoft/verifpal/releases).
- *Compile from source*: Keep reading!

### Building Verifpal from Source
You must have [Rust](https://www.rust-lang.org) installed in order to build Verifpal. Please review the [Rust Getting Started](https://www.rust-lang.org/tools/install) instructions in order to understand how to best install Rust for your computer and operating system.

#### Compiling Verifpal
Simply type `cargo build --release` to build Verifpal. The binary will be available under `target/release/`.

#### Running Tests
Simply type `cargo test --release` to run the full test suite.

### Verifpal for Visual Studio Code
Verifpal comes with a Visual Studio Code extension that offers syntax highlighting, automatic formatting, live analysis, diagram visualizations and much more, allowing developers to obtain insights on their model as they are writing it. To install it, simply search for "Verifpal" from inside Visual Studio Code. More information available [here](https://github.com/symbolicsoft/verifpal-vscode).

## Discussion
Sign up to the [Verifpal Mailing List](https://lists.symbolic.software/mailman/listinfo/verifpal) to stay informed on the latest news and announcements regarding Verifpal, and to participate in Verifpal discussions.

## License
Verifpal and Verifpal for Visual Studio Code are published by Symbolic Software. They are provided as free and open source software, licensed under the [GNU General Public License, version 3](https://www.gnu.org/licenses/gpl-3.0.en.html). The Verifpal User Manual is provided under the [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)](https://creativecommons.org/licenses/by-nc-nd/4.0/) license.

© Copyright 2019-2026 Nadim Kobeissi. All Rights Reserved. “Verifpal” and the “Verifpal” logo/mascot are registered trademarks of Nadim Kobeissi.
