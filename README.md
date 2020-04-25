<!---
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-SA-4.0
-->

# [Verifpal](https://verifpal.com)

## What is Verifpal?
<img src="https://verifpal.com/res/img/png/pose1.png" alt="" align="left" height="300" style="margin:10px" />

Verifpal is new software for verifying the security of cryptographic protocols. Building upon contemporary research in symbolic formal verification, Verifpal’s main aim is to appeal more to real-world practitioners, students and engineers without sacrificing comprehensive formal verification features.

In order to achieve this, Verifpal introduces a new, intuitive language for modeling protocols that is much easier to write and understand than the languages employed by existing tools. At the same time, Verifpal is able to model protocols under an active attacker with unbounded sessions and fresh values, and supports queries for advanced security properties such as forward secrecy or key compromise impersonation.

Verifpal has already been used to verify security properties for Signal, Scuttlebutt, TLS 1.3, Telegram and other protocols. It is a community-focused project, and available under a GPLv3 license.

#### An Intuitive Protocol Modeling Language
The Verifpal language is meant to illustrate protocols close to how one may describe them in an informal conversation, while still being precise and expressive enough for formal modeling. Verifpal reasons about the protocol model with explicit principals: Alice and Bob exist and have independent states.

#### Modeling that Avoids User Error
Verifpal does not allow users to define their own cryptographic primitives. Instead, it comes with built-in cryptographic functions — this is meant to remove the potential for users to define fundamental cryptographic operations incorrectly.

#### Easy to Understand Analysis Output
When a contradiction is found for a query, the result is related in a readable format that ties the attack to a real-world scenario. This is done by using terminology to indicate how the attack could have been possible, such as through a man-in-the-middle on ephemeral keys.

#### Friendly and Integrated Software
Verifpal comes with a Visual Studio Code extension that offers syntax highlighting, automatic formatting, live analysis, diagram visualizations and much more, allowing developers to obtain insights on their model as they are writing it.

## Verifpal is Experimental Software
Verifpal is still highly experimental software. Using it in a classroom or learning environment is welcome, but it should not yet be relied upon for academic formal verification work. For that, check out ProVerif: https://proverif.inria.fr.

## Getting Started

### Verifpal User Manual
The [Verifpal User Manual](https://verifpal.com/res/pdf/manual.pdf) is an essential guide to getting started with cryptographic protocol analysis using Verifpal. It is strongly recommended that you read the Verifpal User Manual before starting work with Verifpal.

### Getting a Copy of Verifpal
On Windows, the best way to install Verifpal is through the [Scoop](https://scoop.sh) package manager, since you'll also get automatic updates:

```
scoop bucket add verifpal https://source.symbolic.software/verifpal/verifpal.git
scoop install verifpal
```

On Linux and macOS, the best way to install Verifpal is through the [Homebrew](https://brew.sh) package manager, since you'll also get automatic updates:

```
brew tap verifpal.com/source https://source.symbolic.software/verifpal/verifpal
brew install verifpal
```

On Linux, Verifpal is also available via Snap:

<a href="https://snapcraft.io/verifpal">
	<img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-white.svg" />
</a>

Otherwise, you can:

- *Download and install a release manually*: Releases for Windows, Linux, macOS and FreeBSD are available [here](https://source.symbolic.software/verifpal/verifpal/-/releases).
- *Compile from source*: Keep reading!

### Building Verifpal from Source
You must have [Go](https://golang.org) installed in order to build Verifpal. Please review the [Go Getting Started](https://golang.org/doc/install) instructions in order to understand how to best install Go for your computer and operating system.

#### Installing Dependencies
Verifpal relies on the [Pigeon](https://github.com/mna/pigeon) PEG parser generator and the [Aurora](https://github.com/logrusorgru/aurora) ANSI color printer. you can easily install them by typing `make dependencies`.

#### Compiling Verifpal
- *Windows*: Simply type `Build` to build Verifpal for Windows, Linux, macOS and FreeBSD. This will also install dependencies.
- *Linux, macOS and FreeBSD*: Simply type `make all` to build Verifpal for Windows, Linux, macOS and FreeBSD.

Builds will be available under `build/`.

### Verifpal for Visual Studio Code
Verifpal comes with a Visual Studio Code extension that offers syntax highlighting, automatic formatting, live analysis, diagram visualizations and much more, allowing developers to obtain insights on their model as they are writing it. To install it, simply search for "Verifpal" from inside Visual Studio Code. More information available [here](https://source.symbolic.software/verifpal/verifpal-vscode/-/blob/master/README.md).

## Discussion
Sign up to the [Verifpal Mailing List](https://lists.symbolic.software/mailman/listinfo/verifpal) to stay informed on the latest news and announcements regarding Verifpal, and to participate in Verifpal discussions.

## License
Verifpal is published by Symbolic Software. It is provided as free and open source software, licensed under the [GNU General Public License, version 3](https://www.gnu.org/licenses/gpl-3.0.en.html). The Verifpal User Manual is provided under the [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)](https://creativecommons.org/licenses/by-nc-nd/4.0/) license.

© Copyright 2019-2020 Nadim Kobeissi. All Rights Reserved. “Verifpal” and the “Verifpal” logo/mascot are registered trademarks of Nadim Kobeissi.
