# Security Policy

## Scope

Verifpal is a formal verification tool for cryptographic protocols. Security-relevant areas include:

- **Parser (`src/parser.rs`):** Parses `.vp` protocol model files. Malformed input could trigger unexpected behavior.
- **Verification engine (`src/verify.rs`, `src/verifyactive.rs`, `src/verifyanalysis.rs`):** Performs symbolic analysis under an active attacker model. Bugs here could cause security properties to be incorrectly verified.
- **Primitive definitions (`src/primitive.rs`):** Built-in cryptographic primitives and their symbolic reduction rules. Errors could lead to unsound analysis results.
- **Resolution and rewriting (`src/resolution.rs`, `src/rewrite.rs`):** Value resolution and term rewriting during analysis. Incorrect behavior could cause missed attacks or false positives.

## Reporting a Vulnerability

If you discover a security vulnerability in Verifpal, you are welcome to report it however you prefer. Coordinated or responsible disclosure is appreciated but not required. Choose whichever channel works best for you:

- **Public issue or pull request:** Open a [GitHub issue](https://github.com/symbolicsoft/verifpal/issues) or submit a pull request with a fix. This is perfectly fine and gets the community involved sooner.
- **Private advisory:** Open a [private security advisory](https://github.com/symbolicsoft/verifpal/security/advisories/new) on GitHub if you prefer to discuss the issue confidentially before it is made public.
- **Email:** Send a report to the maintainers via the contact information on [symbolic.software](https://symbolic.software).

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof of concept (ideally a `.vp` model file that triggers the bug).
- The affected component (parser, verification engine, primitive definitions, etc.).
- The version or commit hash you tested against.

We will acknowledge receipt within 7 days and aim to provide a fix or mitigation plan within 30 days, depending on severity.

## Supported Versions

Security fixes are applied to the latest release on the `master` branch. There is no backporting to older versions.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Security Considerations for Users

- **Verifpal is a verification tool, not a runtime cryptographic library.** Its output is only as reliable as the correctness of its analysis engine and primitive definitions. Always review verification results critically.
- **Soundness matters.** If Verifpal reports that a query is satisfied, a bug in the verification engine could mean that an attack actually exists. If you are relying on Verifpal results for production protocol design, consider cross-checking with other tools (e.g., ProVerif, Tamarin).
- **Pin your version.** Use a specific release or commit hash rather than tracking `master` to avoid unexpected changes in verification behavior.
