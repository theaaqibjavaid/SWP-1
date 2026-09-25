# SWP-1 · Universal Source Provenance Watermark System

**Source Watermark Protocol v1** — a command line tool named `swp`.

[![CI](https://github.com/theaaqibjavaid/SWP-1/actions/workflows/ci.yml/badge.svg)](https://github.com/theaaqibjavaid/SWP-1/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/theaaqibjavaid/SWP-1)](https://github.com/theaaqibjavaid/SWP-1/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-maintenance-ea4aaa)](https://github.com/sponsors/theaaqibjavaid)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](CONTRIBUTING.md#getting-set-up)
[![Platforms: Windows · Linux · macOS](https://img.shields.io/badge/platforms-windows%20%C2%B7%20linux%20%C2%B7%20macos-lightgrey)](docs/GETTING-STARTED.md)

SWP-1 embeds an owner-keyed watermark into the *literals* of a source tree — the
numbers and strings a program computes with — in a way that survives the editing
real code undergoes, and then answers one question about a tree somebody hands
you: **does this carry one of my releases, and how strong is the evidence?** It
answers with an explainable report, a machine-readable document, and an exit
code — offline, on a machine that never runs the code it is reading.

It is a provenance instrument. It is not DRM, and it does not pretend otherwise.

| | |
| --- | --- |
| **Install** | `cargo install --path crates/swp-cli --locked`, or a [prebuilt binary](https://github.com/theaaqibjavaid/SWP-1/releases) |
| **Language** | Rust 2021, MSRV 1.85, no network code path |
| **Licence** | [Apache-2.0](LICENSE) |
| **Protocol** | `SWP-1` · report schema `SWP-1-report-v2` |
| **Ask** | [discussions](https://github.com/theaaqibjavaid/SWP-1/discussions) · [open an issue](https://github.com/theaaqibjavaid/SWP-1/issues/new/choose) |
| **Report a vulnerability** | [SECURITY.md](SECURITY.md), privately |

## Contents

* [What that distinction costs, stated up front](#what-that-distinction-costs-stated-up-front)
* [Install](#install)
* [Sixty seconds](#sixty-seconds)
* [What it does](#what-it-does)
* [Documentation](#documentation)
* [What is in the box](#what-is-in-the-box)
* [How the examples are the real thing](#how-the-examples-are-the-real-thing)
* [Constraints this project accepted, on purpose](#constraints-this-project-accepted-on-purpose)
* [Contributing, sponsorship and licence](#contributing-sponsorship-and-licence)
* [Status](#status)

## What that distinction costs, stated up front

SWP-1 does **not** guarantee, and its documentation is not allowed to claim:

* legal ownership, or proof of authorship by itself;
* detection after arbitrary rewriting, or after a complete reimplementation from
  memory — a rewrite that removes every protected literal leaves nothing to key
  on;
* immunity from deliberate removal — `swp inspect fragments` can list every site,
  so the watermark is *unobtrusive*, not *secret*;
* detection of every possible copy, or zero false positives.

What it does provide is technical provenance evidence: keyed fragments that cannot
be produced without the project's root secret, an authenticated manifest of where
they were placed, and a graded report whose coincidence bound says how much of the
finding chance could explain. [Attacks, and what still gets
through](docs/SECURITY.md#attacks-and-what-still-gets-through) is the honest
version of the list above, attack by attack.

## Install

Rust 1.85 or newer. The build fetches only the packages the root `Cargo.toml`
lists under `[workspace.dependencies]` and their transitive closure — no HTTP
client among them, and no build script that reaches a network.

```sh
cargo install --path crates/swp-cli --locked
swp --version
```

Prebuilt binaries for Windows, Linux and macOS x64 are on the
[releases page](https://github.com/theaaqibjavaid/SWP-1/releases), with a `SHA256SUMS`
covering every artifact of that release:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

A release's section of [CHANGELOG.md](CHANGELOG.md) *is* its release notes, and
[docs/VALIDATION.md](docs/VALIDATION.md) lists what has been measured, the suite
that measured it, and the command that reproduces the number.

One platform difference is worth knowing before you choose a machine for the store:
on Windows the root secret is sealed with DPAPI under your own credential; on
Linux and macOS it is a file with `0600` permissions and is not encrypted at rest.
That is stated where the guarantee is described —
[docs/SECURITY.md](docs/SECURITY.md#the-one-secret-start-to-finish) — and it is the
largest known weakness of the store on those platforms.

## Sixty seconds

In a JavaScript, TypeScript or Python project, with `swp` on your `PATH`:

```console
$ swp init
swp1-… — protected at …
  name       javascript
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  3 source file(s) a scanner can use, 3721 byte(s) read — javascript 3
exit 0
```

```console
$ swp protect --sites 12
3 source files modified in place
warning: 21 candidate location(s) were refused for safety; the release carries 10 sites
protected swp1-… — release rel-…
  sites       10/12 embedded, 21 refused
  tag         4 bits per site
  fingerprint … (L1)
exit 0
```

```console
$ swp verify
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
exit 0
```

```console
$ swp scan ./copy
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

Project swp1-… · release rel-…
  Watermark fragments: 10/10
  Exact renderings: 10
  Keyed bits confirmed: 40 at 4 bits per site
  Fingerprint (10): match
  Evidence: VERY_STRONG
exit 1
```

`swp protect` is the only command that edits your source, and ten of twelve sites
is not a shortfall: a location whose radius already belongs to another site is
skipped, never forced. `scan` exits `1` because *that is the finding*, not a
failure — `0` means a fully examined candidate holds no evidence, and `10` means
part of it was never examined. [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)
walks through all of it, one step at a time.

## What it does

**Protect a tree.** `swp generate` plans a release and prints every refusal with
its reason; `swp protect` writes it and, for each chosen site, rewrites the
literal, re-parses the file and re-proves the value is unchanged before counting
it. A signed private manifest records where the sites are; a public release record
carries a fingerprint of the tree, which a scanner can check without the secret.

**Re-examine your own tree.** `swp verify` authenticates the manifest and reports
whether each site still carries its code. It is the command that belongs in CI,
and it exits non-zero when a protected tree no longer matches its release.

**Judge somebody else's tree.** `swp scan` takes a directory or an archive —
`.zip`, `.tar.gz`, `.gz` — extracts it into a private temporary directory, refuses
path traversal and symlink entries, and never executes anything it finds. It
answers over five channels: keyed fragments, exact renderings, canonicalized
renderings, the release fingerprint, and structure.

**Say how strong the evidence is, and what it is worth.** The ladder runs
`NONE · WEAK · MODERATE · STRONG · VERY_STRONG`, and each rung is a stated count
rather than a heuristic. Beside the level, a report prints the coincidence bound —
how much of the finding chance could produce — and the looser bound that assumes
nothing about which spans may be one span. The level is not a finding about
authorship, and [Reading a report](docs/USER-GUIDE.md#reading-a-report) says what
each field may be used to claim.

**Keep the evidence.** `swp verify --save` stores the report that produced a
verdict, `swp report` re-renders a stored one without re-scanning anything, and a
document can be exported with `swp report --output <name>`.

**Three languages, one refusal, and a rule about the difference.** JavaScript,
TypeScript and Python have real tree-sitter adapters sharing a dialect table of
equivalent literal spellings. Everything else — `examples/generic` is C, shell and
SQL — is refused with `NO_SAFE_LOCATIONS` and nothing written, because a scan that
cannot re-read what it rewrote cannot re-prove it either.

## Documentation

| page | what it answers |
| --- | --- |
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | install it, protect a project, scan a copy, back it up |
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | the workflows, and every field of a report |
| [docs/CLI.md](docs/CLI.md) | every command, option, exit code and error message |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | what each error asks of you, symptom first |
| [docs/SECURITY.md](docs/SECURITY.md) | the secret's life, hostile input, and ten attacks measured against this build |
| [docs/SWP-1-SPEC.md](docs/SWP-1-SPEC.md) | the protocol itself: fragments, identities, artifacts, detection, versioning |
| [docs/DEVELOPER-GUIDE.md](docs/DEVELOPER-GUIDE.md) | building, testing and changing this repository, including writing a language adapter |
| [docs/VALIDATION.md](docs/VALIDATION.md) | what has been measured, and the command that reproduces each number |
| [examples/](examples) | four protected trees, each with the transcript that proves it |

Around the protocol documentation sits the repository's own set:

| file | what it is |
| --- | --- |
| [CHANGELOG.md](CHANGELOG.md) | what shipped, and what a release deliberately does not include |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to build it, what CI rejects, the rules the shape is made of |
| [CLA.md](CLA.md) | the contributor licence agreement, including what it grants the maintainers |
| [SECURITY.md](SECURITY.md) | how to report privately, what counts as a vulnerability here, the backport policy |
| [SPONSORS.md](SPONSORS.md) | the tiers, and what sponsorship does not buy |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | the standard, and how it is enforced |
| [LICENSE](LICENSE) · [NOTICE](NOTICE) | Apache-2.0, and the third-party surface it is built against |

## What is in the box

| crate | what it owns |
| --- | --- |
| `swp-core` | the protocol's vocabulary: sites, radii, canonicalization, limits, the error model. No dependencies |
| `swp-crypto` | sealing, key derivation, ed25519 signing. Primitives are borrowed from the standard ecosystem; nothing here invents one |
| `swp-identity` | the project id, the public identity document, the store on disk |
| `swp-adapters` | the language adapters: tree-sitter grammars for JavaScript, TypeScript, Python, plus the dialect table |
| `swp-manifest` | the signed artifacts: plan, manifest, release record |
| `swp-embedding` | the walk, the candidate harvest, constellation selection, and the rewrite-and-re-prove loop |
| `swp-detection` | scanning a candidate: fragments, exact renderings, fingerprint, structure |
| `swp-evidence` | the ladder, the report document, the text renderer |
| `swp-cli` | the seven commands, the parser, the help pages |
| `swp-test-suite` | every measurement quoted in the documentation, driven against the real product |

The dependency direction is one-way: `swp-cli` over the services over
`swp-core`/`swp-crypto`, and only `swp-adapters` links a parser. Adding a
language therefore cannot require touching the protocol, and a change to the
evidence ladder cannot change how a fragment is rendered.

## How the examples are the real thing

`examples/javascript`, `examples/typescript`, `examples/python` and
`examples/generic` are not descriptions of a workflow; they are transcripts of
one. Every fenced `console` block in this repository — here, in `docs/`, and in
the example pages — is re-run against the current build by
`cargo test -p swp-test-suite --test docs_examples`, which protects each tree
from scratch under a fresh root secret and fails on the first line the product no
longer prints. A number that varies with the key is written as `…` rather than
invented; a number that does not is a number the test re-checks.

That is also why these pages say "not supported" out loud. `examples/generic` is
a C, shell and SQL tree, and what it shows is `swp protect` refusing it with
`NO_SAFE_LOCATIONS` and writing nothing — because a weaker scan over source this
tool cannot re-read after rewriting it is a decision a user should make with a
flag in front of them, not one a tool should assume while writing to their
source.

## Constraints this project accepted, on purpose

* **Offline, always.** No network code path. No telemetry, no phone-home, no
  source or report ever leaves the machine. No crate is fetched at build time; the
  grammars are prebuilt and the CLI has no argument-parsing dependency.
* **The root secret never appears** in source code, generated source, public
  manifests, CLI output, logs, documentation, test snapshots or temporary files.
  The `secret_leak` suite sweeps each of those artifact types after every run.
* **The scanner never executes what it reads.** No `npm install`, no `pip
  install`, no `cargo build`, no `make`, no project scripts. Archives are
  extracted into a private temporary directory, path traversal and symlink
  entries are refused, and the extraction is deleted on exit.
* **If a location cannot be embedded safely, it is skipped.** Never forced, ever.
* **Open source, with the commercial path said out loud.** The eight library crates
  and the command line tool are published under Apache-2.0; only `swp-test-suite`
  stays out of the registry, because it is this project's measurement harness
  rather than anything a user would depend on. [CLA.md](CLA.md) is what lets a
  contribution reach a product that is not Apache-2.0, and
  [SPONSORS.md](SPONSORS.md) states what funding buys — attention, and time — and
  what it will never buy.

## Contributing, sponsorship and licence

* **Start with [CONTRIBUTING.md](CONTRIBUTING.md).** It says how to build this,
  what gets reviewed and by whom, and why a stale documentation example is a build
  failure on purpose.
* **Contributions need the [CLA](CLA.md)**, and that agreement is written to be
  read rather than clicked: its
  [grant of copyright licence](CLA.md#2-licence-to-the-maintainers) is
  perpetual, irrevocable and sublicensable, which is the entire reason it exists
  instead of a `Signed-off-by:` line. Declining it is a legitimate position, and
  [CONTRIBUTING.md](CONTRIBUTING.md#the-cla-and-the-dco) says what happens if you
  hold it.
* **Sponsorship funds maintenance; it does not unlock the tool.**
  [SPONSORS.md](SPONSORS.md) has the three monthly tiers and what each one is —
  $10 for pre-release builds, $100 for a 48-hour acknowledgement on a support request
  plus backport engineering for a fork of yours, $500 for a line to the person who
  decides — and a one-time $25 that buys nothing at all. It also says plainly that a
  security patch is never gated, because a provenance tool whose unpaid users run a
  known-broken detector is not a tool worth buying.
* **Report a security problem through [SECURITY.md](SECURITY.md)**, not an issue.
  What counts as a vulnerability here is narrower than it looks — removal by
  somebody who holds the source is documented behaviour — and the list of what
  does count is on that page.
* **Ask in [discussions](https://github.com/theaaqibjavaid/SWP-1/discussions) or
  an issue**, and attach three things: `swp --version`, the full transcript
  including the `exit N` line, and the smallest tree that reproduces it. Never
  attach `.swp/private/`, and never paste a root key into anything; a project id,
  a path or a report is safe to publish, and
  [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md#reporting-a-failure) says what
  else a maintainer needs. There is no support SLA for unpaid use — what a tier
  buys is stated in [SPONSORS.md](SPONSORS.md) — and maintenance is currently the
  owner plus one maintainer, which [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) says
  out loud where that fact limits what it can promise.
* **Licence.** Apache-2.0, with [NOTICE](NOTICE) naming every third-party component
  this build links. The protocol, the `SWP-1` name and the report schema are not
  licensed for reuse as identity: a fork that changes the wire format should change
  what it calls itself, because a report that claims `SWP-1-report-v2` while
  meaning something else is the one outcome this project cannot afford.

## Status

Protocol v1.0.0, implemented end to end: embed, verify, scan, report. The public
build carries `1.0.0-beta.2`: the protocol is settled and a tree protected by
this build verifies against the release after it, so what the beta withholds is the
endorsement rather than the functionality. Three
languages with real parser adapters, one refusal that is a design decision, and a
test suite that includes an adversarial section whose job is to defeat the
watermark. [docs/VALIDATION.md](docs/VALIDATION.md) lists what has been measured
and the command that reproduces each number; CHANGELOG.md says, in plain sight,
what this release deliberately does not include.
