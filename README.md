# SWP-1 — Universal Source Provenance Watermark System

**Source Watermark Protocol v1**, a command line tool named `swp`.

SWP-1 embeds an owner-keyed watermark into the *literals* of a source tree — the
numbers and strings a program computes with — in a way that survives the editing
that real code undergoes, and then answers one question about a tree somebody
hands you: **does this carry one of my releases, and how strong is the
evidence?** It answers it with an explainable report, a machine-readable document,
and an exit code, offline, on a machine that never runs the code it is reading.

It is a provenance instrument. It is not DRM, and it does not pretend otherwise.

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
finding chance could explain. [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) is the
honest version of the list above, attack by attack.

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
| `swp-test-suite` | everything §42's matrix asks for, driven against the real product |

The dependency direction is one-way: `swp-cli` over the services over
`swp-core`/`swp-crypto`, and only `swp-adapters` links a parser. Adding a
language therefore cannot require touching the protocol, and a change to the
evidence ladder cannot change how a fragment is rendered.

## Documentation

| page | what it answers |
| --- | --- |
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | install it, protect a project, scan a copy, back it up |
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | the workflows: CI, re-protecting, archives, monorepos, the config file |
| [docs/CLI.md](docs/CLI.md) | every command, option, exit code and error message |
| [docs/SWP-1-SPEC.md](docs/SWP-1-SPEC.md) | the protocol itself: fragments, identities, artifacts, detection, versioning |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | using it per language, and which layer does what |
| [docs/LANGUAGE-ADAPTERS.md](docs/LANGUAGE-ADAPTERS.md) | writing an adapter for a language this build does not claim |
| [docs/SECURITY.md](docs/SECURITY.md) | the secret's life, the cryptographic design, what is trusted |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | ten attacks, their impact, the mitigation, and the residue |
| [docs/REPORTS.md](docs/REPORTS.md) | every field of a report, and what each may be used to claim |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | what each error asks of you |
| [docs/FAQ.md](docs/FAQ.md) | the questions that do not fit elsewhere |
| [docs/DEVELOPER-GUIDE.md](docs/DEVELOPER-GUIDE.md) | building, testing and changing this repository |
| [docs/VALIDATION.md](docs/VALIDATION.md) | what was measured, in a clean environment, with results |
| [examples/](examples) | four protected trees, each with the transcript that proves it |

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
* **Nothing is published.** `publish = false` in every manifest; this workspace is
  proprietary and self-contained.

## Status

Protocol v1.0.0, implemented end to end: embed, verify, scan, report. Three
languages with real parser adapters, one refusal that is a design decision, and a
test suite that includes an adversarial section whose job is to defeat the
watermark. [docs/VALIDATION.md](docs/VALIDATION.md) records what was measured and
what is still a limitation rather than a TODO.
