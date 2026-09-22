# Developer guide

How this workspace is built, which rules its shape is made of, and what a change
has to survive before it is called done. It is written for somebody editing the
tool rather than using it — for the latter see
[USER-GUIDE.md](USER-GUIDE.md) and [CLI.md](CLI.md). The protocol itself is
[SWP-1-SPEC.md](SWP-1-SPEC.md); what is trusted is
[SECURITY.md](SECURITY.md); every number quoted here is reproduced in
[VALIDATION.md](VALIDATION.md).

## The workspace

Ten library crates, one binary crate, one test crate. `crates/*` is the whole
member list of the root `Cargo.toml`, which pins `version = "1.0.0"`,
`edition = "2021"`, `rust-version = "1.85"`, `publish = false` and
`license = "LicenseRef-Proprietary"` for all of them at once.

| crate | owns | may depend on |
| --- | --- | --- |
| `swp-core` | canonicalization, tokens, ids, error codes, limits, canonical JSON | nothing in this workspace |
| `swp-crypto` | key derivation, the secret type, sealing, Ed25519 signing, project ids | core |
| `swp-identity` | the `.swp/` store: config, identity, release records, plans, manifests, reports | core, crypto |
| `swp-manifest` | the private manifest document, the four site keys, the fingerprint, signing bytes | core, crypto, identity |
| `swp-adapters` | tree-sitter grammars, parsing, literal forms, safety checks, the generic fallback | core, crypto, manifest |
| `swp-embedding` | the walk, candidate location, selection, plan, and the rewrite itself | everything above |
| `swp-detection` | input sniffing, container extraction, the two-pass site search | everything above |
| `swp-evidence` | evidence items, the level ladder, the coincidence bound, the report document | core, crypto, manifest, detection |
| `swp-cli` | argument parsing, the seven commands, rendering, exit codes | all of them |
| `swp-test-suite` | fixtures, transforms, the measurement suites, the documentation test | used as a dev-dependency only |

`swp-adapters` is the only crate that links tree-sitter, which is what keeps the
C parsing surface in one place. Two structural rules are worth stating because
they are load-bearing rather than stylistic:

* **Nothing below `swp-adapters` knows what JavaScript is.** Language names reach
  the deeper crates only as opaque strings handed over by an adapter and stored
  in a manifest, and `registry.for_language(name)` is the one lookup. A new
  language is therefore an adapter plus a grammar dependency, not a `match`
  scattered through the pipeline.
* **`swp-evidence` never opens a file.** It is graded from the `Detection` struct
  it is handed, so the same code serves `scan` (which must not trust the
  candidate) and `verify` (which may trust its own store) without a flag
  deciding which rules apply.

## The rules a change cannot break

These are the brief's absolutes, restated as engineering constraints. A pull
request that violates one is not a style problem.

1. **No behavioral regression.** The rewrite path is allowed to edit a literal
   only after the result has been re-parsed and the value proved identical, and a
   site whose radius text changes is refused. The guard is
   `crates/swp-adapters/tests/token_stream.rs`, which re-canonicalizes the whole
   file after each edit and fails if anything outside the edited statement moved.
2. **Skip, never force (§11).** Every refusal in `swp-embedding` is a `plan`
   entry with a reason, and the reasons are printed by `swp protect` and by
   `swp inspect plan`. There is no flag that overrides a safety refusal, and adding
   one would need the whole skip taxonomy re-examined.
3. **Never execute the candidate (§21).** No process is spawned anywhere in
   `swp-detection`, `swp-embedding` or `swp-evidence`; the only `Command::new` in
   the product is the one in `swp-crypto/src/seal.rs` that calls `icacls` on a
   file this program just wrote. Nothing installs, builds, imports or evaluates a
   project's code, and the scanner does not read a candidate's own `.swp/`.
4. **No network.** There is no HTTP client and no socket library in the
   dependency graph. [SECURITY.md](SECURITY.md#offline-and-how-to-check-that-claim)
   prints the two commands that verify that claim and the firewall test.
5. **The secret is never printable (§29).** `SecretBytes` has no `Display`, no
   `Serialize` and no `Clone`, and its `Debug` is `SecretBytes([REDACTED N
   bytes])`. Key material is derived, used, and dropped. The seven tests in
   `tests/leak/secret_scan.rs` install two known needles and sweep every artifact,
   every command's stdout and stderr, and every temporary file the write path can
   leave behind.
6. **Every loop is bounded (§45).** Bounds live in `swp-core/src/limits.rs`, come
   from `Limits` rather than a local constant, and are clamped to
   `Limits::ceiling()` — a repository's own config may lower a limit but cannot
   raise it past the hard ceiling, which is what stops a hostile `.swp/config.toml`
   from arguing the safety away.
7. **Do not invent thresholds; document observed results (§24).** Every number in
   this repository's prose is printed by a test. If you change a rule that moves a
   number, the suite that measures it has to be re-run and the documentation
   re-quoted in the same change.
8. **Do not fake support, and do not use fake output in documentation (§40).** A
   language, form or flag that does not exist must not appear in a transcript, a
   table, or an example.

## Building and testing

```text
cargo build --workspace
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets
cargo fmt --all --check
```

`cargo test --workspace` runs the unit tests inside each crate plus the eleven
named suites in `swp-test-suite`. They are deliberately separate targets, because
each one answers a different section of the brief and a measurement you cannot run
by name is a measurement nobody re-runs:

| suite | file | measures |
| --- | --- | --- |
| `secret_leak` | `tests/leak/secret_scan.rs` | §29 — the seven sweeps named above |
| `detection_matrix` | `tests/detection/matrix.rs` | §24 the partial-copy ladder, §25 the thirteen refactoring forms, §26 the four removals, §51 an excluded directory, the §52 padded copy |
| `family_roundtrip` | `tests/detection/roundtrip.rs` | every literal form renders, re-parses and decodes back to its value |
| `false_positive` | `tests/false_positive/corpora.rs` | §27 — 30 scans of six corpora, six generated siblings, shared constants |
| `collision` | `tests/collision/identities.rs` | §28 — disjoint constellations, the id space, 800-symbol draw |
| `property_chains` | `tests/property/chains.rs` | §43 — random attack and refactoring chains, and the verdict contract |
| `resource_limits` | `tests/resource/hostile.rs` | §45 — depth, size, file count, archive bomb, malformed input |
| `performance` | `tests/performance/scale.rs` | §44 — the size ladder, per-file cost, repeated protection |
| `adversarial_removal` | `tests/adversarial/attacks.rs` | §52 — shape search and fold, revert, restructure, compound, two-project planting |
| `acceptance_scenario` | `tests/acceptance/final_scenario.rs` | §57 — the end-to-end two-project scenario |
| `docs_examples` | `tests/docs/examples.rs` | §41 — every documented transcript |
| *(library)* | `crates/*/src` | unit tests beside the code they test, including the pinned derivation vectors |

Most of these suites print the table they measured, because a number nobody can
re-run is not a number anyone should quote in a document — which is where the
figures in [VALIDATION.md](VALIDATION.md) come from. Read them with `--nocapture`:

```text
cargo test -p swp-test-suite --test detection_matrix -- --nocapture
cargo test -p swp-test-suite --test performance -- --nocapture
```

`performance` prints the profile it measured in, and it measures a debug build in
CI-adjacent conditions on purpose: the ratio between tiers is the claim, and an
absolute millisecond figure from one busy laptop is not a claim anybody should
have to defend. Its guard is the ratio, not the time, for exactly that reason.

## The documentation is a test

§41 asks that a documented command be one that was run, and that a stale example
fail the build. That is what `tests/docs/examples.rs` does, and the convention the
pages obey is small:

* a ` ```console ` block is verbatim tool output; the first line is
  `$ swp <args>`, and that header must match **exactly one** command the test run
  executed, or the block is an error;
* `…` (U+2026) stands for whatever the project's key decides — ids, digests,
  timestamps, absolute paths, per-site families and renderings, byte growth, the
  probe and chance columns;
* matching is per line, whitespace-split, in order, so a block quotes a subset of
  a transcript but may not reorder it;
* a trailing `exit N` line is compared against the command's real exit code rather
  than its own text;
* an inline single-line `` `swp …` `` span is fed to the argument parser, so a page
  cannot name a flag that does not exist.

The transcripts are produced by `scripts/capture-docs.sh` (`SWP=target/release/swp
sh scripts/capture-docs.sh /tmp/out`) and re-executed by the test on every run,
against the four projects under `examples/`. Two floor assertions keep the check
from thinning out: at least sixty blocks and at least forty distinct commands must
be covered.

The practical rule when you change output: run the suite, read the diff it prints,
and fix the *page* only if the new output is what you meant. A failure that shows a
number you did not intend is a product bug, and editing the document to match it is
how a documentation test stops meaning anything.

## Adding a command, a flag, or a view

The parser is hand-written in `crates/swp-cli/src/args.rs` — about seven hundred
lines, no derive macros, because the error messages are the product's most-read
text and `--formt json` has to answer with `Did you mean --format?`.

1. Add the variant to `Command` (or the key to `Flag`), then extend `Command::ALL`,
   `Command::name`, and the `Command::flags` list that says which flags *this*
   command accepts. An unknown flag for a known command is a usage error, not an
   ignored one.
2. Decide `Command::needs_secret`. `generate`, `protect`, `verify` and `scan` are
   the four that need the root secret; `init` mints one; `inspect` and `report`
   must keep working with no secret at all, which is the property that lets a
   colleague audit a store they were never given.
3. Implement in a module of `swp-cli`, reached from `run_in(argv, cwd, out, err)`,
   which is what every test drives. Return a `SwpError` with a code from
   `swp-core/src/error.rs` and a `next:` advice line; the code chooses the exit
   status, so add a mapping there rather than inventing a number locally.
4. Write the help text in `crates/swp-cli/src/help.rs` — that file is the only
   source for `swp help`, `swp help <command>` and the exit-code table, and all
   three are quoted by documentation the test checks.
5. Quote the new output in [CLI.md](CLI.md) and, if it is a report, in
   [REPORTS.md](REPORTS.md), with a real transcript.

## Adding a language adapter

[LANGUAGE-ADAPTERS.md](LANGUAGE-ADAPTERS.md) is the full §39 contract: the
`Adapter` trait in `swp-adapters/src/adapter.rs`, the token and role model in
`canon.rs`, the literal-form rules in `literal.rs` and `forms.rs`, and the safety
gate in `safety.rs`. Three constraints decide whether an adapter is honest:

* it must report which literals it can normalize *by value*, and the canonicalizer
  falls back to the raw spelling when it cannot — the loss is documented, not
  hidden;
* it must return the innermost statement and enclosing scope for a byte offset,
  because those two spans are the site's four addresses;
* `safety.rs` must reject any edit that changes parse shape or value, and the
  adapter's own test file must include the round-trip case for every form it
  claims.

An adapter that cannot satisfy those is not added; the generic tokenizer in
`generic.rs` handles the files instead, at a lower guarantee, and the report says
which adapter ran. §14's fallback exists so that "unsupported" is a graded
condition rather than a crash.

## Adding an evidence kind or moving the ladder

`swp-evidence/src/item.rs` declares the kinds and each one's `basis` text, plus
`asserts_provenance()` — the flag that says whether an item may contribute to a
verdict. `STRUCTURAL_MATCH` is graded never, on purpose: an address without its
code is a lead, and any tree that canonicalizes alike can produce one.
`swp-evidence/src/level.rs` holds the ladder constants, each with the sentence
that justifies it beside it. Changing one changes what a report calls `STRONG`,
which changes what a *saved* report of a previous build means, so a ladder change
is a schema discussion, not a commit.

The coincidence arithmetic is `chance_of_coincidence` and its looser sibling, and
both figures are printed in every report: `chance` for spans sharing an address,
`loose` for counting every span separately. §23 forbids percentages, so the
output is always a count of expected coincidences next to the count observed,
never a confidence level.

## Changing a derivation

Do not. Every derivation is pinned: `pinned_derivation_vectors`,
`truncation_respects_width` and `wrong_domain_is_refused` in
`crates/swp-crypto/src/derive.rs`, and `pinned_site_identity_vector` in
`crates/swp-manifest/src/keys.rs`. A change is silent — nothing errors — but every
release already published stops matching its own manifest. If a derivation must
change, the protocol version, the `canonicalizer_version`, or the relevant domain
label changes with it, and old stores keep being read the old way.

## Style, in three sentences

Module docs quote the section of the brief they implement, because the shortest
route to a wrong implementation is a forgotten requirement. Comments explain a
constraint or a cost, never a mechanism the code already states. Error messages
name a path, say what happened, and print a `next:` line — and no message ever
quotes key material, which the leak suite enforces rather than trusts.

Before a change is finished: `cargo clippy --workspace --all-targets` clean,
`cargo fmt --all` applied, the suites that touch it re-run, and the pages that
quote it re-run by `docs_examples` rather than edited until they pass.

---

Next: [LANGUAGE-ADAPTERS.md](LANGUAGE-ADAPTERS.md) for the adapter contract,
[INTEGRATION.md](INTEGRATION.md) for CI and packaging,
[VALIDATION.md](VALIDATION.md) for the measurements this page points at.
