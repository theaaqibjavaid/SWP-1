# Developer guide

How this workspace is built, which rules its shape is made of, and what a change
has to survive before it is called done. It is written for somebody editing the
tool rather than using it — for the latter see
[USER-GUIDE.md](USER-GUIDE.md) and [CLI.md](CLI.md). The protocol itself is
[SWP-1-SPEC.md](SWP-1-SPEC.md); what is trusted is
[SECURITY.md](SECURITY.md); every number quoted here is reproduced in
[VALIDATION.md](VALIDATION.md).

## The workspace

Eight library crates, one crate that is both a library and the `swp` binary, and
one test crate: ten in all. `crates/*` is the whole
member list of the root `Cargo.toml`, which pins `[workspace.package] version`,
`edition = "2021"`, `rust-version = "1.85"` and `license = "Apache-2.0"` for all
of them at once, and which sets `publish = ["crates.io"]` for every crate but
`swp-test-suite` — that one says `publish = false` in its own manifest, because it
is this project's measurement harness rather than something to depend on.

| crate | owns | may depend on |
| --- | --- | --- |
| `swp-core` | canonicalization, tokens, ids, error codes, limits, canonical JSON | nothing in this workspace |
| `swp-crypto` | key derivation, the secret type, sealing, Ed25519 signing, project ids | core |
| `swp-identity` | the `.swp/` store: config, identity, release records, plans, manifests, reports | core, crypto |
| `swp-manifest` | the private manifest document, the four site keys, the fingerprint, signing bytes | core, crypto, identity |
| `swp-adapters` | tree-sitter grammars, parsing, literal forms, safety checks, the generic fallback | core, crypto |
| `swp-embedding` | the walk, candidate location, selection, plan, and the rewrite itself | everything above |
| `swp-detection` | input sniffing, container extraction, the two-pass site search | everything above |
| `swp-evidence` | evidence items, the level ladder, the coincidence bound, the report document | core, identity, manifest, detection |
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

These are the project's absolutes, restated as engineering constraints. A pull
request that violates one is not a style problem.

1. **No behavioral regression.** The rewrite path is allowed to edit a literal
   only after the result has been re-parsed and the value proved identical, and a
   site whose radius text changes is refused. The guard is
   `crates/swp-adapters/tests/token_stream.rs`, which re-canonicalizes the whole
   file after each edit and fails if anything outside the edited statement moved.
2. **Skip, never force.** Every refusal in `swp-embedding` is a `plan`
   entry with a reason, and the reasons are printed by `swp protect` and by
   `swp inspect plan`. There is no flag that overrides a safety refusal, and adding
   one would need the whole skip taxonomy re-examined.
3. **Never execute the candidate.** No process is spawned anywhere in
   `swp-detection`, `swp-embedding` or `swp-evidence`; the only `Command::new` in
   the product is the one in `swp-crypto/src/seal.rs` that calls `icacls` on a
   file this program just wrote. Nothing installs, builds, imports or evaluates a
   project's code, and the scanner does not read a candidate's own `.swp/`.
4. **No network.** There is no HTTP client and no socket library in the
   dependency graph. [SECURITY.md](SECURITY.md#offline-and-how-to-check-that-claim)
   prints the two commands that verify that claim and the firewall test.
5. **The secret is never printable.** `SecretBytes` has no `Display`, no
   `Serialize` and no `Clone`, and its `Debug` is `SecretBytes([REDACTED N
   bytes])`. Key material is derived, used, and dropped. The seven tests in
   `tests/leak/secret_scan.rs` install two known needles and sweep every artifact,
   every command's stdout and stderr, and every temporary file the write path can
   leave behind.
6. **Every loop is bounded.** Bounds live in `swp-core/src/limits.rs`, come
   from `Limits` rather than a local constant, and are clamped to
   `Limits::ceiling()` — a repository's own config may lower a limit but cannot
   raise it past the hard ceiling, which is what stops a hostile `.swp/config.toml`
   from arguing the safety away.
7. **Do not invent thresholds; document observed results.** Every number in
   this repository's prose is printed by a test. If you change a rule that moves a
   number, the suite that measures it has to be re-run and the documentation
   re-quoted in the same change.
8. **Do not fake support, and do not use fake output in documentation.** A
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
each one measures a different property of the product, and a measurement you
cannot run by name is a measurement nobody re-runs:

| suite | file | measures |
| --- | --- | --- |
| `secret_leak` | `tests/leak/secret_scan.rs` | the seven sweeps named above |
| `detection_matrix` | `tests/detection/matrix.rs` | the partial-copy ladder, the thirteen refactoring forms, the four removals, an excluded directory, the padded copy |
| `family_roundtrip` | `tests/detection/roundtrip.rs` | every literal form renders, re-parses and decodes back to its value |
| `false_positive` | `tests/false_positive/corpora.rs` | 30 scans of six corpora, six generated siblings, shared constants |
| `collision` | `tests/collision/identities.rs` | disjoint constellations, the id space, 800-symbol draw |
| `property_chains` | `tests/property/chains.rs` | random attack and refactoring chains, and the verdict contract |
| `resource_limits` | `tests/resource/hostile.rs` | depth, size, file count, archive bomb, malformed input |
| `performance` | `tests/performance/scale.rs` | the size ladder, per-file cost, repeated protection |
| `adversarial_removal` | `tests/adversarial/attacks.rs` | shape search and fold, revert, restructure, compound, two-project planting |
| `acceptance_scenario` | `tests/acceptance/final_scenario.rs` | the end-to-end two-project scenario |
| `docs_examples` | `tests/docs/examples.rs` | every documented transcript |
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

The measurement behind the verdict gate is not a suite but an example:

```text
cargo run --release -p swp-test-suite --example verdict-model -- \
  --iters 30 --matrix 6 --tag-bits 4
```

It drives the built binary over look-alike projects, copies at several fractions,
refactorings and site-removal attacks, and prints the production `tally` for every
scan, which is what the two tables in [VALIDATION.md](VALIDATION.md) are made of.
It is minutes per tag width, so CI does not run it; the rule is that a number it
produced is quoted together with the command that produces it.

## The documentation is a test

A documented command has to be one that was run, and a stale example has to fail
the build. That is what `tests/docs/examples.rs` does, and the convention the
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
from thinning out when a page is edited: at least forty blocks and at least forty
distinct commands must be covered.

`PAGES` is the index the suite reads, and it is a page's claim to be checked, not
a directory listing. A page that quotes no output — the Beta 3 design set
(`docs/BETA3_ARCHITECTURE_AUDIT.md`, `docs/SDK_ARCHITECTURE.md`, `docs/SDK_API.md`,
`docs/VERSIONING_POLICY.md`) describes an interface this build does not have yet,
and prints nothing — is deliberately outside it, because adding it would assert a
coverage the page does not ask for. The cost is real and is the one to weigh when
one of those pages grows: prose commands named there are not parsed, so the suite
will not catch a flag that does not exist. Add a transcript to a page and the page
goes into `PAGES` in the same commit.

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
5. Quote the new output in [CLI.md](CLI.md) with a real transcript, and if it adds
   a report field, in [Reading a report](USER-GUIDE.md#reading-a-report).

## Adding a language adapter

An adapter lives in `crates/swp-adapters` and nowhere else. It is the only crate
that links a parser and the only place a language has a name; everything above it
consumes three types — `Analysis`, `swp_core::canon::Token`,
`swp_core::site::FormFamily` — none of which inspects a spelling.

The files that make up the layer:

| file | owns |
| --- | --- |
| `adapter.rs` | the `LanguageAdapter` trait, `Edit`, `Proof`, the `Registry` |
| `analyze.rs` | `Analysis`, `CandidateSite`, `Capabilities` |
| `ts.rs` | the `Grammar` table and the AST pass every parsed language shares |
| `js.rs`, `py.rs` | per-language grammar tables and identifier-binding rules |
| `dialect.rs` | per-language facts about numbers and strings |
| `literal.rs`, `forms.rs` | literal parsing, the seven fragment families, render and decode dispatch |
| `safety.rs` | which positions a rewrite may not touch |
| `generic.rs` | the lexical fallback, described below |

### The contract

`trait LanguageAdapter: Send + Sync` has ten methods. Five are yours to write —
`name`, `capabilities`, `extensions`, `analyze`, `dialect` — and `identifies` has a
default (extension match) you override only for a name-based rule like a shebang.
The four defaults are not convenience, they are the reason an adapter cannot
drift: `canonicalize` delegates to `swp_core::canon::canonicalize` so that location
ids stay comparable across languages, and `render`/`extract`/`validate` run the
shared family engine and the shared re-parse proof. Override `render` or `extract`
only to *narrow* what the shared engine offers; a rendering your `extract` cannot
decode back is a watermark that exists in a manifest and nowhere in the world.

Two rules about the data you produce:

* `name()` is recorded in every site of every release. Renaming it after a release
  exists means that release cannot re-parse its own manifests.
* `Capabilities` (`analyze.rs`) is a promise, and the report degrades to it. Say
  `scopes: false` if you cannot tell a local name from a free one; say
  `reparse: false` if you cannot re-parse your own output, in which case `validate`
  is no longer a proof. Claiming more than you deliver makes a report print a
  level the evidence does not reach.

`analyze` must return the innermost statement and the enclosing scope for a byte
offset, because those two spans, abstracted four ways, are a site's four
addresses; and it must report which literals it can normalize by value, since the
canonicalizer falls back to the raw spelling where you cannot and records the loss.

### The four steps

1. A `Grammar` table in `crates/swp-adapters/src/<lang>.rs`, plus the two
   functions nobody can write for you: `role_of` and `scan_bindings`. JavaScript's
   and Python's tables are ~15 lines inside 200–340-line modules; the module *is*
   the language's binding rules, and that is the work.
2. A `Dialect` constant: the literal facts, each verifiable from the language's
   specification rather than from what the tool would find convenient.
3. One registry line: `Box::new(AstAdapter::new("<lang>", || &<LANG>))` in
   `Registry::standard()` in `adapter.rs`. It is the only registration point.
4. Tests, in this order: the token-stream guard in
   `crates/swp-adapters/tests/token_stream.rs`, the per-language round-trip in
   `crates/swp-test-suite/tests/detection/roundtrip.rs` (one fixture per form the
   adapter claims), and a `parsed_languages()` assertion. Expect the canon and
   round-trip tests to find real bugs in step 1; that is what they are for.

A language whose literals cannot be classified without resolving types — a macro
system, an evaluation-time metaprogram, an implicit conversion that changes what
`+` means — does not need a bigger adapter. It needs the refusal below, or an
`analyze` that records exactly which literals it could classify and refuses the
rest with a reason a reader can act on.

### What the promise costs

"Without modifying the core protocol" is true of the protocol and the engine: no
schema changes, no derivation changes, nothing upstream learns your language's
name. Beyond the adapter and the registry line you also touch the places that
*record* what this build supports, each of which fails loudly when a language
lands and stays quiet otherwise — which is why they are lists rather than logic
derived from the registry:

| place | what it asserts |
| --- | --- |
| `crates/swp-adapters/tests/token_stream.rs` | that `parsed_languages()` is exactly the set claimed |
| `crates/swp-test-suite/tests/detection/roundtrip.rs` | one fixture and one `Dialect` row per language |
| `crates/swp-test-suite/src/project.rs` | language name → fixture builder |
| `crates/swp-test-suite/tests/docs/examples.rs` | the example trees the documented transcripts are re-produced against |
| the `NO_SAFE_LOCATIONS` message in `swp-core/src/error.rs` | the languages this build parses, named next to "add an adapter" |
| `README.md`, `docs/GETTING-STARTED.md` | the prose a user reads to decide whether their language works today |

A new language also needs an example tree under `examples/` and its row in
[VALIDATION.md](VALIDATION.md), in the same change as the adapter.

### Why "unsupported" is a refusal, not a weaker scan

`generic.rs` is a hand-written lexical scanner whose `Capabilities::LEXICAL` says
`scopes: false`, `reparse: false`, evidence capped at `MODERATE`. Its
`extensions()` is empty, so `Registry::for_path` never selects it silently — a
file becomes source only when a real grammar covers it. Both walks admit a path
only when `for_path` returns an adapter (`swp-embedding/src/walk.rs`) and name the
omission otherwise, because on a language this build cannot re-parse, `validate`
cannot prove the surrounding code unchanged. So an unsupported project is refused
outright rather than covered with weaker tools, and a report never needs a
footnote about which half of a tree was guessed at.

## Adding an evidence kind or moving the ladder

`swp-evidence/src/item.rs` declares the kinds and each one's `basis` text, plus
`asserts_provenance()` — the flag that says whether an item may contribute to a
verdict. `STRUCTURAL_MATCH` is graded never, on purpose: an address without its
code is a lead, and any tree that canonicalizes alike can produce one.
`swp-evidence/src/level.rs` holds the ladder constants, each with the sentence
that justifies it beside it. Changing one changes what a report calls `STRONG`,
which changes what a *saved* report of a previous build means, so a ladder change
is a schema discussion, not a commit.

The coincidence arithmetic is three functions in `level.rs`.
`chance_of_coincidence` sums, over each site's count of *distinct keyed codes*,
the chance that one such draw lands on the site's tag — an upper bound on
accidental confirmations by linearity, needing no independence assumption.
`union_bound_of_coincidence` is its looser sibling, counting every span as if it
carried its own code, and it is printed beside the bound as the
assumption-free figure. `tail_of_coincidence` turns the pair into the number the
verdict is gated on: the Poisson upper tail of seeing this many confirmations or
more when the expectation is the bound, recorded as `coincidence_probability`.
All of them appear in every report. None of them is a probability that anybody
copied anything — that distinction is one of the `limitations` lines a report
prints about itself, so a reader meets it in the document rather than in a
footnote elsewhere.

## Changing a derivation

Do not. Every derivation is pinned: `pinned_derivation_vectors`,
`truncation_respects_width` and `wrong_domain_is_refused` in
`crates/swp-crypto/src/derive.rs`, and `pinned_site_identity_vector` in
`crates/swp-manifest/src/keys.rs`. A change is silent — nothing errors — but every
release already published stops matching its own manifest. If a derivation must
change, the protocol version, the `canonicalizer_version`, or the relevant domain
label changes with it, and old stores keep being read the old way.

## Style, in three sentences

Module docs state the constraint they implement, because the shortest route to a
wrong implementation is a forgotten requirement. Comments explain a constraint or
a cost, never a mechanism the code already states. Error messages name a path,
say what happened, and print a `next:` line — and no message ever quotes key
material, which the leak suite enforces rather than trusts.

Before a change is finished: `cargo clippy --workspace --all-targets` clean,
`cargo fmt --all` applied, the suites that touch it re-run, and the pages that
quote it re-run by `docs_examples` rather than edited until they pass.

---

Next: [SWP-1-SPEC.md](SWP-1-SPEC.md) for the protocol,
[SECURITY.md](SECURITY.md) for the attack surface,
[VALIDATION.md](VALIDATION.md) for the measurements this page points at.
