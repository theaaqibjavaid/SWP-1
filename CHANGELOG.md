# Changelog

All notable changes to SWP-1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one
addition the product needs and semver alone does not supply: the protocol
carries its own version (`SWP-1`), the report carries its own schema tag
(`SWP-1-report-v2`), and a change to either is a change to a *document format*
rather than to a function. See
[the spec's versioning section](docs/SWP-1-SPEC.md#14-versioning) for what each of
the three numbers is allowed to do to the other two.

This project does not have a changelog entry for something it has not shipped. A
line under a released heading is a claim that the released build does it, and
every claim of that kind here was run before it was written
([docs/VALIDATION.md](docs/VALIDATION.md)).

## [Unreleased]

An entry appears here between a change being merged and the tag that carries it,
and not before.

## [1.0.0-beta.5] - 2026-10-03

The release that added three commands and two foreign bindings without moving the
protocol. What a user runs went from seven commands to ten and from seventeen
options to eighteen; `swp-crypto` and `swp-core` have no diff against
`v1.0.0-beta.4` and the workspace's third-party list gained no crate, so the key
derivation, every stored artifact's schema and the verdict arithmetic are still
`1.0.0-beta.4`'s. That is a measurement rather than a reassurance, and the commands
that reproduce it are at the end of this entry — as is the pair of builds that was
run against it. The artefacts of this release are the four `swp` binaries: both
bindings are in the tree as source, gated on the same three systems the CLI is, and
no wheel, sdist or npm package of either has gone to any index.

### Added

**`swp pre-commit` — `swp verify`'s measurement in the shape a git hook needs.** It
grades the working tree against one of the project's own releases, the newest unless
`--release` names another, writes nothing, runs no git command, and hands the
document's exit code back to git: `0` allows the commit, `5` blocks one whose tree no
longer carries the release it is checked against, `10` blocks one it could not read
enough of to say anything. It is `verify` and not `scan` because scanning a protected
project for its own marks always finds them, so a hook that scanned could only ever
block a healthy tree. It prints `verify`'s page through `verify::text_lines` rather
than a second rendering of the same `SWP-1-verify-v1` document — two renderers are two
places for the site wording to disagree.

**`swp scan --compliance` — a coverage grade beside the verdict, capped by what the
report already measured.** `FULL`, `PARTIAL` or `NONE` over the keyed sites of the
release the report leads with, computed only from fields that report carries: a
candidate that was partly read cannot tell an absent site from an unexamined one, and a
count the report will not carry as a finding — one inside the coincidence bound —
cannot be rounded up to `FULL` here. Each of those two caps prints a `·` line naming
the measurement that held the grade back, and the grade changes no exit code. Its
document is `SWP-1-compliance-v1`, printed and never stored: `--save` beside this
flag is a
usage error (`2`), because `swp report` reads `SWP-1-report-v2` and would refuse the
grade file it had just been handed. `verify` and `pre-commit` reject the option
outright — neither has a candidate to grade.

**`swp registry publish` and `swp registry search <file>` — a signed index of the
project's own release records**, at `.swp/public/registry.json` under schema
`SWP-1-registry-v1`. `publish` needs the root secret for one signature over a document
whose every other field the store already publishes under `public/releases/`; `search`
needs no key at all. Reading an index is where its security lives: a document is
validated for schema and protocol, checked that every record inside it names the
project the index itself names, and then authenticated — the index's signature and
each release record's signature inside it, against the verify key the document
carries. On top of that, when the working directory or `--project` holds a protected
project, the verify key the index carries has to be *this* project's. With no local
project it still verifies the signatures and says on stderr that it had nothing to
compare the author claim against. Nothing reads an index for you and `swp scan` never
consults one: SPEC §16 keeps one project vouching for another out of the protocol, so
this is a publisher's list of its own releases and not a trust channel. An earlier
shape of the same command carried a `revoked` flag that no code could set; it is not
in this one.

**`swp badge` and `swp badge show` — the public half of a project on one page**,
at `.swp/public/badge.json` under schema `SWP-1-badge-v1`: `identity.json` embedded
verbatim, the release count, the newest release id, and a signature over those. No
key-derived value appears in it, which is now something the leak sweep proves rather
than something a sentence claimed — an earlier build of this verb published an
`anchor_key` derived from the root secret into that public file, and the field is gone
([docs/SECURITY.md](docs/SECURITY.md)). `badge show` is what makes the file worth
having: it checks the signature and then compares the identity the badge names with
this store's own, because a badge copied whole from another project signs perfectly.

**Two foreign bindings, built and gated, published by nobody.**
`bindings/python/` (PyO3, `abi3` with a 3.10 floor, imported as `swp`) and
`bindings/node/` (napi-rs over Node-API 4, CommonJS and ESM, generated declarations
beside a hand-written entry point) each wrap the `binding_facing` surface ADR-0001
froze, over one error class carrying the envelope
[docs/SDK_API.md](docs/SDK_API.md) §8 defines, and neither adds a rule the Rust
does not have. Both are their own Cargo workspaces outside the repository's, so a
binding toolchain requirement cannot raise the published crates' `rust-version`; both
have a CI job over the three systems the CLI's matrix uses. The Node suite executes
every example its README prints, which is the binding equivalent of `docs_examples`;
Python has no such check yet, and the Python step of §9 of
[docs/SDK_ARCHITECTURE.md](docs/SDK_ARCHITECTURE.md) records that its page is the one
item there no gate re-executes. Each builds under the working name `jrs-swp` at
`0.1.0`; the name it would be published under is an open release decision
([#32](https://github.com/theaaqibjavaid/SWP-1/issues/32)), and no wheel, sdist or npm
package has gone to any index.

**Two proposals about what the next increment has to prove.**
[ADR-0003](docs/adr/0003-precommit-hook-proved-as-a-hook.md) records that
`pre-commit` has been tested as a command and never as a hook;
[ADR-0004](docs/adr/0004-what-a-badge-proves-to-a-stranger.md) states what a badge can
say to a reader who has no store of their own. Both are `proposed`, and neither changed
behaviour here.

### Changed

**A protection run refuses an unusable `--revision` before it writes anything**, which
is what [ADR-0002](docs/adr/0002-release-failure-semantics.md) settles: a run this
build rejects is not allowed to leave behind the manifest-and-plan-with-no-release that
an interrupted run leaves, because the store cannot afterwards tell an operator's typo
from a crash. The set of accepted labels did not move — `SourceRevision::validate` at
`v1.0.0-beta.4` already refused an empty string, one longer than 200 bytes, and one
carrying a control character — so what changed is when the answer arrives and what it
says: three refusals that each name their own reason, the bound written once as
`REVISION_MAX_BYTES`, and a `next:` that talks about a display label instead of about a
corrupt stored file.

**The command line no longer answers "does this verb need the secret".**
`Command::needs_secret` was public, called by nothing, and wrong in both directions at
once — it said yes for `registry` and `badge` whole, where `registry search` and
`badge show` answer with the key file deleted, and it said no for the publishers that
do need it. It is deleted, and the rule lives where it is used (`Ctx::signing_key`
calls `Store::load_root`) and in four tests that remove `.swp/private/root.key` and
assert `inspect`, `report`, `registry search` and `badge show` still read the store.
Seven commands take the signing path; those four keep the property that lets a
colleague audit a store they were never given, now measured rather than declared.

**The leak sweep went from two needles in nine renderings to three in eleven.**
`NeedleSet` had no base32 form at all, and an id in this project is unpadded lowercase
base32, so a keyed value that reached an artifact *as an id* was invisible to the §29
sweep in every domain, not just the one that broke. The third needle is the reserved
`Domain::Evidence` output the badge used to carry, which turns SPEC's promise that
those labels are "reserved and nothing in the product derives under them" into a
tested one; the suite is eight sweeps where it was seven.

**The store can say what a publisher wrote.** `Store::registry_path` and
`Store::badge_path` own the two paths, so a relocated project and a hand-joined
`public/` cannot disagree about where an index lives; both documents are written
through the store's atomic public-write path, so a run that dies halfway leaves the
previous index readable rather than a truncated file the next reader calls damaged.
`Store::inventory` lists each when it exists — that is what `swp inspect store` prints,
and [docs/SECURITY.md](docs/SECURITY.md) reproduces that command's table with its
"may commit" column, and explains why a store that has never published shows neither
file. They are deliberately *not* in `PUBLIC_ARTIFACTS`, the list `swp init` prints for
a store that has just been created, because neither file exists then. SPEC's document
table went from five documents to eight.

**The release gate can see a build artefact it could not see before.** The artefact
sweep in `scripts/check-release.sh` now rejects a tracked `.node` addon, a tracked wheel
and a tracked Python extension module; the pattern it carried at `v1.0.0-beta.4` covered
object files, shared libraries and `.wasm`, and stopped there — no binding format was in
it, which is the same blind spot that lets a built binding into a public tree one file
format at a time. And `publish.yml`'s crate list now matches the ten publishable
workspace members, including `swp-sdk`, which the workflow's own comment named and its
list omitted.

### Fixed

**A relative scan candidate is resolved once.** `swp scan src` — the spelling the
Python binding passes through unchanged, and one the CLI never produces because
`ctx::resolve` absolutizes before a run starts — failed the scan it had been asked to
perform: the walk stored `ScannedFile.abs` relative to a root that was itself relative,
and both read sites joined that root back on, so `src` became `src/src/app.js` and a
file the walk had listed one line earlier could not be opened
([#23](https://github.com/theaaqibjavaid/SWP-1/issues/23)). The walk absolutizes before
it normalizes now, which also makes a leading `..` resolve against the working
directory instead of vanishing from the front of an empty path, and the root parameters
that existed only to feed those re-joins are gone with them. `protect` and `verify` are
untouched — their roots were already absolute — so no release made before the fix reads
differently after it. A scan of a *sub-directory* of a project is still `INCONCLUSIVE`,
which is the design rather than the bug: a fragment of a tree holds too little of the
constellation to say anything about the whole.

### Compatibility, checked rather than assumed

The claim at the top of this entry is a diff, and these are the commands that re-run
it against the tag:

```sh
git diff --stat v1.0.0-beta.4..HEAD -- crates/swp-crypto crates/swp-core
git diff v1.0.0-beta.4..HEAD -- Cargo.toml Cargo.lock | grep -E '^[+-][^+-]' | grep -v '1\.0\.0-beta\.'
```

The first prints nothing: the crates that derive every key, canonicalize every
document and sign every record are what `v1.0.0-beta.4` shipped. The second prints one
line, `+ "swp-crypto",` — `Cargo.lock` recording that `swp-cli` now names that crate,
for the two publishers. Of the forty-five lines the two manifests change by, the other
forty-four are the `1.0.0-beta.4 → 1.0.0-beta.5` version token, and no third-party
crate appears on either side of the diff, so the shipped binary's transitive count is
still the 80 that [docs/SECURITY.md](docs/SECURITY.md) states. The two binding
workspaces carry their own lockfiles and are outside those paths; each moved by
eighteen lines, every one of them the same token.

What a diff cannot say is whether a build from before this work reads a record made
after it, so that was run on 2026-10-03 with two binaries: one built from the tag,
which prints `swp 1.0.0-beta.4`, and this release's build, which prints
`swp 1.0.0-beta.5`. The string is not only a banner — it is a stored field,
`generator.swp_version` — so the records the two builds write genuinely differ, and
each reading below is a cross-version read rather than a tautology.

- A five-site project protected by the tag's build verifies under this one: `manifest
  authenticated`, verdict `INTACT`, exit `0`. It answers identically under the tag's own
  build, which is the baseline that makes the first line a measurement.
- A project protected by this build, with a `--revision` label recorded, verifies under
  the tag's build: same verdict, exit `0`.
- The new commands run against the tag's store — `registry publish`, `badge`,
  `pre-commit`, then `registry search` and `badge show` reading back what they wrote —
  and each exits `0`. The index and the badge carry the tag's release record verbatim,
  its `swp_version: 1.0.0-beta.4` and all, while their own generator field names this
  build; `swp inspect store` lists both new files.
- What the tag's build makes of those two files: `swp inspect store` exits `0` and
  counts six artifacts where this build counts eight in the same directory. It has no
  classifier for a document it has no writer for, and no writer either — `registry`,
  `badge` and `pre-commit` are each `error [USAGE]` and exit `2` there, as is
  `scan --compliance`. Nothing in either new format crosses the boundary, because
  nothing on the old side can reach it.
- The check that can say no: with one character of that release record's signature
  flipped, both builds answer `INVALID_MANIFEST` and exit `5`; put the byte back and
  both return to `INTACT` and `0`.
- A report saved by the tag's build reads under this one, and one saved by this build
  reads under the tag's — `swp report`, exit `0` both ways, each re-rendered with its
  own `graded by` line. A saved report keeps the grade and the tool identity it was
  given; neither build recomputes the other's.
- A copy of the tree this build protected, scanned by the tag's build, found all five
  sites: `PROVENANCE_DETECTED` at `MODERATE`, exit `1`.

[docs/VALIDATION.md](docs/VALIDATION.md) remains the record of what the protocol itself
measures; nothing in the list above required a foreign binding, because the CLI and the
bindings call one implementation.

## [1.0.0-beta.4] - 2026-09-30

The release that answered the limitation `1.0.0-beta.3` recorded, and then took the
dependency updates that had been waiting behind it. What a user runs is still the
same seven commands with the same options, the same exit codes and the same report:
the protocol, every stored artifact's schema, the key derivation and the verdict
arithmetic are `1.0.0-beta.3`'s. No foreign binding ships in this release.

### Added

**`Session::protect_summary`, the account of a protect run without its plan.**
`ProtectSummary` — twenty fields — with its three row types `ProtectedFile`,
`ProtectedSite` and `RefusedSite` carries the release id, the counts, which files
were touched, which sites went in, and which locations were refused; it carries no
keyed site identity. One private projection (`swp-sdk/src/protect.rs:267`) builds it
out of the `ProtectOutcome` that `protect` already returns, so the library keeps one
bookkeeping path rather than two that can disagree. `protect` and `ProtectOutcome`
are still classified `pending` and that is unchanged; what moved is that a future
Python or Node binding has a documented door to be written against.
[`docs/BINDING_SURFACE.json`](docs/BINDING_SURFACE.json) counts 78 binding-facing
items where `1.0.0-beta.3` counted 73, and `binding_surface` still fails the build
when the crate and that file disagree in either direction.
[ADR-0001](docs/adr/0001-protect-generate-binding-boundary.md) is accepted and
implemented.

### Changed

**`sha2` 0.10.9 → 0.11.0, with `hmac` 0.12.1 → 0.13.0.** The hash bump on its own
does not compile: `hmac` 0.12 sits on `digest` 0.10, so `Hmac<Sha256>` has no
`KeyInit` inside the 0.11 universe the two crates must share. Construction now goes
through `KeyInit::new_from_slice` at the two HMAC call sites,
`swp-crypto/src/derive.rs:92` and `swp-crypto/src/secret.rs:98`.

**`ed25519-dalek` 2.2.0 → 3.0.0**, which brings `ed25519` 3.0.0, `signature` 3.0.0,
`curve25519-dalek` 5.0.0 and `rand_core` 0.10.1, and drops the PKCS#8 stack (`der`,
`pkcs8`, `spki`, `base64ct`) that the crate used to carry. No call site moved: this
project signs with `SigningKey::sign` and checks with `VerifyingKey::verify` over the
canonical JSON of a document, and the bump needed only a manifest and a lockfile.

**`thiserror` 2.0.20 → 2.0.21, and `tree-sitter-python` 0.23.6 → 0.25.0.** A grammar
version is not a dialect: the Python adapter matches on node-kind strings, so
`family_roundtrip` and `detection_matrix` re-run the corpora against the new grammar
rather than assuming 0.25 parses the way 0.23 did.

**One digest universe, and the count that goes with it.** `cargo tree --locked` on
this tree resolves exactly one `sha2` (0.11.0) and one `digest` (0.11.3); the only
name still present in two versions is `syn` (2.0.119 and 3.0.6), which is proc-macro
machinery and links nothing at runtime. The shipped binary now pulls 80 third-party
crates transitively where it pulled 77 — `const-oid`, `ctutils`, `cmov` and
`hybrid-array` arrive with the new `digest`, `generic-array` leaves — and
[docs/SECURITY.md](docs/SECURITY.md) states 80 for the same reason this page does:
the number is a measurement, and it moved.

### Compatibility, checked rather than assumed

Every derivation is pinned in the test suite — `pinned_derivation_vectors`,
`pinned_project_id_vector`, `pinned_site_identity_vector` — so a dependency that
computed a different SHA-256, a different HMAC, or a different site identity would
fail the build instead of quietly re-keying a project.

What the pins do not cover is a stored ed25519 *signature*: no test carries one
across a dependency version, so it was checked by hand on 2026-09-30 with two builds
of this tree. A project protected by the pre-`ed25519-dalek`-3 build verifies under
this one (`manifest authenticated`, verdict `INTACT`, exit 0), a project protected by
this build verifies under that one, and a release record with one character of its
signature flipped is refused by both with `INVALID_MANIFEST` and exit 5 — which is
what makes the two passing runs a measurement rather than a check that always says
yes. A tree protected by `1.0.0-beta.3` therefore stays verifiable by this build, and
its public release records stay readable. Saved reports are unaffected in either
direction: `SWP-1-report-v2` and the arithmetic behind the grade did not move here.

## [1.0.0-beta.3] - 2026-09-29

The release that moved the implementation rather than the product. What a user runs is
still the same seven commands with the same options, the same exit codes and the same
report; what changed is that the orchestration those commands perform now lives in a
library crate the command line calls, and that the boundary a future Python or Node
binding would be written against is fixed and checked. The protocol, every stored
artifact's schema, the key derivation and the verdict arithmetic are `1.0.0-beta.2`'s,
and no binding ships in this release.

### Added

**`swp-sdk`, the Rust façade.** `Session` — `open`, `discover`, `init`, `protect`,
`verify`, `scan`, saved-report access, and the identity, configuration, limits and
release reads — plus `capabilities()`, the machine-readable answer to what this build
can do. `swp-cli` keeps argument parsing, rendering and the exit code. This is one
implementation with two doors, not a second one: `sdk_parity` drives the CLI and the
library over a single project state and compares their answers as data.

**The verify document in `swp-evidence`.** `SWP-1-verify-v1` moved out of the
command-line crate so a library caller can hold it, with the field set, ordering and
serialized names it had before the move — which is what the schema guard and the
documented transcripts re-check.

**The foreign-binding boundary, as data and as a gate.**
[`docs/BINDING_SURFACE.json`](docs/BINDING_SURFACE.json) classifies every public item
of `swp-sdk`: what a binding may wrap, what is public in Rust on purpose and stays
there, what would hand a caller keyed or private material, what is meant to cross and
cannot yet, and what must not become public at all. `binding_surface` reads the crate
against that file and fails when the two disagree in either direction, so growing the
façade is a decision a caller has to make twice.

### Changed

**Ten publishable crates, not nine.** `swp-sdk` is in `check-release.sh`'s
`PUBLISHABLE` order, between `swp-evidence` and `swp-cli`.

### Known limitation, recorded rather than repaired

`Session::protect()` is public Rust API, and its result reaches the keyed site
identities of a private plan document — `PlannedSite.locations`, four 128-bit HMAC
outputs per site. A keyed identifier is not a key and not an expected tag, and it is
already inside the plan file the store's access list protects, but it is not something a
foreign binding should be free to print: `protect` and `ProtectOutcome` are classified
`pending`, `Session::open_store()` and `Store` are `rust_only` for `swp inspect`, and no
binding may wrap either until that is answered. Both are written up in
[docs/SDK_ARCHITECTURE.md](docs/SDK_ARCHITECTURE.md) §6 and
[docs/SDK_API.md](docs/SDK_API.md) §11.

## [1.0.0-beta.2] - 2026-09-25

The release that changed how a verdict is reached rather than what the tool can
do. The protocol, the schemas and the commands are the ones `1.0.0-beta.1`
shipped; what moved is the arithmetic that turns a tally into a finding, and the
harness that prints the measurements quoted below is added here so that a reader
can reproduce them rather than take them from this page.

### Changed

**The verdict is decided by a probability, not by a margin.** A tally used to
clear when its confirmations exceeded the coincidence bound by `1.5`, `3.0` or
`6.0`. That rule was measured accusing unrelated code — 13 times across the 5,790
foreign cross-scans of the collision and look-alike suites, which was enough to
leave the §28 collision test red in 5 runs of 100. A finding now has to be
improbable rather than merely above an expectation: the probability that chance
alone produced the count has to clear `1e-3`, and a grade above `WEAK`, `STRONG`
and `VERY_STRONG` needs `1e-3`, `1e-5` and `1e-8` respectively. What it costs is
stated beside what it buys: of the 2,100 findings the old rule reached on the
measured corpus, 1,903 survive the gate (90.6%; 80% at a 4-bit tag, 95% at 6, 97%
at 8), and no scan in those 5,310 was called a finding by the new rule and not by
the old. The residual rate is bounded, not zero — see
[docs/VALIDATION.md](docs/VALIDATION.md).

**The coincidence bound is built from distinct keyed codes, not from spans.**
Three spans that reproduce one address while carrying one repeated literal are one
chance at this project's tag, not three, so the sum no longer needs those draws to
be independent to be admissible. This moves the bound by 1.8% at a 4-bit tag, 0.5%
at 6 and 0.1% at 8; the `2^−w` arithmetic itself is unchanged, and neither number
is why the verdicts moved.

**Reports are `SWP-1-report-v2`.** The document gained the two fields the gate
reads — `draws`, and `coincidence_probability`, the figure the verdict cleared —
and a `SWP-1-report-v1` file is now refused with `PROTOCOL_VERSION_UNSUPPORTED`
rather than re-read under a rule that grades it differently. A tree protected by
`1.0.0-beta.1` still verifies with this build: the identity, manifest, release and
plan schemas are unchanged and every derivation is pinned. What does not survive
is a *saved report*, which is a record of one build's arithmetic; re-run `swp scan`
or `swp verify` to get the current one.

**`base64` moved from 0.22.1 to 0.23.1.** The whole third-party surface of this
build is a decision rather than a default, so a change inside it is stated here
even though no product behaviour turned on it: the crate encodes the sealed secret
and the manifest signature, and is on no path that reads a source tree.

### Added

**A tally prints the arithmetic behind its own grade.** Each release section of a
report now names the spans that reached a tag comparison, the distinct codes they
carried, the bound over them, the looser bound that assumes nothing about spans
sharing an address, and the probability the verdict had to beat — so a reader can
check a grade without reimplementing it.

**`swp-test-suite --example verdict-model`.** A harness that drives the built
binary over look-alike projects, copies at several fractions, refactorings and
site-removal attacks, at a chosen tag width, and prints the production tally for
every scan. It is what prints the gate's costs and its false-positive rate in
[docs/VALIDATION.md](docs/VALIDATION.md), so those numbers are reproducible rather
than transcribed.

## [1.0.0-beta.1] - 2026-09-23

The first build offered for use outside this repository: a tree can be protected, a
protected tree can be re-examined, and a tree somebody else hands you can be judged
— from an offline machine that never runs the code it is reading.

The `-beta` is doing work, so it is worth saying which part. Everything below is
complete rather than stubbed, and a tree protected by this build verifies against
the releases that follow it — the identity, manifest, release and plan schemas are
`1`, and every derivation they depend on is pinned. What a pre-release withholds
is the endorsement: `1.0.0` is this number once somebody has run it against their
own work and the findings held up.

### Added

**Commands.** Seven verbs, one help surface, and stable exit codes — the five a
normal run reaches are `0` nothing found · `1` provenance detected · `10` part of
the candidate was never examined · `2` used incorrectly · `3` the secret is not
available; all eighteen are named in
[CLI.md](docs/CLI.md#exit-codes):

- `swp init` — mints the project identity and its root secret, seals the secret
  with the operating system's own mechanism, and touches no source file.
- `swp generate` — plans a release without writing it: the candidate sites, the
  refusals and their reasons.
- `swp protect` — the one command that edits your source. Selects sites by
  constellation, embeds each one, re-parses and re-proves the file after the
  rewrite, and writes the signed manifest and public release record.
- `swp verify` — checks this tree against its own release: does every site still
  carry its code.
- `swp scan` — the other side of the protocol. Takes a candidate directory or
  archive and answers against the local store whether it carries one of the
  project's releases, and how strong the evidence is.
- `swp inspect` — eight views over the store and its artifacts, including
  `inspect fragments`, which is the honest admission that placement is
  unobtrusive rather than secret.
- `swp report` — lists saved reports, re-renders one, or exports it.

**Language adapters.** JavaScript, TypeScript and Python, each backed by a real
tree-sitter grammar, each with a dialect table of equivalent literal forms —
`1e3` and `1000`, `'a'` and `"a"`, a template literal and a concatenation — that
the embedding and the detection sides share rather than each re-deriving. Every
documented form round-trips: the re-written literal parses, canonicalizes to what
the protocol expected, and evaluates to the same value.

**Evidence.** A detection run produces typed evidence items — keyed fragment,
exact rendering, canonical-only rendering, moved site, fingerprint agreement,
structural agreement — and an evidence level from a ladder whose every rung is a
stated rule, not a heuristic: `NONE`, `WEAK`, `MODERATE`, `STRONG`,
`VERY_STRONG`. Alongside the level, a report carries the coincidence bound: how
many of these hits an unrelated tree would be expected to produce by chance, and
— printed next to it rather than hidden behind it — the looser bound that makes no
assumption about which spans may be the same span.

**Reports.** A versioned JSON document (`SWP-1-report-v1`), a text rendering of
it, and `--save`, which stores the document that produced a verdict so the
verdict can be re-read a year later without re-scanning anything.

**Artifact containers.** `swp scan` accepts a directory, a `.zip`, a `.tar.gz` or
a bare `.gz`, extracts into a private temporary directory, refuses path traversal
and symlink entries, and deletes the extraction on exit.

**The documentation is the test.** Every `console` block in this repository —
the README, the thirteen pages under `docs/`, the four example transcripts — is
re-run against the current build by `cargo test -p swp-test-suite --test
docs_examples`, which protects each example tree from scratch under a fresh root
secret and fails on the first line the product no longer prints. A value that
varies with the key is written as `…`; a value that does not is re-checked.

**Measurement.** Thirty-four test targets, 520 tests, including a suite whose
whole job is to defeat the watermark through seven removal attempts, a
false-positive suite over corpora of boilerplate, generated code and real
open-source shapes, a collision suite over identity and site keys, a
resource-exhaustion suite over hostile archives and pathological trees, and a
scenario that runs the acceptance matrix through the installed binary.

### Not included, deliberately

These are absences with reasons, not a backlog:

- **No language beyond the three adapters and one generic fallback.** A `generic`
  candidate that reaches `swp protect` is refused with `NO_SAFE_LOCATIONS` and
  nothing written, because a scan that cannot re-parse what it rewrote cannot
  re-prove it either. [Adding a language
  adapter](docs/DEVELOPER-GUIDE.md#adding-a-language-adapter) says how to write
  the fourth one.
- **No daemon, no service, no upload.** No network code path exists in the
  binary. There is no telemetry to opt out of.
- **No claim of removal-resistance.** `swp inspect fragments` can enumerate every
  site. [Attacks, and what still gets
  through](docs/SECURITY.md#attacks-and-what-still-gets-through) says so in as
  many words, and the adversarial suite exists to keep that sentence true.
- **No key management system.** The root secret is sealed by the operating
  system, and the store is a directory. That is a documented boundary, not an
  integration point.

### Known limitations at release

- **Sealing differs by platform.** On Windows the root secret is sealed with
  DPAPI under the user's credential; on Linux and macOS the store is written
  with `0600` permissions and the secret is held in a file that is not encrypted
  at rest. A DPAPI-sealed store cannot be opened on a non-Windows host, and the
  error says so. [SECURITY.md](docs/SECURITY.md) states the difference; bringing
  the three platforms to one guarantee is open work.
- **A protected tree is a tree that has been edited.** The rewrite is provably
  value-preserving and the diff is reviewable, but re-protecting after a merge
  conflict is a manual decision, not something the tool should make silently.
- **Detection has a floor.** Fragments carry four bits each, so a candidate whose
  literals were re-spelled outside the dialect table leaves the fingerprint and
  structure channels and nothing else; the report shows that as `WEAK` at best,
  and `WEAK` is defined as a lead worth looking at rather than proof of copying.
- **Reimplementation is out of scope.** A rewrite from memory that removes every
  protected literal leaves nothing to key on, and produces the same report as an
  original. `NO_PROVENANCE_DETECTED` is not a finding of originality.

[Unreleased]: https://github.com/theaaqibjavaid/SWP-1/compare/v1.0.0-beta.5...HEAD
[1.0.0-beta.5]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0-beta.1
