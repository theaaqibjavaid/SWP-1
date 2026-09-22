# Changelog

All notable changes to SWP-1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one
addition the product needs and semver alone does not supply: the protocol
carries its own version (`SWP-1`), the report carries its own schema tag
(`SWP-1-report-v1`), and a change to either is a change to a *document format*
rather than to a function. See
[the spec's versioning section](docs/SWP-1-SPEC.md#14-versioning) for what each of
the three numbers is allowed to do to the other two.

This project does not have a changelog entry for something it has not shipped. A
line under a released heading is a claim that the released build does it, and
every claim of that kind here was run before it was written
([docs/VALIDATION.md](docs/VALIDATION.md)).

## [Unreleased]

Nothing. An entry appears here between a change being merged and the tag that
carries it, and not before.

## [1.0.0] - 2026-09-22

The first release that is end to end: a tree can be protected, a protected tree
can be re-examined, and a tree somebody else hands you can be judged — from an
offline machine that never runs the code it is reading.

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
stated rule, not a heuristic: `NONE`, `WEAK`, `POSSIBLE`, `PROBABLE`, `STRONG`,
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
  re-prove it either. [LANGUAGE-ADAPTERS.md](docs/LANGUAGE-ADAPTERS.md) says how
  to write the fourth adapter.
- **No daemon, no service, no upload.** No network code path exists in the
  binary. There is no telemetry to opt out of.
- **No claim of removal-resistance.** `swp inspect fragments` can enumerate every
  site. The threat model says so in as many words
  ([THREAT-MODEL.md](docs/THREAT-MODEL.md)), and the adversarial suite exists to
  keep that sentence true.
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
  structure channels and nothing else; the report shows that as `WEAK` or
  `POSSIBLE`, and `POSSIBLE` is defined to mean "this could be chance."
- **Reimplementation is out of scope.** A rewrite from memory that removes every
  protected literal leaves nothing to key on, and produces the same report as an
  original. `NO_PROVENANCE_DETECTED` is not a finding of originality.

[Unreleased]: https://github.com/theaaqibjavaid/SWP-1/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/theaaqibjavaid/SWP-1/releases/tag/v1.0.0
