# Measured behaviour

Every number SWP-1 quotes in its documentation is printed by a test suite in this
repository. This page lists the claims, the measurement behind each, and the command
that produces it, so a claim can be checked rather than taken on trust.

Measured on 21–22 September 2026: Windows 11 x64 (build 26200), an 8-logical-processor
Intel laptop, `rustc 1.91.1`. The suites run as debug builds, which is correct for
counting confirmations and wrong for timing; the performance row says which it is.

| Claim | Measured | Reproduce |
| --- | --- | --- |
| A protected tree that is copied intact is detected at the top evidence tier | 15 of 15 fragments confirmed, tree fingerprint `match`, `VERY_STRONG` | `cargo test -p swp-test-suite --test acceptance_scenario -- --nocapture` |
| Detection survives ordinary refactoring: renames, reflow, moved code | The same 15 fragments confirmed after every refactoring in the suite; the fingerprint is the field that fails, not the watermark | same run, `A-refactored` row |
| Partial copies are detected, and not over-claimed | Half the files copied: 10 of 15 fragments confirmed, `STRONG`, and the report says the candidate was only partly examined | same run, `A-partial` row |
| Removing watermark sites degrades the grade rather than the tool | Every second site rewritten: 11 of 15 fragments survive, 4 reported stripped | same run, `A-damaged` row |
| Deleting the watermark is possible | An attacker who locates the sites from the public manifest removes all of them: 0 of 24 confirmed | `cargo test -p swp-test-suite --test adversarial_removal` |
| Unrelated code is not reported as a copy | 0 false findings across 30 unrelated trees | `cargo test -p swp-test-suite --test false_positive` |
| Unrelated code is not silent either | 20 of 30 foreign scans produced at least one *lead* — a single unconfirmed site, graded below the finding threshold | same run |
| One project's keys do not identify another's | Every cross-scan in the acceptance scenario confirms 0 fragments | `--test acceptance_scenario` |
| Hostile input cannot exhaust the scanner | Oversized file, 4,000 nested blocks, 24-deep tree, 400 files over the ceiling, zip bomb: each refused at its ceiling and reported `INCONCLUSIVE` or an error, never a crash | `cargo test -p swp-test-suite --test resource_limits` |
| The root secret never leaves the store | Every artifact of every run — logs, reports, manifests, CLI output, temporary files — swept for the secret | `cargo test -p swp-test-suite --test secret_leak` |
| Cost at ordinary size | 241 files (0.35 MiB, 32 sites): protect 7.2 s, verify 7.2 s, scan 5.0 s, 5.0 MiB peak heap during protect | `cargo test -p swp-test-suite --test performance` |

## What these numbers do not show

* The timings above are a **debug build**, because that is what `cargo test` runs.
  The portable part is the shape — per-file cost falls as the tree grows, and heap
  stays near 14 MiB per MiB of source — not the seconds. A release build is faster by
  a multiplier this page does not quote, because a number nobody can reproduce is not
  a measurement.
* Nothing here measures anonymity, ownership, or authorship. `PROVENANCE_DETECTED` is a
  statement about code derived from a project's secret, and [SECURITY.md](SECURITY.md)
  is where that boundary is drawn.
* The `probes` column in the acceptance output varies between runs of the same tree,
  because site placement is derived from the project's secret. Fragment counts and
  verdicts do not vary.
* Every suite above runs against the built binary as a user would, so "passes" means
  the whole path works: parsing, selection, embedding, detection, grading, reporting.

## Related

* [SECURITY.md](SECURITY.md) — what the tool defends against, and against whom.
* [SWP-1-SPEC.md](SWP-1-SPEC.md) — the protocol the measurements test.
* [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — when your own numbers differ from these.
