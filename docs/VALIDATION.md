# Measured behaviour

Every number SWP-1 quotes in its documentation is printed by a test suite in this
repository. This page lists the claims, the measurement behind each, and the command
that produces it, so a claim can be checked rather than taken on trust.

Measured on 21–22 September 2026, with the verdict-gate measurements below added on
24 September 2026: Windows 11 x64 (build 26200), an 8-logical-processor Intel laptop,
`rustc 1.91.1`. The suites run as debug builds, which is correct for counting
confirmations and wrong for timing; the performance row says which it is. The
collision and `verdict-model` runs are release builds, because 100 repetitions of a
matrix of look-alike projects is not affordable any other way — the counts they
report do not depend on the profile.

| Claim | Measured | Reproduce |
| --- | --- | --- |
| A protected tree that is copied intact is detected at the top evidence tier | 15 of 15 fragments confirmed, tree fingerprint `match`, `VERY_STRONG` | `cargo test -p swp-test-suite --test acceptance_scenario -- --nocapture` |
| Detection survives ordinary refactoring: renames, reflow, moved code | The same 15 fragments confirmed after every refactoring in the suite; the fingerprint is the field that fails, not the watermark | same run, `A-refactored` row |
| Partial copies are detected, and not over-claimed | Half the files copied: 10 of 15 fragments confirmed, `STRONG`, and the report says the candidate was only partly examined | same run, `A-partial` row |
| Removing watermark sites degrades the grade rather than the tool | Every second site rewritten: 11 of 15 fragments survive, 4 reported stripped | same run, `A-damaged` row |
| Deleting the watermark is possible | An attacker who locates the sites from the public manifest removes all of them: 0 of 24 confirmed | `cargo test -p swp-test-suite --test adversarial_removal` |
| Unrelated code is not reported as a copy | 0 false findings across 30 unrelated trees | `cargo test -p swp-test-suite --test false_positive` |
| Unrelated code is not silent either | 20 of 30 foreign scans produced at least one *lead* — a single unconfirmed site, graded below the finding threshold | same run |
| A lead stays a lead when it is measured a hundred times | 3,000 ordered foreign cross-scans over 100 independent runs of the §28 suite: 0 `PROVENANCE_DETECTED`, 1,880 `INCONCLUSIVE`, 1,120 clean; the largest accidental confirmation count seen was 5 of 12 sites, and all 600 same-keys-own-tree scans still found their release | `cargo test --release -p swp-test-suite --test collision --locked`, 100 times |
| The coincidence bound is conservative by a measured factor, not an assumed one | Across 2,790 unrelated cross-scans at 4/6/8 tag bits, `λ` exceeded the observed mean confirmation count by 2.98×, 2.74× and 3.26×; the observed counts were Poisson-shaped (variance/mean 0.95, 1.01, 1.00) | `cargo run --release -p swp-test-suite --example verdict-model -- --iters 30 --matrix 6 --tag-bits 4` |
| The probability gate costs detection, and the cost is known | 1,903 of the 2,100 findings the pre-gate rule reached survive it (90.6%), and the gate never produced a finding the old rule refused — 0 such scans in 5,310 | the same `verdict-model` run at each of 4, 6 and 8 bits |
| One project's keys do not identify another's | Every cross-scan in the acceptance scenario confirms 0 fragments | `--test acceptance_scenario` |
| Hostile input cannot exhaust the scanner | Oversized file, 4,000 nested blocks, 24-deep tree, 400 files over the ceiling, zip bomb: each refused at its ceiling and reported `INCONCLUSIVE` or an error, never a crash | `cargo test -p swp-test-suite --test resource_limits` |
| The root secret never leaves the store | Every artifact of every run — logs, reports, manifests, CLI output, temporary files — swept for the secret | `cargo test -p swp-test-suite --test secret_leak` |
| Cost at ordinary size | 241 files (0.35 MiB, 32 sites): protect 7.2 s, verify 7.2 s, scan 5.0 s, 5.0 MiB peak heap during protect | `cargo test -p swp-test-suite --test performance` |

## What the verdict gate accepts, and what it withholds

The rule in [§12 of the spec](SWP-1-SPEC.md#12-evidence) is a statement about a
scan, so it can be measured: mint look-alike projects, watermark each, scan every
tree with every other project's keys, and record what the gate said. That is what
`verdict-model` does — it calls the same `tally` the report calls, on real
cross-scans, and prints one row per scan. 30 iterations of a 6-project matrix gives
1,770 scans per tag width, 930 of them unrelated.

| | 4 bits (the default) | 6 bits | 8 bits |
| --- | --- | --- | --- |
| `λ` per unrelated scan | 2.827 | 0.825 | 0.210 |
| observed mean confirmations | 0.950 | 0.301 | 0.065 |
| `λ` ÷ observed | 2.98× | 2.74× | 3.26× |
| observed variance ÷ mean | 0.952 | 1.013 | 1.002 |
| `λ` from spans ÷ `λ` from distinct codes | 1.018 | 1.005 | 1.001 |
| unrelated scans accused, previous rule | 3 of 930 | 2 of 930 | 2 of 930 |
| unrelated scans accused, probability gate | **0 of 930** | **0 of 930** | **0 of 930** |
| confirmations a 12-site release needs to be a finding | **10** | 6 | 4 |
| … to reach `STRONG` (never at 4 bits: 13 > 12 sites) | 13 | 8 | 5 |
| … to reach `VERY_STRONG` on tags alone | 17 | 11 | 7 |

Two things follow, and neither is a comfort. At the default 4-bit width a finding on
tag counts alone needs nearly the whole constellation, which is why `STRONG` appears
zero times in the 4-bit column: every `VERY_STRONG` there is a tree-fingerprint
match, and a 12-site release cannot reach `STRONG` on tags at all. Widening the tag
is what buys sensitivity back — 4 of 12 confirmations suffice at 8 bits, where 10
are needed at 4 — and the measurements above are the reason the default is still 4:
at 4 bits the gate withheld every accusation while still confirming every intact
copy.

Detection cost, same scans, counted as findings the pre-gate rule reached. Each cell
is detections under the old rule then under the gate:

| candidate | 4 bits | 6 bits | 8 bits |
| --- | --- | --- | --- |
| own tree, fingerprint `match` | 180 → 180 | 180 → 180 | 180 → 180 |
| whole tree copied, no fingerprint | 30 → 30 | 30 → 30 | 30 → 30 |
| 75% of files copied | 30 → 30 | 30 → 30 | 30 → 30 |
| 50% of files copied | 30 → 1 | 30 → 30 | 30 → 30 |
| 25% of files copied | 30 → 0 | 30 → 2 | 30 → 30 |
| 10% of files copied | 0 → 0 | 0 → 0 | 0 → 0 |
| 13 ordinary refactorings | 360 → 330 | 360 → 360 | 353 → 336 |
| 4 site-removal attacks | 55 → 2 | 38 → 30 | 34 → 32 |
| **all genuine-class scans** | **715 → 573 (80%)** | **698 → 662 (95%)** | **687 → 668 (97%)** |

`X → Y` reads "the replaced additive-slack rule found it, the gate did or did not".
Every one of those numbers is a subtraction or nothing: across all 5,310 scans there
is **no** case where the gate reached a finding the old rule withheld. Where the
gate withholds, the report says `INCONCLUSIVE` and prints the probability it used.

The loss is concentrated in the half-and-under partial copies and in
`site_rewrite`/`module_rebuild` removal attacks at the default width. Those are the
cases where a few true confirmations sit inside what chance hands an unrelated tree,
and the tool now declines to say so — a partial copy at 4 bits is graded
`INCONCLUSIVE` rather than accused on 6 of 12 sites.

* Residual risk, stated as a bound rather than a reassurance: 0 accusations in 100
  runs of the §28 suite leaves a 95% upper bound of **3.0% per run**, and 0 in 5,790
  unrelated scans leaves **5.2e-4 per scan**. The suites are random-key tests; they
  demonstrate the direction of the rule, not its exact rate, and this page is where
  the rate's bound lives rather than in a claim that it is zero.
* The `probes`, `λ` and confirmation columns vary run to run because site placement
  is derived from the project's secret. The verdicts and the ratios above are what
  the 30-iteration sample was sized to support.

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
