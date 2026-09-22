# Validation

Every claim SWP-1 makes about itself is a number some suite printed. This page is
where those numbers live, in the shape the suites print them, with the command that
re-produces each one and a sentence about what it does *not* show.

The rule that shaped the page: no figure here was typed in. Each came off a run on
one machine, and each is reachable again by a named test. Where a run produced a
result that weakens the product, it is on this page rather than omitted — a
validation document that only carries the good rows is marketing.

**One machine, one date.** 21–22 September 2026, Windows 11 x64 (build 26200), an
8-logical-processor Intel laptop, `rustc 1.91.1`. Everything below was measured
there. The measurement suites run as **debug** builds because `cargo test` does
that, which is the correct profile for counting and the wrong one for timing; the
performance section says what is portable and what is not. The clean-environment
run is the exception: it used a real `cargo install --release` binary.

**Two transcripts, then tables.** The two blocks below quote output this build
actually produced, from the fixture run the
[documentation test](DEVELOPER-GUIDE.md#the-documentation-is-a-test) re-runs. The
rest of the page is in tables because the numbers are what matters and a reader
should be able to compare rows without unwinding a transcript.

```console
$ swp verify
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  fingerprint match (release published …)
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent

Every site of this release is present with its code. That is the whole claim; it says nothing about the tree being otherwise unchanged.
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

## How to read a table here

Three columns recur, and each has a precise meaning that is easy to over-read:

| column | means | does not mean |
| --- | --- | --- |
| `confirmed` | sites whose keyed address resolved **and** whose text decoded to the code this project's key derives | "this file is a copy" — a fragment is an observation about an address |
| `probes` | spans that reached a tag comparison, i.e. comparisons actually performed | the size of the candidate tree |
| `chance` | expected confirmations from `probes` draws at `tag_bits`, taking spans that share an address as one draw | a probability about a person or a case |

`guarantee` is `confirmed − chance`: how many confirmations sit above what an
unrelated tree is expected to land by luck. The suites print the assumption-free
bound beside it (`loose`, every span counted separately) rather than picking the
flattering one, because a verdict that depends on which of the two you use is a
verdict resting on an assumption.

`NO_PROVENANCE_DETECTED` is not "original". `INCONCLUSIVE` is not "clean" and not
"detected". The four verdicts and the exit codes are [CLI.md](CLI.md#exit-codes);
the ladder that turns counts into a level is
[REPORTS.md](REPORTS.md). Most rows below end in one of three strings:
`PROVENANCE_DETECTED`, `INCONCLUSIVE`, `NO_PROVENANCE_DETECTED`, followed by the
level.

## 1. A clean environment

A measurement taken only inside fixtures proves the fixtures; this run exists to
prove the system works outside them. It starts by deleting build artifacts and
ends with reports reviewed, in a scratch directory, by the installed binary — not
by `cargo run`, not by the test harness, and with no file copied out of this
repository.

| # | step | what ran | result |
| --- | --- | --- | --- |
| 1 | delete build artifacts | a `CARGO_TARGET_DIR` that had never held a build, and a `--root` prefix that did not exist yet | nothing cached to lean on |
| 2 | clean environment | `cargo install --path crates/swp-cli --root <temp> --locked --offline` | 93 compilation units, release profile, about two minutes, no network access requested |
| 3 | install | the same command; `swp.exe` lands in the temp prefix | `swp --version` → `swp SWP-1 · swp 1.0.0 · report schema SWP-1-report-v1` |
| 4 | brand-new sample project | three hand-written JavaScript files written for this run, 2162 bytes, `src/order.js`, `src/units.js`, `src/format.js` | `swp init` suggested `target_sites 4`, minted `swp1-…`, sealed a key, wrote `.gitignore`, changed no source |
| 5 | protect it | `swp generate`, `swp protect --dry-run`, `swp protect --sites 12` | plan `4/4 embedded, 14 refused`; real run `6/12 embedded, 12 refused` for `overlapping-radius`; 2162 → 2202 bytes |
| 6 | verify it | `swp verify`, `swp verify --format json`, `swp verify --release <id> --save` | `INTACT — 6/6 site(s) still carry their code, 24 keyed bit(s)`, fingerprint `match`, 13 evidence items, exit 0 |
| 7 | second unrelated project | two Python files (a CSV cleaner), 1200 bytes, no relation to the first | `swp scan ../beta` → `NO_PROVENANCE_DETECTED / NONE`, `0/6`, 0 spans reached a tag comparison, exit 0 |
| 8 | scan it | same command | the scan read 2 of 2 files and had no source of the project's to find |
| 9 | copied/refactored project | the two protected files moved to `lib/`, a third file rewritten by hand under new names, comments gone, 4-space indents | `swp scan ../gamma` → `PROVENANCE_DETECTED / STRONG`, `4/6`, 16 keyed bits, all 4 `Found outside their original file`, 2 absent |
| 10 | scan it | same command, then `--format json` | `Hypotheses probed: 34 literal(s), 24 rendering(s), 7 reached a tag comparison`, bound `0.4258` (loose `0.4375`), fingerprint `no-match`, exit 1 |
| 11 | review the reports | `swp report`, `swp report --format json`, `swp report <name>`, `swp report <name> --output` | index lists 1 of 1 saved report; re-render prints the stored grade unchanged; export writes 14541 bytes of JSON |

Four things came out of doing this outside the fixtures.

**A rewrite of the same logic found nothing, and said so.** Step 9's tree was a
copy *plus* a rewrite, so the finding there is mostly the copies. Scanning the
rewrite alone — one file, the same behaviour, every name changed, the protected
literals re-spelled as different expressions — gave
`NO_PROVENANCE_DETECTED / NONE`, `0/6` confirmed, `3` sites showing the release's
address without its code, and exit `0`. That is the boundary holding in the field:
SWP-1 does not detect reimplementation, and the report for a reimplementation is a
clean "nothing here" rather than a hedge.

**Re-minting a key moves the watermark.** The run was performed twice from
identical source. Both times `protect --sites 12` embedded 6 sites and refused 12,
and both times `verify` read `INTACT — 6/6`. They did not protect the same six
addresses: one key took `src/order.js:29` under the `sub` family and
`src/units.js:16` under `add`, the other took `src/order.js:31` under `add` and
`src/units.js:16` under `sub`, and `src/format.js`'s second site moved from line 18
to line 16. This is why every documentation transcript elides key-influenced
values with `…`, and why a report is only comparable to another report from the
same project.

**The scanner never reached outside its own store.** After steps 1–11 the store
holds exactly eight files, none of them outside `alpha/.swp/`:

```text
.swp/config.toml
.swp/private/manifests/rel-4bzkqnjys3j36.json
.swp/private/plans/rel-4bzkqnjys3j36.json
.swp/private/plans/rel-bdfh5ntjfrpbq.json
.swp/private/reports/verify-2026-09-21T23-07-38Z.json
.swp/private/root.key
.swp/public/identity.json
.swp/public/releases/rel-4bzkqnjys3j36.json
```

Two plans, because `swp generate` was run on its own before `swp protect`, and
`protect` mints its own release rather than adopting the plan's. Nothing was
written into `beta/` or `gamma/`; both stayed at the byte count the scanner reported
reading, and neither gained a `.swp/`.

**A display defect the fixtures could not see.** `swp init` printed the project
root as `C:\Users\…\alpha`; `swp inspect store` printed the same root as
`\\?\C:\Users\…\alpha`, the Windows verbatim-path prefix leaking into a line an
operator would copy. The fixtures never noticed because they run from paths that
canonicalize unchanged. `inspect store` and the `--target` refusal now normalize
through the same helper `init` uses
(`swp_core::text::display_path`), and the clean run re-done after the fix prints
one form. Recorded here because a clean run earns its place by finding what the
fixtures cannot see.

## 2. Partial copies

A 24-site release over 12 modules, copied to fractions of itself. `swp-test-suite
--test detection_matrix`. These are observations, not thresholds: no row is a
detection limit, only what this run found.

| kept | files in candidate | confirmed of 24 | probes | chance | guarantee | fingerprint | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10% | 2 of 13 | 3 | 14 | 0.9 | 2.1 | no-match | PROVENANCE_DETECTED / MODERATE |
| 25% | 4 of 13 | 6 | 33 | 1.9 | 4.1 | no-match | PROVENANCE_DETECTED / STRONG |
| 50% | 7 of 13 | 13 | 79 | 4.4 | 8.6 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| 75% | 10 of 13 | 20 | 133 | 6.5 | 13.5 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| 90% | 12 of 13 | 23 | 156 | 7.3 | 15.7 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| 100% | 13 of 13 | 24 | 173 | 7.9 | 16.1 | match | PROVENANCE_DETECTED / VERY_STRONG |

The 10% row is the interesting one: three confirmations out of 24, on 14 probes
where an unrelated tree is expected to land 0.9, clears the bound and is graded
MODERATE — a lead, not a claim. Below that, a single site is 1-in-16 by chance at
4 tag bits, which is why the ladder never treats one fragment as a finding
([SWP-1-SPEC.md](SWP-1-SPEC.md)).

## 3. Normal refactoring

The same release, thirteen transformations applied to a copy. Each row is one form
on its own, which is what a real refactor looks like.

| form | confirmed of 24 | probes | chance | fingerprint | verdict |
| --- | --- | --- | --- | --- | --- |
| variable_rename | 22 | 131 | 6.6 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| function_rename | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| class_rename | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| formatting | 24 | 142 | 7.2 | match | PROVENANCE_DETECTED / VERY_STRONG |
| comment_removal | 24 | 142 | 7.2 | match | PROVENANCE_DETECTED / VERY_STRONG |
| file_movement | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| function_extraction | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| function_inlining | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| expression_rewrite | 24 | 124 | 6.5 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| constant_rewrite | 19 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| import_changes | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |
| dead_code_removal | 5 | 34 | 1.6 | no-match | PROVENANCE_DETECTED / STRONG |
| code_reordering | 24 | 142 | 7.2 | no-match | PROVENANCE_DETECTED / VERY_STRONG |

13 of 13 still produced a finding. Only two rows lose sites: `constant_rewrite`
(19) because rewriting a literal *is* rewriting the fragment's value, and
`dead_code_removal` (5) because deleting a function deletes the statements inside
it, fragment included. Both are honest losses and both are reported as fewer
fragments rather than as a different kind of answer.

`formatting` and `comment_removal` are the two rows whose fingerprint still
matches. The [SWP-1-SPEC §9](SWP-1-SPEC.md#9-fingerprints) digest is taken at L1,
where whitespace between tokens collapses to one space, comments are dropped, and
a line break survives as exactly one newline ([SWP-1-SPEC
§5](SWP-1-SPEC.md#5-canonicalization)) — so re-indenting a file is invisible to
it, while splitting a statement across two lines is not. Every other row says
`no-match` while keeping all 24
fragments, which is the point of having both channels —
[SWP-1-SPEC.md](SWP-1-SPEC.md) has the argument.

## 4. Deliberate removal

Attacks whose only goal is taking the watermark out. The column that matters most
here is the one a vendor would drop: how much of the fragment text is still
physically present after the attack.

| attack | files changed | renderings still in text | confirmed of 24 | probes | chance | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| (unmodified copy) | — | 24 of 24 | 24 | 190 | 8.4 | PROVENANCE_DETECTED / VERY_STRONG |
| artifact_removal | 12 | 0 of 24 | 0 | 194 | 8.5 | NO_PROVENANCE_DETECTED / NONE |
| site_rewrite | 12 | 11 of 24 | 11 | 190 | 8.4 | PROVENANCE_DETECTED / MODERATE |
| constant_normalization | 11 | 24 of 24 | 18 | 154 | 6.4 | PROVENANCE_DETECTED / VERY_STRONG |
| module_rebuild | 12 | 5 of 24 | 2 | 12 | 0.6 | INCONCLUSIVE / WEAK |

The watermark is not impossible to remove. `artifact_removal` — delete every
artifact the tool leaves and the fragments with them — takes it to zero, and the
report says so plainly. That is the design: a reader who is told removal is
impossible will eventually watch it happen and stop trusting the rest.

The two middle columns answer different questions and can disagree. "Renderings
still in the text" asks whether the recorded byte string is somewhere in a file;
"confirmed" asks whether a site's keyed address still resolves to that code.
`constant_normalization` scores 24 of 24 on the first and 18 of 24 on the second:
the fragments are there, and six of them are no longer where the address says they
are.

## 5. Attacks composed

Single attacks understate an adversary who tries several things. Twenty-four random
chains, each applying transformations in a random order.

| experiment | result |
| --- | --- |
| 24 chains of removal attacks, each deleting every artifact it could find | the most any single chain left intact was **13 of 24** sites |
| best-surviving chain | `site_rewrite > artifact_removal > constant_normalization` |
| why order matters | rewriting a site first moves its rendered text, so the deletion that runs after it has nothing left to look for |
| 24 chains of refactoring transformations (seed `0x2545f4914f6cdd1d`) | 21 graded VERY_STRONG, 3 MODERATE, **0 confirmed nothing** |
| longest refactoring chain that still produced a finding | 4 transformations deep |
| verdict contract | held on all 48 chains: a chain that confirms nothing is reported `NO_PROVENANCE_DETECTED`, never as "this was rewritten" or "this is original" |

## 6. Innocent projects

The false-positive question, asked the way an auditor would ask it: take code that
has nothing to do with any protected project, and scan it with real keys.

| corpus | keys tried | confirmed | probes seen | files read |
| --- | --- | --- | --- | --- |
| algorithms | 5 independent identities | 0 in all 5 | 11–30 | 2 per scan |
| framework | 5 | 0 | 4–9 | 2 |
| boilerplate | 5 | 0 | 2–3 | 2 |
| generated (80 modules of one template) | 5 | 0 | 128–192 | 82 |
| stdlib | 5 | 0 | 0 | 1 |
| open-source project | 5 | 0 | 4–9 | 2 |
| **total** | **30 scans** | **0** | **946 spans reached a tag comparison** | **455 files, 692 000 bytes, none left unexamined** |

Across all 30 scans the bounds were `chance` 21.2 and `loose` 59.1 — two figures
printed as measured, not reconciled — and the largest single confirmation count
was **0**. The `generated` corpus is the hardest: eighty modules
of one template hand the matcher more spans at a site's address than the
detector's per-file window cap (`MAX_WINDOWS_PER_FILE`) keeps, which is the shape
that would manufacture evidence out
of sheer volume if counting the same statement twice could do it. It cannot.

| further case | result |
| --- | --- |
| 6 projects from the same generator template, 6 different keys | 0 of 6 confirmed a shared idiom, 123–142 probes each |
| a tree sharing the protected constants verbatim, nothing else | 0 confirmed on 2 probes |
| positive control: an exact copy scanned by the keys that protected it | 24 of 24, VERY_STRONG |

The positive control is what makes the zero rows mean something. Without it, "0 of
30" could be a detector that never fires.

## 7. Two identities, one tree

| check | result |
| --- | --- |
| site addresses derived for one tree under key A and under key B | 48 addresses each, **0 shared** |
| the same tree protected under A, scanned with B's keys | `NO_PROVENANCE_DETECTED / NONE`, 0 of 12 confirmed |
| 6 identities × 6 trees, every off-diagonal pair | 30 foreign scans: 20 confirmed at least one site, largest count 3, **none reached a finding** |
| the 6 diagonal pairs (a project's own keys, its own tree) | 12 of 12 confirmed each, VERY_STRONG |
| project id space | 80 bits (16 base32 characters); 50 freshly minted identities produced 50 distinct ids and 50 distinct verification key sets |
| expected colliding pairs among 50 mints | 1.01 × 10⁻²¹ |
| 800-symbol id draw (rare/expected/common) | rarest 16, commonest 36, expected 25 |
| longest shared prefix across 1225 id pairs | 2 characters, where about 0.00 pairs are expected to reach six |

The 20-of-30 row deserves its reading rather than a softer one. Those six trees are
*siblings* — the same fixture corpus, differently keyed — so shared idioms
reproduce a handful of addresses by construction. Twenty scans saw a lead; none of
them cleared its own coincidence bound, and all twenty printed `INCONCLUSIVE /
WEAK` with exit `10`. Unrelated code (section 6's 30 scans) did not even produce
leads. That difference — a lead is not a finding, and the ladder is what keeps
them apart — is what `--test collision` establishes.

## 8. As an attacker

Seven experiments, run as a suite named `adversarial_removal`.

**Locating sites from the source alone.** No manifest, no key, no knowledge of
which literal was chosen: a search for the four rendering *shapes* this protocol
can emit found all 24 in 12 files.

| shape | located |
| --- | --- |
| foldable arithmetic (`(8 - 8)` style) | 24 |
| mixed-case hex | 0 |
| escape-prefixed string | 0 |
| split string | 0 |

**Then folding what was located:** 0 of 24 confirmed, 154 probes still compared,
`NO_PROVENANCE_DETECTED / NONE`. A shape search is a locator, not a decoder: it can
find the sites, and once they are rewritten the finding is gone.

**Lifting functions into somebody else's project** (12 of 13 files hold at least one
fragment; 5 functions contain one; candidates are an unrelated corpus plus their
text, copied whole):

| lifted | confirmed of 24 | probes | chance | verdict |
| --- | --- | --- | --- | --- |
| 1 function | 1 | 7 | 0.401 | INCONCLUSIVE / WEAK |
| 3 functions | 3 | 11 | 0.626 | PROVENANCE_DETECTED / MODERATE |
| all 5 that hold one | 5 | 13 | 0.751 | PROVENANCE_DETECTED / STRONG |

The single-function row is the one the documentation has to carry: one fragment of
this project inside somebody else's tree is graded a lead on its own numbers, and
is not a claim of copying.

**Reverting to the pre-protection source** — copy the old files back over the new
ones, which is the cheapest attack available to anyone who has the earlier commit:

| reverted | confirmed of 24 | probes | chance | verdict |
| --- | --- | --- | --- | --- |
| a quarter of the site files | 18 | 160 | 7.681 | PROVENANCE_DETECTED / VERY_STRONG |
| half | 12 | 162 | 7.766 | PROVENANCE_DETECTED / STRONG |
| every changed file | 0 | 164 | 7.850 | NO_PROVENANCE_DETECTED / NONE |

**Pasting fragments between projects.** A wrote 24 sites, B 24 of its own; the
candidates hold not one line of either project's source, only the rendered
fragments as new statements next to an unrelated project:

| keys used | fragments planted | confirmed | probes | verdict |
| --- | --- | --- | --- | --- |
| A's | A's | 0 of 24 | 3 | NO_PROVENANCE_DETECTED / NONE |
| B's | A's | 0 of 24 | 2 | NO_PROVENANCE_DETECTED / NONE |
| A's | A's and B's | 0 of 24 | 3 | NO_PROVENANCE_DETECTED / NONE |
| B's | A's and B's | 0 of 24 | 2 | NO_PROVENANCE_DETECTED / NONE |

Fragments without their constellation are not attributable, and a leaked manifest
proved to be a removal tool rather than a framing one in this run.

**Restructuring while preserving behaviour:**

| attack | confirmed of 24 | exact | moved | probes | verdict |
| --- | --- | --- | --- | --- | --- |
| unmodified copy | 24 | 24 | 0 | 159 | PROVENANCE_DETECTED / VERY_STRONG |
| all 13 section-3 forms applied at once | 3 | 3 | 0 | 51 | INCONCLUSIVE / WEAK |
| every statement re-homed into a new enclosing function, files renamed | 24 | 24 | 24 | 159 | PROVENANCE_DETECTED / VERY_STRONG |
| compound, then bundled | 3 | 3 | 3 | 51 | INCONCLUSIVE / WEAK |

Combining the refactoring forms is strictly worse for detection than any one of
them: the forms are style edits keyed on a spelling, so they consume each other's
targets (one of the thirteen, `function_inlining`, found nothing left to rewrite in
the combined diff). The bundled row is the opposite lesson — moving every statement
into new files costs nothing, because no keyed address contains a file name.

**Hiding the tree in an excluded directory.** The same 12 modules bundled into
`dist/`, which the default exclude list removes from the walk: 0 files scanned,
verdict `INCONCLUSIVE / NONE`, `partial: true`. The report says
"contained no source this protocol can read, so there was nothing to match
against" rather than "no watermark" — the distinction between finding nothing and
looking at nothing.

**Dilution by padding** — one stolen tree, three candidates differing only in what
was added around it, fragments and bytes identical in all three (asserted by the
test, not by eye):

| candidate | confirmed of 24 | probes | chance | guarantee | verdict |
| --- | --- | --- | --- | --- | --- |
| exact copy | 24 | 195 | 8.7 | 15.3 | PROVENANCE_DETECTED / VERY_STRONG |
| + 82 generated files | 24 | 359 | 9.5 | 14.5 | PROVENANCE_DETECTED / VERY_STRONG |
| + 80 files in the project's own style | 24 | 982 | 20.6 | 3.4 | PROVENANCE_DETECTED / STRONG |

Padding does not dilute the evidence; it inflates the bound, and the grade absorbs
that. The assumption-free bound nearly triples on the last row and the verdict drops
one step, which is the ladder behaving as designed.

## 9. Hostile input

Trees built to make a scanner hang, crash, over-read or escape its directory.

| input | what the tool did | exit |
| --- | --- | --- |
| directory tree 24 levels deep, `max_depth` 12 | walked 1 of 2 files, named the stopping directory (`src/d0/d1/…/d10: directory at max_depth (12), so its contents were not walked`), verdict `INCONCLUSIVE / NONE` | — |
| one file of 8 388 609 bytes, ceiling 8 388 608 | refused mid-tree, still read the other file (100 bytes), `INCONCLUSIVE / NONE` | 10 |
| a symlink pointing outside the tree | refused and named: `src/escape.js: symbolic link, never followed` | — |
| 4 000 nested blocks in one file (74 910 bytes) | stopped before the stack: `a syntax tree past this scanner's bounds (max_depth=256, max_nodes_per_tree=2000000), so its site list is incomplete` | 10 |
| 400 files, `max_files` 250 | refused the whole scan — a prefix of a tree is not the tree you asked about — `LIMIT_REACHED` | 7 |
| 67 108 864-byte payload in 65 318 zipped bytes (ratio 1027) | measured before expanding: `expands 1029 times over its stored size, past max_archive_ratio (200)` | 7 |
| the same archive *inside* a scanned tree | named as unexamined: `an archive; only the container named on the command line is opened (max_archive_depth=1)` | — |
| 8 malformed files (unclosed, truncated, non-UTF-8, empty, embedded NUL, CRLF-only, 200 KB of semicolons, a non-source file) | answered instead of crashing: 6 scanned, 200 142 bytes read, each refusal named, `INCONCLUSIVE / NONE` | 10 |

Every row ends in either a refusal with a reason or a partial reading with the
unread files named. None ends in a crash, and none ends in `NO_PROVENANCE_DETECTED`
— an unexamined tree is never reported as a cleared one.

## 10. The secret stays out

Seven sweeps, run by `--test secret_leak`, all passing at the time of writing:

| test | what it searches for |
| --- | --- |
| `every_command_prints_and_writes_nothing_searchable` | the stdout and artifacts of all seven commands |
| `public_and_private_artifacts_built_from_the_key_are_clean` | manifests, release records, plans, reports |
| `nothing_in_the_store_but_the_root_key_file_leaks_the_secret` | every file under `.swp/` except the key itself |
| `no_temporary_or_backup_file_survives_a_write` | leftovers a failed write could leave in a shared temp dir |
| `debug_renderings_of_every_secret_bearing_type_are_redacted` | `{:?}` output of every type holding key material |
| `error_messages_never_quote_key_material` | failure paths, including parser refusals |
| `root_key_file_holds_only_sealed_material` | the key file contains OS-sealed bytes, not a usable raw secret |

The clean-environment run swept its own 1 174-line transcript for the sealed key
blob's base64 as well, and found none of it. That is a weaker check than the seven
above and is listed only because it was performed.

## 11. Performance

**Debug profile, one laptop, nothing else running.** The portable claim is the
ratio between tiers and the shape of the columns; the milliseconds are what this
machine did on this evening. Release builds are faster by a multiplier this suite
deliberately does not publish, because the last person to quote one could not
reproduce it either.

| tier | files | MiB | sites | protect | verify | scan | parse | heap (pro/scan) | AST share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| small | 13 | 0.02 | 12 | 1962 ms | 650 ms | 459 ms | 122 ms | 0.3 / 0.2 MiB | 27% |
| medium | 61 | 0.09 | 20 | 3193 ms | 2089 ms | 2007 ms | 732 ms | 1.3 / 0.6 | 36% |
| large | 241 | 0.35 | 32 | 7216 ms | 7212 ms | 5046 ms | 1650 ms | 5.0 / 1.8 | 33% |
| very large | 721 | 1.03 | 48 | 12627 ms | 15905 ms | 15538 ms | 5707 ms | 14.9 / 4.8 | 37% |

| derived | numbers |
| --- | --- |
| per-file protect | 150.9 → 52.3 → 29.9 → 17.5 ms as the tree grows |
| per-file scan | 35.3 → 32.9 → 20.9 → 21.6 ms |
| heap per MiB of source | 18.0 → 14.5 → 14.3 → 14.5 MiB during protect; 10.4 → 6.2 → 5.1 → 4.7 during scan |
| repeated protection of the same tree | 3519 ms then 3004 ms — the second run does not re-pay parse and derivation work it can reuse |
| documented expectation, 241 files | protect 32.1 ms/file; scan 28.9 / 30.8 / 32.8 ms/file over five runs; peak heap 5.0 MiB |

Per-file cost *falls* as the tree grows, because the fixed startup and store I/O is
amortized; heap per MiB falls for the same reason. The `very large` protect column
is the one that grows fastest in absolute terms, and the guard in the suite is on
ratios rather than wall-clock so that a busy laptop cannot fail a correctness
change. Tree-sitter's parser arenas are C allocations and are outside the heap
columns, which is stated because a reader comparing against `heaptrack` output will
otherwise think the numbers disagree.

## 12. End-to-end acceptance

Three projects: A is 5 JavaScript files with 15 sites, B is 4 Python files with 10,
C is 2 files of unrelated code that shares their shapes. Run by
`--test acceptance_scenario`.

| row | confirmed | probes¹ | fingerprint | verdict | whose keys ran |
| --- | --- | --- | --- | --- | --- |
| A → A | 15 | 20 | match | PROVENANCE_DETECTED / VERY_STRONG | A |
| B → B | 10 | 15 | match | PROVENANCE_DETECTED / VERY_STRONG | B |
| C ↛ A | 0 | 1 | no-match | NO_PROVENANCE_DETECTED / NONE | A |
| C ↛ B | 0 | 0 | no-match | NO_PROVENANCE_DETECTED / NONE | B |
| A-copy | 15 | 20 | match | PROVENANCE_DETECTED / VERY_STRONG | A |
| A-refactored | 15 | 20 | no-match | PROVENANCE_DETECTED / VERY_STRONG | A |
| A-partial | 10 | 15 | no-match | PROVENANCE_DETECTED / STRONG | A |
| A-damaged | 11 | 20 | no-match | PROVENANCE_DETECTED / VERY_STRONG | A |
| A's keys ↛ B | 0 | 0 | no-match | NO_PROVENANCE_DETECTED / NONE | B |
| B's keys ↛ A | 0 | 0 | no-match | NO_PROVENANCE_DETECTED / NONE | A |

¹ This is the only column on the page that does not repeat. A probe is a candidate
span that reproduced a manifest address and so reached a tag comparison, and which
spans do that depends on where the protected sites sit — which is derived from the
project's secret, and a run of this test mints a fresh secret. Five re-runs on the
same machine gave 17–21 probes on A's rows and 11–15 on B's, with `confirmed`,
`fingerprint` and `verdict` identical every time. The column is recorded because the
evidence grade is computed from it; it is not a figure to compare your own run
against.

`A-damaged` is the scenario's hardest row. Every second site of A's constellation is
rewritten into a spelling that carries the same value and a different tag, so the
code survives and the watermark does not. 11 of 15 fragments were confirmed, all 11
as exact renderings, 0 moved, 0 canonical-only, 4 stripped, across 3 files — and the
grade stayed VERY_STRONG. That is the result to be uncomfortable about rather than
proud of: 11 survivors clear VERY_STRONG's floor of 8 fragments across 3 files, so
destroying a quarter of the sites did not move the tier. What the row shows is that
the tier tracks *how much* confirms, not how much is missing, and a reader who needs
the second question answered has to ask it of the stripped count in the JSON report
rather than of the grade.

The last column is the store each scan ran from, not a claim about the candidate: a
scan only ever holds one project's keys, so what identifies a candidate is the
confirmed count beside it.

## 13. What none of this shows

Stated as the limit on every table above. SWP-1 does not, and no row here supports
its doing:

* **establish legal ownership** of anything;
* **prove authorship by itself** — it reports that an artifact carries code derived
  from a project's secret; who typed it is outside the measurement;
* **detect after arbitrary rewriting** — section 8's fold row and section 1's
  rewrite-only scan are exactly this case, both correctly answered
  `NO_PROVENANCE_DETECTED`;
* **detect a complete reimplementation** — the same rows;
* **resist deliberate removal** — `artifact_removal` reaches 0 of 24, and the
  composed chains in section 5 delete everything they are pointed at;
* **detect every possible copy** — section 2's 10% row is a copy of three
  fragments and is graded MODERATE, not STRONG;
* **produce zero false positives** — section 6 reports 0 of 30 on unrelated code
  and section 7
  reports 20 of 30 foreign scans producing at least one *lead*. Neither is a
  statement that no tree anywhere will ever confirm a site.

What the numbers do support is narrower and is the only claim this project makes:
SWP-1 provides technical provenance evidence about artifacts, graded against a
coincidence bound that is printed with every finding, and it says when it did not
look.

## Re-running every number on this page

| section | command |
| --- | --- |
| 1 — clean environment | the steps in the table, or the sequence in [GETTING-STARTED.md](GETTING-STARTED.md) against a scratch directory |
| 2, 3, 4, and 8's padding row | `cargo test -p swp-test-suite --test detection_matrix -- --nocapture` |
| 5 | `cargo test -p swp-test-suite --test property_chains -- --nocapture` |
| 6 | `cargo test -p swp-test-suite --test false_positive -- --nocapture` |
| 7 | `cargo test -p swp-test-suite --test collision -- --nocapture` |
| 8 | `cargo test -p swp-test-suite --test adversarial_removal -- --nocapture` |
| 9 | `cargo test -p swp-test-suite --test resource_limits -- --nocapture` |
| 10 | `cargo test -p swp-test-suite --test secret_leak` |
| 11 | `cargo test -p swp-test-suite --test performance -- --nocapture` |
| 12 | `cargo test -p swp-test-suite --test acceptance_scenario -- --nocapture` |
| the two transcripts | `cargo test -p swp-test-suite --test docs_examples` |

Two of these are slow: `performance` is about three minutes, `false_positive` and
`collision` about twenty seconds each. None of them needs a network, and none of
them runs project code from outside this workspace.

## Related

* [THREAT-MODEL.md](THREAT-MODEL.md) — the same measurements read as attacks and residual limitations
* [SECURITY.md](SECURITY.md) — the properties the hostile-input and secret-leak
  sweeps defend
* [REPORTS.md](REPORTS.md) — what each number may be used for
* [DEVELOPER-GUIDE.md](DEVELOPER-GUIDE.md) — the suites above as targets you can edit
* [FAQ.md](FAQ.md) — the short answers, for when you do not want a table
