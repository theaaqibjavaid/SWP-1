# Reports: structure and interpretation

SWP-1 produces one kind of artifact beyond the source it edits: a report. §33
asks for a versioned document that is machine-readable and human-readable at the
same time, and this build resolves that by making the document JSON and the text
a rendering of the same struct — there is no second implementation of the prose
that could drift away from the fields.

This page is the reference for both schemas and for what each number may be used
for. It is deliberately paired with [`SWP-1-SPEC.md`](SWP-1-SPEC.md), which
defines the rules the numbers come from, and with
[`THREAT-MODEL.md`](THREAT-MODEL.md), which defines what a report is evidence
against.

Every transcript here came from `scripts/capture-docs.sh`; a `…` stands for
whatever this project's key decides (an id, a digest, a timestamp, a byte count,
a keyed literal), and the block under a `$ swp` line is checked line by line
against a fresh run of the JavaScript example by the `docs_examples` suite.

## There are two documents, not one

| schema | written by | what it answers |
| --- | --- | --- |
| `SWP-1-report-v1` | `swp scan`, and `swp verify --save` | *does this candidate carry one of my releases?* |
| `SWP-1-verify-v1` | `swp verify`, in its `--format json` output | *is the tree I am standing in still the tree I protected?* |

They share the idea of a run, a candidate and a set of limitations, and they are
not interchangeable. `swp verify --save` writes a `SWP-1-report-v1` document
because a saved report has to be re-readable by `swp report` a year later;
`swp verify --format json` prints the verify document because that shape carries
the per-site table, which is the whole point of verifying.

Neither is signed. A report is an observation made by whoever held the secret at
that moment; the signed artifacts of a release are its record and its manifest,
described in §5 and §6 of the spec.

## Where a report goes

`--save` writes the document under `.swp/private/reports/` as
`<command>-<timestamp>.json`, second-precise like every other timestamp in the
protocol. Two saves inside the same second do not overwrite each other — the
second becomes `…-2.json` — because a re-scan loop that kept only its last
finding would be losing evidence silently. The command prints the name it
actually wrote.

Reports are private, and the listing says why in the tool's own words:

```console
$ swp report
saved reports — javascript (swp1-…)
  1 of 1 file(s) under .swp/private/reports/, newest first

  report                         run     result                 evidence       items
  verify-…    verify  PROVENANCE_DETECTED    VERY_STRONG       …
                                 … (directory) · 6 file(s) · 1 release(s): rel-…

Notes
  · A saved report keeps the grade it was given. This listing prints the level stored in the file; it does not re-run the ladder, so a finding from before a rule change still reads the way it read on the day it was made.
  · Reports live under .swp/private/reports/ and are private: one names your source paths, the sites you protect and the files a candidate had in it. Share the document you mean to share, not the directory.
```

That is the second reason the directory is private, after the obvious one that
it was produced with the secret. A report quotes source text: an evidence item
carries the matched span as it stands in the candidate, which for a protected
literal is a rendering of your watermark. Nothing in a report lets anyone
*derive* the watermark without the secret, and the secret-leak sweep in §29 is
built on exactly that distinction — but a report is a document about your
watermark's locations, and it belongs with your source rather than in a public
issue. `swp report <name> --output out.json` exports one document, unchanged
bytes, so you can choose which finding to hand over.

`swp report` with no name lists, and exits `0` whatever a listed report said:
reading an old finding is not a new one.

## `SWP-1-report-v1`, field by field

The top level is twelve fields, in the order the document writes them:

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | `SWP-1-report-v1`. Checked on load, not assumed |
| `protocol` | string | `SWP-1` |
| `run` | object | who wrote this and in response to what |
| `candidate` | object | what was looked at, and how completely |
| `result` | string | `PROVENANCE_DETECTED`, `NO_PROVENANCE_DETECTED`, `INCONCLUSIVE` |
| `evidence_level` | string | `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG` |
| `explanation` | string[] | one sentence per rule that fired, with its measured numbers |
| `releases` | object[] | one entry per release the candidate was judged against, strongest first |
| `evidence` | object[] | the observations themselves |
| `omissions` | string[] | paths the walk refused, with the reason |
| `notes` | string[] | caveats about the run: widths probed, containers opened, caps reached |
| `limitations` | string[] | the §51 boundary, inside the document |

`run` is `command` (the command that made the document — `scan` or `verify`),
`created_at` (RFC 3339 UTC) and `generator` (the build that wrote it, so an old
report can be re-read with the rules that produced it). `candidate` is
`described` (how you named it on the command line), `kind` (`file`,
`directory`, `zip`, `tar`, `tar.gz`, …), `files_scanned`, `bytes_scanned` and
`partial`.

`partial` is the field most often skipped and most often load-bearing: it is
true when any part of the candidate was never examined, and while it is true a
`NO_PROVENANCE_DETECTED` reading of that candidate is wrong.

### The release tally

`releases[]` is where the arithmetic lives. One scan of a copy of the protected
tree, as one document:

```console
$ swp scan ./copy --format json
{
  "schema": "SWP-1-report-v1",
  "protocol": "SWP-1",
  "run": {
    "command": "scan",
    "created_at": "…",
    "generator": "SWP-1 · swp 1.0.0 · report schema SWP-1-report-v1"
  },
  "candidate": {
    "described": "…",
    "kind": "directory",
    "files_scanned": 3,
    "bytes_scanned": …,
    "partial": false
  },
  "result": "PROVENANCE_DETECTED",
  "evidence_level": "VERY_STRONG",
  "releases": [
    {
      "project_id": "swp1-…",
      "release_id": "rel-…",
      "sites": 10,
      "fragments": 10,
      "stripped": 0,
      "absent": 0,
      "exact_renderings": 10,
      "canonical_only": …,
      "moved": 0,
      "renderings": …,
      "files": 3,
      "bits": 40,
      "tag_bits": 4,
      "probes": …,
      "literals_tried": …,
      "windows_tried": …,
      "fingerprint": "match",
      "chance": …,
      "guarantee": …,
      "level": "VERY_STRONG",
      "reasons": [
        "the candidate's canonicalized tree hashes to the fingerprint this release published, which is an exact copy of the protected source rather than an inference from it",
```

The counts divide into three groups, and mixing them up is the easiest way to
misread a finding.

*What the release had*: `sites` (keyed locations it published), `tag_bits`
(width each site carries).

*What the candidate reproduced*: `fragments` (sites present *with* their code),
`stripped` (address present, code absent), `absent` (no matching span at all),
and four overlapping views of the fragments — `exact_renderings` (byte-for-byte
the rendering the manifest recorded), `canonical_only` (reached only through the
rename-tolerant radii, so the statement matches while the text does not),
`moved` (found in a file other than the one that was protected), `renderings`
(whose matched span is more than one token wide). These are four ways one
confirmation can be described, not a partition of `fragments`: the copy scan
above reports ten fragments, and the same ten are also its ten exact renderings.

`canonical_only` is the one view of the four that can be non-zero for a copy
nobody touched, and so the line elided above: across the twenty recorded runs of
this suite it printed `0` eighteen times for a `copy/` edited in no way, and `1`
twice. Which of a release's sites arrive through the value-normalized radii
rather than the name-preserving ones is decided by the project's key, not by the
candidate, and `fragments`, `bits` and the level were the same in all twenty. It
grades nothing — the ladder counts a confirmation whichever radii delivered it —
and the field exists so an operator can see how a confirmation arrived, which is
the same question `swp verify` answers with its `refactored` boolean.

*What the search cost*: `files` (distinct candidate files holding a
confirmation), `bits` (keyed bits the confirmed sites carry), `probes`,
`literals_tried`, `windows_tried`, `chance`, `guarantee`, `fingerprint`.
`fingerprint` is `"match"`, `"no-match"` or `"not-comparable"` — the third means
the candidate and the release were not graded at the same canonicalization level,
which is an absence of a comparison rather than a failed one.

The last group is what makes a negative auditable. `swp scan ../plain` prints
one evidence item and it is this:

```console
$ swp scan ../plain
Evidence (1 item(s))
  [EV-000] NEGATIVE_CONTROL at - - NONE
      no site of this release was reproduced: 18 literal hypotheses and 11
      rendering hypotheses were keyed and looked up over 2 candidate
      file(s), and 0 span(s) reached a tag comparison
exit 0
```

That is §27's requirement: a clean answer states how hard it looked. A report
whose `literals_tried` is `12` over one file is not the same statement as the
one above, whatever both say about provenance.

`bits` is `fragments × tag_bits` in the ordinary case and it is the number to
compare between releases of the same project: 40 bits at 4 bits a site is ten
confirmations, and a scan of a partial copy that found six of them reports
`24`. `chance` is the expected number of those confirmations an unrelated tree
would produce by luck, computed over the comparisons this scan actually
performed; `guarantee` is `fragments − chance`. Both are described in the spec's
§11 and neither is a probability that anybody copied anything.

### Evidence items

`evidence[]` holds one object per observation, and one *site* can legitimately
produce three of them, because an item records how something was seen rather
than what was seen. Each carries:

| field | meaning |
| --- | --- |
| `id` | `EV-000`, `EV-001`, … deterministic for the same scan of the same tree, so a citation survives re-running |
| `kind` | one of the seven categories below |
| `project_id`, `release_id` | what it was matched against |
| `location` | where it was found in the candidate: `file`, `line`, `excerpt`, `tokens`, `radii` |
| `source_region` | where the same site sits in your protected release. A pointer for a reviewer, never a lookup key |
| `basis` | why this counts, in a sentence containing the measured numbers |
| `strength` | this item's own rung on the ladder |
| `protocol`, `schema` | `SWP-1` and `1` |

`location.excerpt` is the matched text as it stands in the candidate and
`location.tokens` is how wide the span was; `source_region` deliberately has
neither, because your own literal is already in your own manifest. `radii` lists
which of the release's four keyed radii reproduced the span — one radius is the
statement as written, four means it survived under every abstraction.

The seven kinds, what each one asserts, and the strongest grade it can carry:

| kind | earned by | max strength | asserts provenance |
| --- | --- | --- | --- |
| `EXACT_SOURCE_MATCH` | the candidate's canonicalized tree hashes to the release fingerprint | `VERY_STRONG` | yes |
| `WATERMARK_FRAGMENT_MATCH` | a keyed address holds a literal that decodes to this project's code for it | `STRONG` (`VERY_STRONG` only through the fingerprint) | yes |
| `PARTIAL_WATERMARK_MATCH` | some but not all of a release's sites are accounted for | borrowed from coverage | yes |
| `CANONICAL_MATCH` | the address was reproduced only through the rename-tolerant radii | `MODERATE` | yes |
| `STRUCTURAL_MATCH` | the address is present and the code is not | `WEAK` | **no** |
| `TOKEN_MATCH` | the matched span is a multi-token rendering, not a lone literal | `MODERATE` | yes |
| `NEGATIVE_CONTROL` | nothing of this release was reproduced, with the probe counts | `NONE` | no — it asserts absence |

The `basis` of a `STRUCTURAL_MATCH` states its own weakness, which is the
pattern for this array: an item that could be misread says so.

```console
$ swp scan ../typescript-foreign
Evidence (… item(s))
  [EV-000] … at … - WEAK
      the candidate reproduces this site's keyed address (… of four radii)
      but the text there is not this project's code; a copy of the same
      source from before protection, or with the fragments stripped, looks
      identical to this
```

The kind of the first item is elided because it is the one line here a key
decides. Almost always `EV-000` is a `STRUCTURAL_MATCH` like the ones under it,
and the four basis lines quoted are its text. Occasionally the same scan also
lands a code by chance somewhere in that tree — one value in sixteen per probe,
and the tree offers hundreds of probes — and then `EV-000` is a
`PARTIAL_WATERMARK_MATCH`, whose basis is the site tally in its own two lines,
and the four lines quoted belong to `EV-001`. Two of the twenty recorded runs of
this suite produced that second shape, and it is stated here rather than hidden,
because what stops a chance code from becoming a finding is the whole of §27's
point.

## Reading the levels

`evidence_level` is one rung for the whole run and it is computed from the site
list, never by counting items — otherwise one statement pasted under two
different renderings would look like a constellation. The thresholds, as the
report's own `explanation` prints them:

| level | needs, on counts alone |
| --- | --- |
| `NONE` | no fragment confirmed |
| `WEAK` | 1 confirmed site |
| `MODERATE` | 2 |
| `STRONG` | 4 across at least 2 files, or 6 anywhere |
| `VERY_STRONG` | 8 across at least 3 files |

The level is graded from confirmed *sites*, not from items, so a site found in a
different file than the one it was protected in still counts — which is why the
copy scan reaches `VERY_STRONG` against a candidate whose files sit under
`copy/` rather than `src/`.

That ladder is then capped by the coincidence bound, and the cap can only lower
a level, never raise it: `guarantee` — the confirmations left over once this
candidate's own probe volume is accounted for — must reach `1.5` for `MODERATE`,
`3.0` for `STRONG` and `6.0` for `VERY_STRONG`. When it bites, the report names
the level the counts would have earned. A matching fingerprint short-circuits
both rules and returns `VERY_STRONG`, because an exact canonical copy is not an
inference from fragments.

The same two tests decide whether a scan may print the *verdict*
`PROVENANCE_DETECTED`: a `guarantee` above zero **and** a level of at least
`MODERATE`, or a fingerprint match. A single 4-bit confirmation is therefore
listed as `WEAK` evidence while the command still exits `0`: it is a lead worth
looking at, not a finding, and §27's rule that a verdict may not say more than
its evidence level does is enforced by that one condition rather than by prose.

A complete "why" block, from a verification run over a tree that had a copy of
`src/` inside it — every site was found under `copy/`, so the whole-tree hash no
longer matched and the level had to come from the counts alone:

```console
$ swp report verify-…
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

Why this level
  watermark fragments: 10
  candidate files holding them: 3
  the 8 rule: eight or more confirmations across three or more files
  coincidence bound: … span(s) reached a 4-bit tag comparison at 10
    site(s), so an unrelated tree holding those addresses and none of this
    project's codes is expected to confirm at most … of them by chance
    (… if nothing is assumed about spans sharing an address); …
    remain
exit 0
```

## Three readings of the same tool

The clearest way to calibrate is to see a finding, a near-miss and a clean
result side by side. All three are the JavaScript project's store, judging three
different candidates.

**A copy.** `swp scan ./copy` — the three source files copied into `copy/src/`,
nothing else touched:

```console
$ swp scan ./copy
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

Project swp1-… · release rel-…
  Watermark fragments: 10/10
  Address without its code: 0
  Exact renderings: 10
  Present as canonicalized content only: …
  Found outside their original file: 0
  Keyed bits confirmed: 40 at 4 bits per site
  Fingerprint (10): match
  Evidence: VERY_STRONG
exit 1
```

**An unrelated project that happens to rhyme.** The TypeScript example shares no
code with the JavaScript one — it models alarms and temperature readings, not
invoices and tax — but it is written in the same idioms, and a loop of the shape
`let total = 0; for (let i = 0; i < xs.length; i += 1) { … }` canonicalizes the
same under both. A scan of that tree against the JavaScript release reproduces
several of its keyed addresses, and eighteen times in twenty it reproduces none
of its codes:

```console
$ swp scan ../typescript-foreign
result    …
evidence  …

Project swp1-… · release rel-…
  Watermark fragments: …/10
  Address without its code: …
  Exact renderings: …
  Keyed bits confirmed: … at 4 bits per site
  Fingerprint (10): no-match
  Evidence: …
```

Three pairs of lines are elided because they are one fact stated three ways: the
fragment count, the bits it confirms, and the level and verdict computed from
them. When the count is `0/10` the verdict is `NO_PROVENANCE_DETECTED`, the
level is `NONE`, and the command exits `0`. When a key is unlucky and one of the
tree's several hundred probes also matches its 4-bit code — which is what the
two runs out of twenty above did — the count is `1/10`, the level is `WEAK`, and
the verdict is `INCONCLUSIVE` with exit `10`: one confirmation is a lead, and a
lead the coincidence bound covers is not allowed to be called a result.

Those collisions are real, and the report says so in a named line and then
declines to count them. This is the shape a false positive takes in this design:
visible, itemized, and worth nothing. It is also why the address is only half of
a site: any tree that canonicalizes alike can reach an address, so the weight is
carried by the code sitting at it, which at the default width is one value in
sixteen and derived from a secret nobody else holds. Addresses without codes are
exactly what an unrelated project looks like, and the ladder's whole job is to
refuse to read that as provenance.

**An unprotected tree in another language.** No fragments, and the run reports
the negative it earned:

```console
$ swp scan ../plain
result    NO_PROVENANCE_DETECTED
evidence  NONE

Project swp1-… · release rel-…
  Watermark fragments: 0/10
  Address without its code: …
  Exact renderings: 0
  Keyed bits confirmed: 0 at 4 bits per site
  Hypotheses probed: 18 literal(s), 11 rendering(s), 0 reached a tag comparison
  Expected coincidental confirmations: 0.0000 (assumption-free bound 0.0000)
  Fingerprint (10): no-match
  Evidence: NONE

Skipped (1): not examined, so not cleared
  - pyproject.toml: no language adapter for this file type
exit 0
```

`Skipped` is not a defect. `pyproject.toml` is not source to this build, and a
file with no adapter is not a coverage hole — but a file that exists and could
not be opened is, and that difference is what `partial` reports. Here the tree
was examined as completely as this tool can examine a Python tree with no
protected release of its own loaded, so the answer is `0`, not `10`.

## `SWP-1-verify-v1`

`swp verify --format json` is a different question, so it has its own document.
The headline fields:

```console
$ swp verify --format json
{
  "schema": "SWP-1-verify-v1",
  "protocol": "SWP-1",
  "project_id": "swp1-…",
  "display_name": "javascript",
  "tree": "…",
  "release_id": "rel-…",
  "revision": null,
  "manifest_authenticated": true,
  "sites_expected": 10,
  "sites_confirmed": 10,
  "sites_exact": 10,
  "sites_stripped": 0,
  "sites_absent": 0,
  "sites_moved": 0,
  "sites_refactored": …,
  "tag_bits": 4,
  "confirmed_bits": 40,
  "files_scanned": 3,
  "bytes_scanned": …,
  "fingerprint": "match",
```

and per site:

```console
$ swp verify --format json
  "sites": [
    {
      "site": 0,
      "file": "src/invoice.js",
      "line_hint": …,
      "language": "javascript",
      "adapter": "ast",
      "class": "…",
      "family": "…",
      "width": 4,
      "status": "exact-rendering",
      "slots": [
        …
        …
      ],
      "found_in": "src/invoice.js",
      "found_line": …,
      "refactored": …,
      "moved": false
    },
```

Six values are elided, and they are the ones a key decides. Which of a file's
eligible literals becomes site 0, whether it is a number or a string, and which
rendering form it is rewritten as all follow from the project's own keys, so the
same tree prints a different first row in two different projects — see
[`SWP-1-SPEC.md`](SWP-1-SPEC.md) for why the spread is deliberate. `slots` and
`refactored` are elided together because they are the same fact: four radii
listed with `refactored: false` is a site found by its own text, and two — the
value-normalized pair — with `refactored: true` is the site this key happened to
render in a form the literal-preserving radii do not reach, which is the one such
row in twenty that this example prints. Everything else here is what this project
prints under any key, and this test suite re-runs it that way. `found_in` and
`found_line` are the detector's own answer rather
than a restatement of `file` and `line_hint`: a tree that repeats the site's
statement in two files offers two equal observations, and the one at the
published address is the one kept, so `moved` describes where the watermark
actually is.


`status` is one of four values, in ascending strength: `absent`,
`location-only` (an address with no code, the `stripped` count), `tag-confirmed`
(a literal that decodes to this project's code) and `exact-rendering` (that
literal, byte-for-byte as the manifest wrote it). `refactored` and `moved` are
the two booleans beside it rather than statuses of their own, because they
describe how a confirmation arrived, not whether one did. `line_hint` is exactly
that — a hint from the manifest, not an identity, which is why a moved site
still resolves. `omitted_rows` says whether the site list was windowed by
`--limit`, and `next` repeats the two commands that would follow this one.

The three verdicts and the code each one gets are in [`CLI.md`](CLI.md#swp-verify):
`INTACT` exits `0`, `INCOMPLETE` exits `5`, `INCONCLUSIVE` exits `10`. The
difference between the last two is coverage, not confidence: an `INCOMPLETE`
answer means the whole tree was read and some site lost its code, and a
`INCONCLUSIVE` one means part of the tree was never read, so neither answer
exists. `partial` is the field that says which.

Verify's `limitations` are its own three lines, and they are the honest summary
of what this document is:

```console
$ swp verify --format json
  "limitations": [
    "a site that carries its code is a statement about this artifact, not about who wrote it or what rights attach to it",
    "an absent site means the watermark is not here, which a deleted function, a formatter that removed a literal and a deliberate strip all produce identically",
    "the §16 fingerprint is about the whole tree: it can say no-match while every site is intact, because ordinary edits change the tree hash without touching a watermark"
  ],
```

## What no report will ever contain

The root secret, any key derived from it, any expected tag, and any raw location
id. Those are the artifacts that would turn a forwarded document into a copy of
the watermark, and §29's leak sweep runs over the report path as well as over
source and logs.

What a report does contain is source text — yours, and the candidate's — plus
paths, line numbers, families, widths and bit counts. That is enough to go and
look, which is the point, and it is the reason these documents live under
`.swp/private/`.

And no report states a probability that anyone did anything, or who wrote a
line, or what rights attach to it. Those four sentences are in every document
this tool writes, under `limitations`, because a report that gets forwarded is a
report whose caveats would otherwise be the first thing to go missing.
