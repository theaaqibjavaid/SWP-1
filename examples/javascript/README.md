# JavaScript example — a whole-cent invoicing module

Three files, no dependencies, no build step: `src/money.js` holds integer-cent
arithmetic, `src/tax.js` a rate table, `src/invoice.js` the two together. The
watermark goes into numeric and string literals, which is why a project that
computes anything is a good candidate for it.

This page is a transcript, not a description. Every line was printed by `swp`
while writing it, and `cargo test -p swp-test-suite --test docs_examples`
re-runs the sequence against the current build and fails if any of it has gone
stale.

**How to read a block here.** A `console` block is verbatim tool output. Where a
line carries a value this project's secret influences — an id, a digest, a
timestamp, a byte total — the volatile part stands as `…`, because inventing a
plausible one would be worse than leaving it out. Everything without a `…` is a
number the test re-checks: what it takes to protect *this* tree, and what a scan
of a copy of it says.

## The first run

```console
$ swp init
swp1-… — protected at …
  name       javascript
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  3 source file(s) a scanner can use, 3721 byte(s) read — javascript 3
  3 file(s) the walk refused or excluded, so they are not in that count

What was configured in .swp/config.toml
  [protect] targets      src
  [protect] target_sites 4
  [protect] tag_bits       4
  [protect] embed_strings true
exit 0
```

`init` wrote a store and a secret. It modified no source file, and the transcript
says so in as many words.

Four sites is `init`'s measured suggestion for a three-file tree, which is a
starting point rather than a limit: a constellation that fits inside one file is
one `rm` away from nothing, so the suggestion aims at spread. `--sites 12` asks
for more, and this tree is small enough to show what happens when it cannot
deliver.

```console
$ swp generate
plan mode: no source file was modified, and no release record or manifest exists for this run
  sites       4/4 embedded, 27 refused

This release is not protected yet: 4 site(s) exist only in a plan. Nothing here is verifiable until `swp protect --release rel-…` writes them.
exit 0
```

`generate` runs the whole pipeline — walk, harvest, select, prove each rewrite in
memory — and saves the result as a private plan. It is what to run before
`protect` when you want to see what would change.

```console
$ swp protect --sites 12
3 source files modified in place
warning: 21 candidate location(s) were refused for safety; the release carries 10 sites
protected swp1-… — release rel-…
  sites       10/12 embedded, 21 refused
  tag         4 bits per site
  fingerprint … (L1)
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint

What was modified (3 file(s))
  src/invoice.js — 3 site(s), 1214 → … bytes
  src/money.js — 5 site(s), 1497 → … bytes
  src/tax.js — 2 site(s), 1010 → … bytes
exit 0
```

Ten of twelve, not twelve, and the gap is the safety rule doing its work: a
literal whose radius already belongs to another site is skipped, never forced.
What is worth noticing is that the number is reproducible. How many sites a tree
can hold is a property of the tree, so asking the same twelve of these same three
files returns ten under every secret and every run — which is the only reason a
document is allowed to write the figure down. The per-file split (3, 5, 2) is
stable for the same reason; which literal inside each file takes a site is not,
because that is what the keyed priority decides.

```console
$ swp verify
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  fingerprint match (release published …)
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent

Every site of this release is present with its code. That is the whole claim; it says nothing about the tree being otherwise unchanged.
exit 0
```

## Scanning a copy

The copy is `src/` alone — no `.swp/`, so the candidate carries no key, no
manifest and nothing to trust. This is the evidence shape when somebody forwards
you a folder of source:

```console
$ swp scan ./copy
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

Project swp1-… · release rel-…
  Watermark fragments: 10/10
  Address without its code: 0
  Exact renderings: 10
  Present as canonicalized content only: …
  Keyed bits confirmed: 40 at 4 bits per site
  Fingerprint (10): match
  Evidence: VERY_STRONG
exit 1
```

`result PROVENANCE_DETECTED` and the exit code are one statement: `scan` exits
`1` when it found evidence, `0` when a *fully examined* candidate holds none, and
`10` when part of the candidate was never examined. A script that reads `0` as
"clean" without reading `partial` will call an unread tree cleared.

The report also prints, alongside that finding, how much of it chance could
explain: how many of the spans it probed reached a 4-bit tag comparison, and how
many of those an unrelated tree holding the same addresses would be expected to
confirm by accident. Both figures move from run to run, because which literals
carry a site is keyed, so they are not quoted here — and neither is a probability
that anybody copied anything.
[`../../docs/USER-GUIDE.md`](../../docs/USER-GUIDE.md#reading-a-report) sets out
what each number in a report may and may not be used for.

```console
$ swp scan ../plain
result    NO_PROVENANCE_DETECTED
evidence  NONE
exit 0
```

`../plain` is an unprotected copy of [`../python`](../python) — real source, never
touched by this project. The scan examined two files and reproduced no fragment
of this release. No claim is made about the tree beyond that, and the report says
so itself, in a section called "What this report does not say".

## What a site looks like in the source

Two renderings taken from a protected copy of these files, before and after:

```js
const sign = units < (8 - 8) ? "-" : "";
for (let i = (10 - 10); i < amounts.length; i += 1) {
```

```js
throw new Error(("units must be" + " an integer count of cents"));
```

The value is unchanged and the parse is the same shape; the pair of operands is
where the site's 4-bit code sits. `8 - 8` and `10 - 10` are two spellings of the
same number, and which one appears is decided by the keyed fragment at that
address. A string site reads the same way to a user: one literal, rendered as
two with a `+`.

Nothing in the file names the protocol and no comment marks the site, but
`swp inspect fragments --release …` lists every one of them:

```console
$ swp inspect fragments --release rel-…
fragments rel-… — 10 site(s), 4 bit(s) each, 21 candidate(s) refused

  site  file:line                  family     class    bits  what is written there now
  0     src/invoice.js:…          …          …          4  …
exit 0
```

which is why this tool does not describe its watermark as hidden. It is
unobtrusive, not secret. What is secret is the root key, and that is the only
thing standing between a public copy of this project and anybody else computing
the same codes — see [`../../docs/SECURITY.md`](../../docs/SECURITY.md).

## Running it yourself

```bash
cd examples/javascript
swp init
swp generate
swp protect --sites 12
swp verify
```

That writes a `.swp/` **inside this example directory**, including a real root
secret. Do it in a copy, or delete `.swp/` afterwards; neither is part of the
example, and `git status` should never show `.swp/private/`.

## Reading the rest

- [`../../docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md) — the same sequence, step by step
- [`../../docs/CLI.md`](../../docs/CLI.md) — every option used above
- [`../../docs/USER-GUIDE.md`](../../docs/USER-GUIDE.md#reading-a-report) — what each report line means
- [`../../docs/DEVELOPER-GUIDE.md`](../../docs/DEVELOPER-GUIDE.md#adding-a-language-adapter) — what a language gets from its parser
