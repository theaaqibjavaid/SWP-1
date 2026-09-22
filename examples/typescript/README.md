# TypeScript example — a temperature and alarm module

Two files with no runtime dependency: `src/temperature.ts` converts and compares
temperatures, `src/alarm.ts` keeps a bounded queue of alarms. TypeScript is the
case that shows what a parser buys: the grammar distinguishes a type annotation
from a value, and SWP-1 only ever rewrites the value.

Transcript conventions are the same as
[`../javascript`](../javascript): verbatim lines, `…` standing for whatever the
project secret influences, and `cargo test -p swp-test-suite --test docs_examples`
re-running every block against the current build.

```console
$ swp init
  2 source file(s) a scanner can use, 2830 byte(s) read — typescript 2
  3 file(s) the walk refused or excluded, so they are not in that count

What was configured in .swp/config.toml
  [protect] targets      src
  [protect] target_sites 4
  [protect] tag_bits       4
  [protect] embed_strings true
exit 0
```

```console
$ swp protect --sites 12
2 source files modified in place
warning: 13 candidate location(s) were refused for safety; the release carries 8 sites
  sites       8/12 embedded, 13 refused
  scope       2 file(s) analyzed, 2 file(s) hashed into the fingerprint

What was modified (2 file(s))
  src/alarm.ts — 3 site(s), 1265 → … bytes
  src/temperature.ts — 5 site(s), 1565 → … bytes
exit 0
```

Eight of twelve. A two-file tree has less room to spread a constellation than a
three-file one, and the refusals are the same rule as everywhere: no site is
forced into a radius another site already occupies.

```console
$ swp verify
  manifest    authenticated · 8 site(s) at 4 bit(s) each
  verdict     INTACT — 8/8 site(s) still carry their code, 32 keyed bit(s)
  channels    8 exact rendering(s), 0 address-without-code, 0 absent
exit 0
```

The copy is `src/` alone — no `.swp/`, so the candidate carries no key, no
manifest and nothing to trust:

```console
$ swp scan ./copy
result    PROVENANCE_DETECTED
evidence  VERY_STRONG
  Watermark fragments: 8/8
  Exact renderings: 8
  Keyed bits confirmed: 32 at 4 bits per site
  Fingerprint (8): match
exit 1
```

## What the thirteen refusals were

```console
$ swp protect --sites 12
What was refused, and why (skipped, never forced)
  overlapping-radius       13
exit 0
```

Every one of them is a radius overlap, not an unsafe place: these two files hold
thirteen more literals that would have carried a watermark, and each sat inside
the edit-distance shadow of a site already chosen. The view that names them one
per line is `swp inspect plan`, whose whole output is the intended constellation
plus every refusal:

```console
$ swp inspect plan --release rel-…
plan rel-… — what this run intended, written before any of it happened
  targets     src
  asked       12 site(s), ceiling 12 · 8 planned · 13 refused · 4 bit(s)
  strings     enabled

What was refused, and why (skipped, never forced)
  overlapping-radius     src/temperature.ts           line …
exit 0
```

That listing is the difference between "there was nowhere safe to put it" and "we
did not look", which is the question an operator is entitled to ask when a run
comes back short. The positions the safety rules refuse outright — type
annotations, object keys, module specifiers, JSX attributes, docstrings, `match`
patterns — never appear as `overlapping-radius`, and none of them is what held
this tree to eight sites.

TypeScript reaches them through the same table JavaScript does: `.ts`, `.mts`,
`.cts` and `.tsx` all parse, `.js`, `.mjs`, `.cjs` and `.jsx` likewise, and
Python covers `.py` and `.pyi`. The dialect is shared with JavaScript as well,
including the exactness bound at 2^53 − 1 — a TypeScript number is an IEEE-754
double at runtime, so an arithmetic site must stay inside the range where adding
zero still means zero.

## Running it

```bash
cd examples/typescript
swp init
swp protect --sites 12
swp verify
mkdir -p copy/src && cp src/* copy/src/
swp scan ./copy
```

Run it in a copy of this directory: `swp init` writes a real root secret into
`.swp/private/root.key`.
