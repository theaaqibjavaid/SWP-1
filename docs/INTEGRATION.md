# SWP-1 integration guide

How to put SWP-1 into a project, in the four trees this build supports and the one
it does not, and then how the pieces fit together well enough to add a fifth.

This page is about *using* SWP-1 in a repository. The protocol itself — the
schemas, the keyed derivations, the evidence ladder — is
[`SWP-1-SPEC.md`](SWP-1-SPEC.md); the commands and their codes are
[`CLI.md`](CLI.md); writing a new language adapter is
[`LANGUAGE-ADAPTERS.md`](LANGUAGE-ADAPTERS.md).

Every `console` block here is verbatim output from this build, with `…` standing
for what a project's own secret influences. The convention is described in
[`USER-GUIDE.md`](USER-GUIDE.md) and enforced by
`cargo test -p swp-test-suite --test docs_examples`.

---

## 1. The five things you are integrating with

They are separate on purpose, and the separation is a dependency direction rather
than a diagram: `swp-cli` → `{swp-embedding, swp-detection, swp-evidence,
swp-manifest, swp-identity, swp-adapters}` → `{swp-core, swp-crypto}`.

| layer | what it owns | where it lives | what it is allowed to know about a language |
| --- | --- | --- | --- |
| **Protocol** | the document formats and the rules they must obey: identity, release record, private manifest, plan, report; site ids; the keyed derivations; the evidence ladder and its ceiling | `docs/SWP-1-SPEC.md`, then `swp-core` types plus `swp-manifest` and `swp-identity` | nothing. A protocol document names classes (`integer`, `string`), families, levels and widths — never a language |
| **Core engine** | canonical text at L1/L2/L3, the four radius keys, byte-span and token types, limits, the error taxonomy | `swp-core` | nothing. Nothing in it branches on a language name |
| **Language adapter** | parsing, literal classification, the enclosing-statement and enclosing-scope radii, identifier binding rules, the dialect's arithmetic and string facts | `swp-adapters` | everything. It is the only crate that links tree-sitter, and the only place a language is named |
| **CLI** | argument parsing, the store a command opens, rendering, exit codes, report files | `swp-cli` | the name an adapter reports, and no more. It never parses source itself |
| **Project integration** | your `.swp/` directory, `.swp/config.toml`, what you commit, what you back up, when `verify` runs | *your repository* | your file types, and which of them this build has an adapter for |

Two consequences worth holding on to:

* **a project cannot be half-protected by a missing adapter.** `swp protect`
  refuses the whole run when nothing in scope has a parser, rather than writing a
  release over the files it happens to understand (§11: skipped, never forced).
* **adding a language does not change what a release means.** The manifest fields,
  the site ids and the evidence rules are the same for a Rust adapter as for a
  JavaScript one, because none of them is derived from a grammar. That is what
  makes an adapter an extension point instead of a fork.

### What lives where, after `swp init`

```text
.swp/
  config.toml              yours to edit: scope, target_sites, tag_bits, excludes
  private/root.key         the secret. Never committed, never sent, never logged
  private/manifests/       signed: every site, both literals, four location ids
  private/plans/           unsigned: what a run intended and everything it refused
  private/reports/         saved verify and scan results
  public/identity.json     the verify key and the protocol version
  public/releases/         signed: one record per release, safe to commit
```

The classification of each of those — and what "permissions verified" on the
`init` line is actually checking — is in [`SECURITY.md`](SECURITY.md).

---

## 2. A JavaScript project

`examples/javascript` is three files: an invoice line-total module, a money
module, and a tax module. That is the whole tree.

```console
$ swp init
  name       javascript
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  3 source file(s) a scanner can use, … byte(s) read — javascript 3
  3 file(s) the walk refused or excluded, so they are not in that count
exit 0
```

Three files are read as source; three more are refused or excluded — `package.json`
among them, because this build has no parser for JSON and the walk admits a file
only when a grammar covers it. Scope is a config decision, so a tree whose sources
live under `lib/` and `bin/` is pointed at them in `.swp/config.toml` rather than
by moving files:

```toml
[protect]
targets = ["src", "lib"]
excludes = ["**/*.test.js", "vendor"]
target_sites = 4
tag_bits = 4
embed_strings = true
```

`swp protect --dry-run` answers the only question worth asking before an edit: how
many sites the tree can hold, and what would change.

```console
$ swp protect --dry-run
warning: 27 candidate location(s) were refused for safety; the release carries 4 sites
would protect swp1-… — release rel-…
  sites       4/4 embedded, 27 refused
  tag         4 bits per site
  fingerprint … (L1)
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint
exit 0
```

The default target is four sites, which is what `swp init` suggested for a tree
this size. Asking for more is a flag, not an edit:

```console
$ swp protect --sites 12
3 source files modified in place
warning: 21 candidate location(s) were refused for safety; the release carries 10 sites
protected swp1-… — release rel-…
  sites       10/12 embedded, 21 refused
  tag         4 bits per site
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint

What was modified (3 file(s))
  src/invoice.js — 3 site(s), 1214 → … bytes
  src/money.js — 5 site(s), 1497 → … bytes
  src/tax.js — 2 site(s), 1010 → … bytes
exit 0
```

Ten of twelve, twenty-one refused. The refusals are not failures: `overlapping-
radius` means a literal sits inside the radius of a site already taken, and a
second watermark there would make the first one's location ambiguous. Read them
one per line with `swp inspect plan --release …`.

What a site looks like in the file:

```js
const cent = units + (0 - 0);
```

`(0 - 0)` is a spelling of `0` whose operands carry this site's 4-bit code under
this project's key. Same value, same parse shape, no comment naming the protocol.

```console
$ swp verify
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent
exit 0
```

And a copy of it, which is the question the tool exists to answer:

```console
$ swp scan ./copy
scope     3 file(s), … byte(s)
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

  Watermark fragments: 10/10
  Address without its code: 0
  Exact renderings: 10
  Keyed bits confirmed: 40 at 4 bits per site
exit 1
```

`exit 1` is a finding. `--format json` gives the same facts as one document for a
log or a dashboard; see [`REPORTS.md`](REPORTS.md).

---

## 3. A TypeScript project

`examples/typescript` is `src/alarm.ts` and `src/temperature.ts` with a
`tsconfig.json` beside them. The TypeScript adapter is a second grammar entry in
the same `js` module: a different tree-sitter language, the extensions `ts`,
`mts`, `cts` and `tsx`, and the same statement, scope, binding and synonym tables
as JavaScript — which is the honest way of saying that TypeScript's runtime is
JavaScript's, down to the 2^53 − 1 exact-integer bound its `Dialect` carries.

```console:typescript
$ swp init
  name       typescript
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  2 source file(s) a scanner can use, … byte(s) read — typescript 2
exit 0
```

```console:typescript
$ swp protect --sites 12
2 source files modified in place
warning: 13 candidate location(s) were refused for safety; the release carries 8 sites
protected swp1-… — release rel-…
  sites       8/12 embedded, 13 refused
  tag         4 bits per site
  scope       2 file(s) analyzed, 2 file(s) hashed into the fingerprint
exit 0
```

```console:typescript
$ swp verify
  manifest    authenticated · 8 site(s) at 4 bit(s) each
  verdict     INTACT — 8/8 site(s) still carry their code, 32 keyed bit(s)
  channels    8 exact rendering(s), 0 address-without-code, 0 absent
exit 0
```

Three things a TypeScript team asks about:

* **`.d.ts` files are source to the walk.** They carry literals, they parse, so
  they can hold sites. If your declaration files are generated, exclude them; a
  regenerated file changes the L1 fingerprint and reads as an edited tree.
* **a release records the language it wrote, and a scan reads each candidate file
  through whichever grammar its extension selects.** The four location keys are
  digests of the surrounding code, never of a path, so a protected `.ts` file that
  is renamed to `.tsx` keeps its sites — those extensions share one grammar. One
  renamed to `.py` does not: Python canonicalizes to different text, and the site
  reads as absent rather than as a match in a language that never had it.
* **`enum` members and `const` assertions are ordinary code to the parser.** The
  families offered are the same four numeric and three string ones. Nothing in
  the TypeScript adapter invents a spelling the JavaScript one would refuse.

---

## 4. A Python project

`examples/python` is `src/cart.py` and `src/money.py`. Python differs from the two
JavaScript grammars in three ways that reach the protocol, all of them recorded in
its `Dialect` rather than in a branch somewhere:

* **Integers are unbounded.** JavaScript's exact-integer ceiling is 2^53 − 1,
  because a number there is a double; the arithmetic families are gated against
  that. Python's bound is the implementation's own, so a site holding a large
  integer is available there and refused here.
* **Adjacent string literals concatenate.** `"a" "b"` is a spelling Python allows
  and JavaScript does not, so `str-adjacent` is offered for Python sites only,
  and a scanner decoding a candidate under a JavaScript release refuses that family
  rather than guessing at what the parser meant.
* **A newline is grammar.** Python's block structure is its indentation, so the
  canonicalizer keeps a `line_break` token for Python and drops it for the others;
  L1 for Python is a little less forgiving about re-flowing, which is the honest
  consequence of the language being sensitive to the same edit.

```console:python
$ swp protect --sites 12
2 source files modified in place
warning: 10 candidate location(s) were refused for safety; the release carries 8 sites
protected swp1-… — release rel-…
  sites       8/12 embedded, 10 refused
  tag         4 bits per site
  scope       2 file(s) analyzed, 2 file(s) hashed into the fingerprint
exit 0
```

```console:python
$ swp verify
  manifest    authenticated · 8 site(s) at 4 bit(s) each
  verdict     INTACT — 8/8 site(s) still carry their code, 32 keyed bit(s)
  channels    8 exact rendering(s), 0 address-without-code, 0 absent
exit 0
```

f-strings, byte strings and a literal containing a `\` the escape family cannot
re-spell are never offered as candidates at all, so they do not appear in the
refusal table either. That is why `swp inspect plan`'s count can be smaller than
the number of literals in a file.

---

## 5. A tree with no adapter

`examples/generic` is `src/frame.c`, `src/retry.sh` and `src/rollup.sql`. This
build has no parser for any of them, and the integration story is what happens
when you ask:

```console:generic
$ swp init
warning: no file under the default scope has a language adapter, so `swp protect` will refuse this tree. This build parses javascript, typescript, python; point [protect] targets at part of it that does, or add an adapter.
  name       generic
  secret     created · handle … · permissions verified
exit 0
```

```console:generic
$ swp protect --dry-run
error [NO_SAFE_LOCATIONS]: nothing to protect under "…": 3 paths refused (no language adapter for this file type). Check [protect] targets and excludes in .swp/config.toml
exit 15
```

`swp init` succeeded and `swp protect` wrote nothing. That asymmetry is the
design: the store, the identity and the key are the same for every project, so a
tree that has no adapter today has somewhere to put a release the day an adapter
lands. Nothing about the project changes when one arrives — no re-init, no new
identity, no migration.

Mixed trees are the common case and work as you would expect: a repository with
`src/*.py` and a `tools/*.sh` is protected in its Python half, with every shell
file named in the refusal list rather than silently skipped. `swp verify` then
describes only the sites the release holds, and says how many there were.

The generic *adapter* is a different thing from a generic *project*: the fallback
inside `swp-adapters` is a lexical scanner used when a manifest names a language
this build has no grammar for, and it caps a site's evidence at `MODERATE`
(`TOKEN` strength) rather than letting an approximate radius claim provenance.
[`LANGUAGE-ADAPTERS.md`](LANGUAGE-ADAPTERS.md#what-the-fallback-adapter-does-and-does-not-give-you)
has the ceiling and why it exists.

---

## 6. Adding a language

The short version, for judging the size of the job:

1. Write a `Grammar` table over a tree-sitter grammar you already have: the node
   kinds that are statements, scopes, definitions and atomic literals; the
   identifier-binding rules; the operator spellings that count as the same
   operator; whether a newline carries grammar.
2. Write a `Dialect`: the exact-integer ceiling, whether adjacent strings and hex
   escapes are legal spellings, the quote characters, the digit separator.
3. Add one line to the registry in `crates/swp-adapters/src/adapter.rs`.
4. Add a fixture project and the round-trip cases the existing adapters have.

Nothing in `swp-core`, `swp-embedding`, `swp-detection`, `swp-evidence`,
`swp-manifest` or `swp-identity` branches on a language name. What you do have to
update is a handful of *enumerations* — a test that asserts which languages this
build parses, the round-trip project list, the documentation example list — which
are lists of what exists rather than parts of the protocol, and each of them fails
loudly when a language is added instead of quietly ignoring it.
[`LANGUAGE-ADAPTERS.md`](LANGUAGE-ADAPTERS.md) is the long version, including what
each of those four steps has to prove before a watermark in your language is
trustworthy.

---

## 7. Running it in CI, and what to do when it disagrees with you

The two commands that belong in a pipeline are `verify` on your own tree and
`scan` on somebody else's, because both print their exit code as their last line
and neither needs a network.

```console
$ swp verify -p ../plain
error [NOT_PROTECTED]: there is no .swp directory in …
  next: Run `swp init` then `swp protect` in the project first.
exit 4
```

Three rules that keep CI readable:

* **Run `verify` against one release, not "the newest".** `--release <id>` pinned
  to the release your build produced; the newest is a moving target the moment
  somebody else protects the same tree.
* **Keep `.swp/private/` out of the runner.** A job that needs to verify a release
  needs the root secret, which means it needs a secret store, which means it needs
  the decision in [`SECURITY.md`](SECURITY.md) about who may hold it. `scan` needs
  the same secret for the same reason; `inspect release` on a public record needs
  only `identity.json`.
* **`swp report` renders a saved result, it does not re-run one.** A report
  artifact committed next to a release is a record of a check that already
  happened.

When the tool's answer is not the answer you expected — a site you can see is
reported absent, a file you did not touch reads as moved — start at
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md). Both of those have ordinary causes:
a formatter that rewrote a literal into an un-offered spelling, and a tree that
holds the same statement twice.

---

## Contents

* [The five things you are integrating with](#1-the-five-things-you-are-integrating-with)
* [A JavaScript project](#2-a-javascript-project)
* [A TypeScript project](#3-a-typescript-project)
* [A Python project](#4-a-python-project)
* [A tree with no adapter](#5-a-tree-with-no-adapter)
* [Adding a language](#6-adding-a-language)
* [Running it in CI](#7-running-it-in-ci-and-what-to-do-when-it-disagrees-with-you)

---

Related: [`GETTING-STARTED.md`](GETTING-STARTED.md) ·
[`USER-GUIDE.md`](USER-GUIDE.md) · [`CLI.md`](CLI.md) ·
[`SWP-1-SPEC.md`](SWP-1-SPEC.md) · [`LANGUAGE-ADAPTERS.md`](LANGUAGE-ADAPTERS.md)
