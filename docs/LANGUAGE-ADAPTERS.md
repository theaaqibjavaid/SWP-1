# Language adapter development guide

What it takes to teach SWP-1 a language, and what an adapter may never do.

The promise this page has to keep is that *universal* means one protocol with a
per-language seam, not one tool that already knows every language. The seam is
real — nothing in `swp-core`, `swp-embedding`,
`swp-detection`, `swp-evidence`, `swp-manifest` or `swp-identity` branches on a
language name — and §12 below lists, honestly, the enumerations you still have to
touch.

Read [`SWP-1-SPEC.md`](SWP-1-SPEC.md) first for what a site, a family, a radius
key and an evidence level are. Read
[`INTEGRATION.md`](INTEGRATION.md#1-the-five-things-you-are-integrating-with)
for where the adapter layer sits.

---

## 1. The seam

An adapter is `crates/swp-adapters` and nothing else. It is the only crate that
links a parser, and the only place a language has a name.

```text
crates/swp-adapters/src/
  adapter.rs     the trait, Edit, Proof, the Registry
  analyze.rs     Analysis, CandidateSite, Capabilities, AnalysisBuilder
  ts.rs          the Grammar table, and the AST analyze pass every parsed
                 language shares
  dialect.rs     per-language facts about numbers and strings
  literal.rs     literal parsing, RefusalKind, render/decode dispatch
  forms.rs       the seven fragment families, their gates, their renderers
  safety.rs      which positions a rewrite may not touch
  js.rs py.rs    the Grammar tables + identifier-binding rules
  generic.rs     the lexical fallback
```

Everything above the seam consumes three types: [`Analysis`],
[`swp_core::canon::Token`] and [`swp_core::site::FormFamily`]. None of them
inspects a spelling, and none of them can tell a JavaScript site from a Python
one except by reading a string field. That is what a new adapter has to satisfy:
produce those three things honestly, and the rest of the system already works.

```console
$ swp verify --format json
  "sites": [
    {
      "language": "javascript",
      "adapter": "ast",
```

`language` is `LanguageAdapter::name()`; `adapter` is `AdapterKind` rendered as
`ast` or `token`. Both are recorded in every manifest site, which is why
`name()` must never be renamed after a release exists: it is part of what a
release stores, and a renamed adapter cannot re-parse its own old manifests.

---

## 2. Required interface

Nine operations make up the adapter contract — identify, parse, canonicalize,
analyze, find
candidate locations, embed, extract features, detect, validate. They are on
`trait LanguageAdapter: Send + Sync` (`adapter.rs`), grouped where the data
falls out rather than one method per noun: `analyze` *is* parse + token stream +
candidate locations, because a language cannot find safe literal sites without
having parsed the file, and splitting those into three calls would let a caller
pair the results of two different parses.

| method | yours to write? | contract |
| --- | --- | --- |
| `name() -> &'static str` | **required** | recorded in every site of every release. Stable forever |
| `capabilities() -> Capabilities` | **required** | what you promise: kind, `scopes`, `literal_values`, `reparse`, max evidence |
| `extensions() -> &'static [&'static str]` | **required** | lowercase, no dot. This is what makes a file source to SWP-1 |
| `analyze(&self, source, &Limits) -> Result<Analysis, SwpError>` | **required** | the whole front end; see §3 and §6 |
| `dialect() -> &'static Dialect` | **required** | the literal facts in §5; every gate reads it |
| `identifies(&self, path) -> bool` | default | extension match against `extensions()`. Override only for a name-based rule (a `Makefile`, a shebang) |
| `canonicalize(&self, tokens, level, hide_site) -> CanonicalText` | default, **deliberately not yours to change** | delegates to `swp_core::canon::canonicalize` |
| `render(&self, analysis, site, family, code, width) -> Result<String, SwpError>` | default | `CandidateSite::render` under your `Dialect` |
| `extract(&self, text, family, width) -> Option<DecodedSite>` | default | `literal::decode` under your `Dialect` |
| `validate(&self, before, after, &[Edit]) -> Result<Proof, SwpError>` | default | the re-parse proof in §5 |

Five methods to write. The defaults are not convenience: they are the reason an
adapter cannot drift. An adapter that supplied its own `canonicalize` would make
its location ids incomparable with every other language's, and the four radius
keys — the whole refactor-resistance story — would silently become per-dialect.
Override `render`/`extract` only to *narrow* what the shared family engine offers
for your language, never to add a spelling the shared decoder would not accept
back; a rendering your `extract` cannot decode is a watermark that exists in the
manifest and nowhere in the world.

`Capabilities` (`analyze.rs`) is a promise, and the report degrades to it:

```rust
pub const AST: Capabilities = Capabilities {
    kind: AdapterKind::Ast, scopes: true, literal_values: true,
    reparse: true, evidence: EvidenceStrength::Ast,
};
pub const LEXICAL: Capabilities = Capabilities {
    kind: AdapterKind::Lexical, scopes: false, literal_values: true,
    reparse: false, evidence: EvidenceStrength::Token,
};
```

Say `scopes: false` if you cannot tell a local name from a free one and L2 will
canonicalize exactly as L1 does; say `reparse: false` if you cannot re-parse your
own output, and `validate` stops being a proof. Claiming more than you can
deliver does not make a project look better protected — it makes a report print a
level the evidence does not reach, which is the one claim an adapter must never
make.

---

## 3. Parser expectations

A parsed language is a `Grammar` table (`ts.rs`) plus a tree-sitter
`Language`. The AST pass is shared. `AstAdapter` is one struct
(`adapter.rs`) holding a name and a `fn() -> &'static Grammar`; its four
trait methods read the table, and `analyze` is `ts::analyze(self.table(), source,
limits)`.

| field | what it decides |
| --- | --- |
| `name`, `dialect`, `extensions`, `language` | identity, literal facts, file types, the grammar handle |
| `skipped: &[&str]` | node kinds that emit **no token**: comments, doc strings, directives. A comment that reaches the stream is a location key that changes when somebody edits a comment |
| `keywords: &[&str]` | emitted as `TokKind::Keyword`, so they survive an L2 rename as themselves |
| `is_statement(kind) -> bool` | which node is the innermost statement radius. This is the tightest of the four keys, so getting it wrong is the difference between a site that survives a function rename and one that dies on a re-indent |
| `is_scope(&str) -> bool` | the enclosing function/class/module radius |
| `is_atomic(&str) -> bool` | nodes emitted whole rather than descended into: literals, templates, regexes |
| `is_definition(kind, field) -> bool` | which nodes *bind* a name — what makes a declaration a declaration in your language |
| `role_of(&IdentQuery) -> IdentRole` | classification of every identifier: `Local`, `Free`, `MemberName`, `PropertyKey`, `Label` |
| `scan_bindings(node, source, &mut Names, depth)` | the locally bound name set, collected with a depth budget |
| `synonyms: &[(&str, &str)]` | operator spellings that canonicalize to one class at L3 (`!=` and `!==` are one thing; `+` on a string is not `+` on a number) |
| `line_breaks: bool` | whether a newline carries grammar. Python yes, the ECMAScripts no |

Three expectations the shared pass enforces on you:

* **A parse error is data, not a panic.** `Analysis::parse_errors` counts what
  the grammar could not parse, and the pass reports it rather than stopping: a
  file with errors can still hold literals, and selection is allowed to use them.
  What the count is *for* comes later — `validate` compares the watermarked file's
  count against the original's and refuses the run if it got worse (§5).
  tree-sitter returns a lossy tree for broken input, so this must be measured
  rather than assumed away.
* **`Limits` are not suggestions.** `max_sites_per_file` and the traversal bounds
  arrive in `analyze`; `AnalysisBuilder::push_site` returns `false` when the file
  is full, marks `Analysis::truncated`, and records a `resource-limit` refusal.
  A scanner that keeps going past a limit is a scanner that reads an
  attacker-controlled file for as long as the file likes.
* **The token stream is the contract, the tree is private.** Nothing above this
  layer sees a node kind. If your language's radii cannot be expressed as byte
  spans over a token stream, the abstraction is wrong and the fix belongs in this
  crate, not in a new field on the manifest.

---

## 4. Canonicalization requirements

You do not implement canonicalization. You feed it. `swp_core::canon` turns a
`&[Token]` into text at one of three levels, and the three are the protocol's
definition of what "the same code" means:

* **L1** — formatting-insensitive: whitespace collapsed, comments gone, spellings
  kept. This is the release fingerprint's level
  ([§9 Fingerprints](SWP-1-SPEC.md#9-fingerprints)).
* **L2** — L1 plus locally bound identifiers renamed `#l0`, `#l1`, … by first
  occurrence. Free names, member names and property keys are preserved, because
  renaming those changes what the program talks to.
* **L3** — L2 plus literal *values* normalized (`<n:128000>`) and declared
  operator synonyms applied. The refactor-tolerant level.

`TokKind` is the alphabet you must map onto: `Ident`, `Keyword`, `Number`,
`String`, `Template`, `Regex`, `Operator`, `Punct`, `LineBreak`, `Comment`. A
language with a construct that has no home in those ten is the one case where the
list would have to grow, and that is a protocol change with a version bump —
raise it before building it.

The requirement that catches every new adapter at least once:
`canonicalize(tokens, level, hide_site)` takes **one site to hide**. Every token
whose span starts inside that site is replaced by a single `<SITE>` placeholder,
and the four location ids are digests of the result. This is load-bearing rather
than tidy: an id computed over text that *includes* the literal would change the
moment the literal is rewritten, and a site that cannot be found at its own
address after embedding is a site that was never embeddable. Emit your tokens so
that hiding the site leaves the surrounding statement and scope intact, and do
not let `skipped` include anything a radius boundary depends on.

---

## 5. Safe embedding rules

`swp-embedding` asks you to render a code at a family (`render`), splices the
result, and then asks `validate` whether that was safe. The rules your adapter is
responsible for:

**Gate on the dialect, both directions.** `Dialect`
(`dialect.rs`) is six facts: `max_exact_integer`,
`integer_division_truncates`, `adjacent_strings`, `hex_escapes`, `quote_chars`,
`digit_separator`. The four numeric families are bounded by
`max_exact_integer` (JavaScript stops at 2^53 − 1 because a number there is a
double; Python's bound is `i128::MAX`); `str-adjacent` exists only where
`adjacent_strings` is true; `str-escape` is offered only where `hex_escapes` is.
`available_number_families` (`forms.rs`) and
`available_string_families` (`forms.rs`) apply those gates — do not
re-implement them, and never widen one "just for this site".

**Refuse positions, not just spellings.** A literal that is perfectly rewritable
in isolation sits somewhere a rewrite changes what the program means.
`safety.rs::why_unsafe` has six, and each is keyed on node kinds and field names
rather than on language identity — one table serves JavaScript, TypeScript and
Python, and a kind only one grammar produces simply never appears in another's
walk:

| refused position | why a rewrite is not safe there |
| --- | --- |
| a JSX attribute | the grammar accepts a quoted string or a braced expression, not a parenthesized one |
| an object or dict key (`field == "key"` in a `pair`) | a name written as a literal, not a value |
| a module specifier | `import … from`, dynamic `import()`, and the loaders a grammar spells as identifiers (`require`, `__import__`) — it names a module for the loader and for build tooling |
| a type position | `type_annotation`, `*_type`, `*_qualifier`: a literal type is syntax, an expression is not |
| a match/case pattern | the literal is a test, and a parenthesized expression would be a capture |
| a statement that is one string | a docstring or directive, which has meaning beyond its value |

The one name-based rule in the table is the loader spelled as an ordinary
identifier, because it has no shape to key on. Each rule costs at least one
candidate site, and every one is reported by name so the price of safety is
visible in `swp inspect plan`.

**A string must survive being rewritten at all.** `is_rewrite_safe`
(`forms.rs`) is the guard: no backslash, no newline, no quote character that
the chosen quoting cannot reproduce. Otherwise `ContainsEscape`,
`MultilineOrTemplate`, `StringPrefix` and `EmptyLiteral` each name a literal that
never becomes a candidate.

**`validate` fails closed.** The default implementation re-parses `after`, then
proves three things per site (`adapter.rs`): the surrounding code canonicalizes
identically before and after at **L1, L2 and L3** (`ALL_LEVELS = 3`); the new
spelling decodes back to the original value; and the code it carries is the one
requested. `Proof { sites_verified, levels_stable, parse_errors }` is checked with
`is_complete(sites, before_errors)`, and any check that *cannot be performed* is
an error rather than a skipped site. That is deliberate: a transformation that
cannot pass this proof is not a bug to be found later, it is a silent behavior
change, which is the one thing a watermark must never do.

`RefusalKind` (`literal.rs`) is the closed vocabulary all of the above reports
through — fourteen variants, from `not-a-literal` to `resource-limit` — and its
`as_str` strings are what a user reads in `swp inspect plan`. Add a variant only
for a reason a reader cannot already name; a refusal kind nobody can act on is
noise in the one table that is supposed to be actionable.

---

## 6. Feature extraction

`analyze` fills an `Analysis` through `AnalysisBuilder` (`analyze.rs`):
`push_token`, `set_file`, `push_statement`, `push_scope`, `push_site`,
`push_refusal`, `finish`. The result carries `language`, `capabilities`,
`tokens`, `sites`, `refusals`, `parse_errors`, `nodes`, `truncated`, the whole-file
span, and the statement/scope span lists `validate` searches.

A `CandidateSite` (`analyze.rs`) is `span`, the `token` index it came from, a
`SiteValue` (`Integer(i128)` or `Text(OwnedString)` — *after* interpretation, so
`0x10` is 16, `"a" "b"` is one string), the `statement` and `scope` radii as byte
spans, and a `path` breadcrumb for reports. `push_site` is the only one of these
that can say no, and it says no for one reason: the file's site budget is spent.
Offering a literal twice at the same address is legal at this layer — the collision
rules that keep a constellation unambiguous belong to selection, above you.

What your adapter controls is the geometry, and the geometry decides how much of a
project can be watermarked at all. Selection queues a file's candidates by how
far their own edit reaches — shortest footprint first, keyed priority breaking the
ties — because two candidates whose radii touch compete for one slot: a location id
digests the code *around* a site, so embedding inside another site's radius would
leave the first site's recorded id describing a statement that no longer exists,
and a scanner would report it removed when it was only moved by our own edit. A
statement radius that is too wide therefore costs you twice: the site loses
competitions it should have won, and every literal inside its radius is refused
after it. If your `is_statement` returns the enclosing function for a literal
inside an `if`, you have built a smaller constellation, not a safer one.

Do not pre-select for the key. `swp protect` derives a per-candidate priority
from the release under the site's own four location ids
(`candidates.rs`); an adapter that picks its own favorite literals produces a
release nobody can reproduce with `--release`, and reproducibility is what makes a
report checkable a year later.

---

## 7. Detection rules

Detection (`swp-detection`) re-analyzes candidate files through the same
`analyze`, then asks two questions of every span: does it carry one of this
site's four keyed addresses, and if so what does its text decode to under the
family the manifest recorded? Your `extract` answers the second question.

Three rules the scan depends on:

* **One family, strictly.** `observed_code` (in `swp-detection/src/find.rs`) decodes a
  candidate literal under *the* family the manifest names, with the same strict
  decoder that rendered it. Widening this to "try every family and report the
  best" would turn a 2^-width coincidence rate into a several-families-deep one,
  and the entire value of the tag channel is that its false-positive rate is a
  number a measurement produces rather than one a designer picks.
* **`None` is the ordinary answer.** `extract` returning `None` means "this is not
  a rendering of that family", not "mismatch". A `Some` whose code disagrees is
  the mismatch. An adapter that guesses returns false positives.
* **Evidence strength is capped by kind, not by confidence.**
  `AdapterKind::max_evidence()` (`analyze.rs`) caps a lexical analysis at
  `Token` (`MODERATE`), and `EvidenceStrength::is_provenance()` is
  `Ast | Exact` only. A report sorting these levels is sorting the coarse order
  the spec names; there are four levels and nothing interpolates between two.

---

## 8. Testing requirements

A language is supported when these pass, not when the parser compiles.

1. **Token stream and canon** — `crates/swp-adapters/tests/token_stream.rs` runs
   its corpus through every adapter: `every_adapter_produces_a_sound_token_stream`,
   `a_parsed_file_carries_no_grammar_errors`,
   `comments_and_their_contents_never_reach_the_stream`,
   `each_level_is_insensitive_to_what_it_claims_and_no_more`,
   `every_site_that_carries_a_width_renders_and_decodes_back`,
   `a_sites_radii_hold_the_site_and_agree_with_the_query_api`,
   `analyzing_the_same_file_twice_gives_the_same_answer`. Add files to the corpus
   (`PARSED` in `token_stream.rs`) covering your statement, scope and binding rules —
   including the cases where your language's answer differs from JavaScript's.
2. **Hostile input** — `tests/hostile_input.rs` runs the limit cases per adapter:
   deep nesting, huge files, truncation, invalid UTF-8, BOMs. Your parser must
   survive them within `Limits` and say which it refused.
3. **Round trip through the product** —
   `crates/swp-test-suite/tests/detection/roundtrip.rs` has a `PROJECTS` fixture
   per language and asserts `every_family_the_writer_emits_the_reader_finds` and
   `the_form_corpus_keeps_every_family_reachable`. Add a fixture project to
   `crates/swp-test-suite/src/fixtures.rs` and register it in
   `crates/swp-test-suite/src/project.rs`. This is the test that catches an
   adapter whose ids do not survive an actual write-then-scan.
4. **The fallback expectation** — `an_unsupported_language_lands_on_the_fallback_and_says_so`
   asserts the exact set `parsed_languages()` returns. It will fail when you add a
   language, which is the point: it is a statement of what this build supports,
   and it must be updated by somebody who means it.
5. **Documentation** — `crates/swp-test-suite/tests/docs/examples.rs` lists
   the example trees every `console` block in the manual is re-produced against.
   A new language with no example has a new claim with no evidence.

Then the acceptance run: protect a real project in your language, `swp verify`,
copy the tree, `swp scan` the copy, edit the copy's formatting and rename its
local variables, and `swp scan` again. The last two are where an adapter that
passed unit tests tells you what its radii really are.

---

## 9. Security requirements

* **Never execute what you parse.** No subprocess, no project script, no
  "just run the compiler to resolve macros", no network. If your language's
  literals are only knowable by evaluating something, the honest answer is that
  SWP-1 cannot protect this language safely, and `RefusalKind` has a variant for
  saying so.
* **Untrusted input is the normal case.** The scanner reads trees it does not
  trust. Bound traversal by `Limits`, do not recurse without a depth budget in
  `scan_bindings`, and treat `truncated` as an expected outcome rather than an
  error to retry around.
* **No secret may reach the adapter.** You get `&Limits`, a path and text. Never
  read `.swp/private/`, never take a key handle, and never write a file:
  `swp-core`'s leak tests sweep every artifact the product produces, including
  anything an adapter contributes to a manifest.
* **An adapter cannot forge another project.** Every confirmation is keyed with
  the *verifying* project's secret; a hostile adapter's worst outcome is weak or
  wrong evidence about its own language, never a way to claim somebody else's
  source. That is why "claims must match capabilities" is a correctness rule
  rather than a politeness one.
* **Do not fake unsupported support.** Refusing a tree with a clear
  `NO_SAFE_LOCATIONS` message is a correct outcome for an adapter. Returning an
  `Analysis` whose promises its `validate` cannot keep is not.

---

## 10. What the fallback adapter does and does not give you

`generic.rs` is a hand-written lexical scanner for "a caller named a language this
build has no grammar for". Its `Capabilities::LEXICAL` says `scopes: false`,
`reparse: false`, evidence capped at `Token` (`MODERATE`). Its `extensions()` is
**empty**, so `Registry::for_path` never picks it silently — a file becomes source
only when a real grammar covers it.

The important part is where it is *not* used: both walks — the one that writes and
the one that scans — admit a path only when `for_path` returns an adapter
(in `swp-embedding/src/walk.rs`, where `for_path` decides whether a path is source),
and name the omission otherwise. On a language
SWP-1 cannot re-parse, `validate` cannot prove the surrounding code unchanged, so
an unsupported project is **refused outright rather than covered with weaker
tools**, and the protocol's claim stays legible without a footnote about which
half of a tree was guessed at. So "generic" in this build is a clean no, not a
weak yes ([`INTEGRATION.md` §5](INTEGRATION.md#5-a-tree-with-no-adapter) quotes
the refusal). The graded machinery is real and reachable from a caller that names
a language; no product walk exercises it, and the ceiling holds whenever one does.

`Dialect::GENERIC` is the same story in miniature: every field takes the
least-committal value, except `hex_escapes`, which is deliberately `true` — the
fallback offers no string sites of its own, so that flag can only ever widen what
a scan *reads back*, and a scanner that refused to decode an escape it was shown
would lose real evidence to a technicality.

---

## 11. The four steps, at a glance

1. **`Grammar` table** — a new `crates/swp-adapters/src/<lang>.rs` with a
   `pub(crate) static <LANG>: Grammar = Grammar { … }`, and the two functions
   nobody else can write for you: `role_of` and `scan_bindings`. JavaScript's and
   Python's are ~15-line tables in 200–340-line modules; the module is the
   language's binding rules, and that is the work.
2. **`Dialect` constant** — six facts, each one verifiable from your language's
   specification rather than from what the tool would find convenient.
3. **One registry line** — `AstAdapter::new("<lang>", || &<LANG>)` in the `vec![]`
   at `adapter.rs`. This is the only registration point in the system.
4. **Tests and fixtures** — §8, in that order. Expect the canon and round-trip
   tests to find real bugs in step 1; that is what they are for.

A language where literals cannot be classified without resolving types (a macro
system, an evaluation-time metaprogram, an implicit conversion that changes what
`+` means) does not need a bigger adapter. It needs
[the refusal in §9](#9-security-requirements), or an adapter whose `analyze`
records exactly which literals it could classify and refuses the rest with a
reason a reader can act on.

---

## 12. What "without modifying the core protocol" costs

The claim is about the protocol and the engine, and it holds: no document schema
changes, no derivation changes, nothing upstream learns your language's name.
What you *do* touch, beyond the adapter module and the one registry line, is a
handful of enumerations that record what this build supports:

| place | why it is a list rather than logic |
| --- | --- |
| `token_stream.rs:516` | asserts `parsed_languages()` exactly. A support claim, checked |
| `roundtrip.rs:66` and `:475` | one fixture per language; a per-language `Dialect` array |
| `swp-test-suite/src/project.rs:72` | name → fixture builder |
| `docs/examples.rs:42` and `:66` | the example trees the manual's transcripts are re-produced against |
| `README.md`, `GETTING-STARTED.md`, `INTEGRATION.md` | prose that tells a reader which languages work today |
| the refusal message in `swp protect` | it names the languages this build parses, because "add an adapter" is only useful with the current set next to it |

Each of them fails loudly when a language lands and quietly never otherwise,
which is the reason they are lists in tests and prose rather than derived from the
registry: a support statement that cannot go stale cannot be checked.

---

## Contents

* [The seam](#1-the-seam)
* [Required interface](#2-required-interface)
* [Parser expectations](#3-parser-expectations)
* [Canonicalization requirements](#4-canonicalization-requirements)
* [Safe embedding rules](#5-safe-embedding-rules)
* [Feature extraction](#6-feature-extraction)
* [Detection rules](#7-detection-rules)
* [Testing requirements](#8-testing-requirements)
* [Security requirements](#9-security-requirements)
* [The fallback adapter](#10-what-the-fallback-adapter-does-and-does-not-give-you)
* [The four steps](#11-the-four-steps-at-a-glance)
* [What the promise costs](#12-what-without-modifying-the-core-protocol-costs)

---

Related: [`SWP-1-SPEC.md`](SWP-1-SPEC.md) ·
[`INTEGRATION.md`](INTEGRATION.md) · [`DEVELOPER-GUIDE.md`](DEVELOPER-GUIDE.md) ·
[`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](THREAT-MODEL.md)
