# SWP-1 — the protocol

Version 1.0.0. This is the normative description of what SWP-1 writes into a
source tree, what it records about that writing, and what a scan may conclude from
either. Where a sentence here says "must", the implementation enforces it and a
test exists; where it says "does not", that is a boundary the design chose, and
[SECURITY.md](SECURITY.md#attacks-and-what-still-gets-through) states what it
costs.

## 1. Scope, and what a protocol is doing here

SWP-1 is a provenance protocol: a rule for embedding a keyed mark in a body of
source text, and a rule for deciding later whether a body of text carries that
mark. It has two halves that must never be conflated.

* **Protection** (a private operation): given a project's root secret and a tree,
  rewrite a small number of literals so that their spelling encodes bits derived
  from that secret, and record what was done in signed artifacts.
* **Detection** (a judgement about a foreign tree): given the same secret and a
  candidate, decide which recorded sites are present, and grade the result.

Both halves recompute the mark from the secret; neither stores it in the source.
That is what makes a fragment unforgeable to a third party and unremovable without
changing a literal's spelling — and also why detection **requires** the secret.
There is no mode in which SWP-1 scans for your watermark using only public
artifacts: the public release record proves that a manifest is yours, and the
manifest lists where the sites are, but only the key derives what each site must
carry. See [What must be trusted](#13-what-must-be-trusted).

## 2. Vocabulary

| term | meaning |
| --- | --- |
| **literal** | a number or string in source text. `LiteralClass` is `integer` or `string`; a float is never a site, because "same value" is not decidable for one across spellings |
| **fragment** | the bits a rewritten literal carries, `tag_bits` of them |
| **family** | the way a fragment is spelled — one of seven (see [Fragment families](#6-fragment-families)) |
| **site** | one literal carrying one fragment, addressed by its surroundings rather than by its own text |
| **radius key** | one of the four digests that address a site (see [Site identity](#4-site-identity-the-four-radius-keys)) |
| **constellation** | the set of sites one release embeds, and the spacing rule among them |
| **plan** | a private, unsigned record of what a run intended, including every refusal |
| **manifest** | the signed private record of what was embedded: every address, both literals, the family and width |
| **release record** | the signed public record: ids, counts, tag width, fingerprint, manifest digest |
| **candidate** | the tree being judged. Never executed |
| **omission** | part of a candidate that was not examined, and the reason |

## 3. Keys and identities

All keys derive from one 256-bit root secret with domain-separated HMAC-SHA-256.
Every derivation message is length-prefixed and injective, framed as
`SWP-1\0<domain>\0<protocol u16><nfields u32>` followed by each field's own length
and bytes, so no two different field sequences can encode to the same message.

| derived | domain | as |
| --- | --- | --- |
| project id | `identity` | `base32_lower(derive(root, "identity", ["project-id/v1"])[0..10])`, written `swp1-` + those 16 characters — 80 bits of id |
| site key (per project) | `project` | `derive(root, "project", [project_id, canonicalizer_be16])` |
| location id | — | `HMAC(site_key, [project_id, radius_code, canonicalizer_be16, radius_digest])`, first 16 bytes kept — 128 bits |
| tag key (per project) | `location` | `derive(root, "location", [project_id])` |
| tag (per site) | — | `truncate_bits(HMAC(tag_key, [project_id, primary_location_id, width_byte]), tag_bits)` |
| selection key (per release) | `selection` | `derive(root, "selection", [project_id, release_id, canonicalizer_be16])`, then `HMAC(that, [project_id, release_id, the four location ids concatenated])` gives each candidate its priority |
| signing key | `signing` | ed25519 with seed `derive(root, "signing", [project_id])`. Never stored: it is recomputed per run |
| verify key | — | the ed25519 public half, published in `identity.json` — the only key anybody outside the project ever holds |

The domain column is the `Domain` enum in `swp-crypto/src/derive.rs`; two of its
seven labels (`release`, `evidence`) are reserved and nothing derives under them,
spent now so a later protocol version cannot give an old label a new meaning.
`hmac_keyed` refuses a key whose recorded domain does not match the domain of the
derivation it is used in, so swapping two of these rows is an internal error
rather than a quiet wrong answer.

The tag hangs off the site's **primary** location id, which is why a site has one
primary and four addresses. Truncation reads the MAC's first four bytes as one
big-endian word and keeps its low `tag_bits` bits — for the default 4-bit width,
the low nibble of the fourth byte. Every width in use divides 2^32, so masking is
exact and there is no modulo bias to correct; to anybody without the tag key the
result is a random nibble.

Both halves of that sentence are pinned by test vectors — `pinned_derivation_vectors`,
`truncation_respects_width` and `wrong_domain_is_refused` in
`swp-crypto/src/derive.rs`, `pinned_site_identity_vector` in
`swp-manifest/src/keys.rs` — so a change to the encoding cannot pass unnoticed:
every existing release would stop matching its own manifest.

## 4. Site identity: the four radius keys

A site is never addressed by its own text — that text is what the watermark
rewrites, and including it would move the address of the thing it identifies.
Instead the address is a digest of the code *around* the literal, at two radii and
two levels of abstraction:

| key | radius | level | survives |
| --- | --- | --- | --- |
| `statement+identifiers` | innermost statement | L3 | renaming locals, respelling other literals, reformatting |
| `scope+identifiers` | enclosing function or module | L3 | the above, plus the statement moving inside its scope |
| `statement+names` | innermost statement | L1 | reformatting only |
| `scope+names` | enclosing function or module | L1 | reformatting only |

The abstracted pair uses L3 rather than L2 deliberately: L2 abstracts names but
keeps every other literal's spelling, so a copier who writes `1_000` where the
project wrote `1000` would break all four keys at once. No file path, line number
or language name enters a radius digest, which is what makes a site findable in a
file that was renamed, split or moved.

`statement+names` and `scope+names` are equal for a module-level statement in a
short file, and the manifest accepts that: the four *keys* still differ, because
the radius kind is mixed into each id. Two sites whose four keys are all equal are
refused as `indistinguishable-site`.

## 5. Canonicalization

Location ids and fingerprints are computed over a canonical token text, produced
from adapter-supplied tokens by rules identical across languages:

* comments are dropped;
* whitespace between tokens collapses to one space, and a line break survives as
  exactly one newline character, so re-indentation is invisible while splitting one
  line into two is not;
* at L2 and L3, identifiers the adapter reports as locally bound are renamed by
  first occurrence to `#lN`. Imports, globals, property keys and member names stay
  verbatim — renaming those merges genuinely different programs;
* at L3 only, literals are normalized by value (`<n:128000>`, `<s:…>`, `<t:…>`,
  `<r:…>`), and adapter-declared synonym classes replace keyword spellings.

**Deliberate losses.** L3 forgets which literal spelled a value, so two programs
that differ only in numeric spelling are the same text at L3; that is the price
paid for a key that survives respelling, which is why the name-preserving L1 pair
exists beside it. L1 forgets comments and layout, so a comment-only change is
invisible to the fingerprint — and therefore the fingerprint is a statement about
*code*, never about a file's full bytes. The canonicalizer version (1) is recorded
in every artifact: a rule change here changes every address, so it is a protocol
version bump, not a refactor.

## 6. Fragment families

Seven families, each a rewrite of one literal into an equivalent spelling whose
operands carry the site's bits. Per-family `max_bits` bounds the tag width a site
may use with it; a run's `tag_bits` must fit the family.

| family | class | shape | max bits | gate |
| --- | --- | --- | --- | --- |
| `add` | integer | `(v + c) - c` | 8 | `value > 2^w`, result within the dialect's exact-integer bound |
| `sub` | integer | `(v + a) - b` with `b - a = c` | 8 | `value + 2^w` within the exact bound |
| `mul` | integer | `(v * m) / m` | 6 | a divisor exists in every residue class mod `2^w`; search bounded at `8·m` |
| `radix` | integer | one hexadecimal literal | 4 | at least `w` hex digits; the low `w` bits are its last `w` letters, MSB-first |
| `str-concat` | string | `("L" + "R")` | 6 | `char_count > m`; split index `code % m + 1`, so no operand is empty |
| `str-adjacent` | string | `"L" "R"` | 5 | as above; only where the dialect allows adjacent string literals — **Python alone** |
| `str-escape` | string | leading `\xHH` escapes carry the count | 5 | dialect must allow hex escapes; the first `m` characters must be ≤ U+00FF |

An operand encoding a `w`-bit code is `code % 2^w + 1`, never zero: a zero operand
would be the un-watermarked spelling and would make the two states
indistinguishable. Rendering and decoding are strict inverses — a decoder accepts
only the canonical form the encoder emits, so a candidate cannot claim a tag by
being *near* the shape.

**Which** family a site ends up using is part of the keyed decision in [Selection](#7-selection) rather
than a property of the literal: the families a site supports are tried from a
start point derived from its own keyed priority, so a project's watermark spreads
across the seven instead of exhausting one at a time. A literal that could be
written either as a concatenation or with escapes therefore reports a different
`family` in two projects cut from the same tree, which is why the reports elide it
([Reading a report](USER-GUIDE.md#reading-a-report)).

**Dialect.** The bounds are per-language, not global: JavaScript and TypeScript
cap integers at 2^53 − 1 because a number there is an IEEE-754 double, while
Python's bound is the implementation's own integer width. A JavaScript release
therefore stops a numeric family at a value Python would accept, and the scanner
refuses to decode an adjacent-string site under a JavaScript release rather than
guess at what the parser meant.

## 7. Selection

Protection harvests every literal an adapter offers, then chooses a constellation:

1. each candidate is scored by a priority keyed under the **release**, so the
   order is reproducible for a given project and release but not predictable to
   somebody without the key;
2. a candidate is taken unless its radius overlaps one already taken, its four keys
   collide with an existing site, or its location id is already used;
3. a rewrite is applied in memory and the result **re-parsed**: unless the parse
   proves the surrounding code unchanged and the value identical, the location is
   refused. A location that cannot carry a fragment safely is skipped, never
   forced;
4. the run stops at `target_sites` or when the candidate pool is exhausted.

Refusals are recorded, not hidden, and carry a reason from a fixed list:
`overlapping-radius`, `indistinguishable-site`, `identity-already-taken`,
`constellation-full`, `limit-reached`. Parse and safety failures are never offered
as candidates at all — an f-string, a template literal, a string containing an
escape sequence this family cannot re-spell, an empty literal — so they do not
appear in the refusal table either, which is why `swp inspect plan`'s count and a
project's intuition about "why is this one not watermarked" can disagree.

## 8. Artifacts

Five documents, four schemas. `schema` is the numeric `1` inside the private and
public artifacts; a report's `schema` is the string `SWP-1-report-v2` because a
report is rendered for humans as well as machines and names its own shape. The
second version is the coincidence arithmetic: the tally records the distinct keyed
codes it billed as well as the windows it saw, and the probability the verdict
cleared (§12).

| path | document | signed |
| --- | --- | --- |
| `.swp/public/identity.json` | protocol, schema, project id, created, verification block (ed25519 public key), canonicalizer version, generator, display name | no |
| `.swp/public/releases/<id>.json` | ids, created, `source_revision`, `fingerprint` + `fingerprint_level`, `private_manifest_digest`, `watermark` (target sites, tag bits, sites embedded/skipped, canonicalizer version, form set, adapters), generator, signature | yes |
| `.swp/private/manifests/<id>.json` | per site: four location ids and which is primary, file, line hint, language, adapter, grammar, class, family, width, `original`, `rendered`; plus the tree fingerprint | yes |
| `.swp/private/plans/<id>.json` | intended sites and every refusal, with reason | **no** |
| `.swp/private/reports/<name>.json` | a saved `verify` or `scan` result, `SWP-1-report-v2` | no |

A signature is ed25519 over the document's **canonical JSON with the `signature`
field removed**: keys byte-sorted, no whitespace, no floats, integers as decimal
text, base64-encoded. Because the canonicalizer is the same one that computes
fingerprints, a signature survives reserialization and dies on any change of
content.

The plan is unsigned on purpose: it records an intention that was not published,
and signing it would imply a claim about a tree that may never have been written.
`identity.json` is unsigned because it is the key the other signatures are checked
with; self-signing it would move the trust problem rather than solve it, so the
file's authenticity is established by the channel you copied it through.

## 9. Fingerprints

`fingerprint(level, canonicalizer_version, [(path, digest)])` sorts the path-digest
pairs, length-prefixes them, refuses duplicate paths, and hashes. The shipped level
is **L1**, per file's canonical token text, merged across the tree the walk
examined — which is why adding an unrelated file to a protected directory changes
the fingerprint, and why a fingerprint match means an exact copy of the protected
scope rather than an inference from fragments.

Known asymmetry, stated rather than smoothed: the level grammar declares
`["L1", "L2", "L3"]` and a private manifest will accept any of them, a release
record's `validate` accepts only `L1` and `L2`, and detection compares **only** at
L1 — a record declaring L2 or L3 is reported as `not-comparable`, not as a
mismatch. No artifact this build writes is outside that intersection, but the
three lists are not identical, and a future implementation must not read the
declared grammar as a promise.

## 10. Protection procedure

`swp protect` is one transaction with a fixed order:

1. open the store, unseal the secret, check its permissions;
2. read the configuration, apply any `--target` / `--sites` / `--bits` override for
   this run, and validate the result;
3. walk `[protect] targets` under `[limits]`, dropping excluded paths and anything
   no adapter claims;
4. harvest candidates, select the constellation ([Selection](#7-selection)), prove every
   rewrite in memory;
5. write the plan, the manifest and the release record — **before** any source
   file is modified;
6. apply the rewrites, re-reading each file and confirming the rendered literal is
   at the byte offset the manifest recorded;
7. print the artifacts written, the files modified, the refusals, and the settings
   that were actually used.

The order is a safety property: an interruption between 5 and 6 leaves a tree
whose release exists and whose sites are partly absent, which `swp verify` reports
as `INCOMPLETE` — a true statement — rather than as a clean tree with no record,
which would be a lie.

## 11. Detection procedure

`swp scan <candidate>`:

1. load the project's releases (all of them, unless `--release`/`--latest` names
   one) and verify each manifest's signature against the identity's verify key;
2. group the releases by (project, canonicalizer version, tag width), because a
   shared index can only be built for a set of releases that read the same way;
3. walk the candidate — never executing it, ignoring its own `.swp/`, extracting
   archives into a private directory with traversal and symlink entries refused —
   recording every omission with a kind;
4. compute the candidate's L1 tree fingerprint and compare it to each release's
   first, since an exact copy is a different kind of fact than a scattered set of
   matching literals;
5. **pass A** over literals: for each token that could be a fragment, decode it
   under each family the release used and compare the recovered bits to the tag the
   key derives for the address the token sits at;
6. **pass B** over token windows: up to 20 000 windows per file, at most 6 tokens
   wide, which is where a fragment whose literal changed hands (or moved file) is
   still found;
7. grade each site: `exact-rendering` (the span is byte-for-byte the recorded
   rendering), `tag-confirmed` (decodes under the recorded family to the expected
   code), `location-only` (the address is present and the code is not — reported as
   `Address without its code`, and asserting nothing), or `absent`; plus the two
   qualifications `refactored` (found through a name-abstracted key only) and
   `moved` (found in a different file than the manifest named);
8. hand the tally to the ladder ([Evidence](#12-evidence)) and render the report.

Observations per site are capped at 64, with the recorded rendering force-kept, so
a pathological candidate cannot make one site expensive without bound.

## 12. Evidence

Seven kinds, each with a maximum strength it cannot exceed however many of it are
found:

| kind | asserts | max strength |
| --- | --- | --- |
| `EXACT_SOURCE_MATCH` | the candidate's canonicalized tree hashes to a release's fingerprint | `VERY_STRONG` |
| `WATERMARK_FRAGMENT_MATCH` | a site's address and its code are both present | `STRONG` when the rendering is exact, `MODERATE` via one abstracted key, `WEAK` otherwise |
| `PARTIAL_WATERMARK_MATCH` | a fraction of a release's sites are present | `STRONG`, in integer thirds of the ladder |
| `CANONICAL_MATCH` | a region matches a protected region after full L3 normalization, one token | `MODERATE` |
| `TOKEN_MATCH` | a lexical token stream matches | `MODERATE` |
| `STRUCTURAL_MATCH` | an address is present without its code | `WEAK`, and it asserts nothing on its own |
| `NEGATIVE_CONTROL` | a candidate was fully examined and matched nothing | none — it is the absence of a finding, recorded so it is not mistaken for a hole |

The ladder turns counts into a level: `MODERATE` at 2 fragments, `STRONG` at 4
fragments across ≥2 files (or 6 anywhere), `VERY_STRONG` at 8 across ≥3 files. A
fingerprint match short-circuits to `VERY_STRONG`.

Independently, the report measures how much of that count chance could have
produced anyway. Per site it bills the `d` **distinct keyed codes** the candidate
offered at that address — not the `n` windows that reached it, because three spans
that reproduce one address by carrying one repeated literal are one chance at this
project's tag, not three — and sums `1 − (1 − 2^−w)^d` over sites. That sum, `λ`, is
an upper bound on the expected number of accidental confirmations by linearity of
expectation, and it holds without any independence assumption. The looser,
assumption-free union bound `Σ n·2^−w` is printed beside it as the number that
holds without even the distinct-codes step; the gap between the two measures what
the repeated spans were paying for, and it is small — 1.8% of `λ` at 4 tag bits,
0.5% at 6, 0.1% at 8, measured on the look-alike trees §28's collision suite
builds. Counting distinct codes is required for the bound to be admissible, not
because it is large.

The verdict then asks the one question left that arithmetic can answer: how likely
is it that an unrelated tree with exactly these chances produces *at least* the
fragments this scan counted? Taking `λ` as a Poisson mean, a level above `WEAK`
needs that probability under **1e-3**, `STRONG` under **1e-5** and `VERY_STRONG`
under **1e-8**. The final level is `min(counts, probability cap)`, and
`PROVENANCE_DETECTED` requires the 1e-3 floor together with a level of at least
`MODERATE`, or an exact fingerprint match; a scan that clears neither says
`INCONCLUSIVE` rather than accusing anybody. The floors are measurements rather than
round numbers, and `λ` is conservative in a quantified way: on 2,790 unrelated
cross-scans its own mean came out **2.7–3.3× above** the observed mean
confirmation count at every tag width tried — the null count is Poisson-shaped, so
the model is the right one and only its mean is inflated, always in the direction
that withholds a verdict. `VALIDATION.md` carries the record, including what the
gate costs: on a 12-site constellation it accepts no finding below 10 confirmations
at 4 bits, 6 at 6 bits, or 4 at 8.

A report prints all three figures, because they answer different questions: how
much of what was found the count of fragments supports, how much of it chance could
have produced anyway, and how likely that chance was to reach the count this scan
observed. None of them is a probability that anybody copied anything, and the
`limitations` section of every report says so in the report's own voice.

## 13. What must be trusted

* The **root secret**. Whoever holds it can produce valid fragments and valid
  manifests for that project id. It is the whole security of the protocol.
* Your **store**: the scanner trusts your manifests because they are signed by a
  key you derived, and the signature proves consistency, not authorship of the
  source.
* A **candidate** is trusted for nothing. It is parsed, never executed; its
  artifacts are ignored; its paths are confined; its size, depth and expansion are
  bounded by `[limits]`.
* The **verifier of a report** — a lawyer, a reviewer, another team — must hold the
  report document, the project's public identity, and enough of the protocol to
  re-run the scan. A report is not self-authenticating to a third party, and no
  claim is made that it is.

## 14. Versioning

Four version tokens, deliberately separate: the protocol (`SWP-1`), the artifact
schema (numeric `1`), the canonicalizer version (`1`), and the build version
(`1.0.0`). An artifact whose protocol token this build does not implement is
refused with `PROTOCOL_VERSION_UNSUPPORTED` rather than read optimistically, and
one whose canonicalizer version differs is not comparable at all, because a digest
computed under a different rule is a different fact.

Compatible changes inside v1 may add: an adapter, a refusal reason, an omission
kind, a report field, a limit key. They may not: change canonicalization or the
derivation framing, reuse a family's encoding, or reinterpret an existing field.
Any of those is v2, and a v2 build must be able to read a v1 release record well
enough to say so.

The report's schema token moves on its own axis, because what has to stay stable
in a report is what its numbers *mean* rather than which fields carry them. Adding
a field is compatible inside a report schema; changing the rule that turns
evidence into a level, or a level into a verdict, is not, and gets a new token —
which is what `SWP-1-report-v2` records (§12). A build reads one report schema and
refuses the rest, so a saved document is never re-graded under arithmetic its
author did not apply. None of this touches the protocol token or the artifact
schemas: a tree protected under `SWP-1` verifies under `SWP-1`, whatever report the
scan that checked it wrote.

## 15. Errors

The error model is a fixed set of codes with a stable exit number and a `next:`
line that names the reader's next move: `UNSUPPORTED_LANGUAGE`, `INVALID_MANIFEST`,
`INVALID_WATERMARK`, `SECRET_UNAVAILABLE`, `MALFORMED_SOURCE`, `PARSER_FAILURE`,
`UNSAFE_EMBEDDING`, `PROTOCOL_VERSION_UNSUPPORTED`, `INSUFFICIENT_EVIDENCE`, and
the operational codes `USAGE`, `NOT_PROTECTED`, `LIMIT_REACHED`, `IO_ERROR`,
`NO_SAFE_LOCATIONS`, `PATH_REJECTED`, `INTERNAL_ERROR`, with `RELEASE_MISMATCH`
sharing `5` with `INVALID_MANIFEST` by intent. [CLI.md](CLI.md#exit-codes) is the
table; [TROUBLESHOOTING.md](TROUBLESHOOTING.md) is the prose.

## 16. What this protocol does not define

* **Structural region matching.** `STRUCTURAL_MATCH` means "address present, code
  absent", and the report line is labelled accordingly. Region shingling is not
  implemented, and `max_shingles_per_region` is a limit on a feature that does not
  exist yet — stated here rather than hidden.
* **L2/L3 fingerprints.** Declared in the level grammar, never written, never
  comparable ([Fingerprints](#9-fingerprints)).
* **Key sharing, delegation, or a registry.** One project, one secret, one store.
  There is no third party, no online service, and no way for one project to
  verify another's fragments.
* **Any legal or forensic conclusion.** [../README.md](../README.md) states this
  first, because it is the claim most likely to be inferred and the one this tool
  never earns by itself.
