# Threat model

Ten attacks, each with what it is, what it buys, what in this build stands in its
way, and — the column that makes the other three worth reading — what still gets
through. §50 asks for exactly those four headings; §51 forbids rounding the last
one off.

Two things before the first attack.

**The measured numbers in here came from one run.** Every table was printed by
`cargo test -p swp-test-suite` against a synthetic 12-module tree protected to 24
sites, on 2026-09-22, in a debug build, under a root secret minted for that run.
The *counts of confirmed sites* and the *verdict* columns are the shape of the
result and are what the surrounding text claims. The `probes` and `chance`
columns move with the key, because which literal spellings exist in a candidate
depends on which form families the key chose. Nothing in this page is a promise
about your tree: [VALIDATION.md](VALIDATION.md) is where a run's full tables live,
and §4 of it says how to reproduce them.

**The scale is 24 sites, not your repository.** A 4,000-file monorepo protected to
200 sites has more redundancy per file and a different survival curve. Where a
row below says "removal takes this to zero", it means that on a 24-site release,
and the mechanism — not the integer — is what generalizes.

| attack | one-line summary | measured by |
| --- | --- | --- |
| [1. Casual copying](#1-casual-copying) | found, almost always | `tests/detection/matrix.rs` |
| [2. Normal refactoring](#2-normal-refactoring) | found, mostly intact | `tests/detection/matrix.rs` |
| [3. Intentional watermark removal](#3-intentional-watermark-removal) | **beatable**, at a cost that is itself visible | `tests/adversarial/attacks.rs`, `tests/detection/matrix.rs` |
| [4. Watermark discovery](#4-watermark-discovery) | **fully discoverable** from source alone | `tests/adversarial/attacks.rs::a_shape_search_finds_the_sites_…` |
| [5. Manifest theft](#5-manifest-theft) | a removal tool, not a forgery tool | `tests/adversarial/attacks.rs::the_previous_version_…` |
| [6. Secret theft](#6-secret-theft) | total compromise, bounded by the OS account | `tests/leak/secret_scan.rs`, `crates/swp-crypto/src/seal.rs` |
| [7. False-positive attacks](#7-false-positive-attacks) | rare, cheap to avoid, not zero | `tests/false_positive/corpora.rs`, `tests/collision/identities.rs` |
| [8. Source poisoning](#8-source-poisoning) | your release can be made to cover their code | `tests/adversarial/attacks.rs::lifted_functions_…` |
| [9. Malicious repositories](#9-malicious-repositories) | denied time, never a lying answer | `tests/resource/hostile.rs` |
| [10. Parser exploitation](#10-parser-exploitation) | memory-safety risk in a C grammar remains | `tests/resource/hostile.rs` |

---

## 1. Casual copying

**Threat.** Somebody takes your published source — a fork, a vendor directory, a
file pasted into their project — and ships it without changing anything about it.
No adversary model, no effort: the most common case by a wide margin.

**Impact if unmitigated.** Your code runs inside somebody else's product with no
record of where it came from, and no way to tell the difference between that and
an independent reimplementation when it matters.

**Mitigation.** This is the case the constellation is designed for. A release of
the 12-module tree put sites in 12 of 13 files, so a copy carries the whole mark,
and an unmodified copy reproduces both the keyed addresses and the exact
renderings:

```text
(unmodified copy)   24 of 24 confirmed   fingerprint match   VERY_STRONG
```

The fingerprint is the other half of the easy case: an unedited copy hashes to
the release's own L1 canonical digest, so `EXACT_SOURCE_MATCH` is available
without decoding a single literal, and the report can say *this is that tree*
rather than *this resembles that tree*.

**Residual limitation.** Detection needs the copy to be *scanned by you*, with
your secret, and to have kept enough sites. Two ordinary situations defeat it:
a copy whose files your walk excludes — put it under `vendor/` and the default
excludes never read it, which the measured row for that case reports as
`0 of 24 confirmed, INCONCLUSIVE / NONE` with `partial: true` rather than as a
clean result; and a copy of a *small part*, which is attack 8.

## 2. Normal refactoring

**Threat.** A copier does the thing developers do anyway: renames identifiers,
reformats, moves functions into new files, extracts a helper, deletes dead code,
regroups modules. Not an attack on the watermark — an attempt to make the code
look like their own project's style.

**Impact if unmitigated.** Provenance evidence that survives only byte-identical
copies is worth very little, because nobody copies byte-identically.

**Mitigation.** Site identity is computed from the code *around* the literal at
four radii — statement and scope, each with local names abstracted and each with
them kept — and never from a path. §25 measures thirteen real refactoring forms
against a 24-site release; thirteen of thirteen still produced a finding:

| form | confirmed of 24 | verdict |
| --- | --- | --- |
| formatting, comment removal | 24 | VERY_STRONG (fingerprint still matches) |
| function / class rename, file movement, function extraction and inlining, import changes, code reordering | 24 | VERY_STRONG |
| expression rewrite | 24 | VERY_STRONG |
| variable rename | 22 | VERY_STRONG |
| constant rewrite | 19 | VERY_STRONG |
| dead-code removal | 5 | STRONG |

Bundling every module into one `dist/`-style file, which is what a build does to
your source, keeps all 24 (with every site reported as *moved*, because the file
it lives in changed and the keyed address did not care).

**Residual limitation.** Two forms cost real sites. Dead-code removal took 19 of
24, because a site inside a statement nobody calls is a site nobody copies; and a
variable rename that changes a statement's canonical text moves the *address* for
the rename-tolerant keys, which is why that row is 22 and not 24. Anything that
re-derives constants — `MAX = 200` becoming a computed expression — is a stronger
attack than a refactoring, and belongs to §3.

## 3. Intentional watermark removal

**Threat.** An adversary who knows a watermark is present, knows it lives in
literals, and is willing to break their own build discipline to get rid of it.
§26's rule binds here: this tool does not claim the watermark is impossible to
remove, and this row is the reason.

**Impact if unmitigated.** The copy is clean, and — worse than silence — a
`NO_PROVENANCE_DETECTED` report would be an affirmative "not yours" about code
that is.

**Mitigation.** Removal is expensive, and every measured variant costs something
specific. §26's four attacks, on the same 24-site release, with an attacker who
knows which literals are marked:

| attack | what they do | confirmed of 24 | verdict |
| --- | --- | --- | --- |
| `artifact_removal` | rewrite every marked literal back to a plain value | 0 | NONE |
| `site_rewrite` | change the marked sites only, leave the rest | 11 | MODERATE |
| `constant_normalization` | normalize *every* numeric literal in the tree to one style | 18 | VERY_STRONG |
| `module_rebuild` | rebuild each module from an understanding of what it does | 2 | WEAK, `INCONCLUSIVE` |

And two from the attacker's side, without the manifest at all (§52):

```text
every located span folded        0 of 24 confirmed   NO_PROVENANCE_DETECTED / NONE
every changed file reverted      0 of 24 confirmed   NO_PROVENANCE_DETECTED / NONE
```

What a report still says after a successful removal is the part usually left out
of this discussion: the fold row above recorded **154 probes** — 154 candidate
spans that reproduced a keyed address of the release and were offered a tag
comparison. Those appear in a scan as `Address without its code`, and the evidence
ladder refuses to grade them (a `STRUCTURAL_MATCH` never raises a level), but it
does print them. A tree that reproduces 154 of your addresses and confirms none
of their codes is a tree that was edited around your watermark. That is visible;
it is just not, by itself, proof of who did it.

**Residual limitation, stated plainly.** A determined remover wins. Folding every
mark, or restoring the pre-`protect` version of the changed files, takes a 24-site
release to zero confirmations. What the attack cannot buy is a clean tree that
also looks untouched: reverting files is a diff, and normalizing constants means
rewriting code that had nothing to do with the watermark. §11's rule cuts both
ways — the tool never forces a mark into a location that cannot hold it, so an
owner who wants higher resilience adds files and literals, not fragility.

## 4. Watermark discovery

**Threat.** Finding which literals are marked, without the manifest and without
the key — either to remove them (attack 3) or to learn the protocol's shape well
enough to write a generator.

**Impact if unmitigated.** The marks are not merely removable but *publicly
removable*: anyone with the source can find every site in minutes.

**Mitigation.** There is no mitigation, and the design does not pretend there is
one. The watermark is unobtrusive, not secret: `(2 - 2)`, `(98 + 2)`,
`("uni" + "ts …")` are valid spellings that a formatter would not produce and a
reviewer might not notice, and they are all that stands between a reader and the
site list. §52.1 tested the claim by doing it — a search for the four rendering
shapes, with no manifest, no key and no knowledge of which literal had been
chosen, located **24 spans in 12 files**, and folding those located spans took the
finding to zero. That test exists so that this row cannot be written any other
way.

**Residual limitation.** Total, by construction. What secrecy protects instead is
the *key*, and that asymmetry is the whole protocol: knowing which literals carry
codes tells an attacker nothing about what the codes are, and a scanner cannot be
fooled by a code you did not derive. The honest consequence for a project owner is
that `swp inspect fragments` — which prints every site and both of its spellings,
and warns you in the same breath — is a removal tool in a shareable format. Do not
paste it anywhere.

## 5. Manifest theft

**Threat.** The private half of the store is exfiltrated:
`.swp/private/manifests/*.json`, the plans, or a saved report.

**Impact if unmitigated.** If a manifest held the expected tags, stealing one file
would be stealing the watermark: the thief could compute every site's code, forge
new marks, and strip every existing one.

**Mitigation.** No manifest, plan, report or release record stores a tag. Each
site's expected code is recomputed from the root secret at comparison time and
dropped, so the stolen document holds *where* and *what spelling*, not the
derivation. The plans add nothing worse: a plan lists the intended constellation
and every refused location. What an attacker with a manifest gets, precisely:

* every site's four keyed addresses and its file, line and both literals — the
  complete removal map, which is attack 3's `artifact_removal` row handed to them
  pre-computed;
* the set of candidate locations that were *not* used, which is information about
  your code's shape and nothing about its codes;
* nothing that lets them sign a release record, or compute a tag for a location
  the manifest does not already name.

The one subtle exposure is that the *public* release record carries a digest of
the private manifest, so anyone holding both a candidate tree and a guess at the
manifest can test the guess in one hash. The code says so in its own comment:
the manifest's confidentiality comes from `.swp/private/` being ACLed, gitignored
and backed up, not from anything keyed inside it.

**Residual limitation.** A leaked manifest plus access to the copy is a complete
removal, measured at 0 of 24. A leaked manifest is *not* a framing tool on the
evidence this build has: fragments from one project planted as bare literals into
an unrelated tree confirmed **0 of 24** under both owners' keys, because the
renderings are not a constellation and the surrounding code was not there. The
attack that does work is in row 8, and it needs your source rather than your
manifest.

## 6. Secret theft

**Threat.** `root.key` — sealed or not — falls into other hands, or the process
that holds it does.

**Impact if unmitigated.** This is the total-compromise case, and the only one:
with the root secret an adversary derives every key, computes the code at any
location in your project, forges release records signed as your project, and can
no longer be contradicted by your own artifacts.

**Mitigation.** Three layers, each covering a different theft:

* at rest, DPAPI user scope plus an ACL that was tightened and then read back —
  another account on the machine, or the same account on another machine, gets an
  unopenable file, and a hardening that could not be *confirmed* stops the store
  from keeping the artifact at all;
* in transit, nothing: the tool has no network path, and there is no upload to
  lose a key through;
* in every other hand, the key's absence — the §29 sweep, which installs a known
  key and then reads back every byte every command printed and wrote, looking for
  the key and for a raw MAC derived from it.

**Residual limitation.** Anything running as you can read the secret; DPAPI does
not change that, and no document should. A backup copied to a shared drive, a
key committed from a working tree whose `.gitignore` was edited, a machine with
`SWP_SECRET_PLAIN=1` set and an unencrypted disk — those are your controls, not
the protocol's. And there is no rotation: the secret is the root of every id you
have ever published, so recovery from a *suspected* theft is a new project, and
the old copies stay explainable only by the key you believe is burned. Read the
key handle `swp init` printed into your incident notes; it identifies which key a
store holds without identifying the key.

## 7. False-positive attacks

**Threat.** Two versions of the same worry. Innocently: an unrelated tree happens
to reproduce your addresses and codes, and you accuse a stranger. Maliciously:
somebody constructs a tree specifically to make your scanner confirm sites it
should not.

**Impact if unmitigated.** A provenance tool that fires on innocent input is
worse than one that never fires — it trains its users to ignore it, and in a
dispute the false positive is the example the other side leads with. §51 lists
"zero false positives" among the claims this build must not make.

**Mitigation.** The measurement comes before the argument, and the honest headline
is that single coincidences **do** happen:

* 30 scans of six unrelated corpora (algorithms, framework code, boilerplate,
  generated stubs, standard-library samples, an OSS module) against five
  independent identities each: **0 of 30 confirmed a single site**, across 946
  tag comparisons.
* 30 scans where every project's keys judge every other project's tree — six
  projects, same generator, deliberately similar code: **20 of 30 confirmed at
  least one site; the largest count was 3; none reached a finding.** Every row
  off the diagonal ended `NO_PROVENANCE_DETECTED` or `INCONCLUSIVE`.
* six siblings from one template with different keys, i.e. the shape most likely
  to fool an address-based matcher: 0 of 6 confirmed anything, on 123–142 probes
  each.

What converts a coincidence into a verdict is the ladder, and it is deliberately
unfriendly: a finding needs the level to reach `MODERATE` **and** the confirmation
count to clear the coincidence bound — the union bound over the comparisons the
scan actually performed, `probes × 2^-width`, printed next to the number that used
it. Two probabilities are computed every run and both go in the report: the
assumption-free `loose` bound, and `chance`, which treats spans sharing a keyed
address as one draw. The corpora run's 946 probes imply 59.1 and 21.2
respectively. A verdict resting on the gap between those two is a verdict resting
on an assumption, so neither figure is tuned and both are shown.

**Residual limitation.** Three things, and the third is the one that matters.
`INCONCLUSIVE` is the answer a scan gives when chance could explain the count, and
`INCONCLUSIVE` is not exoneration: a tree that carries your code and only two of
your sites reads as a lead, not a finding. A single 4-bit site is 1-in-16 by
chance, which is why one fragment is never a finding and why the width is a
documented config key rather than a constant. And a deliberate framer *can* buy a
finding — see row 8 — by carrying enough of your real code to reproduce addresses
and codes together. What the ladder guarantees is narrower and still worth
stating: no tree is accused by a number this build cannot show its work for.

## 8. Source poisoning

**Threat.** Somebody gets code into your tree that you then protect — a
contribution, a vendored drop, a copy-paste from a snippet site — so that your
release's watermark covers material they wrote, or so that your marks end up in a
tree you did not publish.

**Impact if unmitigated.** A release record that says "this constellation is
mine" over sites whose authorship is contested, and a provenance claim that is
technically true about the release and misleading about the code.

**Mitigation.** The protocol's claim is deliberately smaller than authorship: a
scan confirms that a tree carries *the sites of a particular release of a
particular project*. It says nothing about who wrote them, and the report's
`limitations` block says that in words, in every report, so the caveat travels
with the document instead of living in this page. The controls that do exist are
procedural and they are yours:

* `swp protect --dry-run` and `swp generate` print the constellation and every
  refusal *before* a byte is written, and `swp inspect plan` keeps that list as a
  private artifact you can review after the fact;
* `[protect] targets` and the exclude globs in `.swp/config.toml` decide what is
  even eligible — vendored code you do not want to mark is one pattern away from
  never being considered;
* the site budget is a ceiling, not a quota: 12 requested sites produced 10
  embedded and 21 refused on the JavaScript example, because a location that
  cannot hold a mark safely is skipped rather than forced (§11).

**Residual limitation.** A marked statement in your release is your release's
statement; SWP-1 cannot tell you which of your files were written by whom, and
`line_hint` in a manifest is a hint that goes stale by design. The inverse
poisoning — an outsider pasting your marks into their tree — is bounded only by
how much context they copy with them: one lifted function scored
`INCONCLUSIVE / WEAK`, three scored `MODERATE` and a finding, five `STRONG`. The
finding is not fabricated (that tree really does carry fragments of your release),
but *whose* tree it is stays beyond the tool's reach.

## 9. Malicious repositories

**Threat.** You scan a tree somebody else controls, as part of triaging a
plagiarism report or auditing an incoming dependency. The tree's owner wants your
scanner to hang, to fill your disk, to write outside the directory you pointed it
at, or to make your own report say something false about their tree.

**Impact if unmitigated.** Arbitrary file write through an archive, a scan that
runs their build hooks, or a scan that dies quietly and reports "no evidence" for
a tree it never finished reading.

**Mitigation.** §21's rule is enforced structurally rather than by convention:
**no process is spawned anywhere in `swp-detection`** — an archive is a source
carrier, and the only operations performed on one are "list" and "copy out a
regular file". Entry names are attacker content, so an entry is written only if
its name resolves to a plain relative path beneath the temporary root: no
absolute paths, no drive letters, no verbatim `\\?\` prefixes, no `..` at any
position; symlinks, hardlinks, devices, fifos and sockets are skipped rather than
extracted, and `tar`'s setuid and mode bits are not applied because the extracted
tree is read and then deleted. Archives inside archives are not opened
(`max_archive_depth` is 1), and each one found is named in the report as a part
that was not examined.

Then the bounds, four of them around containers alone, every one of them settable
downward and none settable past the hard ceiling — so the author of the scanned
repository cannot argue your limits away:

```text
built a 67108864-byte payload in 65318 bytes of zip (ratio 1027)
refused before expanding anything: exit 7, LIMIT_REACHED
  archive entry "src/bombed.js" expands 1029 times over its stored size,
  past max_archive_ratio (200)
```

And the rule that keeps the whole thing honest: hitting a bound is never a
negative answer. A 400-file tree under `max_files: 250` refuses the *scan* with
exit 7 rather than reading a prefix; a 24-directory-deep tree at `max_depth: 12`
reports `1 of 2 file(s) reached, INCONCLUSIVE / NONE`; a copy hiding under an
excluded directory reports `0 file(s) scanned, partial: true`, and the report
prints the sentence that says a scan cannot distinguish an unprotected copy from
an empty directory. `tests/resource/hostile.rs` asserts each of those, and asserts
too that the candidate tree was left byte-for-byte untouched.

The last structural control: `Store::discover` walks upward to find a project, and
the scanner never calls it on candidate input. A repository that ships its own
`.swp/` does not get to supply the keys, the limits or the identity that your
build judges it by.

**Residual limitation.** A hostile tree can still cost you time and memory up to
your own ceilings — 8 GiB of cumulative bytes and 200,000 files are generous
defaults, and "generous" is a policy choice you should revisit before pointing
`swp scan` at strangers. The right setting for a public-facing triage queue is a
lowered `[limits]` block, not the defaults: measure the tree, then decide. And a
refusal is still a refusal: an inconclusive scan of a hostile tree is the correct
answer, not a satisfying one.

## 10. Parser exploitation

**Threat.** The grammars are C. Hostile input reaching a parser is memory-safety
input reaching a parser, and `swp-adapters` is the only crate that links
tree-sitter — so the question is what an attacker can steer into it.

**Impact if unmitigated.** A crash at best; a compiled-in grammar bug reachable
from a scanned tree is a native code execution question, and it would be dishonest
to describe it as anything else.

**Mitigation.** The parse is the last thing untrusted bytes reach, and everything
before it is bounded: `max_file_bytes` before reading, `max_parse_bytes` before
handing a document to a grammar, `max_nodes_per_tree` and `max_depth` and
`max_parse_millis` around what the grammar may build, `max_files` and
`max_total_bytes` around the walk. A file that exceeds a parse bound is not
skipped silently: it is named, with the bound that stopped it, and the scan is
`INCONCLUSIVE`. Unbounded recursion in *our* code is designed out rather than
bounded by the grammar — canonicalization and the radius digests run on a flat
token stream, and the 4,000-nested-block case is a test whose point is that it
stops "before the stack is". Malformed input is answered, not crashed: eight
hostile files (unclosed construct, truncated, binary, empty, embedded NUL, CRLF
only, 200 KB of semicolons, one non-source) produce six named omissions and exit
10. Everything the parsers are asked to read is read as bytes and decoded with
`decode_utf8_strict`, which refuses rather than substitutes — the class of bug
where a decoder's replacement characters quietly change what a digest covers is
closed at the door. And the grammars are pinned in `Cargo.lock`, compiled in, and
never fetched at run time.

**Residual limitation.** Bounds are not memory safety. A defect inside
`tree-sitter-javascript`, `-typescript` or `-python` is a defect in third-party C
that this build cannot see, does not fuzz beyond its own hostile-input tests, and
would be reached by exactly the input §45's bounds are designed to make expensive.
If you scan trees from parties you have reason to distrust, run the scan where a
compromise buys nothing: an account with no access to any `root.key`, a read-only
mount of the candidate, no secrets in the environment. That is an operational
recommendation and not a property of this build — no part of SWP-1 sandboxes
itself, and the `test-hooks`-free, single-binary, no-network shape is meant to
make the sandbox cheap to build, not to substitute for one.

---

## What none of these rows buys

Ten attacks is a list of ways to *lose*; the last section of this page is the
shorter list of things an attacker never gains from any of them.

Without your root secret, and after every attack above:

* they cannot compute a code for a location your manifest does not already name,
  so they cannot make a *new* statement confirm;
* they cannot sign a release record or a manifest that `swp verify` accepts —
  one flipped character in a committed record is an `INVALID_MANIFEST` and exit 5;
* they cannot make your scanner accuse a tree of carrying your release without
  carrying, in that tree, code from your release;
* they cannot read your project's identity out of a public copy, only the id you
  published;
* and they cannot make an inconclusive scan look like a clean one, which is the
  failure mode a tool like this is most easily talked into.

[SECURITY.md](SECURITY.md) states the seven things this build must never claim;
this page is the evidence for why each of those seven sentences is there.

---

Related: [`SECURITY.md`](SECURITY.md) · [`VALIDATION.md`](VALIDATION.md) ·
[`SWP-1-SPEC.md`](SWP-1-SPEC.md) · [`REPORTS.md`](REPORTS.md) ·
[`LANGUAGE-ADAPTERS.md`](LANGUAGE-ADAPTERS.md)
