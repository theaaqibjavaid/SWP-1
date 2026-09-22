# FAQ

Questions this project answers over and over, in the order people ask them. The
longer answers are on other pages and this one says so rather than repeating
them: [GETTING-STARTED.md](GETTING-STARTED.md) for the first run,
[USER-GUIDE.md](USER-GUIDE.md) for the seven commands,
[CLI.md](CLI.md) for every flag and exit code,
[REPORTS.md](REPORTS.md) for the report fields,
[SECURITY.md](SECURITY.md) for the threat surface,
[THREAT-MODEL.md](THREAT-MODEL.md) for what an attacker actually achieves, and
[VALIDATION.md](VALIDATION.md) for the numbers.

Every transcript below was printed by this build, and a test re-runs each one.
Where a number is decided by the project's own key it appears as `…`; the last
question under
[Reading the output](#reading-the-output) says which those are.

## What it is

**What is SWP-1, in one paragraph?**
A tool that takes a snapshot of a source tree, hides a small keyed code in a
handful of its literals, and publishes enough about that release — the site
addresses, the widths, a whole-tree fingerprint, an Ed25519 signature — that a
later scan of *any* tree can say how much of this release it reproduces and how
sure that reading is. It is a provenance instrument: it produces an artifact you
can hand to somebody, with the arithmetic next to it.

**Is this DRM? Can it stop someone from copying my code?**
No, and no. Nothing here withholds, licenses, expires or unlocks anything; a
protected file runs exactly as an unprotected one does. A mark is only ever
placed where it changes no meaning, and the whole product is therefore a
measurement, not a control. The question a copy can be asked is "does this
carry your code", not "can this still run".

**Then what is it for?**
For the cases where a copy is discovered and the question is whether the two
trees are related: a departing engineer's new project, a vendored directory that
should not exist, a fork that claims to be clean-room, a leak that has to be
triaged before legal gets involved. It is also for the case before any of that:
`swp protect` on a release makes a copy *legible*, which changes what a
conversation about one is like.

**Can it prove I wrote this?**
Not by itself, and no `swp` output claims it. A confirmation says "this tree
reproduces literals whose values come from a secret that project holds". For
that to mean authorship you additionally need that the secret was never
disclosed, that the release was made before the other copy existed, and that the
signing key belongs to the party you think it belongs to. All three are things
you keep and argue, not things `swp` checks. The tool's output is one exhibit,
not a verdict.

**Can it prove ownership in court?**
That is the same question with a jurisdiction attached, and the answer is still
no — this build has no legal-effect claims anywhere. It produces a reproducible
technical result with its method, its limits and its coincidence bound printed
on it, which is the most a tool can offer a non-tool process.

## What it costs an attacker

**Can I remove the watermark?**
Yes, and the measurement is on the record: on a 24-site release, an attacker who
locates the sites and deletes exactly those renderings ends at **0 of 24
confirmed, `NO_PROVENANCE_DETECTED / NONE`**. Anyone who tells you a watermark
is impossible to remove is selling something else, and no page here claims it.
[THREAT-MODEL.md](THREAT-MODEL.md#3-intentional-watermark-removal) has the four
removal attacks and what each one cost.

**So why use it, if removal is possible?**
Because removal and refactoring are different acts with different costs.
`tests/detection/matrix.rs` applied thirteen ordinary refactoring forms to that
same release: twelve of the
thirteen still produced a finding, eleven at `VERY_STRONG`. The one that hurt was
`dead_code_removal`, which took the count to 5 and still produced a finding.
Removing the watermark means knowing which literals carry it — and to know that
you must either have the manifest or run a shape search over the source, both of
which leave the second footprint [THREAT-MODEL.md](THREAT-MODEL.md) describes.
What the design buys is not "uncopyable" but "a copier must either leave the
mark or do visible surgery, and either way you get an artifact".

**What if they rewrite the code completely?**
Then there is nothing to find, and this tool does not claim otherwise. Detection
needs the literals and the code around them. A clean reimplementation of the same
behaviour is a different thing to argue about and a different thing to test. The
question "Is a `NONE` result 'my code is clean'?", at the end of
[Keys, loss and disclosure](#keys-loss-and-disclosure), puts the same bound in one
sentence.

**How many bits is the mark, and what does that mean for a false hit?**
Four per site by default, so one value in sixteen at each site the scan probes.
That is why a single confirmation is never a verdict: the report computes the
expected number of coincidental confirmations for *that* candidate's own probe
volume — `chance`, printed beside the count — and `guarantee` is the remainder.
Two or more confirmed sites, a level of at least `MODERATE`, and a positive
`guarantee` are all required before a scan says `PROVENANCE_DETECTED`. The
arithmetic is in [REPORTS.md](REPORTS.md#reading-the-levels).

**Can two projects collide?**
Measured in `tests/collision/identities.rs`: 48 addresses derived under one key
and 48 under another, over
identical source, shared **0**. 50 independently minted projects produced 50
distinct ids and 50 distinct verify-key sets, and across the 1,225 pairs the
longest shared id prefix was 2 characters. Project ids are 80 bits; the expected
number of colliding pairs in that whole experiment is about 10⁻²¹.

**Will it accuse an innocent project?**
Not on its own arithmetic, which is the only kind of promise worth making here.
`tests/false_positive/corpora.rs` ran 30 scans of six unrelated corpora against
five independent identities
each: **0 of the 30 confirmed a site**, 946 spans reached a tag comparison, and
the bound for that volume was 21.2 confirmations expected by chance (59.1 under
the loosest assumption). Cross-project scans over sibling trees generated from
one template confirmed 0 of 6. The honest caveat is on
[THREAT-MODEL.md](THREAT-MODEL.md#7-false-positive-attacks): when foreign trees
*do* share code idioms with a protected release, some do confirm one to three
sites — 20 of 30 in the cross-product experiment — and none of them cleared the
bound, so they are printed as leads with `INCONCLUSIVE / WEAK` and exit 10, not
as findings.

## Using it

**What is the difference between `verify` and `scan`?**
`verify` asks "is my own tree still what my release said" and reads *your* store,
including its private half. `scan` asks "does this tree carry any release I hold"
and reads only the candidate, never trusting anything inside it — including a
`.swp/` directory of the candidate's own, which it ignores completely. Their
verdicts are different words on purpose: `INTACT`/`INCOMPLETE` versus
`PROVENANCE_DETECTED`/`NO_PROVENANCE_DETECTED`/`INCONCLUSIVE`.

**Why did the command exit 1?**
For `scan`, `1` *is* the finding — it is the exit code you grep for in a CI job,
and `0` means a fully examined candidate held nothing. This is the one place
where a non-zero status is the success case, so read `result` in
`--format json` when a script needs to be sure. The whole table is in
[CLI.md](CLI.md#exit-codes).

**Why did it exit 10 instead of 0?**
Because part of the candidate was never examined, or a lead did not clear its
bound. A refusal is not a negative: `swp` is saying the question had no clean
answer, and the omission list names every file that was skipped and the limit
that stopped it.

**Does it change what my code does?**
No, and it is built to refuse rather than risk it. Every rewrite is re-parsed and
compared against the value it must preserve; a location that cannot hold a mark
safely is skipped, never forced. On the JavaScript example:

```console
$ swp protect --dry-run
dry run: this is what `swp protect` would do. Nothing was written — no plan, no manifest, no release record, no source change. The release id above is the one a real run would mint, not one that exists.
warning: 27 candidate location(s) were refused for safety; the release carries 4 sites
would protect swp1-… — release rel-…
  sites       4/4 embedded, 27 refused
  tag         4 bits per site
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint

What was modified
  src/invoice.js — 2 site(s), … bytes
  src/money.js — 1 site(s), … bytes
  src/tax.js — 1 site(s), … bytes
```

Growth is a few bytes per site, in the literal. The 27 refusals are the point of
the dry run: they are the candidates this build judged unsafe to mark, and the
reason each one was refused is one command away.

**How many sites should I protect?**
The built-in `target_sites` is 16, and `swp init` overwrites it with a number
measured against your tree instead — 4 for a project of up to three files, 12 for
4–15, rising to 48 as the tree grows. The example releases embed 10 and 8: what
their trees could carry once the refusals were taken out. More sites mean more
rungs available on the evidence ladder — `VERY_STRONG` needs eight confirmations
across three files — but they also mean more edited literals, and the skip rule
means a small or dense tree cannot always supply what you ask for. Ask for a
number, read the refusal counts, and keep the one where the refusals are all the
boring kind (`constellation-full`).

**Which languages work today?**
JavaScript, TypeScript and Python through tree-sitter grammars. Everything else
is refused rather than guessed at: there is a hand-written tokenizing adapter for
"a caller named a language this build has no grammar for", but it claims no file
extensions, so no `protect` or `scan` walk ever selects it — an unsupported tree
gets `NO_SAFE_LOCATIONS` and a clear reason. The honest per-language picture,
including what `pyproject.toml` is to this tool, is in
[LANGUAGE-ADAPTERS.md](LANGUAGE-ADAPTERS.md), which also settles what
`pyproject.toml` is to this tool.

**Can I point it at an archive instead of a directory?**
Yes — a file, a directory, a `.zip`, a `.tar`, a `.tar.gz` or a gzipped single
file, sniffed from the bytes rather than the extension. Containers are opened to
a bounded depth and never executed; an archive found *inside* one is reported as
a note, not extracted, because a scanner that chases nested containers is a
denial-of-service invitation. [SECURITY.md](SECURITY.md#a-candidate-tree-is-hostile-input)
has the five limits that bind a container scan.

**Do I have to commit anything?**
Nothing is required. `swp/public/` and `.swp/config.toml` are committable by
design — the release records are what a colleague or a pipeline verifies against
— and `swp inspect store` classifies every artifact in the tree as `yes` or
`never`. `.swp/private/` is the one directory that must not be committed, and
`swp init` adds it to `.gitignore` and tells you it did.

**Does it phone home? Can you see my code?**
There is no network code in this build to phone home with, and no telemetry, no
update check and no crash reporting. The claim is checkable rather than asked
for: two greps and a firewall test are printed in
[SECURITY.md](SECURITY.md#offline-and-how-to-check-that-claim), and the CLI's
transitive dependency graph contains no HTTP client and no socket library.

**Does it slow anything down?**
On this machine, in a debug build, `swp protect` cost 32 ms per file and `swp
scan` 29 to 33 ms per file over a 241-file, 0.35 MiB tree — and the scan is
deliberately re-run five times in that measurement, because a single figure from
one busy run is not a number worth documenting. The full ladder, from 13 files to
721, with the heap each tier holds, is in
[VALIDATION.md](VALIDATION.md#11-performance). Two rules matter more than the
constants: nothing in `scan` ever runs the candidate, and every loop is bounded
by a limit, so a scan that gets too slow is a scan that stops and says which
limit it stopped at.

## Keys, loss and disclosure

**What happens if I lose `.swp/private/root.key`?**
The releases made with it become unverifiable and un-re-protectable forever:
every site address is derived from that secret, so a new secret is a new
project. You can still keep the public records and the source, and you can
protect future releases under a new identity. Recovery from a *backup* is a
different case and is in [GETTING-STARTED.md](GETTING-STARTED.md). This is why
the dry run above prints a `Back this up` list.

**What happens if my `root.key` leaks?**
The holder can derive every site address and both renderings of every protected
literal, which is a complete removal tool: they can find each mark and take it
out. The adversarial suite measured the framing case too, and it is the reason
this page exists — planting those fragments into an unrelated tree with the
leaked manifest's own keys confirmed **0 of 24** sites, because a handful of
copied fragments is not a constellation and the bound says so. A leak is a
removal problem, not a forgery problem, and the mitigation is still
rotation-free by design: a *new project* for future releases.

**Is `swp inspect fragments` safe to run in the open?**
It is safe to *run* and unsafe to *publish*, and the command prints its own
warning to keep those two facts together:

```console
$ swp inspect fragments --release rel-…
warning: this view prints every site's literal as it was written and as it now stands. It is your own copy of the watermark: do not paste it into an issue, a build log or a document you mean to share.
fragments rel-… — 10 site(s), 4 bit(s) each, 21 candidate(s) refused
```

The view is local and needs the secret; what it prints is the pair of spellings
for each site. Without your key those pairs are inert. With them in a public
issue, they are the removal recipe.

**Can I rotate or revoke a key?**
No, and the reason is structural: the root secret is the root of every id you
have ever published, so "revoking" it erases your ability to connect your old
releases to your new ones. The leak sweep is what stands in place of
revocation, and [SECURITY.md](SECURITY.md#keeping-the-secret-out-the-leak-sweep)
states its own limit. If you believe a key is burned, start a new project
and keep the old records for the old copies.

**Is a `NONE` result "my code is clean"?**
No. `NO_PROVENANCE_DETECTED` means *these keys found nothing in this tree under
these limits*. It does not mean the tree is original, was not copied, or was not
copied from you — a copy that lost every site reads identically. Every report
prints the sentence that bounds its own result, which is why `swp report <name>`
is the document to share rather than a screenshot of a verdict line.

## Reading the output

**Why does `verify` say `INTACT` while the fingerprint says `no-match`?**
Because they measure different things and both are telling the truth. The whole-tree
fingerprint is a hash of the whole canonicalized tree: one edited file, one added
directory, and it changes. The sites are keyed locations, and they are intact
until their own code moves.

```console
$ swp verify --release rel-… --save
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  fingerprint no-match …
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent
```

That tree holds a second copy of `src/` under `copy/`, so the whole-tree hash
covers six files where the release published three — the fingerprint moves and
no watermark does. Where a site really has been relocated, `verify` says so in a
`survived` line under this one, naming how many were found in another file and
how many arrived only through the rename-tolerant keys; save the report when you
want that reading attached to the verdict rather than retyped from a screen.

**Why does a report call something `WEAK` when several sites matched?**
`WEAK` is one confirmed site. The ladder counts confirmations, not matches, and
the structural channel — an address reproduced with its code missing — is listed
as an item and never graded. That is deliberate: any tree that canonicalizes
alike can reach an address, so the weight sits on the code sitting at it.
[REPORTS.md](REPORTS.md#reading-the-levels) has the ladder and the two tests a
verdict must pass.

**What is `canonical_only`, and why can it be non-zero for an untouched copy?**
It counts sites reached through the value-normalized radii rather than the
literal ones — a channel statement about *how* a confirmation arrived, not a
weaker confirmation. Which sites arrive that way follows from the renderings the
key chose, so it is `0` in most runs of this suite and `1` in a couple, with the
fragments, bits and level unchanged either way. See
[REPORTS.md](REPORTS.md#the-release-tally).

**Why do my numbers differ from the ones in the documentation?**
Because part of every transcript is decided by *your project's* key: which
literal becomes site 0, whether it is a string or a number, which rendering form
it gets, the family mix, the byte growth per file, every id and digest and
timestamp, and the probe and chance columns. The convention this documentation
uses is `…` — U+2026 — in exactly those positions, and a test re-runs each
block and fails if a line that is *not* elided stops matching. So a page that
shows `10/10` really does show 10 of 10 for any key; where you see `…`, that is
the key speaking.

**Where should I start reading, if I want the whole picture?**
[GETTING-STARTED.md](GETTING-STARTED.md) for fifteen minutes to a protected tree,
[USER-GUIDE.md](USER-GUIDE.md) for the commands,
[SWP-1-SPEC.md](SWP-1-SPEC.md) for the protocol and the derivations,
[SECURITY.md](SECURITY.md) and [THREAT-MODEL.md](THREAT-MODEL.md) for the threat
surface, [VALIDATION.md](VALIDATION.md) for every measurement in this page with
its test file beside it.

---

Next: [DEVELOPER-GUIDE.md](DEVELOPER-GUIDE.md) if you are building or extending
this tool, [VALIDATION.md](VALIDATION.md) if you would rather see the numbers
than read the answers.
