# Troubleshooting

Every failure `swp` can produce, what it asks of you, and — for the ones worth
seeing rather than reading about — the transcript that a run of this build
actually printed. The exit-code table lives on
[CLI.md](CLI.md#exit-codes); this page is the other half of it, organized by the
thing you just saw on your screen.

Three rules cover most of what goes wrong:

* **A message names a file.** Every error in this build that could be about a
  path prints it, absolute, as the tool resolved it. If a message does not name a
  file, it is about a flag, a setting, or a verdict.
* **Nothing is repaired by force.** A command that refuses has written nothing.
  `swp protect` is the only command that edits source, and it edits only after
  every rewrite in it has been re-parsed and proved. So a failed run costs
  you a re-typed command, never a tree.
* **`swp init` is not a fix for a missing store.** It creates a project, which
  means it creates a *new secret*. Run it on a project whose releases you still
  need and you have made those releases unverifiable, because their keys are
  derived from the secret you replaced. When `.swp/` exists and something in it
  is missing, restore the missing thing.

## "This project is not protected"

`NOT_PROTECTED` is one code for three different situations, and the messages are
deliberately not the same. Read which one you have before running anything.

**There is no `.swp/` here or above here.** The tool looked outward from the
directory you named and found nothing:

```console
$ swp verify -p ../plain
error [NOT_PROTECTED]: there is no .swp directory in …
  next: Run `swp init` then `swp protect` in the project first.
exit 4
```

That tree has never been protected, so `swp init` is exactly the right answer —
here. The usual causes are that you are standing in the wrong directory (`-p
<path>` names another one, and discovery walks *up* from where you are, so a
subdirectory of a protected project is fine) or that `.swp/` is in `.gitignore`,
which it is, and this checkout was cloned rather than protected. A clone has the
committed half of the store — `identity.json`, `releases/`, `config.toml` — and
none of the private half, which is the point: `swp verify` and `swp scan` need
the root secret, and a clone does not have it. `swp scan` from a clone therefore
reports `NOT_PROTECTED` no matter what the candidate holds.

**`.swp/` exists but has no `config.toml`.** A partial checkout, a stray
`git rm`, a backup restored over itself:

```console
$ swp inspect store -p .
error [NOT_PROTECTED]: there is a .swp/ directory at …, but it has no config.toml for this command to read, so it is not treated as a store. Restore that one file (settings only — `swp init` writes the defaults again); do not re-initialize a project whose releases you still need to verify.
  at: ….swp…config.toml
  next: Copy .swp/config.toml back from version control and the store opens again. `swp init` will also rewrite it, in a project that still has its private/ directory — which is the case this message is warning against confusing with the other one, where the whole store is gone.
exit 4
```

The fix is one committed file, and `swp init` would also write it — in a project
that has lost its store. Which of the two you have is visible in the message:
this one says *there is a `.swp/` directory*, the one above says *there is no
`.swp` directory*.

**The store opens and has no releases.** `swp init` ran and `swp protect` has
not, or `protect` refused:

```console:generic
$ swp verify
error [NOT_PROTECTED]: this project has no protected releases yet. Run `swp generate` to plan one, then `swp protect`
  next: Run `swp init` then `swp protect` in the project first.
exit 4
```

Nothing is wrong here. A project is not protected by being initialized;
[GETTING-STARTED.md](GETTING-STARTED.md) is the step that does it.

## "Cannot read the root secret"

`SECRET_UNAVAILABLE`, exit `3`, is the one failure that cannot be worked around
on the machine you are on, because the secret is what the keys are derived from:

```console
$ swp generate -p .
error [SECRET_UNAVAILABLE]: no root secret at ….swp…private…root.key. A protected project can only be re-protected or verified against its own releases using the secret that created it
  next: Watermark verification needs the root secret. … Recovery from backup is documented in docs/GETTING-STARTED.md.
exit 3
```

Work through these in order:

1. **Wrong account.** On Windows the file is additionally sealed per-user
   ([SECURITY.md](SECURITY.md)), so a `.swp/` copied between accounts, or a project on a shared
   drive opened from a different login, reads as missing. Run as the account that
   created it.
2. **Wrong directory.** `-p <path>` names a project. If the path is right, the
   message prints the absolute path it looked at — compare it with what the
   shell lists (`dir` on Windows, `ls -l` elsewhere) rather than with what you
   meant.
3. **The key and the identity came from different backups.** The store compares
   the project id derived from `root.key` with the one in
   `.swp/public/identity.json`, and stops with this code when they disagree —
   every fragment under the wrong key would derive wrongly, and a later scan
   would say "no evidence" about code that is plainly yours. Restore the two
   together.
4. **A private file could not be hardened.** On a write, the store restricts the
   key file to your own account and reads the restriction back; if that
   confirmation fails you get this code and the message says so — "refused to keep
   a private artifact whose access could not be confirmed". `icacls
   .swp\private\root.key` on Windows, or `ls -l` the same path elsewhere, shows
   what it grants; [SECURITY.md](SECURITY.md) says what the check does and does
   not protect.
5. **The file is gone.** Restore `.swp/private/root.key` and
   `.swp/private/manifests/` together, from the backup those two lines in every
   `swp init` and `swp protect` transcript told you to keep. A restored key
   without its manifests can verify nothing: the manifest lists the sites, and
   it is not recomputable from the source you have, because writing it down is
   what the secret was for.

If there is no backup, the releases are gone as far as this tool is concerned:
`swp protect` again under a fresh `swp init` gives you a new project that can be
protected from today forward. The old source still compiles — the watermark is a
rendering of an existing literal, and nothing depends on being able to read it.

## A run said it could not look at everything

`exit 10`, `INCONCLUSIVE`: the scan finished, and it is telling you the answer is
not an answer. This is what a `[limits]` ceiling looks like from the inside —
`max_file_bytes` set below the size of the candidate's files:

```console
$ swp scan ./copy -p .
warning: this scan could not examine the whole candidate (3 omission(s)); it can say nothing was confirmed, not that nothing is there
…
scope     0 file(s), 0 byte(s) — PARTIAL, see notes
result    INCONCLUSIVE
evidence  NONE
…
Skipped (3): not examined, so not cleared
  - src/invoice.js: … bytes, above max_file_bytes (900)
  - src/money.js: … bytes, above max_file_bytes (900)
  - src/tax.js: … bytes, above max_file_bytes (900)
exit 10
```

Four things about that output are worth noticing, because they are the design
rather than the wording:

* The scope line says `PARTIAL` in the place where a clean scan says a byte
  count. A report that read `3 file(s), 0 byte(s)` would be a lie of the kind a
  log is trusted for.
* The omitted files are named, each with the limit that stopped it, under a
  heading that says what was not cleared.
* `evidence NONE` is *not* `NO_PROVENANCE_DETECTED`. The ladder's bottom rung is
  reserved for a candidate the tool read completely; here it refuses both
  directions of the answer, and the "What this report does not say" section says
  so in as many words.
* Nothing was skipped *silently*. There is no version of this where the numbers
  come out looking like a clean scan.

What to do: raise the ceiling, or narrow the input. `[limits]` in
`.swp/config.toml` is the only place ceilings are set — `swp inspect config`
prints the file as it stands, and
[USER-GUIDE.md](USER-GUIDE.md#the-limits-section) explains why the ceilings are
not flags. `swp scan <one directory>` narrows the input instead. A ceiling that
fires during `swp protect` is different: the walk stops, nothing is written, and
the exit code is `7` (`LIMIT_REACHED`).

## `verify` says `INCOMPLETE`

Exit `5`, and the most common reason a team opens this page. This is a tree whose
last source file was emptied out:

```console
$ swp verify -p .
warning: 2 of 10 site(s) of release rel-… are not carrying their code
verify javascript (swp1-…) against release rel-…
  tree        …
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  scope       2 file(s), … byte(s) read
  fingerprint …
  verdict     INCOMPLETE — 8/10 site(s) still carry their code, 32 keyed bit(s)
  channels    8 exact rendering(s), 0 address-without-code, 2 absent

What is no longer carrying its code (2 site(s))
  status        site  file:line                  family  width
  absent           8  src/tax.js:…             …          4
  absent           9  src/tax.js:…             …          4
…
exit 5
```

`INCOMPLETE` means the manifest authenticated, the keys derived, and the site
addresses were looked for — and some are not carrying their code. It is a
statement about those sites. It is not an accusation, and the report says so on
every run:

* **`absent`** — nothing at that address holds a keyed code. A deleted function,
  a formatter that dropped a literal, a refactor that removed the constant
  entirely, and a deliberate strip all look exactly like this. The site's own
  file is named; the code around it was still found, or it would be `absent` in
  a different sense.
* **`address-without-code`** (the `stripped` channel) — the site's location is
  there and its value was replaced with something that does not carry the code.
  This is the shape a *targeted* removal leaves, and it is the only channel that
  distinguishes "somebody changed this literal" from "this literal's file is
  gone".
* The count is out of **this release's** sites. If the tree has been protected
  twice, `verify` checks the newest release unless `--release` names one; an
  older release checked against newer source reports the sites the newer run
  moved as absent, which is true and not what you meant. `swp inspect releases`
  lists what exists, and `--save` writes any verdict out as a document.

The fix is not `--force`; there is no such flag, because there is nothing to
force. Either the watermark is meant to be there — `swp protect` re-embeds the
current tree and records a new release, and the old one stays verifiable — or the
code that carried it is meant to be gone, and `INCOMPLETE` is the correct report
of a tree that has moved on. Re-protect when the change is yours; treat the
finding as a finding when it is not.

## A release record will not open

`.swp/public/releases/*.json` is the half of the store you commit, so it is the
half a repository host, a merge, or a stranger can change. The record is signed,
and the signature is checked before any of it is printed or matched:

```console
$ swp inspect releases -p .
error [INVALID_MANIFEST]: release record: manifest signature does not verify
  next: Re-run with --release <id> naming an intact release under .swp/public/releases/. If the file is genuinely corrupt, restore it from your provenance backup; a manifest cannot be regenerated without the root secret.
exit 5
```

This one is worth taking seriously rather than restoring quietly. The fields a
report quotes — the fingerprint it compared, how many sites the release claimed,
which project claimed them — are read from that document, and `swp verify` also
cross-checks it against the private manifest, so a record that disagrees with the
manifest fails as `RELEASE_MISMATCH` even if somebody had been able to sign it. A
single changed character in a 64-hex digest is enough to fail both.

Restore the file from version control (it is committed) or from your provenance
backup. If the record was edited by somebody with write access to your repository
and you cannot explain it, the release it describes is the thing to distrust, not
the parser: `swp protect` publishes a new one, and the source that carries the
older release's sites is unchanged either way.

A record that fails as `PROTOCOL_VERSION_UNSUPPORTED` (exit `6`) is not damage.
It was written by a newer build; the rules are in [Versioning](SWP-1-SPEC.md#14-versioning).
A *saved report* can fail this way when it is older and the report schema has
moved since — the document records the arithmetic the build that wrote it graded
with, and this build refuses to re-grade it. Re-run `swp scan` or `swp verify` for
a current report; the release the old one describes is untouched.

## `protect` refused to write anything

Exit `15`, `NO_SAFE_LOCATIONS`. The example tree of C, shell and SQL files is the
documented case:

```console:generic
$ swp protect --sites 12
error [NO_SAFE_LOCATIONS]: nothing to protect under "…": 3 paths refused (no language adapter for this file type). Check [protect] targets and excludes in .swp/config.toml
  next: Nothing under [protect] targets has a language adapter, so this tree is not source to SWP-1 and nothing was written. This build parses javascript, typescript, python; another language needs an adapter, which is the extension point the documentation describes. Point [protect] targets at the part of the tree that is one of them, if there is one.
exit 15
```

The refusal is the honest behaviour, and it is a refusal rather than a warning
because the lexical fallback can *scan* source it has no parser for, at MODERATE
strength at most, but embedding into text the tool cannot re-read after
rewriting it means the proof that the rewrite preserved the code is absent.
`swp protect` will not do that to your source on the assumption that you wanted
the strongest thing it knows how to do.

If part of the tree *is* a supported language, name it:
`swp protect --target src/js`, or `[protect] targets` in the config. If it is not
any of them, [Adding a language adapter](DEVELOPER-GUIDE.md#adding-a-language-adapter)
is what it takes to write one, and it is a real extension point rather than a
fork: the protocol knows nothing about your language's syntax.

## A warning that is not a failure

These print on a run that succeeded, and most readers meet them first:

| line | what it says | what to do |
| --- | --- | --- |
| `warning: 21 candidate location(s) were refused for safety; the release carries 10 sites` | a location whose rewrite could not be proved safe, or whose radius belongs to another site, was skipped | nothing, usually. `swp inspect plan --release <id>` lists each one with its reason. Want more sites? `--sites` asks for more; the tree decides how many are safe |
| `warning: no file under the default scope has a language adapter, so swp protect will refuse this tree` (from `swp init`) | the store is fine; the tree's languages are not parsed | point `[protect] targets` at a supported subtree, or accept that this tree is scan-only |
| `warning: <setting> is above the ceiling this build enforces; using <ceiling>` | a `[limits]` value was clamped, because a bigger one is a run this build will not survive | leave it. The clamped value is what the run used, and `swp inspect config` shows both |
| `survived N site(s) found in another file` (from `swp verify`) | N site addresses were matched at a *different* file than the manifest recorded, which is what a moved function or a rename looks like | read it with `channels`; a site found in another file still carries its code. Ordinary edits between two `protect` runs produce this line, and it is not tampering |
| `fingerprint no-match (release published …)` with `verdict INTACT` | the fingerprint is a hash of the whole tree, so any edit moves it; the sites are what survived | nothing. This is the pair the design expects after a normal commit |
| `scope N file(s), M byte(s) — PARTIAL, see notes` in a report you thought was clean | the ceiling stopped part of the walk even though the run finished | see the limits section above; a `PARTIAL` report can only be `INCONCLUSIVE` |

## "The scan found nothing, and I know it is a copy"

Check these in order. Each has a line in a report that settles it:

1. **Was the candidate ever protected?** `swp scan` matches a candidate against
   *your* releases. A tree that never came out of a `swp protect` run holds no
   keyed literals, and the correct report is `NO_PROVENANCE_DETECTED`, exit `0`,
   with a `NEGATIVE_CONTROL` item saying that every file was read and nothing was
   keyed.
2. **Against which release?** The default is every release the project has.
   `--release` names one; a copy of an older build is found by the older release,
   and naming only the newest is how you lose it. `swp inspect releases` is the
   list.
3. **Was the whole candidate read?** A `PARTIAL` scope is exit `10`, not exit `0`.
   That is the difference between "nothing here" and "I could not look".
4. **Were the sites protected, or only planned?** `swp generate` writes a plan and
   touches nothing. Only `protect` puts literals in files.
5. **Is the copy a reimplementation?** A developer who rewrote the module from
   memory produced no copy of any protected literal, and there is no watermark in
   it to find. Every report says this in its last section, on runs that found
   evidence as well as runs that did not.

The opposite confusion — a scan that found something in a tree you are sure is
unrelated — is answered by the report's coincidence bound: address collisions
with none of the codes are graded `NONE`, and a single chance confirmation is
graded `WEAK` and holds the verdict at `INCONCLUSIVE`. [Reading a
report](USER-GUIDE.md#reading-a-report) has the rules;
`cargo test -p swp-test-suite --test false_positive` prints the measured cases,
thirty scans of unrelated corpora included.

## When you think the tool is wrong

Two ways this build can be mistaken, in the ordinary case rather than the
adversarial one:

* **A site whose radius is not unique.** Location ids are digests of the code
  around a literal. Two functions copied from each other produce the same radius,
  and then a site can be reported at a file:line it was never in — which is why
  `exact` counts and `moved` counts are separate lines and why a single fragment
  is never a finding. The finding needs several sites, and the bound says how
  much of what it found chance could explain.
* **A formatter that rewrites the literal itself.** A prettier that turns
  `1_000` back into `1000`, or collapses `'a' + 'b'` into `'ab'`, destroys the
  *rendering* while the address survives: that is an `address-without-code`, and
  the correct response is to re-protect, not to conclude somebody stripped you.

Both are visible in a report rather than hidden in a score, which is the whole
design: an evidence item names its kind, its strength, and the span it is about.

## Reporting a failure

`swp` is offline and keeps it that way, so nothing about your project is
sent anywhere without you sending it. To report a build problem, include:

* `swp --version`, in full — the protocol, schema and canonicalizer versions are
  all in that line, and a mismatch is usually the whole story;
* the command as you typed it, and the transcript, which is safe to paste: no
  output of this tool contains the root secret, and the `secret_leak` suite
  asserts that after every run ([SECURITY.md](SECURITY.md));
* `swp inspect config` for a limits problem, and `swp inspect store` for a
  layout one;
* the smallest tree that reproduces it. Source files that are yours and must
  stay yours: do not attach them to anything. `swp generate --format json` on a
  reproducible input, whose output is a plan and not your code, is often enough.

Do not include `.swp/private/root.key` or anything under `.swp/private/`. A
manifest names your files and the literal text at each site; it is the private
half for that reason, not because it is encrypted-looking.

If a file your tool refused to read is the problem, `swp inspect plan` and the
omission lists are the diagnosis, and both are already in the transcripts above —
this build tries to fail in a way that explains itself, and where it does not,
that is the bug worth reporting.

---

Next: [USER-GUIDE.md](USER-GUIDE.md#reading-a-report) for what every field of a
report means, [CLI.md](CLI.md#exit-codes) for the code table,
[SECURITY.md](SECURITY.md) for what is trusted and what is protected.
