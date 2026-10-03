# Getting started

Twenty minutes, one project, no network. By the end you will have protected a
tree, verified it, and scanned a copy of it — and you will know what each of those
answers does and does not mean, which is the part that matters when the answer is
the one you did not want. §10 is the four commands you reach for after that, and
what each one refuses to claim.

Every transcript on this page is verbatim output from this build. A line with `…`
in it stands for something this project's secret influences — an id, a digest, a
timestamp — and everything without one is a number the test suite re-checks by
running the same sequence from scratch.

## 1. Prerequisites

* **Rust 1.85 or newer.** `rustc --version` to check. The workspace declares
  `rust-version = "1.85"`, so an older toolchain refuses to build rather than
  failing somewhere subtle. If you use rustup, `rust-toolchain.toml` overrides that
  question and installs the one version CI builds and lints with, so the number you
  see from `rustc --version` will be newer than the minimum.
* **A machine this tool can write to.** No server, no account, no database. SWP-1
  is offline-first: it makes no network call in any code path, and it never
  uploads your source, your reports, or a telemetry ping.
* **A project whose source is JavaScript, TypeScript or Python**, with literals in
  it — numbers, strings. That is what carries a fragment. C, Go, Rust, Java and
  every other language are refused rather than guessed at; [§9](#if-your-language-is-not-supported)
  says what happens if you try.

No tree-sitter grammar needs downloading: the three grammars are compiled into
`swp-adapters` as prebuilt sources, so a build on a machine with no network
succeeds. The CLI has no third-party argument-parsing or terminal dependency
either.

## 2. Install the binary

From a checkout of this repository:

```bash
cargo install --path crates/swp-cli
# or, without installing it anywhere:
cargo build --release --bin swp   # the binary is target/release/swp(.exe)
```

Check it:

```console
$ swp --version
swp SWP-1 · swp 1.0.0-beta.5 · report schema SWP-1-report-v2
exit 0
```

The three tokens on that line are the three versions a report records: the
protocol, the build, and the report schema. A report names the schema it was
written under, and this build reads that one and no other — a document it cannot
interpret is refused rather than guessed at, which is why the schema is quoted
separately from the protocol.

## 3. Initialize the project

Run this in the root of the project you want to protect. It creates `.swp/` and a
secret, and changes no source file.

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

Read the last two lines of the first block before anything else: `init` wrote a
`.gitignore` entry so the private half cannot be committed by accident, and it
tells you that your source is untouched. `swp protect` is the only command that
edits files.

`[protect] target_sites 4` is a measurement, not a guess: `init` counted the
files it could parse and suggested a constellation that fits this tree with room
to spare. A constellation inside one file is one `rm` away from nothing, which is
why the suggestion aims at spread rather than at a large number.

## 4. What the secret is, and where it is not

`init` draws 256 bits from the operating system's random source. On Windows they
are sealed to your user account with DPAPI; on Linux and macOS the file holds them
unencrypted behind a `0600` mode, so there the permissions are the protection.
From those bits everything else is derived: the project id, the signing key for
the manifests, and the per-site codes.

* It lives in `.swp/private/root.key` and nowhere else.
* It is never printed by any command, never written into a report, a manifest, a
  release record, a plan, a registry index, a badge, a log or a source file. This is
  not a convention you have to maintain: `tests/secret_leak/` runs every one of
  those commands and then sweeps every artifact they can produce for it, in each of
  the renderings a secret can arrive in — hex, base64, base32, percent-encoded. The
  two files §10 publishes are the newest of those artifact types, and they are on
  that list because a signed *public* document is exactly where a derived key would
  be tempting to put.
* Losing it means losing the ability to verify or scan anything you have already
  protected. The public release records stay readable, and a copy of your source
  still carries its fragments, but only the key can decode them into a claim.
* A second secret would make the first project's copies unverifiable, so `init`
  refuses to replace one. Running it again on an initialized project reports
  `secret kept` and changes nothing.

[§11](#11-backing-up) is about the day you need this.

## 5. Configure it, if the defaults are wrong for you

`.swp/config.toml` is meant to be edited, and committed:

```console
$ swp inspect config
config .swp/config.toml

protocol = "SWP-1"

[protect]
targets = ["src"]
excludes = []
target_sites = 4
tag_bits = 4
embed_strings = true
exit 0
```

Five `[protect]` keys exist; the four you will touch are:

| key | default | meaning |
| --- | --- | --- |
| `targets` | `["src"]` | which paths to walk; a directory or a file, store-relative |
| `excludes` | `[]` | glob patterns dropped from the walk, on top of the built-in list |
| `target_sites` | 16; `init` writes a measured suggestion instead | how many fragments to aim for; 4–4096 |
| `tag_bits` | 4 | bits per site, 2–8. One site at 4 bits is 1-in-16 by chance, which is why one fragment is never a finding |

`embed_strings = false` restricts a constellation to numeric literals. The `[limits]`
section holds seventeen ceilings on file size, parse budget, tree shape and
archive expansion; they are there because hostile input is expected, so raising
one should be a decision you made rather than one the tool made for you.

Flags override for one run and never write to this file — `swp protect --sites 12`
changes what that run embeds, not your configuration — which is why `protect`
prints the settings it actually used.

## 6. Look before you write

Two commands change nothing, and both are worth running first.

```console
$ swp generate
plan mode: no source file was modified, and no release record or manifest exists for this run
  sites       4/4 embedded, 27 refused

This release is not protected yet: 4 site(s) exist only in a plan. Nothing here is verifiable until `swp protect --release rel-…` writes them.
exit 0
```

`generate` runs the whole pipeline and proves every rewrite in memory by
re-parsing it, then saves the result as a private plan. `swp inspect plan
--release <id>` lists what was refused and why; a refusal is the safety rule
working, not a problem.

```console
$ swp protect --dry-run
dry run: this is what `swp protect` would do. Nothing was written — no plan, no manifest, no release record, no source change. The release id above is the one a real run would mint, not one that exists.
warning: 27 candidate location(s) were refused for safety; the release carries 4 sites
would protect swp1-… — release rel-…
  sites       4/4 embedded, 27 refused
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint

What would be generated
  nothing on disk: a dry run writes no artifact

What was modified
  …

Next
  swp protect
exit 0
```

The `…` stands for the per-file list, which names your own paths and the byte
totals those files would grow by.

## 7. Protect

This edits your source files in place. Commit first, or run it on a branch.

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

Ten of twelve, and the gap is the rule that a location cannot be forced. The
three artifacts are written *before* the first source file is touched, so an
interrupted run leaves a tree `swp verify` can describe instead of a half-watermarked
one with no record.

In your source, a site reads like this:

```js
const sign = units < (8 - 8) ? "-" : "";
```

`(8 - 8)` is a spelling of `0`, chosen so that its two operands carry the site's
4-bit code. The value is unchanged and the parse is the same shape. Nothing in the
file names the protocol and no comment marks the site — which is why this tool
does not describe its watermark as *hidden*. It is unobtrusive, not secret. What
is secret is the root key, and it is the only thing between a public copy of your
project and anybody else computing the same codes.

## 8. Verify

```console
$ swp verify
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  fingerprint match (release published …)
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent

Every site of this release is present with its code. That is the whole claim; it says nothing about the tree being otherwise unchanged.
exit 0
```

Exit `0` means every site of the newest release is still there carrying its code.
It is not a statement that the file is otherwise untouched — a watermark cannot
say that, and `verify` says so in its own last line. `--release <id>` checks an
older release; `--save` keeps the result as a report you can render later with
`swp report`.

## 9. Scan a copy

Scanning is the command that runs against somebody else's tree. It reads the
candidate and never executes it: no build, no install, no import, no interpreter,
and the candidate's own `.swp/` is ignored, because the keys come from you.

Make a copy that looks like what somebody would forward you — the sources, nothing
else:

```bash
mkdir -p copy/src && cp src/*.js copy/src/
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

`result` and the exit code are one statement: `1` means evidence was found, `0`
means a *fully examined* candidate holds none, and `10` means the scan cannot say
— either part of the candidate was never examined, or what it found is a lead the
coincidence arithmetic will not carry as a finding. A script that reads `0` as
"clean" without reading `partial` will call an unread tree cleared.

And a tree that is yours but unprotected, for contrast:

```console
$ swp scan ../plain
result    NO_PROVENANCE_DETECTED
evidence  NONE
exit 0
```

That is the same Python source this build also protects, in a tree `swp protect`
never touched: two files examined, no fragment of the release reproduced, and the
scan still exits `0`, because a file with no adapter is *not source to this tool*
rather than a hole in coverage. [Scanning an archive, a directory or one
file](USER-GUIDE.md#scanning-an-archive-a-directory-or-one-file) says where that
line sits.

### If your language is not supported

A tree with nothing parseable in it is refused, and the refusal is explicit:

```console:generic
$ swp protect --sites 12
error [NO_SAFE_LOCATIONS]: nothing to protect under "…": 3 paths refused (no language adapter for this file type). Check [protect] targets and excludes in .swp/config.toml
  next: Nothing under [protect] targets has a language adapter, so this tree is not source to SWP-1 and nothing was written. This build parses javascript, typescript, python; another language needs an adapter, which is the extension point the documentation describes. Point [protect] targets at the part of the tree that is one of them, if there is one.
exit 15
```

Nothing was written, and no weaker scan was attempted on your behalf.
[`../examples/generic/README.md`](../examples/generic/README.md) is that
transcript in full, and [Adding a language
adapter](DEVELOPER-GUIDE.md#adding-a-language-adapter) is how to make your
language one of the three.

## 10. The four that come after

Everything so far is the sequence the tool was designed around: plan it, protect
it, check your own tree, check somebody else's. These four are what people then
ask for — a commit that cannot go through with the mark missing, a way to hand your
release list to somebody else, a page to point at, and a coverage number beside a
finding. None of them measures anything new; all four read the same artifacts the
sequence above wrote.

Put the check where a commit happens:

```console
$ swp pre-commit
pre-commit javascript (swp1-…) against release rel-…
  manifest    authenticated · 10 site(s) at 4 bit(s) each
  verdict     INTACT — 10/10 site(s) still carry their code, 40 keyed bit(s)
  channels    10 exact rendering(s), 0 address-without-code, 0 absent

Every site of this release is present with its code. That is the whole claim; it says nothing about the tree being otherwise unchanged.
exit 0
```

That is `swp verify`'s measurement with a hook's exit codes: `0` allows the commit,
`5` and `10` block it, and there is no flag that lets a `5` through. Put the command
in `.git/hooks/pre-commit` and a commit cannot go through while the tree on disk has
lost a site. Note which tree: it reads the *working* tree, not the index, so a
partial `git add -p` stage is judged as the file currently stands rather than as the
hunk you picked. That is `swp verify`'s limitation as well, and it is the reason a
pipeline that cares runs the same command against a checkout.

Ask the same scan how much of the release the copy reproduced:

```console
$ swp scan ./copy --compliance
result    PROVENANCE_DETECTED
evidence  VERY_STRONG
Compliance grade: FULL
  release   rel-…
  sites     10 held, 10 confirmed, 0 address without code, 0 absent
exit 1
```

A grade is coverage, not strength: `FULL` here means every keyed site of that one
release reappeared in a candidate that was read whole, and it is capped at `PARTIAL`
whenever the report above it declines to treat those confirmations as a finding.
`--compliance` is refused on `swp verify` and on `swp pre-commit`, because neither of
them has a candidate to grade.

Publish the list, and a page:

```bash
swp registry publish
swp badge
```

Each writes a signed summary of things already in `.swp/public/`, each is
committable, and neither is a service: nothing in this build uploads one or reads
another project's. The reader's side of each is the interesting half —
`swp registry search <file>` and `swp badge show` verify the signature before they
print a field, and inside a project they compare the key the document carries
against the identity in `.swp/public/identity.json`, so a file copied from somewhere
else is refused rather than believed. [CLI.md](CLI.md) documents all four of these
verbs; [TROUBLESHOOTING.md](TROUBLESHOOTING.md) is what each refusal asks of you.

## 11. Backing up

Two paths, and both are needed:

| path | why |
| --- | --- |
| `.swp/private/root.key` | without it nothing you have protected can be verified or scanned again |
| `.swp/private/manifests/` | each release's site list. Re-derivable from the key and the source *at that revision*, but not after you have edited the source |

`.swp/public/releases/` and `.swp/config.toml` are safe to commit and are your
audit trail; `swp inspect store` prints the classification of every artifact,
including a `may commit` column, so you never have to remember this table.

Back the private half up to somewhere that is not this working copy, encrypted
there rather than merely copied, before you protect anything. The recovery path if
you lose it is: restore the
backup, or accept that old releases can no longer be verified and start a new
project id — a new `swp init` never replaces a secret in place, so the old copies
and the new ones are different projects, deliberately.

## 12. Uninstalling

Delete `.swp/`. The tool leaves your machine entirely; there is nothing to
de-register.

What deleting it does **not** do is remove the watermark: the fragments are
arithmetic and string concatenations in your source now, and they keep working.
`swp generate` on a fresh store will find them again as candidates. If you want a
tree clean, revert the source commits that protected it — which is why `protect`
prints the list of files it modified before you run it, and why running it on a
branch you can drop is the careful way to try it.

## Next

* [USER-GUIDE.md](USER-GUIDE.md) — the workflows, and every field of a report
* [CLI.md](CLI.md) — every command, option and exit code
* [SECURITY.md](SECURITY.md) — what this resists, what it does not, and how to report a problem
* [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — what each error asks of you
* [../examples/javascript/README.md](../examples/javascript/README.md) — this page's sequence, one language deeper
