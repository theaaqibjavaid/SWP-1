# User guide

[GETTING-STARTED.md](GETTING-STARTED.md) gets one project protected. This page is
about the cases that come after: what the store holds and which parts of it you
must never commit, how many sites to ask for, what happens when you protect the
same tree twice, how to run this in CI, how to scan an archive, and every key in
the configuration file.

## Where everything lives

`swp inspect store` prints the store as the tool sees it, and classifies each
artifact by whether it may be committed:

```console
$ swp inspect store
store .swp — project swp1-…
  root        …
  secret      present · .swp/private/root.key
  created     …
  protocol    SWP-1 · canonicalizer 1
  counts      …
  artifact                                           may commit
  .swp/config.toml                                   yes
  .swp/private/root.key                              never
  .swp/public/identity.json                          yes
exit 0
```

The full layout, and the rule for each path:

| path | what it is | commit | back up |
| --- | --- | --- | --- |
| `.swp/config.toml` | scope, site count, tag width, limits | yes | no |
| `.swp/public/identity.json` | project id, display name, verify key | yes | no |
| `.swp/public/releases/*.json` | one record per release: when, how many sites, which fingerprint | yes | via git |
| `.swp/private/root.key` | the sealed 256-bit secret | **never** | **yes** |
| `.swp/private/manifests/*.json` | the signed site list, both literals per site | **never** | **yes** |
| `.swp/private/plans/*.json` | what a run intended, including every refusal | never | optional |
| `.swp/private/reports/*.json` | reports you saved with `--save` | never | optional |

`init` writes a `.gitignore` entry for the private half, so the ordinary mistake
is prevented rather than documented. The split is not caution for its own sake: a
manifest is your own copy of the watermark, and a public copy of it lets anybody
see every site's address without holding the key. The release record, by contrast,
is designed to be public — it carries the verify key's coverage, not the key.

## What to protect, and what is skipped by default

`[protect] targets` is a list of store-relative paths, defaulting to `["src"]`.
Anything outside it is invisible to protection *and* to verification, so a project
whose code lives in `lib/` or `packages/` needs its targets set before the first
`swp protect`.

`excludes` adds to a built-in list of thirteen patterns that is there because those
files are either generated or hopeless: `**/.git/**`, `**/.swp/**`,
`**/node_modules/**`, `**/target/**`, `**/dist/**`, `**/build/**`, `**/venv/**`,
`**/.venv/**`, `**/__pycache__/**`, `**/vendor/**`, `**/*.min.js`, `**/*.min.css`
and `**/*.map`. Excluded and refused paths are counted in the "the walk
refused or excluded" line `init` prints, so a surprise in that number is a hint to
look at your scope before your watermark.

A file is only ever a candidate if a language adapter claims its extension. That
is the same rule that makes [`../examples/generic`](../examples/generic) refuse:
without a parser there is no way to re-read the file after rewriting it and prove
the surrounding code unchanged.

## How many sites, and how wide

Two knobs, and the trade-off between them is the whole design:

* **Sites** spread the watermark across files. A constellation inside one file is
  one `rm` away from nothing, which is why `init`'s suggestion aims at spread and
  why a scan of a *partial* copy — three files out of forty — can still reach a
  finding. `STRONG` wants four confirmations in at least two files — or six, which
  is the bar when count is the only argument available — and `VERY_STRONG` wants
  eight in at least three, so a single file carrying a whole release buys a lower
  grade than the same number of sites spread across the project.
* **Tag bits** decide how much each site proves: at 4 bits one site is 1-in-16 by
  chance; at 8 bits, 1-in-256. Wider tags cost capacity, because a family has to
  be able to spell that many distinct renderings inside the literal's radius.

Ask for more than the tree can hold and the tool gives you what it can: the JS
example's three files hold 10 of the 12 requested, and the gap is 21 refusals, each
with a reason. Raising `--sites` past a tree's capacity is not a failure —
it is a measurement of how much literal surface the tree has.

The numbers a release can be expected to reach are reproducible for a given tree:
across three independent root secrets the same three JavaScript files returned 10
of 12 with the same refusal split (21) and the same per-file distribution (3, 5,
2). Which *literal* inside each file carries a site is not stable, and neither is
the family it is rendered from, because both are the key's choice.

## Protecting the same tree twice

`swp protect` records a new release whenever you run it. Running it again on a
tree that already carries a release's sites is allowed and has a cost worth
understanding, because it is the one workflow that quietly degrades an old answer.

Observed on the JavaScript example, protecting with `--sites 12` and then again
with the default:

```console
$ swp inspect releases
releases — 1 of project swp1-…

  release                created                sites skipped bits  private half
  rel-…                  …                       10      21    4  manifest (10 site(s))

  10 site(s) across 1 release(s). A `swp scan` matches a candidate against all of them unless --release or --latest names one.
exit 0
```

That listing is the healthy case — one release, its sites intact. In the
two-release experiment, `swp verify --release <older>` returned:

```text
warning: 3 of 10 site(s) of release rel-… are not carrying their code
  verdict     INCOMPLETE — 7/10 site(s) still carry their code, 28 keyed bit(s)
  channels    7 exact rendering(s), 2 address-without-code, 1 absent
exit 5
```

The second run was allowed to place sites in the neighborhoods the first run had
already chosen, and two of those sites' addresses now carry a code the *newer*
release derives, which is not the older one's. `INCOMPLETE` is the honest answer:
the tree moved on from that release.

So the workflow rule is: **protect once per revision, and commit what it changed.**
Re-protect when you mean to publish a new release — a new version of the library,
a new project snapshot — and expect the previous record to describe the previous
tree. `swp verify --release <id>` on an old release is how you check what is left
of it; `--latest` is how you check the current one.

A second protect is never destructive to your code: the rewrites are equivalent
by construction, re-parsed and refused otherwise.

## In CI

The exit codes are the contract, and they are stable enough to branch on:

| command | `0` | non-zero |
| --- | --- | --- |
| `swp verify` | every site of the release is present with its code | `5` sites lost or stripped; `10` the tree was not fully read |
| `swp scan <candidate>` | a fully examined candidate holds no evidence | `1` evidence found; `10` part of the candidate was never examined |
| `swp protect` | the constellation was decided, proved and recorded | `15` nothing safe to embed; `7` a limit stopped it |
| `swp init`, `swp generate` | done | `2`, `3`, `14` as in [CLI.md](CLI.md#exit-codes) |

Three things worth knowing before you wire it up:

* **`scan` exiting `1` is not a build failure.** It is the finding. If your
  pipeline treats non-zero as red, invert it deliberately and read the `result`
  field, not the code: `swp scan ./candidate --format json > report.json`, then
  branch on `.result` and on `.candidate.partial`.
* **Whether a copied secret unseals depends on the operating system.** On Windows
  the store seals it to the account that created it (DPAPI, user scope), so a CI
  runner that is a different account, a different container or a different machine
  needs the secret restored through the documented recovery path, not copied
  byte-for-byte from a developer laptop — a copy that will not unseal is a silent
  way to make protection impossible. On Linux and macOS there is no sealing to
  bypass: the same bytes sit in `.swp/private/root.key` behind a `0600` mode, so a
  copy does work, and those permissions are the only thing protecting it at rest.
  Neither platform's behaviour makes ordinary email of the key safe.
* **Never save a report into a build artifact you publish.** `--save` writes under
  `.swp/private/reports/`, and one names your source paths, your sites and the
  files a candidate contained. `-o/--output` to a path you then handle deliberately
  is the safer shape for an automated check.

## Scanning an archive, a directory or one file

`swp scan <candidate>` takes a directory, a single file, or a `.zip` / `.tar`
archive. An archive is extracted into a private temporary directory with its own
ceilings (`max_archive_entries`, `max_archive_member_bytes`,
`max_archive_expanded_bytes`, `max_archive_ratio`, `max_archive_depth`), path
traversal and symlink entries are refused rather than skipped, and the extraction
is deleted when the command exits.

The candidate is never executed: no install, no build, no import, no interpreter.
A candidate's `.swp/` is ignored, because the keys come from the project doing the
scanning. That also means scanning a copy that still carries *its own* store tells
you nothing about that store — you get your releases' evidence or nothing.

A scan that could not read part of the candidate reports `INCONCLUSIVE` and exits
`10` rather than reporting a clean tree:

```console
$ swp scan ./copy
result    PROVENANCE_DETECTED
evidence  VERY_STRONG
exit 1
```

The `omissions` section of the JSON report — and the "Skipped" block of the text
one — lists what was not examined, with the reason. A file with no adapter is not
an omission: it is not source to this tool, so it neither counts as coverage nor
creates a hole. A file that a limit stopped the walk from reaching is a hole, and
flips a negative result to `10`.

## Several projects, one machine

Each project has its own store, its own secret and its own project id. `swp` finds
the store by searching upward from the working directory; `-p, --project <path>`
names it explicitly, which is what you want in a monorepo where the project root
is not the directory you are standing in:

```bash
swp verify --latest -p packages/ui
swp scan ./builds/suspicious-copy -p packages/ui
```

One project can scan a candidate against only its own releases. There is no key
sharing, no central registry, and no way for project A to verify project B's
artifacts — a copy of the verify key lets anybody *check* a manifest's signature,
and nothing else.

## The `[limits]` section

Seventeen ceilings, all in `.swp/config.toml`, all enforced by the walker, the
parser and the archive reader. They exist because a scan runs against source
everybody can send you, and `tests/resource/hostile.rs` is where each one is
measured. Defaults as this build ships them:

| key | default | guards |
| --- | --- | --- |
| `max_file_bytes` | 8388608 | one file's size on disk |
| `max_parse_bytes` | 4194304 | how much of a file reaches the parser |
| `max_nodes_per_tree` | 2000000 | parser output size |
| `max_depth` | 256 | tree depth |
| `max_parse_millis` | 2000 | time in one parse |
| `max_files` | 200000 | files walked |
| `max_total_bytes` | 8589934592 | bytes read |
| `max_sites_per_file` | 4000 | fragments in one file |
| `max_archive_entries` | 10000 | entries in a candidate archive |
| `max_archive_member_bytes` | 67108864 | one archive member |
| `max_archive_expanded_bytes` | 2147483648 | whole extraction |
| `max_archive_ratio` | 200 | expansion factor, i.e. a zip bomb |
| `max_archive_depth` | 1 | nested archives |
| `max_locations_per_manifest` | 4096 | sites in one release |
| `max_digest_set_entries` | 4000000 | canonicalized digests held |
| `max_shingles_per_region` | 32768 | shingles per structural region |
| `max_rendered_items` | 400 | rows the text renderer prints before counting the rest |

Hitting one is never silent: the command reports `LIMIT_REACHED` (`7`), or records
the unexamined path as an omission and grades the scan `INCONCLUSIVE`. Raising a
limit should be a decision you can explain to yourself, because each of them is a
defence against a specific way to make a tool work too hard.

## Removing SWP-1 from a project

Delete `.swp/` and the tool is gone from the tree; there is no background service
to uninstall, and it never had one. What deleting the store does not do is remove
the fragments: they are arithmetic and string concatenations in your source now,
and they behave. To get a clean tree, revert the commits `swp protect` produced —
which is why that command prints the list of files it modified, and why running it
on a branch you can drop is the careful way to try it.

## Next

* [CLI.md](CLI.md) — the option-level detail
* [REPORTS.md](REPORTS.md) — reading a `verify` or `scan` document field by field
* [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — the error table, symptom first
