# The `swp` command line

Seven commands, seventeen options, one exit-code table. Everything on this page is
generated from the same declaration the binary uses: `swp help` prints the
overview, `swp help <command>` prints one command's options, and a test fails the
build if this page lists an option its command would reject.

```console
$ swp help
swp SWP-1 · swp 1.0.0 · report schema SWP-1-report-v1

Usage: swp <command> [options]

Commands
  init       create the project's identity and private store
  generate   plan a constellation and write nothing into the source
  protect    embed the watermark and record the release
  verify     check this tree against one of its own releases
  scan       scan a candidate copy for evidence of your releases
  inspect    show what the store holds: identity, releases, fragments
  report     list and re-render saved reports
  help       this text
  --version  the protocol and build versions

The normal sequence in a project you own:
  swp init                 once; creates .swp/ and the project secret
  swp generate             see the constellation, change nothing
  swp protect              embed it and record a release
  swp verify               confirm this tree still carries that release
  swp scan ./copy          look at somebody else's tree

Every command takes --help. Machine-readable output is --format json.

Exit codes
    0  success; for scan, no watermark evidence found in a fully examined candidate
    1  scan: watermark evidence found; the candidate carries one of your releases
    2  USAGE
    3  SECRET_UNAVAILABLE
    4  NOT_PROTECTED
    5  RELEASE_MISMATCH
    6  PROTOCOL_VERSION_UNSUPPORTED
    7  LIMIT_REACHED
   10  INCONCLUSIVE / INSUFFICIENT_EVIDENCE — part of the candidate was not examined
   14  IO_ERROR
   15  NO_SAFE_LOCATIONS
   70  INTERNAL_ERROR

Run `swp help <command>` for a command's options.
exit 0
```

The overview's table is the twelve codes a script is most likely to branch on.
Six more exist and are listed under [Exit codes](#exit-codes) with the rest;
they are rarer, not unused.

## How the parser behaves

There is no argument-parsing library in this build, and the grammar is small
enough to state completely:

* `swp` with no argument prints the overview and exits `0`; `-h`, `--help` and
  `help` do the same, and `swp <command> --help` prints that command's page.
* `-V`, `--version` and `version` print the banner.
* An option may be `--flag value` or `--flag=value`; `-o`, `-p`, `-q`, `-v` and
  `-f` are the only short forms.
* A repeated valued option keeps every occurrence. `--target a --target b`
  protects both; a single-valued option such as `--sites` uses the **last** one.
* `--` ends option parsing, so a candidate whose name begins with a dash
  (`swp scan -- --odd-name`) still reaches the scanner as a path.
* An unrecognized option or verb is an error, never a shrug. `--formt` is
  refused by name, with the option it is close to suggested — but only when that
  option belongs to the command on the line:

```console
$ swp scan --formt json ./copy
error [USAGE]: scan does not accept "--formt". Did you mean --format?
  next: Re-run with --help to see accepted arguments.
exit 2
```

* `--format` accepts `text` (the default) or `json` and refuses anything else
  rather than falling back: a machine-readable output that silently arrived as
  prose is the failure that gets baked into a script.

### Where the text goes

Results go to stdout. `warning:` lines and `error [CODE]:` blocks go to stderr,
interleaved in the order the command produced them, so a transcript you paste
into an issue is the transcript a terminal showed you. To capture both in one
file: `swp scan ./copy > out.txt 2>&1`.

Errors always carry the same three lines — the code and what went wrong, an
`at:` line naming the file when one is implicated, and a `next:` line saying what
to do about it. The third is not decoration: §49's rule is that a message has to
tell the reader their move, and several of them are asserted by name in the test
suite.

```console
$ swp scan ./nowhere
error [IO_ERROR]: cannot read … The system cannot find the file specified. (os error 2)
  next: Check that the path exists, is not locked by another process, and that you have write permission.
exit 14
```

## Commands

| command | needs the root secret | writes | can modify your source |
| --- | --- | --- | --- |
| `swp init` | no (it creates one) | `.swp/`, `.gitignore` | never |
| `swp generate` | yes | a private plan | never |
| `swp protect` | yes | plan, manifest, release record, source | yes, in place |
| `swp verify` | yes | optionally a saved report | never |
| `swp scan <candidate>` | yes | optionally a saved report | never; never executes the candidate |
| `swp inspect <view>` | no | nothing | never |
| `swp report [name]` | no | nothing (or `--output`) | never |

The store is found by searching upward from the working directory for `.swp/`,
which is what `-p, --project <path>` overrides. `swp scan` is the one command that
takes a path *to judge* as a positional argument; it still needs your own project
for the keys, and never reads the candidate's `.swp/`.

### `swp init`

Creates the project's identity and private store: `.swp/`, a 256-bit root secret
drawn from the operating system, `identity.json`, and a `.gitignore` entry so the
private half cannot be committed by accident. It then measures the tree and writes
a suggested `[protect] target_sites` into `.swp/config.toml`.

| option | meaning |
| --- | --- |
| `--name <label>` | display label instead of the directory name |
| `-p, --project <path>` | where to create the store |
| `--format <text\|json>` | machine-readable result |
| `-f, --force` | allow `--name` to rename a project that already has a name |
| `-q, --quiet` | print only the result line |

Re-running it is safe: an existing secret is kept, never replaced, because every
past release's fragments are keyed under it. `--force` therefore affects the
display name only, and nothing about which copies are yours — the project id is
derived from the secret, not from the label.

### `swp generate`

Runs the whole pipeline — walk, harvest literal candidates, select a
constellation, and prove every rewrite in memory by re-parsing it — then saves the
result as a private plan. It modifies no source file and publishes no release
record, so nothing it produced is verifiable later.

| option | meaning |
| --- | --- |
| `-p, --project <path>` | the project to plan for |
| `--target <path>` | override `[protect] targets`, repeatable |
| `--sites <n>` | override `[protect] target_sites` |
| `--bits <n>` | override `[protect] tag_bits`, 2–8 |
| `--release <id>` | reuse this id, so `swp protect --release <id>` applies exactly this plan |
| `--format`, `-q`, `-v` | as above |

```console
$ swp generate
plan mode: no source file was modified, and no release record or manifest exists for this run
  sites       4/4 embedded, 27 refused

This release is not protected yet: 4 site(s) exist only in a plan. Nothing here is verifiable until `swp protect --release rel-…` writes them.
exit 0
```

### `swp protect`

Embeds the constellation and records the release. The three artifacts —
`.swp/private/manifests/<id>.json`, `.swp/private/plans/<id>.json`,
`.swp/public/releases/<id>.json` — are written **before** a single source file is
touched, so an interrupted run leaves a tree `swp verify` can still describe.

| option | meaning |
| --- | --- |
| `-p, --project <path>` | the project to protect |
| `--target <path>` | override `[protect] targets`, repeatable |
| `--sites <n>` | how many sites to aim for |
| `--bits <n>` | tag width, 2–8 |
| `--release <id>` | publish under this id |
| `--revision <label>` | record a source revision (a commit sha, a version) in the release record |
| `--dry-run` | decide and report, write nothing |
| `--format`, `-q`, `-v` | as above |

A location that cannot carry a fragment safely is skipped, never forced, so
`sites N/M embedded, K refused` is a normal result rather than a warning to fix —
the refusals are listed by reason, and one line each with its file is
`swp inspect plan --release <id>`.

```console
$ swp protect --dry-run
dry run: this is what `swp protect` would do. Nothing was written — no plan, no manifest, no release record, no source change. The release id above is the one a real run would mint, not one that exists.
warning: 27 candidate location(s) were refused for safety; the release carries 4 sites
would protect swp1-… — release rel-…
  sites       4/4 embedded, 27 refused
  tag         4 bits per site
  fingerprint … (L1)
  scope       3 file(s) analyzed, 3 file(s) hashed into the fingerprint

What would be generated
  nothing on disk: a dry run writes no artifact

What was modified
  src/invoice.js — 2 site(s), 1214 → … bytes
  src/money.js — 1 site(s), 1497 → … bytes
  src/tax.js — 1 site(s), 1010 → … bytes

How the constellation is built
  …

What was refused, and why (§11: skipped, never forced)
  constellation-full       26
  overlapping-radius       1

Next
  swp protect
exit 0
```

Four sites, not twelve, is `init`'s measured suggestion for this tree rather than
the request; `--sites` overrides it. Which family each site is rendered from — and
so how many bytes a file grows by — is what the keyed priority decides, which is
why the byte totals above stand elided while the site counts, the refusal split
and the analyzed scope are printed as numbers. Those three are properties of the
tree, and they repeat under a different secret; the ones that do not are the ones
this manual does not write down. See
[`../examples/javascript/README.md`](../examples/javascript/README.md) for the
same convention, and for the run that re-checks it.

### `swp verify`

Checks this tree against one of its own releases: it re-derives each site's keyed
code from the secret, reads the current source, and reports what it finds.

| option | meaning |
| --- | --- |
| `-p, --project <path>` | the project to check |
| `--release <id>` | which release; the newest one if omitted |
| `--latest` | the newest release only |
| `--format <text\|json>` | the same verdict as a document |
| `--save` | keep a report under `.swp/private/reports/` |
| `-o, --output <path>` | write the JSON document there |
| `--full`, `--limit <n>` | how much of the site table the text lists |
| `-q, --quiet`, `-v, --verbose` | print less, or print what is being looked at |

Exit `0` means every site is present and still carries its code. It does **not**
mean the tree is unchanged — that is not what a watermark can say. See
[REPORTS.md](REPORTS.md) for the verdicts and the per-site statuses.

### `swp scan <candidate>`

Looks for evidence of your releases in somebody else's tree: a directory, a
single file, or a `.zip` / `.tar` archive.

| option | meaning |
| --- | --- |
| `--release <id>` | judge against one release instead of all of them |
| `--latest` | the newest release only |
| `-p, --project <path>` | which project's keys to use |
| `--format <text\|json>` | full report as a document |
| `--save` | keep it with the project doing the scanning |
| `-o, --output <path>` | write the document there |
| `--full`, `--limit <n>` | how many evidence items the text lists |
| `-q, --quiet`, `-v, --verbose` | print less, or print what is being looked at |

The candidate is read and never run: no build, no install, no import, no
interpreter. Archives are extracted into a private temporary directory with
path-traversal and symlink entries refused, and the extraction is deleted on
exit. A candidate's own `.swp/` is ignored — the scanner takes keys from you, not
from the tree it is judging.

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

For this command `1` is not a failure: it is the finding. `0` means a *fully
examined* candidate holds no evidence, and `10` means part of the candidate was
never examined, so neither answer is available. Scripts must read the result
field, not the exit code alone.

### `swp inspect <view>`

Reads the local store and prints it. It cannot tell you anything about a
candidate — that is `swp scan`.

| option | meaning |
| --- | --- |
| `-p, --project <path>` | which store |
| `--release <id>` | required by the four per-release views |
| `--format <text\|json>` | the same data as a document |
| `--full`, `--limit <n>` | table length |

The eight views, in the order `swp inspect --help` lists them:

| view | prints |
| --- | --- |
| `store` (default) | every artifact the store holds, and its classification |
| `identity` | the public identity, including the verify key |
| `config` | the config as it is on disk, not as flags would change it |
| `releases` | one line per protected release, oldest first |
| `release` | one release record, and whether its private half is present |
| `manifest` | the signed site list: keyed addresses and both literals |
| `plan` | what a run intended, including every location it refused |
| `fragments` | the site table and the refusals, as a human reads them |

The last three of those print your own copy of the watermark and say so on
stderr, which is why `store` is the default rather than the most interesting one.
Do not paste them into an issue or a public document.

### `swp report [name]`

Lists the saved reports, or re-renders one from the document that was written at
the time — so a report keeps the grade it was given even after the ladder's rules
change, because the stored level is printed rather than recomputed.

| option | meaning |
| --- | --- |
| `-p, --project <path>` | which store |
| `--release <id>` | filter the listing to reports naming that release |
| `--format <text\|json>` | the index as one document |
| `--full`, `--limit <n>` | listing length |
| `-o, --output <path>` | export a stored document unchanged |

`<name>` is the stem, the file name, or the store-relative path; all three mean
the same entry. This command exits `0` whatever a listed report concluded: reading
an old finding is not a new one.

## Exit codes

`2` means you asked for something the tool does not do; every code above it means
the tool ran. All seventeen, with the name the error line prints for it:

| code | name | when |
| --- | --- | --- |
| `0` | — | success. For `scan`: no evidence in a fully examined candidate. For `report`: the listing printed, whatever it said |
| `1` | — | `scan` only: evidence found; the candidate carries one of your releases |
| `2` | `USAGE` | unknown command or option, a value that is not a number, an out-of-range setting, a rename without `--force` |
| `3` | `SECRET_UNAVAILABLE` | the root secret is missing, unreadable, or refused by the permission check |
| `4` | `NOT_PROTECTED` | no store, no releases, or a `--release` id this project has never published |
| `5` | `INVALID_MANIFEST` / `RELEASE_MISMATCH` | two readings share this code deliberately: a manifest that fails its signature or disagrees with its record, and a tree that no longer matches the release it is checked against |
| `6` | `PROTOCOL_VERSION_UNSUPPORTED` | an artifact written by a protocol this build cannot read |
| `7` | `LIMIT_REACHED` | a `[limits]` ceiling stopped the walk, the parse or the archive |
| `8` | `UNSUPPORTED_LANGUAGE` | a language was named that no adapter claims |
| `9` | `INVALID_WATERMARK` | a fragment that cannot be well-formed: bad width, bad family, bad site id |
| `10` | `INSUFFICIENT_EVIDENCE` / `INCONCLUSIVE` | part of the candidate was not examined, so neither a finding nor a clean answer is available |
| `11` | `UNSAFE_EMBEDDING` | a rewrite that did not provably survive re-parsing; refused, so normally counted as a refusal rather than an error |
| `12` | `MALFORMED_SOURCE` | a file the parser could not be handed at all |
| `13` | `PARSER_FAILURE` | the parser itself errored on a file that looked readable |
| `14` | `IO_ERROR` | a read or write the operating system refused |
| `15` | `NO_SAFE_LOCATIONS` | nothing under `[protect] targets` passed the safety preconditions; nothing was modified |
| `16` | `PATH_REJECTED` | a candidate path that tried to escape the tree being scanned |
| `70` | `INTERNAL_ERROR` | an invariant this build holds broke; please report it, with the text and nothing else |

Codes `8`, `9`, `11`, `12`, `13` and `16` are absent from the `swp help` table
because no ordinary run is expected to reach them; they are reachable, and
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) covers what each one means when it
appears.

## Settings the command line does not offer

`[limits]` — seventeen ceilings on file size, parse budget, tree shape and archive
expansion — lives only in `.swp/config.toml`, because a run that can be widened
one flag at a time is a run whose limits nobody reads. `swp inspect config` prints
the file as it stands; `swp protect` prints the settings a run actually used,
which is the same thing unless `--target`, `--sites` or `--bits` said otherwise.
See [USER-GUIDE.md](USER-GUIDE.md#the-limits-section).

## Reading the rest

- [GETTING-STARTED.md](GETTING-STARTED.md) — the sequence above, run against a real tree
- [REPORTS.md](REPORTS.md) — every field of a text or JSON report
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — what each error asks you to do
- [`../examples/javascript/README.md`](../examples/javascript/README.md) — a transcript that stays honest because a test re-runs it
