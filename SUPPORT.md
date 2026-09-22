# Support

## Where to ask

| situation | route |
| --- | --- |
| something the tool does that it should not | [open an issue](https://github.com/OWNER/swp/issues/new/choose) with a reproducing tree |
| something the documentation says that is not true | an issue, and treat it as a bug report — a wrong sentence here is a product defect |
| how do I do X | [discussions](https://github.com/OWNER/swp/discussions), or [USER-GUIDE.md](docs/USER-GUIDE.md) first |
| a suspected security problem | **[SECURITY.md](SECURITY.md), not an issue** — a public issue is a disclosure |
| you need an answer in hours, or you run a fork | [SPONSORS.md](SPONSORS.md) |

There is no support SLA for the public project, and no promise of one on this
page. Maintainers answer when they can; the target that *is* stated is the
five-business-day acknowledgement for security reports, and everything else is
best effort. If an answer matters more than that, sponsor it or open the issue
with the reproducer attached, which is the fastest thing available to anyone.

## Before you post

Three items make the difference between a triaged bug and a thread of guesses.
All three are safe to publish, and none of them is your source code.

1. **The build and the platform.**

   ```console
   $ swp --version
   swp SWP-1 · swp 1.0.0 · report schema SWP-1-report-v1
   ```

   Say which operating system and, for a scan, whether the candidate came from an
   archive or a directory.

2. **What the tool actually said.** The full output, including the `exit N` line
   the product prints, and the command exactly as typed. If you have a saved
   report, `swp report --format json` and paste it; the JSON is the artifact a
   maintainer can reason about.

3. **The smallest tree that still does it.** `swp protect` on a two-file
   `scratch/` directory is usually enough to reproduce an embedding problem, and a
   scan problem needs the candidate plus the store that judged it.

`swp inspect store` prints paths and identifiers from your project. That is the
one command whose output you should read before attaching it:

```console
$ swp inspect store
store .swp — project swp1-…
  root        C:\Users\…\proj
  secret      present · .swp/private/root.key
  created     2026-09-22T04:38:04Z
  protocol    SWP-1 · canonicalizer 1
  counts      0 release(s), 0 manifest(s), 0 plan(s), 0 report(s)
```

The rest of that view is a table of every artifact in the store with a **may
commit** column, and the list of views.

The root secret is never printed by anything — the `secret_leak` suite exists to
make that a tested statement rather than a hope — and the public identity document
is public by design. Paths and project ids are yours to redact if the tree is
sensitive. Do not attach `.swp/private/`, and do not paste a `.swp/private/root.key`
file into anything, anywhere.

## What a report's numbers mean

If you are here because a scan said `POSSIBLE` and you wanted `STRONG`, the answer
is on [REPORTS.md](docs/REPORTS.md): the ladder, the rule behind each rung, and the
coincidence bound that says what chance could have done. The short version is that
`POSSIBLE` is defined to mean *this could be chance*, and a report is written to
say the weaker true thing rather than the stronger flattering one.

If you are here because a scan found your code in somebody else's tree, this
repository will not adjudicate that. It will tell you what was matched, how many
keyed bits were confirmed, and what the odds were — and that is the whole of what a
provenance instrument is permitted to claim.

## Getting a fix into your schedule

Workarounds are usually configuration: `[protect] targets` and exclusion lists
decide where sites go, `--sites` and `--bits` trade evidence strength against
footprint, and `--target` lets one release cover one package of a monorepo.
[CLI.md](docs/CLI.md) lists every setting the command line does not offer, and
[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) covers each error code with what it
asks of you.
