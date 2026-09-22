# Sponsorship

SWP-1 is open source under Apache-2.0, and it stays that way: every command in
[CLI.md](docs/CLI.md), every language adapter that exists, and every security fix
is in the public build. Sponsoring does not unlock the tool.

What sponsorship buys is **attention and engineering time** — the scarce thing in
an open-source project, and the one thing that can be sold without making anybody
else's copy of the software worse.

Sponsor here: https://github.com/sponsors/theaaqibjavaid

## Why this exists

SWP-1's security argument is cryptographic, not secret. The watermark is keyed to
a root secret that lives on *your* machine, and the code that derives and checks
it is readable by anyone precisely so that it can be audited
([docs/SECURITY.md](docs/SECURITY.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).
Publishing the implementation costs the project nothing in protection and gains it
review.

Maintenance is not free, though. A scanner that refuses hostile archives, a
canonicalization whose every rule is tested, and a documentation set whose every
example is re-executed by the test suite are all things somebody has to keep
correct while three ecosystems' grammars move underneath them. Sponsorship is how
that gets done on a schedule rather than when there is time.

## The tiers

Current amounts and benefits are on the sponsorship page; the tiers below are the
shape of the arrangement, and they are the same for everyone at that level.

### Tier 1 — Builder

For somebody using SWP-1 in anger and wanting to see where it is going.

* Pre-release builds of the next version, including development snapshots of
  SWP-2's public surface, before they are tagged.
* A sponsor-only changelog: what is being worked on, and what got dropped and
  why.
* The sponsor announcements channel for the project's roadmap discussions.
* A name (or your organisation's) in the acknowledgements of each release.

### Tier 2 — Production

For a team whose CI runs `swp verify` and whose scans matter commercially.

Everything in Tier 1, plus:

* **A 48-hour acknowledgement SLA** on a support request or a suspected
  vulnerability, with an engineer reproducing it against your input. Compare the
  public baseline: best-effort, five business days, in [SECURITY.md](SECURITY.md).
* **Backport engineering.** If you run a fork, a vendored copy, or a branch of
  this codebase that is not the current release, an engineer will prepare and
  test the patch for *that* tree, not just for mainline.
* **An early advisory channel**: notice that a security issue exists, with the
  mitigation, while the fix is still being prepared — so you can harden a
  deployment before the disclosure, rather than reading about it afterwards.
* Production configurations reviewed by a maintainer: `[protect]` targets, exclusion
  lists, and site/bit budgets for a real repository, and a review of what a
  report you are relying on actually says.

### Tier 3 — Enterprise backer

Everything in Tier 2, plus:

* **A direct engineering channel** with the people who wrote the detector —
  scheduled, not just reactive.
* **Roadmap influence.** Not control: what SWP-1 becomes is decided by the
  maintainers, and a sponsor's position is stated, weighted, and answered with a
  reason. Language adapters and integration surfaces are the usual ask, and the
  usual answer is yes when the work is real.
* Priority on integration and adapter work that the public roadmap wants anyway.
* **A public brand acknowledgment** in `README.md` and the release notes of every
  version your funding covered.
* Option to be named in the security advisory for an issue you reported.

## What sponsorship does not buy

Stated because the alternative is a promise the project cannot keep.

* **Not an advance on a security patch.** Every supported public version gets a
  security fix in the same release cycle as everyone else. The reasons are in
  [SECURITY.md](SECURITY.md#patch-and-backport-policy), and they are about the
  product's credibility, not just fairness: a provenance tool whose users run
  known-broken detectors for a billing interval is not worth buying.
* **Not the source code of a paid product.** Sponsor-funded work on SWP-2 is
  closed, and that is disclosed rather than apologised for; everything that lands
  in SWP-1 is Apache-2.0 and stays there. Contributions to SWP-1 are governed by
  [CLA.md](CLA.md), which is where the relicensing right actually comes from.
* **Not access to your data, or to anyone else's.** `swp` has no network code path,
  collects nothing, and never sees the trees it examines
  ([docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)). A sponsor's support request
  is a conversation about a problem, not a feed of other people's findings, and we
  could not sell one if we wanted to.
* **Not a way to have a project's watermark removed, or a report's verdict
  changed.** `swp inspect fragments` already lists every site in a tree you own;
  that is a feature of the protocol, and no amount of sponsorship is required for
  it or excluded from it.
* **Not the removal of any documented limitation.** A missing language adapter does
  not appear because somebody funded another one.

## Other ways to help that cost nothing

Report a false positive with a reproducing tree. Write the fourth language adapter
([docs/LANGUAGE-ADAPTERS.md](docs/LANGUAGE-ADAPTERS.md) is the spec). Run
`swp verify` in CI and tell us when it disagrees with you. Answer a question in
issues — the [FAQ](docs/FAQ.md) is assembled from those. Fix a sentence that claims
too much; that is a documentation bug, and the ones here are treated as product
bugs.

## For maintainers

Sponsorship income is recorded in the project's public accounting alongside the
time it pays for, and `CHANGELOG.md` says which release a funded item landed in. If
that stops being true, [open an issue](https://github.com/theaaqibjavaid/SWP-1/issues) —
this page is a commitment, and commitments here are meant to be checked.
