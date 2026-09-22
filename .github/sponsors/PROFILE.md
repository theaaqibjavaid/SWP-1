# The sponsor profile page — the text, in the order to paste it

For <https://github.com/sponsors/theaaqibjavaid>. The per-tier field values are in
[TIERS.md](TIERS.md); this is the page a person reads before choosing one.

Two things about pasting this anywhere on GitHub:

* **Image URLs have to be absolute**, and a GitHub Sponsors profile is not a
  repository, so relative paths will not resolve. The links below point into this
  tree and will 404 until the repository is public — publish the repo first, then
  paste.
* **The profile page is the account's, not the project's.** A sponsor arriving
  there sees every project under the account. The copy says what SWP-1 is in the
  first line rather than assuming the reader got there from this README.

---

## 1. Bio — one line, wherever the form asks for a summary

```text
Maintainer of SWP-1, a source provenance watermark tool. Offline, auditable, Apache-2.0.
```

## 2. Opening

SWP-1 is a command line tool that embeds an owner-keyed watermark into the
literals of a source tree — the numbers and strings a program computes with — and
then answers one question about a tree somebody hands you: *does this carry one of
my releases, and how strong is the evidence?*

It is free, open source, and stays that way. Sponsoring does not unlock a feature.
There is no paid build. Every command, every language adapter and every security
fix is in the public repository.

**Sponsorship buys the scarce thing instead: engineering time, and attention with a
deadline on it.**

## 3. Where the money goes

Maintenance in this project has a specific shape, and it is the shape that
goes unfunded:

* Three tree-sitter grammars move on their own schedules, and every change has to
  be re-checked against the embedding rules and the detection rules, because a
  grammar update that shifts a byte offset is a watermark that stops verifying.
* The documentation is executed. Every `console` block in the README, in `docs/`,
  and in `examples/` is re-run against the current build by a test suite, and a
  page that no longer matches the product fails CI rather than opening an issue.
* A test section whose job is to defeat the watermark — rewrite protected code,
  minify it, reformat it, copy it into another file — and report what survives.
* Archives are parsed without ever running the code inside them, which means
  treating every input as hostile: path traversal refused, symlink entries
  refused, extraction into a private temporary directory that is deleted on exit.

None of that is visible in a feature list, and all of it is why the tool can be
trusted with an answer that might end up in a dispute.

## 4. What sponsorship does not buy

Short version, because the long version is
[SPONSORS.md](https://github.com/theaaqibjavaid/SWP-1/blob/main/SPONSORS.md) and it
is the part of this arrangement a sponsor should read first:

* **Not a security fix ahead of anybody else.** Every supported public version is
  patched in the same release. Sponsors buy a 48-hour *acknowledgement*, backport
  engineering for a fork they run, and an early advisory with the mitigation while
  the fix is still being written. A provenance tool that left paying customers on a
  known-broken detector would not be worth buying.
* **Not the source of a paid product.** Work funded toward SWP-2 is closed, and
  that is disclosed rather than apologised for. Everything that lands in SWP-1 is
  Apache-2.0 and stays there.
* **Not data.** `swp` has no network code path, collects nothing, and never sees
  the trees it examines. There is no feed of other people's findings to sell, and
  nobody has asked, because there is nothing to ask for.
* **Not a changed verdict, or a removed watermark.** `swp inspect fragments`
  already lists every site in a tree you own. That is a property of the protocol.

## 5. The tiers

![The three sponsorship tiers](https://github.com/theaaqibjavaid/SWP-1/raw/main/.github/sponsors/assets/swp-tier-ladder.svg)

| | |
| --- | --- |
| **Supporter** — $25 once | A contribution to maintenance time. No rewards, no queue. |
| **Tier 1 · Builder** — $10/mo | Pre-release builds, the sponsor changelog, the roadmap channel, a name in each release's notes. |
| **Tier 2 · Production** — $100/mo | 48-hour acknowledgement, backport engineering for your fork, the early advisory channel, a maintainer review of your configuration. Everything in Builder. |
| **Tier 3 · Enterprise backer** — $500/mo, 3-month minimum | A scheduled engineering channel, roadmap influence that is answered with a reason, priority on adapter work, your brand in `README.md`. Everything in Production. |

Roadmap influence is not roadmap control. What SWP-1 becomes is decided by the
people who maintain it; a sponsor's position is stated, weighted, and answered.

## 6. Proof, if you would rather check than take my word

| | |
| --- | --- |
| What it does, run end to end | [examples/](https://github.com/theaaqibjavaid/SWP-1/tree/main/examples) — four protected trees, each with the transcript that produced it |
| What was measured, and what is still a limitation | [docs/VALIDATION.md](https://github.com/theaaqibjavaid/SWP-1/blob/main/docs/VALIDATION.md) |
| The attacks it does not survive | [docs/THREAT-MODEL.md](https://github.com/theaaqibjavaid/SWP-1/blob/main/docs/THREAT-MODEL.md) |
| Whether the claims are current | [CI](https://github.com/theaaqibjavaid/SWP-1/actions/workflows/ci.yml) — including the job that re-runs every documented transcript |

## 7. Fine print

Maintained by **Aaqib Javaid** under **Yeast Technologies**, which he owns.
SWP-1's licence is [Apache-2.0](https://github.com/theaaqibjavaid/SWP-1/blob/main/LICENSE);
contributions are governed by the
[CLA](https://github.com/theaaqibjavaid/SWP-1/blob/main/CLA.md), which is where the
right to keep a funded successor closed actually comes from — a sponsor is not
buying that right, the project is reserving it in the open, before anyone
contributes, in a document anybody can read.

Sponsorship is support for open-source maintenance. It is not an investment
offer, and no tier conveys equity, revenue share, or a claim on the project or its
company. Invoices and receipts are handled by GitHub's payment processor; anything
contracted separately — custom adapter work, integration into a private codebase —
is a different arrangement, discussed directly, and not sold through this page.
