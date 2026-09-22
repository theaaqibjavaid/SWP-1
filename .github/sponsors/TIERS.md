# GitHub Sponsors — paste sheet

The field values to enter at **github.com/settings/sponsors → Sponsorships → Tiers**
for the profile at <https://github.com/sponsors/theaaqibjavaid>.

This file is derived. **[SPONSORS.md](../SPONSORS.md) is the promise**; if the two
disagree, that page is right and this one is stale. `scripts/check-release.sh`
compares the tier names and prices between them and fails if they drift.

Amounts are monthly. GitHub's own ceiling is US$12,000 per month per tier, and it
also accepts one-time amounts, which is what the first row is.

---

## Supporter — one-time, US$25

**Description field** (78 characters, as one line):

```text
A one-time contribution to maintenance time. No rewards, no queue — thank you.
```

No benefits. It exists because some people will want to give once, and a tier that
pretends to be a membership is worse than one that says it is a thank-you.

---

## Tier 1 · Builder — US$10 / month

**Description field** (97 characters, as one line):

```text
Pre-release builds, a sponsor changelog, the roadmap channel, and a name in each
release's notes.
```

**Rewards to enable:** early access to release tags; a private discussion channel;
name or logo listed in the release acknowledgements.

---

## Tier 2 · Production — US$100 / month

**Description field** (170 characters, as one line):

```text
48-hour acknowledgement on a report, backport engineering for your fork, the early
advisory channel, and a maintainer review of your configuration. Everything in Builder.
```

**Rewards to enable:** everything in Builder, plus the support arrangement described
in [SPONSORS.md](../SPONSORS.md#tier-2--production).

State the SLA as an acknowledgement commitment, not a resolution commitment. A
promise about *fixing* something in 48 hours is a promise the project will one day
miss because the bug is hard, and a missed promise about a fix is worse than a met
one about attention.

---

## Tier 3 · Enterprise backer — US$500 / month, three-month minimum

**Description field** (154 characters, as one line):

```text
A scheduled engineering channel, roadmap influence, priority on adapter work, and
your brand in README.md. Everything in Production. Minimum three months.
```

**Rewards to enable:** everything in Production, plus the brand acknowledgment.
Enforce the minimum outside GitHub's form — GitHub has no "minimum term" field, so
it belongs in the description, which is why it is in the text above.

---

## Two settings that are not tiers

* **`.github/FUNDING.yml`** already points the repository's Sponsor button at
  `github: theaaqibjavaid`. Nothing to change there; it is what makes the badge in
  `README.md` resolve.
* **Links on the profile page.** Add `https://github.com/theaaqibjavaid/SWP-1`,
  `https://github.com/theaaqibjavaid/SWP-1/blob/main/SPONSORS.md`, and the
  repository's Discussions. The second link matters more than it looks: a sponsor
  who reads what sponsorship does *not* buy before paying is a sponsor who does not
  dispute the invoice later.

---

## Before publishing, in this order

1. Confirm the amounts. They are a recommendation for a single-maintainer CLI in a
   niche category, not a market rate you asked for and not something this
   repository can verify. `SPONSORS.md` carries them, so change both files.
2. Check what GitHub's form actually asks. Field labels and character limits are
   GitHub's to change, and the counts above are this file's, not a citation.
3. Read the two clauses this design has to stay inside, from
   [GitHub's Sponsors additional terms](https://docs.github.com/en/site-policy/github-terms/github-sponsors-additional-terms):
   no *misrepresentation about the reasons you are raising funds*, and no *offer of
   securities, equity, or investment*. The first is why every benefit below is
   written as something a person does, not something a product unlocks. The second
   is why Tier 3 sells engineering hours and a name in a README, and never a stake
   in the project — say so out loud if a sponsor asks.
4. Note that a one-time "donation" without a Subscription offer is not routed
   through GitHub's payouts at all: those go to your own payment processor. If the
   Supporter row above is created as a donation rather than a tier, it will not
   appear in the monthly GitHub statement.
