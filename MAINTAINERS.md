# Maintainers

Who is responsible for this repository, how to reach them, and how that list
changes. The conduct-reporting route in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
and the security route in [SECURITY.md](SECURITY.md) both point here, so the
addresses below are the ones those processes depend on.

## Roles

| role | who | what they decide |
| --- | --- | --- |
| Owner | Aaqib Javaid · [@theaaqibjavaid](https://github.com/theaaqibjavaid) · aaqib100javaid@gmail.com | the repository, its settings, the sponsor arrangement, and who else has write access |
| Lead maintainer | Aaqib Javaid · same as above | what merges, and the wording of a claim in the documentation |
| Maintainer | justin-coders · [@justin-coders](https://github.com/justin-coders) | triage, review, and release builds |
| Security contact | Aaqib Javaid · aaqib100javaid@gmail.com · no key published | intake of a private advisory and the embargo decision |

Three of those four rows are the same person. That is stated rather than
smoothed over, because two documents depend on it: a security advisory has one
intake reader and no second pair of eyes before the embargo decision, and the
conduct route in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), which promises that a
report is read by at least two maintainers where that is possible, cannot deliver
that promise for a report about the owner. What follows from this list is that
adding a second maintainer who is not the owner is the highest-value
contribution available to this project, and [ROADMAP.md](ROADMAP.md) does not need
to say so for it to be true.

A role here is a set of decisions somebody answers for, not a badge: the lead
maintainer is the person who says no to a change that would make a report claim
more than its measurement supports, and the security contact is the person who
decides whether an embargo is worth the exposure.

## Reaching the project

For everything that is not a security report, an issue or a discussion is better
than a direct message: it is the record, and somebody else usually has the same
question. [SUPPORT.md](SUPPORT.md) has the routes.

## Becoming a maintainer

Contribution is the only route. The standing that counts here is a history of
correct calls in review — including in documentation, where the judgement is the
same kind — and a merge is a maintainer's statement that they will answer for it
afterwards. Write access is granted by the owner, added to
`.github/CODEOWNERS`, and recorded in the commit that adds it.

## Stepping back

A maintainer who cannot answer for the role should say so in a pull request that
removes themselves from `CODEOWNERS`, and that change is accepted without
discussion. Silence is not a role. Where the departing maintainer was the security
contact, the replacement is named in the same change, because
[SECURITY.md](SECURITY.md) publishes the contact as part of a disclosure path.

## Legal identity

SWP-1's copyright holder is **Aaqib Javaid**, and the party that takes
contributor grants in [CLA.md](CLA.md) §9 is **Yeast Technologies**, a business he
owns; `NOTICE` names both on one line. The distinction matters to a contributor,
who should be able to point at a counterparty, so it is stated in the CLA rather
than left to be inferred from a GitHub account. As the project stands on two named
people and one company, all of them the same interest — which is exactly what a
CLA discloses by putting the entity's name in §9.
