# Maintainers

Who is responsible for this repository, how to reach them, and how that list
changes. The conduct-reporting route in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
and the security route in [SECURITY.md](SECURITY.md) both point here, so the
addresses below are the ones those processes depend on.

## Roles

| role | who | what they decide |
| --- | --- | --- |
| Owner | `[GitHub organisation owner]` | the repository, its settings, the sponsor arrangement, and who else has write access |
| Lead maintainer | `[name · GitHub handle · email]` | what merges, and the wording of a claim in the documentation |
| Maintainer | `[name · GitHub handle · email]` | triage, review, and release builds |
| Security contact | `[name or alias · address · key fingerprint]` | intake of a private advisory and the embargo decision |

Fill these in before the first public release, with people rather than aliases
where possible. An empty table is how a security report ends up in a public issue.

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

The copyright holder of SWP-1 and the party named in [CLA.md](CLA.md) are
`[legal entity name]`. Where that is an individual rather than an entity, say so
in the CLA's §9 before the first external contribution is signed; a licence grant
to a party that does not exist is a grant nobody can rely on, and this project's
contributors deserve a counterparty they can point at.
