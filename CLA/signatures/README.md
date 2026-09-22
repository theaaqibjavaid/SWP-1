# Signed contributor statements

One file per contributor, named `<github-handle>.md`, containing the fields below.
These are legal records, not documentation: they are added by a maintainer's hand
after the statement in CLA.md §9 arrives in a pull request or by email, and they are
never edited to make a check pass.

```markdown
name:   the person or entity granting the rights
email:  the address on their commits, or the one they signed with
github: their handle, without the @
date:   2026-04-02
agreement: SWP-1 CLA v1.0
employer: not applicable, or the name, title and date from §7
notes:  optional, and anything written here is readable by anyone in the project
```

The `.github/workflows/cla.yml` check matches a pull request's author by the
`github:` or `email:` field of a file in this directory. Its own README is not a
record, so its example fields are angle-bracketed rather than filled in — an address
that looks real is one that can match by accident, and a false approval here is
worse than a missed one.

If a contributor signs under an entity (`"Company X, by its counsel"`) rather than a
personal address, record the entity name in `name:` and put the address they used in
`email:`, so the two are not confused later by somebody who is not here.
