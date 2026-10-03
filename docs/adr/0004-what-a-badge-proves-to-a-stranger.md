# ADR-0004 — what a badge can prove to somebody who has never met you

**Status: proposed, with a position.** The documentation passes that shipped the badge
and the registry index removed every claim that those two public documents did more than
they do. This record settles the question those passes leave standing — the last sentence
people will still read into them — and states what would have to change before the answer
could be different.

## 1. Problem

`swp registry search <file>` and `swp badge show` prove a document was not edited. They
do not prove the document came from somebody the reader trusts, because the key that
signed the claims travels inside the claims: `RegistryDocument` carries `project_id` and
the public `verify_key` (`crates/swp-cli/src/registry.rs:51-57`), and a badge embeds
`ProjectIdentity` whole (`crates/swp-cli/src/badge.rs:48`).

The one real pin available today is a local store. Run inside a project, the readers
compare the document against `.swp/public/identity.json` — that is what
`badge.rs:214` and `registry.rs:331` do, and what makes a copied badge refuse to print.
Run outside one the two commands differ, and the difference is the whole question:
`registry search` degrades on purpose, printing the index after a warning that names the
weaker reading (`registry.rs:301-311`, and `docs/CLI.md:424-427` says the same in prose),
while `swp badge show` opens the store as its first act (`badge.rs:179`) and so has no
path for a stranger's file at all. `docs/SWP-1-SPEC.md:432` lists key sharing, delegation
and a registry service as non-goals.

So the gap is exactly one question: *what does a reader do when they have your
`badge.json` and no store of their own?*

## 2. Options

* **A — say nothing more.** A badge is a self-authenticating statement by an author about
  their own project. A reader who needs binding goes to the repository the badge names,
  where the pin exists. Costs nothing; keeps the ceiling where SPEC put it.
* **B — a key the reader imports out of band.** `--trust <identity.json>` or a pinned
  keyring, so a badge or index can be checked against a key chosen separately from the
  document it authenticates. This is the only option that actually answers the question.
  It needs: a pin file format and its own schema row, a decision about what happens to a
  pinned key whose project later re-generates, an error code and exit row, a line in
  `docs/CLI.md` and `docs/TROUBLESHOOTING.md`, and a `secret_leak` pass over the new
  artifact class. And its honest weakness is that out-of-band key exchange is the step
  almost nobody performs, so the feature would ship used by a fraction of its audience.
* **C — borrow an external signer** (a git tag, a cosign-style attestation). Real trust,
  but it places SWP-1's claim inside somebody else's root of trust and makes the verdict
  depend on a service. Rejected on the same ground as a registry service.

## 3. Position

**A, for now.** The two documents are publisher-side artifacts, and the wording they
shipped with says exactly that wherever a reader meets them. B is a protocol change, not
a feature: it defines a relationship between two projects' keys, which
`docs/SWP-1-SPEC.md:432` currently refuses to define, and SPEC §16 is where a change of
that size belongs.

**What would flip this position:** evidence that readers actually try to verify a badge
they found outside the project — for example repeated requests to make `badge show` work
on a stranger's file. That is a demand for a trust channel, and the right answer to it is
an ADR that supersedes this one and amends SPEC §16, with B's format, codes and leak
coverage designed in it, rather than a relaxed check in the reader.

## 4. Rejected within B

* **Deriving a badge-specific "anchor key" from the root secret** and publishing it. That
  is key material derived from the secret in a committable public file. It would also
  spend a derivation label: `Domain` (`crates/swp-crypto/src/derive.rs:31`) is a closed
  protocol decision, and its two unused labels — `Release` and `Evidence` — are reserved
  precisely so a later version cannot give them a second meaning. Adding an eighth purpose
  to make a badge look authoritative is the wrong trade.
* **Trusting the first document seen** (a trust-on-first-use keyring). TOFU would record a
  key an attacker could have supplied first, which is weaker than the warning it removes.
* **Letting `badge show` print an unpinned claim with a caveat**, the way
  `registry search` does. A registry index is a list of a project's releases, and a reader
  can use it as a lead. A badge is a claim of standing, and printed with a caveat it reads
  like the verified thing.

## 5. Follow-ups

If the owner wants B explored, the first deliverable is a draft schema for the pin file
and the answer to one question: is a pinned key per project, per author, or per machine.
