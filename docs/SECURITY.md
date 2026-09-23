# Security

What SWP-1 protects, how it protects it, and — the part this page exists to be
honest about — where the boundary is between *protected by construction* and
*protected because nobody wanted it badly enough*.

One sentence frames everything below. A public copy of your project, plus
`.swp/public/`, is enough for anyone to *verify* a watermark but not to *compute*
one. The only thing standing between a stranger and the codes your sites carry
is the 256-bit root secret, and it is the only artifact in this system whose loss
or theft changes what the tool can prove.

This page answers "where is the secret, and what holds it there", then works
attack by attack in [Attacks, and what still gets
through](#attacks-and-what-still-gets-through). The rules the secret produces are
in the spec's [Keys and identities](SWP-1-SPEC.md#3-keys-and-identities) and [Site
identity](SWP-1-SPEC.md#4-site-identity-the-four-radius-keys).

---

## Contents

* [What is being protected, and from whom](#what-is-being-protected-and-from-whom)
* [Attacks, and what still gets through](#attacks-and-what-still-gets-through)
* [The one secret, start to finish](#the-one-secret-start-to-finish)
* [The key hierarchy](#the-key-hierarchy)
* [What is signed, and what a signature does not buy](#what-is-signed-and-what-a-signature-does-not-buy)
* [The public and private line](#the-public-and-private-line)
* [What each artifact costs to lose](#what-each-artifact-costs-to-lose)
* [Keeping the secret out: the leak sweep](#keeping-the-secret-out-the-leak-sweep)
* [A candidate tree is hostile input](#a-candidate-tree-is-hostile-input)
* [Offline, and how to check that claim](#offline-and-how-to-check-that-claim)
* [What is trusted](#what-is-trusted)
* [What SWP-1 must not claim](#what-swp-1-must-not-claim)

---

## What is being protected, and from whom

SWP-1 is not access control. It does not hide your source, does not prevent a
copy from running, and does not gate who may use a file. It protects two things,
and both are narrow:

1. **The unforgeability of provenance claims.** Someone without your root secret
   cannot produce a watermark that your scanner confirms, cannot compute the code
   at a location in your project, and cannot edit a signed release record without
   that edit being visible.
2. **Your own ability to say "I cannot see all of it".** Every resource bound
   that a hostile repository can reach is set to fail *toward the truth*: a
   scan that was stopped reports `INCONCLUSIVE`, never `NO_PROVENANCE_DETECTED`.
   A watermark that is quietly truncated into a clean result is worse than no
   watermark, because it is a negative answer that nobody earned.

Four adversaries, and what stands in each one's way:

| adversary | wants | stopped by | not stopped |
| --- | --- | --- | --- |
| a copier of your published source | to use it undetected | the keyed constellation in the literals themselves; the codes are not computable without your secret | a rewrite thorough enough to remove every site — see [Attacks, and what still gets through](#attacks-and-what-still-gets-through) |
| a thief of your repository | to forge or strip evidence | `.swp/private/` being gitignored *and* ACLed; the manifest holding no tags | reading a stolen manifest as a map of where to cut, which is exactly what it is |
| the owner of a tree you scan | to make your scan lie or crash | the bounds, the name checks, the never-execute rule, and the fact that a candidate's own `.swp/` is never consulted | making the scan inconclusive, which is a real cost and is reported |
| someone who wants to frame you | to make an innocent tree carry your marks | they need your root secret, or your private manifest, for that site list is keyed and theirs is not | planting *their* fragments into a tree you then scan — which the coincidence bound keeps at a lead rather than a finding |

## Attacks, and what still gets through

Ten attacks, what each one achieves against this build, and the suite that
measures it. Run them yourself with
`cargo test -p swp-test-suite --test <name>`.

The outcomes below are the shape of one measured run: a synthetic 12-module tree
protected to 24 sites, built in debug, scanned under a root secret minted for that
run. Confirmed-site counts and verdicts are what the run fixes; which literal
carries a site, and therefore the probe and chance figures, are the key's choice
and move between runs. [VALIDATION.md](VALIDATION.md) has the numbers this build
prints, and the commands that printed them.

| attack | what it gets | measured by |
| --- | --- | --- |
| Casual copying — a fork, a vendor directory, one pasted file | nothing. An unedited copy reproduces the keyed addresses *and* the exact renderings, and its canonicalized tree hashes to the release fingerprint | `detection_matrix` |
| Normal refactoring — renames, reformatting, moving a function between files | nothing much. Addresses are computed over abstraction-normalized surroundings, so the statement is found while its text is not | `detection_matrix` |
| Intentional removal by somebody who holds the source | a win, at a visible cost. `swp inspect fragments` lists every site, so the marks are unobtrusive rather than secret; removing them leaves `stripped` addresses, which a report prints and the ladder weighs as nothing | `adversarial_removal` |
| Watermark discovery from published source alone | everything it needs to start: a shape search over the literals finds the sites without your secret | `adversarial_removal` |
| Theft of your private manifest | a removal tool, not a forgery tool. It names every site and carries no tags, so it cannot make a new statement confirm | `adversarial_removal` |
| Theft of the root secret | total. The holder can compute your codes and sign records in your name; the blast radius is bounded by the OS account the seal is tied to | `secret_leak`, `crates/swp-crypto/src/seal.rs` |
| False-positive attacks — an unrelated tree made to resemble yours | a lead, not a finding. Chance confirmations are covered by the coincidence bound, which holds the verdict at `INCONCLUSIVE` | `false_positive`, `collision` |
| Source poisoning — their code lifted into your project before protection | your release can come to cover their code, so a later scan says *yours* about a fragment you absorbed. Protect reviewed source, not pasted source | `adversarial_removal` |
| A malicious repository as scan input | time and memory, if the bounds did not exist. They do: every ceiling reached is recorded as an omission, and a scan that was stopped says `INCONCLUSIVE` | `resource_limits` |
| Parser exploitation — a file aimed at the tree-sitter grammars | the residue this page cannot argue away: the grammars are C. Input is bounded and never executed; memory safety is the parsers' problem, not this design's | `resource_limits` |

And the shorter list of what none of them buys. Without your root secret, an
attacker cannot:

* compute a code for a location your manifest does not already name, and so
  cannot make a *new* statement confirm;
* sign a release record or manifest that `swp verify` accepts — one flipped
  character is `INVALID_MANIFEST` and exit `5`;
* make your scanner accuse a tree of carrying your release without that tree
  carrying code from your release;
* read your project's identity out of a public copy, only the id you published;
* make an inconclusive scan look like a clean one.

## The one secret, start to finish

**Minted, not chosen.** `swp init` draws 32 bytes from the operating system's
random source (`getrandom`, the same primitive Rust's crypto ecosystem uses) and
wraps them in `RootSecret::from_bytes`, which refuses any other length. There is
no passphrase, no KDF, no default, and no way to supply a key of your own: the
only environment variable the product reads about secrets is `SWP_SECRET_PLAIN`,
which changes how the key is *stored*, never what it is.

**Sealed at rest, in two independent layers.** `.swp/private/root.key` is an
envelope — the literal header `swp1-secret-v1`, a `scheme:` line, and a base64
payload:

* On Windows the payload is protected with DPAPI in **user scope**, so the bytes
  are unreadable to any other account on the machine and to the same account on a
  different machine. The header is why a hand-edited or truncated file produces
  "unrecognized secret file format" rather than a wrong key.
* Independently of that, the file's access control list is replaced with one
  granting only the current user, and then **read back and parsed**. `icacls`
  must show the grant and must show no inherited entries. Anything less is
  reported, and for a private artifact an unconfirmed hardening is an error: the
  store refuses to keep the file and says so — *"refused to keep a private
  artifact whose access could not be confirmed"*. That check exists because
  `std::fs::set_permissions` on Windows reports success while changing nothing;
  a permission call that is not verified is a permission call that did not
  happen.

So the `permissions verified` in `swp init`'s output is not a claim that the ACL
*should* be tight — it is the parsed read-back of `icacls` after the change. On
non-Windows the same function sets `0600` and re-reads `metadata` to confirm it,
with the same three-way outcome: verified, set-but-unconfirmed, or unavailable.

**Which layer does what.** The honest limit, stated in the source that
implements it: *anything running as you can read the secret*. DPAPI does not
change that. What it changes is what a stolen backup, a second account on the
machine, or a lifted disk image can do with the file. `SWP_SECRET_PLAIN=1` gives
the first layer up — the file then holds the key itself, ACL only — and exists
for the cases where DPAPI's portability guarantee is the thing in your way:
container images, backup tooling that must copy a key between machines, CI. With
it set, the ACL and your volume encryption are the whole at-rest protection, and
that trade should be a deliberate one.

**Loaded, used, dropped.** Four commands ask for the secret at all — `generate`,
`protect`, `verify`, `scan`. `init` mints it, and `inspect` and `report` run
against the public half with no key present, which is what lets a third party
check a release record. On load the store does one extra thing beyond unsealing:
it derives the project id from the key and compares it with
`.swp/public/identity.json`, and stops if they disagree. A key and an identity
from different backups would derive every fragment wrongly and then report "no
evidence" about code that is plainly yours; one clear message is worth more than
a confident wrong answer.

**In memory, it is not printable.** `SecretBytes` wraps `Zeroizing<Vec<u8>>`: no
`Display`, no `Serialize`, no `Clone`, and a `Debug` impl that reports only a
length. `RootSecret` is the same story (`RootSecret([REDACTED])`), and its raw
bytes are reachable only through a `pub(crate)` accessor, so they never leave
`swp-crypto` as a `&[u8]` a caller can log. Two things may be said about a key
without saying it: `same_as`, a constant-time comparison, and `fingerprint()`, a
40-bit check value computed with the *public* label as the HMAC key and the secret
as the message. The latter is the handle `swp init` prints (`handle oowhrb3s`) and
it exists so that a restored backup can be recognised as the right one. It is a
check value of the key, not a MAC of a constant under it, so there is no offline
search from the printed eight characters back to the 256 bits.

**Not rotatable, on purpose.** The project id, the signing key and every location
id in every manifest you have ever published hang off this one value. Replacing
it would not be a credential rotation; it would silently invalidate every
release the old key signed. So `Store::init` refuses to overwrite an existing
key, `swp init` on an initialized project is a no-op for the secret, and there is
a test named `init_is_idempotent_and_never_rotates_the_secret` to keep that from
being an accident of the current code. If a key is genuinely compromised the
recovery is a new `swp init` — a new project, new ids, and old copies still
carrying marks only the old key can prove.

## The key hierarchy

Seven labelled purposes, five in use, two spent so a future protocol version
cannot give an old label a new meaning. Every derivation is
`HMAC-SHA-256(key = root, message = framing ‖ fields)` with the framing
`SWP-1\0<domain>\0<protocol u16>`, a field count, and every field length-prefixed.

| domain | derives | its answer | what it would cost an attacker |
| --- | --- | --- | --- |
| `identity` | the project id | `swp1-` + 16 base32 characters, 80 bits | nothing: it is published, and knowing it grants no derivation |
| `project` | the site key | location ids — "which site is this?" | would let them *recognize* your sites in a tree, not place new ones |
| `location` | the tag key | the code each site carries | the whole game: this is the key that makes a watermark forgeable |
| `selection` | the selection key | which candidate sites a release uses, and in which form family | which sites to look at, given a manifest; the codes are still elsewhere |
| `signing` | the ed25519 seed | signatures on the manifest and the release record | forged release records *for your project* |
| `release`, `evidence` | — | reserved in v1 | — |

Three properties here are load-bearing rather than stylistic, and all three are
tested:

* **Domain separation is enforced, not assumed.** `hmac_keyed` refuses a key
  whose recorded domain does not match the derivation it is being used in, so
  mixing two rows of that table is a loud internal error rather than a quiet
  wrong answer. `wrong_domain_is_refused` and `domains_do_not_share_keys` pin it.
* **The field encoding is injective.** Length prefixes, and a prefixed field
  count, so `["ab","c"]`, `["a","bc"]` and `["ab\0c"]` cannot land on the same
  message. Bare separators would collide, and a collision between two sites'
  identities is a false positive with a signature on it.
* **The construction is borrowed, not invented.** The root is already a uniform
  256-bit key, so HMAC-SHA-256 over an injective encoding *is* HKDF-Expand, which
  is what RFC 5869 prescribes for that case; HKDF-Extract would add salt ceremony
  without adding strength. Truncating a MAC to `tag_bits` takes the low bits of
  the first big-endian word and every width in use divides 2³², so the mask is
  exact and there is no bias to correct. No primitive in `swp-crypto` was written
  here: `sha2`, `hmac`, `ed25519-dalek`, `getrandom`, `zeroize`, `subtle`,
  `base64`, plus `crypt32` for DPAPI. That list is the whole crypto surface, and
  `cargo tree` is the check.

The asymmetry that makes re-protection safe is deliberate: location ids and tags
are keyed by the **project**, not the release, so protecting a second time keeps
every unchanged site's mark and each release *adds* coverage. Selection is keyed
by the release too, because which sites a release happens to use is
release-specific information, and a second constellation should be reachable
without rotating the first.

## What is signed, and what a signature does not buy

Both documents a release produces are signed by one rule, written down in exactly
one function (`swp-manifest/src/sig.rs`):

```text
canonical JSON of the document, with the "signature" field removed
    → ed25519 under the project's signing key
    → base64, back into the "signature" field
```

Removing the field rather than signing a hand-written prefix is the part that
matters: a signed prefix that later forgets a newly added field silently
un-binds that field from the signature, whereas here a new field is covered the
moment it appears in the struct — and a test asserts that for the fields that
exist today. Signing is deterministic per RFC 8032, so release records stay
diffable.

What the signature proves is precisely one thing: that this document was written
by whoever held the root secret, and has not been edited since. `swp verify` and
`swp inspect` check it, on the public record as well as the private manifest.
That check was added after an earlier build verified only the manifest — the
record is the *committed* half, the one an attacker who can push to your
repository can reach, and an editor who flips one character of its fingerprint
should not be rewarded with a green run. They are not:

```console
$ swp inspect releases -p .
error [INVALID_MANIFEST]: release record: manifest signature does not verify
  next: Re-run with --release <id> naming an intact release under .swp/public/releases/. If the file is genuinely corrupt, restore it from your provenance backup; a manifest cannot be regenerated without the root secret.
exit 5
```

What it does not prove is the thing a signature is often asked to prove. A
release record states that a project with this id published a tree with this
fingerprint on this date, using this build. It does not prove the claim was true,
that the publisher had the right to publish, or that the date is honest — the
timestamp is this build's, not an authority's. There is no certificate chain, no
registration authority and no revocation list in SWP-1: the verify key is
self-signed in the sense that `identity.json` is its own trust anchor, which also
means **whoever can edit your `identity.json` can substitute a key**. The
residual protection is the one every public key has: distribute it through a
channel you already trust.

Two artifacts are deliberately *not* signed: reports, because a report is an
observation made by whoever held the secret at that moment and signing it would
make a forwarded document look like a statement from the project rather than from
the scan; and `identity.json`, because it holds the key that would have to sign
it.

## The public and private line

The split is a table in code (`swp-manifest/src/classify.rs`) that `swp init`,
`swp inspect store` and the tests all read, so the document, the CLI and the
product cannot disagree about what is safe to commit:

```console
$ swp inspect store
store .swp — project swp1-…
  secret      present · .swp/private/root.key
  counts      1 release(s), 1 manifest(s), 2 plan(s), 1 report(s)

  artifact                                           may commit
  .swp/config.toml                                   yes
  .swp/private/manifests/rel-….json                   never
  .swp/private/plans/rel-….json                       never
  .swp/private/root.key                              never
  .swp/public/identity.json                          yes
  .swp/public/releases/rel-….json                     yes
```

`init` appends `.swp/private/` to your `.gitignore` under its own marker comment
without clobbering the file, and reports `created`, `updated` or `already
ignored` accordingly. That is a convenience, not a control: the control is that
everything under `private/` is written through one function which tightens its
ACL and reads it back.

The line is drawn by **capability**, not by field name. A public document names
the project, describes a release, and carries a fingerprint — it contains no
location ids, no tags, and no source text. A private document holds keyed
addresses, your file paths, and both literal spellings at each site. Losing a
public file costs a record; losing `root.key` or the manifests costs the ability
to prove provenance at all, which is why every `init` and `protect` transcript
ends by naming those two paths as the backup.

The public half of the identity is worth reading in the tool's own words:

```console
$ swp inspect identity
identity .swp/public/identity.json

  project     swp1-…
  display     javascript
  protocol    SWP-1 · schema 1 · canonicalizer 1
  generator   swp-cli 1.0.0
  verify key  … (ed25519, 32 bytes)

  This file is public by design: the verify key authenticates this project's
  manifests and release records, and anyone holding it can check them. Nobody
  holding it can produce one — the signing key is derived from the root secret and
  is never stored. The project id is that same derivation, so changing the display
  name here never changes which copies are yours.
exit 0
```

That paragraph is not decoration. The signing key is recomputed per run from the
root secret and never written to disk — there is no key file for it to leak out
of — and the project id is a derivation of the same secret, which is why editing
`display_name` cannot change which copies of the tree are yours.

## What each artifact costs to lose

The manifest is the one people misjudge, because rule 1 of `swp-manifest` sounds
like a confidentiality guarantee and is not the whole of one:

> The expected tag is never stored.

True: no manifest, plan, report or release record holds a tag integer, and
`swp verify` recomputes each site's expected code from the root secret at the
moment of the comparison and drops it. That rule exists so that stealing the
document that *explains* the watermark is not the same as stealing the watermark.

But the same document lists every site, its primary radius key, and **both
literals** — the text before the rewrite and the text after. Which is what the
view that prints it warns about, in the product's own words:

```console
$ swp inspect manifest --release …
warning: this view prints the signed site list, which is every site's keyed site addresses, its file and line, and both literals. It is your own copy of the watermark: do not paste it into an issue, a build log or a document you mean to share.
manifest … — signed, and authenticated against this project's verify key
  sites       10 · 4 bit(s) each · canonicalizer 1
  …
exit 0
```

So a stolen private manifest is a **removal tool**: it tells an attacker exactly
which statements to normalize and what to write instead, and a full revert of the
protected files took a measured 24-site release to zero confirmed sites. What it
is not, on the evidence this build has, is a **framing tool**: fragments planted
from one project into an unrelated tree were scanned by both owners' keys and
confirmed nothing for either, because the planted renderings are not a
constellation and the coincidence bound says so. Its confidentiality therefore
does not come from anything keyed inside it. The
public release record carries a digest of the manifest, and a digest of a
guessable document is testable in one hash by anyone holding a candidate tree —
the record's own source comment says this out loud. The manifest is private
because `.swp/private/` is ACLed, gitignored and backed up carefully, and for no
more reason than that.

| lost or stolen | an attacker gets | you lose |
| --- | --- | --- |
| `identity.json` | the verify key, the project id | nothing; it is meant to be public |
| a release record | fingerprint, counts, tag width, canonicalizer version, manifest digest | nothing if it is edited instead: the signature fails, exit `5` |
| a plan | the intended constellation *and every refusal* — the sites that were not used | coverage knowledge; still no codes |
| a report | your paths and a candidate's text, side by side | confidentiality of the fact that you scanned that candidate |
| a private manifest | every site and both of its spellings | nothing unforgeable; the derivation domains stay unreachable |
| `root.key` | the tag key: forge your marks, compute any site, sign any release | the ability to *deny* having issued a forged record, and every release's trustworthiness until you rotate by starting a new project |

## Keeping the secret out: the leak sweep

The rule this build holds itself to is absolute in one direction: the root
secret, any key derived from it, and any expected tag appear in **no** artifact —
not source, not manifests, not reports, not stdout, not logs, not error messages,
not temporary files. That is not auditable by reading, so it is asserted by
`cargo test -p swp-test-suite --test secret_leak`, which installs a root secret
of *known* value into a real store and then sweeps for it. Two needles, not one:
the master key and a raw keyed MAC output — because an implementation that
resists printing the master while happily printing a per-location MAC has leaked
a derivable half of the same thing.

| test | what it looks at |
| --- | --- |
| `nothing_in_the_store_but_the_root_key_file_leaks_the_secret` | every file a real store holds, with `root.key` the one permitted hit |
| `root_key_file_holds_only_sealed_material` | the permitted file itself: envelope header, scheme line, no plaintext key |
| `public_and_private_artifacts_built_from_the_key_are_clean` | manifests, plans, release records and identities constructed from the key |
| `debug_renderings_of_every_secret_bearing_type_are_redacted` | `{:?}` of every type that can hold key material |
| `error_messages_never_quote_key_material` | the error paths, which is where a `format!("{:?}", secret)` in a message would surface |
| `no_temporary_or_backup_file_survives_a_write` | the `.name.tmp` siblings the atomic writer creates |
| `every_command_prints_and_writes_nothing_searchable` | **every** verb the CLI offers, in both formats, with the flags whose purpose is to print more, sweeping stdout, stderr and every file each run wrote |

What the suite says about its own limit, from its header, is worth repeating
rather than rounding off: it checks the commands that exist, not every way to
reach them, and a flag combination no suite has ever run is a flag combination
nobody has swept. The per-command non-vacuity assertions in the last test are
what keep that gap narrow rather than merely invisible.

## A candidate tree is hostile input

SWP-1 must never execute an untrusted project, and `swp-detection` takes it
literally: **no process is spawned anywhere in that crate**. The only
`Command::new` in the entire product is `icacls`, in `swp-crypto`, run against a
file the store is hardening — never against a candidate.

An archive is treated as a source carrier, not a program. The only operations
performed on one are "list" and "copy out a regular file", and an entry is
written only when its name resolves to a plain relative path beneath the temporary
root:

* no absolute paths, no drive letters, no verbatim `\\?\` prefixes;
* no `..` component at any position in the name;
* symlinks, hardlinks, devices, fifos and sockets are skipped, not extracted —
  a symlink inside an archive is a write to somewhere else, which is the exact
  thing the name check exists to prevent;
* `tar`'s `setuid`, `setgid` and mode bits are not applied, because the extracted
  tree is read and then deleted.

Then the bounds, from `swp-core::Limits`, five of them around containers alone —
entry count, per-entry size, cumulative expanded bytes, per-entry compression
ratio, and how many levels deep a container may be opened, since a 42-byte zip can
expand to terabytes. The defaults, with the hard ceiling in parentheses:

| key | default | ceiling | guards |
| --- | --- | --- | --- |
| `max_file_bytes` | 8 MiB | 64 MiB | reading a file at all |
| `max_parse_bytes` | 4 MiB | 32 MiB | handing a file to an AST parser |
| `max_nodes_per_tree` | 2,000,000 | 8,000,000 | keeping a tree |
| `max_depth` | 256 | 512 | nesting canonicalized, and directories walked |
| `max_parse_millis` | 2,000 | 20,000 | wall clock per document |
| `max_files` | 200,000 | 1,000,000 | the size of a walk |
| `max_total_bytes` | 8 GiB | 64 GiB | cumulative bytes per operation |
| `max_sites_per_file` | 4,000 | 20,000 | candidate sites one file can offer |
| `max_archive_entries` | 10,000 | 100,000 | entries listed |
| `max_archive_member_bytes` | 64 MiB | 256 MiB | one member |
| `max_archive_expanded_bytes` | 2 GiB | 16 GiB | a container's whole output |
| `max_archive_ratio` | 200 | 1,000 | decompression bombs |
| `max_archive_depth` | 1 | 2 | archives inside archives |
| `max_locations_per_manifest` | 4,096 | 16,384 | a signed site list |
| `max_digest_set_entries` | 4,000,000 | 16,000,000 | the region working set |
| `max_shingles_per_region` | 32,768 | 262,144 | structural comparison memory |
| `max_rendered_items` | 400 | 10,000 | how much a report prints |

Two things about that table are security properties rather than tuning:

* **Configuration may lower a limit and never raise it past the ceiling.** A
  value above the ceiling is clamped, with a warning naming what was clamped. The
  point of a limit is that the author of the repository being scanned cannot
  argue it away.
* **Hitting a bound is never a negative answer.** Exceeding a walk bound is
  `LIMIT_REACHED` (exit `7`); an incomplete examination of a candidate is
  `INCONCLUSIVE` (exit `10`) with each unexamined part named and reasoned. "As
  much as fit" would let a deliberately explosive archive win by making the scan
  look clean:

```console
$ swp scan ./copy -p .
warning: this scan could not examine the whole candidate … it can say nothing was confirmed, not that nothing is there
scope     0 file(s), 0 byte(s) — PARTIAL, see notes
result    INCONCLUSIVE
evidence  NONE
exit 10
```

The same discipline covers the other two ways a hostile tree can try to talk to
the scanner. It is never asked what it wants: `Store::discover` walks up from a
directory to find an enclosing project, and the scanner does not call it on
candidate input, because a third-party repository that ships its own `.swp/` must
not get to supply the keys your build verifies against. And a candidate that
breaks a parser is answered, not crashed — malformed UTF-8, embedded NULs,
truncated files, 4,000 nested blocks and 200 KB of semicolons all produce a named
omission and an inconclusive verdict in `tests/resource/hostile.rs`.

## Offline, and how to check that claim

SWP-1 makes no network call in any code path, uploads nothing — not your source,
not your reports, not a usage ping — and requires no account, server or registry.
That is not a preference with a config switch: nothing in the dependency graph
can open a connection, and the three grammars are compiled into `swp-adapters` as
prebuilt sources, so a build on a machine with no network succeeds. The shipped
binary pulls 77 third-party crates transitively — `serde`, `sha2`, `curve25519`,
archive readers, the grammars, and their proc-macro machinery — and none of them
is an HTTP client or a socket library.

Three ways to check that without trusting this page:

```bash
cargo tree -e normal | grep -iE 'reqwest|hyper|ureq|curl|socket|tokio'   # no output
grep -rn "TcpStream\|UdpSocket\|reqwest\|ureq" crates/*/src/             # no output
```

and, on Windows, a firewall rule that blocks the binary while you run a full
`init → generate → protect → verify → scan` cycle. Every command in that cycle
has to work with the outbound path closed, including `icacls`, which is a local
process spawn and not a connection.

## What is trusted

Trusting less is the goal; claiming to have achieved it is the failure mode. Here
is what this build actually relies on.

| trusted | for | why it is on this list |
| --- | --- | --- |
| the OS account you run as | everything, including the sealed key | the seal is per-user; a process with your token is you, and no document should pretend otherwise |
| your own `.swp/` store | configuration and keys | a candidate's store never is; yours is the trust anchor of your own provenance |
| the toolchain and the vendored crates | correctness of SHA-256, HMAC, ed25519, DPAPI, and the tree-sitter grammars | nothing here invents a primitive; the compiled-in grammar sources are third-party parsers and belong in your supply-chain audit |
| `icacls` | the read-back that makes `permissions verified` mean anything | it is a Windows tool, invoked with paths this store is hardening |
| your backup discipline | whether a release is provable a year from now | `root.key` and the manifests are unrecoverable if both go, and no property of the protocol brings them back |

And what is *protected*, in the other direction: the candidate tree you scan is
never trusted, never executed and never consulted about how it should be judged;
your source text is protected from egress by the offline rule; and the person who
ends up holding a report is protected from over-reading it by the limitations
block that travels inside every report.

## What SWP-1 must not claim

The prohibition runs on the documentation as well as on the code, and the
documentation defers. SWP-1 does not guarantee:

* **legal ownership** — nothing here adjudicates rights;
* **proof of authorship by itself** — a watermark shows that a tree carries the
  marks of *your release*, and needs its own corroboration to say who wrote it;
* **detection after arbitrary rewriting** — a rewrite thorough enough to remove
  every site removes them; [Attacks, and what still gets
  through](#attacks-and-what-still-gets-through) has the measured case;
* **detection after complete reimplementation** — code written fresh from an
  understanding of the algorithm carries no literal of yours;
* **immunity from deliberate watermark removal** — the marks are unobtrusive, not
  secret, and a maintainer of your own tree can find them by folding the shapes
  that have no reason to be there;
* **detection of every possible copy** — a copy below the site budget, or one
  whose files were all excluded from the walk, is not found;
* **zero false positives** — unrelated trees *do* reproduce keyed addresses and
  *do* occasionally confirm a single site by chance; what the coincidence bound
  does is keep those at `INCONCLUSIVE` rather than at a finding.

What SWP-1 provides is technical provenance evidence: an explanation of a scan in
terms a reader can check, that survives being forwarded, and that says
`INCONCLUSIVE` when it has earned nothing better.

---

Related: [`SWP-1-SPEC.md`](SWP-1-SPEC.md) — the protocol these rules come from ·
[`USER-GUIDE.md`](USER-GUIDE.md#reading-a-report) — what a report may be used to
claim · [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) ·
[`VALIDATION.md`](VALIDATION.md) · [`../SECURITY.md`](../SECURITY.md) — how to
report a problem here
