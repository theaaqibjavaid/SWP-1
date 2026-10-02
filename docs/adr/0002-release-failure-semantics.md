# ADR-0002 — what a protection run leaves behind when it refuses

**Status: accepted, and implemented in the same change.** Issue
[#26](https://github.com/theaaqibjavaid/SWP-1/issues/26) asked which invariant the
release path is supposed to hold when a run is refused, because the code and three
documents disagreed about it. This record settles that, and the disagreement is the
reason it exists.

## 1. Problem

`swp protect --revision ""` — or `--revision "   "`, which trims to the same thing —
was refused with `INVALID_MANIFEST` (exit 5) *after* the run's private manifest and
private plan had already reached disk. `bindings/node/src/options.rs` said the same
label is refused "before anything is written". [SDK_API.md §4](../SDK_API.md) described
the residue. Both could not be true, and the question was not which sentence to keep:
it was what state the store is allowed to be in.

## 2. Measurement

Every row below was produced by the release binary built from
`fix/release-contract-drift` (`f0c7279`) against a fresh `swp init` project of ten
JavaScript files, in a temporary tree, on Windows. The store paths are written
short: **M** = `.swp/private/manifests/<id>.json`, **P** = `.swp/private/plans/<id>.json`,
**R** = `.swp/public/releases/<id>.json`.

| Run refused | Error | Artifacts left | Source |
| --- | --- | --- | --- |
| `--release bad-id` | `INVALID_MANIFEST` "release id must start with \"rel-\"" | nothing | unchanged |
| `--revision ""` / `"   "` / 201 bytes / `a\tb` | `INVALID_MANIFEST` "source revision is not usable" | **M**, **P** | unchanged |
| every candidate location unsafe | `NO_SAFE_LOCATIONS` (15) | nothing | unchanged |
| manifest write blocked | `IO_ERROR` (14) | nothing | unchanged |
| plan write blocked | `IO_ERROR` (14) | **M** | unchanged |
| record write blocked | `IO_ERROR` (14) | **M**, **P** | unchanged |
| source write #4 of 10 blocked | `IO_ERROR` (14) | **M**, **P**, **R** | 3 files rewritten |

Two facts decide the question, and both are in the code rather than in a document:

* The **same artifact set** — **M** + **P**, no **R** — is produced by a disk failure at
  the record step and by a label the operator typed. The store cannot tell the two apart
  afterwards, and neither can `swp inspect store`, which reports that state as
  `0 release(s), 1 manifest(s), 1 plan(s)`.
* `refuse_replaced_release` (`crates/swp-embedding/src/protect.rs`) treats exactly that
  set as a durable condition: reusing the id is refused with *"…so this release id is
  half-recorded. Choose a new release id; the orphan is listed by `swp inspect store`
  and can be removed by hand."* **by hand** — the design declines to clean it up, and
  declines to finish it, because a release id names one signed constellation forever.

So the half-recorded state is not an accident the pipeline has not noticed. It is a
named, listed, operator-owned state whose meaning is *"a run got partway to disk."*

## 3. What was already settled elsewhere

* The module doc of `crates/swp-embedding/src/protect.rs` states the write order and
  why: records before sources, so "a run interrupted between the two leaves a release
  that `swp verify` reports as incomplete — an honest answer about a half-finished job".
  `swp protect --help` says the same to the operator. The ordering is the recovery
  property, not an optimisation, and this record does not touch it.
* `NO_SAFE_LOCATIONS` refuses before the first write and says *"Nothing was written:
  this is a refusal, not a partial success."*
* `crates/swp-embedding/src/candidates.rs` states the principle for input-derived
  refusal: reject them *before anything is written*, "instead of discovering at
  verification" time.
* Issue #15 decided the same shape of question for the store's own writer and chose
  removal: an artifact the store could not *confirm* does not stay on disk, because a
  retained unconfirmed `root.key` proved unrecoverable on the next `swp init`. That is
  the trigger there — an unconfirmed write — and it is not this one: a manifest and a
  plan that landed and were confirmed, described by a record that was never allowed to
  exist. #15's precedent therefore does not reach this case, and rollback would be the
  wrong answer here for the reason #15 gives in the other direction: those two files
  are the only account of a run the *filesystem* stopped.

## 4. Decision

**Caller input is refused before any artifact of the run reaches disk. The
half-recorded state is reserved for a run the filesystem interrupted.**

Concretely: `swp_embedding::protect()` validates `SourceRevision` at its own door,
beside `req.identity.validate()` and `req.config.validate()`, before
`refuse_replaced_release` and before the first write. The label is the operator's input,
the same class of thing as an identity, a config and a release id, and the release id of
the same run is already refused there with nothing written. `Store::write_release()`
keeps calling `ReleaseRecord::validate()`, so a caller that builds a record by hand is
still refused — the door check is not the only check.

Two consequences were accepted deliberately:

* The refusal is **mode-independent**. `Mode::Plan` and `Mode::DryRun` now reject an
  unusable label instead of succeeding and silently discarding what the caller stated.
  A label that cannot be recorded is not a label; the mode decides what the run writes,
  not whether the input is coherent. `swp generate` takes no `--revision` at all, so the
  CLI door is unchanged, and `ProtectOutcome::revision` can now only be `None` when the
  caller passed none.
* The message names its own reason (empty / over 200 bytes / control character) and
  carries a specific next step through `SwpError::with_next`, because the code-level
  `INVALID_MANIFEST` next step — *"re-run with `--release <id>` naming an intact
  release"* — describes a corrupt stored file, which is a different reading of the same
  code. The error code and exit status do not move: `INVALID_MANIFEST` already represents
  "a release document this run cannot produce", and a new code for a typo would be a
  fourth thing an operator has to learn.

## 5. Alternatives, and why they lost

* **Model A — reject before any persistent artifact exists, everywhere.** Adopted for
  input, rejected as a general rule: it would have to un-write **M** and **P** when a
  disk error stops the record step, which destroys the very evidence the ordering exists
  to preserve.
* **Model B — the manifest and plan are valid intermediates, so the residue is fine.**
  Rejected: it makes one artifact set mean two unrelated things, and it is what the Node
  comment, the SDK prose and the store's own guard disagree about. Retaining it for a
  typo costs the operator a manual cleanup for nothing.
* **Model C — make the release a transaction (stage everything, commit atomically).**
  Rejected as out of scope and larger than the problem: it changes the recovery semantics
  of an interrupted run, the store's writer, and the "records before sources" property
  this repository documents as the point of the ordering. Nothing measured here requires
  it; the residue was only ever reachable through an input check that could run earlier.

## 6. Evidence this is not a protocol change

No stored document changed shape, no digest, key derivation, site identity, evidence
arithmetic or exit code moved, and no schema version was touched. The revision label is
display metadata that `ReleaseRecord` never hashes — which is why the fix belongs at the
input door and not in the record's content rules. The tests added with this decision
(`an_unusable_revision_is_refused_before_anything_is_written`,
`an_interrupted_record_leaves_the_private_half_for_inspection` in
`crates/swp-embedding/src/protect.rs`) pin both halves: the door refuses with the store
untouched, and a blocked record write still leaves **M** and **P** with the id refused
for reuse.

## 7. Follow-ups

Issue [#27](https://github.com/theaaqibjavaid/SWP-1/issues/27) is the same documentation
surface one row further up: §4's *Effects* row credited `Mode::Plan` with a manifest
and a release record it does not write. That row now describes the three branches the
pipeline actually takes — the plan branch at `swp-embedding/src/protect.rs:282-293`,
`write_release` at `:336-398`, the dry run's note at `:294-301`. This record
deliberately did not fold that fix in — #26 had to settle what a refused run means
before #27 could say what a *successful* plan run writes.
