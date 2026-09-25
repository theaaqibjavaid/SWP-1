# Versioning policy (Beta 3 onward)

Seven version numbers are in play around this repository, and the point of this
page is that they are not seven names for one thing. Four are facts a saved
artifact carries inside itself, three are facts about the build that wrote it, and
one more row is not a version at all but a floor a runtime has to clear. Only that
last one may move because a wheel was rebuilt.

When a number varies with the project's key it is not a version at all — it is a
digest, and `AGENTS.md`'s rule about not inventing a documented number applies to
it. Nothing below is such a value.

## 1. What each number means

| axis | value today | where it lives | changes when |
| --- | --- | --- | --- |
| protocol | `SWP-1` | `crates/swp-core/src/version.rs:2`, `ProtocolVersion::V1` (`:8-19`) | a change a saved artifact must survive: fragment format, key derivation, tag semantics, detection matching. A new major protocol is SWP-2 and is a different product's name |
| canonicalizer | `V1` | `version.rs:68` | the L1/L2/L3 rules change. Recorded per identity and re-checked per release: a disagreement is `RELEASE_MISMATCH` (`swp-detection/src/index.rs:128-144`) |
| report schema | `SWP-1-report-v2` | `swp-evidence/src/report.rs:36`, `SchemaVersion::REPORT_V2` | grading arithmetic, field set, or meaning. A reader that does not recognise it refuses the document (`report.rs:147-154`) |
| other artifact schemas | `SWP-1-manifest-v1`, `-identity-v1`, `-plan-v1` | `version.rs:44-52` | the stored documents' shape. Checked on read, same rule |
| Rust crate version | `1.0.0-beta.2` | `[workspace.package] version`, inherited by all ten crates; `check-release.sh:35-50` fails if one is not pinned to it | a release. There is exactly one version across the workspace, and `swp-sdk` joins it |
| CLI version | same string | `swp_cli::VERSION` (`swp-cli/src/lib.rs:57`) | never independently |
| binding package version | none yet | the wheel's / the npm package's own metadata | the binding's own surface, or the façade it wraps |
| runtime support | CPython ≥ 3.10; Node per §4 | package metadata, binding README | the binding's floor, and only as a *major* |

The four rows a saved artifact carries inside itself — protocol, canonicalizer,
report schema, and the other document schemas — are the ones the rules below
protect. Everything else is packaging.

## 2. Rule: a binding version change never implies a protocol change

This is the handoff's requirement, restated as something checkable rather than as
an intention.

* The protocol name is read out of `swp_core::version::SWP_PROTOCOL_NAME` and is
  never a literal in a binding's source, its package metadata, or its README.
* A binding's own version is `MAJOR.MINOR.PATCH` of *that package*. It moves when
  the façade surface it exposes moves: `PATCH` for a binding fix, `MINOR` for an
  added operation or field, `MAJOR` for a removed or renamed one.
* A binding must not advertise a protocol version it has not read. `capabilities()`
  (`docs/SDK_API.md` §1) is the only permitted source for that string in a
  binding's documentation or error messages.
* The reverse also holds, and it is the more dangerous half: a *crate* version
  bump says nothing about the protocol either. `1.0.0-beta.2 → 1.0.0` is not a
  protocol change, and a report written by one is read by the other, because
  `schema` and `protocol` inside the document — not the crate version — are what
  `Report::from_json` checks. `run.generator` records which build wrote it, for
  diagnosis, and `swp_core::version.rs:77-79` states plainly that it never
  participates in a hashed value.

## 3. Rule: a saved report is a versioned artifact

A report is the artifact that leaves the machine: it gets forwarded, filed, and
quoted later by someone with a different build. So:

* `schema` and `protocol` are carried inside the document
  (`swp-evidence/src/report.rs:72-73`) and the reader refuses a mismatch with
  `PROTOCOL_VERSION_UNSUPPORTED` (`:147-162`) — exit code 6 — rather than doing
  its best with a foreign document. A binding surfaces that error and does not
  catch-and-continue.
* **A binding must not recompute anything a report asserts.** The coincidence
  bound (`ReleaseTally::chance`, `level.rs:248-260`), the tail probability
  (`coincidence_probability`, `:252-257`), the level (`level.rs:81`) and the
  verdict are the arithmetic of *this* build applied at the time of the run.
  Reimplementing the ladder in Python or JavaScript to "sort by strength" or to
  render a bar is the silent reinterpretation this rule exists to prevent, and it
  is prevented by the design rather than by review: `swp-evidence`'s grading
  functions are the only implementation, and the binding surface exposes fields
  and `to_text`, not a re-grade hook.
* `Report.exit_code()` (`report.rs:126`) is exposed as a property of the document
  — a report written by any build says what `swp scan` would have exited with —
  and it is part of schema v2's meaning. Changing it changes the schema.
* `to_text()` is the stored document rendered by the current build. It is a
  *display* of a versioned artifact, not a new claim, which is why the text and
  the JSON are allowed to be produced by different code paths
  (`swp-cli/src/verify.rs:242-245` makes the same argument for the verify
  document's two tables).

## 4. Runtime support windows

* **CPython.** The wheel is `abi3` with a floor of 3.10, and the CPython docs are
  what the floor promises: an extension using only the Limited API is
  "ABI-compatible with all Python 3 releases from the specified one onward"
  (*C API Stability*, Python 3.14). Nothing verifies that an `abi3` wheel is
  installed into a new-enough interpreter, so `requires-python` is the guarantee
  and the binding's CI installs at the floor and at the newest supported minor.
  Free-threaded builds are not supported until `abi3t` is wired up; that is a
  *stated* limitation, not an assumed one.
* **Node.** The floor is the range the current napi-rs toolchain supports
  (`^20.17.0 || ^22.13.0 || >=23.5.0` as documented on 2026-09-25) mirrored into
  `engines`. Dropping a supported major is a binding `MAJOR`, never a `PATCH`
  that a lockfile-free install discovers on its own.
* **Rust.** The library crates keep `rust-version = "1.85"`. `swp-sdk`, as a
  workspace member, holds that line too: it may not pull a dependency that needs
  more. The binding crates sit outside the workspace precisely because napi-rs
  asks for 1.88, so that a binding toolchain requirement cannot raise the
  published crates' floor. The pinned toolchain here is 1.91.1
  (`rust-toolchain.toml`), which is what CI and this machine actually build with.
* **Platforms.** The four targets `release.yml` builds the CLI for
  (`:129-152`) are the four the bindings ship. A platform is supported when a
  prebuild exists and its tests ran; anything else is "build from source, if you
  have a linker", written that way.

## 5. The compatibility table, and where it is kept

Every binding release states five things, in its README and in `CHANGELOG.md`, in
one table:

```text
| binding version | swp / swp-sdk version | protocol | reads report schema | writes report schema |
```

The two report columns can differ, and the fact that they can is the point: a
binding built against a façade that still reads `SWP-1-report-v1` documents — if
such a thing ships — writes v2. What a release may not do is leave that pair
unstated and let a reader infer support from a version number that looks close.

The `swp` column is the workspace version, because one version number covers all
ten crates and `check-release.sh` will not pass otherwise. The `swp-sdk` column
exists only to make it legible to somebody reading a lockfile.

## 6. Deprecation

* A report schema is deprecated by announcing that a future release will not read
  it, in `CHANGELOG.md` and in this page's table, and not by silently failing to
  parse it. Until then, readers refuse with `PROTOCOL_VERSION_UNSUPPORTED`, which
  means a binding that cannot read a document says so with the same code and the
  same next step as the CLI (`swp-core/src/error.rs:133-135`).
* An operation on this API is deprecated by a doc comment naming its replacement
  and a release note, and stays for one `MAJOR` of the binding that exposed it.
  Removing a façade operation removes it from three ecosystems at once, so the
  façade's `MAJOR` and each binding's are bumped together and the table records
  it.
* A binding's runtime floor moves on a schedule the maintainer chooses, but never
  in the same release as an API removal: one reason to upgrade per version, so the
  release note can be read as the change it is.

## 7. What must never be versioned separately

`swp-sdk` and the crates it composes. It is a workspace member, inherits
`[workspace.package] version`, and is added to the publishable list in dependency
order after `swp-evidence` (`scripts/check-release.sh:30`). The temptation to give
the façade its own cadence arrives the first time a binding needs a fix and does
not want to cut a whole release; the answer is that a fix the façade needs is a
release the façade ships, because a façade version that does not identify a set
of crate versions is not a version, it is a guess.
