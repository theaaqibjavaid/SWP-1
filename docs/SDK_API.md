# SDK API contract

A language-neutral description of the operations Beta 3 exposes, and of the
Rust code each one is a view of. Nothing here is a new protocol operation: every
operation below is a command that `swp` already runs, or a document it already
writes, and the mapping is stated with a file and line so that a reader can
check the claim against the implementation rather than against this page.

The binding-specific shape of each operation (Python class, Node object,
TypeScript types) is in that binding's README; this page defines what those
three must agree on. The rationale for the boundary is in
[SDK_ARCHITECTURE.md](SDK_ARCHITECTURE.md), and
[VERSIONING_POLICY.md](VERSIONING_POLICY.md) governs which of these values may
change without a protocol change.

The Rust side of this contract exists: `crates/swp-sdk` implements it, §11 lists the
shipped surface, and the citations below point at that crate. Two things this page
once held back — `verify` (§6) and the per-site scan rows (§5) — are now exposed as
described there.

Conventions used below:

* **Effects** — what the operation touches: `none`, `reads`, `writes store`,
  `writes source`. Every one of these is derived from code, and `protect`'s two
  write predicates are the implementation's own
  (`swp-embedding/src/protect.rs:99, :106`).
* **Secret** — whether the operation loads the project's root secret, and if so
  where it is dropped. A `Session` never holds one between calls; the
  implementation loads inside the operation and drops it before the tree walk
  (`crates/swp-sdk/src/session.rs:403` in the release loader,
  `crates/swp-sdk/src/protect.rs:377` after `swp-embedding` has derived what it
  needs, `crates/swp-sdk/src/init.rs:175, :190, :195` for the secret a run drew and
  did not use), and the boundary keeps that.
* **Blocks** — whether the call is expected to take long enough that a binding
  should release its host's interpreter lock. All of them are synchronous;
  there is no async Rust here and none will be added for bindings.
* **Concurrent** — whether two calls may be in flight at once, and against what.

---

## 1. `capabilities()`

The machine-readable answer to "what can this build do", so a binding does not
have to hard-code a language list and a user does not have to trust a README.

| | |
| --- | --- |
| Inputs | none |
| Effects | none |
| Secret | no |
| Blocks | no |
| Concurrent | yes, freely |

```rust
fn capabilities() -> Capabilities;

pub struct Capabilities {
    pub protocol: String,             // SWP-1, swp_core::version.rs:2
    pub swp_version: String,          // GeneratorInfo::current().swp_version, version.rs:86-93
    pub report_schema: String,        // "SWP-1-report-v2", swp-evidence/src/report.rs:36
    pub canonicalizer_version: u16,   // CanonicalizerVersion::V1, version.rs:68
    pub languages: Vec<LanguageInfo>, // see below
    pub tag_bits: TagRange,           // min 2, max 8, default 4: swp-core/src/site.rs:89-116
    pub target_sites: SiteRange,      // min 4, default 16, max 4096: swp-identity/src/config.rs:16-18
    pub defaults: DefaultPolicy,      // built-in excludes, config.rs:24-37
}

pub struct LanguageInfo {
    pub name: &'static str,           // "javascript" | "typescript" | "python"
    pub extensions: Vec<String>,      // js,mjs,cjs,jsx / ts,mts,cts,tsx / py,pyi
}
```

`languages` is composed from the registry the adapters already expose:
`Registry::standard().parsed_languages()` (`swp-adapters/src/adapter.rs:393`)
for the names and `for_language(name).extensions()` (`adapter.rs:371`,
`adapter.rs:131`) for the extensions. The audit's §7 records that no single API
returns both today, and that composing them here is the whole reason this
operation exists: three ecosystems guessing at the shape of the answer is how a
language stops being "supported" in one of them.

A language listed here is one this build **parses**. It is not a promise about
which literal forms will survive a safety check — `StringAdjacent` is Python-only
(`swp-adapters/src/forms.rs:424`) and template literals are refused in
JavaScript (`literal.rs:179-221`) — and `capabilities()` deliberately says
nothing about how many sites a given tree will yield, because that is a property
of the tree.

Errors: none. It is a constant.

## 2. `Session::init(project_root, options) -> InitOutcome`

Create or re-open a project's store. Two outcomes, and the difference is a fact
about the tree rather than a flag: a directory that already has a store keeps its
identity and its secret, because SWP never replaces a project secret
(`swp-identity/src/store.rs:210-214`).

| | |
| --- | --- |
| Inputs | `project_root: Path`, absolute, must already exist; `options: InitOptions { name: Option<String>, force: bool }` (the display label, validated at `crates/swp-sdk/src/init.rs:143-149`; `force` is `--force`, and without it a rename of an existing label is `USAGE` at `:151-161`) |
| Effects | **writes store**: creates `.swp/`, `root.key`, `identity.json`, `config.toml`, and the `.gitignore` entry (`store.rs:185-244`) |
| Secret | generates one (`SealedSecret::generate`, `swp-crypto/src/seal.rs:81`), hands it to `Store::init`, drops it (`init.rs:175, :190, :195`). Never accepts one. |
| Blocks | briefly (one tree measure: `init.rs:169` calls `measure`, `:248`) |
| Concurrent | one init per project at a time. There is no lock in this tree, in any layer. |

```rust
pub struct InitOutcome {
    pub session: Session,      // the project, open and ready to protect
    pub result: InitResult,
}

pub struct InitResult {
    pub project_id: ProjectId,
    pub display_name: String,
    pub pre_existing: bool,             // store.rs:49-59 StoreInit
    pub secret_state: &'static str,     // "created" | "kept"
    pub secret_scheme: &'static str,    // "dpapi" | "plain" — seal.rs:32-38
    pub secret_handle: String,          // RootSecret::fingerprint(), secret.rs:95 — non-secret
    pub permissions_verified: bool,     // PermissionOutcome::is_verified(), seal.rs:231
    pub permissions_detail: String,     // what the OS reported back
    pub gitignore: &'static str,        // "created" | "updated" | "already ignored" | "not written"
    pub created: Vec<String>,           // store-relative, forward-slashed
    pub renamed: bool,                  // whether this run changed the label
    pub measurement: Measurement,       // see below
    pub settings: Settings,             // see below
}

pub struct Measurement {                // swp-sdk/src/init.rs:39-48
    pub files: u32,                     // files with a parser-covered extension
    pub bytes: u64,
    pub languages: BTreeMap<String, u32>,
    pub tops: BTreeMap<String, u32>,    // source files per top-level directory
    pub skipped: u32,
}

pub struct Settings {                   // swp-sdk/src/init.rs:52-61
    pub targets: Vec<String>,
    pub target_sites: u32,
    pub tag_bits: u8,
    pub embed_strings: bool,
    pub written: bool,                  // did this run write the config, or leave it
    pub suggestion: u32,                // what the measurement suggested, applied or not
}
```

`InitOutcome` carries a `Session` because the store this call just created is the
one the caller wants to protect with: `init` returns the opened project as well as
the account of what it wrote, so a binding does not have to open a directory it
named a moment earlier and hope the two agree.

Three fields are here because a caller cannot otherwise know something it needs.
`secret_scheme`: on Windows, `SWP_SECRET_PLAIN=1` skips DPAPI
(`seal.rs:209-216`), and an embedded process inherits its host's environment, so
without this field an application could write an unsealed key and never be told.
`permissions_verified`/`permissions_detail`: `std::fs::set_permissions` on
Windows reports success while changing nothing, which is why this build reads the
ACL back and parses it (`docs/SECURITY.md`, `seal.rs:243`); an embedder must see
the same three-way answer the CLI prints. `created` is what `swp init` shows a
user, and the store's own test pins its completeness and order
(`swp-identity/src/store.rs`, `init_creates_the_expected_layout_and_reopens`).

`Measurement` and `Settings` are the shapes `swp-cli` used to keep private
(`init.rs:40-48`, `:64` before the extraction). They are the SDK's now, and the
CLI renders them, which is what keeps `suggest_sites`
(`swp-sdk/src/init.rs:300`) the single source of the default constellation for a
terminal and a bound caller alike.

Errors: `USAGE` when the path is not a directory; `SECRET_UNAVAILABLE` (exit 3's
code) when a store exists and its key cannot be opened; `IO_ERROR`. A private
artifact whose access could not be confirmed is refused by the store, which is
`swp-identity`'s rule, not a new one.

## 3. `Session::open(project_root, overrides) -> Session`

Reopen a project without creating or changing anything.

| | |
| --- | --- |
| Inputs | `project_root: Path`, absolute, named by the caller; `overrides: Overrides` (see §11) |
| Effects | reads `config.toml`, `identity.json` |
| Secret | no |
| Blocks | no |
| Concurrent | yes — a `Session` is a path plus two parsed documents, and every operation reloads what it needs |

`Store::open` (`store.rs:166`) requires the caller to say which directory it is,
and that requirement is a security property the binding must not blur: a
candidate tree may contain its own `.swp/`, and the scanner must never read
config from the tree it is scanning (`swp-identity/src/config.rs:1-8`). So
`Session::open` takes an explicit path and there is no "find my project" default
in the API — `Session::discover(from)` (`swp-sdk/src/session.rs:105`) is the CLI's
walk-up-from-a-directory offered by name, not by default, and it takes the same
`Overrides`. A binding may offer a `discover()` convenience; it must resolve it in
the host and pass the result in, and `open` remains the recommended entry point
because its error names the directory it was given.

Errors: `NOT_PROTECTED` with the same two-cause message the CLI gives
(`session.rs:106-121`), `INVALID_MANIFEST` for an unreadable identity. A directory
that has a `.swp/` but no readable config is reported as an incomplete store
(`incomplete_store`, `session.rs:479`, raised at `:94-96` and `:110`) rather than
recommended for `swp init`, which is the one command that would make it worse.

## 4. `Session::protect(options) -> ProtectOutcome`

The one operation that rewrites source, and — with `mode: plan` — the one that
records a constellation without touching it. `swp generate` and `swp protect` are
already the same function in the CLI (`swp-cli/src/lib.rs:122-123`
→ `protect::run(.., mode)`), and they are one operation here for the same reason.

| | |
| --- | --- |
| Inputs | `ProtectOptions { mode: Mode, release_id: Option<ReleaseId>, revision: Option<String> }`. The settings the run protects *with* — targets, excludes, site count, tag width, string literals — are the project's `[protect]` config as patched by the `Overrides` the `Session` was opened with, not per-call arguments (§11), because `swp-embedding` validates one coherent settings document rather than a config plus a set of exceptions. |
| Effects | `plan` → **writes store** (the private plan and nothing else: no manifest, no release record, no source change — `swp-embedding/src/protect.rs:282-293`); `release` → **writes store + source** (manifest, then plan, then the public release record, then the source files: `:271-281` → `write_release`, `:336-398`); `dry_run` → **none** (`:294-301`). `Mode::writes_source` / `Mode::writes_store` (`:99`, `:106`) state the same bounds the match enforces: only `release` may touch source, and only `dry_run` leaves nothing behind. |
| Secret | yes: `ManifestKeys::derive` (`swp-manifest/src/keys.rs:73`) and `ManifestSigningKey::from_root`. Dropped when the call returns (`swp-sdk/src/protect.rs:377`, immediately after `swp_embedding::protect` has derived what it needed). |
| Blocks | yes, proportional to tree size. This is the call a binding must run off the host's main thread. |
| Concurrent | one `protect` per project at a time. Two at once write the same files. |

```rust
pub enum Mode { Plan, Release, DryRun }   // swp_embedding::Mode, re-exported (protect.rs:80-87)

pub struct ProtectOptions {               // swp-sdk/src/protect.rs:45-73
    pub mode: Mode,
    pub release_id: Option<ReleaseId>,    // None allocates one
    pub revision: Option<String>,         // display metadata; never hashed
}

pub struct ProtectOutcome {               // :89-101
    pub protection: Protection,           // swp-embedding's result, unaltered
    pub revision: Option<String>,         // what the caller stated, trimmed; `None`
                                          // only when none was stated — a label
                                          // that trims to nothing is refused at the
                                          // door before anything is written
}
```

`ProtectOptions` has no `Default` on purpose: a struct reachable by `::default()`
would be a struct whose default mode rewrites the source tree, so `mode` is an
argument of `ProtectOptions::new` and cannot be reached by accident.

`revision` is what the operator claims the source is — a git ref, a version, a
build number. `None` records the content fingerprint as the revision
(`SourceRevision::Content`); `Some(text)` records `text` trimmed. There is no
stated-but-empty third state. `SourceRevision::validate` rejects a label that is
empty, over 200 bytes, or carries a control character
(`swp-identity/src/release.rs:70`), and the protection pipeline runs that check at
its own door, with the identity and the config, before the store is consulted at
all (`swp-embedding/src/protect.rs:200`). So `swp protect --revision ""` — and
`--revision "   "`, which trims to the same thing — is refused with
`INVALID_MANIFEST`, exit 5, and **nothing is written**: no manifest, no plan, no
record, no source change. The refusal is mode-independent — `Mode::Plan` and
`Mode::DryRun` reject the same label rather than silently dropping what the caller
stated — and the record still validates itself where it is written
(`Store::write_release`, `swp-identity/src/store.rs:345`), so a caller that builds a
`ReleaseRecord` by hand is refused the same way.
`ProtectOutcome::revision` is `None` only for the unstated case, and it is returned
because the release record holds what was *stored*: a caller that normalized the
label a second time could disagree with it. There is no `git` shell-out on this
path in either door (§21).

The reason the label is judged at the door rather than at the record is the store's
own state machine, and [ADR-0002](adr/0002-release-failure-semantics.md) is the
record of it: a manifest and a plan with no release beneath them are the artifact
set an *interrupted* run leaves, `swp inspect store` reports them as such, and the
release id they carry is refused for reuse. Leaving that set behind for a typo would
make one state mean two things.

The `Protection` inside the outcome is the service crate's type
(`swp-embedding/src/protect.rs:143-171`), which already derives `Serialize` and
already carries `artifacts` (store-relative, in write order, `:165-167`),
`files_changed`, `sites_embedded`, `sites_skipped`, `candidates`, the fingerprint
and its level, and the full `Plan` including every refusal with its reason. The
façade adds nothing to it and subtracts nothing from it.

`release_id` is not cosmetic and is the easiest way for a binding to get this
wrong. A plan is keyed by release id, so applying a generated constellation
means passing the same id: `swp protect --release <id>` after `swp generate`
(`swp-cli/src/protect.rs:89-95`, and the same field on `ProtectOptions`). A binding
that allocates a fresh id for the second call derives different keys, embeds
different tags, and produces a second release the plan does not describe — while
still succeeding. So the rule is: `mode: plan` returns `release_id` in
`protection.release_id` and `mode: release` accepts it; a fresh id is allocated
only when the caller passes none, which is the "protect without a plan" case the
CLI runs by default.

`Overrides::targets` are subject to the containment rule the CLI applies: an
absolute target must resolve inside the project root or it is `USAGE`
(`swp-sdk/src/session.rs:143-175`), because a target that escapes the root is a way
to write outside the project. It is decided where the root is known — once, in
`Session`, for a terminal and a bound caller alike. Warnings the CLI prints before
a run (a limit clamped against the hard ceiling, `session.rs:129-131`) are read
from `Session::warnings()`, not raised as errors and not dropped.

Errors: `NO_SAFE_LOCATIONS` when every candidate failed a safety precondition —
source unchanged, and that is the designed outcome, not a failure to work around
(`AGENTS.md`, and `error.rs:148-154`); `LIMIT_REACHED` when a resource ceiling
trimmed the run; `MALFORMED_SOURCE`/`PARSER_FAILURE` from the adapters;
`RELEASE_MISMATCH` when a named release already exists with different content
(`swp-embedding/src/protect.rs:214`).

### `Session::protect_summary(options) -> ProtectSummary`

The same call, with the private plan left in Rust. A binding cannot wrap `protect`
today because its result can: `ProtectOutcome` → `Protection` → `Plan` →
`PlannedSite.locations: [LocationId; 4]`, and `Protection` derives `Serialize`, so
printing the envelope prints every keyed site address in the project. This is the
accepted answer to that — Option B of
[ADR-0001](adr/0001-protect-generate-binding-boundary.md) — and it is one operation,
not two: `protect_summary` calls `protect` (`swp-sdk/src/protect.rs:256-260`) and
projects the result onto fields that carry no key (`summarize`, `:267`). Nothing is
re-derived, so the two cannot disagree about what the run did, and the mode
semantics, errors and the secret's lifetime are `protect`'s unchanged.
```rust
pub struct ProtectSummary {               // swp-sdk/src/protect.rs:180-240
    pub mode: Mode,                       // serializes snake_case: `dry_run`, not `dry-run`
    pub project_id: ProjectId,
    pub release_id: ReleaseId,            // pass it back to apply this constellation
    pub created_at: Timestamp,
    pub revision: Option<String>,
    pub fingerprint: Digest,              // public SHA-256 of the tree; §16
    pub fingerprint_level: String,
    pub tag_bits: u8,
    pub requested_sites: u32,
    pub target_sites: u32,                // after the ceilings trimmed it
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    pub files_walked: usize,
    pub files_in_scope: usize,
    pub candidates: usize,
    pub files_changed: Vec<ProtectedFile>, // file, sites, bytes_before, bytes_after
    pub sites: Vec<ProtectedSite>,        // file, line_hint, language, adapter, class,
                                          // family, width, primary — one per embedded site
    pub refusals: Vec<RefusedSite>,       // file, line_hint, reason — one per skipped candidate
    pub artifacts: Vec<String>,           // in write order; empty for `dry_run`
    pub notes: Vec<String>,
}
```

What is *not* here, and what each absence is: the plan's four keyed identities per
site (a `LocationId` is `HMAC(site_key, …)` truncated to 128 bits — not a key and
not invertible, but a cross-release join address for one project's source layout,
which is why `swp protect --format json` prints zero of them and this result carries
zero of them); the refusal's `detail` sentence, because a dropped site's sentence
is `no family reachable here rendered code <n>` with `<n>` a rendered tag
(`swp-embedding/src/apply.rs:235, :256-266`, copied into the plan at
`plan.rs:132-139`); and the plan document itself, which a binding has no use for —
nothing downstream of a protection run reads a plan id, and M5 of the ADR measured
that a release applies from its release id without the plan being an FFI object.

`notes` crosses because every string that can appear there was read, not because it
is a `String`. Seven push sites in five files, all in `swp-embedding`: `candidates.rs:358-361,
:385-388` (a path with a count of literals left out; the limits in force),
`plan.rs:155-157` — one line per walk omission, whose reason is fixed prose, a path,
a byte count or a limit number (`walk.rs:239-424`) — `plan.rs:158-164` with
`select.rs:312-320` (the shortfall line: two counts of sites), `protect.rs:288-292,
:295-300` (the `plan`/`dry_run` explanations) and `:391-395` (how many files were
modified). None interpolates a key, a keyed id or a tag.

The claim is checked three ways, not asserted. `binding_surface` parses this
struct's field types and field *names* and fails on a keyed type or a keyed name
whatever type it carries. `sdk_parity` runs one tree through both doors and compares
22 keys of `swp protect --format json` against the serialized summary
key-for-key (`the_binding_facing_account_matches_the_cli_document_key_for_key`),
draws one plan twice and proves the summary is the outcome minus `locations` and
`detail`, then sweeps the summary's JSON and `Debug` against that run's own location
ids — four per embedded site, read off that same plan (`the_summary_is_the_same_run_with_every_keyed_site_identity_left_behind`),
and compares a release run through either door
(`a_release_through_the_binding_door_reports_the_same_run_as_the_cli_document`).
`no_value_the_sdk_hands_back_prints_the_key_it_just_used` sweeps this value for the
root secret and a derived per-location MAC along with every other artifact the SDK
hands back.

For a caller, the shape is what makes it wrappable: owned `String`s and integers, no
borrow of the `Session`, no handle into the store, nothing to free or zeroize across
an FFI boundary, and `Serialize` so the JSON a binding shows is this document. It is
also `PartialEq`/`Eq`, which the other result envelopes are not, because a test and a
binding alike need to compare two accounts of a run.

## 5. `Session::scan(candidate, releases, save) -> ScanOutcome`

Ask whether this build's provenance is present in an artifact you did not write.

| | |
| --- | --- |
| Inputs | `candidate: Path` (directory, file, `.zip`/`.tar`/`.tar.gz`), `releases: &ReleaseSelection` (`All` — the default — `Latest`, or explicit ids), `save: bool` |
| Effects | reads the candidate and the store; **writes outside the project** when unpacking an archive (`swp-detection/src/input.rs:333-343`, removed on `Drop`); writes `reports/` only if `save` |
| Secret | yes, to derive each release's keys — and dropped before the candidate is opened (`swp-sdk/src/session.rs:403`, and the call order in `swp-sdk/src/scan.rs:119-121` is load → index → open), because a scan should not hold a key while walking a stranger's tree |
| Blocks | yes, proportional to candidate size |
| Concurrent | yes for *different* candidates; a `save` to the same store from two threads is one artifact per call and `Store::save_report` numbers a collision rather than overwriting (`store.rs:379`) |

```rust
pub struct ScanOutcome {                     // swp-sdk/src/scan.rs:27-41
    pub report: Report,                      // the swp-evidence document, verbatim
    pub saved: Option<SavedReport>,          // Some only when `save` was asked for
    pub sites: Vec<ScannedSite>,             // per-site rows, secret-free
}

pub struct SavedReport {                     // :78-87
    pub name: String,                        // the stem `read_report` takes
    pub path: String,                        // store-relative, forward-slashed
}

pub struct ScannedSite {                     // :51-74
    pub release_id: String,                  // joins the row to the report's tally
    pub site: usize,                         // index into that release's site list
    pub status: &'static str,                // one of the four rungs listed below
    pub probes: u32,                         // spans that reached a tag comparison
    pub distinct_codes: u32,                 // this site's share of the bound's draws
    pub found_tokens: u8,                    // literal size, saturating at 255
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    pub found_excerpt: Option<String>,       // the same text an evidence item quotes
}

pub struct Report { /* swp-evidence's document, field for field */ }
```

`Report` is the same in both doors. It is `swp_evidence::Report`
(`swp-evidence/src/report.rs:71-92`), which derives `Serialize` + `Deserialize` with
`deny_unknown_fields` and carries the verdict as **fields, not accessors**:
`result: Outcome` (`PROVENANCE_DETECTED | NO_PROVENANCE_DETECTED | INCONCLUSIVE`),
`evidence_level: EvidenceLevel` (`NONE` … `VERY_STRONG`), `explanation`,
`releases: Vec<ReleaseTally>`, `evidence`, `omissions`, `notes`, `limitations`.
The methods on it are the reading and writing ones: `from_json` (`:140`),
`to_json` (`:132`), `to_text(full)` (`:170`), `to_text_items(items)` (`:182`), and
`exit_code()` (`:126`) — which is a property of the document here, not a process
instruction. Every binding exposes the same JSON and the same text rendering, so a
report produced by the CLI, by a wheel, or by a `.node` addon is one artifact with
one reading path.

`ScanOutcome` is the façade's own envelope, and only two things are in it that the
document does not already carry:

* `saved` names the store entry a `save` actually wrote. `Store::save_report`
  numbers a collision rather than overwriting, so the name to hand back is the one
  in the path it returned, not the one asked for (`scan.rs:174-180`), and it is the
  name `read_report` accepts (§7).
* `sites` is the per-site view the report sums into a tally. A `ReleaseTally`
  carries `sites`, `fragments`, `probes` and `draws` for a whole release, which is
  what a verdict needs; a caller drawing the distribution needs the same numbers
  one row at a time. `ScanOutcome.sites` is a *companion* to the document and never
  a second grading — it copies the counts out of the detection's rows and nothing
  else, so a site graded `absent` here is graded `absent` in the report
  (`scan.rs:148-167`). A saved report never contained these rows, and re-reading
  one gives the document, not this field.

The rows are deliberately free of anything keyed. The location ids and the expected
codes a match was decided against stay inside `swp-detection`, so a row says *that*
a span confirmed and how much work reaching it took without becoming a list of the
values that would let a caller test a guess against a site that was never hit —
which is the tag oracle §10 refuses, per site.

`status` carries the four rungs the detector draws in one place
(`swp-detection/src/find.rs:86-100`): `absent` (nothing stood at that address),
`location-only` (a span produced a key but the literal there does not carry the
code — stripped, or a pre-protection build, which the scan cannot tell apart),
`tag-confirmed` (the literal decodes to the expected fragment), `exact-rendering`
(the literal is byte-for-byte the spelling the manifest recorded). Only the last
two are watermark evidence, and that line is the detector's
(`SiteStatus::is_watermark`, `:128-134`), not a caller's judgement. The words are
stable strings, and `SiteStatus::parse` (`:112-126`) is their inverse for a reader
holding a saved report's row: an unrecognised word yields `None` rather than a
guess, because treating a newer build's status as evidence would be the silent
strengthening §19 forbids.

The release-selection default is `All`, and that is the protocol's choice rather
than a convenience: a copy could have come from any release, and picking one
silently would be a claim about which (`swp-sdk/src/session.rs:51-65`).

`scan` of a candidate that contains a store does not read that store's config
(`config.rs:1-8`); a `PathRejected` error means the archive tried to escape its
extraction directory and the whole candidate was refused rather than partially
read (`error.rs:155-157`).

## 6. `Session::verify(options) -> VerifyOutcome`

The narrowest claim the tool makes, and the one an owner asks most often: *is this
tree still the tree that was protected?* `swp verify` reads **this** project's root
against **one** release, and answers per site with a verdict — `INTACT`,
`INCOMPLETE`, `INCONCLUSIVE` — in the `SWP-1-verify-v1` document.

| | |
| --- | --- |
| Inputs | `VerifyOptions { release: Option<ReleaseId>, save: bool, rows: Option<usize> }` |
| Effects | reads the project tree and the store; writes `reports/` only if `save`. **No source is written and no candidate is opened.** |
| Secret | yes, to derive the one release's keys, through the same loader `scan` uses, dropped before the tree is walked |
| Blocks | yes, proportional to tree size |
| Concurrent | yes for reads; one `protect` must not be in flight against it |

```rust
pub struct VerifyOptions {                   // swp-sdk/src/verify.rs:27-44
    pub release: Option<ReleaseId>,          // None = the newest
    pub save: bool,                          // a SWP-1-report-v2 copy of the scan
    pub rows: Option<usize>,                 // how many rows the caller will render
}

pub struct VerifyOutcome {                   // :48-57
    pub document: VerifyDocument,            // swp-evidence's, verbatim
    pub report_saved: Option<String>,        // store-relative path, when `save`
}
```

`VerifyDocument` is `swp_evidence`'s type (`swp-evidence/src/verify.rs:139-183`,
schema constant `SCHEMA` at `:46`) — it moved out of `swp-cli` before this
operation could be exposed, so that a bound caller and a terminal read one schema
and one grading function. Its fields are the verdict (`verdict: Verdict`, plus
`partial` and the counts behind it: `sites_expected`, `sites_confirmed`,
`sites_exact`, `sites_stripped`, `sites_absent`, `sites_moved`,
`sites_refactored`), the identity it authenticated against
(`project_id`, `manifest_authenticated`), what the tree is (`tree`, `fingerprint`,
`fingerprint_expected`, `revision`), the per-site `sites: Vec<SiteRow>`, and
`exit_code` — which crosses as a document field, the same way `Report::exit_code`
does.

Three semantics a binding has to keep straight:

* `release: None` is the **newest**, because "is the tree I am standing in still
  the tree I protected?" is a question about the last protection run
  (`session.rs:305-314`). A named release that is not in the store is
  `NOT_PROTECTED` naming the releases that are, not the interrupted-run refusal —
  the two need different answers from the operator (`swp-sdk/src/verify.rs:71-80`).
* `save` writes a **report**, not a verification. The `SWP-1-verify-v1` document is
  returned and never written; reading a saved report back is §7, and its numbers
  belong to the moment they were measured.
* `rows` fills in `document.omitted_rows` and nothing else. The document always
  carries every row; `rows` is the record that a *rendering* left some out, so a
  caller that intends to print the first twenty passes `Some(20)` and a caller that
  prints all of them passes `None`.

The reason this section was once a plan is the reason it is now short. Two options
existed and only one was honest: move `VerifyDocument` down into `swp-evidence`
unchanged and let `swp-cli` render what the service produced, or hold `verify` back
and let a caller use `scan` of their own root, which returns a report and *not* a
verdict. Offering the second and calling it `verify` would have put a scan's
outcome behind a verify's name. The move happened first, on the original field set,
ordering and serde names, with `docs_examples` and the CLI's own tests as the net;
what is exposed now is the document the command has always printed.

A `Verdict::Inconclusive` is not a weak `Incomplete`: it says part of the tree was
never read, so this run could not have seen a missing site. `VerifyDocument`
separates them with `partial`, and the exit codes differ (5 and 10).

## 7. Report access: `Session::reports()`, `Session::read_report(name)`, `Report` from a string

Reading a stored report back is the operation with the fewest edges: no secret
(both calls reach `Store` only — `report_names`, `report_path`, `read_report` —
and `report.rs:45-84` never asks the session for one), no tree walk, no write.

| | |
| --- | --- |
| Inputs | `Session::reports()` → stems; `Session::read_report(name)` → bytes → `Report::from_json`; or `Report::from_json(text)` with no session at all |
| Effects | reads `reports/`; `from_json` touches nothing |
| Secret | no |
| Blocks | no |
| Concurrent | yes |

```rust
pub struct StoredReport {                    // swp-sdk/src/report.rs:25-35
    pub report: Report,                      // the document as it was graded
    pub name: String,                        // the stem read_report takes
    pub path: String,                        // store-relative, forward-slashed
}

pub fn report_stem(what: &str) -> String;    // :88
```

One entry has three spellings and all three are accepted: the stem `--save`
printed, the store-relative path a listing prints, and the file name a shell
completion offers. `report_stem` is the normalization, and it is public because a
binding that shows a user a path needs to hand the same entry back to
`read_report`. What a name may not do is leave the directory: the trimmed last
segment goes to `Store::report_path` (`store.rs:125`), which is the layer that
refuses an escaping name, and the path is never assembled from the caller's string
here. A traversal is therefore stripped to its final segment and then refused or
accepted on its own merits — `report_stem("../manifests/rel-…")` yields
`rel-…`, and the store decides whether that is a report.

`reports()` lists the directory, not the parseable documents in it: a file that is
not a report this tool wrote still appears, because `read_report` is where it fails
and the caller is the only party who can do anything about it. The names come back
newest first — the stems are timestamped, so that is chronological order, and it is
the order `swp report` prints (`swp-identity/src/store.rs:398-408`). That is also why a
missing name is `USAGE` with the count of what *is* stored, rather than a
`FILE_NOT_FOUND`-shaped surprise.

`Report::from_json` with no session is the operation a report viewer wants, and the
one that must not be mistaken for a scan: it grades a document that was already
graded. The text and JSON it produces are the stored document's, and the numbers
in it are the arithmetic of the build that wrote it — which is
[VERSIONING_POLICY.md](VERSIONING_POLICY.md)'s subject. `StoredReport.report` is
the parsed document, so re-serializing it yields the stored bytes unchanged: the
report *is* this type rather than a re-reading of a `serde_json::Value`, and key
order is part of what makes an export diffable against its original.

## 8. Errors

Every failure is a `SwpError` re-projected, not a new taxonomy
([audit §6](BETA3_ARCHITECTURE_AUDIT.md)). In **Rust** there is nothing to
re-project: a façade call returns `Result<T, swp_core::error::SwpError>`, the same
type the service crates raise, with the same stable `ErrorCode` discriminant
(`code()`), `message()`, `path()`, `caused_by()`, `next_step()` and `render()`
already public on it. There is no `swp_sdk::Error`, because turning one Rust error
type into another adds a taxonomy and no information. The struct below is the
**binding's** envelope, built from those six accessors at the FFI boundary:

```rust
pub struct Error {
    pub code: &'static str,      // ErrorCode::as_str(), swp-core/src/error.rs:55-75 — 17 stable names
    pub message: String,         // SwpError::message(), :274
    pub path: Option<String>,    // SwpFailure.path, :207 — already store-relative where applicable
    pub caused_by: Option<String>,
    pub next_step: String,       // SwpError::next_step(), :259 — may name `swp` commands
    pub rendered: String,        // SwpError::render(), :283 — the three-line human form
}
```

Rules the boundary must keep:

* **No exit codes in errors.** `ErrorCode::exit_code` (`error.rs:172-191`) is the
  CLI's contract with a shell; a library caller branches on `code`. The one exit
  code that does cross is `Report.exit_code()`, because there it is a field of a
  document the caller is reading, not a process instruction.
* **No subclass per code.** Seventeen exception classes would be a second
  taxonomy and would invite a caller to catch the ones that were thought of. One
  type, with `code` as the discriminant, and a `docs/CLI.md`-compatible name.
* **`next_step` is advice, not a machine interface.** It names CLI commands
  because it was written for a person at a terminal (`error.rs:101-168`). It is
  passed through unchanged, because rewriting it into "call protect() again"
  would be a second claim about what to do next.
* **A panic becomes `INTERNAL_ERROR`.** `error.rs:162-166` already defines that
  code as "a defect in SWP-1: report it", which is exactly what an unwinding
  panic across FFI is. It is not converted to "no evidence".

## 9. Ownership, lifetimes, and thread behaviour

The boundary is deliberately dull here, because FFI is where lifetimes stop
being a Rust problem:

* Every argument the caller passes is either a path it owns or a plain value;
  nothing borrows caller memory, so no signature in this API has a lifetime
  parameter. `swp_embedding::Request<'a>` (`protect.rs:114-130`) does — that is
  the internal type the façade builds and owns.
* Every value returned is owned data. `Session` holds a `Store`, which is a
  `PathBuf` (`store.rs:42-44`); no file handle, no mmap, no lock, no cache.
* Nothing in the read path holds a `static`, a `thread_local`, a `RefCell` or an
  `Rc` (audit §7's FFI notes). `LanguageAdapter: Send + Sync`
  (`swp-adapters/src/adapter.rs:120`) and a `tree_sitter::Parser` is built per
  call (`ts.rs:370`), so two threads with two sessions may scan two trees.
* **No operation is cancellable.** Once `protect` begins its write loop it runs
  to the end of that loop; an abort in the middle is a half-rewritten tree, and
  a binding that offered cancellation would be offering the failure this project
  exists to prevent.
* **The store is not locked, by anyone, anywhere in this tree.** One mutating
  operation per project at a time is the caller's obligation in a binding
  exactly as it is in a shell. Adding a lock at the binding layer would create a
  safety property that `swp` itself does not have, which is worse than documenting
  the absence.

## 10. What is deliberately not on this surface

Not an omission list to be worked through — a list of things whose absence is
the design, each with the reason the audit supports.

* **Key import or export.** No argument accepts key bytes and no field returns
  them. `RootSecret::from_bytes` exists in Rust (`secret.rs:56`) precisely so
  `Store::load_root` can rebuild a type after unsealing; across FFI those bytes
  would live in garbage-collected memory this project cannot zeroize. In the Rust
  façade the rule is a type rule and a capability rule: `Session::secret` is
  `pub(crate)` (`swp-sdk/src/session.rs:265`), `swp-sdk` re-exports no secret type,
  and `SecretBytes::as_slice` — the only accessor that turns held key material into a
  byte slice — is `pub(crate)` inside `swp-crypto` (`secret.rs:39`), so a `RootSecret`
  cannot be printed, cloned, serialized, or read back out as bytes.
* **What that wall is not made of.** The façade withholds keyed material from its own
  signatures; it does not sandbox the store. `Session::open_store()`
  (`session.rs:221-231`) is public, `Store` is re-exported (`lib.rs:101`), and
  `Store::load_root` (`swp-identity/src/store.rs:306`), `read_private_manifest`
  (`:358`) and `root_key_path` (`:86`) are public methods of that re-exported type — so
  a Rust caller that wants them can take a second handle and read them, exactly as
  `swp inspect` does. Three things keep that honest rather than ironic: no bytes come
  out of the secret type; the operating-system seal and the access list on `root.key`
  are the protection a `swp` process relies on too, and a caller who can run
  `swp inspect manifest` can already do all of this; and `open_store` exists for
  `swp-cli`, which is a Rust crate. **It is therefore a Rust-only door: no binding may
  wrap it**, and §11 marks it as the one public accessor whose return value opens the
  private half of the store.
* **Expected tags.** `ManifestKeys::fragment_tag` (`keys.rs:149`) and
  `ReleaseIndex::expected_tag` (`index.rs:257`) would turn a binding into a tag
  oracle: a caller could test a candidate without the evidence maths that decides
  whether a match means anything, and quote the answer as a finding. The two
  façade accessors that could reach them are `pub(crate)` for exactly this reason:
  `load_releases` (`session.rs:371`) hands back the keyed constellation itself, and
  `indexes` (`:428`) the built `ReleaseIndex`es. No public signature of the façade names
  either type — which is a statement about the façade, not about a caller that links
  `swp-manifest` directly.
* **Private store paths and private manifests, through a `Session`.**
  `Store::root_key_path`
  (`store.rs:86`), `read_private_manifest` (`:358`). The façade's own private
  manifest read is module-private (`private_manifest`, `session.rs:444`) — not even
  `pub(crate)` — and the release loader refuses a manifest whose recorded id is not
  the one asked for (`ReleaseMismatch`, `:380-389`). A `Session` offers no way to reach
  either; the second handle in the bullet above does, by design, for the CLI.
* **`inspect`.** Eight views of a store (`View::ALL`, `inspect.rs:62-71`), three of
  which print private manifest contents — `manifest`, `plan`, `fragments`
  (`view_names` and `private_view_names`, `inspect.rs:143-157`, both built from the
  same table so a fourth private view cannot be added to one list and left out of
  the other). A typed accessor is the right answer to a real future need; note
  that the *public* half of what `inspect` prints is already reachable without
  one, through `Session::identity`, `config`, `stored_config`, `release` and
  `release_history`.
* **`swp` as a subprocess.** Explicitly out of scope, and the boundary makes it
  unnecessary: `capabilities()`, `protect()`, `scan()` and `Report` reach the
  same code the binary runs.
* **A "quick mode", a "strict mode", or any knob that overrides a safety
  refusal.** There is no such flag in the CLI and there will not be one in a
  binding (`docs/DEVELOPER-GUIDE.md`, "Skip, never force").

## 11. The Rust surface as shipped

This section is the freeze list: what `swp-sdk` exposes today, so that a binding
plan can be written against names rather than against the prose above. Everything
here is read from `crates/swp-sdk/src/`; nothing in it is a plan. The same
classification is written as data in [BINDING_SURFACE.json](BINDING_SURFACE.json),
which is what a binding reads, and the `binding_surface` suite fails this workspace
when the file and the crate disagree in either direction.

**Modules.** `capabilities`, `init`, `protect`, `report`, `scan`, `session`,
`verify` — all `pub mod`, and each one's items are also re-exported at the crate
root (`lib.rs:85-101`), so `swp_sdk::Session` and `swp_sdk::session::Session` are
one type.

**Crate-level items.** `VERSION: &str` (`lib.rs:105`) and `banner()` (`:113`) —
one function, because the same sentence goes into a report's `generator` field and
into `swp --version`, and a library build and a CLI build that described
themselves differently would put two generators on one release.

**Types re-exported from the service crates, unchanged** — the façade defines no
wrapper for any of them: `ErrorCode`, `SwpError`, `ProjectId`, `ReleaseId`,
`Limits`, `Mode`, `Protection` (`swp-embedding`), `Report`, `SiteRow`, `Verdict`,
`VerifyDocument` (`swp-evidence`), `ProjectIdentity`, `ReleaseRecord`, `Store`,
`SwpConfig` (`swp-identity`).

**`session`**

```rust
pub struct Overrides {                    // session.rs:36-49 — Default, PartialEq, Eq
    pub targets: Vec<String>,             // appended to [protect] targets; containment applies
    pub excludes: Vec<String>,            // appended to [protect] excludes
    pub target_sites: Option<u32>,
    pub tag_bits: Option<u8>,
    pub embed_strings: Option<bool>,
}

pub enum ReleaseSelection {               // :57-65 — Default = All
    All,
    Latest,                               // newest by recorded time
    Ids(Vec<ReleaseId>),                  // each one must exist
}
```

`Overrides` is the whole of what a caller may change about the stored settings, and
it is applied once, at open (`session.rs:143-175`), so nothing downstream knows a
flag was involved — that is what keeps `swp_embedding::protect` validating one
coherent settings document. An invalid patch is a `USAGE` error from
`Session::open`/`discover`, before any operation runs. `Latest` means the newest
**recorded time** in the release records, ties broken by id (`:500-512`).

`Session` (`session.rs:76-81`) is `Debug + Clone`, and its public methods are:

| | |
| --- | --- |
| openers | `init(project_root, &InitOptions) -> InitOutcome` (associated), `open(&Path, &Overrides)`, `discover(&Path, &Overrides)` |
| what the project is | `identity()`, `config()`, `stored_config()`, `limits()`, `warnings()`, `project_root()`, `open_store()` |
| which releases | `releases(&ReleaseSelection)`, `one_release(&ReleaseSelection)`, `release_history()`, `release(&ReleaseId)` |
| the operations | `protect(&ProtectOptions)`, `protect_summary(&ProtectOptions)`, `verify(&VerifyOptions)`, `scan(&Path, &ReleaseSelection, bool)`, `reports()`, `read_report(&str)` |

`config()` is the stored config *with this run's overrides applied*;
`stored_config()` is the file on disk, unchanged, for a caller that must not act on
a setting nobody wrote. `release_history()` sorts by `(created_at, release_id)`
(`:317-328`) — which is the order a history is printed in and is deliberately not
`Store::releases()`' alphabetical file order, so a listing parity assertion is
made against this, not against the store's directory walk.

`open_store()` is the one method in that list whose return value is not nothing: it
hands back a second `Store` handle (`:221-231`), which can read the private half of
the directory and load the sealed secret. It is public because `swp-cli` is a separate
crate and `swp inspect`'s three private views need it; §10 states the rule that comes
with it — Rust-only, never wrapped by a binding.

**`init`** — `InitOptions` (`init.rs:66-74`), `Measurement` (`:39-48`), `Settings`
(`:52-61`), `InitResult` (`:86-109`), `InitOutcome` (`:112-115`), and
`suggest_sites(files: u32) -> u32` (`:300`), public because it is the single source
of the default constellation (§9's no-hard-coded-site-count rule) and a caller that
wants to explain a number must be able to compute it.

**`protect`** — `ProtectOptions` (`protect.rs:45-73`) + `ProtectOptions::new(Mode)`
(`:78`), `ProtectOutcome` (`:89-101`), and the binding-facing account of the same run
`ProtectSummary` (`:180-240`) with its three row types `ProtectedFile` (`:109`),
`ProtectedSite` (`:126`) and `RefusedSite` (`:156`), returned by
`Session::protect_summary` (`:256`) and built by the one private projection
`summarize` (`:267`). **No `Default`** on `ProtectOptions`, by the
reason stated in §4.

**`verify`** — `VerifyOptions` (`verify.rs:27-44`, `Default`), `VerifyOutcome`
(`:48-57`).

**`scan`** — `ScanOutcome` (`scan.rs:27-41`), `ScannedSite` (`:51-74`),
`SavedReport` (`:78-87`).

**`report`** — `StoredReport` (`report.rs:25-35`), `report_stem(&str) -> String`
(`:88`).

**`capabilities`** — `capabilities()` (`capabilities.rs:112`) and the five structs
§1 documents (`:23, :33, :51, :69, :87`), each `Serialize`, so the answer a
binding shows is the same JSON on all three ecosystems.

**Derives, stated because a binding's generated types depend on them.** The two
versioned documents (`Report`, `VerifyDocument`) and `Capabilities`/`Measurement`/
`Settings` and the capabilities range types derive `Serialize`, and the documents
derive `Deserialize` with `deny_unknown_fields` as well. The *envelopes* —
`InitOutcome`, `InitResult`, `ProtectOutcome`, `VerifyOutcome`, `ScanOutcome`,
`ScannedSite`, `SavedReport`, `StoredReport` — are `Debug`/`Clone` data with typed
fields and are read field by field, not serialized: a binding that wants JSON of a
`ScanOutcome` serializes `report`, which is the artifact that has a schema.
`VerifyOutcome` is `Debug` only (it holds the document by value), and `InitOutcome`
derives nothing so that it can hold a `Session` and stay moveable.

`ProtectSummary` and its three row types are the exception, and deliberately: they
derive `Debug`/`Clone`/`PartialEq`/`Eq`/`Serialize` and nothing else. No
`Deserialize` — a summary is what a run said, not something to be authored — and no
borrowed fields, so the value an FFI caller receives is one it can keep, compare and
print without holding the `Session` that produced it. It is serialized by a binding
because there is no schema for it to obey; `swp protect --format json` remains the
documented, versioned artifact, and this is the Rust-side account that a caller
outside Rust can be given.

**The keyed-material boundary, by name.** These items are how the façade reaches what
§10 refuses. All but the last are not `pub`, and the last is the one place the surface
lets the store through.

| item | where | visibility | why it stops there |
| --- | --- | --- | --- |
| `Session::secret` | `session.rs:265` | `pub(crate)` | returns a `RootSecret`; §10 keeps key bytes off the surface |
| `Session::load_releases` | `:371` | `pub(crate)` | returns `swp_detection::CandidateRelease` — manifest, record and `ManifestKeys` together |
| `Session::loaded` | `:414` | `pub(crate)` | a selection-resolving wrapper over the same |
| `Session::indexes` | `:428` | `pub(crate)` | a built `ReleaseIndex` answers "what tag would this site carry" |
| `Session::private_manifest` | `:444` | module-private | the keyed constellation is the document itself |
| `Session::store` | `:453` | `pub(crate)` | the session's own handle, kept inside so the operations share one authenticated view of the store |
| `Session::relabel` | `:449` | `pub(crate)` | not secret-bearing; internal because callers should see store-relative strings, not a path helper |
| `Session::build` | `:125` | `pub(crate)` | the shared open path for `open`/`discover`/`init` |
| `Session::open_store` | `:229` | **`pub`** | the exception, and a handle rather than bytes: §10 states why it is public and why no binding may wrap it |

The rule that keeps the list honest: no signature in this crate hands out key bytes, a
derived key, an expected tag or a parsed private manifest, and `swp-sdk` re-exports no
type that can be turned back into bytes — `SecretBytes::as_slice` is `pub(crate)`
inside `swp-crypto` (`secret.rs:39`), which is what makes that hold even of the handle
above. What the crate does offer, deliberately and in Rust only, is the store itself.

Two things qualify that sentence, and both are on the list rather than under it.
The rule is about *names in signatures*, so a value reachable by walking public fields
is a different question: `Session::protect()`'s result reaches
`PlannedSite.locations: [LocationId; 4]` (`swp-embedding/src/plan.rs:57`) — a keyed
site identity, not a key, and not a tag, and the first thing a binding would print if
it were free to walk the struct. Hence `protect`/`ProtectOutcome` as `pending` and
`LocationId`/`Plan`/`PlannedSite`/`Protection` as `forbidden` in the boundary file,
with the field read by a `const` closure in the suite so the classification changes
only when the field does. The operation is not therefore unavailable to a binding:
`Session::protect_summary` returns the same run projected onto fields that carry no
key, and it is the door the boundary file names for protection. `protect` stays
`pending` because narrowing *its* result to this shape is a `MAJOR` change to the
Rust API (§11 of `VERSIONING_POLICY.md`), not because nothing crosses.
And `open_store` in the table above is the only row marked
`pub`; the row exists because being public is a fact about the Rust API, not a
licence for a binding to wrap it.

## 12. Binding-readiness notes

Six questions a binding author asks first, answered with what the source actually
says. Where the answer is "this is not specified", that is stated rather than
smoothed over, because a binding that guesses becomes the second implementation
this boundary exists to prevent.

* **Release selection is specified.** `All` is the default and means *every*
  release; `Latest` is the newest recorded time, ties by id
  (`session.rs:500-512`); `Ids` requires each id to be present and refuses the
  whole call otherwise — partially-matching a selection would be a silent claim
  about which releases were skipped (`:286-301`). `one_release` narrows a selection
  to one: the id named, or the newest when several matched (`:305-314`).
* **Missing-release behaviour is specified, and it is not one code.** A project
  with no releases is `NOT_PROTECTED` with the "run `swp generate`, then
  `swp protect`" advice (`session.rs:272-282`); a selection that names a release
  the store does not have is `NOT_PROTECTED` too, and it lists the ids that *are*
  there (`:286-297`). Reading one release record directly, `Session::release(&id)`,
  goes through `Store::read_release` and so reports `IO_ERROR` for an absent file
  (`swp-identity/src/store.rs:465-473`). A binding that wants "does this release
  exist" must ask the selection path, not the record path; the two otherwise
  disagree in exactly the case where a user typed a wrong id. An
  unreadable-but-present manifest or record is `INVALID_MANIFEST`, and one whose
  stored id is not the id asked for is `RELEASE_MISMATCH` (`session.rs:380-389`).
* **Scan per-site semantics are specified** in §5, down to which status words count
  as evidence and what `probes` versus `distinct_codes` mean for the coincidence
  bound. What is *not* specified is an ordering guarantee beyond "scan order, then
  the release's own site order" (`scan.rs:32-40`) — a binding must not assume the
  rows arrive strongest-first the way `Report.releases` does.
* **Saved-report naming and read-back are specified** in §7: a stem is
  `scan-<timestamp>` or `verify-<timestamp>`, the store numbers a collision instead
  of overwriting (`store.rs:379`) and hands back the name it used (`scan.rs:174-180`),
  and all three spellings of that entry resolve to the same document. A report is
  never rewritten and never re-graded on the way back.
* **Machine contract versus presentation text.** Contract: `ErrorCode::as_str()`
  and its discriminant, the field names and value domains of `SWP-1-report-v2` and
  `SWP-1-verify-v1`, the four status words, `Mode`, `Verdict`, the `&'static str`
  value sets that `secret_state`, `secret_scheme` and `gitignore` carry, and
  store-relative forward-slashed paths. Presentation: the CLI's stdout — its
  column alignment, its next-step lists, its per-view renderings — and
  `SwpError::render()`. In between sit
  the *prose fields inside a versioned document*: `Report.explanation`,
  `Report.limitations`, `VerifyDocument.next`, `SwpError::next_step`. Those are
  wording rather than values, stable only in the sense that a schema version governs
  them; a binding may display them and must not parse them.
* **Which structures are binding-facing, and the categories that are not.**
  The answer is data, not prose: [BINDING_SURFACE.json](BINDING_SURFACE.json) names
  every item under five categories — `binding_facing` (what a future Python or Node
  binding may wrap), `rust_only` (public in Rust on purpose and staying there),
  `forbidden` (would hand a caller keyed or private material), `pending` (meant to
  cross, blocked by a named item), `sealed` (must not become public at all) — and the
  `binding_surface` suite is what keeps the file describing this crate.
  Every type in §11's list is `binding_facing` — it is the surface the Rust caller
  reads, and `swp-cli` reads the same fields to print — except the two that §4
  explains: `Session::protect` and `ProtectOutcome`, both `pending`, blocked by the
  keyed plan their result reaches, with `Session::protect_summary` as the door that
  crosses today. And one of §11's re-export list is not `binding_facing` at all:
  `Protection` comes out of `swp-embedding` at `lib.rs:99` because `ProtectOutcome`
  holds it, and the boundary marks it `forbidden` for the reason §4 gives. Naming a
  type in a public signature and offering it to a binding are different decisions,
  and the file keeps them apart. Two items are `rust_only`, and
  both are in §10: `Session::open_store()` — it hands back the store
  handle, which is a capability rather than a value, and a binding that wrapped it
  would offer `swp inspect manifest` as a method — and `Store` itself. That leaves the
  façade's other re-exports, `ProjectIdentity` and `ReleaseRecord`: they are
  `binding_facing` because they are what `identity()` and `release()` return, and they
  carry public identity and published release fields; the private reads a binding must
  not offer are the methods on `Store`, not these values. The two enum *types* that
  appear as `Report` field values —
  `swp_evidence::Outcome` and
  `swp_evidence::EvidenceLevel` — are **not re-exported by `swp-sdk`**, so a Rust
  caller either names them through `swp-evidence` (which it may already depend on)
  or reads `report.result.as_str()` / `report.evidence_level.as_str()` and the JSON.
  This is a gap in the façade's export list rather than a boundary decision: nothing
  key-shaped is behind either name, and closing it is a one-line `pub use` in a
  commit that also fixes a binding's need, not a documentation change.
