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

Conventions used below:

* **Effects** — what the operation touches: `none`, `reads`, `writes store`,
  `writes source`. Every one of these is derived from code, and `protect`'s two
  write predicates are the implementation's own
  (`swp-embedding/src/protect.rs:99, :106`).
* **Secret** — whether the operation loads the project's root secret, and if so
  where it is dropped. A `Session` never holds one between calls; today's code
  loads inside the operation and drops it before the tree walk
  (`crates/swp-cli/src/ctx.rs:270, :298`; `swp-cli/src/protect.rs:106, :119`),
  and the boundary keeps that.
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

## 2. `Session::init(project_root, options) -> Session`

Create or re-open a project's store. Two outcomes, and the difference is a fact
about the tree rather than a flag: a directory that already has a store keeps its
identity and its secret, because SWP never replaces a project secret
(`swp-identity/src/store.rs:210-214`).

| | |
| --- | --- |
| Inputs | `project_root: Path`, `name: Option<String>` (the display label, validated at `swp-cli/src/init.rs:111-135`) |
| Effects | **writes store**: creates `.swp/`, `root.key`, `identity.json`, `config.toml`, and the `.gitignore` entry (`store.rs:185-244`) |
| Secret | generates one (`SealedSecret::generate`, `swp-crypto/src/seal.rs:81`), hands it to `Store::init`, drops it (`init.rs:155, :167`). Never accepts one. |
| Blocks | briefly (one tree measure, `init.rs:335`) |
| Concurrent | one init per project at a time. There is no lock in this tree, in any layer. |

```rust
pub struct InitResult {
    pub project_id: ProjectId,
    pub display_name: String,
    pub pre_existing: bool,             // store.rs:49-59 StoreInit
    pub secret_state: &'static str,     // "created" | "kept"
    pub secret_scheme: &'static str,    // "dpapi" | "plain" — seal.rs:32-38
    pub secret_handle: String,          // RootSecret::fingerprint(), secret.rs:95 — 8 chars, non-secret
    pub permissions_verified: bool,     // PermissionOutcome::is_verified(), seal.rs:231
    pub permissions_detail: String,     // what the OS reported back
    pub gitignore: &'static str,        // "created" | "updated" | "already ignored" | "not written"
    pub created: Vec<String>,           // store-relative, forward-slashed
    pub measurement: Measurement,       // files, bytes, per-language counts, top-level dirs
    pub settings: Settings,             // the targets and site count this run wrote
}
```

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

`measurement` and `settings` are `swp-cli`'s private shapes today
(`init.rs:40-48`, `:64`); the façade exposes equivalent types whose fields are
the same values, so that `suggest_sites` (`init.rs:387`) stays the single source
of the default constellation.

Errors: `USAGE` when the path is not a directory; `SECRET_UNAVAILABLE` (exit 3's
code) when a store exists and its key cannot be opened; `IO_ERROR`. A private
artifact whose access could not be confirmed is refused by the store, which is
`swp-identity`'s rule, not a new one.

## 3. `Session::open(project_root) -> Session`

Reopen a project without creating or changing anything.

| | |
| --- | --- |
| Inputs | `project_root: Path`, absolute, named by the caller |
| Effects | reads `config.toml`, `identity.json` |
| Secret | no |
| Blocks | no |
| Concurrent | yes — a `Session` is a path plus two parsed documents, and every operation reloads what it needs |

`Store::open` (`store.rs:166`) requires the caller to say which directory it is,
and that requirement is a security property the binding must not blur: a
candidate tree may contain its own `.swp/`, and the scanner must never read
config from the tree it is scanning (`swp-identity/src/config.rs:1-8`). So
`Session::open` takes an explicit path and there is no "find my project" default
in the API — the CLI's `Store::discover(cwd)` (`store.rs:150`) walks up from the
*process* working directory, which for an embedded library means whatever the
host application's cwd happens to be, and a protection run whose scope depends
on an ambient directory is not a protection run anyone should script. A binding
may offer a `discover()` convenience; it must resolve it in the host and pass the
result in.

Errors: `NOT_PROTECTED` with the same two-cause message the CLI gives
(`ctx.rs:59-76`), `INVALID_MANIFEST` for an unreadable identity.

## 4. `Session::protect(options) -> Protection`

The one operation that rewrites source, and — with `mode: plan` — the one that
records a constellation without touching it. `swp generate` and `swp protect` are
already the same function in the CLI (`swp-cli/src/lib.rs:131`
→ `protect::run(.., mode)`), and they are one operation here for the same reason.

| | |
| --- | --- |
| Inputs | `mode`, `release_id: Option<String>`, `sites: Option<u32>`, `tag_bits: Option<u8>`, `targets: Vec<String>`, `excludes: Vec<String>`, `embed_strings: Option<bool>`, `revision: Option<String>` |
| Effects | `plan` → **writes store** (manifest, plan, release record); `release` → **writes store + source**; `dry_run` → **none** (`protect.rs:99, :106`) |
| Secret | yes: `ManifestKeys::derive` (`swp-manifest/src/keys.rs:73`) and `ManifestSigningKey::from_root`. Dropped when the call returns (`swp-cli/src/protect.rs:119`). |
| Blocks | yes, proportional to tree size. This is the call a binding must run off the host's main thread. |
| Concurrent | one `protect` per project at a time. Two at once write the same files. |

```rust
pub enum Mode { Plan, Release, DryRun }        // mirrors swp-embedding::Mode, protect.rs:78-87
```

The returned `Protection` is the service crate's type
(`swp-embedding/src/protect.rs:142-171`), which already derives `Serialize` and
already carries `artifacts` (store-relative, in write order, `:165-167`),
`files_changed`, `sites_embedded`, `sites_skipped`, `candidates`, the fingerprint
and its level, and the full `Plan` including every refusal with its reason. The
façade adds nothing to it and subtracts nothing from it.

`release_id` is not cosmetic and is the easiest way for a binding to get this
wrong. A plan is keyed by release id, so applying a generated constellation
means passing the same id: `swp protect --release <id>` after `swp generate`
(`swp-cli/src/protect.rs:89-95`). A binding that allocates a fresh id for the
second call derives different keys, embeds different tags, and produces a second
release the plan does not describe — while still succeeding. So the rule is:
`mode: plan` returns `release_id` and `mode: release` accepts it; a fresh id is
allocated only when the caller passes none, which is the "protect without a plan"
case the CLI runs by default.

`targets` are subject to the containment rule the CLI applies today: an absolute
target must resolve inside the project root or it is `USAGE`
(`ctx.rs:101-144`), because a target that escapes the root is a way to write
outside the project. Warnings the CLI prints before a run (a limit clamped
against the hard ceiling, `ctx.rs:81-89`) are returned as `notes` on the result,
not raised as errors and not dropped.

Errors: `NO_SAFE_LOCATIONS` when every candidate failed a safety precondition —
source unchanged, and that is the designed outcome, not a failure to work around
(`AGENTS.md`, and `error.rs:148-154`); `LIMIT_REACHED` when a resource ceiling
trimmed the run; `MALFORMED_SOURCE`/`PARSER_FAILURE` from the adapters;
`RELEASE_MISMATCH` when a named release already exists with different content
(`protect.rs:193`).

## 5. `Session::scan(candidate, options) -> Report`

Ask whether this build's provenance is present in an artifact you did not write.

| | |
| --- | --- |
| Inputs | `candidate: Path` (directory, file, `.zip`/`.tar`/`.tar.gz`), `releases: ReleaseSelection` (`All` — the default — `Latest`, or explicit ids), `save: bool` |
| Effects | reads the candidate and the store; **writes outside the project** when unpacking an archive (`swp-detection/src/input.rs:333-343`, removed on `Drop`); writes `reports/` only if `save` |
| Secret | yes, to derive each release's keys — and dropped before the candidate is opened (`ctx.rs:298`), because a scan should not hold a key while walking a stranger's tree |
| Blocks | yes, proportional to candidate size |
| Concurrent | yes for *different* candidates; a `save` to the same store from two threads is one artifact per call and `Store::save_report` numbers a collision rather than overwriting (`store.rs:379`) |

```rust
pub struct Report { /* the swp-evidence document, verbatim */ }

impl Report {
    pub fn from_json(text: &str) -> Result<Report, Error>;   // report.rs:140
    pub fn to_json(&self) -> String;                          // report.rs:132
    pub fn to_text(&self, full: bool) -> String;              // report.rs:170
    pub fn result(&self) -> Outcome;                          // PROVENANCE_DETECTED | NO_PROVENANCE_DETECTED | INCONCLUSIVE
    pub fn evidence_level(&self) -> EvidenceLevel;            // NONE … VERY_STRONG
    pub fn exit_code(&self) -> i32;                           // report.rs:126 — a property of the document
}
```

`Report` is not a binding type. It is `swp_evidence::Report` (`report.rs:69-92`),
which derives `Serialize` + `Deserialize` with `deny_unknown_fields`, carries
`schema` and `protocol` in itself, and refuses a document from another schema
with `PROTOCOL_VERSION_UNSUPPORTED` (`report.rs:147-162`). Every binding exposes
the same JSON and the same text rendering, so a report produced by the CLI, by a
wheel, or by a `.node` addon is one artifact with one reading path.

The release-selection default is `All`, and that is the protocol's choice rather
than a convenience: a copy could have come from any release, and picking one
silently would be a claim about which (`ctx.rs:179-184`).

`scan` of a candidate that contains a store does not read that store's config
(`config.rs:1-8`); a `PathRejected` error means the archive tried to escape its
extraction directory and the whole candidate was refused rather than partially
read (`error.rs:155-157`).

## 6. `Session::verify(options) -> VerifyDocument` — **not in Beta 3's first cut**

The operation is real, and so is the reason it is held back. `swp verify` answers
a different question from `swp scan`: it reads *this* tree against *one named*
release and gives a per-site verdict — `INTACT`, `INCOMPLETE`, `INCONCLUSIVE`
(`swp-cli/src/verify.rs:189-195`) — in a `SWP-1-verify-v1` document whose type is
module-private inside `swp-cli` (`verify.rs:104`).

Two options exist and only one is honest. The document moves down into
`swp-evidence`, unchanged, and `swp-cli` renders what the service produced; or
`verify` is not exposed and a caller uses `scan` of their own project root, which
returns a report and *not* a verdict. Offering the second and calling it
`verify` would put a scan's outcome behind a verify's name, which is the kind of
claim this project's rules close changes over. So: the move happens first, and
this section documents the operation it will expose — same effects table as
`scan`, no candidate path, `release: Option<String>` defaulting to the newest
(`ctx.rs:215-224`), and the report written only with `save`.

Until then, `verify` is absent from every binding, not present and weaker.

## 7. Report access: `Session::reports()`, `read(stem)`, `Report` from a string

Reading a stored report back is the operation with the fewest edges: no secret
(mirrored by a test in the CLI's `inspect.rs:1006`), no tree walk, no write.

| | |
| --- | --- |
| Inputs | `Session::reports()` → names; `read(stem)` → bytes → `Report::from_json`; or `Report.parse(text)` with no session at all |
| Effects | reads `reports/`; `parse` touches nothing |
| Secret | no |
| Blocks | no |
| Concurrent | yes |

`stem` is validated by `Store::report_path` (`store.rs:125`), which is the layer
that refuses a name that would escape the reports directory; a binding must pass
the stem it was given and not build a path.

`Report.parse` with no session is the operation a report viewer wants, and the
one that must not be mistaken for a scan: it grades a document that was already
graded. The text and JSON it produces are the stored document's, and the numbers
in it are the arithmetic of the build that wrote it — which is
[VERSIONING_POLICY.md](VERSIONING_POLICY.md)'s subject.

## 8. Errors

Every failure is a `SwpError` re-projected, not a new taxonomy
([audit §6](BETA3_ARCHITECTURE_AUDIT.md)):

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
  would live in garbage-collected memory this project cannot zeroize.
* **Expected tags.** `ManifestKeys::fragment_tag` (`keys.rs:149`) and
  `ReleaseIndex::expected_tag` (`index.rs:257`) would turn a binding into a tag
  oracle: a caller could test a candidate without the evidence maths that decides
  whether a match means anything, and quote the answer as a finding.
* **Private store paths and private manifests.** `Store::root_key_path`
  (`store.rs:86`), `read_private_manifest` (`:358`).
* **`inspect`.** Nine renderings of a store, three of which print private
  manifest contents (`inspect.rs:143-158` splits public from private views for
  that reason). A typed accessor is the right answer to a real future need.
* **`swp` as a subprocess.** Explicitly out of scope, and the boundary makes it
  unnecessary: `capabilities()`, `protect()`, `scan()` and `Report` reach the
  same code the binary runs.
* **A "quick mode", a "strict mode", or any knob that overrides a safety
  refusal.** There is no such flag in the CLI and there will not be one in a
  binding (`docs/DEVELOPER-GUIDE.md`, "Skip, never force").
