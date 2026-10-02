# SDK architecture (Beta 3)

Beta 3's deliverable is a boundary, not a feature. [The audit](BETA3_ARCHITECTURE_AUDIT.md)
established what is already here; this page is the set of decisions built on it,
with the reason for each and the cost it carries. The operation-by-operation
contract is in [SDK_API.md](SDK_API.md) and the version rules are in
[VERSIONING_POLICY.md](VERSIONING_POLICY.md).

Nothing on this page changes the protocol, the derivation, the tag algorithms,
the evidence mathematics, the report schema, or what any of them mean. If a
decision below appears to require one of those, the decision is wrong and the
audit citation next to it is the place to argue.

## 1. The boundary, in one diagram

```text
             Python                     JavaScript                   TypeScript
                │                            │                          │
                │ PyO3 extension module      │ napi-rs addon (.node)    │ generated .d.ts
                ▼                            ▼                          ▼
        bindings/python/swp-python   bindings/node/swp-node ── same crate ──┘
                            \            /
                             ▼          ▼
                        crates/swp-sdk          ← one façade: session, ordering,
                             │                     error and panic envelopes
       ┌──────────┬──────────┴───────────┬──────────────┬───────────┐
       ▼          ▼                      ▼              ▼           ▼
  swp-embedding swp-detection       swp-evidence   swp-identity  swp-manifest
       └──────────┴───────────┬──────┴──────────────┴───────────┘
                              ▼
                     swp-core · swp-crypto · swp-adapters
```

The line that matters is the one between `swp-sdk` and `swp-cli`: it does not
exist. The façade does not depend on `swp-cli` in any release, and `swp-cli` is now
its consumer — the dependency this page's first draft expected but did not claim
for this release, because until the extraction landed there was nothing to depend
on. The reason the direction is one-way is the one-way rule restated for a new
consumer: a binding must never have to parse text or branch on an exit code, and a
façade must never have to render. What the façade *is* is `swp-cli`'s composition,
moved out of it — see §2 — so that there is one sequence that authenticates a
release, and `swp-cli` is the rendering on top of it rather than a second
implementation beside it.

## 2. PHASE 1 decision: a façade, created by extraction

The audit's §8 compares the options at length; the short version is that the
three things a binding needs before it can produce a correct answer were already
written, once, and they were in the CLI crate:

| need | where the audit found it | why a binding cannot re-do it |
| --- | --- | --- |
| open a project without a command line | `Ctx::open`, `crates/swp-cli/src/ctx.rs:48-92` | it is `Store::open`/`discover` + `identity()` + `config()` + the limit-ceiling warnings, in that order |
| turn a store into something the detector may trust | `Ctx::load_releases`, `ctx.rs:266-306` | two signature checks against the *public* verify key (`ctx.rs:316-330`), manifest/release id agreement, key derivation under *this* identity's canonicalizer version, `drop(secret)` before the walk |
| choose the defaults a project gets | `suggest_sites` `init.rs:387`, `write_settings` `init.rs:405`, `--target` containment `ctx.rs:101-144` | a re-implementation diverges from `swp init` on the same tree, in a value the user never typed |

Those line numbers are the state this decision was made from, and they no longer
point at the code: each row moved down rather than being copied. `Ctx::open` is
`Session::open`/`discover` and `Session::build` (`crates/swp-sdk/src/session.rs:91,
:105, :125`), `Ctx::load_releases` is `Session::load_releases` with the same four
rules and the same `drop(secret)` (`session.rs:371-411`), and the defaults are
`suggest_sites` (`swp-sdk/src/init.rs:300`), `write_settings` (`:318`) and the
target-containment check (`session.rs:143-175`). `swp-cli/src/ctx.rs` is now the
flag→`Overrides` translation and the private-artifact reads `swp inspect` needs.

So: **`crates/swp-sdk`, a new publishable library crate whose `src/` holds types,
ordering, and envelopes — no protocol, no crypto, no grading.** It is created by
moving the `Parsed`-free half of `ctx.rs` down into it, not by writing new
composition beside the old. `swp-cli::ctx::Ctx` then holds a `swp_sdk::Session`
and keeps only the flag→options translation, so `Parsed` survives in `swp-cli`
and nowhere below it.

Two invariants that keep the façade from becoming a second product:

1. **Every operation is a call into a service crate.** If `swp-sdk/src/` ever
   contains arithmetic, canonicalization, a path rule, or a decision about
   evidence, that code belongs one layer down and this page is wrong about it.
   The extraction held: the only rules the crate owns are which release id a run
   uses, what the source is claimed to be, where the secret is dropped, and how a
   report's three names normalize to one entry — and each of those is stated in
   [SDK_API.md](SDK_API.md) with the call it delegates to.
2. **The façade and the CLI must agree, and one test proves it** (§7, "parity").
   A binding that disagrees with `swp protect` on the same tree is a bug in the
   boundary, not a platform difference.

What the façade adds that the crates do not have: a `Session` that owns no
secret between calls (the `Ctx` this came from loaded and dropped one per
operation, `ctx.rs:270`/`:298` in the pre-extraction file, and `Session` keeps
that at `session.rs:403` and `swp-sdk/src/protect.rs:377`), owned plain-data
argument types instead of eight-borrow `Request<'a>`
(`swp-embedding/src/protect.rs:114-130`), and one place for the errors to be
shaped. The `catch_unwind` and the error *conversion* in this list belong to the
FFI boundary, not to this crate: in Rust a façade call returns
`Result<T, swp_core::error::SwpError>` with the service crate's own code and text,
because converting one Rust error type into another adds a taxonomy and no
information ([SDK_API.md](SDK_API.md) §8). A panic across that boundary is
`INTERNAL_ERROR`, and a panic in Rust stays a panic.

## 3. PHASE 2 decision: the operation surface

The protocol has seven verbs. The binding surface has five operations plus a
data type, because the audit showed that two of the verbs are one call
(`mode_of`, `crates/swp-cli/src/lib.rs:131`) and two of them are CLI
affordances. Every row marked *yes* is reachable from `swp-sdk` as shipped; the
`maps to` column is still the audit's map, so its line numbers are the
pre-extraction ones except where a row below says otherwise.

| operation | maps to | exposed | why |
| --- | --- | --- | --- |
| `capabilities()` | `swp_core::version`, `Registry::parsed_languages` + `extensions`, `Limits`, `TagWidth`, `REPORT_SCHEMA` | yes | read-only, pure, no filesystem, no secret; and the audit's §7 shows no single API answers "which languages and which extensions" |
| `init` | `SealedSecret::generate` → `Store::init` → `measure` → `suggest_sites` → `write_settings` (`init.rs:105-151`) | yes | without it nothing else can run; the store cannot be hand-built |
| `protect` (modes `plan` / `release` / `dry_run`) | `swp_embedding::protect(&Request)` with `Mode` (`protect.rs:78-108`) | yes, as **one** operation, with two results: `protect` → `ProtectOutcome` for Rust and `protect_summary` → `ProtectSummary` for a binding | `generate` and `protect` already are one function; splitting them into two binding methods invites divergence — and so does a second protection pipeline, which is why the binding-facing result is a projection of the same call rather than a re-run of it (§6) |
| `scan` | `ctx` release load + `build_indexes` + `input::open` + `scan_against` + `Report::build` (`scan.rs:41-73`) | yes | the embedding question an integrator actually asks: "is my provenance in this artifact?" |
| `verify` | the same, against the project root, plus the per-site verdict — now `Session::verify` (`swp-sdk/src/verify.rs:71`) | yes | this row was the exception when the page was written: the answer was `VerifyDocument`, a module-private DTO inside `swp-cli`, and exposing it meant moving it down into `swp-evidence` first (`swp-evidence/src/verify.rs:139`, schema `SWP-1-verify-v1` at `:46`). The move happened, on the original field set, before the façade took it. Until it had, `scan` of your own tree was all the binding could offer — which is *not* the same claim, and pretending otherwise is the overclaim this project's rules forbid |
| `report` | `Store::read_report`/`report_names` + `Report::from_json`/`to_json`/`to_text`/`exit_code` (`report.rs:118`, `swp-evidence/src/report.rs:126-182`) | yes, as a data type | already a versioned, fully serializable document with a schema guard; the cleanest existing model for what a binding result should look like |
| `inspect` | `inspect.rs:159`, eight views (`View::ALL`, `:62-71`) | **no** | see below |
| `help`, `--version` | `help.rs` | no | terminal affordances; `capabilities()` is the machine form of the one that carries information |

`inspect` is refused on three grounds, and the middle one is decisive. It is a
human audit surface over `.swp/private/` whose views are renderings, not types.
And three of its views — `plan`, `fragments`, `manifest` (`inspect.rs:143-157`
already splits public from private views for exactly this reason) — print
private-manifest contents, which is material PHASE 5 puts on the
must-not-cross list; putting them behind a binding method would make a routine
`console.log` in somebody's application a private-manifest dump. If an embedder
later needs "what is in my store", the correct answer is a new typed accessor
next to `session.releases()`, not `inspect` over FFI. Deferred, by name, with
the reason, so that a future request has something to argue with.

`generate` and `inspect` were each evaluated against "does a caller need this or
would they build it wrong?" and the answers above are the ones the audit
supports. No operation in this table is new: every row is a command that already
exists, and there is no row for an operation that does not.

## 4. PHASE 4 decisions: the bindings

Both ecosystems get a native addon that links the same Rust code the CLI links.
That is not a preference; it is forced by what the operations do — file
rewrites, DPAPI, `icacls`, archive extraction — which §4.3 says why.

### 4.1 Python: PyO3 + maturin

**Decision: PyO3, `abi3` with a floor of CPython 3.10, wheels built by maturin
per OS/arch, source-only fallback.**

* *Why PyO3 rather than a C API or ctypes-over-cdylib:* it is the only option
  here that gets reference counting, exceptions, `PathLike` handling and the
  GIL right without hand-written C, and it is what maturin is built around.
* *Why `abi3`:* the stable ABI is documented as forward-compatible — an
  extension using only the Limited API "can be compiled once and be loaded on
  multiple versions of Python" and is "ABI-compatible with all Python 3
  releases from the specified one onward" (Python 3.14, *C API Stability*). One
  wheel per platform per OS rather than one per interpreter minor version,
  which for a tool whose wheel carries a tree-sitter grammar and a C linker
  invocation is the difference between a release process and a scheduler.
  Windows caveat from the same page: stable-ABI extensions link
  `python3.dll`, and nothing verifies that an `abi3` wheel is installed on a
  Python new enough to satisfy it — so the floor must be stated in the package
  metadata (`requires-python = ">=3.10"`), not merely assumed.
* *Free-threaded CPython is not claimed.* `abi3t` exists for it
  (PyO3 0.29.2, published 2026-08-05, checked here 2026-09-25), but it is a
  second ABI to build and test; the
  package states "GIL builds only" rather than being silent about it.
* *GIL.* `init`, `protect` and `scan` are CPU-bound and take the whole tree;
  each runs with the GIL released (`allow_threads`) so an embedding process
  keeps its other threads, and each is documented as blocking. The Rust side is
  re-entrant here: `swp-adapters` builds a `tree_sitter::Parser` per call
  (`ts.rs:370`) and no crate in the read path holds a thread-local or a
  `static` mutable — see audit §7.
* *Errors:* one exception class `swp.Error` carrying `code` (the exact
  `ErrorCode::as_str()` string), `message`, `path`, `caused_by`, `next_step`.
  No per-code Python subclasses: seventeen classes would be the second error
  taxonomy PHASE 6 warns about, and `code` is already the discriminant.
* *Paths:* accept `str` and `os.PathLike`, convert to `PathBuf` on the Rust
  side, and never round-trip a path through a lossy `String` in a write path.
  The existing code is already careful here — store paths are canonical,
  forward-slashed relative names (`Protection.artifacts`, `protect.rs:165-167`,
  and the `init` test asserts no `:` and no `\` in `created`) — and the binding
  must not be the layer that mangles them.
* *Wheel matrix:* the four targets `release.yml` already builds the CLI for
  (`.github/workflows/release.yml:129-152`): `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`.
  `aarch64-unknown-linux-gnu`, musl and i686 are not shipped for the binary and
  so are not shipped for the wheel either; a tree that wants one is a proposal,
  not an omission to apologise for.
  A platform the project does not ship binaries for is installable from source
  only if a linker and a Python dev header are present; say that in the page.

### 4.2 JavaScript and TypeScript: napi-rs, one package, no second implementation

**Decision: napi-rs (Node-API), one npm package holding the addon and the types,
with per-platform prebuilds and TypeScript declarations generated from the Rust
signatures.** The package name is the owner's call — it must be one name, shared
by JavaScript and TypeScript, not a `swp` plus a `swp-types` pair.

* *Why Node-API and not a V8-native addon:* the addon has to survive Node
  majors, and Node-API is the ABI that promises that. napi-rs is the maintained
  Rust side of it; its generated bindings, `.d.ts` output, and prebuild
  machinery are the reason not to hand-write `node_api.h` calls.
* *Runtime floor:* follow what the current napi-rs toolchain supports rather
  than inventing one — its documented Getting-started range (checked
  2026-09-25) is Node `^20.17.0 || ^22.13.0 || >=23.5.0`, and its Rust floor is
  1.88, which is why the binding crates live outside the published workspace
  (§5). The declared floor is restated in the package's `engines` and in the
  binding README, and a lower-version job in CI is not run: unsupported is a
  sentence, not a silent fall-through.
* *Packaging:* `<name>.<platform>-<arch>-<abi>.node` per target, declared in
  `napi.targets`, distributed as per-platform packages wired through
  `optionalDependencies` so an install fetches one binary, and a source-build
  fallback for a target with no prebuild. This is the same matrix as the Python
  wheels and should be built in the same CI job shapes.
* *Async:* `AsyncTask`/`async fn` wrappers for `protect` and `scan` (they are
  the long ones), running on libuv's thread pool. The Rust work is `Send` but
  **not** cancellation-safe: `protect` rewrites files and a cancelled task must
  not be allowed to stop mid-loop. So the JS promise resolves when the work
  finishes and the binding offers no abort; a "timeout" that abandons a
  half-rewritten tree is a data-corruption feature. That is the API's
  documented behaviour, not an omission.
* *Errors:* one `SwpError extends Error` class carrying `code`, `path`,
  `causedBy`, `nextStep` and `rendered` — the [SDK_API.md](SDK_API.md) §8
  envelope, with `code` as the discriminant and no subclass per code, as in
  §4.1. A synchronous operation throws it; the two asynchronous ones,
  `protectSummary` and `scan`, reject with it. No `Result`-returning variant is
  offered: §8 gives a bound caller one failure type and one way to raise it, and
  a second spelling of the same outcome would be the second implementation §4.2
  exists to avoid.
* *TypeScript is the same package.* napi-rs emits `index.d.ts` from the Rust
  signatures, and the TS deliverable is that file plus a compile-time test
  (`tsc --noEmit` over `types/*.test-d.ts`). There is no `swp-ts` package and no
  TS wrapper module that adds behaviour: the handoff's "TypeScript must not
  become a second implementation" is satisfied structurally, by TS having no
  runtime of its own here. If a typed surface ever needs a helper, the helper
  is written in Rust and re-exported.

### 4.3 WebAssembly: evaluated and rejected, on the code

WASM is the familiar answer and the wrong one here, for reasons that are in
these files rather than in taste:

* `init` seals the root secret with DPAPI via Windows FFI
  (`swp-crypto/src/seal.rs:89-102`) and hardens the file by running `icacls`
  and parsing its output back (`seal.rs:371-378`). A WASM guest can do neither:
  no process spawn, no Windows API.
* `protect` writes the project tree and re-reads it to compare bytes
  (`swp-embedding/src/protect.rs:420-450`); `scan` unpacks archives into
  `std::env::temp_dir()` (`swp-detection/src/input.rs:333-343`). WASI gives a
  guest only pre-opened directories, so every real invocation would need the
  host to map the project, the temp dir, and the store — and the security
  property of the archive-safety checks (`PathRejected`, `error.rs:155`) would
  depend on a host-side mapping this project does not control.
* `getrandom` on `wasm32` needs a JS entropy import, so "the OS CSPRNG generated
  your root of trust" (`seal.rs:82`) stops being a statement about the machine.
* The release-artifact check in `scripts/check-release.sh:166` fails the tree on
  a tracked `.wasm`, and the licence/CLA posture assumes crates.io publishing.

What WASM *could* do faithfully is read a report: `Report::from_json` and
`to_text` are pure (`swp-evidence/src/report.rs:132-182`), no secret, no
filesystem. That is a different, much smaller product — a viewer — and shipping
it under the same name would invite readers to mistake it for SWP. Out of scope
for Beta 3, recorded so that the next person does not have to redo this.

## 5. PHASE 6 decision: the repository layout

The audit decides this, not habit. Three constraints: the root workspace is
`members = ["crates/*"]` with no `exclude`; `check-release.sh`'s
`PUBLISHABLE` list was the nine crates then and its artefact sweep fails a tracked
`.so`/`.dll`/`.dylib`/`.wasm`/`.exe`; and `cargo build --workspace` + CI must
not start requiring a Python interpreter or a Node headers download.

```text
crates/swp-sdk/                 ← the tenth workspace member: the façade. Rust only,
                                     no binding dependency, so CI and the publish
                                     order are unchanged except for one more crate.
bindings/
  python/
    Cargo.toml                  ← [workspace] (self-contained); path-deps on the
                                     crates two levels up, so it is not a member of
                                     the published workspace
    pyproject.toml              ← maturin, requires-python >=3.10, abi3
    src/lib.rs                  ← #[pymodule]: types, conversion, GIL release
    tests/                      ← pytest, run against the built wheel
  node/
    Cargo.toml                  ← same shape
    package.json                ← napi.targets, optionalDependencies, engines
    src/lib.rs                  ← #[napi]: the same operations, one wrapper each
    tests/                      ← node:test, run against the built addon
    types/                      ← compile-time .d.ts assertions, no runtime code
docs/
  BETA3_ARCHITECTURE_AUDIT.md   ← this set
  SDK_ARCHITECTURE.md
  SDK_API.md
  VERSIONING_POLICY.md
```

Why `bindings/` and not `packages/` or a `swp-sdk/` directory: there is one
artifact per language and no monorepo tooling, so a directory named for what it
contains (a binding) beats one named for a packaging convention nobody in this
repository uses. The published crate is `swp-sdk`, so the façade and its
bindings are not both called `sdk`.

`bindings/*` stay **outside** the root workspace on purpose: they need a Python
interpreter and a Node toolchain at build time, they need a newer Rust than the
`rust-version = "1.85"` floor for napi-rs, and their release cadence is not the
crates' (§[VERSIONING_POLICY.md](VERSIONING_POLICY.md)). Each carries its own
`Cargo.lock`, and CI runs them in their own jobs — a binding build failure must
not be able to break `cargo test --workspace`.

The consequence that has to be handled rather than discovered:
`check-release.sh`'s artefact sweep means **no built binary is ever committed
under `bindings/`**, and its `PUBLISHABLE` list did not know about `swp-sdk`
until this crate was added there. Both are settled now: the list is ten crates,
with `swp-sdk` in dependency order after `swp-evidence` and before `swp-cli`, and
the sweep is a repo-wide `git ls-files` filter (`:166`), so a wheel or an addon
committed under `bindings/` fails the release check as loudly as a `.dll`
anywhere else in the tree.

## 6. PHASE 5: the security review of this design

The rule the boundary is built to satisfy: the SDK cannot expose the root
secret, a derived key, an expected watermark tag, private-manifest contents, or
a private store path, because no operation it offers asks for them.

As shipped, that is a rule about **signatures**, and the honest way to say it is
that the façade is not a capability sandbox around `.swp/`. No public signature in
`swp-sdk` takes or returns keyed material, and the crate re-exports no type that can
be turned back into bytes (`SecretBytes::as_slice` is `pub(crate)` in `swp-crypto`,
`secret.rs:39`); but `Session::open_store()` is public, because `swp-cli` is a
separate crate and `swp inspect`'s three private views are its job, and the `Store`
it hands back can read those artifacts and unseal the project's own key. The
protection that still holds is the one the CLI relies on — the operating-system seal
and the access list on `root.key` — and the protection a bound caller gets is the
binding's own surface, which therefore must not wrap `open_store`. [SDK_API.md](SDK_API.md)
§10 and §11 name the item and the rule.

That sentence is now checked rather than asserted. [BINDING_SURFACE.json](BINDING_SURFACE.json)
classifies every `pub` item of `swp-sdk` into five groups — `binding_facing`,
`rust_only`, `forbidden`, `pending`, `sealed` — and the `binding_surface` suite
(`crates/swp-test-suite/tests/binding/surface.rs`) reads the crate's sources against
that file: every public item must be classified, a binding-facing type's fields and a
binding-facing function's signature may name only binding-facing types, the privileged
names are listed in Rust as well as in JSON so that editing the file cannot admit one,
and the sealed accessors must still have the visibility the file records. A binding
reads the same file; nothing in it has to be re-derived from prose.

The review found one exposure that is *not* a signature-name leak, and it is recorded
rather than repaired by narrowing the API: `Session::protect()` is public Rust API, and
its result reaches the keyed site identities of a private plan document by field —
`ProtectOutcome.protection` (`swp-sdk/src/protect.rs:89-101`),
`Protection.plan` (`swp-embedding/src/protect.rs:170`), `Plan.sites`, and
`PlannedSite.locations: [LocationId; 4]` (`swp-embedding/src/plan.rs:57`), which is
128 bits of HMAC output per radius under the project's root secret. `LocationId` is a
keyed *identifier*, not a key and not a tag: it cannot be turned into either without the
secret, and it is already written into the private plan file whose disclosure this
surface refuses. It is still the first thing a binding would print if it walked the
struct, so `protect` and `ProtectOutcome` are classified `pending` — meant to cross,
blocked by that field — and `LocationId`, `Plan`, `PlannedSite` and `Protection` are
`forbidden`. The API was not narrowed to make the list tidy: the pin in the suite is a
`const` closure that reads the field, so the record is deleted by the change that
removes the field, not by an edit to this page.

What crosses instead is `Session::protect_summary(&ProtectOptions) -> ProtectSummary`
(`swp-sdk/src/protect.rs:256`), the accepted answer in
[ADR-0001](adr/0001-protect-generate-binding-boundary.md) and one operation rather than
two: it calls `protect` and projects the result onto the fields the CLI itself reads
(`summarize`, `:267`), so the pipeline stays authoritative and the two results cannot
drift on what a run did. The projection is written as a copy out of named fields, not
as a filter over the struct — a keyed value crosses only if something reads it, and
this reads no `locations` and no refusal `detail`. The suite checks that claim three
ways: by field type and field *name* on the binding-facing structs, by reading the
body of `summarize` for those two reads, and at runtime, by sweeping the serialized
summary of a real run against that run's own location ids, taken from its own plan
(`sdk_parity`). `Mode::Plan`, `Mode::Release` and `Mode::DryRun` all work through it,
because it delegates; and because applying a generated constellation needs only its
release id, the plan is not an object a binding has to hold.

| risk | where it comes from | what the design does |
| --- | --- | --- |
| key bytes as a value | `RootSecret::from_bytes` (`secret.rs:56`), `SecretBytes::from_vec` (`:21`) | no façade argument or field is `Vec<u8>`/`bytes`/`Buffer`; the only accessor that returns key material — `Session::secret` — is `pub(crate)` (`session.rs:264-266`) and every caller of it drops the secret before returning (`session.rs:403`). Importing a key from outside the store is not offered, in any language. The field-shape half of that sentence is checked: `binding_surface` refuses a binding-facing type with a `[u8; N]`, `&[u8]` or `Vec<u8>` member, with one exception it names — `Digest`, the public SHA-256 of already-published material |
| a keyed site id as a value | `PlannedSite.locations: [LocationId; 4]` (`swp-embedding/src/plan.rs:57`) | reachable from public Rust `protect`, and therefore `forbidden` in the boundary file while `protect`/`ProtectOutcome` sit in `pending`. See the two paragraphs above: recorded, pinned by a `const` closure, and not repaired by narrowing the API — a binding is pointed at `protect_summary`, which is built without reading that field, and the suite sweeps the built value against the run's own ids |
| key bytes as a *print* | `RootSecret`/`DerivedKey`/`SealedSecret` already redact (`secret.rs:44,106,135`, `seal.rs:70`) | the façade's own types must not be able to hold one: `Session` stores a `Store` (a `PathBuf`), and the result DTOs are plain data, so a `Debug`/`inspect`/`console.log` of any binding value prints paths and counts |
| a tag oracle | `ManifestKeys::fragment_tag` (`keys.rs:149`), `ReleaseIndex::expected_tag` (`index.rs:257`) | neither is reachable from the façade surface. A caller with them could test a candidate without a report and without the maths that says whether the answer means anything — which is how a weak signal starts being quoted as a finding |
| private-manifest disclosure | `Store::read_private_manifest` (`store.rs:358`); `PrivateManifest`/`SiteEntry` derive `Serialize` | not re-exported, and the façade's own read is module-private (`session.rs:444`); the reason `inspect` is out (§3). The paragraph above states what that does not cover |
| private paths | `root_key_path` (`store.rs:86`), `private_dir` (`:74`) | store artifacts are named store-relatively, as `Protection.artifacts` already does; absolute paths appear only for what the caller passed in |
| silent unsealed key | `SWP_SECRET_PLAIN` (`seal.rs:211`), inherited from the embedding app's environment | `init` returns `secret_scheme`, and the binding page documents it, so an app that set the variable for another reason finds out on the first run instead of in an incident |
| panic across FFI | unwinding into CPython or Node is UB-adjacent | `catch_unwind` per façade call → `INTERNAL_ERROR`, the code that already means "a defect in SWP-1: report it" (`error.rs:162`) |
| error text as a leak | messages already use `Store::relabel` (`session.rs:385`, `:449-451`, `swp-sdk/src/report.rs:69`, `:78`); `PermissionOutcome::detail()` can carry an `icacls` transcript | passed through verbatim — a redaction step here would hide a real refusal — and swept by `secret_leak` rather than by trust |
| object lifetime | `Store` is a `PathBuf`; `Session` holds no borrow | bindings may hold a `Session` in a class/instance freely; nothing in the façade borrows a caller's buffer, and no `Request<'a>` reaches a binding signature |
| concurrency | no store lock exists anywhere in this tree | documented as a caller obligation: one `protect`/`init` per project at a time, exactly as two CLI processes are uncoordinated today. The façade does not add a lock, because a lock that only the binding layer holds would be a lock that the CLI walks straight past |
| zeroization at the boundary | `Zeroizing` covers the Rust side; Python `bytes` and Node `Buffer` are garbage-collected | the answer is not to zeroize harder across FFI, it is that nothing secret crosses. §"no key bytes as a value" above is the mitigation |

What this review does **not** claim: that the façade makes misuse impossible. The
service crates stay publishable with their full `pub` surface
([audit §8](BETA3_ARCHITECTURE_AUDIT.md)). The claim is narrower and checkable:
every value that can cross this boundary has been named, none of the five forbidden
kinds is on the list, and the one keyed value the public Rust surface does reach — a
`LocationId` through `protect`'s plan field — is classed as what may not cross rather
than argued into the boundary, with `protect_summary` as the door that offers the same
run without it.

## 7. PHASE 8: tests, written before the code

### Rust — `crates/swp-sdk/tests/`

* **public API**: each operation against a real temporary store, asserting the
  result's fields rather than its rendering.
* **envelope**: an operation that fails returns the same `code` the CLI would
  exit from, and the message is `SwpError`'s, not a paraphrase. One
  table-driven test over `ErrorCode::ALL` (`error.rs:79-97`), which is the
  existing mechanism for "no code was left out of a table".
* **panic boundary**: a façade call that panics yields `INTERNAL_ERROR` and does
  not abort the process.
* **parity** — the test that keeps §2's invariant honest. Same example tree,
  fresh secret: drive the CLI in-process through `swp_cli::run_in`
  (`lib.rs:81`, the same entry `tests/docs/examples.rs:117` uses) and drive the
  façade, then compare the parsed artifacts: identity, release record, plan,
  private manifest, and the report document. If they differ, either the façade
  or the CLI has a second implementation of something, and this is the test that
  catches it.
* **secret-leak**: `swp-test-suite`'s §29 gate already installs a *known* key and
  sweeps every artifact and every `Debug` rendering of every secret-bearing type
  (`tests/leak/secret_scan.rs:108,168,201,289,326`), including a raw keyed
  output as a second needle so a per-location MAC leaking is caught too. Extend
  it: sweep every façade result DTO, serialized to JSON, and the two rendering
  strings a binding would show a user.

### Python — `bindings/python/tests/`, run against the built wheel

protect → verify-by-scan → scan of a copy → report parse; the same tree through
the binary as through the module, with the JSON compared; every error path
reachable without a panic (unprotected directory, missing secret, an unsafe-only
tree); secret-leak: assert no returned object's `repr`, and no serialized result,
contains the known key; path handling with spaces, non-ASCII, and a long path;
`abi3` floor behaviour on the oldest and newest supported interpreter;
Windows/Linux/macOS in the same matrix CI uses for the CLI.

### JavaScript — `bindings/node/tests/`, `node:test`

the same functional list, plus ESM `import` and CommonJS `require` of the built
addon, the promise path on `protect`/`scan` (resolves once, never twice, and the
tree is complete when it does), and rejection carrying `code`.

### TypeScript — compile-time only

`types/*.test-d.ts` asserting the shape of each result and the absence of
anything key-shaped from it, compiled with `tsc --noEmit`. No runtime code lives
here, by design (§4.2).

### What is *not* tested, and why

Protocol behaviour is not re-tested through the bindings. The bindings are a
boundary: their tests are about the boundary. The 100+ existing library,
adversarial and measurement suites stay the authority on the protocol, and
running them again through three interpreters would produce three slower copies
of the same verdict.

## 8. PHASE 9: documentation

One page per language, in its own binding directory — `bindings/python/README.md`
and `bindings/node/README.md`, with the TypeScript usage in the latter because
there is one package — and **not** under `docs/`. The reason is the mechanism,
not tidiness: `docs_examples`' `PAGES` list
(`crates/swp-test-suite/tests/docs/examples.rs:65-75`) is the page index, and a
page there must quote transcripts this build produces. Binding transcripts come
from a wheel and an `.node` file that suite does not build. So the binding pages
live with their packages, and each carries its own runnable-example check: a
pytest and a `node:test` file that executes every example in the page it
documents. That is the binding-specific equivalent of `docs_examples` the
brief asks for, and it is the rule these pages obey:

* no example that is not executed by that test;
* every `console`/`pycon`-style transcript either executed or absent — until a
  page is added to `PAGES` with a capture path, which is a bigger change than a
  Beta 3 commit should carry. The four `SDK*`/`VERSIONING_POLICY` pages here
  deliberately quote **no** tool output at all: they are design documents, they
  hold no transcript block of any kind, and they are therefore not listed in
  `PAGES`. A future edit that adds a transcript must add the page to `PAGES` in
  the same commit;
* supported platforms and runtime versions stated, including what is *not*
  supported (no free-threaded CPython, no musl, no i686, no Deno/Bun claim);
* per operation: whether it writes your source, writes your store, or reads
  only — taken from `Mode::writes_source()`/`writes_store()`
  (`swp-embedding/src/protect.rs:99,106`) rather than restated from memory;
* offline behaviour: nothing here opens a socket, in any code path, in any
  binding — the same rule `AGENTS.md` states for the tool;
* secret handling: where the key lives, that DPAPI seals to a Windows account so
  a backup restores into the same identity but not the same machine, and that no
  API on this surface accepts or returns key material;
* the report schema, with the rule from [VERSIONING_POLICY.md](VERSIONING_POLICY.md)
  that a saved report is a versioned artifact;
* error behaviour: the code table, that `next_step` names CLI commands, and that
  the binding does not fake exit codes;
* installation, per platform, including how to tell a prebuild from a
  source build.

No page on this list may make a claim the measurement documents do not already
support. [VALIDATION.md](VALIDATION.md) is where a number lives, and a binding
page that wants one cites it rather than printing its own.

## 9. Beta 3 implementation phases

Each step is a commit-sized change with the full gate on it
(`AGENTS.md`'s list, in that order), and none of them depends on a later one to
be correct. The Rust landing shipped with Beta 3 covers steps 1, 2 and 3, the crate
part of step 6, and the binding-surface freeze §6 records; steps 4 and 5 landed after
it, and what is left in both is publication rather than implementation.
The list below is the plan as approved, with what actually happened marked on it.

1. **`swp-sdk` as an extraction.** `Session`, `Error`, `catch_unwind`, and the
   moved composition from `ctx.rs` — no new behaviour, no binding dependency.
   `swp-cli::ctx` delegates. Parity test lands here, because it is what proves
   the move was a move. *Done, with the correction §2 records: no `Error` type
   and no `catch_unwind` went into this crate — they are the FFI boundary's, and
   in Rust a façade call returns the service crate's own `SwpError`. The
   composition moved, and `swp-test-suite`'s `sdk_parity` target is the evidence
   that the move was a move.*
2. **`init`, `protect` (three modes), `scan`, `report`, `capabilities`.**
   Result DTOs, JSON round-trip, `secret_scheme` in the init result, `secret_leak`
   extended over the new types. *Done. `scan` came back with the per-site rows and
   the saved-report companion this surface needs, and the settings a `protect`
   call uses arrive through `Session::open`'s `Overrides` rather than per-call
   options.*
3. **Move `VerifyDocument` down into `swp-evidence`, then expose `verify`.**
   The riskiest step, because the document is a published schema
   (`SWP-1-verify-v1`, `verify.rs:47`; now `swp-evidence/src/verify.rs:46`): the
   field set, ordering and serde names must come out byte-identical, and
   `docs_examples` plus the CLI's own tests are the net. If it cannot be moved
   without changing the document, the move waits and `verify` stays unexposed —
   which is a supported outcome, not a failure. *Done as written, in that order:
   the move was its own commit (`e73165a`), the document came out with its field
   set, ordering and serde names intact, and `Session::verify` was exposed after
   it. The condition was met, so the fallback outcome was not taken.*
4. **Python binding.** `#[pymodule]`, error/`PathLike`/GIL handling, pytest suite,
   wheel matrix in CI, `bindings/python/README.md` with every example executed.
   *Done, with two of those five items read as what CI runs rather than as what they
   sound like. The "wheel matrix" is the `binding-python` job's three-operating-system
   matrix: one `abi3` wheel per OS, each built by `maturin build --release --locked`
   against CPython 3.10 and installed for `pytest -q`, so the interpreter-version axis
   is carried by the `abi3` floor and not by a per-version build. The suite is the
   eleven modules under `bindings/python/tests/`. `bindings/python/README.md` is in the
   tree and is the one item here no gate re-executes: `docs_examples` does not read it,
   and Node has a `readme.test.mjs` where Python has none. Whether a wheel goes to an
   index is step 6's, and none has.*
5. **Node binding + generated types.** Same list, plus the `.node` prebuild and
   `optionalDependencies` wiring and the `tsc --noEmit` type test.
   *Done except for the two items that name distribution. The napi addon, the
   generated `binding.d.ts` beside the hand-written `index.d.ts`, the ten
   `*.test.mjs` suites (which include `readme.test.mjs`, the one that does execute the
   README's examples) and the `tsc --noEmit` type test all run in `binding-node` on
   each of the three operating systems, where the addon is built from source on the
   runner. The prebuild and the wiring are not: `bindings/node/package.json` names
   four targets under its `napi` key and declares no `optionalDependencies`, so an
   archive installed without building gets no binary. Platform prebuilds are #32 and
   the package name is still the unresolved `jrs-swp`; neither is settled by this step.*
6. **Release wiring.** `swp-sdk` into `check-release.sh`'s `PUBLISHABLE` order,
   publish job, binding version policy applied
   ([VERSIONING_POLICY.md](VERSIONING_POLICY.md)), CHANGELOG entries. *Two of these
   four have landed: `PUBLISHABLE` is ten crates with `swp-sdk` between `swp-evidence`
   and `swp-cli`, and the Beta 3 CHANGELOG entry is part of the version preparation on
   this branch. The publish job and the binding version policy are still open, and they
   are no longer waiting on a binding to be written — steps 4 and 5 shipped their
   build-and-test halves, so the outstanding binding work is publication: this step's
   publish job, the version contract #31 states, and the prebuilt artefacts #32
   distributes.*

Steps 1-3 are Rust-only and shippable on their own: they make the implementation
embeddable whether or not a wheel is ever built. That ordering is deliberate —
if a binding slips, the boundary it was going to use is already reviewed and
tested, and nothing about the protocol has moved.
