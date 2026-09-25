# Beta 3 architecture audit

**Status: an audit, not a changelog.** Everything below describes the tree as it
stands at `v1.0.0-beta.2`, with a file and line beside each claim, so that the
design in [SDK_ARCHITECTURE.md](SDK_ARCHITECTURE.md) can be checked against the
code rather than against an intention. Where something is *not* true of this
build it says so, and where this audit could not prove a claim it says that too.

Beta 3's goal is one sentence: make this implementation usable from Python,
JavaScript and TypeScript without a second copy of anything. That is a constraint
on the design, not a licence to add a layer. So the first question is not "what
should the SDK look like" but "what is already here", and this page is the answer.

The pages that carry it forward:
[SDK_ARCHITECTURE.md](SDK_ARCHITECTURE.md) (the boundary, the bindings, the
layout, the security review, the test and documentation strategy),
[SDK_API.md](SDK_API.md) (the operation-by-operation contract), and
[VERSIONING_POLICY.md](VERSIONING_POLICY.md) (how a binding version relates to a
protocol version).

---

## 1. The dependency graph, read out of the manifests

Ten members (`Cargo.toml:1-3`, `members = ["crates/*"]`, `resolver = "2"`, no
`exclude`), each inheriting `[workspace.package]` version `1.0.0-beta.2`,
edition 2021, `rust-version = "1.85"`, `license = "Apache-2.0"`. There is no
`[features]` section in any manifest and no optional dependency anywhere in the
workspace, so the graph below is the whole graph: no edge appears or disappears
with a flag.

```text
swp-core        -> (nothing)
swp-crypto      -> core
swp-adapters    -> core, crypto
swp-identity    -> core, crypto
swp-manifest    -> core, crypto, identity
swp-embedding   -> core, crypto, identity, manifest, adapters
swp-detection   -> core, crypto, identity, manifest, adapters, embedding
swp-evidence    -> core, detection, identity, manifest
swp-cli         -> core, crypto, identity, manifest, adapters, embedding, detection, evidence
swp-test-suite  -> core, crypto, identity, cli        (+ dev: detection, evidence, adapters)
```

Acyclic, and every edge points strictly downward through eight layers:
`core → crypto → {adapters, identity} → manifest → embedding → detection →
evidence → cli`. `swp-core` is the only root; `swp-cli` and `swp-test-suite` are
the only leaves. The three internal dev-dependencies
(`crates/swp-test-suite/Cargo.toml:33,34,42`) exist only so the measurement
harness can reach the detector, the grader and the parsers, and `swp-adapters`
keeps an empty `[dev-dependencies]` block (`crates/swp-adapters/Cargo.toml:23-25`)
with a comment saying it stays that way to avoid closing a cycle. Two facts follow
from the shape and matter for Beta 3:

* **`swp-evidence` is where the read side ends.** It is graded from a `Detection`
  struct it is handed and never opens a file, so the same code serves `scan`
  (which must not trust the candidate) and `verify` (which may trust its own
  store). A binding boundary therefore has to sit at or above `swp-evidence`;
  there is nothing below it that produces a finished answer.
* **`swp-cli` is the only crate that touches all eight**, and it is a library as
  well as a binary (`crates/swp-cli/Cargo.toml:14-20`: `[lib] name = "swp_cli"`,
  `[[bin]] name = "swp"`). `main.rs` is 36 lines: one of them calls
  `swp_cli::run`, and the rest is the byte-clamping its own comment explains.
  Nothing else lives there.

What each crate pulls in from outside is a decision, not an accident, and the
binding-relevant ones are: `swp-adapters` owns every tree-sitter crate
(`tree-sitter 0.25`, `tree-sitter-javascript 0.25`, `tree-sitter-typescript 0.23`,
`tree-sitter-python 0.23`; root `Cargo.toml:60-63`) and is the only crate that
links a C parser; `swp-crypto` owns `ed25519-dalek`, `hmac`, `sha2`, `getrandom`,
`zeroize`, `subtle`, and the Windows sealing surface; `swp-detection` owns the
archive readers (`zip 2` with default features off plus `deflate`, `tar 0.4`,
`flate2 1` with `rust_backend`); `swp-identity` owns `toml` and `time`;
`swp-cli` depends on **no** argument-parsing crate — the parser is hand-written
in `crates/swp-cli/src/args.rs` so that `--formt json` can answer `Did you mean
--format?`.

## 2. Public API map

The counts are `pub fn` (including inherent methods), `pub struct|enum|trait|type`
and `pub const` per crate's `src/`. "Root re-exports" is what `pub use` in
`lib.rs` lifts to the crate root; every one of these crates also exposes its
modules publicly, so a root re-export set is a *convenience*, never a
capability limit — anything `pub` in a module is reachable today. There are zero
`#[doc(hidden)]` items in the workspace.

| crate | pub fn / types / consts | serde on public types | secret required | filesystem | CLI-shaped output |
| --- | --- | --- | --- | --- | --- |
| `swp-core` | 92 / 24 / 11 | partial, 10 of 24 types: the four id newtypes (`Digest`, `ProjectId`, `ReleaseId`, `LocationId`, hand-written `impl`s in `id.rs`), `TagWidth`, `SiteTag`, `FormFamily`, `LiteralClass`, `Limits`, `GeneratorInfo` | no | no | no |
| `swp-crypto` | 43 / 10 / 2 | only `PublicKeys` (`secret.rs:142`) | it *is* the secret layer | `harden_permissions` (seal.rs:243), DPAPI | no |
| `swp-identity` | 64 / 10 / 16 | the eight stored documents: `SwpConfig`, `ProtectConfig`, `ProjectIdentity`, `ReleaseRecord`, `SourceRevision`, `WatermarkParams`, `AdapterUse`, `Timestamp` | `Store::load_root` returns one | the store: every path accessor and every `read_*`/`write_*` | no |
| `swp-manifest` | 38 / 5 / 8 | `PrivateManifest`, `SiteEntry` | `ManifestKeys::derive` takes one | reads none (it builds and checks documents) | no |
| `swp-adapters` | 49 / 22 / 9 | **none** — zero serde in the crate | no | reads nothing (`analyze` takes `&str`; `Registry::for_path` takes the caller's `Path`) | no |
| `swp-embedding` | 46 / 25 / 1 | `Mode` (`protect.rs:78`), `FileChange` (`:133`) and `Protection` (`:142`) are `Serialize` *only* — nothing in this crate reads one back; `Plan`, `PlannedSite`, `SkippedSite` (`plan.rs:36,61,74`) round-trip | yes, borrowed: `Request.secret` (`protect.rs:118`) | walks and **rewrites** the project tree | no |
| `swp-detection` | 40 / 11 / 3 | **none** — zero serde in the crate | yes, indirectly: `CandidateRelease.keys` | opens candidates; stages archives into the OS temp dir (`input.rs:149`, `:333-343`) | no |
| `swp-evidence` | 22 / 10 / 13 | **all ten public types**; the seven structs additionally carry `deny_unknown_fields`, the three fieldless enums have nothing to deny | no | no | `to_text` is a rendering, but it lives with the document |
| `swp-cli` | 73 / 8 / 4 | no public type is serializable; its thirteen `Serialize` items are all module-private — eleven report DTOs, `Verdict`, and the JSON `Value` helper in `output.rs:199` | `Ctx::secret()` (`ctx.rs:175`) | everything, through the crates below | yes: `Sink`, `Format`, `deliver`, exit codes |

Read against Beta 3's question, the map divides the surface into four groups.

**Already a finished answer, FFI-shaped today.** `swp-evidence::Report` is a
versioned document with `to_json` (`report.rs:132`), `from_json` (`:140`),
`to_text` (`:170`), `to_text_items` (`:182`) and `exit_code` (`:126`), and every
type in the crate derives `Serialize` + `Deserialize` — the seven document structs
with `deny_unknown_fields`, the three fieldless enums having nothing to deny.
`swp_embedding::Protection` and `FileChange` are the same
kind of thing, already returned by one function. These cross a language boundary
as a string of JSON with nothing added.

**Correct to expose, one call too deep.** `swp_embedding::protect(&Request)`
(`protect.rs:179`) is the entire protection pipeline behind one call, but
`Request<'a>` (`:114-130`) borrows eight values including `&Store`,
`&RootSecret`, `&ProjectIdentity`, `&SwpConfig` and a caller-owned `Timestamp`.
`swp_detection::scan_against` (`find.rs:394`) and `build_indexes` (`index.rs:285`)
are similar. Exposable, but the *arrangement* of their arguments is the part
bindings would have to agree on.

**Not for external consumers, and `pub` only because Rust needs it.**
`ManifestKeys::fragment_tag` (`keys.rs:149`) and `ReleaseIndex::expected_tag`
(`index.rs:257`) return the *expected watermark tag* as a `u32`;
`Store::read_private_manifest` (`store.rs:358`) returns the private manifest's
bytes; `RootSecret::from_bytes` (`secret.rs:56`) and `SecretBytes::from_vec`
(`:21`) accept raw key material; `Store::root_key_path` (`:86`) and
`Store::private_dir` (`:74`) name where the key lives. All of these are necessary
inside the workspace and all of them are on the list of things a binding must not
put in front of a caller (§5 below, and PHASE 5 of the design).

**CLI-only by construction.** `swp-cli`'s public surface is `args`, `ctx`, `help`,
`output` and one `run` per verb. The argument parser, `Sink`, the text renderings
and the exit-code contract belong to the command line; the last section of this
page shows why the *composition* inside `ctx.rs` is a different thing.

One asymmetry is worth naming before it becomes a design mistake: the write side
returns serializable data and the read side does not. `swp-detection` has eleven
public types and none of them derives serde, `CandidateRelease` is not even
`Clone` (`index.rs:270`, and the comment above it explains why), and
`ReleaseIndex<'k>` borrows its `ManifestKeys`
(`index.rs:64`). That is deliberate — a `Detection` is an in-memory intermediate
that the *grader* turns into a document — and it tells the binding design where
to cut: hand out the `Report`, not the `Detection`.

## 3. What each command actually calls

The CLI's dispatch is one `match` (`crates/swp-cli/src/lib.rs:107`) and
`mode_of` (`:131`) is where `generate` and `protect` turn out to be the same call.
Below, "library" means "reachable without the CLI"; "glue" means lines in
`swp-cli` that a caller would have to reproduce.

### `swp init` — `crates/swp-cli/src/init.rs:90`

```text
dir check                                        glue (a usage error, init.rs:96-102)
swp_crypto::SealedSecret::generate               library (seal.rs:81)
swp_identity::Store::init(root, &secret)         library (store.rs:185)
Store::identity / write_identity                 library (store.rs:274, :285)
measure: walk::walk_for_scan + Registry::standard library pieces + glue (init.rs:335)
suggest_sites(files)                             glue, and it is a policy  (init.rs:387, pub)
write_settings                                   glue                      (init.rs:405)
store.load_root → RootSecret::fingerprint        library (store.rs:306, secret.rs:95)
drop(root)                                       explicit, twice           (init.rs:155, :167)
InitDocument, schema "SWP-1-init-v1"             private DTO               (init.rs:172)
```

`suggest_sites` is the interesting one: the ladder `MIN → 12 → 20 → 32 → 48` by
file count is a *protocol-adjacent default*, and a caller that reimplements it
gets a different constellation from `swp init` on the same tree.

### `swp generate` and `swp protect` — one function, three modes

`swp_cli::protect::run` (`protect.rs:84`) builds a `Ctx` (`ctx.rs:48`), takes a
fresh `ReleaseId` (`swp_identity::new_release_id`, `release.rs:29`), loads the
secret, and calls `swp_embedding::protect(&Request)` (`swp-embedding/src/protect.rs:179`)
with `Mode::Plan`, `Mode::Release` or `Mode::DryRun`
(`lib.rs:131`, `protect.rs:78-108`). Inside that one call:
`ManifestKeys::derive` (`keys.rs:73`), `ManifestSigningKey::from_root`
(`sign.rs`), `walk::walk`, `candidates::scan`, `select::select`, `apply::apply`,
`Plan::build`, `release_fingerprint`, `PrivateManifest::build` + `sign` +
`verify_signature`, `sign_release_record` + `verify_release_record`, then the
writes (`store.rs:354, :362, :345`) and the source rewrites
(`protect.rs:388-430`). `Mode::writes_source()` and `Mode::writes_store()`
(`protect.rs:99, :106`) already answer "does this operation touch my files" —
as a *function*, not a doc sentence.

Glue a caller would otherwise repeat: the release-id allocation, the timestamp,
`refuse_replaced_release` (`protect.rs:193`), and the `--target` containment rule
that refuses a target escaping the project root (`ctx.rs:101-144`).

### `swp scan` — `crates/swp-cli/src/scan.rs:39`

Six library calls, in this order, and they must stay in this order:

```text
Ctx::open                       ctx.rs:48    → Store::open/discover + identity + config + limit ceiling
Ctx::candidate_releases         ctx.rs:257   → load_releases  ctx.rs:266
identity.verify_key()                        → scan.rs:47
swp_detection::build_indexes    index.rs:285 → authenticates manifests and records, checks key agreement
swp_detection::input::open      input.rs:149 → sniffs, unpacks archives to a temp dir
swp_detection::scan_against     find.rs:394  → SiteMatch statuses, never a file write
swp_evidence::Report::build     report.rs:96 → grades; takes command, created_at, generator as &str
```

Then three CLI-only things: `to_text_items`, `output::deliver`, and
`report.exit_code()` (`scan.rs:106-108`). `--save` writes through
`Store::save_report` (`store.rs:379`), which is library code.

**`Ctx::load_releases` (`ctx.rs:266-306`) is the one piece of glue this audit
keeps coming back to.** It is where a store becomes something the detector can
trust: it loads the secret, reads each private manifest and *verifies its
signature against the project's public verify key* (`ctx.rs:316-330`), reads the
public record, checks `manifest.release_id == id` (`ctx.rs:275`), derives
`ManifestKeys` from *this* identity's canonicalizer version, and
`drop(secret)`s it before returning (`ctx.rs:298`). Every one of those is a
security property, not a convenience. It takes `&[ReleaseId]`, so it is
already `Parsed`-free; the only thing keeping it out of a library consumer's
hands is that it is a method on a type in the CLI crate.

### `swp verify` — `crates/swp-cli/src/verify.rs:147`

The same six calls with `one_release` (`ctx.rs:215`) and `input::open` pointed at
the project root instead of a candidate (`verify.rs:157-158`), then a per-site
table and a verdict that is *not* the report's outcome: `INTACT` when every site
is confirmed, `INCONCLUSIVE` when the scan was partial, `INCOMPLETE` otherwise
(`verify.rs:189-195`). The document it renders — `VerifyDocument`, schema
`SWP-1-verify-v1` (`verify.rs:47`, struct at `:104`) — is a module-private
`Serialize` DTO inside `swp-cli`. `--save` puts a report-v2 document in the store
(`verify.rs:269-290`).

### `swp report` — `crates/swp-cli/src/report.rs:118`

`Store::report_names`/`read_report` (`store.rs:394, :400`) and
`Report::from_json` (`report.rs:140`), which refuses a document whose `schema` or
`protocol` is not this build's with `PROTOCOL_VERSION_UNSUPPORTED`
(`report.rs:147-162`). No secret, no write, no tree walk. This is the cleanest
existing example of "a library operation that happens to have a CLI front".

### `swp inspect` — `crates/swp-cli/src/inspect.rs:159`

Nine views over the store, deliberately secret-free — there is a test named
`inspect_reads_a_store_whose_root_key_is_absent` (`inspect.rs:1006`). Its JSON is
`SWP-1-inspect-v1` (`:41`), its DTOs are private (`:59-100`), and three of its
views (`plan`, `fragments`, `manifest`) print *private-manifest contents* —
including per-site keyed material — because a person sitting at their own terminal
is allowed to see their own store. `view_names` and `private_view_names`
(`:143, :151`) already encode that split.

## 4. Secret boundaries

The root secret has exactly one entry point, one exit point, and no path through
the rest of the system as data.

```text
generated   swp_crypto::SealedSecret::generate            seal.rs:81   (OS CSPRNG, random.rs)
            32 bytes; RootSecret::from_bytes is the only other constructor, secret.rs:56
sealed      SealedSecret::seal                            seal.rs:88   (DPAPI user scope on
                                                                       Windows, :89-102; Plain elsewhere)
persisted   Store::init → write_private(root.key)         store.rs:185, :216
            atomic_write + harden_permissions             store.rs     (ACL read back and parsed)
reloaded    Store::load_root → parse_file_bytes+unseal    store.rs:306, seal.rs:112
consumed    ManifestKeys::derive                          keys.rs:73   → four keyed radii
            ManifestSigningKey::from_root                 sign.rs
            project_id_from_root / make_project_id        identity.rs:36, project.rs:16
destroyed   drop, explicitly, at the end of the scope     init.rs:155, :167; ctx.rs:298
```

The types enforce most of this themselves, and the enforcement is worth reading
before designing around it (`crates/swp-crypto/src/secret.rs`):

* `SecretBytes` — `Zeroizing<Vec<u8>>`, no `Display`, no `Serialize`, no `Clone`,
  `Debug` prints only the byte count (`:15-18, :44-48`), and `as_slice` is
  `pub(crate)` (`:39`) with the comment "once bytes leave here they are no longer
  zeroized".
* `RootSecret` — same shape; the two public ways to *observe* one are
  `same_as` (`:84`, constant-time, deliberately "the only way to compare root
  secrets without exposing bytes") and `fingerprint` (`:95`, 40 bits of an HMAC
  under a public label, i.e. a non-secret handle so `swp init` can print
  "key 3fqz2-…").
* `DerivedKey` — carries its `Domain` and cannot be moved into another
  derivation (`:115-133`).
* `SealedSecret` — payload is a `SecretBytes` because under `Scheme::Plain` those
  bytes *are* the key (`:59-68`).
* `ManifestKeys` — hand-written `Debug` (`keys.rs:57`).

Three consequences for a binding boundary. **(1) Bytes must not be an
accept-value or a return-value.** `RootSecret::from_bytes` and
`SecretBytes::from_vec` are already `pub` in Rust, and importing a key from
outside the store is a real operation the CLI does not offer; if a binding ever
offers it, the byte array has to survive as a Python `bytes` or a Node `Buffer`,
unzeroized, in a garbage-collected heap, next to whatever the app logs. Beta 3
does not offer it. **(2) The handle is the only thing that may leave.**
`fingerprint()` is designed to be printed; it is what `InitResult` may carry.
**(3) Two secrets are consumed on every keyed read and must not outlive it.**
`ctx.rs:270-298` is that pattern; `drop(secret)` before walking a stranger's tree
is a deliberate line, and a boundary that hands out keys instead of results
would delete it.

One thing that is *not* a leak and must not be over-corrected: a report-v2
document quotes the matched text of a candidate site (`Region.excerpt`,
`item.rs:60-66`) and the family name, but no keyed value. `crates/swp-evidence/src/item.rs:40-42`
states the rule — "a report is a copy of the watermark, and a report is the one
artifact of a scan that gets forwarded to other people" — and §29's sweep holds
`basis` strings to counts, paths, line numbers and family names. The
`expected tag` never appears in it, and `ReleaseTally` (`level.rs:212-260`) counts
bits rather than naming codes.

## 5. Filesystem boundaries

There is no in-memory mode. Every operation is a filesystem operation, and the
effects divide into five kinds:

| effect | who performs it | note |
| --- | --- | --- |
| reads the project tree | `swp_embedding::walk::walk`, `walk_for_scan`, `swp-detection::input::open` | bounded by `Limits`; omissions are recorded, not skipped silently |
| writes the project tree | `protect` in `Mode::Release` only (`protect.rs:99`) | atomic via a sibling `.swp-tmp-<pid>` (`:399-414`), then **re-reads the file and compares bytes** (`:422-429`) |
| creates and writes `.swp/` | `Store::init` (`store.rs:185`), `write_*` (`:269-394`) | every private write goes through `atomic_write`, which hardens and verifies the ACL, and refuses to keep a private artifact whose hardening it could not confirm |
| writes outside the project | `swp-detection::input::make_temp` (`input.rs:333-343`) | unpacking an archive stages it under `std::env::temp_dir()`, named with `std::process::id()`, removed on `Drop` (`input.rs:99-105, :127`) |
| reads process state | `Store::discover` → `env::current_dir` (`store.rs:450`); `plain_requested` → `SWP_SECRET_PLAIN` (`seal.rs:211`); `windows_user_name` → `USERNAME`/`USERDOMAIN` (`seal.rs:360-361`) | three `std::env` reads in the whole library surface — everything else is passed in |

The last row is a design constraint, not trivia. `SWP_SECRET_PLAIN=1` skips DPAPI
("the file then contains the key itself, protected only by its ACL",
`seal.rs:209-216`), and a binding inherits the *embedding application's*
environment, so an app that sets the variable for an unrelated reason would
silently get an unsealed key. A CLI user sees the effect in `swp init`'s own
output; an embedder sees nothing unless the API returns it. So the init result
must carry the scheme, and PHASE 5 records that as a requirement rather than a
suggestion.

Path *names* are a boundary too. `Store::relabel` (`store.rs:254`) exists to turn
an absolute store path into `.swp/...`, and the messages this build prints use it
(`ctx.rs:280`, `:324`). A binding should return store-relative names for store
artifacts (as `Protection.artifacts` already does, `protect.rs:165-167`) and
absolute paths only for things the caller named itself.

## 6. The error model, and what an FFI caller should get

`SwpError` (`crates/swp-core/src/error.rs:221`) is one struct for the whole
workspace: `{ failure: SwpFailure{code, message, path}, cause: Option<String>,
next: Option<String> }`, where `next` overrides the per-code advice for one
failure (`:222-231`), 17 `ErrorCode` variants (`:6-41`), `as_str()` in
SCREAMING_SNAKE (`:55-75`), `next_step()` per code (`:101-168`), and `exit_code()`
mapping to `2,3,4,5,5,6,7,8,9,10,11,12,13,14,15,16,70` (`:172-191`).
`render()` (`:283-290`) is the three-line human form — code, message, `caused by`,
`next step` — and `output::print_error` (`output.rs:170`) prefixes it with
`error [CODE]` and returns the code to `run_in`.

A binding should receive **this taxonomy, re-projected, not replaced**:

```text
{ code: "NO_SAFE_LOCATIONS",        ErrorCode::as_str, stable, tested exhaustively
  message: <what happened>,         SwpError::message()
  path: <option>,                   SwpFailure.path — already relabelled by callers
  caused_by: <option>,              SwpError.cause
  next_step: <sentence>,            SwpError::next_step()
  retryable: <bool>? }              NO — see below
```

The reason to keep it is that `SwpError` is already what every crate returns, so
any other shape is a translation table that can drift; and `ErrorCode::ALL`
(`:79-97`) exists precisely so a test can fail when a table misses a variant — a
binding's conversion is exactly such a table.

Three things the boundary must decide rather than inherit:

* **No exit code.** The exit code is the CLI's contract with a shell
  (`AGENTS.md`, and `docs/CLI.md`). A Python or JS caller catches an exception or
  checks a result; giving it `15` invites `os._exit(15)` and a silent process
  policy that the CLI got from a *decision*, not from a library. The one place a
  code does belong on this boundary is `Report.exit_code()` (`report.rs:126`),
  because there it is a property of a document the caller is reading.
* **No `retryable`/`category` enum.** The codes already carry the distinction,
  and a coarser class would lose the one thing the table is for: `USAGE` and
  `NO_SAFE_LOCATIONS` both mean "nothing happened" and ask for opposite answers.
* **`render()` is the string to display, `message` the string to match.** The
  advice in `next_step` names CLI commands (`swp inspect plan --release <id>`,
  `--force`) because it was written for a person at a terminal. It is honest to
  pass it through; it is wrong to make a binding's error type depend on it.

## 7. How JavaScript, TypeScript and Python are already supported

This is the section the "don't build another language registry" instruction turns
on, and the answer is better than expected: the adapter layer is one trait, one
implementation, and a closed list of three.

* **One trait.** `pub trait LanguageAdapter: Send + Sync`
  (`crates/swp-adapters/src/adapter.rs:120`) with four required methods —
  `name`, `capabilities`, `extensions`, `analyze(&self, source: &str,
  limits: &Limits) -> Result<Analysis, SwpError>` (`:141`), `dialect` — and
  defaults for `identifies` (extension match), `canonicalize`, `render`,
  `extract` and `validate` (`:128-313`). No generics on the trait; the
  `Send + Sync` bound is what lets a registry live behind a shared reference.
* **One implementation.** `AstAdapter` (`:405-443`) holds a `ts::Grammar` table
  (`ts.rs:39-77`) of function pointers and static node-kind lists. JavaScript,
  TypeScript and Python are *three instances of the same struct* with three
  grammars: `JAVASCRIPT` (`js.rs:306`, extensions `js,mjs,cjs,jsx`),
  `TYPESCRIPT` (`js.rs:323`, `ts,mts,cts,tsx`, and it is "JS with types" —
  `interface`/`type`/`satisfies` live in `JS_KEYWORDS`, `js.rs:61-129`, and
  `type_identifier → Free`), `PYTHON` (`py.rs:200`, `py,pyi`, with
  `line_breaks: true` (`py.rs:214`) and `self`/`cls` preserved (`:112-114`)).
* **One registry, no feature gates.** `Registry::standard()` (`adapter.rs:345`)
  builds three `AstAdapter`s plus a `fallback: GenericAdapter`
  (`generic.rs`) — an iterative lexer so a file in an unknown language still gets
  *canonicalization and the fingerprint channel*, just not keyed sites. Lookup is
  `for_path` (`:357`), `for_language` (`:371`, falls back to generic), and
  `parsed_languages() -> Vec<&'static str>` (`:393`).
* **The pipeline asks the registry, never a language.** The walk admits a file
  only via `registry.for_path(...).is_none()` (`walk.rs:421-427`); the two sides
  that need dialect rules call `for_language(&analysis.language).dialect()`
  (`candidates.rs:306`, `find.rs:462, :489`). There is no `match` on a file
  extension and no `Language` enum outside `swp-adapters`; the strings
  `"javascript"` and `"python"` elsewhere in the workspace are test fixtures and
  a doc comment. That is what lets the DEVELOPER-GUIDE promise that a fourth
  language is "an adapter plus a grammar dependency, not a `match` scattered
  through the pipeline" (`ts.rs:6-8` says the same in code).
* **Safety, not language, gates a rewrite.** `safety::why_unsafe`
  (`safety.rs:42-91`) is keyed on node kinds — JSX attributes, object/dict keys,
  module specifiers including `require`/`__import__` by name (`:61`), type
  positions, match patterns, docstrings — and the dialect layer refuses the
  literal forms that cannot round-trip: template literals and backticks,
  `f`/`r`/`b` prefixes, triple quotes and escapes (`literal.rs:179-221`),
  floats, `1_000`, `0755`, `BigInt`, and integers past `2^53-1` in JS
  (`literal.rs:130-171`; `Dialect::JS.max_exact_integer` at `dialect.rs:45-55`
  against `PY` at `:64-72`). `StringAdjacent` exists only for Python
  (`adjacent_strings`, `forms.rs:424`).
* **The proof is not optional.** `validate` (`adapter.rs:194-313`) re-parses
  before and after, decodes the value back out of the rewritten text, and
  compares L1/L2/L3 canonicalization of the statement and its scope radii with
  the site hidden. It fails closed.

Two facts a binding surface has to live with. The crate has **no serde anywhere**
— `Analysis`, `CandidateSite`, `Edit`, `Proof`, `DecodedSite`, `SiteValue` are
plain data, but plain Rust data (`OwnedString`, `ByteSpan`, `FormFamily`,
`TagWidth`), and `StringForm<'a>` borrows (`forms.rs:361`). And there is **no
single API that answers "which languages, and which extensions"** —
`parsed_languages()` gives names and `for_language(name).extensions()` gives a
`&'static [&'static str]`, so a caller composes two calls. That composition is
trivial and it belongs on the boundary (§"capabilities" in the design), because
otherwise three ecosystems each guess at it.

For FFI purposes the adapters layer is the friendliest part of the tree: no
`unwrap`/`expect` outside `#[cfg(test)]` (verified: the sites at
`analyze.rs:460`, `forms.rs:871`, `generic.rs:548`, `literal.rs:331` are all past
their `#[cfg(test)]` markers at `:409, :642, :538, :326`), recursion bounded by
`max_depth`/`max_nodes_per_tree` (`ts.rs:163-169`), names capped at 65,536
(`ts.rs:93`), refusals capped at 256 (`analyze.rs:390`), parse bytes capped by
`max_parse_bytes` (`ts.rs:360-369`), no thread-locals, no `env::var`, no process
spawn, no current-directory dependence. The one caller-controlled panic is
`validate` slicing `&after[rendered.start..]` (`adapter.rs:230`) with a span the
caller supplied — reachable only by a caller that builds `Edit`s itself, which is
not this design's plan.

## 8. PHASE 1: is a new crate actually needed?

The three candidates, judged against the sections above.

**Option A — expose the existing crates directly.** A Python binding depends on
`swp-identity`, `swp-manifest`, `swp-embedding`, `swp-detection`,
`swp-evidence`. It gets everything: `protect(&Request)`, `build_indexes`,
`scan_against`, `Report::build`. What it must *reproduce* in each of three
languages is: opening a project (`Ctx::open` minus `Parsed`: `Store::open` or
`Store::discover`, `identity()`, `config()`, `apply_limit_ceiling()` —
`ctx.rs:48-92`), release selection (`ctx.rs:184-224`), and the whole of
`load_releases` (`ctx.rs:266-306`) including both signature checks and the
`drop(secret)`. Three bindings, three copies of the authentication sequence, and
a missing check in any one of them is not a crash — it is a scan that trusts an
edited manifest and reports a clean copy as tampered with, which is exactly the
failure the doc comment at `ctx.rs:240-256` enumerates. What it must also *avoid*
is the group in §2 that is `pub` for internal reasons: `fragment_tag`,
`expected_tag`, `read_private_manifest`, `root_key_path`, `from_bytes`. Nothing
in Option A stops a binding from reaching them; only the binding author's
attention does.

**Option C — expose `swp-cli`'s library APIs.** Rejected on the handoff's own
grounds, and on two of its own. `swp-cli`'s public entry is `run(argv, out, err)
-> i32` (`lib.rs:64`, `run_in` at `:81`), which is *text and an exit code*: a
binding would have to parse the CLI's stdout, or run it and capture a `String`
from a `dyn Write`. Every structured shape it produces — `InitDocument`,
`VerifyDocument`, the inspect DTOs — is module-private, so there is nothing
typed to call. And `Ctx`, `Parsed`, `Flag`, `Format`, `Sink` are public but
`Parsed`-shaped: the boundary would be the argument parser, which is
`docs/CLI.md`'s contract, not a library's. `run_in` stays what it already is —
the in-process entry the integration tests drive
(`swp-test-suite/src/project.rs:519`, `tests/docs/examples.rs:117`) — and the
parity test in the design uses it as the reference implementation, which is a
different job from being the binding surface.

**Option B — a thin facade.** One crate whose public API is the composition the
CLI already performs, with `Parsed` replaced by named options. The three tests
the handoff sets for a facade:

* *Does it materially reduce FFI complexity?* Yes, and specifically at the
  boundary's two hard points: it turns an eight-borrow `Request<'a>` and a
  six-call scan sequence with a mandatory order into one owned call, and it puts
  a `catch_unwind` plus one error conversion around every operation instead of
  three. `Protection` and `Report` are already serializable, so the marshalling
  is `serde_json` at one place rather than three.
* *Does it prevent internal API leakage?* Partially, and honestly: a facade is a
  **review** boundary, not a **capability** boundary. Every crate here is
  publishable (`check-release.sh`'s `PUBLISHABLE` list is all nine), so nothing
  in this design prevents a determined consumer from depending on
  `swp-manifest` directly and calling `fragment_tag`. What a facade changes is
  what an audit has to read: three bindings that depend on exactly one crate,
  whose entire `pub` surface is the documented API, is reviewable; three bindings
  that reach eight crates is not. Saying more than that would be the kind of
  overclaim this repository does not publish.
* *Is it justified by anything other than "we are adding SDKs"?* Yes, by
  §3's finding. The authentication bridge and the default policies
  (`suggest_sites`, `write_settings`, the `--target` containment rule, the limit
  ceiling warnings) exist once, in `swp-cli`, and a binding that composes crates
  directly either copies them or diverges from `swp init`/`swp protect` on the
  same tree. Divergence in a default is the worst kind: it produces two
  different constellations from one project without either being wrong locally.

**Verdict: Option B, built as an extraction rather than a new layer.** The
facade's session type is `Ctx` with the `Parsed` arguments removed; the
`Parsed` → options translation stays in the CLI. After that move, `ctx.rs` is
allowed to mention `Parsed` only in the translation, and `swp-cli` keeps
argument parsing, rendering, and exit codes — which is what the DEVELOPER-GUIDE
already says it owns ("argument parsing, the seven commands, rendering, exit
codes"). The invariant that makes Option B safe rather than additive is that
**no protocol, cryptographic, detection or grading logic is written in the
facade**: its `src/` is types, ordering, and error/panic envelopes, and a test
in the design's §"parity" checks that the facade and the CLI agree on the same
tree.

Two named costs, stated where they can be argued with. First, a second public
API surface to keep honest: `swp-sdk` must be versioned with the crates it
composes, and its `pub` items become promises to three ecosystems that read docs
and not source. Second, the `verify` answer is not in the service crates yet:
`VerifyDocument` must move from `swp-cli/src/verify.rs` down into `swp-evidence`
before a binding can return a verdict, and until it does, Beta 3 does not expose
`verify` at all — see PHASE 2 in [SDK_ARCHITECTURE.md](SDK_ARCHITECTURE.md).
Shipping a report-shaped `verify` from bindings because it was easy would be
exactly the overclaim the project exists to avoid.

## 9. What this audit could not prove

* The crate graph is read from manifests, not from `cargo tree`: it is what the
  manifests *ask for*, which is the claim being made here, but a stale
  `Cargo.lock` would show up in `check-release.sh`'s metadata check rather than
  in this page.
* `swp-cli`'s public items are listed as reachable; several of them exist only
  to be shared between the CLI's own modules (`ctx::resolve` is `pub(crate)`,
  `output::window` is not) and the audit does not sort "public because
  another verb needs it" from "public because someone forgot to write
  `pub(crate)`". That sorting is a task for the extraction commit, not a finding.
* Concurrency is argued from absence: no `static`/`thread_local`/`RefCell`/`Rc`
  in the read path, `LanguageAdapter: Send + Sync`, and the process-id-suffixed
  temp names. What is *not* provided anywhere is a lock on the store: two
  concurrent `protect` runs against one `.swp/` are as uncoordinated as two CLI
  processes are, and the binding layer does not change that. The API page states
  it as a caller obligation rather than pretending the boundary made it safe.
