# ADR-0001 — `protect`/`generate` at the foreign-binding boundary

**Status: accepted, and now implemented.** This record settled *which* contract a
binding phase should build to and *why*; the type it asked for exists.

At acceptance it changed no protocol semantics, no stored artifact, no Rust
signature, and no category in [BINDING_SURFACE.json](../BINDING_SURFACE.json), and
`Session::protect` and `ProtectOutcome` stayed `pending` until the type described in
§7 existed. That is what the rest of this document records, and the evidence in §§2–6
and Appendix A is the acceptance-time measurement: it has not been revised by the
implementation, because a decision record that moves its own evidence to match the code
is not a record. Its two pointers into `crates/swp-sdk/src/protect.rs` are the file as it
stood then — `Request<'a>` still borrows the secret at `swp-embedding/src/protect.rs:118`,
and that is unchanged — while the implementation grew the SDK module, so what it cites as
the drop at `:137` is `:377` now and `ProtectOptions` at `:35-57` is `:45-73`.

Implemented as §7 decided: `swp_sdk::Session::protect_summary(&ProtectOptions) ->
swp_sdk::ProtectSummary` (`crates/swp-sdk/src/protect.rs`), a `binding_facing`
projection of the same call. `Session::protect` and `ProtectOutcome` remain `pending`
— narrowing them further is Option C, a `MAJOR` change to public Rust API that no
binding needs — and the five items §7 required to stay outside the boundary all do.
§9 records what the implementation answered and what it did not.

Decided here: whether the operation a binding most wants — embedding a constellation —
can cross the boundary, and if so in what shape.

## 1. Problem

`swp-sdk` is the façade a Python or Node binding would wrap. Its freeze
([BINDING_SURFACE.json](../BINDING_SURFACE.json), enforced by
`crates/swp-test-suite/tests/binding/surface.rs`) admits 73 items and refuses the
keyed half of the tree. `verify`, `scan` and `report` are already `binding_facing`, so
a binding can be built on them today — but `Session::protect` is `pending`, which means
the one operation that *produces* provenance cannot cross, so a binding would be a
read-only client of work done in Rust or through the CLI.

The blocker is narrow and was recorded rather than analysed: [SDK_ARCHITECTURE.md §6](../SDK_ARCHITECTURE.md)
says the result "reaches the keyed site identities of a private plan document by field"
and that "the API was not narrowed to make the list tidy". This record does the
analysis that sentence deferred: what exactly crosses, what any consumer reads back,
and what it would cost to hand the same operation to a foreign runtime.

Two constraints bound every answer:

* the binding layer must not become a way to read the keyed constellation out of a
  project, and
* a change that makes a finding sound stronger than the measurement behind it is
  closed rather than revised ([../../AGENTS.md](../../AGENTS.md)). So the claims below
  are either source citations or numbers from the harness in §5.

## 2. Current behavior, read from source

`swp generate` and `swp protect` are one operation — `Session::protect`
(`crates/swp-sdk/src/protect.rs:100-142`) — differing only in `Mode`
(`crates/swp-embedding/src/protect.rs:80-109`): `Plan` is `swp generate`, `Release` is
`swp protect`, `DryRun` is `swp protect --dry-run`. `Mode::writes_source()` is `Release`
only (`:99`) and `writes_store()` is everything but `DryRun` (`:106`).

The call, and where keyed material is made and used:

| step | source | what it produces |
| --- | --- | --- |
| `Session::protect` loads the root secret, builds a `Request`, calls the pipeline, drops the secret | `swp-sdk/src/protect.rs:124`, `:136-137`; `Request<'a>` borrows `&RootSecret` (`swp-embedding/src/protect.rs:114-130`) | nothing keyed leaves the frame |
| walk + analyse the tree | `swp-embedding/src/candidates.rs` | one `Candidate` per literal that could carry a fragment, each with `locations: [LocationId; 4]` (`candidates.rs:58, 78`) derived at `:343` |
| select | `swp-embedding/src/select.rs:149` | which sites and which family, ordered by `selection_priority` (`swp-manifest/src/keys.rs:179`) |
| apply | `swp-embedding/src/apply.rs:121` | the tag to render (`:235`), the re-derivation check (`:345-347`), and the `SiteEntry`s written into the signed manifest (`:353-354`) |
| plan | `swp-embedding/src/plan.rs:104-185` | `Plan { sites: Vec<PlannedSite>, skipped: Vec<SkippedSite>, … }`, each `PlannedSite.locations` copied from the applied entry (`:128`) |
| write | `swp-embedding/src/protect.rs:322-384` (release), `:268-279` (`Mode::Plan`, which writes the plan document and rewrites no source) | signed private manifest, private plan, public release record, rewritten sources |
| return | `swp-embedding/src/protect.rs:142-171`, `swp-sdk/src/protect.rs:73-84` | `Protection { …counts, fingerprint, artifacts, notes, plan: Plan }` inside `ProtectOutcome { protection, revision }` |

The keyed values themselves (`swp-manifest/src/keys.rs`):

```text
site_key         = derive(root, Project,  project_id ‖ canonicalizer_version)   (:86)
tag_key          = derive(root, Location,  project_id)                          (:87)
selection_key    = derive(root, Selection, project_id ‖ release_id ‖ ver)        (:88)
location_id      = first_128_bits(HMAC(site_key, project_id ‖ radius ‖ ver ‖ canonical_digest))  (:110-125)
fragment_tag     = truncate(HMAC(tag_key, project_id ‖ primary_location_id ‖ width), width)      (:149)
```

Three facts follow from those lines, and the rest of this record depends on them.
A `LocationId` is keyed — it is HMAC output under a root-derived key. Its inputs are
the project, the radius, the canonicalizer version and the site's canonical *shape*
(the enclosing statement with the literal replaced by `<SITE>`), and **no release id**:
ids name a site, not a run. `selection_priority` is the field that does take a release
id, which is why "which sites, in which form" is per-release while "what names a site"
is not.

The path out of the SDK is one field wide. `swp-sdk` re-exports `Mode` and `Protection`
(`crates/swp-sdk/src/lib.rs:96`) but not `Plan`, `PlannedSite`, `SkippedSite` or
`LocationId`; the only way a caller of the façade names a keyed id is by walking
`ProtectOutcome.protection.plan.sites[i].locations` — and `LocationId` is
`pub struct LocationId(pub [u8; 16])` with `as_bytes()`, `hex()`, `Display` and a
`Serialize` that writes hex (`crates/swp-core/src/id.rs:66-115`), while `Protection`
derives `Serialize` (`swp-embedding/src/protect.rs:142`), so serializing the envelope
serializes every id.

Store-side reads of the same material — `Store::read_plan`, `Store::read_private_manifest`
(`crates/swp-identity/src/store.rs:358`, `:366`) — are `forbidden`, and every accessor on
`Session` that reaches them is `pub(crate)` or `sealed`. `swp inspect plan --format json`
does echo ids, but it is a CLI store reader (`crates/swp-cli/src/inspect.rs:642-742`)
reaching the same private file, not a façade return value.

## 3. The security concern, stated precisely

The freeze's `forbidden` reason for `LocationId` claims that a caller holding ids
"could collect a project's whole address set and test candidate spans against it
**without the evidence maths**". That sentence over-claims, and this record replaces it.

Computing an id for a candidate span requires `site_key` (`keys.rs:110-125`), which
requires the root secret. A foreign runtime handed ids therefore gets *recognition*,
not an *oracle*: it cannot test a guess about code it has not already been given ids
for. The oracle risks in this design are real and are separately closed —
`fragment_tag` and `ReleaseIndex::expected_tag` are unreachable from the façade
([SDK_ARCHITECTURE.md §6](../SDK_ARCHITECTURE.md)) — and this is not one of them.

What disclosure of ids *does* cost, in order of how much the evidence supports it:

1. **It leaks the private constellation as a set of names.** An id is the keyed name of
   a site's shape. §18 of the spec refuses to store a fragment id in the public manifest
   for the same reason (`crates/swp-manifest/src/private.rs` module doc): doing so "would
   copy the watermark into the file that explains the watermark". A plan document is
   already inside that refusal; a binding result is outside it.
2. **It is a join key between documents.** Because no release id enters the derivation,
   an unchanged site carries the same id in every release of the project (§5, M2: 34–38
   of ~41 distinct ids shared between two releases chosen under different keys, and 10–11
   of 12 four-id tuples identical). Two leaked plan documents can therefore be aligned
   site-for-site, and a party who sees two projects sharing ids learns they share code —
   a statement about the source that neither document was written to make.
3. **It is the primary key of the signed manifest.** `PrivateManifest::validate` refuses
   two sites with the same primary id, and `sites_for(&LocationId)` resolves an id back
   to slot indices (`crates/swp-manifest/src/private.rs`). A leaked id set is the address
   set the evidence maths is computed against, which makes it the natural thing for a
   debug print, a crash log, or a telemetry payload to carry by accident.
4. **A foreign runtime prints what it is given.** `Debug`/`inspect`/`console.log` on a
   struct whose field is `pub [u8; 16]` with a hex `Display` emits keyed text into a
   garbage-collected language's logging, where this project cannot zeroize or redact it.
   `secret_leak` sweeps Rust artifacts and CLI output; it cannot sweep a Python `repr`.

Point 4 is the operational reason the boundary is a *type* rule rather than a
documentation rule, and it is the reason the options below are about shapes, not about
warning comments.

## 4. What the evidence had to settle

Five questions were open after the read, and each was answered by measurement rather
than argument, because the answer changes the decision:

* **E1** Can a keyed id be reconstructed from what is already public? (If yes, the
  boundary is decorative.)
* **E2** Does anything downstream of a protection run read the ids the result carries?
  (If no, the field can be dropped from a binding-facing result with no loss.)
* **E3** Does the CLI need them after `protect` returns? (This decides whether a
  sanitized result can reach CLI parity.)
* **E4** Are the ids already in the release artifacts a binding could read instead?
  (If they are only in private files, a binding that shows them is disclosing, not
  relabeling.)
* **E5** Is a plan reproducible, or is it load-bearing state a caller must hold?
  (This decides whether a binding needs the plan at all.)

## 5. Evidence

All of it is one harness, in this repository, offline, on synthetic projects in a
temporary directory, driving the same in-process entry point the CLI uses:

```text
cargo run --locked -p swp-test-suite --example protect-binding-boundary
```

`crates/swp-test-suite/examples/protect-binding-boundary.rs` prints tab-separated
`tag  key  value` rows, grouped M1–M6. Nothing in it changes product behavior: the
documents it corrupts are ones it wrote into its own temporary projects, and it reads
them back through the product's own loaders. Each `Project::synthetic_wide(_, 8, 12)`
run gets a fresh root secret, so the *relations* are the results, not the raw numbers;
three runs reproduced every relation below and M2's counts moved within the ranges
stated.

### M1 — where the ids a run produces actually land (E4)

Twelve sites, 48 ids (`12 × 4`), each id searched for by its 32-hex rendering:

| artifact | ids present (distinct / occurrences) |
| --- | --- |
| public release record `.swp/public/releases/` | 0 / 0 |
| private manifest | 48 / 72–76 |
| private plan | 48 / 72–76 |
| saved verify report | 0 / 0 |
| saved scan report | 0 / 0 |
| verify document (the SDK return value, as JSON) | 0 / 0 |
| **serialized `Protection` envelope** | **48 / 72–76** |
| `swp protect --format json` stdout | 0 / 0 |
| `swp protect` text stdout | 0 |
| sites the CLI's own JSON document described | 12 |

The occurrence totals exceed 48 because copies of one statement share an id; the
distinct count is the signal, and the last row is there because a CLI document that
described no site would print no id for a reason that proves nothing. This settles
E4 — every id is already in exactly the two private documents — and produces the
finding: the SDK's own result envelope is the one published-shaped object that carries
them, because `Protection: Serialize`. A binding that returns `Protection` and hands it
to `JSON.stringify` produces a private-plan equivalent on a wire.

### M2 — what an id names (E1, and the join claim in §3)

Two `Mode::Plan` runs of one untouched project under two release ids (`rel-aaaa…`,
`rel-bbbb…`):

| row | run A / run B |
| --- | --- |
| sites in each plan | 12 / 12 |
| distinct ids, release one / release two | 42 / 40–42 |
| ids present in both sets | 34–38 |
| four-id tuples identical in both | 10–11 of 12 |
| plan mode published a release | false (`NotProtected` refused the release list) |
| the two runs' tree fingerprints identical | false |
| the two runs' touched-file sets identical | true |

Positions cannot be the join here, and the harness says why in its own comment: a
`PlannedSite.line_hint` is a line in the *protected* text, and which equivalent form
carries a site's code is keyed by the release (`select.rs:149`, `keys.rs:179-189`), so
one `(file, line_hint)` can name a different site in the two plans. That is also what
explains the ids that do *not* overlap: the site's canonical shape really did change
between the two protected trees, which is what `fingerprint_identical false` records.
The overlap that does exist is the finding: no release id is an input
(`keys.rs:110-125`), so ids are stable names for unchanged sites and two plan documents
join on them.

### M3 — what the published half of a store can do (E1)

A project was protected, then `.swp/private/` was left behind and only `.swp/public/`
— which is where the identity lives, `swp-identity/src/store.rs:82-84` — the config and
the rewritten sources were copied into a second directory, which was opened as a
session. The holder of all 48 ids, with the public artifacts:

| row | value |
| --- | --- |
| session opens | yes |
| releases listed | 1 |
| public record readable | OK, carrying 0 ids |
| `verify` | `SECRET_UNAVAILABLE` |
| `scan` | `SECRET_UNAVAILABLE` |
| `protect --dry-run` | `SECRET_UNAVAILABLE` |

The ids are worthless as a capability without the secret, and equally worthless
as a description of what the evidence will later conclude: the verifier refuses before
it looks. This is the measurement that closes the "tag oracle" reading of the freeze's
`LocationId` reason, and it is the reason §3 calls the concern disclosure rather than
an oracle.

### M4 — what reads the ids back (E2, E3)

One protected project, all 48 ids in the stored plan replaced by `0000…0000` through
`Store::write_plan`, then every downstream consumer re-run and its output compared with
the snapshot taken before the tamper. Documents carry the moment they ran, so the
comparison ignores that one field; a difference in anything else is reported as a
difference.

| consumer | after destroying the plan's ids |
| --- | --- |
| `verify` document | identical |
| `scan` report | identical but for the moment it ran |
| public release record | identical |
| `inspect plan` text view | identical |
| `inspect fragments` text view | identical |
| `inspect manifest` text view | identical |
| **`inspect plan --format json`** | **DIFFERS** |

The second row is the harness's own honesty check: a saved report carries the clock, so
the first version of this measurement called it a difference and said nothing. The row is
reported as the harness prints it, and the field it ignores is a timestamp and nothing
else — the shape removed is `YYYY-MM-DDTHH:MM:SS`, which no id, path or count in these
documents has.

Then the same question against the *signed* document, tampering one hex character of one
manifest id: `verify` → `INVALID_MANIFEST`, `scan` → `INVALID_MANIFEST`, `inspect
manifest` → exit code 5.

This settles E2 and E3 together and draws the line this record turns on. Ids are
load-bearing in the signed manifest, where they are authenticated and where a single
bit of drift fails the release. In the plan they are descriptive — copied there so a
reader can confirm a plan and a manifest agree (`plan.rs:54-57`) — and the only reader
that surfaces them is one JSON echo of a private file. Nothing that grades evidence
reads them from a plan, and nothing in the CLI's own output does.

### M5 — is a plan reproducible (E5)

Generate (`Mode::Plan`) under a fixed release id, delete the plan file the run wrote,
then protect with that same id from the untouched tree:

| row | value |
| --- | --- |
| plan file deleted | true |
| ids planned / ids applied | 48 / 48 |
| the applied constellation identical to the plan | true |
| per-site file/class/family identical | true |
| `verify` afterwards | `INTACT` |
| `swp inspect plan` after apply | exit 0 |

Same release id over the same tree is the same plan (`swp-sdk/src/protect.rs:101-107`),
and `Mode::Release` writes its own plan document, so a binding caller never needs the
plan *as state*. It needs it only as a description of what a run decided — which is
what §6 says the result should carry.

### M6 — can the CLI's own document be rebuilt without ids (E3)

A `swp protect --dry-run --format json` run's document was parsed (29 keys) and each key
rebuilt from `Protection` plus plan-derived strings, with no id anywhere:

| source of the key | count | keys |
| --- | --- | --- |
| a `Protection` or `ProtectOutcome` field | 22 | schema, protocol, mode, project_id, release_id, fingerprint, fingerprint_level, tag_bits, requested_sites, target_sites, sites_embedded, sites_skipped, files_walked, files_in_scope, candidates, files_changed, artifacts, generated, modified, notes, revision, skip_reasons + families (both from plan field strings) |
| owned by `swp-cli` | 6 | command, commit, never_commit, back_up, next |
| per-run clock, not comparable across two runs | 1 | created_at (it is `Protection.created_at`, set in `swp-sdk/src/protect.rs:133` and printed at `swp-cli/src/protect.rs:152`) |
| unreachable without a keyed field | **0** | — |
| ids present in the printed document | **0** | — |

The two plan-derived tallies were not empty, which is the only way this measurement means
anything: 12 sites behind `families` and 153 refused candidates behind `skip_reasons`, both
rebuilt from `PlannedSite.family` and `SkippedSite.reason` strings alone.

Every key the CLI prints is reachable from the non-keyed part of the result. The two
aggregate keys are computed from `site.family` and `skipped.reason`
(`swp-cli/src/protect.rs:119-126`), which is the whole use the CLI makes of the plan.

## 6. Options considered

Five shapes were on the table. Each is assessed against the same fourteen criteria, in
the same order, without ranking: the criteria do not carry equal weight, and the
decision in §7 says which ones it turned on.

Legend for the criteria lines, once, to keep the option sections readable:
**B** security boundary · **C** API correctness · **S** semantic completeness ·
**P** CLI parity · **R** Rust API compatibility · **Y** Python suitability ·
**N** Node suitability · **Z** serialization requirements · **M** memory ownership ·
**V** future versioning impact · **T** testability · **X** changes protocol semantics ·
**A** changes stored artifacts · **G** migration required.

### Option A — keep `protect`/`generate` Rust-only

Leave the freeze exactly as it is: bindings wrap `verify`, `scan`, `report`,
`capabilities` and `init`, and embedding stays a Rust or CLI operation.

* **B** Strongest. No keyed type is nameable from a foreign runtime, and no result of a
  secret-loading call exists across the boundary at all.
* **C** Correct but incomplete: it accepts a façade where the write path is Rust-only and
  the read path is polyglot, so `swp-sdk`'s own doc ("the operations a binding exists to
  offer", `swp-sdk/src/lib.rs`) is only partly true.
* **S** Nothing lost — nothing gained. A binding cannot report what a run decided.
* **P** Divergent by construction: a Python user would shell out to `swp` and parse
  `ProtectionDocument`, re-implementing the CLI's text rather than calling it.
* **R** Zero change: `Protection`, `Plan` and `ProtectOutcome` keep their shapes.
* **Y**, **N** No work. The binding package would document one missing operation and the
  reason.
* **Z** None — but the exposure it leaves: `Protection: Serialize` still emits all 48 ids
  from Rust, so A does not actually close M1's row, it only declines to widen it.
* **M** Trivial: no protection value crosses.
* **V** None. Nothing moves; `pending` stays `pending` forever, and a `pending` item is a
  decision that has been paid for twice — once in the freeze, once here.
* **T** Weak: there is nothing new to assert beyond `binding_surface`'s existing pins.
* **X**, **A**, **G** None, none, none.

### Option B — keep the Rust result, add a sanitized binding-facing result

Leave `ProtectOutcome` and `Protection` untouched for Rust callers and define a second
type — the same counts, fingerprint and artifacts, per-site rows and skip rows with no
ids — that a binding returns.

* **B** Sound if, and only if, the new type is a *different* type rather than a
  redaction of the old one. M1 is the warning: a serializer that walks the real struct
  emits every id, so "sanitize on the way out" cannot be a convention — it has to be a
  type the boundary test can check field by field, exactly as `ScannedSite` and
  `swp_evidence::SiteRow` already are.
* **C** Correct downstream, but it leaves two spellings of one account in the public API,
  and both are reachable from `Session::protect`. The drift risk is the ordinary one: a
  field added to `Protection` and not to its sanitized twin.
* **S** Complete for a caller's actual questions — what was embedded, where, how many
  were refused and why, what changed on disk, what the tree now hashes to. What is
  dropped is per-site identity, which M4 shows nothing reads and M5 shows is regenerable.
* **P** Reachable: M6 rebuilt 22 of 29 document keys from the non-keyed fields alone, with
  0 unreachable. A row set mirroring `SiteRow`'s design (join by site index, never by id)
  gets parity by construction rather than by approximation.
* **R** Additive: no existing Rust signature moves, so the pre-1.0 crate surface grows by
  one type. `VERSIONING_POLICY.md §2` makes an added field a `MINOR` and a removed or
  renamed one a `MAJOR`, so B is a minor and its sanitized twin never forces one.
* **Y** Good — plain data, no borrow, no key bytes, so `PyO3` maps it to a dict/`dataclass`
  and nothing needs zeroizing (SDK_ARCHITECTURE §6: "nothing secret crosses").
* **N** Good — the same shape crosses `napi-rs` as a `Result`-typed object; `Vec<T>` maps
  to an `Array`, and there is no `Vec<u8>` field to argue about.
* **Z** The twin must be `Serialize` and must *not* name a `LocationId`, which
  `binding_surface`'s field-shape and type-name gates already enforce.
* **M** Owned plain data; no `Request<'a>`, no borrow of the session, matching the façade's
  existing object-lifetime rule (`SDK_ARCHITECTURE.md §6`, "no `Request<'a>` reaches a
  binding signature").
* **V** Costs a second result type to keep in sync forever, and every later field added to
  `Protection` needs a decision about whether it crosses.
* **T** Strong: `sdk_parity` can assert the twin's values equal the CLI's document
  key-for-key, and `binding_surface` refuses it a keyed field. A test that fails if the
  twin drifts is worth more than a comment saying do not drift.
* **X** None. Nothing about the derivation, the selection, the tags, or the grading moves.
* **A** None. The plan and manifest documents keep their bytes, so M4's tamper behavior is
  untouched and `inspect plan --format json` still echoes ids to a store reader.
* **G** None: no stored document changes shape, so no saved artifact is reinterpreted.

### Option C — split internal planning structures from the public Rust result

Rebuild the Rust SDK so `protect`'s public result no longer contains a `Plan` at all: the
plan stays an internal artifact of the embedding pipeline, and the public result is the
non-keyed account.

* **B** Strongest of the result-shaping options, and the only one that makes the invariant
  structural: there is then no keyed field on any path out of a public façade operation,
  so `binding_surface`'s `const` pin (`tests/binding/surface.rs`, which reads
  `outcome.protection.plan.sites[0].locations`) would be *deleted by the change*, as the
  freeze says a pin should be.
* **C** The most correct API in isolation — a public result that carries a private
  document's contents is the shape M1 exposed — but it is a claim about the Rust API, not
  just the binding one.
* **S** Complete, provided the internal plan is still reachable by the Rust callers that
  legitimately want ids today. Two exist: `swp-cli inspect plan` reads the plan from the
  store, not from the result (`swp-cli/src/inspect.rs:642-742`), so CLI-side does not
  need it; `swp-sdk`'s own `protect` writes it before returning, so nobody needs the copy.
  The measured question is who else does, and today that is only the test suite.
* **P** Same parity as B, from a different direction: the CLI document becomes a projection
  of the public result, which is what M6 shows it already is.
* **R** **Breaking.** `swp_embedding::Protection` and `swp_embedding::Plan` are re-exported
  through `swp-sdk` (`lib.rs:96`) and are Rust-public API; removing `Protection.plan`, or
  changing `ProtectOutcome.protection`'s type, is a `MAJOR` under
  `VERSIONING_POLICY.md §2`, and every consumer in this tree — `swp-cli/src/protect.rs`,
  `tests/binding/surface.rs`'s pin, the `sdk_parity` suite, and this harness — moves with
  it. That is affordable pre-1.0 and would be cheap to do *now*; it is not affordable as
  a side effect of a binding phase.
* **Y**, **N** Identical to B once landed: the binding wraps whatever the Rust result is.
* **Z** Cleanest: the only serializable result is the safe one, so a `JSON.stringify` of
  the envelope cannot produce M1's finding row.
* **M** Unchanged from today.
* **V** One major version, then no drift risk: there is no second type to keep in sync.
* **T** Best: one shape, so `sdk_parity` compares the CLI document to the same value a
  binding would get, and `binding_surface` never has to reason about two twins.
* **X** None — as long as the plan document keeps being written byte-for-byte. If it were
  instead narrowed (see D), that would be a schema change, and it is not what C says.
* **A** None. `Store::write_plan` and the signed manifest are untouched; the private plan
  is still the plan, with its ids.
* **G** None for artifacts. Migration in the *API* sense only: Rust callers holding
  `outcome.protection.plan` re-read their code.

### Option D — transform or replace `LocationId` in the binding-facing contract

Keep one result type and make what crosses safe: give the binding a per-site value that
stands in for the ids — a truncated prefix, an unkeyed hash of the digest, or a
binding-local surrogate index.

* **B** Worst of the five, and the analysis has to say why precisely. Any *deterministic
  public* stand-in is derived from content that is not otherwise public. An unkeyed hash
  of the canonical digest is computable by anyone who has the site's text, so it turns a
  keyed name into an unkeyed, openly testable one: the disclosure stops being something
  only a secret-holder can align and becomes something a scanning attacker can compute
  for candidate code and compare against a leaked document. A truncated prefix keeps the
  same property with fewer bits of defense. A per-run surrogate (an index into the
  binding's own row list) is safe *within* one run and is the only variant that does not
  leak — see B, which gets the same effect with no new identity at all.
* **C** Introduces a second name for one site. `PrivateManifest::sites_for`, `ReleaseIndex
  ::lookup` and `apply.rs`'s drift check (`:345-347`) all speak `LocationId`; a
  binding-visible alias invites a caller to believe the two are interchangeable across
  runs, and M2 shows they are not.
* **S** Nothing added that a caller needs; the surrogate is only useful for correlating
  rows inside one document, which an index already does — `SiteRow.site` is exactly that
  ("Index into that release's site list", `swp-evidence/src/verify.rs:84-104`).
* **P** No parity gain: the CLI prints no id (`swp-cli/src/protect.rs:187-293`; M1's last
  two rows).
* **R** Depends on the variant. A newtype in the result only is additive; changing
  `LocationId`'s rendering or `Serialize` is breaking, and `hex()` is used by every
  document that shows one.
* **Y**, **N** A surrogate index needs the binding to hold the run's ordering, which
  pushes state into the foreign runtime — the opposite of the façade's owned-plain-data
  rule (`SDK_ARCHITECTURE.md §6`).
* **Z** Requires a canonical mapping from id to surrogate that survives serialization in
  both directions, and a schema name for it. That mapping is a new artifact contract.
* **M** No change.
* **V** If the surrogate ever enters a stored document, its meaning is frozen forever, and
  `VERSIONING_POLICY.md §1` exists to keep saved documents from being reinterpreted.
* **T** Poor: the property to assert is "this value is not derivable from content", which
  is a statement about a hash function, not about a field.
* **X** **Yes, if the id's own representation moves.** `location_id`'s inputs and its
  output width are protocol, and the width was chosen for the birthday bound stated at
  `keys.rs:122-123`. Changing it changes what a scan matches.
* **A** **Yes** for any variant that changes the stored ids — the manifest is signed over
  them, and a `swp-embedding` test asserts that a plan's ids agree with the manifest
  entries they describe.
* **G** **Yes**: every protected project's manifest and plan would describe a different
  identity than the one a detector derives, so detection would have to keep reading the
  old form indefinitely.

### Option E — return a document, as `verify` and `scan` already do

Do not add a protection-shaped struct at all. `swp-evidence` already builds the
versioned documents that cross the boundary — the verify document (`grade` →
`VerifyDocument`) and the saved report (`Report::build`) — and `swp-cli`'s protect output
is already such a document (`SWP-1-protection-v1`, `swp-cli/src/protect.rs:118-185`).
Build the protection document inside `swp-evidence`, return *that* from a binding-facing
result, and let `Protection`/`Plan` stay what they are for Rust.

* **B** As strong as B, with less surface to trust: the crossing value is a document whose
  field set and ordering are a published schema (`swp_evidence::Report`'s reader refuses a
  schema it does not know, `report.rs:147-162`), not a struct a future field can quietly
  widen.
* **C** Consistent with the two operations that already cross. This is the pattern Beta 3
  established when the verify document moved into `swp-evidence` so the SDK and the CLI
  could not disagree about its contents.
* **S** Complete by definition — the document is what an operator reads.
* **P** Parity by construction, not by test: one builder, two renderers. The six
  `swp-cli`-owned keys (command, commit, never_commit, back_up, next, and the `created_at`
  clock it stamps) stay in `swp-cli` or move with the document; M6 shows they are the only
  keys the SDK result does not supply.
* **R** Additive for the SDK; it moves code out of `swp-cli` into `swp-evidence`, which is
  a crate-boundary question — `swp-cli` over the service crates, `swp-evidence` below
  `swp-sdk` — and the direction the dependency rules already allow.
* **Y**, **N** The binding returns a string/document object it can `JSON.parse` or
  `json.loads`, exactly as `verify`'s binding would. Both language stories want a
  schema-versioned blob more than a class hierarchy they must keep in step.
* **Z** The heaviest: a published document schema (`SWP-1-protection-v1` is today only a
  CLI shape, not a `swp-evidence` schema constant) would have to be named, versioned, and
  carried inside the document. That is the price, and it is a real one.
* **M** A string across FFI. Simplest ownership of all five options.
* **V** A field becomes a schema decision, i.e. `MINOR` when added and `MAJOR` when
  removed — which is *slower* to change than a Rust struct, and that is the intended
  trade: `VERSIONING_POLICY.md §3` says a saved report is never reinterpreted.
* **T** Strongest: `sdk_parity` compares bytes of the same document from two paths, and
  `docs_examples` already re-executes the CLI's protection transcript, so a drift fails a
  documented example rather than a unit test.
* **X** None, if the document describes the same run. If it also gets *saved* into the
  store, it becomes a fourth artifact — and a protection document that can be read back is
  a disclosure surface, so the answer is: return it, do not store it. `Mode::Plan` already
  stores only the plan (`swp-embedding/src/protect.rs:268-279`).
* **A** None, under that condition.
* **G** None.

## 7. Decision

**`protect`/`generate` will cross the boundary as a sanitized result carrying Appendix A's
FFI-`yes` subset and nothing else — Option B, with Option E's document as its preferred
container — and not through any change to `LocationId`, the plan document, or the
manifest.** What is decided is the *content* and the fact that it is a separate type
rather than a redaction; whether that content is a Rust struct or a schema-versioned
document is §9.1, and both are B. A stays on the table only as the fallback if the
document's schema cost is judged too high; C is recorded as the shape to move to if a
second result type ever demonstrably drifts; D is rejected on evidence.

The chain of reasoning, with the measurement attached to each link:

1. The boundary is one field wide, not a type hierarchy: every keyed value a public façade
   operation emits is `PlannedSite.locations`, reached through
   `ProtectOutcome → Protection → Plan → sites` (§2), and it escapes only through the
   serialized envelope (M1's `sdk_protection_envelope_json 48/48`).
2. Holding those ids is a disclosure problem, not an oracle problem (M3, and `keys.rs:110`
   — deriving a new one needs the secret). §3 replaces the freeze's over-claimed reason
   with that statement, plus the join-key property M2 measures.
3. Nothing any consumer reads back needs them. Destroying every id in the stored plan
   changes exactly one output — a JSON echo of a private file — while one flipped hex
   character in the signed manifest fails `verify` and `scan` outright (M4). And the CLI,
   which is the consumer whose parity a binding has to meet, rebuilds its whole document
   from the non-keyed fields with 0 ids and 0 unreachable keys (M6).
4. So a result type that carries the counts, the fingerprint, the artifact list, one row
   per embedded site (file, line hint, language, adapter, class, family, width, radius
   names) and one row per refusal (file, line hint, reason token) loses nothing that is
   read, and stays inside patterns this repository already enforces: `ScannedSite` and
   `SiteRow` are per-site rows joined by index, "deliberately free of anything keyed", and
   `binding_surface` already refuses a binding-facing field that is byte-shaped or keyed.
5. Because the plan is reproducible from a release id over an untouched tree (M5), a
   binding does not need the plan as state. It needs the run's account, which is item 4.
6. Therefore the decision does not touch protocol semantics, stored artifacts, or saved
   documents: no schema moves, no bytes change, no migration exists (B/E: **X** none, **A**
   none, **G** none). What it costs is the criteria the others pass for free — a second
   result type to keep in sync (**V**, and §8 says who pays for that).
7. What it must *not* be is a redaction convention on the existing type. M1 is the
   counterexample: a `Serialize` walk emits every id, so the safe result has to be a
   separate type or a separate document, and the boundary test has to read it field by
   field.

Rejected with reasons, stated so the next reader does not re-litigate:

* **A** keeps the freeze's honest limitation but leaves the finding of M1 in place —
  `Protection: Serialize` still emits the private constellation from Rust — and freezes a
  `pending` item that this record has now resolved into a shape.
* **D** in every variant except a within-run index converts an id from something only a
  secret-holder can align into something computable from public content, and the
  within-run-index variant is what B already gets from a `site: usize` field, with no new
  identity to version.
* **C** is the right structural claim and the wrong next step: it is a `MAJOR` against
  re-exported Rust API (`lib.rs:96`, `VERSIONING_POLICY.md §2`) taken to serve a binding
  that does not exist yet. Recorded as the fallback if B's twin drifts.

## 8. Consequences

* The freeze does not move yet. `Session::protect` and `ProtectOutcome` stay `pending`,
  `LocationId`, `Plan`, `PlannedSite`, `SkippedSite` and `Protection` stay `forbidden`,
  and no category in `BINDING_SURFACE.json` gains or loses an item in this change set. A
  binding-facing type that does not exist cannot be allowlisted, and the `pending` items'
  reasons now name this record so the next phase inherits the decision rather than the
  question.
* Three reasons in that file were wrong or over-stated and are corrected here, because a
  boundary file that over-claims invites a reader to discount the true claim: the
  `LocationId` reason asserted an oracle (§3), the `SkippedSite` reason called it
  "keyed by content" when the type carries no keyed field (`plan.rs:63-71`), and the
  `Session::protect` reason called narrowing the result "protocol-visible" when M4 and M5
  show it is neither protocol-visible nor artifact-visible. The `SkippedSite` correction
  replaces a false claim with a true and load-bearing one: a refusal's `detail` sentence
  can quote a computed fragment tag (`swp-embedding/src/apply.rs:235`, `:256-266` →
  `plan.rs:132-139`), and a tag *is* keyed material, so the type still does not cross. A
  fourth reason, `ProtectOutcome`, states the escape path M1 measured rather than only the
  field chain, and one `notes` line points at the harness so no number in the file has to
  be re-derived from prose.
* The next binding phase owns the cost this decision accepts: one sanitized result type
  (or one `swp-evidence` protection document, if it takes §6 E's shape), its field-by-field
  `binding_surface` coverage, and a `sdk_parity` assertion that its values equal the CLI's
  document. Until that exists, the boundary test keeps its `const` pin reading
  `outcome.protection.plan.sites[0].locations`, which is the mechanism that makes §7's
  decision provable rather than aspirational.
* `docs/SDK_ARCHITECTURE.md §6` and `docs/SDK_API.md §4` describe today's freeze and are
  not rewritten by this record; they will need one paragraph reconciled to it when the
  phase lands, and that is a documentation change to make *with* the code, not before it.
* Nothing about a finding's strength changed. No evidence level, coincidence bound, or
  grading arithmetic was touched, and no new failure mode exists, so no error code, CLI
  line, or troubleshooting line was added.

## 9. Unresolved questions

Recorded as open at acceptance. The implementation answered 1, 2 and 4 by deciding
what to build; 3 and 5 are still open, and nothing built here closes them.

1. **Document or struct.** B and E differ on the container, and the evidence does not
   settle it: M6 shows a struct is sufficient, §6 E shows a document is drift-proof. The
   deciding question is whether the protection document becomes a *published schema*. The
   name already exists as a literal a CLI printer writes
   (`swp-cli/src/protect.rs:146`, `SWP-1-protection-v1`); what does not exist is a
   constant, a reader, and the refusal rule that makes an unknown reader reject a document
   it cannot interpret, which is what `Report` already does for a saved report
   (`swp-evidence/src/report.rs:147-162`). That is a versioning decision for
   `VERSIONING_POLICY.md §1`, not a binding one.
   **Resolved: an owned Rust struct.** The evidence did not change during
   implementation, so the choice was made on what is in the tree today: publishing a
   schema means a constant, a reader and an unknown-schema refusal rule, and none of
   those exist because no consumer of a protection run parses its output — the CLI's
   document is written and never read back. `ProtectSummary` therefore carries no
   `schema` and no `protocol` field: a struct with a schema number in it is half a
   schema and none of the discipline. E's container stays available; adopting it later
   is additive over this type's fields, which are the same 22 the CLI reads.
2. **Does `Mode::DryRun` cross?** Its result is the same shape with no writes
   (`swp-embedding/src/protect.rs:103-108`), so it is the natural first candidate for a
   binding and the natural first test of the sanitized type. Nothing in this record
   requires it, and nothing forbids it either.
   **Resolved: all three modes cross, because there is nothing mode-specific to
   decide.** `protect_summary` calls `protect` and projects its result, so a mode is
   a field of the answer rather than a gate in front of it. `sdk_parity` runs the
   projection under each of the three (`the_binding_facing_account_matches_the_cli_document_key_for_key`
   is a dry run against the CLI's own `--dry-run` document,
   `the_summary_is_the_same_run_with_every_keyed_site_identity_left_behind` a plan,
   `a_release_through_the_binding_door_reports_the_same_run_as_the_cli_document` a
   release).
3. **`inspect`-equivalent reads.** A binding that can protect but cannot read a plan
   cannot explain a refusal beyond a reason token. `swp inspect plan`'s text view prints
   file, line and reason with no id (M4: identical under total id destruction), so a
   plan-view operation is likely crossable — but the plan it reads is a store file, and
   `Store::read_plan` is `forbidden`, so that is a *new* façade read to design, not a
   reclassification.
   **Still open, and narrower than it was.** The summary answers most of the question
   without touching the store: a binding holds every refusal's file, line and reason
   token from the run that made it. What remains genuinely open is reading a *stored*
   plan for a release the caller did not just produce — a new façade read, not a
   reclassification, and still out of scope here.
4. **How much of `notes` is safe.** It is `Vec<String>` assembled from walk omissions and
   resource-limit lines (`plan.rs:154-164`), i.e. free-form text from inside the pipeline.
   A boundary rule that checks types cannot check prose, so its crossing needs the same
   argument `SkippedSite.detail` got: read the producers, name the strings that can carry
   keyed text, and refuse the type until they cannot.
   **Resolved: it crosses, and the census is in the boundary file.** Seven push sites, all
   read, all in `swp-embedding`: `candidates.rs:358-361` and `:385-388` (a
   project-relative path with a count of literals left out, and the limits in force),
   `plan.rs:155-157` (one line per walk omission, each reason fixed prose, a path, a byte
   count or a limit number, per `walk.rs:239-424`), `plan.rs:158-164` with
   `select.rs:312-320` (the shortfall line: two counts of sites), `protect.rs:274-278`
   and `:281-286` (the `plan`/`dry_run` explanations, written at the call site), and
   `protect.rs:377-381` (how many source files were modified). None interpolates a key, a
   keyed id or a rendered tag. The argument is not the only thing
   holding it: `sdk_parity` sweeps the serialized summary of a real run against that
   run's own location ids, and a note that carried one would fail there rather than in
   review. `SkippedSite.detail`, by contrast, still does not cross — its sentence
   renders a tag (`apply.rs:235, :256-266`), and `RefusedSite` carries the token.
5. **Whether `Protection: Serialize` should stay.** M1's finding row is a property of a
   derive on a Rust type, so a Rust program can already write a private-plan equivalent to
   a log. Removing the derive is a breaking Rust-API change (C's cost) that no binding
   needs; it is left as a standing finding rather than folded into this decision.
   **Still open, and untouched.** The derive is why `ProtectOutcome` is `pending` rather
   than `binding_facing`, and this change did not move it: a binding is pointed at the
   projection instead. A Rust caller can still serialize a `Protection` and write the
   keyed constellation into its own log; that is the standing finding, and it is the
   CLI's own stdout that M1 measured as carrying zero ids.

## Appendix A — field-by-field classification

Every field of the seven types in the chain — plus `FileChange`, which
`Protection.files_changed` carries — against the eight labels. Each declaration is cited
once, above its table.

| label | question it answers |
| --- | --- |
| **pub** | does this value already appear in a published artifact (`.swp/public/releases/`) or on the CLI's stdout? |
| **secret** | is it key material — the root secret, a derived key, or sealed bytes? |
| **keyed** | is it the output of a MAC under a root-derived key? |
| **safe** | is it derived but safe: a public algorithm over content or over already-published material? |
| **fs** | does it describe the operator's filesystem or store layout? |
| **doc** | is it a field of a versioned, schema-named document? |
| **FFI** | may it appear in a binding-facing type today — `yes`, or `no: <reason>` |

Nothing here is `secret`, and that is a finding rather than an omission: `Request<'a>`
borrows `&RootSecret` (`swp-embedding/src/protect.rs:118`) and `Session::protect` drops it
before returning (`swp-sdk/src/protect.rs:137`), so key material is not a field of anything
a caller can hold. The column stays because the question was asked of every field.

### `ProtectOptions` — `swp-sdk/src/protect.rs:35-57` (binding-facing today)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mode` | `Mode` | yes — `swp protect` and `generate` differ only here | – | – | yes, an enum tag | – | yes | yes |
| `release_id` | `Option<ReleaseId>` | yes — in the public record | – | – | yes; an allocated label, which *selects* keys without being one | – | yes | yes |
| `revision` | `Option<String>` | yes | – | – | yes; display text, never hashed (`:48-55`) | – | yes | yes |

### `ProtectOutcome` — `swp-sdk/src/protect.rs:73-84` (`pending`)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `protection` | `Protection` | partly — every field but `plan` | – | **yes, by containment** | – | yes, via `artifacts` | – | no: the only keyed path out of a public façade operation |
| `revision` | `Option<String>` | yes | – | – | yes | – | yes | yes — the one field a binding could be given today |

### `Protection` — `swp-embedding/src/protect.rs:143-171` (`forbidden`)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `project_id` | `ProjectId` | yes | – | – | yes | – | yes | yes |
| `release_id` | `ReleaseId` | yes | – | – | yes | – | yes | yes |
| `created_at` | `Timestamp` | yes | – | – | yes | – | yes | yes |
| `mode` | `Mode` | yes | – | – | yes | – | yes | yes |
| `fingerprint` | `Digest` | yes — published in the record | – | – | yes, SHA-256 of the tree (§16) | – | yes | yes; `Digest` is already binding-facing |
| `fingerprint_level` | `String` | yes | – | – | yes | – | yes | yes |
| `tag_bits` | `u8` | yes | – | – | yes | – | yes | yes |
| `requested_sites` | `u32` | yes | – | – | yes | – | yes | yes |
| `target_sites` | `u32` | yes | – | – | yes | – | yes | yes |
| `sites_embedded` | `u32` | yes | – | – | yes | – | yes | yes |
| `sites_skipped` | `u32` | yes | – | – | yes | – | yes | yes |
| `files_walked` | `usize` | yes | – | – | yes | – | yes | yes |
| `files_in_scope` | `usize` | yes | – | – | yes | – | yes | yes |
| `candidates` | `usize` | yes | – | – | yes | – | yes | yes |
| `files_changed` | `Vec<FileChange>` | yes | – | – | yes | – | yes | yes |
| `artifacts` | `Vec<String>` | no — names files under `.swp/private/` | – | – | yes | **yes**, store-relative, which is the form already crossing as `VerifyOutcome::report_saved` | yes | yes, while the store-relative rule holds |
| `notes` | `Vec<String>` | yes | – | – | free-form text from inside the pipeline | – | yes | qualified — §9.4 |
| `plan` | `Plan` | **no — this is the private plan document** | – | **yes** | – | yes | yes | no: carries every id |

### `FileChange` — `swp-embedding/src/protect.rs:133-139`

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `file` | `String` | yes | – | – | yes | project-relative, not private | yes | yes |
| `sites` | `u32` | yes | – | – | yes | – | yes | yes |
| `bytes_before` | `u64` | yes | – | – | yes | – | yes | yes |
| `bytes_after` | `u64` | yes | – | – | yes | – | yes | yes |

### `Plan` — `swp-embedding/src/plan.rs:76-99` (`forbidden`; the stored private document)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol`, `schema` | `String`, `u16` | yes | – | – | yes | – | yes, `SWP-1-plan-v1` | yes |
| `project_id`, `release_id`, `created_at` | `ProjectId`, `ReleaseId`, `Timestamp` | yes | – | – | yes | – | yes | yes |
| `canonicalizer_version` | `u16` | yes | – | – | yes | – | yes | yes |
| `generator` | `GeneratorInfo` | yes | – | – | yes | – | yes | yes |
| `targets`, `excludes` | `Vec<String>` | yes — the scope the run read | – | – | yes | config-derived names | yes | yes |
| `tag_bits`, `embed_strings` | `u8`, `bool` | yes | – | – | yes | – | yes | yes |
| `requested_sites`, `target_sites` | `u32` | yes | – | – | yes | – | yes | yes |
| `sites` | `Vec<PlannedSite>` | no | – | **yes, by containment** | – | – | yes | no |
| `skipped` | `Vec<SkippedSite>` | no | – | no by type, possible by text | – | – | yes | no: see `SkippedSite` |
| `notes` | `Vec<String>` | yes | – | – | free-form | – | yes | qualified — §9.4 |

### `PlannedSite` — `swp-embedding/src/plan.rs:38-58` (`forbidden`)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `file` | `String` | yes | – | – | yes | project-relative | yes | yes |
| `line_hint` | `u32` | yes | – | – | yes; a hint in the *protected* text, and "nothing keyed reads it" (`:41-42`) | – | yes | yes |
| `language`, `adapter`, `class`, `family` | `String` | yes | – | – | yes | – | yes | yes |
| `width` | `u8` | yes | – | – | yes | – | yes | yes |
| `primary` | `u8` (`RadiusKind` code) | yes | – | – | yes; a slot selector, not a key input of its own | – | yes | yes |
| `locations` | `[LocationId; 4]` | **no — private plan and private manifest only** | – | **yes: 4 × 128 bits of HMAC output under `site_key`** | – | – | yes | **no — the field this record is about** |

### `SkippedSite` — `swp-embedding/src/plan.rs:63-71` (`forbidden`)

| field | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `file` | `String` | yes | – | – | yes | project-relative | yes | yes |
| `line_hint` | `u32` | yes | – | – | yes | – | yes | yes |
| `reason` | `String` | yes | – | – | yes; a stable token (`overlapping-radius`, `constellation-full`, `refused-by-validation`) | – | yes | yes |
| `detail` | `String` | no | – | **can be** — a refusal sentence interpolates `code {code}`, and `code` is `fragment_tag`, truncated HMAC output (`apply.rs:235`, `:256-266`, copied at `plan.rs:132-139`) | – | – | yes | no: text this boundary cannot check by type |

### `LocationId` — `swp-core/src/id.rs:66-115` (`forbidden`)

| member | type | pub | secret | keyed | safe | fs | doc | FFI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| the inner array | `pub [u8; 16]` | no | – | **yes** — `first_128_bits(HMAC(site_key, …))` (`keys.rs:110-125`) | – | – | yes, wherever a plan or manifest writes one | no |
| `as_bytes` | `&[u8; 16]` | – | – | yes, in raw form | – | – | – | no: `binding_surface` refuses a binding-facing `[u8; N]` or `Vec<u8>` member |
| `hex`, `Display`, `Serialize` | `String` | – | – | yes, in text form | – | – | yes | no: this is the route by which it reaches a log |
| `from_hex`, `PartialOrd`, `Hash` | – | – | yes, as a value | – | – | – | – | no — and they are what make a collected id set a usable `BTreeSet`, i.e. the alignment property §3.2 measures |

## Appendix B — what the CLI reads, and what it prints

`swp-cli` is the only in-repository consumer of a protection result, so its read set is
the evidence for what a binding would have to reproduce. Both protect paths run
`swp-cli/src/protect.rs:100-116`, which takes the `ProtectOutcome` and calls `document`
(`:118-185`) and `text_lines` (`:187-293`).

| what the CLI reads | where | what it becomes |
| --- | --- | --- |
| 14 scalars of `Protection` | `:149-163` | the document's `mode`, `project_id`, `release_id`, `created_at`, `fingerprint`, `fingerprint_level`, `tag_bits`, `requested_sites`, `target_sites`, `sites_embedded`, `sites_skipped`, `files_walked`, `files_in_scope`, `candidates` |
| `files_changed` | `:164-173` | `files_changed`, plus `modified` as the file list alone |
| `artifacts` | `:176-177` | `artifacts`, and `generated` as the same list |
| `notes` | `:105-107`, `:182` | stderr notes plus the document's `notes` |
| `sites_skipped` as a count | `:108-113` | one warning line |
| `plan.sites[].family` | `:119-122` | a tally map — **the only use the CLI makes of a planned site** |
| `plan.skipped[].reason` | `:123-126` | a reason tally |
| `outcome.revision` | `:103`, `:153` | the document's `revision` |
| `plan.sites[].locations` | **nowhere** | — |
| any `LocationId`, `primary`, `width`, or a site's `line_hint` | **nowhere** | — |

`text_lines` prints no site identifier at all, and where a reader would want one it sends
them to the store instead (`:187-293`). So the CLI needs from the plan two strings — one
per embedded site, one per refusal — which is exactly Appendix A's FFI-`yes` subset, and
M6 rebuilds all 29 printed keys from it with no id present.

The three readers that *do* name ids are store readers, not result consumers: `inspect
plan --format json` serializes the plan it loaded through `Store::read_plan`
(`swp-cli/src/inspect.rs:642-742`), `inspect manifest` prints the signed manifest's slots,
and `swp-sdk`'s own private-manifest read is module-private. That distinction is why §7 can
narrow a *result* without touching a *document*.
