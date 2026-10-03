# `jrs-swp` — the Node binding

A native addon over [`swp-sdk`](../../docs/SDK_ARCHITECTURE.md), built with
[napi-rs](https://napi.rs): one call into the same orchestration layer the CLI uses — the walk, the
safety preconditions, the cryptography, the detection, the evidence grading, the report arithmetic.
The binding adds a JavaScript object model, one error class and the libuv thread
discipline; it subtracts the terminal.

`jrs-swp` is the identifier this tree builds under. The published name is a release decision that
has not been made, so nothing here assumes one: `package.json`'s `name` is the only place the string
lives, and renaming the package is a metadata change rather than a code change.

**Every example below is a program, and every program ran.**
[`tests/readme.test.mjs`](tests/readme.test.mjs) reads this file, lifts each `js`, `mjs` and `ts`
fence out of it, and gives each one a directory of its own containing the tree declared just below,
a `node_modules/jrs-swp` link to this package and a freshly drawn root secret. The `text`
fence under a program is the transcript it printed. `…` stands for whatever this project's secret
influences — a release id, a byte total that moves with the width of the tag literal — and matches
the rest of a word or a run of words on its own; whitespace is insignificant. So a line with no `…`
is a number this build re-derives on every run: what `tag_bits` defaults to, how many sites this
tree can hold, what a scan of a copy of it says. The `sh` fences are the commands this package's
[job in `ci.yml`](../../.github/workflows/ci.yml) runs, in that order — the job puts
`cargo fmt --check` and `cargo clippy` between `npm ci` and the build, because the binding is its
own Cargo workspace and the repository's lint jobs never see it.

Every program runs in a directory holding this, and nothing else:

```tree
my-project/src/app.js
my-project/src/main.ts
```

## The four rules that shape this surface

* **Nothing keyed crosses the boundary.** `docs/BINDING_SURFACE.json` classifies the Rust surface,
  and this addon wraps exactly the items that file permits. The private plan, the keyed site
  identities, the root secret and the store handle are not on any JavaScript value, and they are not
  reachable by walking a property graph from one that is.
  [`tests/leakage.test.mjs`](tests/leakage.test.mjs) exercises that against a real protection run in
  both directions: every string a returned object can print is checked against the keyed identities
  the project's own store holds, and every field name a private document carries is checked against
  the summary's document form.
* **No unwind crosses the boundary.** Every operation runs inside
  [`capture`](src/error.rs), which turns a Rust panic into an ordinary
  [`INTERNAL_ERROR`](../../docs/TROUBLESHOOTING.md) `SwpError` rather than letting an unwind reach
  the interpreter — the code that means "a defect in SWP-1: report it", arriving as the same shape
  as every other failure. What a caller sees is one class — [`SwpError`](#errors) — and the code the
  branch should key on.
* **Nothing is cancellable.** `protectSummary` and `scan` return promises that settle exactly once
  and take no `AbortSignal`. A cancelled protection can leave a tree half-rewritten and a cancelled
  scan half-saved under `.swp/private/`; a promise that outlives its caller's patience is the
  designed outcome, not a bug to hand the caller.
* **Synchronous calls throw; the two asynchronous ones reject.** `open`, `discover`, `init`,
  `verify`, `releaseHistory` and the helpers raise, `protectSummary` and `scan` return a rejected
  promise. A `catch` around an `await` sees both kinds; a `.catch()` hung on `Session.open` is a
  handler that never runs.

## Open a project

`Session.init` is the one operation that creates a project, and the only place a root secret exists:
it is drawn, sealed by the operating system, and never returned. What comes back is *where* it went —
`secretScheme`, `secretState` and the 40-bit non-secret `secretHandle` on the result — which is the
whole of the disclosure.

```js
const swp = require('jrs-swp')

const outcome = swp.Session.init('my-project', { name: 'sample' })
const result = outcome.result

console.log(result.secretState)
console.log(result.preExisting)
console.log(result.gitignore)
console.log(result.measurement.files, result.measurement.bytes, result.measurement.languages.javascript)
console.log(result.settings.targets.join(' '), result.settings.targetSites, result.settings.suggestion)
console.log(result.created.join(' '))
console.log(String(outcome.session).startsWith('Session(projectRoot='))
console.log(outcome.session.identity.protocol, outcome.session.identity.displayName)
```

```text
created
false
created
2 411 1
src 4 4
.swp .swp/public .swp/private .swp/public/releases .swp/private/manifests .swp/private/plans .swp/private/reports .swp/private/root.key .swp/public/identity.json .swp/config.toml
true
SWP-1 sample
```

`secretScheme` is `'dpapi'` on Windows and `'plain'` everywhere else, and on Windows a
`SWP_SECRET_PLAIN=1` in the environment this process inherited selects `'plain'` too — which is the
reason the field is returned rather than derived: an embedded app can end up with an unsealed key
without having asked for one. `permissionsVerified` is `true` only when the access control on the
private half was set *and* confirmed by reading it back (`icacls` on Windows, mode `0600` on Unix),
and `permissionsDetail` is the text behind that answer; the read-back exists because
`std::fs::set_permissions` reports success on Windows while changing nothing. `swp init` prints the
permission pair, and the scheme is the field the SDK adds for a bound caller — the terminal user is
told the key was drawn, the embedding application is told how it is sealed. Re-running `init` on a
directory that already has a `.swp/`
is idempotent rather than an error: the existing identity and secret are kept (`preExisting` and
`secretState === 'kept'` say so), because SWP never replaces a project secret. Importing somebody
else's secret is not offered, in any language.

Opening a project that exists does not re-draw anything, and `discover` walks up from a file the way
`swp` does:

```js
const swp = require('jrs-swp')

swp.Session.init('my-project')
const session = swp.Session.open('my-project')
const tuned = swp.Session.open('my-project', { targetSites: 8, tagBits: swp.capabilities().tagBits.max })

console.log(session.config.protect.targets.join(' '))
console.log(session.config.protect.targetSites, session.config.protect.tagBits)
console.log(tuned.config.protect.targetSites, tuned.config.protect.tagBits)
console.log(tuned.storedConfig().protect.targetSites)
console.log(swp.Session.discover('my-project/src/app.js').identity.projectId === session.identity.projectId)
console.log(session.warnings.length)
```

```text
src
4 4
8 8
4
true
0
```

The `Overrides` argument changes what *this session's* runs do; `storedConfig()` is the file on disk
saying what it says. A config key this build ignores, a limit that had to be clamped and a stored
document that did not validate all arrive on `warnings` rather than being silently applied.

## Protect a tree

`protectSummary` is the only protection operation this binding offers. The Rust `protect` returns the
plan the run wrote, and that plan's site identities are keyed under the project secret;
[ADR-0001](../../docs/adr/0001-protect-generate-binding-boundary.md) settled that a foreign binding
reads the summary instead. What the summary carries is everything else: the run's arithmetic, its
artifacts, its refusal list, and — for a mode that writes no source — the predicted rewrite it would
have applied.

The three modes differ in one thing only: what they leave behind. A plan keys its constellation to a
release id and writes one private document; the release that applies it passes that id back, because
a different id derives different keys and silently makes a second release.

```mjs
import swp from 'jrs-swp'

const session = swp.Session.init('my-project').session

const plan = await session.protectSummary({ mode: 'plan' })
console.log(plan.mode)
console.log(plan.filesWalked, plan.sitesEmbedded, plan.sitesSkipped, plan.candidates)
console.log(plan.filesChanged.map((file) => `${file.file}=${file.sites}`).join(' '))
console.log(plan.refusalCounts.map((entry) => `${entry.reason}=${entry.count}`).join(' '))
console.log(plan.languages.join(' '), plan.tagBits, plan.targetSites)
console.log(plan.artifacts.length)

const published = await session.protectSummary({
  mode: 'release',
  releaseId: plan.releaseId,
  revision: 'build-7'
})
console.log(published.mode, published.releaseId === plan.releaseId)
console.log(published.revision, published.filesWithSites)
console.log(published.filesChanged.map((f) => `${f.file} ${f.bytesBefore}->${f.bytesAfter}`).join(' '))
console.log(published.sites.map((s) => `${s.file}:${s.lineHint} ${s.language} ${s.class}`).join(' '))
console.log(published.artifacts.filter((a) => !a.includes(published.releaseId)).join(' '))
```

```text
plan
2 2 1 3
src/app.js=1 src/main.ts=1
overlapping-radius=1
javascript typescript 4 4
1
release true
build-7 2
src/app.js 267->… src/main.ts 144->…
src/app.js:12 javascript integer src/main.ts:2 typescript integer
src/app.js src/main.ts
```

The `artifacts` list is in write order: the private manifest, the plan, the public release record,
then the source files the run rewrote. Every `.swp/` entry in it is store-relative and
forward-slashed, so a log line never reveals where the project lives.

A dry run leaves nothing anywhere — no plan, no manifest, no source:

```mjs
import { Session } from 'jrs-swp'
import { readFileSync } from 'node:fs'

const session = Session.init('my-project').session
const before = readFileSync('my-project/src/app.js', 'utf8')

const rehearsal = await session.protectSummary({ mode: 'dry-run' })
console.log(rehearsal.mode)
console.log(rehearsal.artifacts.length, rehearsal.filesChanged.length, rehearsal.sites.length)
console.log(readFileSync('my-project/src/app.js', 'utf8') === before)
console.log(session.releaseHistory().length, session.reports().length)
```

```text
dry-run
0 2 2
true
0 0
```

`filesChanged` is filled in for every mode; the `mode` word and `artifacts` are what tell the three
apart. A refusal is not a failure: it is a location the run could not mark without changing what the
program computes, and it is reported with its token and its count.

## Verify a copy

`verify` grades this project's own tree against one of its releases; the document is
`SWP-1-verify-v1` and it is built by the crate that grades it — nothing on this side decides a
verdict, compares a probability, or maps a result to an exit code.

```mjs
import swp from 'jrs-swp'

const session = swp.Session.init('my-project').session
const published = await session.protectSummary({ mode: 'release' })

const outcome = session.verify({ release: published.releaseId })
console.log(outcome.schema, outcome.protocol)
console.log(String(outcome))
console.log(outcome.verdict, outcome.exitCode, outcome.fingerprint)
console.log(outcome.sitesConfirmed, outcome.sitesExpected, outcome.sitesExact, outcome.sitesAbsent)
console.log(outcome.tagBits, outcome.confirmedBits, outcome.manifestAuthenticated)
console.log(outcome.revision, outcome.reportSaved, outcome.partial)
console.log(outcome.sites[0].file, outcome.sites[0].status, outcome.sites[0].confirmed)
console.log(outcome.sites[0].slots.join(' '))
console.log(JSON.parse(outcome.toJson()).sites.length === outcome.sites.length)

const record = session.releaseHistory()[0]
console.log(record.protocol, record.schema, record.fingerprintLevel)
console.log(record.validationError, record.revision === undefined)
console.log(session.releases({ kind: 'all' }).length, session.releaseHistory().length)
```

```text
SWP-1-verify-v1 SWP-1
VerifyOutcome(releaseId='rel-…', verdict='INTACT', sitesConfirmed=2/2)
INTACT 0 match
2 2 2 0
4 8 true
null null false
src/app.js exact-rendering true
statement+identifiers statement+names scope+identifiers scope+names
true
SWP-1 1 L1
undefined true
1 1
```

Two null spellings, and the difference is the shape they arrive on. A class getter that has nothing
to give returns `null` (`outcome.revision`, `outcome.reportSaved`), because the getter always exists
and its value is the absence. A field of a plain document object is *absent*
(`record.revision === undefined`, `record.validationError === undefined`), because the Rust
document does not carry the key. `to_dict()`-style presence checks on a document therefore ask
`in`, and a getter asks `=== null`.

`exitCode` is data on the outcome, and it is the verdict's own field rather than a code this side
picks: `0` `INTACT`, `5` `INCOMPLETE` (a site is not carrying its code and the tree was read
completely enough to say so), `10` `INCONCLUSIVE` (some site is not, and part of the tree was never
examined). It is the code a shell would have got, not an exception, and the binding maps nothing —
it forwards the document's field.

## Scan somebody else's artifact

`scan` looks for this project's provenance in a tree or archive it does not own. The candidate is a
path: one source file, a directory read in place, or a container — `zip` (which is also a wheel, a
`.jar`, a `.vsix` or an Office document), a plain `tar`, a `tar.gz`, or a gzipped single file. It is
described in the report by where it was, not by anything keyed.

```mjs
import swp from 'jrs-swp'
import { cpSync } from 'node:fs'

const session = swp.Session.init('my-project').session
await session.protectSummary({ mode: 'release' })

cpSync('my-project/src', 'staged/src', { recursive: true })

const outcome = await session.scan('staged', { kind: 'latest' }, true)
console.log(outcome.report.result, outcome.report.evidenceLevel)
console.log(outcome.report.exitCode())
console.log(outcome.report.run.command, outcome.report.candidate.kind)
console.log(outcome.report.releases[0].level, outcome.report.releases[0].fragments)
console.log(outcome.sites.map((s) => s.status).join(' '))
console.log(outcome.saved.path.startsWith('.swp/private/reports/'))
console.log(session.reports().length, session.readReport(outcome.saved.name).report.schema)
```

```text
PROVENANCE_DETECTED VERY_STRONG
1
scan directory
VERY_STRONG 2
exact-rendering exact-rendering
true
1 SWP-1-report-v2
```

The `releases` argument is a `ReleaseSelection` — `{ kind: 'all' }`, `{ kind: 'latest' }` or
`{ kind: 'ids', ids: [...] }`. Omit it and every release the project has is scanned, because picking
one silently would be an unstated claim about which.

`save: true` writes a copy of the `SWP-1-report-v2` document under `.swp/private/reports/`, which is
where it belongs: it names your source paths and the sites you protect, so it goes beside the secret
and not beside the release. `outcome.saved` is `null` unless you asked. `session.readReport(name)`
takes the name, the file name or the store-relative path — `reportStem()` is the normalisation, and
it is exported because the listing that shows a name is not where the path came from.

The report is the evidence ladder's document, and `chance` and `coincidenceProbability` travel with
the verdict rather than being summarised away:

```mjs
import swp from 'jrs-swp'
import { cpSync } from 'node:fs'

const session = swp.Session.init('my-project').session
await session.protectSummary({ mode: 'release' })

cpSync('my-project/src', 'staged/src', { recursive: true })

const outcome = await session.scan('staged')
const tally = outcome.report.releases[0]
console.log(outcome.report.explanation.length, tally.reasons.length)
console.log(outcome.report.limitations.length > 0)
console.log(typeof tally.chance, typeof tally.coincidenceProbability, tally.probes > 0)
console.log(outcome.report.toText().split('\n').length > 1)
console.log(outcome.report.toJson().includes('"coincidence_probability"'))
```

```text
2 2
true
number number true
true
true
```

## Errors

One class. A new failure mode needs an error code, the text a user reads, and a line in
[`docs/CLI.md`](../../docs/CLI.md) and [`docs/TROUBLESHOOTING.md`](../../docs/TROUBLESHOOTING.md) —
this class is the same contract on a library side, and a subclass per code is deliberately not
offered: codes are data, and a hierarchy would be a second taxonomy to keep in step with the Rust one.

```mjs
import swp from 'jrs-swp'

const session = swp.Session.init('my-project').session

try {
  swp.Session.open('my-project/src')
} catch (error) {
  console.log('thrown', error instanceof swp.SwpError, error.name, error.code)
  console.log('fields', error.path, error.causedBy, error.nextStep)
}

try {
  swp.Session.open('never-made')
} catch (error) {
  console.log('missing root', error.code)
}

try {
  await session.protectSummary({ mode: 'apply' })
} catch (error) {
  console.log('bad mode', error.code, swp.errorCodes().includes(error.code))
}

await session.protectSummary({ mode: 'release' })
try {
  await session.scan('never-there')
} catch (error) {
  console.log('rejected', error.code, error.message.includes('never-there'), error.path)
}
```

```text
thrown true SwpError NOT_PROTECTED
fields null null Run `swp init` then `swp protect` in the project first.
missing root PATH_REJECTED
bad mode USAGE true
rejected IO_ERROR true null
```

Branch on `code`, never on the message; `swp.errorCodes()` is the table the branch can check itself
against — the same 17 codes the CLI exits with, spelled the same way. `path` is set when the failure
means a store entry (store-relative, forward-slashed) and `causedBy` when the Rust error carried a
lower-level cause to give; both are `null` rather than absent, so reading an envelope never depends
on a key existing.
`rendered` is the whole block a terminal user would have read, kept so a foreign process can print it
verbatim instead of composing its own.

What is deliberately *not* on `SwpError` is an exit code: `swp`'s contract with a shell is not a
library caller's. The two numbers that do reach JavaScript are a `Report`'s and a `VerifyOutcome`'s,
and there they are fields of a document.

## TypeScript

The package's `types` entry is [`index.d.ts`](index.d.ts), hand-written; the `binding.d.ts` beside it
is generated from the Rust signatures by every build. The declaration list is checked by compiling:
[`types/*.test-d.ts`](types/) runs under `tsc --noEmit`, and
[`tests/surface.test.mjs`](tests/surface.test.mjs) compares those declarations against the names the
loader actually re-exports, in both directions.

```ts
import { Session, SwpError, type ProtectSummary, type VerifyOutcome } from 'jrs-swp'

export async function protectRelease (root: string, revision: string): Promise<ProtectSummary> {
  const session = Session.init(root, { name: 'sample' }).session
  return await session.protectSummary({ mode: 'release', revision })
}

export function isNotProtected (error: unknown): error is SwpError {
  return error instanceof SwpError && error.code === 'NOT_PROTECTED'
}

export function confirmLatest (session: Session): VerifyOutcome {
  return session.verify()
}
```

Nothing here re-speaks a protocol fact as a type: `ProtectOptions.mode` is the three modes and no
fourth, `Capabilities` carries the ranges this build claims, and a refused name — `Store`,
`RootSecret`, `Plan`, `LocationId`, `protect` — is not declared, so `tsc` is the first place a caller
learns it does not exist.

## Asynchronous calls and the thread pool

`protectSummary` and `scan` run on libuv's worker pool: the walk, the cryptography and the detection
all happen off the main thread, so an application's event loop keeps turning through a protection
run. The completion always fires, exactly once, on the main thread — including for a run whose
caller has stopped waiting.

```mjs
import swp from 'jrs-swp'

const session = swp.Session.init('my-project').session

const summaries = await Promise.all([
  session.protectSummary({ mode: 'plan' }),
  session.protectSummary({ mode: 'plan' })
])
console.log(summaries.map((s) => s.mode).join(' '))
console.log(summaries[0].releaseId === summaries[1].releaseId)
console.log(session.releaseHistory().length)
```

```text
plan plan
false
0
```

Two concurrent calls on one session are two runs, and they resolve the way two shells would: each
allocates its own release id rather than sharing the other's constellation, and a plan publishes
nothing, so the public history is still empty afterwards. What they do *not* do is interleave with a
release run: `protectSummary({ mode: 'release' })` twice for one id is the one pair that cannot both
succeed, and the second arrives as `USAGE` saying which record already exists. `verify`, `open` and
the rest are synchronous and cheap by comparison — they read documents this session already holds.

## The module helpers

Five functions need no session — `banner`, `capabilities`, `errorCodes`, `reportStem` and
`suggestSites` — and `capabilities()` touches nothing at all: no filesystem, no project, no secret. It
cannot fail.

```js
const swp = require('jrs-swp')

console.log(swp.SWP_VERSION)
console.log(swp.BINDING_VERSION)
console.log(swp.banner())

const caps = swp.capabilities()
console.log(caps.protocol, caps.reportSchema, caps.canonicalizerVersion)
console.log(caps.languageNames.join(' '))
console.log(caps.tagBits.min, caps.tagBits.default, caps.tagBits.max)
console.log(caps.targetSites.min, caps.targetSites.default, caps.targetSites.max)
console.log(swp.suggestSites(128))
console.log(swp.reportStem('scan-2026-09-30T14-18-00Z.json'))
console.log(swp.errorCodes().length)
```

```text
1.0.0-beta.4
0.1.0
SWP-1 · swp 1.0.0-beta.4 · report schema SWP-1-report-v2
SWP-1 SWP-1-report-v2 1
javascript typescript python
2 4 8
4 16 4096
32
scan-2026-09-30T14-18-00Z
17
```

`suggestSites` is the §9 ladder `init` consults, `banner()` is what `swp --version` prints, and the
two versions are two numbers with two lifecycles: the tool this addon drives, and the addon itself.

## Paths, and what they look like

The binding hands a path to Rust exactly once — no re-anchoring, no normalisation, no second
`resolve` — and describes a project by where it was, not by anything keyed. Three spellings are
deliberately different, and `tests/paths.test.mjs` pins each:

| What | Spelling | Why |
| --- | --- | --- |
| `Session.projectRoot` | the store's canonical path: `\\?\C:\Users\…\my-project` on Windows, `/home/…/my-project` elsewhere | it is what the store holds, so two sessions opened through different paths still compare equal |
| `VerifyOutcome.tree`, `ReleaseRecord`, `candidate.described`, the names in `filesChanged` and `artifacts` | what the caller said, or the ordinary project-relative form | a record of a run, not a live handle |
| every `.swp/…` path (`artifacts`, `SavedReport.path`, `InitResult.created`, `SwpError.path`) | store-relative, forward-slashed | safe to print, and it does not reveal where the project lives |

A Rust error's message may quote a native path with backslashes on Windows — it is the SDK's own
sentence, forwarded. The fields are the stable place to read a path from; `message` is for a human.
Because Windows' extended-length prefix is not valid in a `file://` URL or a POSIX path, print
`projectRoot` only where a Windows path is expected, or use the project-relative fields.

## Compatibility

| | |
| --- | --- |
| Node.js | `^20.17.0 \|\| ^22.13.0 \|\| >=23.5.0` — one range, because the addon is Node-API rather than V8 ABI |
| Platforms | `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Module systems | CommonJS (`require`) and ES modules (`import`, default and named) — both executed by the suite |
| TypeScript | the package's own `index.d.ts`; `strict` and `noUnusedLocals` are what the declaration tests are written against |
| libc | glibc on Linux; the loader detects musl and looks for the `-musl` artifact, which this tree does not build |

`engines` in `package.json` states the Node range, and the CI job runs the suite on the floor of it
rather than on a runner default. The addon is compiled against Node-API 4 — the version the deferred
promises `protectSummary` and `scan` are built on — and resolves its Node-API entries from the host
process at load time, which is what lets one binary serve every release in that range. Outside it,
the loader's failure names the artifact it tried.

## The published contract

[`docs/VERSIONING_POLICY.md`](../../docs/VERSIONING_POLICY.md) §5 asks a binding release
to state five things in one table, and §2 says the last three are read out of the build
rather than typed from memory. The row below is what the addon built from this tree
reports — `swp.BINDING_VERSION`, `swp.SWP_VERSION`, `swp.capabilities().protocol` and
`.reportSchema` — so it describes an artefact rather than a version number that looks
close enough:

| binding version | swp / swp-sdk version | protocol | reads report schema | writes report schema |
| --- | --- | --- | --- | --- |
| `0.1.0` | `1.0.0-beta.4` | `SWP-1` | `SWP-1-report-v2` | `SWP-1-report-v2` |

The two report columns match because one `swp-evidence` reader sits behind both
directions: the `schema` field inside a saved document is what a read checks, and a
mismatch rejects with `PROTOCOL_VERSION_UNSUPPORTED` — exit code 6 in the CLI, and the
same `code` on the `SwpError` here. They are two columns because they can come apart in
a future build; this is the current pair.

`0.1.0` is this package's own SemVer under §2: it moves when the surface this package
exposes moves (`PATCH` for a fix, `MINOR` for an added operation or field, `MAJOR` for a
removal), independently of the workspace version beside it, and `1.0.0-beta.4 → 1.0.0`
would say nothing about the protocol. No release of this package is on the registry, so
there is no released row to add to `CHANGELOG.md` yet — that entry belongs to the
release commit — and the name it is published under, `jrs-swp` in `package.json`, is
still an open release decision recorded in
[issue #32](https://github.com/theaaqibjavaid/SWP-1/issues/32).

## Building and installing

The addon is a `cdylib` in its own Cargo workspace, outside the root `members = ["crates/*"]` — the
placement [`docs/SDK_ARCHITECTURE.md`](../../docs/SDK_ARCHITECTURE.md) records for `bindings/*`: a
binding needs a newer Rust than the `rust-version = "1.85"` the published crates advertise, and its
build must not be able to break `cargo test --workspace`.

```sh
cd bindings/node
npm ci
npm run build          # napi build --platform --release --js binding.cjs --dts binding.d.ts
npm test               # node --test, over the built addon
npm run typecheck      # tsc --noEmit over types/*.test-d.ts
```

`npm run build` runs `napi build`, which has no way to pass `--locked` through to the Cargo it
invokes, so CI runs `cargo build --release --locked -j 2` in this directory first and lets
`napi build` reuse the artifact and only name it for this platform. `node --test tests/` is not the
same command as `node --test`: the runner does not expand a directory argument, it tries to *run* it,
and dies with `Cannot find module …\bindings\node\tests`. The no-argument form is the one that walks
the package for `*.test.mjs`, so it is the one `package.json` names.

Installing the built package into an application is a `file:` install of this directory, or a built
tarball:

```sh
npm pack --pack-destination "${TMPDIR:-/tmp}"
npm install "${TMPDIR:-/tmp}/jrs-swp-0.1.0.tgz"
```

`files` in `package.json` is `index.js`, `binding.cjs`, `binding.d.ts`, `index.d.ts`, `README.md` and
the built `.node`. Publishing for all four platforms the conventional way means the napi triplet
packages (`jrs-swp-windows-x64-msvc`, `jrs-swp-linux-x64-gnu`, …) and an `optionalDependencies` map
pointing at them; the loader already walks that chain and falls back to the bundled artifact. Those
package names are part of the publication decision the note at the top of this page refers to, so
this tree builds and ships one platform's addon and states the rest rather than inventing four names
now.

## What this page does not cover

The binding is a transport over `swp-sdk`, and a decision this binding re-states in JavaScript is a
second implementation of it. So: nothing here re-derives a tag, a location id, a coincidence
probability, a verdict or an exit-code mapping. Where a value is shown above, it was read off the
Rust document that decided it. The protocol's full surface — including the CLI's own `swp protect`,
`swp verify` and `swp scan` — is documented at [`docs/`](../../docs/); the boundary this binding
keeps is documented at [`docs/BINDING_SURFACE.json`](../../docs/BINDING_SURFACE.json) and
[ADR-0001](../../docs/adr/0001-protect-generate-binding-boundary.md).
