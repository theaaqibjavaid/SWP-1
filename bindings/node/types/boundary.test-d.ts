// The refusals: calls that must not compile, checked by the compiler's own
// accounting.
//
// Every `@ts-expect-error` here is a two-way test. If the call becomes legal, the
// directive is unused and `tsc` fails; if the call becomes illegal for *another*
// reason, the line still shows an error and the test would pass for the wrong
// reason — which is why each line below is one short statement whose only
// possible error is the one named above it, and why argument positions go through
// a declared function rather than a variable that could be unused.
//
// Three families, in the order they matter.
//
// The **boundary of the surface**: `Session.protect` returns the plan the run
// wrote, and a plan's site identities are keyed under the project secret, so
// ADR-0001 settled that a foreign binding reads a summary instead. The names of
// the Rust types behind that decision — `Store`, `RootSecret`, `Plan`,
// `LocationId` — are not names in this package, and a caller should not be able
// to reach them even as types.
//
// The **shape of a call**: the mode words, the required fields, and the exact
// number of arguments, which is where a cancellation channel would have to be
// added. A promise that can be aborted and an operation that cannot are the same
// call until somebody writes `{ signal }` in a place that has no `signal`.
//
// The **read-only half**: the getters on a bound class are views onto a Rust
// document, so assigning through one would be writing to a value that has no
// place to be written.

import * as pkg from '../index'
import type { ProtectOptions, ProtectSummary, Report, ScanOutcome, Session, VerifyOutcome } from '../index'

declare const session: Session
declare const report: Report
declare const scanned: ScanOutcome
declare const verified: VerifyOutcome
declare const initOutcome: pkg.InitOutcome

/** The argument position of `mode`, so a wrong word is refused where it is written. */
declare function acceptsMode (mode: ProtectOptions['mode']): void

// -- what this package does not offer --------------------------------------

// `protect` is the plan-returning call, and the plan is the keyed constellation.
// `protectSummary` is the surface, and no spelling of the other one exists here.
// @ts-expect-error ADR-0001: a foreign binding reads the summary, never the plan.
void pkg.Session.protect
// @ts-expect-error the same refusal on an instance.
void session.protect

// The Rust-side types, named by nobody.
export type NotExported = [
  // @ts-expect-error the store handle is a Rust path and a lock, not a JS value.
  pkg.Store,
  // @ts-expect-error the root secret is drawn and sealed inside `init` and never crosses.
  pkg.RootSecret,
  // @ts-expect-error a plan document is keyed material; only its summary crosses.
  pkg.Plan,
  // @ts-expect-error a planned site's identity is a keyed address.
  pkg.PlannedSite,
  // @ts-expect-error `LocationId` is the keyed site id inside the manifest.
  pkg.LocationId,
  // @ts-expect-error the protection record is the private half of a release.
  pkg.Protection,
  // @ts-expect-error `ProtectOutcome` is the Rust return the summary replaces.
  pkg.ProtectOutcome,
  // @ts-expect-error opening the store is not an operation a binding gets.
  pkg.open_store
]

// -- the shape of a call ---------------------------------------------------

// @ts-expect-error `'apply'` is not one of the three modes; there is no fourth word.
acceptsMode('apply')
// @ts-expect-error a run is told a mode; nothing defaults it, because a silent default would pick a side effect.
acceptsMode()
// @ts-expect-error an option name the SDK does not read is refused at the literal, not ignored.
session.protectSummary({ mode: 'release', dryRun: true })
// @ts-expect-error `targets` is a list of paths, not a path.
void pkg.Session.open('some/project', { targets: 'src' })
// @ts-expect-error a release selection is one of three kinds, and `'newest'` is not one of them.
void session.releases({ kind: 'newest' })
// @ts-expect-error `readReport` takes the name it would list, not an index.
void session.readReport(3)
// @ts-expect-error `from` is required: discovering from nowhere would be guessing the caller's directory.
void pkg.Session.discover()

// There is nowhere to put a cancellation channel. `protectSummary` takes its one
// options object and `scan` takes three positional arguments, all of them
// documented above; a fourth, or a second object, is a compile error because a
// half-rewritten tree and a half-saved report are the outcomes a caller must not
// be able to reach by giving up early.
// @ts-expect-error no signal, no callback, no second argument — the run finishes.
void session.protectSummary({ mode: 'release' }, {})
// @ts-expect-error the same refusal on the scan.
void session.scan('some/dir', null, true, {})

// `verify` is synchronous: it hands back the document, not a promise of one. The
// error is the type-level statement of "this call throws rather than rejects",
// which is the fact a `catch` block is written against.
// @ts-expect-error a `VerifyOutcome` is a value, so there is nothing to chain onto it.
void session.verify().then

// -- the read-only half ----------------------------------------------------

// These are getters over a Rust document. The document's own fields — the plain
// objects in `documents.test-d.ts` — are writable, because they are copies the
// caller owns; a view onto the store is not.
// @ts-expect-error a view onto the project's directory cannot be reassigned.
session.projectRoot = 'other/dir'
// @ts-expect-error the schema tag is read off the document, not written into it.
report.schema = 'SWP-1-report-v3'
// @ts-expect-error a verdict is what the measurement said.
verified.verdict = 'INTACT'
// @ts-expect-error a session is opened, never installed afterwards.
initOutcome.session = session
// @ts-expect-error the per-site rows belong to the run that produced them.
scanned.sites = []

// And a positive control for every directive above: the copies a caller *does*
// own stay writable. Were the declarations to turn everything read-only, the
// refusals would still compile and this would be the line that notices.
function ownsACopy (summary: ProtectSummary): void {
  summary.mode = 'plan'
  summary.releaseId = 'swp1-release-example'
  summary.filesChanged = []
}
void ownsACopy
