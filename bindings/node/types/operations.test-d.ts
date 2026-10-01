// The operations, typed the way they behave: which calls hand back a value and
// which hand back a promise, and how many arguments each one takes.
//
// Two properties live here that a caller cannot see in any other way.
//
// The first is the shape of the async surface. `protectSummary` and `scan` are
// the only two operations that return a promise, so they are the only two that
// can *reject*; everything else throws. The types say "this one is awaited",
// and only the runtime says where the error arrives, so the rule is written into
// `index.d.ts` and checked here as a fact about each return type: a future
// change that quietly makes `verify` asynchronous would show up as this file
// refusing to compile, which is the earliest moment anybody would notice.
//
// The second is the absence of cancellation. Each operation's argument list is
// asserted at its exact length, because an options object that grew a `signal`
// would look like a small ergonomic addition and would in fact be a new way to
// abandon a half-rewritten tree or a half-saved report. The length is the
// compile-time statement that there is nowhere to put one.

import type {
  InitOptions,
  InitOutcome,
  InitResult,
  Overrides,
  ProtectOptions,
  ProtectSummary,
  Report,
  ReleaseSelection,
  ScanOutcome,
  Session,
  SiteRow,
  SwpConfig,
  StoredReport,
  VerifyOptions,
  VerifyOutcome,
  Limits,
  ProjectIdentity,
  ReleaseRecord,
  SavedReport,
  ScannedSite
} from '../index'
import { Equals, expectTrue } from './assertions'

// -- the promise boundary ---------------------------------------------------

expectTrue<Equals<ReturnType<Session['protectSummary']>, Promise<ProtectSummary>>>()
expectTrue<Equals<ReturnType<Session['scan']>, Promise<ScanOutcome>>>()
expectTrue<Equals<ReturnType<Session['verify']>, VerifyOutcome>>()
expectTrue<Equals<ReturnType<Session['storedConfig']>, SwpConfig>>()
expectTrue<Equals<ReturnType<Session['readReport']>, StoredReport>>()

// Awaits settle to the documents themselves, not to a wrapper a caller has to
// unwrap: `Awaited` is the type a caller actually holds after the `await`.
expectTrue<Equals<Awaited<ReturnType<Session['scan']>>, ScanOutcome>>()
expectTrue<Equals<Awaited<ReturnType<Session['protectSummary']>>, ProtectSummary>>()

// Exactly one argument: the run's settings. There is no second position for a
// cancellation channel, and `boundary.test-d.ts` refuses a call that tries one.
expectTrue<Equals<Parameters<Session['protectSummary']>['length'], 1>>()
expectTrue<Equals<Parameters<Session['protectSummary']>[0], ProtectOptions>>()

// Three, and the last two are the optional scalars rather than an options
// object: `undefined` and `null` both mean "the build's own default", which is
// what napi-rs generates for an optional argument and what the loader accepts.
expectTrue<Equals<Parameters<Session['scan']>['length'], 1 | 2 | 3>>()
expectTrue<Equals<Parameters<Session['scan']>[0], string>>()
expectTrue<Equals<Parameters<Session['scan']>[1], ReleaseSelection | undefined | null>>()
expectTrue<Equals<Parameters<Session['scan']>[2], boolean | undefined | null>>()

// The synchronous operations take their options the same way: one optional
// argument, no overloads, and no positional argument a caller can mis-order.
expectTrue<Equals<Parameters<Session['verify']>[0], VerifyOptions | undefined | null>>()
expectTrue<Equals<Parameters<typeof Session.open>['length'], 1 | 2>>()
expectTrue<Equals<Parameters<typeof Session.open>[1], Overrides | undefined | null>>()
expectTrue<Equals<Parameters<typeof Session.discover>[1], Overrides | undefined | null>>()
expectTrue<Equals<Parameters<typeof Session.init>[1], InitOptions | undefined | null>>()

// `releases` and `oneRelease` have no default selection. Omitting a release in
// the CLI means "every release the project has", and a binding that quietly
// defaulted to the newest would be an unstated claim about which one was
// checked — so the parameter is required, and these two lines are what makes
// the difference visible in the declarations.
expectTrue<Equals<Parameters<Session['releases']>['length'], 1>>()
expectTrue<Equals<Parameters<Session['oneRelease']>['length'], 1>>()
expectTrue<Equals<Parameters<Session['release']>[0], string>>()
expectTrue<Equals<Parameters<Session['readReport']>[0], string>>()

// -- what each operation returns -------------------------------------------

expectTrue<Equals<ReturnType<Session['releases']>, Array<string>>>()
expectTrue<Equals<ReturnType<Session['oneRelease']>, string>>()
expectTrue<Equals<ReturnType<Session['releaseHistory']>, Array<ReleaseRecord>>>()
expectTrue<Equals<ReturnType<Session['release']>, ReleaseRecord>>()
expectTrue<Equals<ReturnType<Session['reports']>, Array<string>>>()
expectTrue<Equals<Session['warnings'], Array<string>>>()

// An outcome object is reachable through its getters, and the getter is the only
// route: `InitOutcome` gives the session and the record of the run, `ScanOutcome`
// the document and the save, `StoredReport` the document plus its name and path.
expectTrue<Equals<InitOutcome['session'], Session>>()
expectTrue<Equals<InitOutcome['result'], InitResult>>()
expectTrue<Equals<ScanOutcome['report'], Report>>()
expectTrue<Equals<ScanOutcome['sites'], Array<ScannedSite>>>()
// `null` rather than an absent key, because this is a class getter and not a
// document field: `x.saved !== null` is the whole test a caller needs.
expectTrue<Equals<ScanOutcome['saved'], SavedReport | null>>()
expectTrue<Equals<StoredReport['report'], Report>>()
expectTrue<Equals<VerifyOutcome['sites'], Array<SiteRow>>>()
expectTrue<Equals<Session['projectRoot'], string>>()
expectTrue<Equals<Session['limits'], Limits>>()
expectTrue<Equals<Session['identity'], ProjectIdentity>>()
expectTrue<Equals<Session['config'], SwpConfig>>()

// A document renders three ways and the renderings are methods, not properties:
// `toJson` is the saved bytes, `toText` is what a terminal shows, and both are
// strings — the field that is a number is `exitCode()`, which is a call at the
// boundary and a *field* on `VerifyOutcome`, exactly as the two documents differ.
expectTrue<Equals<Report['exitCode'], () => number>>()
expectTrue<Equals<Report['toText'], (full?: boolean | undefined | null) => string>>()
expectTrue<Equals<Report['toTextItems'], (items: number) => string>>()
expectTrue<Equals<Report['toJson'], () => string>>()
expectTrue<Equals<VerifyOutcome['exitCode'], number>>()
expectTrue<Equals<ReturnType<typeof Report.fromJson>, Report>>()

// Every operation prints one line and no more: `toString` is the only rendering
// a bound class offers besides its document methods, which is what keeps a
// `console.log` of a session from dumping a project's paths twice.
expectTrue<Equals<Session['toString'], () => string>>()
expectTrue<Equals<ScanOutcome['toString'], () => string>>()
expectTrue<Equals<VerifyOutcome['toString'], () => string>>()
