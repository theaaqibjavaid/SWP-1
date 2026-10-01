// The names a TypeScript caller may import, checked as a closed set.
//
// `tests/surface.test.mjs` holds the runtime half of this promise: it compares
// `index.js` against the loaded addon and fails if a name reaches the binary
// without reaching the entry point. This file is the compile-time half, and it
// is the one that decides what an editor offers — the list a caller autocompletes
// from is exactly the list asserted here, and adding an export to the loader
// without adding it below breaks the build rather than shipping a name only the
// runtime test knows about.
//
// `keyof typeof pkg` covers the *value* exports: the classes, the functions and
// the two version strings. The interfaces and unions re-exported as types are
// not values, so they cannot appear in a `keyof`; they are checked where they
// carry information — in `documents.test-d.ts`, against their fields.

import * as pkg from '../index'
import type { SwpError } from '../index'
import { Equals, expectTrue } from './assertions'

/** Every name the entry point re-exports, and no more than that. */
expectTrue<Equals<keyof typeof pkg,
  | 'BINDING_VERSION'
  | 'InitOutcome'
  | 'Report'
  | 'SWP_VERSION'
  | 'ScanOutcome'
  | 'Session'
  | 'StoredReport'
  | 'SwpError'
  | 'VerifyOutcome'
  | 'banner'
  | 'capabilities'
  | 'errorCodes'
  | 'reportStem'
  | 'suggestSites'
>>()

// The module-level functions, each with the exact argument list a caller has to
// write. `capabilities` and `banner` take nothing at all: they touch no
// filesystem and cannot fail, so a parameter would imply a choice that does not
// exist, and an error path that does not.
expectTrue<Equals<typeof pkg.banner, () => string>>()
expectTrue<Equals<typeof pkg.capabilities, () => pkg.Capabilities>>()
expectTrue<Equals<typeof pkg.errorCodes, () => Array<string>>>()
expectTrue<Equals<typeof pkg.reportStem, (what: string) => string>>()
expectTrue<Equals<typeof pkg.suggestSites, (files: number) => number>>()

// The versions are `string`, not literal types. A build number that was baked
// into the declarations would be a second copy of a number that `--version`
// prints, and the two would disagree the first time somebody rebuilt.
expectTrue<Equals<typeof pkg.SWP_VERSION, string>>()
expectTrue<Equals<typeof pkg.BINDING_VERSION, string>>()

// Classes are values *and* types: `new` is not offered for any of them (see
// `boundary.test-d.ts`), so what a caller uses is the instance type. That the
// class object and the instance type are the same declaration is what lets
// `catch (error)` narrow to `SwpError` with one import.
expectTrue<Equals<InstanceType<typeof pkg.SwpError>, SwpError>>()
expectTrue<Equals<ReturnType<typeof pkg.Session.open>, pkg.Session>>()
expectTrue<Equals<ReturnType<typeof pkg.Session.discover>, pkg.Session>>()
expectTrue<Equals<ReturnType<typeof pkg.Session.init>, pkg.InitOutcome>>()

// An `import * as` namespace is not a module: the entry point has no default
// export, because a default would be a second, quieter spelling of the same
// surface for an ESM caller while being invisible to `cjs-module-lexer`.
expectTrue<Equals<'default' extends keyof typeof pkg ? true : false, false>>()
