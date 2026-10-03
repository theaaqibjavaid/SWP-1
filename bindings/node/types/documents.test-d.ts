// The document and option interfaces: which fields are required, which are
// absent-until-needed, and which are one of a stated list of words.
//
// Three properties a caller meets without noticing them otherwise.
//
// **Omission versus `null`.** A field that is `Option<T>` in Rust crosses inside
// a plain object as a key that is simply not there, so its type carries
// `undefined`; the same absence behind a getter on a bound class crosses as
// `null`. Both mean "none" and they are not interchangeable in a declaration:
// `summary.revision === undefined` is how a protect summary says no label was
// stated, and `outcome.revision === null` is how a verification document says it.
// Asserting each spelling keeps a future edit from tidying one into the other,
// which would silently break every caller that tested the field.
//
// **The closed key sets on the input shapes.** `ProtectOptions`, `VerifyOptions`,
// `Overrides`, `InitOptions` and `ReleaseSelection` are what a caller writes, and
// TypeScript refuses an extra key in an object literal. A declaration that
// advertised a knob the Rust side never reads would be a lie that compiles, so
// these sets are asserted as exhaustively as the runtime suite asserts the ones
// the SDK consumes.
//
// **Which vocabulary fields are unions.** `mode` and `kind` are accepted *as
// input*, so they are literal unions and a typo is a compile error. `verdict`,
// `status`, `fingerprint` and `strength` arrive as `string`, because a document
// written by an older build may carry a word this build would never write — and
// refusing to type that word would be refusing to read the file.

import type {
  Candidate,
  Capabilities,
  EvidenceItem,
  InitOptions,
  InitResult,
  Measurement,
  Overrides,
  ProtectOptions,
  ProtectedFile,
  ProtectedSite,
  ProtectSummary,
  RefusedSite,
  Region,
  ReleaseRecord,
  ReleaseSelection,
  ReleaseTally,
  ScannedSite,
  SiteRow,
  TagRange,
  VerifyOptions,
  VerifyOutcome
} from '../index'
import { Equals, expectTrue } from './assertions'

// -- the input shapes: closed key sets -------------------------------------

expectTrue<Equals<keyof ProtectOptions, 'mode' | 'releaseId' | 'revision'>>()
expectTrue<Equals<keyof VerifyOptions, 'release' | 'save' | 'rows'>>()
expectTrue<Equals<keyof InitOptions, 'name' | 'force'>>()
expectTrue<Equals<keyof ReleaseSelection, 'kind' | 'ids'>>()
expectTrue<Equals<keyof Overrides,
  'targets' | 'excludes' | 'targetSites' | 'tagBits' | 'embedStrings'
>>()

// `mode` is the one required input field on a protect run, and its three words
// are the whole of what a caller may ask for: a plan, a release, or a count of
// what a release would touch. Everything else on the shape is optional.
expectTrue<Equals<ProtectOptions['mode'], 'plan' | 'release' | 'dry-run'>>()
expectTrue<Equals<ProtectOptions['releaseId'], string | undefined>>()
expectTrue<Equals<ProtectOptions['revision'], string | undefined>>()
expectTrue<Equals<ReleaseSelection['kind'], 'all' | 'latest' | 'ids'>>()
expectTrue<Equals<ReleaseSelection['ids'], Array<string> | undefined>>()
expectTrue<Equals<VerifyOptions['rows'], number | undefined>>()
expectTrue<Equals<Overrides['embedStrings'], boolean | undefined>>()

// -- absence: `undefined` inside a document, `null` behind a getter --------

expectTrue<Equals<ProtectSummary['revision'], string | undefined>>()
expectTrue<Equals<ReleaseRecord['revision'], string | undefined>>()
expectTrue<Equals<ReleaseRecord['validationError'], string | undefined>>()
expectTrue<Equals<VerifyOutcome['revision'], string | null>>()
expectTrue<Equals<VerifyOutcome['reportSaved'], string | null>>()

// A scanned site that was not found simply has no location; the row keeps its
// `releaseId` and `site`, because those two are what joins it to a tally, and a
// `file` on the row would be a claim about where it was that the row cannot make.
expectTrue<Equals<keyof ScannedSite,
  | 'releaseId' | 'site' | 'status' | 'probes' | 'distinctCodes' | 'foundTokens'
  | 'foundIn' | 'foundLine' | 'foundExcerpt'
>>()
expectTrue<Equals<ScannedSite['foundIn'], string | undefined>>()
expectTrue<Equals<ScannedSite['foundLine'], number | undefined>>()
expectTrue<Equals<SiteRow['foundIn'], string | undefined>>()
expectTrue<Equals<Region['excerpt'], string | undefined>>()
expectTrue<Equals<Region['tokens'], number | undefined>>()
expectTrue<Equals<EvidenceItem['location'], Region | undefined>>()

// A verify row always names its file and always answers the confirmed question —
// those two are the document's own words, and `undefined` here would be an
// unfinished row rather than an absent field.
expectTrue<Equals<SiteRow['file'], string>>()
expectTrue<Equals<SiteRow['confirmed'], boolean>>()
expectTrue<Equals<SiteRow['slots'], Array<string>>>()

// -- the words a document uses ---------------------------------------------

expectTrue<Equals<ProtectSummary['mode'], 'plan' | 'release' | 'dry-run'>>()
expectTrue<Equals<VerifyOutcome['verdict'], string>>()
expectTrue<Equals<SiteRow['status'], string>>()
expectTrue<Equals<Candidate['kind'], string>>()
expectTrue<Equals<ReleaseTally['level'], string>>()
expectTrue<Equals<ReleaseTally['fingerprint'], string>>()
expectTrue<Equals<InitResult['secretState'], string>>()

// -- the numbers, as numbers ----------------------------------------------

// `chance`, `guarantee` and `coincidenceProbability` are the evidence ladder's
// own arithmetic and they cross as `number`: a caller that prints the bound
// beside the verdict is printing the measured value, not a formatted string the
// binding invented. Saturation is the exception worth naming — `foundTokens`
// caps at `255` rather than wrapping, and that is a field, not a type.
expectTrue<Equals<ReleaseTally['coincidenceProbability'], number>>()
expectTrue<Equals<ReleaseTally['chance'], number>>()
expectTrue<Equals<ScannedSite['foundTokens'], number>>()
expectTrue<Equals<ProtectedSite['width'], number>>()
expectTrue<Equals<ProtectedFile['bytesAfter'], number>>()
expectTrue<Equals<RefusedSite['lineHint'], number>>()
expectTrue<Equals<Candidate['partial'], boolean>>()

// The per-language and per-directory counts are records keyed by the name the
// SDK chose, in the SDK's own order: a `Map` would have been a second container
// to keep in step, and an index signature `Record<string, number>` is honest
// about what it is — counts, by name.
expectTrue<Equals<Measurement['languages'], Record<string, number>>>()
expectTrue<Equals<Measurement['tops'], Record<string, number>>>()

// The two ranges and the defaults are `Capabilities`' whole shape: a caller that
// branches on what this build can do reads exactly these nine names, and nothing
// in the list is a secret or a path.
expectTrue<Equals<keyof Capabilities,
  | 'protocol' | 'swpVersion' | 'reportSchema' | 'canonicalizerVersion'
  | 'languages' | 'languageNames' | 'tagBits' | 'targetSites' | 'defaults'
>>()
expectTrue<Equals<Capabilities['tagBits'], TagRange>>()

// A protect summary carries its three lists as arrays in the order the run
// produced them, and the length of the first two is stated by two scalars on the
// same document — the counts are the document's, not something a caller has to
// re-derive by summing a list.
expectTrue<Equals<ProtectSummary['filesChanged'], Array<ProtectedFile>>>()
expectTrue<Equals<ProtectSummary['sites'], Array<ProtectedSite>>>()
expectTrue<Equals<ProtectSummary['refusals'], Array<RefusedSite>>>()
expectTrue<Equals<ProtectSummary['artifacts'], Array<string>>>()
