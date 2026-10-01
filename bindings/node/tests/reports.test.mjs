// The `SWP-1-report-v2` document, and the copies of it the store keeps.
//
// `swp-evidence` owns this document: it grades a detection run, states the
// evidence level with the numbers that produced it, and carries the §51 boundary
// inside the file. So these cases are about *reading* it faithfully:
//
// * every getter returns the document's own field, and `toJson()` is the
//   serialization the schema defines — not a rendering of a copy;
// * `Report.fromJson()` gives back the same document, and refuses one it was not
//   written under rather than re-grading it;
// * `toText()` is the same text `swp scan` prints, and windowing only shortens
//   the printout, never the data;
// * a saved report is the same bytes, reachable by every spelling of its name.
//
// Nothing here grades evidence or compares a probability against a floor: the
// numbers below are asserted *against each other*, so a binding that recomputed
// one would be caught by the relation rather than by a constant.
//
// Where this diverges from the Python suite the reason is Node's. `Report` and
// `StoredReport` hold the Rust document, so they expose prototype getters and
// carry no own properties: the inventory a test can read is the class prototype
// plus `toJson()`, and `JSON.stringify` of an instance is `{}`. The blocks
// inside it — `run`, `candidate`, the tallies, the evidence items, the regions —
// are plain objects, and an absent optional field is *omitted from the key set*
// rather than present and `null`. `toString()` stands in for the Python
// `__repr__`, and a document cannot be built from JavaScript at all, because
// napi gives the class no constructor.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { Report, StoredReport, SWP_VERSION, SwpError, capabilities, errorCodes, reportStem } from '../index.js'
import { SOURCE_TREE, foreignTree, isForwardSlashed, makeProtected, purgeAll, stageArtifact, tempRoot } from './helpers.mjs'

after(purgeAll)

const RESULTS = new Set(['PROVENANCE_DETECTED', 'NO_PROVENANCE_DETECTED', 'INCONCLUSIVE'])
/** The §23 ladder, weakest first, so its index is comparable. */
const LEVELS = ['NONE', 'WEAK', 'MODERATE', 'STRONG', 'VERY_STRONG']
const KINDS = new Set([
  'EXACT_SOURCE_MATCH',
  'WATERMARK_FRAGMENT_MATCH',
  'PARTIAL_WATERMARK_MATCH',
  'CANONICAL_MATCH',
  'STRUCTURAL_MATCH',
  'TOKEN_MATCH',
  'NEGATIVE_CONTROL'
])

/** Every field the schema defines, with the getter that reads it. */
const DOCUMENT_FIELDS = new Map([
  ['schema', 'schema'],
  ['protocol', 'protocol'],
  ['run', 'run'],
  ['candidate', 'candidate'],
  ['result', 'result'],
  ['evidence_level', 'evidenceLevel'],
  ['explanation', 'explanation'],
  ['releases', 'releases'],
  ['evidence', 'evidence'],
  ['omissions', 'omissions'],
  ['notes', 'notes'],
  ['limitations', 'limitations']
])

/** The 23 fields of one release's tally, as the getter spells them. */
const TALLY_KEYS = [
  'projectId',
  'releaseId',
  'sites',
  'fragments',
  'stripped',
  'absent',
  'exactRenderings',
  'canonicalOnly',
  'moved',
  'renderings',
  'files',
  'bits',
  'tagBits',
  'probes',
  'draws',
  'literalsTried',
  'windowsTried',
  'fingerprint',
  'chance',
  'guarantee',
  'coincidenceProbability',
  'level',
  'reasons'
]

/** The eight fields every evidence item carries. */
const EVIDENCE_ALWAYS_KEYS = ['id', 'kind', 'projectId', 'releaseId', 'basis', 'strength', 'protocol', 'schema']

/** The three fields every region carries; the other two are candidate-side only. */
const REGION_ALWAYS_KEYS = ['file', 'line', 'radii']

const SLOTS = new Set(['statement+identifiers', 'statement+names', 'scope+identifiers', 'scope+names'])

/** Field names that belong to the private plan and manifest, never to a report. */
const PRIVATE_NAMES = ['locations', 'fragment_tag', 'expected_tag', 'root_secret', 'grammar_path', 'root.key']

const keys = (value) => Object.keys(value).sort()
const close = (actual, expected, epsilon = 1e-9) => Math.abs(actual - expected) <= epsilon
const rank = (level) => LEVELS.indexOf(level)

/** A stored document's block, in the spelling the getters use for it. */
function renamed (value) {
  if (Array.isArray(value)) return value.map(renamed)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([name, nested]) => [name.replace(/_([a-z])/g, (_match, letter) => letter.toUpperCase()), renamed(nested)])
    )
  }
  return value
}

/** A scan of a copy of the protected sources, with its document saved. */
async function graded (label = 'report') {
  const project = await makeProtected(`reports-${label}`)
  const staged = stageArtifact(project, label)
  const outcome = await project.scan(staged, { save: true })
  return { project, outcome, report: outcome.report }
}

test('the document is the schema this build writes', async () => {
  const { report } = await graded('schema')
  assert.equal(report.schema, 'SWP-1-report-v2')
  assert.equal(report.protocol, 'SWP-1')
  assert.equal(report.schema, capabilities().reportSchema)
  assert.ok(report instanceof Report)
})

test('every getter returns the document it is standing in', async () => {
  const { report } = await graded('fields')
  const document = JSON.parse(report.toJson())
  assert.deepEqual(keys(document), [...DOCUMENT_FIELDS.keys()].sort())
  // The document keeps the schema's snake_case; the getters speak JavaScript.
  for (const [field, getter] of DOCUMENT_FIELDS) {
    assert.deepEqual(report[getter], renamed(document[field]), getter)
  }
  // The object has no own properties at all, which is why `toJson()` is the
  // machine-readable form and `JSON.stringify` is not.
  assert.deepEqual(Object.getOwnPropertyNames(report), [])
  assert.deepEqual(JSON.parse(JSON.stringify(report)), {})
  // A returned array is a fresh projection, so a caller cannot push the document
  // out of shape.
  const items = report.evidence
  items.push(items[0])
  assert.equal(report.evidence.length, items.length - 1)
})

test('the run block says who wrote the document', async () => {
  const { report } = await graded('run')
  const run = report.run
  assert.equal(run.command, 'scan')
  // RFC 3339 UTC to the second: the store keeps no sub-second stamps, and a
  // report whose clock drifted out of UTC would sort wrong against its siblings.
  assert.match(run.createdAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, run.createdAt)
  assert.equal(Number.isNaN(Date.parse(run.createdAt)), false)
  // The generator string is how an old report says which rules produced it.
  assert.ok(run.generator.includes(SWP_VERSION), run.generator)
  assert.ok(run.generator.includes(report.schema), run.generator)
  assert.deepEqual(keys(run), ['command', 'createdAt', 'generator'])
})

test('the candidate block describes the input', async () => {
  const { report, outcome } = await graded('candidate')
  const candidate = report.candidate
  assert.equal(candidate.kind, 'directory')
  assert.equal(candidate.filesScanned, Object.keys(SOURCE_TREE).length)
  assert.ok(candidate.bytesScanned > 0)
  assert.equal(candidate.partial, false)
  assert.deepEqual(keys(candidate), ['bytesScanned', 'described', 'filesScanned', 'kind', 'partial'])
  // The rows and the candidate are two views of one walk.
  assert.deepEqual(new Set(outcome.sites.map((row) => row.foundIn.split('/')[0])), new Set(['src']))
})

test('one tally per release, strongest first', async () => {
  const { report } = await graded('tally')
  assert.equal(report.releases.length, 1)
  const tally = report.releases[0]
  assert.deepEqual(keys(tally), [...TALLY_KEYS].sort())
  assert.equal(tally.sites, tally.fragments + tally.stripped + tally.absent)
  assert.ok(tally.exactRenderings <= tally.fragments)
  assert.equal(tally.canonicalOnly, tally.fragments - tally.exactRenderings)
  assert.ok(tally.files >= 1 && tally.files <= Object.keys(SOURCE_TREE).length)
  assert.ok(tally.fragments > 0)
  const bounds = capabilities().tagBits
  assert.ok(bounds.min <= tally.tagBits && tally.tagBits <= bounds.max)
  assert.equal(tally.bits, tally.fragments * tally.tagBits)
  // The level is one of the ladder's rungs, and the reasons are the document's.
  assert.ok(LEVELS.includes(tally.level))
  assert.deepEqual(tally.reasons, report.explanation)
  assert.ok(tally.reasons.every((sentence) => sentence.trim().length > 0))
  JSON.parse(JSON.stringify(tally))
})

test('the coincidence numbers are the document’s own arithmetic', async () => {
  // Asserted as relations between the document's fields: a binding that invented
  // any one of them would break at least one, and nothing here repeats the
  // arithmetic.
  const { report } = await graded('coincidence')
  const tally = report.releases[0]
  assert.ok(tally.chance >= 0)
  assert.ok(tally.coincidenceProbability >= 0 && tally.coincidenceProbability <= 1)
  assert.ok(close(tally.guarantee, tally.fragments - tally.chance), `${tally.guarantee} vs ${tally.fragments - tally.chance}`)
  if (tally.fragments > 0) {
    assert.ok(tally.draws >= 1)
    assert.ok(tally.tagBits > 0 && tally.tagBits <= 32)
  }
  // A finding is graded by the tail probability *or* by the tree fingerprint, and
  // which of the two fired is the document's business: this case only reads the
  // numbers, so it asserts no floor of its own.
  if (tally.level === 'NONE') {
    assert.equal(tally.fragments, 0)
  } else {
    assert.ok(tally.fragments >= 1)
  }
})

test('the evidence items are citable', async () => {
  const { report } = await graded('evidence')
  const items = report.evidence
  assert.ok(items.length > 0, 'a detection document that cites nothing cites nothing')
  assert.deepEqual(items.map((item) => item.id), items.map((_, index) => `EV-${String(index).padStart(3, '0')}`))
  for (const item of items) {
    assert.ok(EVIDENCE_ALWAYS_KEYS.every((name) => item[name] !== undefined), item.id)
    assert.deepEqual(keys(item).filter((k) => EVIDENCE_ALWAYS_KEYS.includes(k)), [...EVIDENCE_ALWAYS_KEYS].sort())
    assert.ok(KINDS.has(item.kind), item.kind)
    assert.ok(LEVELS.includes(item.strength), item.strength)
    assert.ok(rank(item.strength) <= rank(report.evidenceLevel), `${item.id} is stronger than the verdict`)
    assert.equal(item.protocol, 'SWP-1')
    assert.equal(item.schema, 2, 'the report schema the document is written under')
    assert.ok(item.basis.trim().length > 0)
    for (const region of [item.location, item.sourceRegion]) {
      if (region === undefined) continue
      assert.ok(REGION_ALWAYS_KEYS.every((name) => region[name] !== undefined))
      assert.ok(region.file.startsWith('src/'))
      assert.ok(region.line >= 1)
      assert.ok(region.tokens === undefined || region.tokens >= 1)
      assert.ok(region.radii.every((slot) => SLOTS.has(slot)), region.radii.join(','))
    }
    // A source-side region is where we protected; it quotes nothing from the
    // candidate, so it carries no excerpt and no token count.
    if (item.sourceRegion !== undefined) {
      assert.deepEqual(keys(item.sourceRegion), [...REGION_ALWAYS_KEYS].sort())
    }
  }
  assert.ok(items.some((item) => item.location === undefined), 'an exact-source item has no hit to quote')
  assert.ok(items.every((item) => item.location === undefined || item.sourceRegion !== undefined))
  JSON.parse(JSON.stringify(items))
})

test('a watermark item points at both sides', async () => {
  // The candidate's region and the release's region, for the same site.
  const { report, outcome } = await graded('both-sides')
  const fragments = report.evidence.filter((item) => item.kind === 'WATERMARK_FRAGMENT_MATCH')
  assert.ok(fragments.length >= 1)
  const hit = fragments[0]
  assert.ok(outcome.sites.some((row) => row.foundIn === hit.location.file))
  assert.equal(hit.location.line, hit.sourceRegion.line)
  assert.ok(['STRONG', 'VERY_STRONG'].includes(hit.strength), hit.strength)
})

test('the boundary and the caveats are inside the document', async () => {
  const { report } = await graded('boundary')
  assert.ok(report.limitations[0].startsWith('This is an observation about artifacts'))
  assert.ok(report.limitations.every((sentence) => sentence.trim().length > 0))
  assert.ok(report.limitations.length >= 3)
  assert.ok(report.notes.some((note) => note.includes(`at tag widths ${report.releases[0].tagBits}`)), report.notes.join('|'))
  assert.ok(Array.isArray(report.omissions))
  assert.ok(report.omissions.every((omission) => omission.includes(': ')))
})

test('all three verdicts reach JavaScript', async () => {
  // Detected, not detected, and unable to have said either way.
  const project = await makeProtected('reports-verdicts')
  const staged = stageArtifact(project, 'verdicts')
  const detected = (await project.scan(staged)).report
  assert.equal(detected.result, 'PROVENANCE_DETECTED')
  assert.equal(detected.exitCode(), 1)

  const nothing = (await project.scan(foreignTree())).report
  assert.equal(nothing.result, 'NO_PROVENANCE_DETECTED')
  assert.equal(nothing.exitCode(), 0)
  assert.equal(nothing.evidenceLevel, 'NONE')
  assert.equal(nothing.releases[0].fragments, 0)
  // A negative document still cites one thing: the control that says what the run
  // excluded, so "nothing was found" is a measured claim rather than a silence.
  assert.deepEqual(nothing.evidence.map((item) => item.kind), ['NEGATIVE_CONTROL'])
  assert.equal(nothing.evidence[0].strength, 'NONE')
  assert.equal(nothing.evidence[0].location, undefined)

  const prose = tempRoot('reports-prose')
  mkdirSync(join(prose, 'docs'), { recursive: true })
  writeFileSync(join(prose, 'docs', 'notes.md'), '# nothing\n', 'utf8')
  const inconclusive = (await project.scan(prose)).report
  assert.equal(inconclusive.result, 'INCONCLUSIVE')
  assert.equal(inconclusive.exitCode(), 10)
  assert.equal(inconclusive.evidenceLevel, 'NONE')

  for (const report of [detected, nothing, inconclusive]) {
    assert.ok(RESULTS.has(report.result))
    assert.ok(LEVELS.includes(report.evidenceLevel))
    // The strongest release's level is the overall one, in every direction.
    const levels = report.releases.map((tally) => tally.level)
    assert.equal(levels.reduce((best, level) => (rank(level) > rank(best) ? level : best), 'NONE'), report.evidenceLevel)
  }
})

test('toJson is the document and fromJson reads it back', async () => {
  const { report } = await graded('roundtrip')
  const text = report.toJson()
  assert.ok(text.endsWith('\n'))
  assert.ok(text.includes('\n  "'), 'pretty-printed, the way the store writes it')
  const document = JSON.parse(text)
  assert.equal(document.schema, 'SWP-1-report-v2')
  assert.equal(document.result, report.result)
  assert.equal(document.evidence.length, report.evidence.length)

  const again = Report.fromJson(text)
  assert.ok(again instanceof Report)
  assert.equal(again.toJson(), text, 'a round trip is byte-identical')
  assert.equal(again.result, report.result)
  assert.equal(again.evidenceLevel, report.evidenceLevel)
  assert.deepEqual(again.evidence.map((item) => item.id), report.evidence.map((item) => item.id))
  assert.deepEqual(again.limitations, report.limitations)
  assert.equal(again.toString(), report.toString())
})

test('fromJson refuses a document it was not written under', async () => {
  // A foreign schema is not damage: it is arithmetic this build does not apply.
  const { report } = await graded('refusal')
  const text = report.toJson()
  const otherSchema = JSON.parse(text)
  otherSchema.schema = 'SWP-1-report-v1'
  const foreign = thrown(() => Report.fromJson(JSON.stringify(otherSchema)))
  assert.ok(foreign instanceof SwpError, String(foreign))
  assert.equal(foreign.code, 'PROTOCOL_VERSION_UNSUPPORTED')
  assert.ok(foreign.message.includes('SWP-1-report-v1'), foreign.message)
  assert.ok(foreign.message.includes(capabilities().reportSchema), foreign.message)

  for (const bad of ['not json at all', '{}', text.slice(0, Math.floor(text.length / 2)), '["a list"]', '']) {
    const error = thrown(() => Report.fromJson(bad))
    assert.ok(error instanceof SwpError, bad.slice(0, 20))
    assert.equal(error.code, 'INVALID_MANIFEST', bad.slice(0, 20))
  }
  // A refusal leaves nothing behind: the document under test is still readable.
  assert.equal(Report.fromJson(text).toJson(), text)
})

test('toText is the rendering the command prints', async () => {
  const { report } = await graded('text')
  const text = report.toText()
  assert.ok(text.includes(report.schema))
  assert.ok(text.includes(report.result))
  assert.ok(text.includes(report.evidenceLevel))
  assert.ok(text.includes(`${report.candidate.filesScanned} file(s)`), text.slice(0, 400))
  assert.ok(text.includes('Keyed bits confirmed'))
  // The §51 boundary is printed with the verdict, not left to a README.
  assert.ok(text.split('\n').some((line) => line.includes('artifact')))
  assert.ok(report.toText(true).split('\n').length >= text.split('\n').length)
  for (const item of report.evidence) {
    assert.ok(report.toText(true).includes(item.id), item.id)
  }
})

test('the window only shortens the printout', async () => {
  const { report } = await graded('window')
  const full = report.toText(true)
  const narrow = report.toTextItems(1)
  assert.ok(narrow.split('\n').length < full.split('\n').length)
  assert.ok(narrow.includes(report.evidence[0].id))
  assert.ok(!narrow.includes(report.evidence[report.evidence.length - 1].id))
  // What the window leaves out is counted rather than hidden.
  assert.ok(narrow.includes(`and ${report.evidence.length - 1} more`), narrow)
  assert.ok(full.includes(`${report.evidence.length} item(s)`))
  // Data is never windowed: the document beside the text is the whole run.
  assert.equal(JSON.parse(report.toJson()).evidence.length, report.evidence.length)
})

test('a saved report is readable by every spelling of its name', async () => {
  const { project, outcome, report } = await graded('spellings')
  const saved = outcome.saved
  const names = [saved.name, `${saved.name}.json`, `reports/${saved.name}.json`, saved.path]
  const documents = new Set(names.map((name) => project.session.readReport(name).report.toJson()))
  assert.deepEqual([...documents], [report.toJson()], 'one entry, four spellings')
  assert.ok(names.every((name) => reportStem(name) === saved.name))
})

test('the stored document is the one that was graded', async () => {
  const { project, outcome, report } = await graded('stored')
  const stored = project.session.readReport(outcome.saved.name)
  assert.ok(stored instanceof StoredReport)
  // `StoredReport` is a class over the record, so its inventory is its prototype:
  // the name, the path and the document — the Python `to_dict()`'s four words
  // split across two objects.
  assert.deepEqual(
    Object.getOwnPropertyNames(StoredReport.prototype).filter((name) => name !== 'constructor'),
    ['name', 'path', 'report', 'toString']
  )
  assert.deepEqual(Object.getOwnPropertyNames(stored), [])
  assert.equal(stored.name, outcome.saved.name)
  assert.equal(stored.path, outcome.saved.path)
  assert.equal(stored.path, `.swp/private/reports/${stored.name}.json`)
  assert.ok(isForwardSlashed(stored.path))
  assert.equal(stored.report.toJson(), report.toJson())
  assert.equal(stored.report.run.command, 'scan')
  assert.match(stored.toString(), /^StoredReport\(name='scan-/)
  // The record's two words are the document's own.
  assert.ok(stored.toString().includes(report.result))
  assert.ok(stored.toString().includes(report.evidenceLevel))
})

test('reports are listed newest first and survive a name collision', async () => {
  const project = await makeProtected('reports-listing')
  const staged = stageArtifact(project, 'listing')
  const names = []
  for (const _attempt of [0, 1, 2]) names.push((await project.scan(staged, { save: true })).saved.name)
  assert.equal(new Set(names).size, 3, 'a save never overwrites an earlier record')
  assert.ok(names.every((name) => /^scan-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d+)?$/.test(name)), names.join(','))
  const listed = project.session.reports()
  assert.deepEqual(listed, [...names].reverse(), 'newest first, as `swp report` lists them')
  assert.ok(listed.every((name) => !name.endsWith('.json')), 'the name a caller passes in')
  for (const name of listed) assert.equal(project.session.readReport(name).name, name)
})

test('an unknown report name is a usage error that names what exists', async () => {
  const { project } = await graded('unknown')
  const error = thrown(() => project.session.readReport('no-such-report'))
  assert.ok(error instanceof SwpError, String(error))
  assert.equal(error.code, 'USAGE')
  assert.ok(error.message.includes('no-such-report'), error.message)
  assert.ok(error.message.includes('1 report'), error.message)
  // An empty name is refused before the store is searched: no report SWP-1 would
  // have written is spelled `""`. (The Python binding reaches the same refusal
  // through a different argument check.)
  const blank = thrown(() => project.session.readReport(''))
  assert.equal(blank.code, 'PATH_REJECTED')
  assert.ok(blank.message.includes('report name'), blank.message)
})

test('a report document carries no field of the private store', async () => {
  // The projection is the SDK's summary, not a re-reading of a manifest.
  const { report } = await graded('private')
  const document = JSON.parse(report.toJson())
  assert.deepEqual(Object.keys(document).filter((name) => PRIVATE_NAMES.includes(name)), [])
  const forms = [report.toJson(), report.toString(), report.toText(true), ...report.evidence.map((item) => JSON.stringify(item))]
  for (const name of PRIVATE_NAMES) {
    assert.ok(!forms.some((form) => form.includes(name)), `${name} reached a report form`)
  }
})

test('toString is the verdict line and nothing else', async () => {
  const { report } = await graded('tostring')
  assert.equal(
    report.toString(),
    `Report(schema='SWP-1-report-v2', result='${report.result}', evidenceLevel='${report.evidenceLevel}')`
  )
  // The document is not in there: a `toString` that listed twelve fields would be
  // a second copy of the run in whatever log the caller wrote the line to.
  assert.ok(!report.toString().includes(report.evidence[0].id))
})

test('a report cannot be built or rewritten from JavaScript', async () => {
  const { report } = await graded('immutable')
  // napi gives the class no constructor, so there is no way to stand a `Report`
  // up from the JavaScript side at all — the Python `TypeError` for a missing
  // argument is the same refusal with a different face.
  const constructed = thrown(() => new Report())
  assert.ok(constructed instanceof Error && !(constructed instanceof SwpError), String(constructed))
  assert.match(constructed.message, /constructor/i)

  const written = thrown(() => {
    report.result = 'PROVENANCE_DETECTED'
  })
  assert.ok(written instanceof TypeError, String(written))

  // A document is read from text: anything else fails in napi, before the SDK
  // sees a call, and with a shape word rather than an SWP-1 error code.
  const notText = thrown(() => Report.fromJson(report))
  assert.ok(!(notText instanceof SwpError), String(notText))
  assert.equal(notText.code, 'StringExpected')
  assert.ok(!errorCodes().includes(notText.code))
})

/** The error a synchronous call raised, or `null` when it did not raise. */
function thrown (run) {
  try {
    run()
    return null
  } catch (error) {
    return error
  }
}
