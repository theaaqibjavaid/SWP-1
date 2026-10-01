// Looking for your provenance in somebody else's artifact.
//
// `Session.scan` is the operation that runs against a tree or archive this project
// does not own, so these cases are built around a copy of the protected sources with
// no store beside it — an artifact the way a reviewer receives one. What is asserted
// is the shape of the answer and the arithmetic the detector already did: the row per
// expected site, the release or releases it was graded against, the candidate's own
// description, and the refusal when the candidate cannot be read.
//
// The verdict, the evidence level and the exit code are read out of the
// `SWP-1-report-v2` document — `tests/reports.test.mjs` holds that document's own
// field assertions — so nothing here decides whether a finding is a finding.
//
// Where this diverges from the Python suite the reason is Node's: `scan` returns a
// promise, because it is the read-only operation that can outlast a caller's patience,
// and that promise settles exactly once and cannot be cancelled. The candidate is a
// path string — a `URL`, a number or an object is refused by napi before the SDK sees
// it. `outcome.saved` is a `{name, path}` object or `null` rather than an absent
// attribute, and a row's `foundIn`/`foundLine`/`foundExcerpt` are *omitted* from the
// object when the site was not found.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { crc32 } from 'node:zlib'

import { SwpError, errorCodes, reportStem } from '../index.js'
import {
  SOURCE_TREE,
  absolute,
  copyTree,
  foreignTree,
  isForwardSlashed,
  makeProject,
  makeProtected,
  plain,
  purgeAll,
  stageArtifact,
  tempRoot
} from './helpers.mjs'

after(purgeAll)

/** The detector's four rungs, weakest first. */
const SITE_STATUSES = new Set(['absent', 'location-only', 'tag-confirmed', 'exact-rendering'])

/** The §23 evidence ladder, as a tally or an item spells it. */
const LEVELS = new Set(['NONE', 'WEAK', 'MODERATE', 'STRONG', 'VERY_STRONG'])

/** The evidence kinds `swp-detection` names, including the negative control. */
const KINDS = new Set([
  'EXACT_SOURCE_MATCH',
  'WATERMARK_FRAGMENT_MATCH',
  'PARTIAL_WATERMARK_MATCH',
  'CANONICAL_MATCH',
  'STRUCTURAL_MATCH',
  'TOKEN_MATCH',
  'NEGATIVE_CONTROL'
])

/** The seven fields a scan row always carries. */
const SITE_ALWAYS_KEYS = ['releaseId', 'site', 'status', 'probes', 'distinctCodes', 'foundTokens']

/** The three place-fields, present together or not at all. */
const SITE_FOUND_KEYS = ['foundIn', 'foundLine', 'foundExcerpt']

/** A row may carry the seven always-fields and either none or all three place-fields. */
const isSiteKey = (key) => SITE_ALWAYS_KEYS.includes(key) || SITE_FOUND_KEYS.includes(key)


/** A stored (uncompressed) zip, written by hand so the suite needs no archive tool. */
function zipTree (root, dest) {
  const entries = []
  const walk = (dir, base = '') => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = base ? `${base}/${entry.name}` : entry.name
      if (entry.isDirectory()) walk(join(dir, entry.name), rel)
      else entries.push([rel, readFileSync(join(dir, entry.name))])
    }
  }
  walk(root)
  const locals = []
  const centrals = []
  let offset = 0
  for (const [name, data] of entries) {
    const nameBuf = Buffer.from(name, 'utf8')
    const crc = crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0, 10) // time and date: as ordinary as the contents
    local.writeUInt16LE(0x2821, 12) // 2000-01-01
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuf.length, 26)
    locals.push(local, nameBuf, data)
    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    // The mode is recorded as a unix regular file, because `swp-detection` skips an
    // entry whose mode it cannot read — and an archive whose every member was
    // skipped is refused rather than reported as an empty finding.
    central.writeUInt16LE(0x0314, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0x2821, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(data.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(nameBuf.length, 28)
    central.writeUInt32LE(((0o100644 << 16) >>> 0), 38)
    central.writeUInt32LE(offset, 42)
    centrals.push(Buffer.concat([central, nameBuf]))
    offset += local.length + nameBuf.length + data.length
  }
  const body = Buffer.concat(locals)
  const cd = Buffer.concat(centrals)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(cd.length, 12)
  eocd.writeUInt32LE(body.length, 16)
  writeFileSync(dest, Buffer.concat([body, cd, eocd]))
  return dest
}

/** A protected project, its artifact, and the scan of it. */
async function scanned (label) {
  const project = await makeProtected(label)
  const staged = stageArtifact(project)
  return { project, staged, outcome: await project.scan(staged) }
}

const listing = (root) => {
  const out = []
  const walk = (dir, base = '') => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = base ? `${base}/${entry.name}` : entry.name
      out.push(rel)
      if (entry.isDirectory()) walk(join(dir, entry.name), rel)
    }
  }
  walk(root)
  return out
}

/**
 * Whatever a scan call did with this argument: the value it settled with, or the
 * failure — thrown synchronously by this binding's own interpretation, or rejected
 * by the SDK the operation called into.
 */
async function settled (run) {
  try {
    return { value: await run() }
  } catch (error) {
    return { error }
  }
}

test('a copy of the sources is detected, by the document and not by this test', async () => {
  const { project, staged, outcome } = await scanned('scan-copy')
  const report = outcome.report
  assert.equal(report.result, 'PROVENANCE_DETECTED')
  assert.equal(report.exitCode(), 1)
  assert.ok(LEVELS.has(report.evidenceLevel), report.evidenceLevel)
  assert.notEqual(report.evidenceLevel, 'NONE', 'a finding is not the absence ladder')
  assert.equal(report.schema, 'SWP-1-report-v2')
  assert.equal(report.protocol, 'SWP-1')
  assert.equal(report.run.command, 'scan')
  assert.equal(report.candidate.kind, 'directory')
  assert.equal(report.candidate.filesScanned, Object.keys(SOURCE_TREE).length)
  assert.ok(report.candidate.bytesScanned > 0)
  assert.equal(report.candidate.partial, false)
  // The candidate is described by where it was, not by anything keyed.
  assert.equal(absolute(report.candidate.described), absolute(staged))
  assert.equal(outcome.saved, null, 'a scan saves only when the caller asks')
  assert.deepEqual(project.session.reports(), [])
})

test('every expected site gets a row, and no row is keyed', async () => {
  const { project, outcome } = await scanned('scan-rows')
  const published = project.session.releases({ kind: 'all' })
  const rows = outcome.sites
  assert.equal(rows.length, project.summary.sitesEmbedded)
  const seen = new Set()
  for (const row of rows) {
    assert.ok(published.includes(row.releaseId), row.releaseId)
    const key = `${row.releaseId}:${row.site}`
    assert.equal(seen.has(key), false, 'one row per site per release')
    seen.add(key)
    assert.ok(SITE_STATUSES.has(row.status), row.status)
    const keys = Object.keys(row).sort()
    assert.deepEqual(keys.filter((k) => !SITE_FOUND_KEYS.includes(k)), [...SITE_ALWAYS_KEYS].sort())
    assert.ok(keys.every((key) => isSiteKey(key)), keys.join(','))
    // A found site names its place in all three fields; an absent one names none.
    if (row.foundIn === undefined) assert.deepEqual(keys.filter((k) => SITE_FOUND_KEYS.includes(k)), [])
    else assert.deepEqual(keys.filter((k) => SITE_FOUND_KEYS.includes(k)).sort(), [...SITE_FOUND_KEYS].sort())
    assert.ok(row.probes >= 0 && row.distinctCodes >= 0)
    assert.ok(row.foundTokens >= 0 && row.foundTokens <= 255, 'the token count saturates')
    if (row.status === 'absent') {
      assert.equal(row.probes, 0)
      assert.equal(row.foundIn, undefined)
      assert.equal(row.foundExcerpt, undefined)
    }
    if (row.foundIn !== undefined) {
      assert.ok(row.foundIn.startsWith('src/'), row.foundIn)
      assert.ok(isForwardSlashed(row.foundIn), 'candidate-relative and forward-slashed')
      assert.ok(row.foundLine >= 1)
      assert.ok(row.foundExcerpt.length > 0)
    }
  }
  assert.ok(rows.every((r) => (r.status !== 'absent') === (r.foundIn !== undefined)))
})

test('the rows are the report summing itself', async () => {
  const { outcome } = await scanned('scan-tally')
  const tally = outcome.report.releases[0]
  const rows = outcome.sites.filter((r) => r.releaseId === tally.releaseId)
  assert.equal(tally.sites, rows.length)
  assert.equal(tally.fragments, rows.filter((r) => ['tag-confirmed', 'exact-rendering'].includes(r.status)).length)
  assert.equal(tally.absent, rows.filter((r) => r.status === 'absent').length)
  assert.equal(tally.stripped, rows.filter((r) => r.status === 'location-only').length)
  assert.equal(tally.probes, rows.reduce((sum, r) => sum + r.probes, 0))
  assert.equal(tally.draws, rows.reduce((sum, r) => sum + r.distinctCodes, 0))
  assert.equal(tally.bits, tally.fragments * tally.tagBits)
  // The sub-counts describe the confirmations; they are not a partition of them.
  assert.ok(tally.exactRenderings <= tally.fragments)
  assert.ok(tally.canonicalOnly <= tally.fragments)
  assert.ok(tally.moved <= tally.fragments)
  assert.ok(tally.files <= tally.fragments)
  assert.ok(tally.chance >= 0)
  assert.ok(tally.coincidenceProbability >= 0 && tally.coincidenceProbability <= 1)
  assert.ok(tally.guarantee >= 0, 'confirmations above the bound are a count, not a debt')
  assert.ok(tally.reasons.length > 0, 'the ladder always says why')
  assert.ok(tally.reasons.every((reason) => reason.trim().length > 0))
  assert.ok(['match', 'no-match', 'not-comparable'].includes(tally.fingerprint), tally.fingerprint)
})

test('an archive is a candidate like any other', async () => {
  const { project, staged } = await scanned('scan-zip')
  const archive = zipTree(staged, join(tempRoot('scan-zip-file'), 'artifact.zip'))
  const outcome = await project.scan(archive)
  assert.equal(outcome.report.candidate.kind, 'zip')
  assert.equal(outcome.report.candidate.filesScanned, Object.keys(SOURCE_TREE).length)
  assert.equal(outcome.report.result, 'PROVENANCE_DETECTED')
  assert.ok(outcome.sites.every((r) => r.status === 'exact-rendering'))
  assert.ok(outcome.sites.every((r) => r.foundIn.startsWith('src/')))
  assert.equal(outcome.saved, null, 'reading an archive writes nothing unless asked')
})

test('scanning the project itself prunes the store', async () => {
  // `.swp/` is not source: the walk declines it rather than matching against it,
  // so a scan of the project directory reports the same scope it would report for
  // a copy of the sources and finds nothing inside the store.
  const project = await makeProtected('scan-self')
  const outcome = await project.scan(plain(project.session.projectRoot))
  assert.equal(outcome.report.candidate.filesScanned, Object.keys(SOURCE_TREE).length)
  assert.equal(outcome.report.result, 'PROVENANCE_DETECTED')
  assert.ok(outcome.sites.every((r) => r.foundIn === undefined || !r.foundIn.includes('.swp')))
  assert.ok(outcome.report.omissions.every((omission) => omission.includes(': ')), outcome.report.omissions.join(' | '))
})

test('a tree that is nobody else is graded as such', async () => {
  const project = await makeProtected('scan-foreign')
  const outcome = await project.scan(foreignTree())
  assert.equal(outcome.report.result, 'NO_PROVENANCE_DETECTED')
  assert.equal(outcome.report.evidenceLevel, 'NONE')
  assert.equal(outcome.report.exitCode(), 0)
  assert.equal(outcome.saved, null)
  for (const row of outcome.sites) {
    assert.equal(row.status, 'absent')
    assert.equal(row.probes, 0)
    assert.equal(row.distinctCodes, 0)
    assert.equal(row.foundIn, undefined)
    assert.equal(row.foundExcerpt, undefined)
  }
  const tally = outcome.report.releases[0]
  assert.equal(tally.fragments, 0)
  assert.equal(tally.bits, 0)
  assert.ok(tally.coincidenceProbability <= 1)
  // The document records the control rather than going silent.
  assert.ok(outcome.report.evidence.every((item) => item.kind === 'NEGATIVE_CONTROL'))
})

test('a candidate with nothing readable is inconclusive', async () => {
  // Not-finding and not-looking are different answers, and the document says which.
  const project = await makeProtected('scan-prose')
  const bare = tempRoot('scan-prose-tree')
  mkdirSync(join(bare, 'docs'), { recursive: true })
  writeFileSync(join(bare, 'docs', 'notes.md'), '# nothing a parser reads\n', 'utf8')
  const outcome = await project.scan(bare)
  assert.equal(outcome.report.result, 'INCONCLUSIVE')
  assert.equal(outcome.report.evidenceLevel, 'NONE')
  assert.equal(outcome.report.exitCode(), 10)
  assert.equal(outcome.report.candidate.filesScanned, 0)
  assert.ok(outcome.report.notes.some((note) => note.includes('no source this protocol can read')),
    outcome.report.notes.join(' | '))
  assert.ok(outcome.sites.every((r) => r.status === 'absent'))
})

test('a candidate that cannot be read is an IO_ERROR naming the caller path', async () => {
  const { project, staged } = await scanned('scan-io')
  const missing = join(staged, 'never-written')
  const { error } = await settled(() => project.scan(missing))
  assert.ok(error instanceof SwpError, String(error))
  assert.equal(error.code, 'IO_ERROR')
  assert.ok(error.message.includes('never-written'), error.message)
  assert.ok(errorCodes().includes(error.code))
})

test('a selection limits which releases are graded', async () => {
  // The copy is made after the first release, so that release's constellation is
  // what the artifact carries and the second one is not.
  const project = makeProject('scan-selection')
  const first = await project.protectMode('release')
  const staged = stageArtifact(project, 'selection')
  const second = await project.protect({ mode: 'release' })
  assert.notEqual(second.releaseId, first.releaseId)

  const one = (await settled(() => project.scan(staged, { releases: { kind: 'ids', ids: [first.releaseId] } }))).value
  assert.deepEqual(one.report.releases.map((t) => t.releaseId), [first.releaseId])
  assert.equal(one.sites.length, first.sitesEmbedded)
  assert.ok(one.sites.every((r) => r.releaseId === first.releaseId))
  assert.deepEqual(new Set(one.report.evidence.map((e) => e.releaseId)), new Set([first.releaseId]))

  const both = (await settled(() => project.scan(staged, { releases: { kind: 'all' } }))).value
  assert.deepEqual(
    new Set(both.report.releases.map((t) => t.releaseId)),
    new Set([first.releaseId, second.releaseId])
  )
  assert.equal(both.sites.length, one.sites.length + second.sitesEmbedded)
  const fragments = both.report.releases.map((t) => t.fragments)
  assert.deepEqual(fragments, [...fragments].sort((a, b) => b - a), 'the strongest tally comes first')

  const latest = (await settled(() => project.scan(staged, { releases: { kind: 'latest' } }))).value
  assert.equal(latest.report.releases.length, 1)
  assert.equal(latest.report.releases[0].releaseId, project.session.releases({ kind: 'latest' })[0])
})

test('a release id this project never published is refused', async () => {
  const { project, staged } = await scanned('scan-unknown')
  const missing = 'rel-' + 'z'.repeat(13)
  // What the SDK reports about a call it accepted arrives as a rejection.
  const unknown = (await settled(() => project.scan(staged, { releases: { kind: 'ids', ids: [missing] } }))).error
  assert.ok(unknown instanceof SwpError, String(unknown))
  assert.equal(unknown.code, 'NOT_PROTECTED')
  assert.ok(unknown.message.includes(missing), unknown.message)
  assert.ok(/It has release/.test(unknown.message), unknown.message)
  const rejected = await project.session.scan(staged, { kind: 'ids', ids: [missing] }).then(
    () => null,
    (error) => error
  )
  assert.ok(rejected instanceof SwpError, String(rejected))
  assert.equal(rejected.code, 'NOT_PROTECTED')

  // A selection this binding cannot interpret is refused before the AsyncTask is
  // built, so it is thrown rather than rejected — the same split as `protect`.
  const kindless = (await settled(() => project.scan(staged, { releases: { kind: 'nope' } }))).error
  assert.ok(kindless instanceof SwpError, String(kindless))
  assert.equal(kindless.code, 'USAGE')
  assert.ok(errorCodes().includes(kindless.code))
  assert.throws(() => project.session.scan(staged, { kind: 'nope' }), SwpError)

  const empty = (await settled(() => project.scan(staged, { releases: { kind: 'ids', ids: [] } }))).error
  assert.equal(empty.code, 'NOT_PROTECTED')
})

test('save writes the document and names the copy it wrote', async () => {
  const { project, staged } = await scanned('scan-save')
  const outcome = (await settled(() => project.scan(staged, { save: true }))).value
  const saved = outcome.saved
  assert.notEqual(saved, null)
  assert.deepEqual(Object.keys(saved).sort(), ['name', 'path'])
  assert.ok(project.session.reports().includes(saved.name), saved.name)
  assert.equal(saved.path, `.swp/private/reports/${saved.name}.json`)
  assert.ok(isForwardSlashed(saved.path), saved.path)
  assert.equal(statSync(join(project.root, ...saved.path.split('/'))).isFile(), true)
  assert.match(saved.name, /^scan-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d+)?$/, saved.name)
  assert.equal(reportStem(saved.name), saved.name)
  assert.equal(reportStem(saved.path), saved.name)
  // The name and path are the store's; the document beside them is verbatim.
  const stored = project.session.readReport(saved.name)
  assert.equal(stored.report.toJson(), outcome.report.toJson())
  assert.equal(stored.report.run.command, 'scan')
})

test('the outcome string gives the three values a caller reads first', async () => {
  const { outcome } = await scanned('scan-string')
  assert.equal(
    outcome.toString(),
    `ScanOutcome(result='${outcome.report.result}', evidenceLevel='${outcome.report.evidenceLevel}', sites=${outcome.sites.length})`
  )
  assert.deepEqual(Object.getOwnPropertyNames(outcome), [], 'the outcome carries no own state')
  const row = outcome.sites[0]
  assert.match(row.releaseId, /^rel-[a-z2-7]{1,32}$/, row.releaseId)
  assert.equal(typeof row.site, 'number')
  assert.ok(SITE_STATUSES.has(row.status), row.status)
})

test('a saved copy is the only place scan writes', async () => {
  // A scan of somebody else's tree must not leave a mark on it.
  const project = await makeProtected('scan-purity')
  const staged = copyTree(project.child('src'), 'scan-purity-artifact')
  const before = listing(staged)
  const outcome = (await settled(() => project.scan(staged))).value
  assert.deepEqual(listing(staged), before)
  assert.equal(outcome.saved, null)
  assert.deepEqual(project.session.reports(), [])
})

test('scan settles exactly once, and there is nothing to cancel it with', async () => {
  const { project, staged } = await scanned('scan-once')
  const call = project.session.scan(staged)
  assert.equal(typeof call.then, 'function')
  assert.equal(call.cancel, undefined, 'no cancellation handle on the promise')
  const first = await call
  const again = await call
  assert.equal(first, again, 'one settle, one document')
  assert.equal(first.report.result, again.report.result)
  if (first.report.evidence.length > 0) {
    assert.ok(KINDS.has(first.report.evidence[0].kind), first.report.evidence[0].kind)
  }
})

test('a candidate that is not a path string is refused before the walk', async () => {
  const { project } = await scanned('scan-shape')
  for (const value of [null, 42, { path: 'src' }]) {
    const { error } = await settled(() => project.session.scan(value))
    assert.ok(error !== undefined, `${String(value)} was accepted`)
    assert.ok(!(error instanceof SwpError), `${String(value)} crossed as ${error.constructor.name}`)
    assert.ok(!errorCodes().includes(error.code), String(error.code))
    assert.match(error.message, /into rust type `String`/, error.message)
  }
  const badSave = (await settled(() => project.session.scan(tempRoot('scan-shape-target'), undefined, 'yes'))).error
  assert.ok(!(badSave instanceof SwpError), String(badSave))
  assert.match(badSave.message, /rust type `bool`/, badSave.message)
})
