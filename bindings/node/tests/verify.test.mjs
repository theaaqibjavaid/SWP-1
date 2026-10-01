// Grading your own tree: what `session.verify()` hands back.
//
// Every case here runs against a release the fixture published, and the assertions
// are about the document `swp-evidence` graded — not about arithmetic this suite
// performs. Three kinds of claim are made, and they are deliberately different:
//
// * **the document's own words** — the verdict, the fingerprint, the exit code, the
//   advice. The binding only reads them off; a test that recomputed a verdict would
//   pass on a binding that ignored the SDK's judgement and drew its own conclusion.
// * **internal consistency** — the site counts equal the rows, the statuses are the
//   detector's vocabulary, `toJson()` agrees with every getter. A copy of a document
//   can drift from its own fields; these cases are why this binding holds one value
//   rather than a dozen copies of it.
// * **the same site in two documents** — the rows `protectSummary` returned and the
//   rows this call returns describe the same locations, so a binding that renumbered
//   or re-derived them is caught here.
//
// The tamper cases damage the protected tree afterwards, which is the only way to
// see a grade that is not `INTACT` without inventing a release. What a damaged site
// becomes (`absent`, `location-only` or `tag-confirmed`) depends on the code the
// drawn key gave it, so those cases assert the invariants that hold either way.
//
// Where this diverges from the Python suite the reason is Node's: `verify` is
// synchronous — it rewrites nothing, takes no lock and needs no await — `revision`
// and `reportSaved` come back as `null` rather than an absent attribute, and a row's
// `foundIn`/`foundLine` are *omitted* from the object when the site was not found.
// A malformed `VerifyOptions` field is refused by napi's own cast, as a plain
// `Error` whose code is not one of `errorCodes()`: that is a call which never
// reached the SDK, and the two vocabularies are kept distinguishable on purpose.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { Report, SwpError, errorCodes, reportStem } from '../index.js'
import { SOURCE_TREE, absolute, isForwardSlashed, makeProject, plain, purgeAll } from './helpers.mjs'

after(purgeAll)

/** The document's site statuses, as `swp-detection` spells them. */
const SITE_STATUSES = new Set(['absent', 'location-only', 'tag-confirmed', 'exact-rendering'])

/** The watermark grades: a site carrying its code, at one radius or the recorded one. */
const CONFIRMED_STATUSES = new Set(['tag-confirmed', 'exact-rendering'])

/** The 32 fields of `SWP-1-verify-v1`, each with the getter that reads it. */
const DOCUMENT_FIELDS = new Map([
  ['schema', 'schema'],
  ['protocol', 'protocol'],
  ['project_id', 'projectId'],
  ['display_name', 'displayName'],
  ['tree', 'tree'],
  ['release_id', 'releaseId'],
  ['release_created_at', 'releaseCreatedAt'],
  ['revision', 'revision'],
  ['manifest_authenticated', 'manifestAuthenticated'],
  ['sites_expected', 'sitesExpected'],
  ['sites_confirmed', 'sitesConfirmed'],
  ['sites_exact', 'sitesExact'],
  ['sites_stripped', 'sitesStripped'],
  ['sites_absent', 'sitesAbsent'],
  ['sites_moved', 'sitesMoved'],
  ['sites_refactored', 'sitesRefactored'],
  ['tag_bits', 'tagBits'],
  ['confirmed_bits', 'confirmedBits'],
  ['files_scanned', 'filesScanned'],
  ['bytes_scanned', 'bytesScanned'],
  ['fingerprint', 'fingerprint'],
  ['fingerprint_expected', 'fingerprintExpected'],
  ['verdict', 'verdict'],
  ['partial', 'partial'],
  ['sites', 'sites'],
  ['omitted_rows', 'omittedRows'],
  ['omissions', 'omissions'],
  ['notes', 'notes'],
  ['report_saved', 'reportSaved'],
  ['limitations', 'limitations'],
  ['next', 'next'],
  ['exit_code', 'exitCode']
])

/** The 15 fields of one site row; the last two are present only when it was found. */
const ROW_KEYS = new Set([
  'site',
  'file',
  'lineHint',
  'language',
  'adapter',
  'class',
  'family',
  'width',
  'status',
  'confirmed',
  'slots',
  'foundIn',
  'foundLine',
  'refactored',
  'moved'
])

const ROW_ALWAYS_KEYS = [
  'site',
  'file',
  'lineHint',
  'language',
  'adapter',
  'class',
  'family',
  'width',
  'status',
  'confirmed',
  'slots',
  'refactored',
  'moved'
]

/** The four keyed radii a confirming span can be reproduced by. */
const SLOTS = new Set(['statement+identifiers', 'statement+names', 'scope+identifiers', 'scope+names'])

const SCENARIOS = ['intact', 'deleted', 'edited', 'moved']

/** `verify` grades synchronously, so what it refuses it throws rather than rejects. */
function thrown (run) {
  try {
    run()
    return null
  } catch (error) {
    return error
  }
}

/** Where `damage` moves a site's file to, keeping the extension it parses by. */
function relocated (file) {
  return `src/relocated${file.slice(file.lastIndexOf('.'))}`
}

/** Damage the protected tree the way one of the four scenarios says. */
function damage (root, row, scenario) {
  const path = join(root, ...row.file.split('/'))
  if (scenario === 'deleted') {
    rmSync(path)
    return
  }
  if (scenario === 'moved') {
    // Byte-for-byte the same file under a new name, and the same extension: the
    // adapter selects on the suffix, so a move that changed the file type would be
    // a rewrite of the source in a different language rather than a move.
    writeFileSync(join(root, ...relocated(row.file).split('/')), readFileSync(path))
    rmSync(path)
    return
  }
  assert.equal(scenario, 'edited')
  const raw = readFileSync(path, 'utf8')
  const eol = raw.includes('\r\n') ? '\r\n' : '\n'
  const lines = raw.split(/\r?\n/)
  assert.ok(row.lineHint > 0 && row.lineHint <= lines.length, `${row.file}:${row.lineHint}`)
  const line = lines[row.lineHint - 1]
  // Damage the site itself, whichever class of literal the drawn key made it.
  const edited = /\d/.test(line)
    ? line.replace(/\d+/, '999999')
    : line.replace(/(['"])([^'"]+)\1/, (_match, quote, body) => `${quote}${body}damaged${quote}`)
  assert.notEqual(edited, line, `line ${row.lineHint} of ${row.file} holds no literal to damage`)
  lines[row.lineHint - 1] = edited
  // The line endings are preserved: moving every byte of the file would make every
  // site of it stale, and this case is about one damaged literal.
  writeFileSync(path, lines.join(eol), 'utf8')
}

/** One release, verified before and after one of four things happened to it. */
async function graded (scenario) {
  const project = makeProject(`verify-${scenario}`)
  const summary = await project.protectMode('release')
  const first = project.verify()
  if (scenario !== 'intact') damage(project.root, first.sites[0], scenario)
  return { project, summary, first, outcome: project.verify() }
}

const rowAt = (outcome, site) => outcome.sites.find((row) => row.site === site)

const sourceBytes = Object.values(SOURCE_TREE).reduce((sum, text) => sum + Buffer.byteLength(text, 'utf8'), 0)

for (const scenario of SCENARIOS) {
  test(`the document is internally consistent after it was ${scenario}`, async () => {
    const { summary, outcome } = await graded(scenario)
    const rows = outcome.sites
    const document = JSON.parse(outcome.toJson())

    assert.equal(outcome.sitesExpected, rows.length)
    assert.equal(outcome.sitesExpected, summary.sitesEmbedded)
    assert.equal(outcome.sitesConfirmed, rows.filter((r) => r.confirmed).length)
    assert.equal(outcome.sitesExact, rows.filter((r) => r.status === 'exact-rendering').length)
    assert.equal(outcome.sitesStripped, rows.filter((r) => r.status === 'location-only').length)
    assert.equal(outcome.sitesAbsent, rows.filter((r) => r.status === 'absent').length)
    assert.equal(outcome.sitesMoved, rows.filter((r) => r.moved).length)
    assert.equal(outcome.sitesRefactored, rows.filter((r) => r.refactored).length)
    assert.ok(rows.every((r) => SITE_STATUSES.has(r.status)))
    assert.ok(rows.every((r) => r.confirmed === CONFIRMED_STATUSES.has(r.status)))
    // A site is watermark evidence, an address without a code, or missing.
    assert.equal(outcome.sitesConfirmed + outcome.sitesStripped + outcome.sitesAbsent, outcome.sitesExpected)
    assert.ok(outcome.sitesExact <= outcome.sitesConfirmed)
    assert.ok(outcome.sitesConfirmed <= outcome.sitesExpected)
    assert.equal(document.sites_confirmed, outcome.sitesConfirmed)
    // The keyed evidence is the width of every site that is carrying its code.
    assert.equal(outcome.confirmedBits, rows.filter((r) => r.confirmed).reduce((sum, r) => sum + r.width, 0))

    assert.ok(['INTACT', 'INCOMPLETE', 'INCONCLUSIVE'].includes(outcome.verdict), outcome.verdict)
    assert.equal(outcome.exitCode, { INTACT: 0, INCOMPLETE: 5, INCONCLUSIVE: 10 }[outcome.verdict])
    assert.equal(outcome.sitesConfirmed === outcome.sitesExpected, outcome.verdict === 'INTACT',
      'every site carrying its code is exactly what INTACT claims')
    assert.equal(outcome.verdict === 'INCONCLUSIVE', outcome.partial)

    assert.equal(outcome.schema, 'SWP-1-verify-v1')
    assert.equal(outcome.protocol, 'SWP-1')
    assert.equal(outcome.manifestAuthenticated, true)
    assert.equal(document.exit_code, outcome.exitCode)
  })
}

test('an untouched tree is intact, by the document and not by this test', async () => {
  const { project, outcome } = await graded('intact')
  assert.equal(absolute(plain(outcome.tree)), absolute(project.root))
  assert.equal(outcome.displayName, project.session.identity.displayName)
  assert.equal(outcome.verdict, 'INTACT')
  assert.equal(outcome.exitCode, 0)
  assert.equal(outcome.fingerprint, 'match')
  assert.equal(outcome.sitesAbsent, 0)
  assert.equal(outcome.sitesMoved, 0)
  assert.equal(outcome.filesScanned, Object.keys(SOURCE_TREE).length)
  // The protected tree is larger than the sources that went into it.
  assert.ok(outcome.bytesScanned > sourceBytes, `${outcome.bytesScanned} vs ${sourceBytes}`)
  assert.ok(outcome.sites.every((r) => r.status === 'exact-rendering'))
  assert.equal(outcome.partial, false)
  assert.equal(outcome.revision, null, 'nothing labelled this release')
})

test('a missing file is a site that is absent, and the verdict says so', async () => {
  const { summary, outcome } = await graded('deleted')
  assert.equal(outcome.verdict, 'INCOMPLETE')
  assert.equal(outcome.exitCode, 5)
  assert.equal(outcome.fingerprint, 'no-match')
  assert.equal(outcome.sitesAbsent, 1)
  assert.equal(outcome.sitesMoved, 0)
  assert.equal(outcome.filesScanned, Object.keys(SOURCE_TREE).length - 1)
  const lost = rowAt(outcome, 0)
  assert.equal(lost.file, summary.sites[0].file)
  assert.equal(lost.status, 'absent')
  assert.equal(lost.confirmed, false)
  assert.equal(lost.foundIn, undefined, 'a site that was not found has no place to name')
  assert.deepEqual(lost.slots, [])
  assert.equal(outcome.sitesExact, outcome.sitesExpected - 1)
})

test('a damaged literal cannot claim the rendering it recorded', async () => {
  const { summary, outcome } = await graded('edited')
  const damaged = rowAt(outcome, 0)
  // The tree fingerprint goes stale the moment a byte moves; the grade may follow,
  // and which of the four radii still reproduces the span is the drawn key's
  // business — measured both ways across runs — so this stops at what cannot vary:
  // the recorded rendering is gone, and the other sites are not.
  assert.equal(outcome.fingerprint, 'no-match')
  assert.equal(outcome.sitesExpected, summary.sitesEmbedded)
  assert.ok(SITE_STATUSES.has(damaged.status), damaged.status)
  assert.notEqual(damaged.status, 'exact-rendering')
  assert.equal(outcome.sitesExact, outcome.sitesExpected - 1)
  assert.ok(outcome.sites.filter((r) => r.site !== damaged.site).every((r) => r.status === 'exact-rendering'))
})

test('a moved site is the same site found somewhere else', async () => {
  const { summary, outcome } = await graded('moved')
  const rows = outcome.sites.filter((r) => r.moved)
  assert.equal(rows.length, 1)
  assert.equal(outcome.sitesMoved, 1)
  const row = rows[0]
  // `file` stays where the release put it; `foundIn` says where the mark is now.
  assert.equal(row.site, 0)
  assert.equal(row.file, summary.sites[0].file)
  assert.equal(row.foundIn, relocated(row.file))
  assert.equal(row.foundLine, row.lineHint)
  assert.equal(row.status, 'exact-rendering')
  assert.equal(row.confirmed, true)
  assert.equal(row.refactored, false)
  assert.equal(outcome.sitesAbsent, 0)
  // A move is reported beside the row rather than as a new site or a lost one: the
  // index, the line hint and the shape are still the plan's, and every site of the
  // release is still carrying its code — so the verdict is INTACT even though the
  // tree no longer hashes to the published fingerprint.
  assert.equal(outcome.verdict, 'INTACT')
  assert.equal(outcome.exitCode, 0)
  assert.equal(outcome.fingerprint, 'no-match')
})

for (const scenario of SCENARIOS) {
  test(`the rows are the plan rows with a grade added (${scenario})`, async () => {
    const { summary, outcome } = await graded(scenario)
    const planned = new Map(summary.sites.map((site, index) => [index, site]))
    const seen = new Set()
    for (const row of outcome.sites) {
      assert.equal(seen.has(row.site), false, 'a site index keys the release, it is not a counter')
      seen.add(row.site)
      const site = planned.get(row.site)
      assert.deepEqual(
        [row.file, row.lineHint, row.language, row.adapter, row.class, row.family, row.width],
        [site.file, site.lineHint, site.language, site.adapter, site.class, site.family, site.width]
      )
      assert.ok(['ast', 'lexical'].includes(row.adapter), row.adapter)
      assert.ok(['integer', 'string'].includes(row.class), row.class)
      assert.equal(row.width, outcome.tagBits)
      assert.ok(row.slots.every((slot) => SLOTS.has(slot)), row.slots.join(','))
      const keys = Object.keys(row).sort()
      assert.deepEqual(keys.filter((key) => key !== 'foundIn' && key !== 'foundLine'), [...ROW_ALWAYS_KEYS].sort())
      assert.ok(keys.every((key) => ROW_KEYS.has(key)), keys.join(','))
      // A found site names its place in both fields or in neither.
      assert.equal(row.foundLine === undefined, row.foundIn === undefined)
      if (row.confirmed) {
        assert.notEqual(row.foundIn, undefined, 'a confirmed site was found somewhere')
        assert.equal(row.foundIn === row.file, !row.moved)
      } else {
        assert.ok(['absent', 'location-only'].includes(row.status), row.status)
      }
    }
    assert.deepEqual([...seen].sort((a, b) => a - b), [...Array(outcome.sitesExpected).keys()])
  })
}

for (const scenario of SCENARIOS) {
  test(`the document form holds every getter and nothing else (${scenario})`, async () => {
    const { outcome } = await graded(scenario)
    const document = JSON.parse(outcome.toJson())
    assert.deepEqual(Object.keys(document).sort(), [...DOCUMENT_FIELDS.keys()].sort())
    assert.deepEqual(Object.getOwnPropertyNames(outcome), [], 'the outcome carries no own state')
    for (const [field, getter] of DOCUMENT_FIELDS) {
      if (field === 'sites') {
        assert.deepEqual(document.sites.map((row) => row.site), outcome.sites.map((row) => row.site))
        continue
      }
      assert.deepEqual(document[field], outcome[getter], field)
    }
    assert.equal(typeof outcome.toJson(), 'string')
    assert.ok(outcome.toString().includes(outcome.verdict), outcome.toString())
  })
}

test('toJson is the document the command would print', async () => {
  const { summary, outcome } = await graded('intact')
  const text = outcome.toJson()
  // Pretty-printed, as `swp verify --format json` prints it.
  assert.ok(text.endsWith('\n'))
  assert.ok(text.includes('\n  "'), 'not a single-line document')
  const document = JSON.parse(text)
  assert.equal(document.schema, 'SWP-1-verify-v1')
  assert.equal(document.verdict, outcome.verdict)
  assert.equal(document.release_id, summary.releaseId)
  assert.equal(document.sites.length, outcome.sitesExpected)
  assert.ok(['integer', 'string'].includes(document.sites[0].class))
  assert.ok(!text.includes('class_'), 'the document key is the schema word')
  assert.ok(!text.includes('lineHint'), 'and not the JavaScript spelling of it')
  assert.ok(!text.includes('foundIn'), 'which the document spells found_in')
})

for (const scenario of SCENARIOS) {
  test(`the advice and the boundary travel inside the document (${scenario})`, async () => {
    const { summary, outcome } = await graded(scenario)
    assert.ok(
      outcome.limitations[0].startsWith('a site that carries its code is a statement about this artifact'),
      'the §51 boundary is the first thing a forwarded report still says'
    )
    assert.ok(outcome.limitations.every((line) => line.trim().length > 0))
    assert.equal(outcome.next[0], `swp inspect manifest --release ${summary.releaseId}`)
    assert.equal(outcome.next.length === 3, outcome.verdict !== 'INTACT')
    if (outcome.verdict !== 'INTACT') {
      assert.ok(outcome.next.some((line) => line.includes('swp protect')), outcome.next.join(' | '))
    }
    assert.ok(outcome.notes.some((note) => note.includes(`at tag widths ${outcome.tagBits}`)), outcome.notes.join(' | '))
    // The store's own `.gitignore` is declined by the walk. A decline is a named
    // omission, not a hole in the tree: `partial` says something else entirely.
    assert.ok(outcome.omissions.every((omission) => omission.includes(': ')), outcome.omissions.join(' | '))
    assert.equal(outcome.partial, false)
  })
}

test('verify grades synchronously, and re-reads the store each call', async () => {
  const { project } = await graded('intact')
  const outcome = project.verify()
  assert.equal(typeof outcome.then, 'undefined', 'a promise here would be a lie about locking')
  const again = project.verify()
  assert.notEqual(again, outcome)
  assert.deepEqual(JSON.parse(again.toJson()), JSON.parse(outcome.toJson()))
})

test('a second release is only verified when it is asked for', async () => {
  // Which of two releases is "newest" is the SDK's answer — the recorded time, and
  // on a tie inside one second the larger release id. Ids are drawn, so a test may
  // not assume the *second* run is the newest; only that the default call reads
  // whatever the store says is. What is deterministic is the other half: the tree
  // carries the second run's codes, because that run rewrote the source, so that is
  // the constellation that matches and the first is the one that does not.
  const project = makeProject('verify-two-releases')
  const first = await project.protectMode('release')
  const second = await project.protect({ mode: 'release', revision: 'build-7' })
  assert.notEqual(second.releaseId, first.releaseId)

  const newest = project.session.releases({ kind: 'latest' })[0]
  const byDefault = project.verify()
  assert.equal(byDefault.releaseId, newest)

  const matches = project.verify({ release: second.releaseId })
  assert.equal(matches.verdict, 'INTACT')
  assert.equal(matches.fingerprint, 'match')
  assert.equal(matches.revision, 'build-7', 'the label the release recorded, or nothing')
  assert.equal(matches.sitesExpected, second.sitesEmbedded)

  const older = project.verify({ release: first.releaseId })
  assert.equal(older.releaseId, first.releaseId)
  assert.equal(older.fingerprint, 'no-match')
  assert.notEqual(older.verdict, 'INTACT')
  assert.equal(older.revision, null)
  assert.equal(older.sitesExpected, first.sitesEmbedded)

  // Naming the newest release asks for what the default call already answered.
  const newestRun = newest === second.releaseId ? matches : older
  assert.deepEqual(JSON.parse(byDefault.toJson()), JSON.parse(newestRun.toJson()))
})

test('the release record and the document describe one run', async () => {
  const project = makeProject('verify-record')
  const summary = await project.protectMode('release')
  const outcome = project.verify()
  const record = project.session.release(outcome.releaseId)
  assert.equal(record.releaseId, outcome.releaseId)
  assert.equal(record.releaseId, summary.releaseId)
  assert.equal(record.projectId, outcome.projectId)
  assert.equal(record.fingerprint, outcome.fingerprintExpected)
  assert.match(outcome.fingerprintExpected, /^[0-9a-f]{64}$/)
  assert.equal(record.watermark.tagBits, outcome.tagBits)
  assert.equal(record.watermark.sitesEmbedded, outcome.sitesExpected)
  assert.match(outcome.releaseCreatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/, outcome.releaseCreatedAt)
  assert.ok(!Number.isNaN(Date.parse(outcome.releaseCreatedAt)))
})

test('a save writes the report and names where it went', async () => {
  const project = makeProject('verify-save')
  await project.protectMode('release')
  const unsaved = project.verify()
  assert.equal(unsaved.reportSaved, null)
  assert.deepEqual(project.session.reports(), [])

  const saved = project.verify({ save: true })
  const path = saved.reportSaved
  assert.match(path, /^\.swp\/private\/reports\/verify-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d+)?\.json$/, path)
  assert.ok(isForwardSlashed(path), 'store-relative and forward-slashed, so it is safe to print')
  assert.ok(existsSync(join(project.root, ...path.split('/'))))
  const stem = reportStem(path)
  assert.deepEqual(project.session.reports(), [stem])

  const again = project.verify({ save: true })
  assert.notEqual(again.reportSaved, path, 'a save never clobbers an earlier record')
  assert.ok(existsSync(join(project.root, ...again.reportSaved.split('/'))))
  assert.deepEqual(new Set(project.session.reports()), new Set([stem, reportStem(again.reportSaved)]))
  assert.equal(unsaved.reportSaved, null, 'a run that did not save says it did not save')

  // The saved copy is the `SWP-1-report-v2` document the same run graded.
  const stored = project.session.readReport(stem)
  assert.equal(stored.name, stem)
  assert.equal(stored.path, path)
  assert.equal(stored.report.schema, 'SWP-1-report-v2')
  assert.equal(stored.report.run.command, 'verify')
  assert.equal(stored.report.result, 'PROVENANCE_DETECTED')
  assert.equal(stored.report.candidate.filesScanned, unsaved.filesScanned)
  assert.equal(Report.fromJson(stored.report.toJson()).toJson(), stored.report.toJson())
})

test('rows windows only the text rendering', async () => {
  const project = makeProject('verify-rows')
  const summary = await project.protectMode('release')
  const narrow = project.verify({ rows: 1 })
  // `rows` is `--rows`: it counts what the printout left out, and hides nothing.
  // The getters and the stored document still hold every site, because a windowed
  // site list would be a different artifact than the one that was graded.
  assert.equal(narrow.omittedRows, summary.sitesEmbedded - 1)
  assert.equal(narrow.sites.length, summary.sitesEmbedded)
  assert.equal(JSON.parse(narrow.toJson()).sites.length, summary.sitesEmbedded)
  assert.deepEqual(JSON.parse(narrow.toJson()).sites, JSON.parse(project.verify().toJson()).sites)
  assert.equal(project.verify().omittedRows, 0)
  assert.equal(project.verify({ rows: summary.sitesEmbedded + 40 }).omittedRows, 0)
  assert.equal(project.verify({ rows: 0 }).omittedRows, summary.sitesEmbedded)
})

test('a release this project never published is refused, and the refusal is thrown', async () => {
  const project = makeProject('verify-refusals')
  await project.protectMode('release')
  const missing = 'rel-' + 'q'.repeat(13)
  const first = thrown(() => project.session.verify({ release: missing }))
  assert.ok(first instanceof SwpError, String(first))
  assert.equal(first.code, 'NOT_PROTECTED')
  assert.ok(first.message.includes(missing), first.message)
  assert.ok(/It has release/.test(first.message), 'the refusal names what does exist')
  assert.ok(errorCodes().includes(first.code))

  // This binding's own argument interpretation is refused before anything is read.
  const second = thrown(() => project.session.verify({ release: 'not-a-release' }))
  assert.ok(second instanceof SwpError, String(second))
  assert.equal(second.code, 'INVALID_MANIFEST')
  assert.ok(second.message.includes('rel-'), second.message)
  assert.ok(errorCodes().includes(second.code))
})

test('verifying a project with no releases is refused', () => {
  const project = makeProject('verify-nothing')
  const error = thrown(() => project.session.verify())
  assert.ok(error instanceof SwpError, String(error))
  assert.equal(error.code, 'NOT_PROTECTED')
  assert.ok(error.nextStep.length > 0, error.nextStep)
  assert.ok(error.rendered.includes(error.code), error.rendered)
})

test('an outcome is read-only, and cannot be edited into a different verdict', async () => {
  const { outcome } = await graded('intact')
  // The document's fields are getters on the prototype and nothing of the
  // instance's own, so a caller that tries to overwrite one is refused by the
  // language rather than by a setter this binding invented.
  assert.deepEqual(Object.getOwnPropertyNames(outcome), [])
  assert.throws(() => {
    outcome.verdict = 'INTACT'
  }, TypeError, 'a verdict is not a field a caller gets to write')
})

test('a malformed option is napi refusing the shape, not the SDK refusing the call', async () => {
  const project = makeProject('verify-shape')
  await project.protectMode('release')
  // napi's own cast failure has its own code and no envelope: it is a call that
  // never reached the SDK, and `errorCodes()` deliberately does not list it.
  for (const field of ['release', 'rows', 'save']) {
    const error = thrown(() => project.session.verify({ [field]: { not: 'the declared type' } }))
    assert.ok(error !== null, `${field} was accepted`)
    assert.ok(!(error instanceof SwpError), `${field} crossed as ${error.constructor.name}`)
    assert.ok(!errorCodes().includes(error.code), String(error.code))
    assert.ok(error.message.includes(`VerifyOptions.${field}`), error.message)
  }
  const plain_ = thrown(() => project.session.verify({}))
  assert.equal(plain_, null, '{} is the default call')
  assert.equal(project.verify({}).sitesExpected, project.verify().sitesExpected)
})
