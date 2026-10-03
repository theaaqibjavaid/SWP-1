// The three protection modes, and what each one is allowed to touch.
//
// `protectSummary` is the only protection operation this binding offers, by
// ADR-0001's decision: the Rust `protect` returns the keyed plan, and a foreign
// binding reads the summary instead. These cases hold both halves of that — the
// summary is complete enough to drive a release, and it carries nothing from the
// plan it replaced.
//
// The modes differ in one thing only: what they leave behind. Site selection
// reads the tree and the project secret, neither of which a rehearsal changes,
// so `plan`, `dry-run` and a release of the same tree report the same run. That
// is what makes a rehearsal worth running, and it is why `filesChanged` is
// asserted on here the way it is: it is the *predicted* rewrite in `plan` and
// `dry-run`, and the published one in `release`. `artifacts` and `mode` are what
// tell the three apart.
//
// Where this suite diverges from the Python one the reason is Node's, and it is
// recorded at the test: the mode is a string rather than an enum, the summary is
// a plain object rather than a `to_dict()` away, and the call is a promise that
// has to settle exactly once and must not be cancellable.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync, statSync } from 'node:fs'

import { Session, SwpError, capabilities, errorCodes } from '../index.js'
import {
  PRIVATE_FIELD_NAMES,
  SOURCE_TREE,
  makeProject,
  plain,
  purgeAll,
  treeBytes,
  walkStrings
} from './helpers.mjs'

after(purgeAll)

/// The mode words the CLI, the plan document and the SDK all use for one run.
const MODE_WORDS = ['plan', 'dry-run', 'release']

/// The keys a `ProtectSummary` object has: the twenty-two values the CLI reads
/// beside its verdict, and no plan document among them.
const SUMMARY_KEYS = [
  'mode',
  'projectId',
  'releaseId',
  'createdAt',
  'fingerprint',
  'fingerprintLevel',
  'tagBits',
  'requestedSites',
  'targetSites',
  'sitesEmbedded',
  'sitesSkipped',
  'filesWalked',
  'filesInScope',
  'candidates',
  'filesChanged',
  'sites',
  'refusals',
  'artifacts',
  'notes',
  'filesWithSites',
  'languages',
  'refusalCounts'
]

const bytesAt = (project, rel) => statSync(project.child(...rel.split('/'))).size
const diskAt = (project, rel) => readFileSync(project.child(...rel.split('/')))

/// Capture what a call raised synchronously, rather than letting it end the test.
const thrown = (run) => {
  try {
    run()
  } catch (error) {
    return error
  }
  return null
}

test('the mode is the word the CLI prints, and no other word is accepted', async () => {
  for (const word of MODE_WORDS) {
    const project = makeProject(`mode-${word}`)
    const summary = await project.protect({ mode: word })
    assert.equal(summary.mode, word)
  }
  const project = makeProject('mode-bad')
  // The binding interprets its own arguments at the call, so an uninterpretable
  // mode never reaches the thread pool and never becomes a promise: this throws,
  // where a failure the SDK reports rejects. It is the same line the Python
  // binding draws by constructing `ProtectOptions` eagerly, and it is what keeps
  // "the returned promise settles exactly once" true of every promise this
  // method returns.
  assert.throws(
    () => project.protect({ mode: 'nope' }),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'USAGE')
      // The refusal names the ladder it wanted, so a caller reading a log does
      // not have to know the binding to correct the call.
      assert.match(error.message, /'plan', 'release', 'dry-run'/, error.message)
      return true
    }
  )
})

test('a call that does not match the declared shape is not an SwpError', async () => {
  // `mode` is a required field of the options object, so Node's boundary refuses
  // a call that omits it before the SDK is reached. This is the one failure the
  // binding does not translate, and it stays distinguishable on purpose: it is
  // an ordinary `Error`, its `code` is napi's own spelling, and that code is not
  // one of the codes `errorCodes()` lists. A caller that branches on
  // `error.code` must therefore check `instanceof SwpError` first.
  const project = makeProject('no-mode')
  const error = thrown(() => project.protect({}))
  assert.ok(error instanceof Error)
  assert.equal(error instanceof SwpError, false)
  assert.ok(!errorCodes().includes(error.code), `${error.code} is in the SDK table`)
  assert.match(error.message, /mode/, error.message)
})

test('every mode reports the same run of the same tree', async () => {
  const project = makeProject('same-run')
  const identity = project.initResult.projectId
  for (const word of MODE_WORDS) {
    const summary = await project.protect({ mode: word })
    assert.equal(summary.mode, word)
    assert.equal(summary.projectId, identity)
    assert.ok(summary.sitesEmbedded >= 1, `${word}: nothing was embedded`)
    assert.equal(summary.sites.length, summary.sitesEmbedded)
    assert.equal(summary.refusals.length, summary.sitesSkipped)
    assert.ok(summary.requestedSites >= summary.targetSites, word)
    assert.ok(summary.targetSites >= summary.sitesEmbedded, word)
    assert.ok(summary.candidates >= summary.sitesEmbedded + summary.sitesSkipped, word)
    assert.ok(summary.filesWalked >= 1, word)
    assert.ok(summary.filesInScope >= summary.filesWalked, word)
    assert.ok(summary.tagBits >= 1, word)
    assert.match(summary.releaseId, /^rel-[a-z2-7]{1,32}$/, summary.releaseId)
    assert.match(summary.createdAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  }
})

test('a plan predicts the release, file for file', async () => {
  const project = makeProject('plan-then-release')
  const before = treeBytes(project.root)
  const planned = await project.protect({ mode: 'plan' })
  assert.ok(planned.filesChanged.length > 0, 'a plan that names no file tells the caller nothing')
  const afterPlan = treeBytes(project.root)

  // The one thing a plan writes is its own document; every source file the plan
  // says it would change is the file it was before the call.
  const added = Object.keys(afterPlan).filter((rel) => !(rel in before))
  assert.deepEqual(added, [`.swp/private/plans/${planned.releaseId}.json`])
  for (const entry of planned.filesChanged) {
    assert.ok(before[entry.file].equals(afterPlan[entry.file]), `a plan rewrote ${entry.file}`)
  }
  assert.ok(planned.notes.some((n) => n.includes('no source file was modified')), planned.notes)

  const published = await project.protect({ mode: 'release', releaseId: planned.releaseId })
  assert.equal(published.releaseId, planned.releaseId)
  assert.deepEqual(published.sites, planned.sites)
  assert.deepEqual(published.filesChanged, planned.filesChanged)
  for (const entry of published.filesChanged) {
    const written = diskAt(project, entry.file)
    assert.ok(!written.equals(before[entry.file]), 'the rewrite is on disk')
    assert.equal(written.length, entry.bytesAfter, 'the plan predicted the disk')
  }
})

test('a dry run writes nothing anywhere and still gives a full account', async () => {
  const project = makeProject('dry-run')
  const before = treeBytes(project.root)
  const summary = await project.protect({ mode: 'dry-run' })
  assert.deepEqual(summary.artifacts, [], 'a dry run claims no artifact')
  assert.ok(summary.filesChanged.length > 0, 'the rehearsal still reports the rewrite it rehearsed')
  const after = treeBytes(project.root)
  for (const [rel, bytes] of Object.entries(before)) {
    assert.ok(after[rel]?.equals(bytes), `${rel} moved during a dry run`)
  }
  assert.deepEqual(Object.keys(after).sort(), Object.keys(before).sort(), 'a dry run created a file')
  assert.ok(summary.notes.some((n) => n.includes('Nothing was written')), summary.notes)
  // The history is the store's own answer: a dry run published no release, so
  // there is nothing to list.
  assert.deepEqual(project.session.releaseHistory(), [])
  // The id it names is one that does not exist, which is what the note says. The
  // store answers with the missing file: `release` takes a well-formed id, so
  // this is the read refusing, not the spelling.
  assert.throws(
    () => project.session.release(summary.releaseId),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'IO_ERROR')
      assert.match(error.message, /releases/, error.message)
      return true
    }
  )
})

test('a plan writes only a plan into the private store', async () => {
  const project = makeProject('plan-artifacts')
  const before = treeBytes(project.root)
  const summary = await project.protect({ mode: 'plan' })
  assert.ok(summary.artifacts.some((a) => a.startsWith('.swp/private/plans/')), summary.artifacts)
  assert.ok(!summary.artifacts.some((a) => a.startsWith('.swp/public/')), summary.artifacts)
  assert.ok(!summary.artifacts.some((a) => a.startsWith('.swp/private/manifests/')), summary.artifacts)
  assert.ok(summary.artifacts.every((a) => a.startsWith('.swp/')), 'no source file was claimed')
  // Store-relative and forward-slashed, on every platform.
  assert.ok(summary.artifacts.every((a) => !a.includes('\\')), summary.artifacts.join(','))
  assert.notDeepEqual(treeBytes(project.root), before, 'the plan itself is on disk')
  for (const entry of summary.filesChanged) {
    assert.ok(diskAt(project, entry.file).equals(before[entry.file]), 'the bytes it planned are not the bytes it wrote')
  }
})

test('a release writes source, records the plan and publishes a release', async () => {
  const project = makeProject('release')
  const summary = await project.protect({ mode: 'release' })
  const artifacts = summary.artifacts
  assert.ok(artifacts.some((a) => a.startsWith('.swp/private/plans/')), artifacts.join(','))
  assert.ok(artifacts.some((a) => a.startsWith('.swp/private/manifests/')), artifacts.join(','))
  assert.ok(artifacts.some((a) => a.startsWith('.swp/public/releases/')), artifacts.join(','))
  assert.ok(summary.filesChanged.length > 0, 'a release that rewrote nothing published nothing')
  for (const entry of summary.filesChanged) {
    assert.ok(artifacts.includes(entry.file), `${entry.file} was rewritten but not claimed`)
    assert.ok(entry.bytesAfter > entry.bytesBefore, entry.file)
    assert.ok(entry.sites >= 1, entry.file)
    assert.equal(bytesAt(project, entry.file), entry.bytesAfter, 'sizes are the files sizes')
  }
  const across = summary.filesChanged.reduce((total, entry) => total + entry.sites, 0)
  assert.equal(across, summary.sitesEmbedded)
  assert.equal(summary.filesWithSites, summary.filesChanged.length)
  assert.deepEqual(summary.languages, [...summary.languages].sort())
  assert.ok(summary.notes.some((n) => n.includes('modified in place')), summary.notes)
  assert.deepEqual(project.session.releases({ kind: 'all' }), [summary.releaseId])
})

test('protected source still parses, and keeps what surrounds the mark', async () => {
  const project = makeProject('still-parses')
  const summary = await project.protect({ mode: 'release' })
  const checked = spawnSync(process.execPath, ['--check', project.child('src', 'app.js')], {
    encoding: 'utf8'
  })
  assert.equal(checked.status, 0, checked.stderr)
  // The rewrite must not change what a program computes, and a watermark added
  // to one function must not delete the lines around it.
  for (const site of summary.sites) {
    const text = diskAt(project, site.file).toString('utf8')
    const original = SOURCE_TREE[site.file]
    assert.ok(text.split('\n').length >= original.split('\n').length, site.file)
    for (const [, name] of original.matchAll(/(?:def|function|const|LIMIT)\s+(\w+)/g)) {
      assert.ok(text.includes(name), `${name} disappeared from ${site.file}`)
    }
  }
})

test('the rewrite is a real change in the named place', async () => {
  const project = makeProject('real-change')
  const summary = await project.protect({ mode: 'release' })
  for (const site of summary.sites) {
    const entry = summary.filesChanged.find((f) => f.file === site.file)
    assert.ok(entry, `${site.file} carries a site but was not rewritten`)
    const raw = diskAt(project, site.file)
    // Bytes, not text: the files were written with this platform's line endings,
    // and a text read would report fewer bytes than the run measured on disk.
    assert.equal(raw.length, entry.bytesAfter)
    assert.ok(!raw.equals(Buffer.from(SOURCE_TREE[site.file])), `${site.file} is claimed and unchanged`)
  }
})

test('a refusal names a place and a reason, and the counts add up', async () => {
  const project = makeProject('refusals')
  const summary = await project.protect({ mode: 'release' })
  assert.ok(summary.refusals.length > 0, 'this fixture tree is built to leave a candidate refused')
  for (const refusal of summary.refusals) {
    assert.ok(refusal.file in SOURCE_TREE, 'a refusal names a file of the project')
    assert.ok(refusal.lineHint >= 1, refusal.file)
    assert.ok(typeof refusal.reason === 'string' && refusal.reason.length > 0)
  }
  const counts = summary.refusalCounts
  assert.deepEqual([...counts].map((c) => c.reason), [...counts.map((c) => c.reason)].sort())
  assert.deepEqual(
    counts.map((c) => c.reason).sort(),
    [...new Set(summary.refusals.map((r) => r.reason))].sort()
  )
  const total = counts.reduce((sum, c) => sum + c.count, 0)
  assert.equal(total, summary.refusals.length)
  assert.equal(total, summary.sitesSkipped)
  JSON.parse(JSON.stringify(counts))
})

test('refusal counts are sorted, so a log line from one run is comparable', async () => {
  // Two runs of one tree mint two release ids, and the constellation is keyed by
  // id, so their *counts* legitimately differ. What must not differ is the
  // ordering rule: a caller that prints this list prints the same shape every
  // run, which is the whole reason the SDK sorts it by token.
  const project = makeProject('stable-refusals')
  for (const summary of [await project.protect({ mode: 'release' }), await project.protect({ mode: 'release' })]) {
    const reasons = summary.refusalCounts.map((c) => c.reason)
    assert.deepEqual(reasons, [...reasons].sort())
    assert.equal(new Set(reasons).size, reasons.length, 'a token appears in two rows')
  }
})

test('sites are the plan rows without the keyed identities', async () => {
  const project = makeProject('site-rows')
  const summary = await project.protect({ mode: 'release' })
  const bounds = capabilities()
  assert.ok(summary.sites.length > 0)
  for (const site of summary.sites) {
    assert.ok(site.file.startsWith('src/'), site.file)
    assert.ok(site.lineHint >= 1)
    assert.ok(bounds.languageNames.includes(site.language), site.language)
    assert.ok(['ast', 'lexical'].includes(site.adapter), site.adapter)
    assert.ok(['integer', 'string'].includes(site.class), site.class)
    assert.ok(typeof site.family === 'string' && site.family.length > 0)
    assert.ok(site.width >= 1 && site.width <= bounds.tagBits.max, String(site.width))
    assert.ok([0, 1, 2, 3].includes(site.primary), String(site.primary))
    assert.deepEqual(Object.keys(site), [
      'file', 'lineHint', 'language', 'adapter', 'class', 'family', 'width', 'primary'
    ])
  }
  // The keyed half of the plan: every site identity the project's own store holds
  // is absent from the summary, whole or embedded in a longer string. A `40-bit`
  // hex id inside a path would be just as much of a leak as a field holding one.
  const printable = new Set(walkStrings(summary))
  const text = JSON.stringify(summary)
  for (const id of project.locationIds()) {
    assert.ok(!printable.has(id), `a keyed location crossed the boundary: ${id}`)
    assert.ok(!text.includes(id), `a keyed location is embedded in a printed string: ${id}`)
  }
})

test('no private field name appears in any summary form', async () => {
  const project = makeProject('private-fields')
  const summary = await project.protect({ mode: 'release' })
  assert.deepEqual(Object.keys(summary).sort(), [...SUMMARY_KEYS].sort())

  const keys = new Set(walkStrings(summary))
  for (const name of keys) {
    assert.ok(
      !PRIVATE_FIELD_NAMES.has(name),
      `the summary speaks a private field name: ${name}`
    )
  }
  // Compared against the real schema, not a list this suite invented: the plan
  // and the private manifest this run wrote do carry the keyed fields, and none
  // of the names they use for them appears in anything the summary can print.
  const summaryNames = new Set(Object.keys(summary))
  for (const row of [...summary.sites, ...summary.refusals, ...summary.filesChanged]) {
    for (const key of Object.keys(row)) summaryNames.add(key)
  }
  const privateNames = new Set()
  for (const { document } of project.privateDocuments()) {
    for (const value of Object.values(document)) {
      if (!Array.isArray(value)) continue
      for (const row of value) {
        if (row && typeof row === 'object') for (const key of Object.keys(row)) privateNames.add(key)
      }
    }
  }
  const withheld = [...privateNames].filter((name) => !summaryNames.has(name))
  for (const name of ['locations', 'grammar_path', 'original', 'rendered']) {
    assert.ok(withheld.includes(name), `expected ${name} to be withheld: ${withheld.sort()}`)
  }
  const printed = JSON.stringify(summary)
  for (const name of withheld) {
    assert.ok(!printed.includes(`"${name}"`), `a withheld field name was printed: ${name}`)
  }
})

test('the summary survives JSON, and the mode is the word in it', async () => {
  const project = makeProject('json-summary')
  const summary = await project.protect({ mode: 'release' })
  const parsed = JSON.parse(JSON.stringify(summary))
  assert.deepEqual(parsed, summary)
  assert.ok(typeof parsed.mode === 'string' && MODE_WORDS.includes(parsed.mode), parsed.mode)
  assert.deepEqual(Object.keys(parsed.filesChanged[0]).sort(), ['bytesAfter', 'bytesBefore', 'file', 'sites'])
  assert.ok(parsed.artifacts.every((a) => typeof a === 'string'))
})

test('the fingerprint is the hex digest it claims to be', async () => {
  const project = makeProject('fingerprint')
  const summary = await project.protect({ mode: 'release' })
  assert.match(summary.fingerprint, /^[0-9a-f]{64}$/, summary.fingerprint)
  // The level names the method the §16 fingerprint was taken by, so a later tree
  // can be compared under the rules that produced this one.
  assert.match(summary.fingerprintLevel, /^L[1-9]$/, summary.fingerprintLevel)
  const stored = project.session.release(summary.releaseId)
  assert.equal(stored.fingerprint, summary.fingerprint)
  assert.equal(stored.fingerprintLevel, summary.fingerprintLevel)
})

test('an explicit release id is honoured and a malformed one is refused', async () => {
  const project = makeProject('release-id')
  const chosen = 'rel-' + 'a'.repeat(13)
  const summary = await project.protect({ mode: 'release', releaseId: chosen })
  assert.equal(summary.releaseId, chosen)
  assert.deepEqual(project.session.releases({ kind: 'all' }), [chosen])

  const before = project.session.releases({ kind: 'all' })
  const error = thrown(() => project.protect({ mode: 'release', releaseId: 'not-a-release' }))
  assert.ok(error instanceof SwpError)
  assert.ok(errorCodes().includes(error.code), error.code)
  assert.equal(error.code, 'INVALID_MANIFEST')
  assert.match(error.message, /rel-/, error.message)
  assert.deepEqual(project.session.releases({ kind: 'all' }), before, 'the refused run wrote nothing')
})

test('protecting a published id again is refused, not duplicated', async () => {
  const project = makeProject('same-id')
  const chosen = 'rel-' + 'b'.repeat(13)
  await project.protect({ mode: 'release', releaseId: chosen })
  const error = await project.protect({ mode: 'release', releaseId: chosen }).catch((e) => e)
  assert.ok(error instanceof SwpError)
  assert.ok(errorCodes().includes(error.code), error.code)
  // A release id belongs to one constellation; reusing it would rewrite history.
  assert.match(error.message, /never replaces a release record/, error.message)
  assert.deepEqual(project.session.releases({ kind: 'all' }), [chosen])
})

test('revision is display metadata, and the record holds what was kept', async () => {
  const project = makeProject('revision')
  const summary = await project.protect({ mode: 'release', revision: '  build-42  ' })
  assert.equal(summary.revision, 'build-42')
  assert.equal(project.session.release(summary.releaseId).revision, 'build-42')

  const plain = await project.protect({ mode: 'release' })
  // Nothing was stated, so nothing is recorded: `undefined`, and the key is not
  // in the document at all rather than present with a null in it.
  assert.equal(plain.revision, undefined)
  assert.equal('revision' in plain, false)
  assert.equal(project.session.release(plain.releaseId).revision, undefined)

  // The SDK bounds the label rather than parsing it, and the refusal is the
  // record's own validation answering — including the empty string, which is a
  // label of zero length and not a way to say "no label".
  for (const unusable of ['', '   ', 'x'.repeat(201), 'a\tb']) {
    const error = await project.protect({ mode: 'release', revision: unusable }).catch((e) => e)
    assert.ok(error instanceof SwpError, JSON.stringify(unusable))
    assert.equal(error.code, 'INVALID_MANIFEST', JSON.stringify(unusable))
    assert.match(error.message, /revision/, error.message)
  }
})

test('an override reaches the run that reports it, and not the config file', async () => {
  const project = makeProject('site-budget')
  const bounds = capabilities()
  const stored = project.session.config.protect.targetSites
  const raised = Math.min(stored + 4, bounds.targetSites.max)
  const session = Session.open(project.root, { targetSites: raised, tagBits: bounds.tagBits.max })
  assert.equal(session.config.protect.targetSites, raised)
  assert.equal(session.config.protect.tagBits, bounds.tagBits.max)
  assert.equal(project.session.storedConfig().protect.targetSites, stored)
  assert.equal(project.session.config.protect.targetSites, stored, 'an open does not rewrite the file')

  const summary = await session.protectSummary({ mode: 'release' })
  project.observed.push(summary, ...summary.sites, ...summary.filesChanged, ...summary.refusals)
  assert.equal(summary.requestedSites, raised)
  assert.ok(raised >= summary.targetSites && summary.targetSites >= summary.sitesEmbedded)
  assert.equal(summary.sites.length, summary.sitesEmbedded)
  assert.equal(summary.tagBits, bounds.tagBits.max)
  assert.equal(project.session.releaseHistory().at(-1).releaseId, summary.releaseId)
})

test('a tree with no source in the targets is refused, not silently empty', async () => {
  const project = makeProject('no-source', { files: { 'docs/readme.md': 'prose\n'.repeat(10) } })
  const error = await project.protect({ mode: 'release' }).catch((e) => e)
  assert.ok(error instanceof SwpError)
  assert.equal(error.code, 'NO_SAFE_LOCATIONS')
  assert.match(error.message, /config\.toml/, error.message)
  assert.ok(error.rendered.includes(error.code), error.rendered)
})

test('the promise settles exactly once, and offers no way to cancel it', async () => {
  const project = makeProject('settles-once')
  const pending = project.protect({ mode: 'dry-run' })
  assert.equal(typeof pending.then, 'function')
  // A cancelled protection can leave a tree half-rewritten, so the surface
  // carries no cancellation handle: not a method on the promise, not a signal
  // in the options.
  assert.equal(pending.cancel, undefined)
  const first = await pending
  const second = await pending
  assert.equal(first, second, 'one call, one settled value')
  const both = await Promise.all([pending, pending])
  assert.equal(both[0], both[1])

  // The rejection half of the same promise, reached through the SDK rather than
  // through the argument parser: a second release onto an id that is already
  // published fails after the task has started.
  const chosen = 'rel-' + 'd'.repeat(13)
  await project.protect({ mode: 'release', releaseId: chosen })
  const failing = project.protect({ mode: 'release', releaseId: chosen })
  const a = await failing.catch((e) => e)
  const b = await failing.catch((e) => e)
  assert.ok(a instanceof SwpError)
  assert.equal(a, b, 'one call, one rejected value')
})

test('a protection runs off the JavaScript thread, so the loop keeps turning', async () => {
  // The AsyncTask is the reason the binding can protect a tree without freezing
  // the caller's event loop: a timer scheduled beside the call fires while the
  // run is still in flight.
  const project = makeProject('concurrent', { files: bigTree() })
  let ticked = 0
  const ticker = setInterval(() => {
    ticked += 1
  }, 2)
  const summary = await project.protect({ mode: 'dry-run' })
  clearInterval(ticker)
  assert.equal(summary.mode, 'dry-run')
  assert.ok(ticked > 0, 'the protection blocked the event loop')
})

function bigTree () {
  const files = {}
  for (let index = 0; index < 40; index += 1) {
    files[`src/mod${index}.js`] =
      `const base${index} = ${index * 31 + 7};\n` +
      Array.from({ length: 4 }, (_, step) =>
        `export function f${index}_${step}(x) {\n  let acc = x + ${step * 101 + index};\n` +
        `  for (let i = 0; i < ${step + 3}; i++) { acc = acc + i; }\n  return acc;\n}\n`
      ).join('\n')
  }
  return files
}

test('a returned path is the store spelling: project-relative and forward-slashed', async () => {
  const project = makeProject('returned-paths')
  const summary = await project.protect({ mode: 'release' })
  const root = plain(project.session.projectRoot)
  for (const entry of [...summary.sites, ...summary.filesChanged, ...summary.refusals]) {
    assert.ok(!entry.file.includes('\\'), entry.file)
    assert.ok(!entry.file.startsWith('/'), entry.file)
    assert.ok(project.child(...entry.file.split('/')).startsWith(root), entry.file)
  }
})
