// Failure: one exception class, six fields, and the codes the SDK already defines.
//
// The contract these cases check is the one docs/SDK_API.md §8 states: every
// failure the SDK reports crosses the boundary as a `SwpError` carrying `code`,
// `message`, `path`, `causedBy`, `nextStep` and `rendered`. There is no subclass
// per code, so a caller branches on `code` — and every case here produces a real
// refusal from a real store rather than a hand-built error object, because an
// envelope nobody raised is an envelope nobody tested.
//
// Three boundaries are checked against each other:
//
// * a *semantic* refusal — an id with the wrong shape, a target outside the
//   project, a report that was never saved — arrives as a `SwpError` with a code
//   from `errorCodes()`;
// * whether it *throws* or *rejects* is decided by which half of the binding
//   refused: an argument this package interprets before the SDK is called is
//   thrown even from an async method, and an SDK failure is rejected, so both
//   halves are exercised here and their envelopes compared;
// * a *type or range* mistake is napi's own complaint — `Error` with a shape code
//   like `StringExpected`, and no envelope fields at all. The binding does not
//   translate the host's objection to a call that never reached Rust, and a
//   caller must not read `error.path` off one.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { Report, Session, SwpError, errorCodes } from '../index.js'
import { makeProtected, makeProject, purgeAll, stageArtifact } from './helpers.mjs'

after(purgeAll)

/** The six fields §8 declares, and nothing else a caller may read. */
const ENVELOPE = ['code', 'message', 'path', 'causedBy', 'nextStep', 'rendered']

/** Every field on the object: the six, plus the two `Error` itself brings. */
const OWN_FIELDS = [...ENVELOPE, 'name', 'stack'].sort()

/** The unknown-but-well-shaped release id: the store, not the parser, refuses it. */
const NEVER_PUBLISHED = `rel-${'z'.repeat(13)}`

/**
 * Run a call, and say how it failed.
 *
 * `rejected` distinguishes the two halves: a call that got as far as building a
 * promise failed inside it, and one that threw before returning anything failed
 * in the binding's own reading of the arguments.
 */
async function raised (run) {
  let pending
  try {
    pending = run()
  } catch (error) {
    return { error, rejected: false }
  }
  if (pending !== null && typeof pending === 'object' && typeof pending.then === 'function') {
    try {
      await pending
      return { error: null, rejected: false }
    } catch (error) {
      return { error, rejected: true }
    }
  }
  return { error: null, rejected: false }
}

/** A project, and every failure this binding can raise on it, already raised. */
async function collected () {
  const project = await makeProtected('errors-envelope')
  const staged = stageArtifact(project, 'errors')
  const cases = []

  async function capture (expected, label, run) {
    const { error, rejected } = await raised(run)
    assert.ok(error instanceof SwpError, `${label}: expected a SwpError, got ${String(error)}`)
    assert.equal(error.code, expected, `${label}: ${error.code} — ${error.message}`)
    cases.push({ code: expected, label, error, rejected })
  }

  await capture('PATH_REJECTED', 'open a directory that was never made', () => Session.open(join(project.root, 'never-made')))
  await capture('NOT_PROTECTED', 'open a directory with no store', () => Session.open(project.child('src')))
  await capture('USAGE', 'open with a width out of range', () => Session.open(project.root, { tagBits: 99 }))
  await capture('USAGE', 'open with a target outside the project', () => Session.open(project.root, { targets: ['../outside'] }))
  await capture('USAGE', 'read a report that was never saved', () => project.session.readReport('no-such-report'))
  await capture('INVALID_MANIFEST', 'select an id that is not an id', () => project.session.releases({ kind: 'ids', ids: ['nope'] }))
  await capture('INVALID_MANIFEST', 'protect onto an id that is not an id', () => project.session.protectSummary({ mode: 'release', releaseId: 'bad' }))
  await capture('USAGE', 'protect in a mode that is not one of the three', () => project.session.protectSummary({ mode: 'nope' }))
  await capture('PROTOCOL_VERSION_UNSUPPORTED', 'read a document from another schema', () => Report.fromJson('{"schema":"SWP-1-report-v1","protocol":"SWP-1"}'))
  await capture('INVALID_MANIFEST', 'read something that is not a document', () => Report.fromJson('not json at all'))
  await capture('IO_ERROR', 'scan a candidate that cannot be read', () => project.scan(join(project.root, 'also-never-made')))
  await capture('NOT_PROTECTED', 'scan against a release that was never published', () => project.scan(staged, { releases: { kind: 'ids', ids: [NEVER_PUBLISHED] } }))

  return { project, cases }
}

let collectedOnce = null
const refusals = async () => {
  if (collectedOnce === null) collectedOnce = await collected()
  return collectedOnce
}

test('every failure is the same class with the same six fields', async () => {
  const { cases } = await refusals()
  assert.ok(cases.length >= 10)
  for (const { code, error } of cases) {
    assert.equal(error.constructor, SwpError, 'one class per §8, not a subclass per code')
    assert.ok(error instanceof Error)
    assert.equal(error.name, 'SwpError')
    assert.equal(error.code, code)
    assert.ok(error.message.length > 0)
    assert.ok(error.nextStep.length > 0, `${code} arrives without advice`)
    assert.ok(error.path === null || typeof error.path === 'string')
    assert.ok(error.causedBy === null || typeof error.causedBy === 'string')
    // Both nulls are present as keys, so a printed envelope never depends on
    // whether a field happened to be filled in.
    assert.deepEqual(Object.getOwnPropertyNames(error).sort(), OWN_FIELDS)
  }
})

test('the message is the Error message, and rendered is the block a terminal prints', async () => {
  const { cases } = await refusals()
  for (const { code, error } of cases) {
    assert.equal(String(error), `SwpError: ${error.message}`)
    assert.ok(error.stack.startsWith(`SwpError: ${error.message}`), code)
    // `{code} — {message}`, then the cause if there is one, then the next step.
    const lines = error.rendered.split('\n')
    assert.equal(lines[0], `${code} — ${error.message}`)
    assert.equal(lines[lines.length - 1], `  next step: ${error.nextStep}`)
    assert.ok(error.rendered.startsWith(`${error.code} `))
    const causes = lines.filter((line) => line.startsWith('  caused by: '))
    assert.equal(causes.length > 0, error.causedBy !== null, code)
    for (const line of causes) assert.equal(line, `  caused by: ${error.causedBy}`)
  }
})

test('thrown or rejected, the envelope is the same object', async () => {
  // The binding's own argument checks throw even from an async method; the SDK's
  // refusals reject. A caller must be able to catch both with one `catch`.
  const { project, cases } = await refusals()
  const thrown = cases.filter((c) => !c.rejected)
  const rejected = cases.filter((c) => c.rejected)
  assert.ok(thrown.length > 0 && rejected.length > 0, 'the suite lost one half of the split')
  assert.deepEqual(
    rejected.map((c) => c.code).sort(),
    ['IO_ERROR', 'NOT_PROTECTED'],
    'the two async operations are the only rejections here'
  )
  for (const { error } of [...thrown, ...rejected]) {
    assert.ok(error instanceof SwpError)
    assert.deepEqual(Object.getOwnPropertyNames(error).sort(), OWN_FIELDS)
  }
  // The rejection is the same class the sync path raises, not a wrapper: this is
  // the value a `.catch` receives, with the whole §8 envelope on it.
  const missing = await project.scan(join(project.root, 'nothing-here')).catch((error) => error)
  assert.ok(missing instanceof SwpError, String(missing))
  assert.equal(missing.code, 'IO_ERROR')
  assert.ok(missing.nextStep.length > 0)
})

test('a path-naming failure says which path, store-relative and forward-slashed', async () => {
  const { project } = await refusals()
  const named = await raised(() => project.session.readReport('nope'))
  assert.equal(named.error.code, 'USAGE')
  assert.equal(named.error.path, '.swp/private/reports/nope.json')
  assert.ok(!named.error.path.includes('\\'), named.error.path)
  assert.ok(named.error.message.includes('nope'), named.error.message)

  // The field is `null`, not absent, when the failure named nothing in the store:
  // an unreadable caller path is not a store entry.
  const unnamed = await raised(() => Session.open(join(project.root, 'nope-nope')))
  assert.equal(unnamed.error.path, null)
  assert.ok('path' in unnamed.error)
})

test('a cause is carried when the SDK had one to give', async () => {
  // A stray file in the public releases directory is judged by the same reader as
  // a corrupt record, and that reader says where it found the name.
  const project = await makeProtected('errors-cause')
  writeFileSync(join(project.root, '.swp', 'public', 'releases', 'README.json'), '{}', 'utf8')
  const { error } = await raised(() => Session.open(project.root).releaseHistory())
  assert.ok(error instanceof SwpError, String(error))
  assert.equal(error.code, 'INVALID_MANIFEST')
  assert.ok(error.causedBy.startsWith('a release file in '), String(error.causedBy))
  assert.ok(error.causedBy.includes('has a name that is not a release id'), error.causedBy)
  assert.ok(error.rendered.includes(`  caused by: ${error.causedBy}`), error.rendered)
  // The advice is the sentence this code always gets: the cause is a second line,
  // not a different taxonomy.
  const { error: bare } = await raised(() => project.session.releases({ kind: 'ids', ids: ['nope'] }))
  assert.equal(bare.code, 'INVALID_MANIFEST')
  assert.equal(bare.causedBy, null)
  assert.equal(error.nextStep, bare.nextStep)
})

test('codes come from the table the module publishes', async () => {
  const { cases } = await refusals()
  const declared = new Set(errorCodes())
  assert.ok(['USAGE', 'NOT_PROTECTED', 'IO_ERROR', 'INTERNAL_ERROR'].every((code) => declared.has(code)))
  const codes = new Set(cases.map((c) => c.code))
  for (const code of codes) assert.ok(declared.has(code), code)
  assert.ok(!codes.has('INTERNAL_ERROR'), 'a defect in SWP-1 is not a failure mode this suite can produce on purpose')
  // Each code's advice is its own: the table is not one string repeated, and two
  // refusals that mean different things do not point the caller at the same step.
  const adviceFor = (code) => cases.filter((c) => c.code === code).map((c) => c.error.nextStep)
  assert.ok(codes.size >= 5, [...codes].join(','))
  assert.ok(new Set(adviceFor('USAGE')).size === 1, 'one code, one piece of advice')
  assert.notEqual(adviceFor('USAGE')[0], adviceFor('NOT_PROTECTED')[0])
})

test('a value no Rust type can hold is the host’s own complaint', async () => {
  // `tag_bits: 400` cannot be a `u8` at all, so no Rust code runs and the caller
  // gets napi's conversion error. `tag_bits: 99` fits the type and is refused by
  // the settings validator with a code — see the table above.
  const project = makeProject('errors-napi')
  const cases = [
    ['open a number', () => Session.open(123), /into rust type `String`/],
    ['open null', () => Session.open(null), /into rust type `String`/],
    ['open nothing', () => Session.open(), /into rust type `String`/],
    ['open bytes', () => Session.open(Buffer.from('some/bytes')), /into rust type `String`/],
    ['a width over u8', () => Session.open(project.root, { tagBits: 400 }), /Overrides\.tagBits/],
    ['options that are no object', () => project.session.protectSummary(), /undefined or null/]
  ]
  const declared = new Set(errorCodes())
  for (const [label, run, message] of cases) {
    const { error } = await raised(run)
    assert.ok(error, label)
    assert.ok(!(error instanceof SwpError), `${label}: ${error.constructor.name} is an SWP-1 envelope`)
    assert.match(error.message, message, label)
    assert.ok(!declared.has(error.code), `${label}: ${error.code} is an SWP-1 code`)
    // No envelope is invented for a call that never reached Rust: a caller that
    // reads `error.path` off this object gets `undefined`, not a store entry.
    for (const field of ENVELOPE.filter((name) => name !== 'code' && name !== 'message')) {
      assert.equal(error[field], undefined, `${label} carried ${field}`)
    }
  }
})

test('an error can be caught, logged and re-thrown', async () => {
  const { project } = await refusals()
  const { error } = await raised(() => Session.open(project.child('src')))
  assert.equal(error.code, 'NOT_PROTECTED')
  // The refusal names the directory it looked in; walking up from there finds the
  // store, so the two calls agree about where the project is.
  assert.deepEqual(Session.discover(project.child('src')).identity, project.session.identity)
  try {
    throw error
  } catch (again) {
    assert.equal(again, error, 're-throwing hands back the same envelope')
    assert.equal(again.code, error.code)
    assert.equal(again.rendered, error.rendered)
  }
  assert.ok(JSON.stringify(Object.fromEntries(ENVELOPE.map((field) => [field, error[field]]))))
  // A refusal that happened while reading arguments left the project untouched.
  assert.equal(project.session.releaseHistory().length, 1)
})

test('no failure text carries keyed material', async () => {
  // The message is what a user reads; it must not be where a secret surfaces.
  const { project, cases } = await refusals()
  const needles = new Set([...project.secretStrings(), ...project.locationIds()])
  assert.ok(needles.size > 0, 'a sweep against an empty needle set proves nothing')
  for (const { code, error } of cases) {
    const text = ENVELOPE.map((field) => error[field] ?? '').join('\n') + String(error)
    for (const needle of needles) {
      assert.ok(!text.includes(needle), `${code} leaked ${needle.slice(0, 8)}…`)
    }
    assert.ok(!text.includes('root.key'), code)
    assert.ok(!text.toUpperCase().includes('PRIVATE KEY'), code)
  }
})
