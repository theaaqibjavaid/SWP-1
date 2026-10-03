// The project handle: what `init` leaves behind, and what a session reads about
// the project it is standing in.
//
// A `Session` is a resolved root, two parsed documents and the warnings that came
// with opening them. It is not a key holder — the root secret is loaded inside the
// operations that need it and dropped before they return — so the assertions here
// are about identity, config and the release history, and about the refusals a
// caller meets first: a directory that is not a project, a path that does not
// exist, and a project with nothing published yet.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { SWP_VERSION, Session, SwpError, capabilities, suggestSites } from '../index.js'
import { SOURCE_TREE, foreignTree, makeProject, makeProtected, plain, purgeAll } from './helpers.mjs'

after(purgeAll)

test('init draws a secret, measures the tree and writes the store', () => {
  const project = makeProject('init')
  const result = project.initResult

  assert.match(result.projectId, /^swp1-[a-z2-7]{16}$/, result.projectId)
  assert.equal(result.preExisting, false)
  assert.equal(result.secretState, 'created')
  // What the seal discloses is *where* the key went, never the key. `'plain'`
  // is the honest answer on a machine without DPAPI, so the assertion accepts
  // either spelling and the detail field carries which one it got.
  assert.ok(['dpapi', 'plain'].includes(result.secretScheme), result.secretScheme)
  assert.ok(result.secretHandle.length > 0)
  assert.equal(result.permissionsVerified, true, result.permissionsDetail)
  assert.ok(result.permissionsDetail.length > 0)
  assert.ok(['created', 'updated', 'already ignored', 'not written'].includes(result.gitignore), result.gitignore)
  assert.ok(result.created.includes('.swp/public/identity.json'), result.created.join(','))
  assert.ok(result.created.includes('.swp/private/root.key'))
  // Store-relative and forward-slashed in every report, on every platform.
  assert.ok(result.created.every((entry) => !entry.includes('\\')), result.created.join(','))
  // Every path the result names is a path that now exists: the disclosure and
  // the filesystem have to agree.
  for (const rel of result.created) {
    assert.ok(existsSync(join(project.root, ...rel.split('/'))), `${rel} was reported and not written`)
  }
  // `init` writes no source file; a run that rewrote the tree would be protection.
  assert.equal(project.text('src/app.js'), SOURCE_TREE['src/app.js'])
})

test('the measurement is the walk the adapter registry describes', () => {
  const { measurement } = makeProject('measure').initResult
  assert.equal(measurement.files, Object.keys(SOURCE_TREE).length)
  assert.ok(measurement.bytes > 0)
  assert.equal(typeof measurement.bytes, 'number')
  // A tree with one file per adapter is a three-language measurement, and the
  // per-directory half is what `[protect] targets` is chosen from.
  assert.deepEqual(Object.keys(measurement.languages).sort(), ['javascript', 'python', 'typescript'])
  assert.deepEqual(measurement.tops, { src: Object.keys(SOURCE_TREE).length })
  const total = Object.values(measurement.languages).reduce((a, b) => a + b, 0)
  assert.equal(total, measurement.files)
})

test('skipped counts what the walk declined, not what it pruned', () => {
  // The store `init` writes beside the sources declines one file of its own —
  // the `.gitignore` it just made has no language adapter — so the absolute
  // count belongs to the build rather than to this fixture. What a test can pin
  // is the difference between two trees that differ only in declined files:
  // prose with no adapter, and an empty file.
  const before = makeProject('measure-plain').initResult.measurement
  const after = makeProject('measure-extended', {
    files: { ...SOURCE_TREE, 'extra/notes.txt': 'prose, not source\n', 'extra/empty.js': '' }
  }).initResult.measurement

  assert.equal(after.files, before.files, 'a declined file is not a counted one')
  assert.equal(after.bytes, before.bytes, 'bytes is summed over admitted files')
  assert.equal(after.skipped, before.skipped + 2, `${before.skipped} then ${after.skipped}`)
  // The store directory is pruned on its own path, so it never reaches the
  // decline list at all: the delta above is the two files, not `.swp/`.
  assert.ok(before.skipped < 3, `the store itself is being reported as source: ${before.skipped}`)
})

test('the settings a run reports are the settings the config file holds', () => {
  const project = makeProject('settings')
  const { settings, measurement } = project.initResult
  assert.equal(settings.written, true)
  // A fresh project is sized from its own measurement, not from a constant.
  assert.equal(settings.suggestion, suggestSites(measurement.files))
  assert.equal(settings.targetSites, settings.suggestion)
  assert.deepEqual(settings.targets, ['src'])
  const bounds = capabilities().tagBits
  assert.ok(bounds.min <= settings.tagBits && settings.tagBits <= bounds.max)
  const onDisk = readFileSync(join(project.root, '.swp', 'config.toml'), 'utf8')
  assert.ok(onDisk.includes(`tag_bits = ${settings.tagBits}`), onDisk)
  assert.ok(onDisk.includes(`target_sites = ${settings.targetSites}`), onDisk)
})

test('re-running init keeps the identity and says the secret was not replaced', () => {
  const project = makeProject('again')
  const again = Session.init(project.root)
  assert.equal(again.result.projectId, project.initResult.projectId)
  assert.equal(again.result.preExisting, true)
  // The store already had a key: SWP never replaces a project secret, so the
  // freshly drawn one is discarded and this call reports the one it kept.
  assert.equal(again.result.secretState, 'kept')
  assert.equal(again.result.renamed, false)
  assert.deepEqual(again.session.identity, project.session.identity)
  assert.equal(
    again.session.identity.verification.verifyKeyB64,
    project.session.identity.verification.verifyKeyB64
  )
})

test('a conflicting label is a usage error unless the caller forces it', () => {
  const project = makeProject('label-two')
  assert.throws(
    () => Session.init(project.root, { name: 'something else' }),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'USAGE')
      // The refusal says how to override it, because the cost of the rename is
      // stated there too: reports written before it keep the old label.
      assert.match(error.message, /force/)
      return true
    }
  )
  const renamed = Session.init(project.root, { name: 'renamed', force: true })
  assert.equal(renamed.result.renamed, true)
  assert.equal(renamed.session.identity.displayName, 'renamed')
  assert.equal(renamed.result.projectId, project.initResult.projectId)
})

test('a label is display metadata, and the identity carries it back verbatim', () => {
  const name = "Quoted — 名称 v1.0's «tree»"
  const project = makeProject('label', { name })
  assert.equal(project.session.identity.displayName, name)
  assert.equal(project.initResult.displayName, name)
})

test('the identity document is the public half', () => {
  const project = makeProject('identity')
  const identity = project.session.identity
  assert.equal(identity.protocol, 'SWP-1')
  assert.equal(identity.schema, 1)
  assert.match(identity.projectId, /^swp1-[a-z2-7]{16}$/)
  assert.equal(identity.projectId, project.initResult.projectId)
  assert.equal(identity.displayName, 'identity')
  assert.match(identity.createdAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  assert.equal(identity.verification.algorithm, 'ed25519')
  // Public by design: a release is verified against this key, so a binding that
  // could not print it could not check a signature. 32 bytes, base64.
  assert.equal(Buffer.from(identity.verification.verifyKeyB64, 'base64').length, 32)
  assert.equal(identity.generator.swpVersion, SWP_VERSION)
  assert.ok(identity.generator.generator.length > 0)
  assert.equal(identity.canonicalizerVersion, capabilities().canonicalizerVersion)
  JSON.parse(JSON.stringify(identity))
})

test('projectRoot names the directory the session is standing in', () => {
  const project = makeProject('rooted')
  // The store's own canonical spelling, verbatim prefix and all; the caller's
  // spelling is what the refusal messages use, and the two are compared through
  // `plain()` rather than as strings.
  assert.equal(plain(project.session.projectRoot), plain(project.root))
})

test('a directory that is not a project refuses, and says which one', () => {
  const foreign = foreignTree()
  assert.throws(
    () => Session.open(foreign),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'NOT_PROTECTED')
      assert.ok(error.message.includes('no .swp'), error.message)
      return true
    }
  )
})

test('a path that does not exist is refused by the spelling it was given', () => {
  const project = makeProject('missing')
  const away = join(project.root, 'no-such-directory')
  assert.throws(
    () => Session.open(away),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'PATH_REJECTED')
      assert.ok(error.message.includes(away), error.message)
      return true
    }
  )
})

test('discover walks up to the root and reports the same project', () => {
  const project = makeProject('discovered')
  const found = Session.discover(join(project.root, 'src'))
  assert.equal(found.identity.projectId, project.session.identity.projectId)
  assert.equal(plain(found.projectRoot), plain(project.session.projectRoot))
})

test('discover finds no project above a plain tree', () => {
  assert.throws(
    () => Session.discover(foreignTree()),
    (error) => error instanceof SwpError && error.code === 'NOT_PROTECTED'
  )
})

test('the config in force is the stored config plus the overrides on this session', () => {
  const project = makeProject('overrides', { overrides: { targetSites: 8, tagBits: 3, excludes: ['vendor'] } })
  const inForce = project.session.config
  const stored = project.session.storedConfig()

  assert.equal(inForce.protect.targetSites, 8)
  assert.equal(inForce.protect.tagBits, 3)
  assert.deepEqual(inForce.protect.excludes, ['vendor'])
  assert.deepEqual(inForce.protect.targets, ['src'])
  // The file on disk is the operator's, and a session's override must not read as
  // though it had been written there.
  assert.deepEqual(stored.protect.excludes, [])
  assert.notEqual(stored.protect.targetSites, 8)
  assert.equal(inForce.protocol, stored.protocol)
  assert.equal(inForce.limits.maxFiles, stored.limits.maxFiles)
  assert.deepEqual(project.session.warnings, [])
})

test('an override outside the range this build allows is refused at the call that makes it', () => {
  const project = makeProject('override-range')
  const floor = capabilities().targetSites.min
  assert.throws(
    () => Session.open(project.root, { targetSites: floor - 1 }),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'USAGE')
      assert.match(error.message, /target_sites/)
      return true
    }
  )
})

test('the ceilings cross as numbers, not BigInt', () => {
  const limits = makeProject('limits').session.limits
  // Every wide value in the surface is a `number` so a returned document stays
  // JSON-stringifyable for the leak sweep; a BigInt would throw on `stringify`.
  for (const [name, value] of Object.entries(limits)) {
    assert.equal(typeof value, 'number', `${name} is ${typeof value}`)
    assert.ok(Number.isFinite(value) && value > 0, `${name} = ${value}`)
  }
  assert.ok(limits.maxFileBytes < 2 ** 53)
  JSON.parse(JSON.stringify(limits))
})

test('a project with nothing published says so, in the code the CLI uses', () => {
  const session = makeProject('history').session
  assert.deepEqual(session.releaseHistory(), [])
  assert.deepEqual(session.reports(), [])
  for (const call of [
    () => session.releases({ kind: 'all' }),
    () => session.releases({ kind: 'latest' }),
    () => session.oneRelease({ kind: 'latest' }),
    () => session.verify()
  ]) {
    assert.throws(call, (error) => error instanceof SwpError && error.code === 'NOT_PROTECTED')
  }
})

test('the release record is the run that wrote it, read back from the store', async () => {
  const project = await makeProtected('history-two')
  const session = project.session
  const summary = project.summary
  const ids = session.releases({ kind: 'all' })
  assert.deepEqual(ids, [summary.releaseId])
  assert.deepEqual(ids, session.releases({ kind: 'latest' }))
  assert.equal(session.oneRelease({ kind: 'latest' }), ids[0])

  const record = session.release(ids[0])
  assert.equal(record.releaseId, ids[0])
  assert.equal(record.projectId, summary.projectId)
  assert.equal(record.projectId, session.identity.projectId)
  assert.equal(record.protocol, 'SWP-1')
  assert.ok(record.schema >= 1, String(record.schema))
  assert.match(record.fingerprint, /^[0-9a-f]{64}$/)
  assert.match(record.privateManifestDigest, /^[0-9a-f]{64}$/)
  assert.ok(record.signature.length > 0)
  // The public record answers for the run it came out of: same tree hash, same
  // constellation size, same tag width. A binding that recomposed any of these
  // would be grading the release rather than reporting it.
  assert.equal(record.fingerprint, summary.fingerprint)
  assert.equal(record.fingerprintLevel, summary.fingerprintLevel)
  assert.equal(record.createdAt, summary.createdAt)
  assert.equal(record.watermark.tagBits, summary.tagBits)
  assert.equal(record.watermark.targetSites, summary.targetSites)
  assert.equal(record.watermark.sitesEmbedded, summary.sitesEmbedded)
  assert.equal(record.watermark.sitesSkipped, summary.sitesSkipped)
  assert.equal(record.watermark.canonicalizerVersion, capabilities().canonicalizerVersion)
  assert.ok(record.watermark.adapters.length > 0, 'a release with no adapter row claims nothing')
  for (const use of record.watermark.adapters) {
    assert.ok(capabilities().languageNames.includes(use.language), use.language)
    assert.ok(use.files > 0, use.language)
  }
  // The record answers for itself: `validationError` is the Rust document's
  // `validate()` answering, and an `undefined` here is the absence of a reason
  // to stop.
  assert.equal(record.validationError, undefined)
  assert.deepEqual(session.releaseHistory().map((r) => r.releaseId), ids)
  JSON.parse(JSON.stringify(record))
})

test('two releases are listed in the store order, and latest means the newest record', async () => {
  // `releases()` comes back as the store keeps them and `releaseHistory()` is
  // sorted by the recorded time, with the id breaking a tie inside one second.
  // A test that confused the two passes on a single-release project, which is
  // exactly the case that does not exercise it.
  const project = makeProject('two-releases')
  const first = await project.protectMode('release')
  const second = await project.protectMode('release')
  assert.notEqual(second.releaseId, first.releaseId)

  const session = project.session
  const ids = session.releases({ kind: 'all' })
  assert.deepEqual([...ids].sort(), [first.releaseId, second.releaseId].sort())
  const history = session.releaseHistory()
  assert.deepEqual(history.map((r) => r.releaseId).sort(), ids.slice().sort())
  const stamps = history.map((r) => r.createdAt)
  assert.deepEqual(stamps, [...stamps].sort(), 'history is oldest-first, by the recorded time')
  assert.equal(session.oneRelease({ kind: 'latest' }), history.at(-1).releaseId)
  assert.deepEqual(session.releases({ kind: 'ids', ids: [first.releaseId] }), [first.releaseId])
  assert.equal(session.oneRelease({ kind: 'ids', ids: [first.releaseId] }), first.releaseId)
})

test('a target outside the project is refused when the session is built', () => {
  const project = makeProject('escape')
  const elsewhere = makeProject('elsewhere').root
  assert.throws(
    () => Session.open(project.root, { targets: [elsewhere] }),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'USAGE')
      // Containment is checked before anything is written, and the message names
      // the CLI's own flag so the reader recognises the rule.
      assert.match(error.message, /--target/, error.message)
      return true
    }
  )
})

test('with nothing overridden, the config in force is the stored one', () => {
  const session = makeProject('config').session
  const inForce = session.config
  const stored = session.storedConfig()
  assert.deepEqual(inForce, stored)
  assert.equal(inForce.protocol, 'SWP-1')
  assert.deepEqual(inForce.protect.targets, ['src'])
  assert.deepEqual(inForce.limits, session.limits)
  for (const warning of session.warnings) {
    assert.ok(typeof warning === 'string' && warning.length > 0, String(warning))
  }
})

test('a release id that is not a release id is refused before anything is read', () => {
  const session = makeProject('bad-id').session
  assert.throws(
    () => session.release('nope'),
    (error) => error instanceof SwpError && error.code === 'INVALID_MANIFEST'
  )
  assert.throws(
    () => session.readReport('nope'),
    (error) => error instanceof SwpError && error.code === 'USAGE'
  )
})

test('a selection of ids is the list the caller gave, and an empty one selects nothing', async () => {
  const project = await makeProtected('selection')
  const [only] = project.session.releases({ kind: 'all' })
  assert.deepEqual(project.session.releases({ kind: 'ids', ids: [only] }), [only])
  assert.deepEqual(project.session.releases({ kind: 'ids', ids: [] }), [])
  // A well-formed id this project never published is a refusal that names what
  // does exist, not an empty answer a caller would read as "no releases".
  assert.throws(
    () => project.session.releases({ kind: 'ids', ids: ['rel-' + 'q'.repeat(13)] }),
    (error) => {
      assert.ok(error instanceof SwpError)
      assert.equal(error.code, 'NOT_PROTECTED')
      assert.match(error.message, /It has/, error.message)
      return true
    }
  )
  assert.throws(
    () => project.session.releases({ kind: 'nope' }),
    (error) => error instanceof SwpError && error.code === 'USAGE'
  )
})

test('toString names the root and the project id, and nothing else', () => {
  const project = makeProject('tostring')
  const line = project.session.toString()
  assert.match(line, /^Session\(projectRoot='/, line)
  assert.ok(line.includes(project.session.identity.projectId))
  assert.ok(!line.includes('root.key'))
})

test('two sessions on one project agree', async () => {
  const project = await makeProtected('twins')
  const other = Session.open(project.root)
  assert.equal(other.identity.projectId, project.session.identity.projectId)
  assert.deepEqual(other.identity, project.session.identity)
  assert.deepEqual(other.config, project.session.config)
  assert.deepEqual(other.limits, project.session.limits)
  assert.equal(other.verify().verdict, project.session.verify().verdict)
  assert.deepEqual(other.releases({ kind: 'all' }), project.session.releases({ kind: 'all' }))
  assert.equal(other.toString(), project.session.toString())
})
