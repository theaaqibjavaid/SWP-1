// Nothing a JavaScript caller can read is keyed material, a site identity, or the
// private half.
//
// This is the binding's version of the Rust `secret_leak` suite, and it works the
// same way: it does not check that the code *avoids* certain variables. It takes
// every object a real run handed back and prints it — `String()`, `JSON.stringify()`,
// `util.inspect()` with getters turned on, and each `toJson()` / `toText()` the object
// offers — then looks for needles. The needles are read off the project's own store:
// the sealed root secret in both of its spellings, and the keyed site identities the
// private plan holds. Neither set is invented here, which is what makes their absence
// meaningful rather than tautological.
//
// Four claims sit behind the sweeps:
//
// * a value that is keyed never crosses — no root secret, no derived rendering of it,
//   no location id, and no field value the private documents keep under a keyed name;
// * a document that is private never crosses: the plan's and the manifest's field
//   names are not the shape of anything the binding offers, because the binding reads
//   the summaries `swp-sdk` hands back and builds nothing itself;
// * a *name* for the private half never crosses: the package exports no class, getter
//   or method that would be an accessor for a store, a secret or a plan — including
//   the unsanitized `protect` ADR-0001 settled against;
// * a private path is named only by the two lists that exist to disclose it —
//   `InitResult.created` and `ProtectSummary.artifacts`, the same lists `swp init` and
//   `swp protect` print in their JSON — and by nothing else.
//
// `util.inspect` is in the list on purpose. It is what `console.log` calls, and with
// `getters: true` it walks the prototype of every bound class — which is the shape a
// leaking `toString()` would surface in somebody's log without their meaning to.
//
// The positive control is part of the test. A sweep whose needle sets were empty would
// pass on a binding that leaked everything, so every case first asserts that this
// project really does hold ids and secret renderings, and that the sweep ran over a
// great many characters.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { inspect } from 'node:util'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'

import { Session, SwpError, banner, capabilities, errorCodes, reportStem } from '../index.js'
import * as api from '../index.js'
import { PRIVATE_FIELD_NAMES, makeProject, purgeAll } from './helpers.mjs'

after(purgeAll)

/** Field names the private half uses for a value it keeps to itself. */
const KEYED_FIELDS = new Set([
  'locations',
  'location_id',
  'location_ids',
  'fragment_tag',
  'expected_tag',
  'grammar_path',
  'root_secret',
  'secret_bytes',
  'signature'
])

/**
 * The identifiers the boundary reserves for the private crates.
 *
 * Matched exactly, so a documented name that merely contains one of these words is
 * not accused — `protectSummary` is the sanitized half of ADR-0001, and `release()`
 * is the public record.
 */
const FORBIDDEN_NAMES = new Set([
  'RootSecret',
  'SecretBytes',
  'ManifestKeys',
  'ReleaseIndex',
  'CandidateRelease',
  'Protection',
  'Plan',
  'PlannedSite',
  'SkippedSite',
  'LocationId',
  'Store',
  'open_store',
  'store',
  'protect',
  'fragment_tag',
  'expected_tag',
  'root_key',
  'secret'
])

/** Names the package does offer that a forbidden word must not be confused with. */
const OFFERED = ['protectSummary', 'release', 'releaseHistory', 'releases', 'StoredReport', 'readReport']

/**
 * Directories whose documents are unsigned intermediate state: the binding is not
 * given them, so nothing it prints should send a caller looking for them.
 * `.swp/private/reports/` is deliberately absent — `verify({save})` and
 * `scan({save})` name where they wrote, and a path is not the document.
 */
const PRIVATE_DIRS = ['.swp/private/plans', '.swp/private/manifests', '.swp/private/root.key']

/** One project taken through init, protect, verify, scan and the store's listings. */
async function runEverything () {
  const project = makeProject('leak')
  await project.protectMode('release')
  await project.protectMode('plan')
  project.verify({ save: true })
  const scanned = await project.scan(project.root, { save: true })
  const latest = project.session.releases({ kind: 'latest' })[0]
  project.observed.push(
    project.session.identity,
    project.session.config,
    project.session.limits,
    project.session.warnings,
    project.session.storedConfig(),
    project.session.release(latest),
    project.session.readReport(reportStem(scanned.saved.path)),
    scanned.report,
    scanned.saved,
    scanned.sites,
    capabilities(),
    errorCodes(),
    banner()
  )
  project.observed.push(...project.session.releaseHistory())
  // A pending promise is not a printed form: Node's inspector reaches through a
  // settled one and prints its value. So the inventory is awaited before it is
  // swept, and every value is read in the only form a caller can print it in.
  project.observed = await Promise.all(project.observed)
  return project
}

let runOnce = null
const runEverythingOnce = async () => {
  if (runOnce === null) runOnce = await runEverything()
  return runOnce
}

/**
 * Everything a caller can print off one value, plus every field name it touches.
 *
 * Strings are collected as texts; a bound class contributes its `toString`, its
 * `inspect`ion and the value of every accessor on its prototype; a plain object
 * contributes each of its keys to `keyNames` and recurses.
 */
function collect (value, path, texts, keyNames) {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    texts.push([path, String(value)])
    return
  }
  if (value === null || value === undefined) return
  if (Array.isArray(value)) {
    value.forEach((nested, index) => collect(nested, `${path}[${index}]`, texts, keyNames))
    return
  }
  if (typeof value !== 'object') return
  const proto = Object.getPrototypeOf(value)
  if (proto === Object.prototype || proto === null) {
    for (const [name, nested] of Object.entries(value)) {
      keyNames.add(name)
      collect(nested, `${path}.${name}`, texts, keyNames)
    }
    return
  }
  texts.push([`${path} (String)`, String(value)])
  texts.push([`${path} (inspect)`, inspect(value, { depth: 4, getters: true, breakLength: Infinity })])
  for (const name of Object.getOwnPropertyNames(proto)) {
    if (name === 'constructor') continue
    keyNames.add(name)
    const descriptor = Object.getOwnPropertyDescriptor(proto, name)
    if (descriptor?.get !== undefined) {
      collect(value[name], `${path}.${name}`, texts, keyNames)
      continue
    }
    if (typeof descriptor?.value !== 'function') continue
    // The methods a caller reaches for to print a document, and no others: an
    // argument-taking method is not a rendering of the value it sits on.
    if (name === 'toJson') texts.push([`${path}.toJson()`, value.toJson()])
    if (name === 'toText') texts.push([`${path}.toText()`, value.toText()], [`${path}.toText(true)`, value.toText(true)])
    if (name === 'toTextItems') texts.push([`${path}.toTextItems(1)`, value.toTextItems(1)])
    if (name === 'exitCode') texts.push([`${path}.exitCode()`, String(value.exitCode())])
  }
}

/**
 * The values whose documented job is to disclose what a run wrote.
 *
 * `swp init` and `swp protect` print the same paths in their JSON, so a private
 * path may appear here and nowhere else. Both the two lists and the individual
 * strings inside them count, because the fixture records what a run returned —
 * including its path rows — rather than a curated subset.
 */
function disclosing (project) {
  const values = new Set()
  const carriers = [project.initResult, ...project.observed.filter((value) => Array.isArray(value?.artifacts) || Array.isArray(value?.created))]
  for (const carrier of carriers) {
    values.add(carrier)
    for (const entry of [...(carrier.created ?? []), ...(carrier.artifacts ?? [])]) values.add(entry)
  }
  return values
}

/** `(where it came from, printed text)` for everything this project handed back. */
function sweep (project, { skipDisclosing = false } = {}) {
  const skipped = disclosing(project)
  const texts = []
  const keyNames = new Set()
  const roots = [[project.session, 'Session'], [project.initResult, 'InitResult'], ...project.observed.map((value, index) => [value, `#${index}`])]
  for (const [value, index] of roots) {
    if (value === null || value === undefined) continue
    if (skipDisclosing && skipped.has(value)) continue
    collect(value, `${value?.constructor?.name ?? 'value'}${index}`, texts, keyNames)
  }
  assert.ok(texts.length >= 2 * (project.observed.length + 2), `${texts.length} printed forms for ${project.observed.length} values`)
  return { texts, keyNames }
}

/** The strings that must never appear in anything JavaScript can print. */
function needles (project) {
  const out = new Set([...project.secretStrings()].filter((s) => s.length >= 8))
  for (const id of project.locationIds()) if (id.length >= 8) out.add(id)
  assert.ok(out.size > 0, 'the store holds no secret rendering and no site id: nothing was tested')
  return out
}

/** Every value the private documents keep under a keyed field name. */
function keyedValues (project) {
  const found = new Set()
  const walk = (value, key) => {
    if (Array.isArray(value)) {
      for (const nested of value) walk(nested, key)
    } else if (value !== null && typeof value === 'object') {
      for (const [name, nested] of Object.entries(value)) walk(nested, name)
    } else if (typeof value === 'string' && KEYED_FIELDS.has(key) && value.length >= 8) {
      found.add(value)
    }
  }
  const documents = project.privateDocuments()
  assert.ok(documents.length > 0, 'the run left no private document, so this sweep read nothing')
  for (const { document } of documents) walk(document, null)
  assert.ok(found.size > 0, 'no private document holds a keyed value')
  return found
}

test('the needles are real and the sweep is large', async () => {
  const project = await runEverythingOnce()
  assert.ok(project.locationIds().size > 0, 'the plan holds no location id, so that half tested nothing')
  assert.ok([...project.secretStrings()].some((s) => s.length >= 32), 'root.key is not the shape read here')
  const { texts } = sweep(project)
  const characters = texts.reduce((sum, [, text]) => sum + text.length, 0)
  assert.ok(characters > 40_000, `${characters} characters swept`)
})

test('no printed form of any returned value names a key or an id', async () => {
  // The whole of the boundary, measured against a real protection run.
  const project = await runEverythingOnce()
  const { texts } = sweep(project)
  for (const needle of needles(project)) {
    for (const [label, text] of texts) {
      assert.ok(!text.includes(needle), `${label} printed ${needle.slice(0, 6)}…`)
    }
  }
})

test('no keyed value from the private documents is mirrored', async () => {
  // A plan's keyed strings stay in the plan — the *values*, not a list of names,
  // so a keyed field added tomorrow contributes a needle on the day it appears.
  const project = await runEverythingOnce()
  const values = keyedValues(project)
  assert.ok([...project.locationIds()].every((id) => values.has(id) || id.length < 8), 'the keyed sweep missed a site identity')
  assert.ok([...values].some((value) => !needles(project).has(value)), 'the sweep read site ids only, so KEYED_FIELDS tested one key')
  const { texts } = sweep(project)
  for (const value of values) {
    for (const [label, text] of texts) {
      assert.ok(!text.includes(value), `${label} mirrors the private value ${value.slice(0, 6)}…`)
    }
  }
})

test('no document key belongs to the private half', async () => {
  // Matched against the *names* the run produced, not their values: a plan-mode
  // summary legitimately says `mode: 'plan'`, and the claim here is that no
  // document the binding offers is *shaped* like a private one.
  const project = await runEverythingOnce()
  const { keyNames } = sweep(project)
  assert.ok(keyNames.size > 40, [...keyNames].join(','))
  assert.deepEqual([...keyNames].filter((name) => PRIVATE_FIELD_NAMES.has(name)), [])
})

test('a private path is named only by the lists that disclose it', async () => {
  const project = await runEverythingOnce()
  const { texts } = sweep(project)
  const disclosed = texts.filter(([, text]) => PRIVATE_DIRS.some((dir) => text.replaceAll('\\', '/').includes(dir)))
  assert.ok(disclosed.length > 0, 'the artifact lists name no private path, so this case read nothing')
  const quiet = sweep(project, { skipDisclosing: true })
  for (const [label, text] of quiet.texts) {
    const normalised = text.replaceAll('\\', '/')
    for (const folder of PRIVATE_DIRS) {
      assert.ok(!normalised.includes(folder), `${label} names ${folder}`)
    }
  }
})

test('the package exports no accessor for the private half', async () => {
  // `StoredReport` stays out of the forbidden list on purpose: it is a saved
  // *report*, which is the SDK's own document, not the store.
  const exported = Object.keys(api).filter((name) => !name.startsWith('_'))
  assert.deepEqual(exported.filter((name) => FORBIDDEN_NAMES.has(name)), [])
  for (const name of OFFERED) {
    assert.ok(!FORBIDDEN_NAMES.has(name), `${name} is offered, so it is not forbidden`)
  }
  const members = new Set()
  for (const name of exported) {
    const value = api[name]
    if (typeof value !== 'function') continue
    for (const member of Object.getOwnPropertyNames(value)) if (member !== 'constructor') members.add(member)
    for (const member of Object.getOwnPropertyNames(value.prototype ?? {})) if (member !== 'constructor') members.add(member)
  }
  assert.deepEqual([...members].filter((member) => FORBIDDEN_NAMES.has(member)), [])
  assert.ok(members.has('protectSummary'), 'the sanitized verb is the one that is offered')
  assert.equal(typeof Session.prototype.protect, 'undefined', 'ADR-0001: the plan-carrying protect stays Rust-only')
  assert.equal(typeof Session.open_store, 'undefined')
})

test('a private document cannot be read as a report', async () => {
  // `readReport` is confined to the reports folder, whatever name it is given: a
  // store-relative path is normalised to a stem and looked for under
  // `.swp/private/reports/`, so a release's manifest is not reachable by naming
  // its path.
  const project = await runEverythingOnce()
  const manifests = readdirSync(join(project.root, '.swp', 'private', 'manifests')).filter((name) => name.endsWith('.json')).sort()
  assert.ok(manifests.length > 0, 'the release wrote no manifest, so this case tested nothing')
  const name = manifests[0]
  for (const spelling of [name, `../manifests/${name}`, `.swp/private/manifests/${name}`, join('.swp', 'private', 'manifests', name)]) {
    const error = (() => {
      try {
        project.session.readReport(spelling)
        return null
      } catch (caught) {
        return caught
      }
    })()
    assert.ok(error instanceof SwpError, `${spelling}: read back a private document`)
    assert.equal(error.code, 'USAGE', spelling)
    assert.ok(error.message.includes('no saved report'), error.message)
  }
})

test('a summary and a release record use the public field names only', async () => {
  // Both sets are read from the objects rather than from a list this file
  // maintains, so a new field that copies a private document's key is caught on
  // the day it is added.
  const project = await runEverythingOnce()
  const summary = await project.protectMode('plan')
  const latest = project.session.releases({ kind: 'latest' })[0]
  const documents = [summary, project.session.release(latest)]
  for (const document of documents) {
    const keyNames = new Set()
    collect(document, 'document', [], keyNames)
    assert.deepEqual([...keyNames].filter((name) => PRIVATE_FIELD_NAMES.has(name)), [])
  }
  assert.ok(Array.isArray(summary.artifacts), 'the disclosure list this case depends on is gone')
  assert.ok('watermark' in JSON.parse(JSON.stringify(project.session.release(latest))))
})

test('an exception about a project never prints the key', async () => {
  // Failures are a surface too: their text, their path, their cause and their
  // advice — and the stack a host prints beside them.
  const project = await runEverythingOnce()
  const refusals = []
  for (const run of [
    () => project.session.release(`rel-${'q'.repeat(13)}`),
    () => project.session.readReport('nope'),
    () => project.scan(join(project.root, 'absent-candidate')),
    () => Session.open(join(project.root, 'nowhere')),
    () => Session.init(project.root, { name: 'other' }),
    () => Session.open(project.root, { tagBits: 99 })
  ]) {
    try {
      await run()
      assert.fail(`no refusal from ${run}`)
    } catch (error) {
      assert.ok(error instanceof SwpError, String(error))
      refusals.push(error)
    }
  }
  assert.equal(refusals.length, 6)
  const printed = refusals.flatMap((error) => [
    error.rendered,
    inspect(error, { depth: 2, getters: true }),
    String(error),
    error.stack ?? '',
    JSON.stringify([error.code, error.message, error.path, error.causedBy, error.nextStep])
  ])
  for (const needle of needles(project)) {
    for (const text of printed) assert.ok(!text.includes(needle), needle.slice(0, 6))
  }
})
