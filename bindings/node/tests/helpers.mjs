// The fixtures the Node binding suite shares.
//
// Two rules shape this file, and both come from what a project directory holds.
//
// * **A test project is a real project.** Every case runs `init` and
//   `protectSummary` against its own temporary root, so the values a test
//   asserts on are the ones the Rust crates produced for that tree under that
//   tree's own drawn secret. Nothing is mocked, and no site count, release id or
//   fingerprint is written into a test — several of them depend on the key, and
//   a hard-coded one would be a number this suite invented.
// * **A test project is left nowhere.** The root secret lives in the project
//   directory, so a directory that outlives its test leaves a sealed key in a
//   shared temp folder. `purge` is the teardown, and it fails the run out loud
//   rather than ignoring a leftover.
//
// The suite is deliberately the Python binding's suite in another language: the
// same tree, the same four operations, the same leak sweep. Where the two
// diverge the reason is Node's — a promise that must settle once, a loader that
// must be visible to `cjs-module-lexer` — and it is recorded at the test, not
// silently.

import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { Session } from '../index.js'

/** One tree per language adapter this build claims, plus a shared-shape spread
 * so the walker has several candidate sites to choose among. The contents are
 * deliberately ordinary: a test that depended on an exotic construct would be
 * testing the adapter's fixtures rather than the binding. */
export const SOURCE_TREE = {
  'src/app.js': `
const greeting = 'hello world';

function add(left, right) {
  return left + right;
}

export function label(value) {
  return '[' + value + ']';
}

const table = { alpha: 1, beta: 2, gamma: 3 };

export function total(items) {
  let sum = 0;
  for (const item of items) {
    sum = sum + item;
  }
  return sum;
}
`,
  'src/util.py': `
def scale(value, factor):
    return value * factor


LIMIT = 4096


def render(name):
    parts = []
    for index in range(3):
        parts.append(name + str(index))
    return '-'.join(parts)
`,
  'src/main.ts': `
export function pick(items: string[], index: number): string {
  const offset = 7;
  return items[index + offset];
}

export const retries = 5;
`,
}

const createdRoots = []

/**
 * A fresh directory whose name says which suite made it, in the spelling the
 * store answers with.
 *
 * A temporary root arrives in whatever spelling the platform hands out, and on
 * two of the three CI runners that spelling is not the directory's own name:
 * macOS reports `/var/folders/…` for a directory that lives at
 * `/private/var/folders/…`, and a Windows runner's `%TEMP%` is the 8.3 short
 * form of its user profile, `C:\Users\RUNNER~1\…`. The binding canonicalises
 * whatever it is given and reports the resolved path, so a fixture holding the
 * caller's spelling would compare a path printer against a filesystem and fail
 * on those two runners while passing on Linux, where `/tmp` is already the
 * directory's name. Canonicalising here rather than at each comparison leaves
 * every assertion standing and moves no test to a skip.
 *
 * `realpathSync` is not enough: it resolves links but leaves a short name short,
 * which is exactly how the Windows failure survived a `realpathSync`-on-both-sides
 * comparison. `realpathSync.native` asks the filesystem for the final path.
 */
export function tempRoot (label) {
  const safe = String(label).replace(/[^A-Za-z0-9_-]/g, '-')
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), `swp-node-${safe}-`)))
  createdRoots.push(root)
  return root
}

export function writeTree (root, files) {
  for (const [rel, text] of Object.entries(files)) {
    const path = join(root, ...rel.split('/'))
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, text, 'utf8')
  }
  return root
}

/**
 * Remove a project directory, and fail loudly if a secret survived it.
 *
 * Windows seals `root.key` with an ACL that can deny the deleting process, so
 * the walk restores the owner's bits first; on POSIX a directory without the
 * search bit turns every later stat into EACCES and a recursive remove into a
 * silent no-op. The final check is the point of the function: a leftover
 * directory holding a test root secret is the one thing this suite must not
 * leave behind, so it throws rather than being logged.
 *
 * A link is removed, never opened into. `chmod` follows a link, so restoring
 * bits on the link restores them on whatever it points at — and one of this
 * suite's roots holds a `node_modules` link whose target is the package the
 * rest of the run is testing. On POSIX that write takes the target's search bit
 * away and every later process started in the package fails with EACCES.
 */
export function purge (root) {
  if (!existsSync(root)) return
  const walk = (dir) => {
    try {
      chmodSync(dir, 0o700)
    } catch {
      /* already gone, or not ours to open */
    }
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.isSymbolicLink()) continue
      else {
        try {
          chmodSync(path, 0o600)
        } catch {
          /* as above */
        }
      }
    }
  }
  walk(root)
  rmSync(root, { recursive: true, force: true, maxRetries: 5 })
  if (existsSync(root)) {
    if (existsSync(join(root, '.swp', 'private', 'root.key'))) {
      throw new Error(`a directory holding a test root secret could not be removed: ${root}`)
    }
    rmSync(root, { recursive: true, force: true, maxRetries: 5 })
  }
}

/** Remove every directory this file made. Call it from `after()`. */
export function purgeAll () {
  const leftovers = createdRoots.splice(0, createdRoots.length)
  for (const root of leftovers) purge(root)
}

/** A one-file JavaScript tree, for the cases that only need a site to exist. */
export function smallTree (name = 'only.js') {
  return { [name]: 'export function twice(n) {\n  return n * 2 + 13;\n}\n' }
}

/**
 * One temporary project: its directory, its session, and everything the binding
 * handed this test.
 *
 * `observed` is the leak sweep's inventory. Recording what a case actually
 * received is what makes `tests/leakage.test.mjs` a measurement rather than a
 * list of the values the author thought to check.
 */
export class Project {
  constructor (root, session, initResult) {
    this.root = root
    this.session = session
    this.initResult = initResult
    this.observed = []
  }

  child (...rel) {
    return join(this.root, ...rel)
  }

  track (...values) {
    this.observed.push(...values)
    return values[values.length - 1]
  }

  protect (options) {
    const summary = this.session.protectSummary(options)
    this.observed.push(summary)
    return summary.then((settled) => {
      this.observed.push(...settled.sites, ...settled.filesChanged, ...settled.refusals)
      return settled
    })
  }

  protectMode (mode = 'release') {
    return this.protect({ mode })
  }

  verify (options) {
    const outcome = this.session.verify(options)
    this.observed.push(outcome, ...outcome.sites)
    return outcome
  }

  scan (candidate, options = {}) {
    const outcome = this.session.scan(String(candidate), options.releases, options.save)
    this.observed.push(outcome)
    return outcome.then((settled) => {
      this.observed.push(settled.report, ...settled.sites)
      if (settled.saved !== null) this.observed.push(settled.saved)
      return settled
    })
  }

  /** What `protect --mode release` left in the tree, read back from disk. */
  text (rel) {
    return readFileSync(this.child(...rel.split('/')), 'utf8')
  }

  // -- the private half, read by the tests that sweep it ---------------------

  privateDocuments () {
    const out = []
    for (const kind of ['plans', 'manifests']) {
      const folder = join(this.root, '.swp', 'private', kind)
      if (!existsSync(folder)) continue
      for (const name of readdirSync(folder).sort()) {
        if (!name.endsWith('.json')) continue
        out.push({ path: join(folder, name), document: JSON.parse(readFileSync(join(folder, name), 'utf8')) })
      }
    }
    return out
  }

  /**
   * Every keyed site identity this project's own store holds.
   *
   * Read off the disk and never printed: these are the strings whose appearance
   * in a JavaScript-visible value is the failure the leak sweep exists to catch.
   */
  locationIds () {
    const ids = new Set()
    for (const { document } of this.privateDocuments()) {
      for (const key of ['sites', 'skipped']) {
        for (const site of document[key] ?? []) {
          for (const id of site.locations ?? []) ids.add(String(id))
        }
      }
    }
    return ids
  }

  /**
   * Renderings of the sealed root secret that must never cross the boundary.
   *
   * The envelope's payload is DPAPI or file-mode-protected ciphertext rather
   * than the key itself, so a sweep that only looked for the key bytes would
   * pass on a binding that dumped this file into a `toString()`. Both spellings
   * of the same bytes are needles.
   */
  secretStrings () {
    const path = join(this.root, '.swp', 'private', 'root.key')
    if (!existsSync(path)) return new Set()
    const needles = new Set()
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const at = line.indexOf(':')
      if (at < 0) continue
      const name = line.slice(0, at).trim()
      const value = line.slice(at + 1).trim()
      if (!value || name === 'scheme') continue
      needles.add(value)
      try {
        needles.add(Buffer.from(value, 'base64').toString('hex'))
      } catch {
        /* not base64; the verbatim spelling is still a needle */
      }
    }
    return needles
  }
}

/**
 * A fresh, initialised project.
 *
 * `init: false` hands back the directory and no session, for the cases about
 * opening something that is not a project yet.
 */
export function makeProject (label = 'project', { files = null, name = null, overrides = null, init = true } = {}) {
  const root = tempRoot(label)
  writeTree(root, files ?? SOURCE_TREE)
  if (!init) return { root, session: null, initResult: null, observed: [] }
  const outcome = Session.init(root, { name: name ?? label })
  let session = outcome.session
  if (overrides !== null) session = Session.open(root, overrides)
  const project = new Project(root, session, outcome.result)
  project.initOutcome = outcome
  project.observed.push(outcome.result, ...outcome.result.created)
  return project
}

/**
 * A project with one published release, so verify and scan have something to
 * find. The run's own summary travels with it: a test that compares a release
 * record against the protection that made it needs the numbers that run
 * reported, and inventing them here would be a fixture asserting on itself.
 */
export async function makeProtected (label = 'protected', { files = null, mode = 'release' } = {}) {
  const project = makeProject(label, { files })
  project.summary = await project.protectMode(mode)
  return project
}

/** A tree that is nobody's protected project, for a scan that must find nothing. */
export function foreignTree () {
  const root = tempRoot('foreign')
  writeTree(root, {
    'src/other.py': 'def unrelated(values):\n    total = 0\n    for value in values:\n        total = total + value\n    return total\n',
    'src/other.js': 'export function unrelated(n) {\n  return n * 3;\n}\n'
  })
  return root
}

/** Copy a tree, so a scan has a candidate that is not the project itself. */
export function copyTree (from, label = 'copy') {
  const to = tempRoot(label)
  cp(from, to)
  return to
}

/**
 * A copy of the project's protected sources, with no store beside them — an
 * artifact the way a reviewer receives one.
 */
export function stageArtifact (project, label = 'artifact') {
  const root = tempRoot(`artifact-${label}`)
  cpSync(project.child('src'), join(root, 'src'), { recursive: true })
  return root
}

/**
 * Every byte of every file under a directory, keyed by forward-slashed relative
 * path — the private store included.
 *
 * A rehearsal is only a rehearsal if the disk is the same afterwards, and the
 * half of the disk a caller cannot see is the half that has to be checked.
 */
export function treeBytes (root) {
  const out = {}
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else out[path.slice(root.length + 1).replaceAll('\\', '/')] = readFileSync(path)
    }
  }
  walk(root)
  return out
}

function cp (from, to) {
  mkdirSync(to, { recursive: true })
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const source = join(from, entry.name)
    const target = join(to, entry.name)
    if (entry.isDirectory()) cp(source, target)
    else writeFileSync(target, readFileSync(source))
  }
}

// -- assertions several suites share ----------------------------------------

/**
 * Field names that belong to the private plan and the private manifest.
 *
 * They are not secret by themselves; they are the shape of the documents a
 * binding is not given, so their appearance in a JavaScript document form means
 * the binding rebuilt one rather than read the summary it was handed.
 */
export const PRIVATE_FIELD_NAMES = new Set([
  'locations',
  'location_id',
  'location_ids',
  'grammar_path',
  'original',
  'rendered',
  'root_secret',
  'secret_bytes',
  'plan',
  'fragment_tag',
  'expected_tag',
  'expected'
])

/** Every string in a nested object or array — keys included. */
export function * walkStrings (value) {
  if (Array.isArray(value)) {
    for (const nested of value) yield * walkStrings(nested)
  } else if (value !== null && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      yield key
      yield * walkStrings(nested)
    }
  } else if (typeof value === 'string') {
    yield value
  }
}

/**
 * The store's canonical spelling of a root, minus the verbatim prefix Windows
 * adds.
 *
 * `projectRoot` reports what the store holds, which on Windows is a
 * `\\?\`-prefixed path — the same thing the Python binding documents. Comparing
 * that string with a caller's would test two path printers against each other,
 * so the cases that care about identity strip the prefix first.
 */
export function plain (path) {
  return path.startsWith('\\\\?\\') ? path.slice(4) : path
}

/** The store's own paths, which the binding promises to forward-slash. */
export function isForwardSlashed (path) {
  return !path.includes('\\')
}

export function readJson (path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

export function isDirectory (path) {
  return existsSync(path) && statSync(path).isDirectory()
}

export function absolute (path) {
  return resolve(path)
}
