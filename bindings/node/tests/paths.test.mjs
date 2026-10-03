// Every spelling a caller can type, and what the binding makes of it.
//
// The property this file exists for is that a path survives the crossing: the
// characters a caller wrote are the characters the filesystem is asked about, with
// no lossy intermediate and no quiet normalisation nobody agreed to. It is checked
// from both ends, as the Python suite checks it —
// `bindings/python/tests/test_paths.py` is the blueprint, and where the families
// differ the reason is the host language's.
//
// Python has three ways to hand over a directory and one way to refuse it: `str`,
// `pathlib.Path` and `os.PathLike`, against `bytes` and an `int`. Node has one way
// to hand over a directory — a string — so the family that replaces that one here
// is the *spellings* family: a JS caller chooses its own separators, may or may not
// end the string in one, may write `.` and `..`, and on Windows may reach for the
// verbatim prefix. Each of those is a decision the binding must not quietly make on
// the caller's behalf.
//
// Two spellings of the same directory come back from the binding, and the
// difference is deliberate rather than accidental:
//
// * `projectRoot` is the store's canonical Windows form, `\\?\C:\…`, because that is
//   what the store holds and it is what lets a past-`MAX_PATH` project be named at
//   all;
// * `VerifyOutcome.tree`, `Report.candidate.described` and every exception message
//   that resolves a root print the plain form, and a store-relative path — anything
//   under `.swp/`, and every site row's `file` — is forward-slashed on every
//   platform, because those strings are written into documents and compared across
//   operating systems.
//
// The rest is the filesystem's end of the crossing: a root whose name carries
// spaces, non-ASCII or shell metacharacters completes a whole cycle; a file inside
// the tree with those characters in its name is the same site afterwards; a
// relative candidate means the directory it means to the process that stands in the
// working directory; and a root past Windows' `MAX_PATH` is reached, because the
// conversion happens in Rust's path layer rather than in the caller's `fs` calls.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, sep } from 'node:path'

import { Session, reportStem } from '../index.js'
import {
  SOURCE_TREE,
  isForwardSlashed,
  makeProject,
  makeProtected,
  plain,
  purgeAll,
  tempRoot,
  writeTree
} from './helpers.mjs'

after(purgeAll)

/** The Windows verbatim prefix: the only spelling that reaches a past-`MAX_PATH`
 * tree through Node's own `fs` calls. */
const VERBATIM = '\\\\?\\'

const WINDOWS = process.platform === 'win32'

/** Characters a caller is entitled to use in a directory name. */
const NAMES = ['with spaces', 'проект-ünïcode-漢字', "a b'c(d)#e%20f", 'dotted.name']

/** One tree whose file names carry the same awkwardness the roots above do. */
const ODD_TREE = {
  'src/app.js': SOURCE_TREE['src/app.js'],
  'src/my app (1).js': SOURCE_TREE['src/app.js'],
  'src/ünïcode 漢字.py': SOURCE_TREE['src/util.py'],
  'src/sub-dir/one-more.ts': SOURCE_TREE['src/main.ts']
}

/**
 * A project directory whose *name* is the string under test.
 *
 * `tempRoot` sanitises its label into the prefix, which is right for naming a test
 * and useless for a test about names: here the characters have to be the ones on
 * disk. The sanitised base is what `purgeAll` removes, secret and all.
 */
function namedRoot (name, files = SOURCE_TREE) {
  const base = tempRoot('name')
  const root = join(base, name)
  mkdirSync(root, { recursive: true })
  writeTree(root, files)
  return { base, root }
}

/** The whole documented lifecycle in `root`, with nothing invented on the way. */
async function cycle (root, label) {
  const init = Session.init(root, { name: label })
  const summary = await init.session.protectSummary({ mode: 'release' })
  const outcome = init.session.verify({})
  const scanned = await init.session.scan(root)
  return { init, session: init.session, summary, outcome, scanned }
}

/** Run `run` with the process standing in `directory`. */
async function from (directory, run) {
  const before = process.cwd()
  process.chdir(directory)
  try {
    return await run()
  } finally {
    process.chdir(before)
  }
}

// -- a root whose name is not a plain word -----------------------------------

for (const name of NAMES) {
  test(`a root named ${JSON.stringify(name)} completes a whole cycle`, async () => {
    // Spaces, non-ASCII, quoting characters and dots are path data, not errors.
    // Every operation the binding offers runs against this root, and a character
    // lost anywhere in the path layer costs one of the four assertions.
    const { root } = namedRoot(name)
    const { init, session, summary, outcome, scanned } = await cycle(root, name)

    assert.match(init.result.projectId, /^swp1-/)
    assert.equal(session.identity.displayName, name)
    assert.equal(summary.sitesEmbedded, 3)
    assert.equal(outcome.verdict, 'INTACT')
    assert.equal(outcome.sitesConfirmed, outcome.sitesExpected)
    assert.equal(scanned.report.result, 'PROVENANCE_DETECTED')
    assert.equal(scanned.report.candidate.filesScanned, 3)
  })

  test(`the root the store reports for ${JSON.stringify(name)} is the root that exists`, () => {
    // The characters survive the store's canonicalisation as well as the call, and
    // the reported path is a directory the caller can open — so this is the samefile
    // check, in the one spelling both sides agree on.
    const { root } = namedRoot(name)
    const reported = plain(Session.init(root, { name }).session.projectRoot)
    assert.equal(basename(reported), name)
    assert.ok(statSync(reported).isDirectory())
    assert.equal(realpathSync(reported), realpathSync(root))
  })

  test(`a missing path ${JSON.stringify(name)} is refused naming the characters it was given`, () => {
    // The refusal quotes the caller's spelling rather than a normalisation of it, so
    // what an operator reads is what they typed.
    const { root } = namedRoot('quoted')
    assert.throws(() => Session.open(join(root, name)), (error) => {
      assert.equal(error.code, 'PATH_REJECTED')
      assert.ok(error.message.includes(name), error.message)
      return true
    })
  })
}

test('a file named as the project is refused as not a project', () => {
  // `NOT_PROTECTED`, not a made-up identity: the path exists and has no store.
  const project = makeProject('file-as-root')
  assert.throws(() => Session.open(project.child('src', 'app.js')), { code: 'NOT_PROTECTED' })
})

// -- the spellings a caller types, and what comes back -----------------------

test('the spellings of a directory all name one project', () => {
  // Trailing separators, a `.` segment, a parent traversal and forward slashes are
  // all resolved by the filesystem on the way in, so they name the same store. The
  // binding passes the path; it does not first re-print it.
  const project = makeProject('spellings')
  const canonical = project.session.projectRoot
  const typed = project.root.replace(/\\/g, '/')
  const spellings = [project.root, typed, typed + '/', typed + '/.', typed + '/src/..']
  for (const spelling of spellings) {
    assert.equal(Session.open(spelling).projectRoot, canonical, spelling)
  }
  assert.equal(Session.open(project.root + sep).projectRoot, canonical)
  assert.equal(Session.discover(join(project.root, 'src')).projectRoot, canonical)
})

test('the windows spellings of a directory name the same project', { skip: !WINDOWS }, () => {
  // Win32 strips a trailing separator and trailing spaces from a name, and accepts
  // the verbatim prefix outright. POSIX reads all three as part of a name no entry
  // carries, which is why this case is Windows-only rather than platform-branched.
  const project = makeProject('windows-spellings')
  const canonical = project.session.projectRoot
  for (const spelling of [project.root + '\\\\', project.root + '  ', VERBATIM + project.root]) {
    assert.equal(Session.open(spelling).projectRoot, canonical, spelling)
  }
})

test('init accepts a trailing separator and stores the project where it said', () => {
  // A separator on the end of a creation path must not create a sibling or a
  // half-made store: the directory the identity is written under is the one the
  // caller named.
  const base = tempRoot('trailing')
  const root = join(base, 'inside')
  writeTree(root, SOURCE_TREE)
  const init = Session.init(root + sep, { name: 'trailing' })
  assert.equal(init.session.projectRoot, Session.open(root).projectRoot)
  assert.equal(init.session.identity.displayName, 'trailing')
  assert.ok(existsSync(join(root, '.swp', 'private', 'root.key')))
})

test('a relative root is resolved where the process stands', async () => {
  // Relative means the process working directory, not the session's root: the
  // binding passes the path on without re-anchoring it, so `.` and the empty string
  // mean what they mean to any other program run from the same place.
  const project = makeProject('relative-root')
  const canonical = project.session.projectRoot
  await from(project.root, async () => {
    assert.equal(Session.open('.').projectRoot, canonical)
    assert.equal(Session.open('').projectRoot, canonical)
    if (WINDOWS) assert.equal(Session.open(' ').projectRoot, canonical, 'Win32 strips the trailing space')
  })
  await from(project.child('src'), async () => {
    assert.equal(Session.discover('.').projectRoot, canonical)
    assert.equal(Session.discover('..').projectRoot, canonical)
  })
  await from(project.root, async () => {
    assert.throws(() => Session.open('nothing-here'), { code: 'PATH_REJECTED' })
  })
})

test('a parent traversal is honoured rather than normalised away', () => {
  // `..` is resolved by the filesystem, so it names the directory above. Cancelling
  // it textually would be wrong when a component in between is a symlink, and the
  // refusal proves the traversal actually happened, because the parent is not a
  // project — and says so with the parent's own name.
  const base = tempRoot('traversal')
  const root = join(base, 'inside')
  writeTree(root, SOURCE_TREE)
  Session.init(root, { name: 'traversal' })
  assert.throws(() => Session.open(root + sep + '..'), (error) => {
    assert.equal(error.code, 'NOT_PROTECTED')
    assert.equal(basename(plain(error.message.split(' in ', 2)[1])), basename(base), error.message)
    return true
  })
})

test('a candidate is described in the report as it was named', async () => {
  // Forward slashes and a trailing separator are kept, not rewritten: the scan
  // resolves the path it was handed and never re-prints the caller's string, so the
  // document says what the command said.
  const project = await makeProtected('described')
  const typed = project.root.replace(/\\/g, '/') + '/'
  const scanned = await project.session.scan(typed)
  assert.equal(scanned.report.candidate.described, typed)
  assert.equal(scanned.report.result, 'PROVENANCE_DETECTED')
  assert.equal(scanned.report.candidate.filesScanned, 3)
})

test('the candidate root is part of the path the binding passes', async () => {
  // The document locates a site from the candidate's root, so that root matters.
  // Scanning `src` instead of the project hands the same three files one level
  // higher than the release recorded them, and `swp-evidence` says so: every site
  // moved, the fingerprint no-match, an inconclusive scan rather than a strong one
  // over a tree whose shape it had misread. Nothing here smooths that over.
  const project = await makeProtected('candidate-root')
  const whole = await project.session.scan(project.root)
  const part = await project.session.scan(project.child('src'))
  assert.equal(whole.report.candidate.described, project.root)
  assert.equal(part.report.candidate.described, project.child('src'))
  assert.equal(whole.report.releases[0].moved, 0)
  assert.equal(part.report.releases[0].moved, part.report.releases[0].sites)
  assert.equal(part.report.candidate.filesScanned, 3)
  assert.equal(part.report.releases[0].fingerprint, 'no-match')
  assert.equal(part.report.result, 'INCONCLUSIVE')
})

test('a candidate with extra separators is still read', async () => {
  const project = await makeProtected('candidate-separators')
  for (const suffix of ['', sep, '/', '//']) {
    const scanned = await project.session.scan(project.root + suffix)
    assert.equal(scanned.report.candidate.filesScanned, 3, suffix)
    assert.equal(scanned.report.result, 'PROVENANCE_DETECTED', suffix)
  }
})

test('a relative scan candidate is walked', async () => {
  // `scan('src')` examines `src` exactly as the absolute spelling does. The
  // candidate still crosses as typed — the report describes it as `'src'` — and what
  // the Rust walk does with it is resolve it against the working directory once, up
  // front, so the paths it reads files by are absolute. Joined back onto the root it
  // was already joined from, `'src'` became `'src/src/app.js'` and the scan could
  // not open a file it had walked one line earlier.
  //
  // The verdict is then the one the case above documents for any spelling of `src`:
  // those files sit one level above where the release recorded them, so every site
  // has moved. What changes here is that the relative spelling gets that considered
  // answer at all, instead of an I/O failure over a path that never existed.
  const project = await makeProtected('relative-candidate')
  await from(project.root, async () => {
    const here = await project.session.scan('src')
    const there = await project.session.scan(project.child('src'))
    assert.equal(here.report.candidate.described, 'src')
    assert.equal(here.report.candidate.filesScanned, 3)
    assert.equal(here.report.result, 'INCONCLUSIVE')
    assert.equal(here.report.releases[0].fingerprint, 'no-match')
    assert.equal(here.report.releases[0].moved, there.report.releases[0].moved)
    const whole = await project.session.scan('.')
    assert.equal(whole.report.candidate.filesScanned, 3)
    assert.equal(whole.report.result, 'PROVENANCE_DETECTED')
  })
})

// -- names inside the tree ---------------------------------------------------

test('sites in files with awkward names are protected and recovered', async () => {
  // Four odd-named files, four sites, and verification back to INTACT. Recovery
  // means reading each file at exactly the name it was written under, so a mangled
  // name costs a site rather than passing quietly.
  const { root } = namedRoot('odd-tree', ODD_TREE)
  const { session, summary, outcome, scanned } = await cycle(root, 'odd-tree')
  const names = Object.keys(ODD_TREE)
  assert.equal(summary.sitesEmbedded, 4)
  assert.deepEqual(summary.filesChanged.map((row) => row.file).sort(), [...names].sort())
  assert.deepEqual([...new Set(summary.sites.map((row) => row.file))].sort(), [...names].sort())
  assert.equal(outcome.verdict, 'INTACT')
  assert.deepEqual(outcome.sites.map((row) => row.file).sort(), [...names].sort())
  assert.equal(scanned.report.candidate.filesScanned, 4)
  assert.equal(session.identity.displayName, 'odd-tree')
})

test('a site row names a file that is really there', async () => {
  // `file` is store-relative and forward-slashed; joining it to the root opens it.
  const { root } = namedRoot('odd-rows', ODD_TREE)
  const { session } = await cycle(root, 'odd-rows')
  const rows = session.verify({}).sites
  assert.ok(rows.length > 0)
  for (const row of rows) {
    assert.ok(isForwardSlashed(row.file), row.file)
    assert.ok(Object.hasOwn(ODD_TREE, row.file), row.file)
    assert.ok(statSync(join(root, ...row.file.split('/'))).isFile(), row.file)
    if (row.foundIn !== undefined) {
      assert.ok(isForwardSlashed(row.foundIn), row.foundIn)
      assert.ok(statSync(join(root, ...row.foundIn.split('/'))).isFile(), row.foundIn)
    }
  }
})

test('the protected bytes are written back under the same name', async () => {
  // A rewrite of a non-ASCII path is a rewrite of the same file, not a new one.
  const { root } = namedRoot('odd-bytes', ODD_TREE)
  const read = () => Object.fromEntries(
    Object.keys(ODD_TREE).map((rel) => [rel, readFileSync(join(root, ...rel.split('/')))])
  )
  const before = read()
  await cycle(root, 'odd-bytes')
  const after = read()
  assert.deepEqual(Object.keys(after).sort(), Object.keys(before).sort())
  assert.ok(
    Object.keys(before).some((rel) => !after[rel].equals(before[rel])),
    'protection rewrote nothing'
  )
})

test('one file with a space and brackets in its name is a candidate', async () => {
  // A candidate may be a single file, and its name may carry the awkward characters.
  // The rows keep the candidate's own addresses, and `foundIn` for a staged single
  // file is that file's own name — the spaces and brackets arrive unharmed, which is
  // what a caller matching a row against the tree has to be able to do.
  const { root } = namedRoot('odd-candidate', ODD_TREE)
  const { session, summary } = await cycle(root, 'odd-candidate')
  const target = join(root, 'src', 'my app (1).js')
  const scanned = await session.scan(target)
  const candidate = scanned.report.candidate
  assert.equal(candidate.kind, 'file')
  assert.equal(candidate.filesScanned, 1)
  assert.equal(candidate.described, target)
  assert.equal(scanned.sites.length, summary.sitesEmbedded)
  assert.deepEqual([...new Set(scanned.sites.map((row) => row.foundIn).filter((name) => name !== undefined))], ['my app (1).js'])
  const tally = scanned.report.releases[0]
  assert.equal(tally.sites, summary.sitesEmbedded)
  assert.equal(tally.fragments + tally.stripped + tally.absent, tally.sites)
  assert.ok(scanned.sites.some((row) => ['exact-rendering', 'tag-confirmed'].includes(row.status)))
  assert.ok([0, 1, 10].includes(scanned.report.exitCode()))
})

test('a missing candidate file is an I/O error with the name given', async () => {
  const { root } = namedRoot('odd-missing', ODD_TREE)
  const { session } = await cycle(root, 'odd-missing')
  await assert.rejects(
    session.scan(join(root, 'src', 'проект не существует.js')),
    (error) => {
      assert.equal(error.code, 'IO_ERROR')
      assert.ok(error.message.includes('проект не существует.js'), error.message)
      return true
    }
  )
})

// -- past MAX_PATH -----------------------------------------------------------

test('a tree Node cannot walk is still a project', { skip: !WINDOWS }, async () => {
  // The limit is in the caller's path layer, not in the binding's: Node needs the
  // verbatim prefix to create this tree, and every operation below reaches it
  // without one. `init` seals its store, `protect` rewrites the source, `verify`
  // reads it back and `scan` finds the provenance.
  //
  // The teardown is part of the assertion. A leftover directory this deep is a
  // sealed root secret nobody can delete by hand, so the case removes it through the
  // same long-path API it created it with and proves it went.
  const base = mkdtempSync(join(tmpdir(), 'swp-node-long-'))
  try {
    let deep = base
    for (let step = 0; step < 9; step += 1) deep = join(deep, `directory-number-${step}-with-a-long-name`)
    mkdirSync(VERBATIM + join(deep, 'src'), { recursive: true })
    writeFileSync(VERBATIM + join(deep, 'src', 'deep.js'), SOURCE_TREE['src/app.js'], 'utf8')
    assert.ok(deep.length > 260, `${deep.length} characters is not past MAX_PATH`)

    const { session, summary, outcome, scanned } = await cycle(deep, 'deep')
    assert.equal(summary.sitesEmbedded, 1)
    assert.deepEqual(summary.filesChanged.map((row) => row.file), ['src/deep.js'])
    assert.equal(outcome.verdict, 'INTACT')
    assert.deepEqual(outcome.sites.map((row) => row.file), ['src/deep.js'])
    assert.equal(scanned.report.candidate.filesScanned, 1)
    assert.ok(session.projectRoot.length > 260, session.projectRoot.length)
    assert.equal(Session.discover(join(deep, 'src')).projectRoot, session.projectRoot)
    assert.equal(Session.open(deep).identity.displayName, 'deep')
  } finally {
    rmSync(VERBATIM + base, { recursive: true, force: true, maxRetries: 5 })
    assert.ok(!existsSync(base), `a directory holding a test root secret survived: ${base}`)
  }
})

// -- the paths the store reports back ----------------------------------------

test('no store-relative path ever carries a backslash', async () => {
  // `.swp/…` names keep the store's spelling on every platform. These strings appear
  // in saved documents, in listings and in exception text, and the same project
  // directory is read on another operating system — a Windows separator leaking into
  // one of them makes the artifact unfindable there. The sweep covers everything a
  // run produced rather than one field.
  const project = await makeProtected('store-paths')
  const summary = await project.protectMode('release')
  const outcome = project.verify({ save: true })
  const scanned = await project.scan(project.root, { save: true })
  const values = [
    ...summary.filesChanged.map((row) => row.file),
    ...summary.sites.map((row) => row.file),
    ...summary.artifacts,
    ...outcome.sites.map((row) => row.file),
    ...outcome.sites.filter((row) => row.foundIn !== undefined).map((row) => row.foundIn),
    outcome.reportSaved,
    scanned.saved.path,
    ...project.initResult.created,
    ...project.session.reports()
  ]
  assert.ok(values.length > 10, 'the sweep ran over nothing')
  for (const value of values) {
    assert.ok(isForwardSlashed(value), value)
  }
})

test('every spelling of a saved report names that report', async () => {
  // Stem, name, store-relative path, backslashes, a folder prefix and padding all
  // normalise to one file — `report_stem` is the SDK's own function, so this is
  // parity with the Rust unit test at `crates/swp-sdk/src/report.rs`, not a rule the
  // binding adds.
  const project = await makeProtected('report-spellings')
  const saved = project.verify({ save: true }).reportSaved
  const name = saved.split('/').pop()
  const stem = name.slice(0, -'.json'.length)
  for (const spelling of [name, stem, saved, saved.replaceAll('/', '\\'), `reports\\${name}`, `/${name}`, `  ${name}  `]) {
    assert.equal(project.session.readReport(spelling).path, saved, spelling)
  }
  assert.equal(reportStem(saved.replaceAll('/', '\\')), stem)
  assert.throws(() => project.session.readReport(''), { code: 'PATH_REJECTED' })
})
