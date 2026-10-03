// Every example in README.md, run.
//
// The rule the repository states about its documentation is that an example has to
// have been executed: `docs_examples` re-runs every `console` block in `docs/`
// against the current build for exactly that reason. This is the same rule applied
// to the binding's own page, with the convention that test already uses — `…` stands
// for whatever the project's secret influences, whitespace is insignificant, and a
// line without `…` is asserting a number this build re-derives on every run.
//
// Three things make this more than a paste check:
//
// * **Each program is a program.** A `js` block is written to a fresh directory and
//   run by a child Node process, so the README's `require('jrs-swp')` and
//   `import swp from 'jrs-swp'` resolve the way an installed application's do —
//   through `node_modules`, not through a relative path the suite happened to know.
//   An example that only works while the prose around it is remembered is the one a
//   documentation test would never catch. That link is why the teardown gets tested
//   at the end of this file: an example directory is removed with a link inside it,
//   and the package the link points at has to come out of that intact.
// * **A fresh root secret per program**, so a transcript that quoted a value the key
//   decides fails on the second run rather than the first. The byte totals a rewrite
//   produces are the documented case: they move with the width of the tag literal.
// * **The `ts` block is compiled and the links are resolved.** Declarations a caller
//   cannot import are a documentation defect, and `[a page](its/path)` pointing at
//   nothing is the one `CONTRIBUTING.md` names.
//
// What is deliberately *not* here: the `sh` fences. Those are the build and test
// commands, and the binding's CI job runs them; a suite that ran `npm ci` inside a
// test would be a test that rebuilt the thing it is testing.

import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import assert from 'node:assert/strict'
import test, { after } from 'node:test'

import { isDirectory, purge, purgeAll, tempRoot } from './helpers.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const PACKAGE = resolve(HERE, '..')
const README = join(PACKAGE, 'README.md')

/** The fence tags this page may use, and what each one owes the suite. */
const TAGS = new Set(['js', 'mjs', 'ts', 'text', 'tree', 'sh'])

/**
 * The tree every example runs in. The paths are the README's business — they are in
 * its `tree` fence, and the first test checks this list against that one — while the
 * bytes are the suite's, because two transcripts assert a file size and a size
 * written by hand into a document would be a number this suite invented.
 */
const FIXTURE = {
  'my-project/src/app.js': `const greeting = 'hello world';

function add(left, right) {
  return left + right;
}

export function label(value) {
  return '[' + value + ']';
}

export function total(items) {
  let sum = 0;
  for (const item of items) {
    sum = sum + item;
  }
  return sum;
}
`,
  'my-project/src/main.ts': `export function pick(items: string[], index: number): string {
  const offset = 7;
  return items[index + offset];
}

export const retries = 5;
`
}

/** The document as fenced blocks, in order: the tag, the body, the line it opens on. */
function fences (text) {
  const lines = text.split('\n')
  const out = []
  let open = null
  for (let at = 0; at < lines.length; at++) {
    const fence = /^\s*```(\w*)\s*$/.exec(lines[at])
    if (fence === null) {
      if (open !== null) open.body.push(lines[at])
      continue
    }
    if (open !== null) {
      out.push({ tag: open.tag, body: open.body.join('\n'), line: open.line })
      open = null
      continue
    }
    open = { tag: fence[1], body: [], line: at + 1 }
  }
  if (open !== null) throw new Error(`the \`\`\`${open.tag} fence at line ${open.line} is never closed`)
  return out
}

const blocks = fences(readFileSync(README, 'utf8'))

/** Every example directory holds a sealed test secret, so none of them survives. */
after(purgeAll)

/** Programs are the blocks that run; each owes the page a transcript to follow it. */
const isProgram = (block) => block.tag === 'js' || block.tag === 'mjs'

/** The block immediately after `at`, if there is one. */
const blockAfter = (at) => at + 1 < blocks.length ? blocks[at + 1] : null

/** `line 12` is what a failure has to say for the reader to find the block. */
const where = (block) => `README line ${block.line}`

/**
 * One documented line against one real line.
 *
 * `…` matches the rest of a word or a run of words on its own, the way the
 * documentation test's elision does; runs of whitespace collapse, so the page quotes
 * a value rather than a column alignment.
 */
function sameLine (expected, actual) {
  const clean = (line) => line.trim().replace(/\s+/g, ' ')
  const want = clean(expected)
  const got = clean(actual)
  if (!want.includes('…')) return want === got
  const pattern = want.split('…').map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*')
  return new RegExp(`^${pattern}$`).test(got)
}

/**
 * A directory one example runs in: the fixture tree, and this package reachable as
 * `jrs-swp` through `node_modules` the way an installed application reaches it.
 *
 * A junction on Windows, where a directory symlink asks for a privilege a test run
 * does not have, and a symlink elsewhere. Neither copies the package, which is the
 * point: the addon under the link is the one the rest of the suite loaded, so an
 * example cannot pass against a build that is not under test.
 */
function stage (label) {
  const run = tempRoot(label)
  for (const [rel, text] of Object.entries(FIXTURE)) {
    const path = join(run, ...rel.split('/'))
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, text, 'utf8')
  }
  const modules = join(run, 'node_modules')
  mkdirSync(modules, { recursive: true })
  symlinkSync(PACKAGE, join(modules, 'jrs-swp'), process.platform === 'win32' ? 'junction' : 'dir')
  return run
}

/** stdout without the newline the last `console.log` left behind it. */
function lines (text) {
  return text.split(/\r?\n/).filter((line, at, all) => !(line === '' && at === all.length - 1))
}

test('the README declares its examples in fences this suite knows', () => {
  const unknown = blocks.filter((block) => !TAGS.has(block.tag))
  assert.deepEqual(
    unknown.map((block) => `${where(block)} opens \`\`\`${block.tag}`),
    [],
    'an unclassified fence is an example nothing checks'
  )

  const orphans = blocks
    .map((block, at) => ({ block, at }))
    .filter(({ block, at }) => isProgram(block) && (blockAfter(at) === null || blockAfter(at).tag !== 'text'))
    .map(({ block }) => where(block))
  assert.deepEqual(orphans, [], 'an example with no transcript is an example nobody ran')

  const trees = blocks.filter((block) => block.tag === 'tree')
  assert.equal(trees.length, 1, 'the examples all run in the one tree the page declares')
  assert.deepEqual(
    trees[0].body.split('\n').map((line) => line.trim()).filter(Boolean).sort(),
    Object.keys(FIXTURE).sort(),
    'the documented tree is not the tree the suite builds'
  )

  const programs = blocks.filter(isProgram)
  assert.ok(programs.length >= 6, `only ${programs.length} runnable examples on a page that shows seven operations`)
  assert.ok(
    blocks.some((block) => block.tag === 'js') && blocks.some((block) => block.tag === 'mjs'),
    'the page has to document both module systems by running both'
  )
})

test('every example in the README runs and prints what the README says', () => {
  for (const [at, block] of blocks.entries()) {
    if (!isProgram(block)) continue
    const transcript = blockAfter(at)
    const run = stage(`readme-${String(at).padStart(2, '0')}`)
    const program = join(run, `example.${block.tag === 'mjs' ? 'mjs' : 'cjs'}`)
    writeFileSync(program, `${block.body}\n`, 'utf8')

    const child = spawnSync(process.execPath, [program], { cwd: run, encoding: 'utf8', timeout: 120_000 })
    const actual = lines(child.stdout)
    const expected = transcript.body.split('\n')
    const shown = `${where(block)}${child.stderr === '' ? '' : `\n--- stderr ---\n${child.stderr}`}`

    assert.equal(child.status, 0, `${shown}\nexited ${child.status}`)
    assert.equal(child.stderr, '', `${shown}\nwrote to stderr`)
    assert.equal(
      actual.length,
      expected.length,
      `${shown}\nprinted ${actual.length} lines, the page quotes ${expected.length}\n--- actual ---\n${child.stdout}`
    )
    for (let line = 0; line < expected.length; line++) {
      assert.ok(sameLine(expected[line], actual[line]), `${shown}\nline ${line + 1}\n  documented: ${expected[line]}\n  printed:      ${actual[line]}`)
    }
  }
})

test('the README TypeScript example compiles against the shipped declarations', () => {
  const at = blocks.findIndex((block) => block.tag === 'ts')
  assert.ok(at >= 0, 'the TypeScript section has to carry a block the suite can compile')
  const run = stage('readme-ts')
  const program = join(run, 'readme.mts')
  writeFileSync(program, `${blocks[at].body}\n`, 'utf8')

  const tsc = join(PACKAGE, 'node_modules', 'typescript', 'bin', 'tsc')
  assert.ok(existsSync(tsc), 'typescript has to be installed for the declarations to be checked')
  const child = spawnSync(
    process.execPath,
    [tsc, '--noEmit', '--strict', '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--noUnusedLocals', program],
    { cwd: run, encoding: 'utf8', timeout: 180_000 }
  )
  assert.equal(child.status, 0, `${where(blocks[at])} does not compile:\n${child.stdout}${child.stderr}`)
})

test('every link the README points at is a file this repository has', () => {
  const text = readFileSync(README, 'utf8')
  const broken = []
  for (const match of text.matchAll(/\]\(([^)\s]+)(?:#[^)]*)?\)/g)) {
    const target = match[1]
    if (/^(https?:|mailto:|#)/.test(target)) continue
    if (!existsSync(resolve(PACKAGE, target))) broken.push(target)
  }
  assert.deepEqual(broken, [], 'a page that links to a document that is not there is a broken promise, not a typo')
})

test('an example directory is removed without editing what its link points at', () => {
  // `stage` reaches this package through `node_modules/jrs-swp`, so every example's
  // teardown walks past a link whose target is the tree the rest of the run is
  // testing. `chmod` follows a link, and the teardown chmods what it finds: on POSIX
  // that write lands on the target directory and takes its search bit away, so
  // every later `stat`, `chdir` or process started inside the package fails EACCES —
  // which is how a suite with nothing failing in it came to break the CI step running
  // next to it on the Linux and macOS runners. Windows is untouched by it because
  // `chmod` there reaches no access right, measured through a junction, so the mode
  // half of this claim is made only where a mode carries permission.
  const run = tempRoot('link-run')
  const pkg = tempRoot('link-package')
  mkdirSync(join(pkg, 'tests'), { recursive: true })
  writeFileSync(join(pkg, 'tests', 'helpers.mjs'), 'export const purge = 1\n', 'utf8')
  const mode = statSync(pkg).mode
  const modules = join(run, 'node_modules')
  mkdirSync(modules, { recursive: true })
  symlinkSync(pkg, join(modules, 'jrs-swp'), process.platform === 'win32' ? 'junction' : 'dir')

  purge(run)

  assert.ok(!existsSync(run), 'the example directory survived its teardown')
  assert.ok(isDirectory(pkg), 'the teardown removed the package the link pointed at')
  assert.equal(readFileSync(join(pkg, 'tests', 'helpers.mjs'), 'utf8'), 'export const purge = 1\n')
  if (process.platform !== 'win32') {
    assert.equal(statSync(pkg).mode, mode, 'the teardown chmod-ed through the link into the package')
  }
})
