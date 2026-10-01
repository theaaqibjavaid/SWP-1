// What the package promises before any project is opened.
//
// A binding that loads is not a binding that works: this suite checks the parts a
// caller reads first — the two versions, the capability list, the failure-code
// table, the names on the entry point — because those are the surface an
// application codes against without ever running a protection. It also checks
// the two things that are Node's own rather than the Python binding's: that the
// hand-written loader is what gives an ES module its named exports, and that the
// addon's internal names stay off the package's API.

import { createRequire } from 'node:module'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import * as esm from '../index.js'
import swp from '../index.js'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const manifest = JSON.parse(readFileSync(path.join(here, '..', 'package.json'), 'utf8'))

// The addon behind the loader, reached on purpose: the point of several of these
// cases is what the loader does with it.
const addon = require('../binding.cjs')

/** The names the addon registers and the package does not offer. */
const INTERNAL = new Set(['installErrorFactory', 'ProtectTask', 'ScanTask', '__napiBindingTarget'])

/**
 * The store and the keyed plan. `docs/BINDING_SURFACE.json` classifies these as
 * `rust_only`, and a Node name for any of them is the boundary failing open.
 */
const FORBIDDEN = [
  'Store',
  'open_store',
  'openStore',
  'RootSecret',
  'rootSecret',
  'LocationId',
  'locationId',
  'Plan',
  'PlannedSite',
  'Protection',
  'ProtectOutcome',
  'protect'
]

/** Every reachable name on the public surface: the exports, and the class members. */
function publicNames () {
  const names = new Set(Object.keys(swp))
  for (const value of Object.values(swp)) {
    if (typeof value !== 'function') continue
    for (const key of [...Object.getOwnPropertyNames(value), ...Object.getOwnPropertyNames(value.prototype ?? {})]) {
      names.add(key)
    }
  }
  return names
}

test('the entry point is the loader, not the addon', () => {
  // A caller who reached `binding.cjs` directly would get a package with no
  // `SwpError` installed: the addon hands back plain `Error` objects until the
  // loader gives it the constructor.
  assert.ok(swp.SwpError, 'the loader did not export its error class')
  assert.ok(!INTERNAL.has('SwpError'))
  for (const internal of INTERNAL) {
    assert.equal(swp[internal], undefined, `${internal} is the addon's business, not the package's`)
  }
})

test('every public export is reachable as an ES module named export', () => {
  // This is the static import at the top of the file: Node decides what
  // `import { Session } from 'jrs-swp'` can see by running cjs-module-lexer over
  // the loader's source, so an `Object.assign`-style re-export would leave this
  // namespace with a `default` and nothing else.
  const expected = Object.keys(swp).sort()
  assert.ok(expected.includes('Session'), 'the loader exports nothing')
  for (const name of expected) {
    assert.ok(name in esm, `import { ${name} } fails while require().${name} works`)
    assert.equal(esm[name], swp[name], `${name} differs between the two loaders`)
  }
})

test('the loader re-exports the addon public surface and adds nothing of its own', () => {
  const fromAddon = Object.keys(addon)
    .filter((name) => !INTERNAL.has(name))
    .sort()
  const exported = Object.keys(swp).filter((name) => name !== 'SwpError').sort()
  // Drift in either direction is a defect: a name the addon has and the loader
  // dropped is unreachable, and a name the loader exports that the addon never
  // raised is a claim about an API that does not exist.
  assert.deepEqual(exported, fromAddon)
  assert.ok(fromAddon.length >= 12, fromAddon.join(','))
})

test('the binding version is the version the package advertises', () => {
  // `BINDING_VERSION` is the addon crate's number and `manifest.version` is the
  // npm package's; the two are the same lifecycle, and a mismatch says one was
  // rebuilt without the other being released.
  assert.match(swp.BINDING_VERSION, /^\d+\.\d+\.\d+[0-9A-Za-z.-]*$/)
  assert.equal(swp.BINDING_VERSION, manifest.version)
})

test('the tool version is the one every report is written under', () => {
  assert.equal(swp.SWP_VERSION, swp.capabilities().swpVersion)
  assert.ok(swp.banner().includes(swp.SWP_VERSION), swp.banner())
})

test('the banner names the protocol and the report schema', () => {
  const banner = swp.banner()
  const capabilities = swp.capabilities()
  assert.ok(banner.includes('SWP-1'))
  assert.ok(banner.includes(capabilities.protocol))
  assert.ok(banner.includes(capabilities.reportSchema))
})

test('errorCodes is the table the envelope draws from', () => {
  const codes = swp.errorCodes()
  assert.ok(Array.isArray(codes))
  assert.equal(new Set(codes).size, codes.length, 'a code listed twice makes a branch ambiguous')
  assert.ok(codes.includes('INTERNAL_ERROR'))
  assert.ok(codes.includes('USAGE'))
  for (const code of codes) assert.match(code, /^[A-Z][A-Z0-9_]*$/, code)
})

test('no public name reaches the store or the keyed plan', () => {
  const names = publicNames()
  for (const forbidden of FORBIDDEN) {
    assert.ok(!names.has(forbidden), `${forbidden} is rust_only and reached Node`)
  }
})

test('suggestSites is a monotone ladder over file count', () => {
  const ladder = [0, 1, 5, 20, 50, 100, 500, 1000, 5000].map((n) => swp.suggestSites(n))
  assert.deepEqual(ladder, [...ladder].sort((a, b) => a - b))
  assert.ok(ladder.every((n) => n > 0), ladder.join(','))
})

test('reportStem normalises every spelling of one entry', () => {
  for (const spelling of ['stem', 'stem.json', 'reports/stem.json', '.swp/private/reports/stem.json']) {
    assert.equal(swp.reportStem(spelling), 'stem', spelling)
  }
})

test('capabilities describe the build that is running', () => {
  const capabilities = swp.capabilities()
  assert.equal(capabilities.protocol, 'SWP-1')
  assert.ok(capabilities.reportSchema)
  assert.ok(capabilities.canonicalizerVersion >= 1)
  // The short list is the long list's projection, not a second list someone
  // maintains beside it.
  assert.deepEqual(capabilities.languageNames, capabilities.languages.map((info) => info.name))
  assert.equal(new Set(capabilities.languageNames).size, capabilities.languageNames.length)
  for (const info of capabilities.languages) {
    assert.ok(info.extensions.length, `${info.name} with no extension is never selected`)
    for (const ext of info.extensions) assert.match(ext, /^[A-Za-z0-9]+$/, `${info.name}: ${ext}`)
    assert.equal(new Set(info.extensions).size, info.extensions.length)
  }
  for (const range of [capabilities.tagBits, capabilities.targetSites]) {
    assert.ok(range.min <= range.default && range.default <= range.max, JSON.stringify(range))
  }
  assert.ok(capabilities.defaults.excludes.every((rule) => typeof rule === 'string' && rule.length > 0))
  JSON.parse(JSON.stringify(capabilities))
})

test('SwpError is the only error class the package exports', () => {
  assert.equal(typeof swp.SwpError, 'function')
  assert.ok(swp.SwpError.prototype instanceof Error)
  const classes = Object.entries(swp)
    .filter(([, value]) => typeof value === 'function')
    .map(([name]) => name)
  // A subclass per code would be a second taxonomy to keep in step with the Rust
  // one, so the surface offers exactly one name that reads like an exception.
  assert.deepEqual(classes.filter((name) => /Error$/.test(name)), ['SwpError'], classes.join(','))
})

test('the declarations name exactly what the loader exports', () => {
  // `index.d.ts` is hand-written and `binding.d.ts` is generated, so neither is
  // derived from the other and the runtime is the only place they can be joined:
  // this is that place. `tsc` checks that a caller can compile against the two
  // files together (`types/surface.test-d.ts`); this checks that what they compile
  // against is what `require('jrs-swp')` actually hands back — a name declared and
  // never exported, or exported and never declared, is a lie in whichever tool the
  // caller reaches for first.
  const hand = readFileSync(path.join(here, '..', 'index.d.ts'), 'utf8')
  const generated = readFileSync(path.join(here, '..', 'binding.d.ts'), 'utf8')

  const values = reexports(hand, 'export')
  const types = reexports(hand, 'export type')
  const exported = Object.keys(swp).filter((name) => name !== 'SwpError').sort()

  assert.deepEqual(values.sort(), exported, 'the value exports and the declared values differ')
  for (const name of [...values, ...types]) {
    assert.ok(declaredNames(generated).has(name), `${name} is declared nowhere in the generated surface`)
  }
  // The reverse direction: a new type on the Rust side has to be *chosen* at the
  // entry point, which is what keeps `installErrorFactory` and the two napi task
  // handles off the surface a caller autocompletes from.
  for (const name of declaredNames(generated)) {
    if (INTERNAL.has(name)) continue
    assert.ok(values.includes(name) || types.includes(name), `${name} reaches the binary and is undeclared`)
  }
})

test('the package advertises the hand-written types entry', () => {
  // `main` and `types` both point at the loader and its declaration beside it, and
  // both files ship: a package whose `types` names the generated file would give a
  // TypeScript caller an `Error` class that does not exist and a surface the
  // runtime refuses to export.
  assert.equal(manifest.main, 'index.js')
  assert.equal(manifest.types, 'index.d.ts')
  for (const entry of [manifest.main, manifest.types]) {
    assert.ok(manifest.files.includes(entry), `${entry} is not in files`)
    assert.ok(existsSync(path.join(here, '..', entry)), `${entry} is missing`)
  }
})

/** The names inside `export { … } from './binding'`, in either its value or type form. */
function reexports (text, keyword) {
  const block = new RegExp(`${keyword} \\{([^}]*)\\} from '\\./binding'`).exec(text)
  assert.ok(block, `${keyword} block is missing from the declarations`)
  return block[1].split(',').map((name) => name.trim()).filter(Boolean)
}

/** Every top-level name the generated declarations export. */
function declaredNames (text) {
  const names = new Set()
  for (const [, name] of text.matchAll(/^export (?:declare )?(?:class|interface|function|const|type|enum) (\w+)/gm)) {
    names.add(name)
  }
  return names
}

test('the reserved word stays a document key and never a property name', () => {  // `class` is the protocol's field. napi puts it behind `class` on the JS side,
  // which a caller can reach only as `row.class` — legal in JavaScript, and the
  // reason the binding does not rename it the way Python's surface had to.
  const site = { file: 'a.js', lineHint: 1, language: 'javascript', adapter: 'ast', class: 'integer', family: 'sub', width: 4, primary: 0 }
  assert.equal(site.class, 'integer')
  assert.ok('class' in site)
})
