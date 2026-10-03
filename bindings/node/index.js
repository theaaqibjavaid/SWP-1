/* eslint-disable */
'use strict'

// The public entry point of the SWP-1 Node binding: the generated loader, plus
// the one thing a native addon cannot do for itself — define the exception
// class in JavaScript, where `extends Error` lives.
//
// `binding.cjs` is napi-rs's generated loader; `napi build` writes it and never
// this file, so the platform resolution, the `jrs-swp-<target>` optional
// dependency chain and the musl detection are all machine-maintained. What is
// hand-written here is small on purpose: the class below and the call that
// installs it. Nothing in this file may decide a protocol fact — no verdict, no
// exit code, no error taxonomy. `errorCodes()` remains the list to branch
// against, and `SwpError.code` remains the string the Rust table printed.

const binding = require('./binding.cjs')

/**
 * The only error this package raises, for every failure the SDK reports and for
 * a panic that reached the boundary.
 *
 * `message` is the SDK's own sentence; `code` is the stable half of the
 * contract, and the field to branch on. `path` is set when the failure named a
 * file, `causedBy` when the SDK had a lower-cause to give, and both are `null`
 * rather than absent so a printed envelope never depends on a key existing.
 * `rendered` is the whole block a terminal user would have read — code,
 * sentence, next step — kept because a foreign process may want to show it
 * verbatim instead of composing its own.
 *
 * A subclass per code is deliberately not offered: codes are data
 * (`errorCodes()`), and a hierarchy would be a second taxonomy this binding
 * would then have to keep in step with the Rust one.
 */
class SwpError extends Error {
  constructor (code, message, path, causedBy, nextStep, rendered) {
    super(message)
    this.name = 'SwpError'
    this.code = code
    this.path = path ?? null
    this.causedBy = causedBy ?? null
    this.nextStep = nextStep
    this.rendered = rendered
  }
}

// Handing the addon the constructor is what lets a failure cross the boundary
// as this object rather than as a napi `Error`: the addon keeps a reference and
// calls `new` on the JS thread, so what a `catch` block receives — the value a
// rejected promise carries — is the `SwpError` itself. Refusing the reference is
// an install failure, not an SWP-1 failure, and it throws here rather than
// turning every later error into an `INTERNAL_ERROR` that reads like a defect
// in the tool.
binding.installErrorFactory(SwpError)

// Re-export the addon's public surface by name. Every line is a static
// `exports.X =` assignment for two reasons: `cjs-module-lexer` is what gives
// `import { Session } from 'jrs-swp'` its named exports and it cannot see a
// spread, an `Object.assign` or a reassigned `module.exports`; and the addon's
// own bag holds names this package does not offer — `installErrorFactory` is
// the seam between these two files, and `ProtectTask`/`ScanTask` are napi's
// registration handles, which have no constructor and no meaning here.
// `tests/surface.test.mjs` compares this list against the addon so a new export
// cannot be reachable from the binary and invisible from the entry point.
exports.Session = binding.Session
exports.InitOutcome = binding.InitOutcome
exports.Report = binding.Report
exports.StoredReport = binding.StoredReport
exports.ScanOutcome = binding.ScanOutcome
exports.VerifyOutcome = binding.VerifyOutcome
exports.banner = binding.banner
exports.capabilities = binding.capabilities
exports.errorCodes = binding.errorCodes
exports.reportStem = binding.reportStem
exports.suggestSites = binding.suggestSites
exports.SWP_VERSION = binding.SWP_VERSION
exports.BINDING_VERSION = binding.BINDING_VERSION
exports.SwpError = SwpError
