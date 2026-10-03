// The one error class, and the exact shape of the envelope it carries.
//
// `SwpError` is the only type this package throws or rejects with, so its
// declaration is the contract a `catch` block is written against. Two decisions
// are recorded here because nothing else in the type system would notice if they
// drifted: the fields are *not* readonly — the loader assigns them as plain own
// properties, and a caller who copies an envelope into their own error type has
// to be able to — and `code` is `string` rather than a union of the table,
// because the table is runtime data (`errorCodes()`) that a rebuilt addon can
// lengthen while these declarations stay frozen.
//
// `keyof SwpError` is asserted as a closed set, which is how "no aliases" stops
// being a sentence in a README: a second spelling of `nextStep`, or a per-code
// subclass that grew a field, fails here.

import type { SwpError } from '../index'
import { SwpError as SwpErrorValue } from '../index'
import { Equals, Differs, expectTrue } from './assertions'

// The whole envelope, field by field. `message`, `name` and `stack` come from
// `Error`; the five after them are this binding's, and `path`/`causedBy` are
// `null` rather than absent so reading an envelope never depends on a key.
expectTrue<Equals<keyof SwpError,
  | 'name' | 'message' | 'stack' | 'cause'
  | 'code' | 'path' | 'causedBy' | 'nextStep' | 'rendered'
>>()

expectTrue<Equals<SwpError['name'], 'SwpError'>>()
expectTrue<Equals<SwpError['code'], string>>()
expectTrue<Equals<SwpError['message'], string>>()
expectTrue<Equals<SwpError['path'], string | null>>()
expectTrue<Equals<SwpError['causedBy'], string | null>>()
expectTrue<Equals<SwpError['nextStep'], string>>()
expectTrue<Equals<SwpError['rendered'], string>>()

// `code` is the stable half of the contract, and it is a `string` by design. A
// literal union here would be a second copy of the Rust table, frozen into the
// declarations of every published version of this package, and a caller who
// switched on it would get a compile error for a code that exists.
expectTrue<Differs<SwpError['code'], 'NOT_PROTECTED' | 'IO_ERROR'>>()

// An `Error` subtype, and nothing more exotic: no `exitCode`, because the exit
// codes are `swp`'s contract with a shell, and a library caller has no use for a
// number they cannot exit with. `errors.test.mjs` checks the same thing at
// runtime against every code in the table.
function isAnError (err: SwpError): Error {
  return err
}
void isAnError

expectTrue<Equals<'exitCode' extends keyof SwpError ? true : false, false>>()
expectTrue<Equals<'codeEnum' extends keyof SwpError ? true : false, false>>()

// The constructor's arity and order, because the class is exported and a caller
// can build one — for a fixture, mostly. Six positional arguments and no options
// object is the shape the loader's factory call uses; a seventh field would have
// to be added at both ends and would fail here first.
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>['length'], 6>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[0], string>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[1], string>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[2], string | null>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[3], string | null>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[4], string>>()
expectTrue<Equals<ConstructorParameters<typeof SwpErrorValue>[5], string>>()

// Writable, because the loader writes them. Copying an envelope into another
// error type is a thing callers do, and `readonly` fields would refuse it.
function copiesAnEnvelope (err: SwpError): SwpError {
  const copy: SwpError = Object.create(SwpErrorValue.prototype) as SwpError
  copy.name = err.name
  copy.message = err.message
  copy.code = err.code
  copy.path = err.path
  copy.causedBy = err.causedBy
  copy.nextStep = err.nextStep
  copy.rendered = err.rendered
  return copy
}

// `instanceof` is how a `catch` block decides what it holds, and the narrowing
// has to reach the fields — the alternative a caller would be pushed to is
// `(error as any).code`, which is the same cast repeated forever.
function readsACaughtError (caught: unknown): string {
  if (caught instanceof SwpErrorValue) {
    expectTrue<Equals<typeof caught, SwpError>>()
    return caught.code
  }
  throw caught
}

void [copiesAnEnvelope, readsACaughtError]
