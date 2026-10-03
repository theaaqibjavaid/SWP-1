// The two primitives every compile-time test in this directory is written with,
// and nothing else. There is no assertion runner here and no runtime behaviour:
// these files are checked by `npm run typecheck`, so a test passes by compiling
// and fails by producing an error — which is also how a test that should fail
// is checked, by `@ts-expect-error` turning a missing error into one.
//
// `Equals` is the strict, bidirectional identity rather than assignability,
// because these tests are about optionality and unions: `string | undefined`
// must not pass as `string`, and an optional field must not pass as a required
// one. `A extends B` would let both through.

/**
 * `true` only when `A` and `B` are the same type, and `false` for anything
 * merely assignable to each other.
 *
 * The deferred-conditional encoding is the standard one: two function types are
 * mutually assignable only when their conditional bodies resolve identically,
 * which makes the comparison sensitive to `undefined`, to union members and to
 * optional modifiers — the three things a declaration file gets wrong in ways a
 * caller only meets at the call site.
 */
export type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false

/** `true` when `A` and `B` are genuinely different types; the assertion for "this field is *not* a literal union". */
export type Differs<A, B> = Equals<A, B> extends false ? true : false

/**
 * Refuses to compile unless its type argument is exactly `true`.
 *
 * Declared, never defined: nothing here is called at runtime, and a body would
 * be code that no test executes.
 */
export declare function expectTrue<T extends true>(): void

/**
 * The argument shape a `@ts-expect-error` test hands to an operation it means
 * to refuse, without the expression itself failing for some *other* reason.
 *
 * A directive suppresses every error on its line, so a test whose expression is
 * already broken would pass for the wrong reason. `as any` is the one shape
 * that guarantees the only error left is the one under examination.
 */
export declare const anything: any
