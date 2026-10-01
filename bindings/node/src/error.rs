//! The one exception object, and the panic boundary in front of every call.
//!
//! Two things happen here and nothing else happens here. A `SwpError` becomes a
//! `SwpError` *JavaScript object* carrying the six fields [docs/SDK_API.md] §8
//! defines — read off the accessors that are already public on the Rust type,
//! with no new taxonomy — and a Rust panic becomes `INTERNAL_ERROR` rather than
//! an unwind into the host process.
//!
//! The JS object is built by a constructor the loader installs once
//! ([`install_error_factory`]), because a napi class cannot extend the built-in
//! `Error` — only JavaScript can define `class SwpError extends Error`, and this
//! crate's job is to hand that class the six values, not to reimplement it.
//!
//! The envelope is built *after* the worker thread is done: constructing any JS
//! value needs the JS thread, exactly as the Python envelope needs the GIL. So
//! a detached closure hands back [`Failure`] — plain `Send` data — and only on
//! the JS thread, in the promise's `resolve` step or in the sync call's error
//! path, does it become a JavaScript object. napi then throws or rejects with
//! *that object verbatim* (`Error::from_unknown_without_coercion` retains it;
//! settled by the scaffold probe), so no re-wrap layer exists in JavaScript.

use std::any::Any;
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{ErrorCode, SwpError};

/// The SDK_API §8 envelope, in the order the loader's constructor takes it:
/// code, message, path, causedBy, nextStep, rendered.
type FactoryArgs = (
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
);

thread_local! {
    static ERROR_FACTORY: RefCell<Option<FunctionRef<FnArgs<FactoryArgs>, Unknown<'static>>>> =
        const { RefCell::new(None) };
}

/// Lets the JS loader hand the addon its `SwpError` constructor.
///
/// Not in the generated types: it is the seam between `index.js` and the addon,
/// and a caller who has the addon but not the loader has a build that never
/// finishes loading anyway.
#[napi(skip_typescript)]
pub fn install_error_factory(
    factory: Function<'_, FnArgs<FactoryArgs>, Unknown<'static>>,
) -> Result<()> {
    let reference = factory.create_ref()?;
    ERROR_FACTORY.with(|cell| {
        *cell.borrow_mut() = Some(reference);
    });
    Ok(())
}

/// The SDK_API §8 envelope, carried as the Rust error it came from.
///
/// A newtype rather than a copy of six fields, for the same two reasons the
/// Python binding records: the JS object's attributes are read off
/// [`SwpError`]'s own accessors at the moment the object is built, so this type
/// cannot drift from the error contract; and an unwound panic becomes an
/// ordinary `INTERNAL_ERROR` `SwpError`, which means it renders, codes and
/// advises exactly like a failure the SDK raised itself.
#[derive(Debug)]
pub struct Failure(pub(crate) SwpError);

impl From<SwpError> for Failure {
    fn from(e: SwpError) -> Self {
        Failure(e)
    }
}

impl Failure {
    /// What an unwind across the boundary is: `swp-core`'s `error.rs` already
    /// defines that code as "a defect in SWP-1: report it", and a panic that
    /// reached a caller's process instead of their `catch` block is exactly
    /// that.
    fn from_panic(payload: Box<dyn Any + Send>) -> Self {
        let detail = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "no message".to_string());
        Failure(
            SwpError::new(
                ErrorCode::Internal,
                format!("SWP-1 panicked across the Node boundary: {detail}"),
            )
            .caused_by(detail),
        )
    }

    /// A caller's argument that no Rust code can accept: a mode that is not one
    /// of the three words, an id that is empty. `USAGE` is the code the CLI
    /// already gives for this.
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Failure(SwpError::usage(message))
    }

    /// The `SwpError` JavaScript object for this failure, built by the
    /// loader-installed constructor. Must run on the JS thread.
    fn to_value(&self, env: &Env) -> Result<Unknown<'_>> {
        let e = &self.0;
        ERROR_FACTORY.with(|cell| {
            let borrow = cell.borrow();
            let factory = borrow.as_ref().ok_or_else(|| {
                Error::from_reason(
                    "SWP-1 internal error: the Node loader never installed the SwpError constructor",
                )
            })?;
            let ctor = factory.borrow_back(env)?;
            ctor.new_instance(FnArgs {
                data: (
                    e.code().as_str().to_owned(),
                    e.message().to_owned(),
                    e.path().map(str::to_owned),
                    e.cause.as_deref().map(str::to_owned),
                    e.next_step().to_owned(),
                    e.render(),
                ),
            })
        })
    }

    /// The value a `#[napi]` function returns as its `Err`: napi throws or
    /// rejects with the retained object verbatim, so what the caller catches is
    /// the loader's `SwpError`, not a wrapper around it.
    pub(crate) fn into_napi_error(self, env: &Env) -> Error {
        match self.to_value(env) {
            Ok(value) => Error::from_unknown_without_coercion(value),
            Err(e) => e,
        }
    }
}

/// Run `f` on the current thread with a panic turned into [`Failure`].
///
/// The Node counterpart of the Python binding's `detached`: there is no GIL to
/// release — the operations that need a worker thread are the two async ones,
/// and libuv already moved them off the JS thread — so what remains of the
/// boundary is the unwind catch and the envelope. Every sync operation here
/// goes through [`guarded`]; the two async ones call `capture` inside
/// `compute` and settle on the JS thread in `resolve`.
pub(crate) fn capture<T, F>(f: F) -> std::result::Result<T, Failure>
where
    F: FnOnce() -> std::result::Result<T, Failure>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(outcome) => outcome,
        Err(payload) => Err(Failure::from_panic(payload)),
    }
}

/// A sync façade call: run it, and raise anything it fails as the loader's
/// `SwpError` object.
pub(crate) fn guarded<T, F>(env: &Env, f: F) -> Result<T>
where
    F: FnOnce() -> std::result::Result<T, Failure>,
{
    capture(f).map_err(|failure| failure.into_napi_error(env))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the boundary owes the host: an unwind leaves as a failure a caller
    /// can catch, with the code that means "a defect in SWP-1: report it".
    #[test]
    fn an_unwind_becomes_internal_error_with_its_payload_as_the_cause() {
        let caught =
            capture(|| -> std::result::Result<(), Failure> { panic!("the probe message") });
        let error = caught.expect_err("a panic is not a success").0;
        assert_eq!(error.code().as_str(), "INTERNAL_ERROR");
        assert!(
            error.message().contains("the probe message"),
            "the panic's own words have to survive into the message: {}",
            error.message()
        );
        assert_eq!(error.cause.as_deref(), Some("the probe message"));
    }

    /// A payload that is not a string is still an unwind, and still contained.
    #[test]
    fn a_panic_without_a_readable_message_is_still_a_failure() {
        let caught =
            capture(|| -> std::result::Result<(), Failure> { std::panic::panic_any(42u8) });
        let error = caught.expect_err("a panic is not a success").0;
        assert_eq!(error.code().as_str(), "INTERNAL_ERROR");
        assert_eq!(error.cause.as_deref(), Some("no message"));
    }

    /// The boundary catches unwinds and nothing else: an error the SDK returned
    /// arrives unchanged, with its own code, message and advice.
    #[test]
    fn a_returned_error_is_passed_through_untouched() {
        let original = SwpError::new(ErrorCode::NotProtected, "this project has no releases")
            .with_next("run `swp protect`");
        let caught =
            capture(|| -> std::result::Result<(), Failure> { Err(Failure::from(original)) })
                .expect_err("passed through");
        assert_eq!(caught.0.code().as_str(), "NOT_PROTECTED");
        assert_eq!(caught.0.message(), "this project has no releases");
        assert_eq!(caught.0.next_step(), "run `swp protect`");
    }
}
