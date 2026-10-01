//! The one exception type, and the panic boundary in front of every call.
//!
//! Two things happen here and nothing else happens here. A `SwpError` becomes an
//! [`Error`] carrying the six fields [docs/SDK_API.md] §8 defines — read off the
//! accessors that are already public on the Rust type, with no new taxonomy — and
//! a Rust panic becomes `INTERNAL_ERROR` rather than an unwind into the
//! interpreter.
//!
//! The envelope is built *after* the GIL is reacquired, because constructing a
//! `PyErr` needs the GIL and [`detached`] releases it for the whole call. So the
//! detached closure hands back [`Failure`], which is plain `Send` data, and only
//! then does it become a Python object.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{ErrorCode, SwpError};

create_exception!(
    swp,
    Error,
    PyException,
    "The one failure SWP-1 raises. Branch on `code`, never on the message."
);

/// The SDK_API §8 envelope, carried as the Rust error it came from.
///
/// A newtype rather than a copy of six fields, for two reasons. The Python object's
/// attributes are read off [`SwpError`]'s own accessors at the moment the object is
/// built, so this type cannot drift from the error contract or grow a seventh field
/// nobody declared; and an unwound panic becomes an ordinary `INTERNAL_ERROR`
/// `SwpError`, which means it renders, codes and advises exactly like a failure the
/// SDK raised itself.
pub struct Failure(SwpError);

impl From<SwpError> for Failure {
    fn from(e: SwpError) -> Self {
        Failure(e)
    }
}

impl Failure {
    /// What an unwind across the boundary is: `error.rs` already defines that code
    /// as "a defect in SWP-1: report it", and a panic that reached a caller's
    /// process instead of their `except` clause is exactly that.
    fn from_panic(payload: Box<dyn Any + Send>) -> Self {
        let detail = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "no message".to_string());
        Failure(
            SwpError::new(
                ErrorCode::Internal,
                format!("SWP-1 panicked across the Python boundary: {detail}"),
            )
            .caused_by(detail),
        )
    }

    /// A caller's argument that no Rust code can accept: a path that is bytes,
    /// an id that is empty. `USAGE` is the code the CLI already gives for this.
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Failure(SwpError::usage(message))
    }

    pub(crate) fn into_pyerr(self, py: Python<'_>) -> PyErr {
        let e = &self.0;
        let err = PyErr::new::<Error, _>(e.message().to_string());
        let value = err.value(py);
        // Each `setattr` is a line of the contract: dropping one would leave an
        // attribute that raises `AttributeError` on a caught exception, which is
        // a worse surprise than the panic this type exists to contain.
        let _ = value.setattr("code", e.code().as_str());
        let _ = value.setattr("message", e.message());
        let _ = value.setattr("path", e.path());
        let _ = value.setattr("caused_by", e.cause.as_deref());
        let _ = value.setattr("next_step", e.next_step());
        let _ = value.setattr("rendered", e.render());
        err
    }
}

/// So a `Failure` can be the `?` conversion inside a `PyResult` return — which is
/// how the argument validators in [`crate::options`] report a bad id without taking
/// a `Python` token as an argument.
impl From<Failure> for PyErr {
    fn from(f: Failure) -> PyErr {
        Python::attach(|py| f.into_pyerr(py))
    }
}

/// Run `f` with the GIL released, and turn anything it raises into [`Failure`].
///
/// Every operation in this crate goes through here, which is what makes "no
/// unwind crosses the Python boundary" a property of the build rather than of
/// review. Releasing the GIL is not a performance gesture: `protect` and `scan`
/// hold it for the length of a walk over somebody's tree, and an embedding
/// application with worker threads should not have them stop.
///
/// `f` may borrow whatever it needs — a `&Session`, an `&Overrides` — since the
/// borrow cannot outlive the call; that is why the bound is `Send` rather than
/// `'static`. The returned `T` has to be `Send` too, which is a fact about the
/// Rust types and not a restriction anyone chose: every one of them is owned data.
///
/// Callers end with `.map_err(|e| e.into_pyerr(py))` rather than `?`, because
/// building the `PyErr` needs the GIL this function just gave up.
pub fn detached<T: Send, F>(py: Python<'_>, f: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, Failure> + Send,
{
    py.detach(move || capture(f))
}

/// The half of [`detached`] that needs no interpreter: run the call, and turn an
/// unwind into the documented `INTERNAL_ERROR`.
///
/// Split out because it is testable on its own. `detached` additionally needs a
/// running CPython, and this crate is built `cdylib` with `extension-module`, so no
/// test binary of it has a Python to attach to.
fn capture<T, F>(f: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, Failure>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(outcome) => outcome,
        Err(payload) => Err(Failure::from_panic(payload)),
    }
}

/// `Name(field=value, …)` for any object whose `to_dict` is the field list.
///
/// One implementation rather than forty `__repr__`s, because a hand-written repr
/// is a second list of the same fields, and the second list is the one that
/// forgets a field the day a DTO gains one. `secret_leak`'s counterpart in the
/// Python suite sweeps these strings against a real run's keyed site identities,
/// so the repr of every returned object is checked and not merely promised.
pub fn repr_of(name: &str, fields: &Bound<'_, PyDict>) -> PyResult<String> {
    let mut parts = Vec::with_capacity(fields.len());
    for (key, value) in fields.iter() {
        parts.push(format!(
            "{}={}",
            key.str()?.to_string_lossy(),
            value.repr()?.to_string_lossy()
        ));
    }
    Ok(format!("{name}({})", parts.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the boundary owes the interpreter: an unwind leaves as a failure a
    /// caller can catch, with the code that means "a defect in SWP-1: report it".
    #[test]
    fn an_unwind_becomes_internal_error_with_its_payload_as_the_cause() {
        let caught = capture(|| -> Result<(), Failure> { panic!("the probe message") });
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
        let caught = capture(|| -> Result<(), Failure> { std::panic::panic_any(42u8) });
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
        let caught = capture(|| -> Result<(), Failure> { Err(Failure::from(original)) })
            .expect_err("passed through");
        assert_eq!(caught.0.code().as_str(), "NOT_PROTECTED");
        assert_eq!(caught.0.message(), "this project has no releases");
        assert_eq!(caught.0.next_step(), "run `swp protect`");
    }
}
