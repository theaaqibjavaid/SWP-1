//! Getting a caller's path into Rust without losing a character of it.
//!
//! The tempting implementation is `obj.extract::<String>()`, which calls `str()`
//! on whatever was passed and then hands the result to the filesystem. That is
//! wrong twice over: `str()` on a `pathlib.Path` is not its `__fspath__` on every
//! object a caller might build, and a `String` that cannot represent the real
//! bytes — the ones a `bytes` path on Unix carries — would have to be *invented*
//! rather than refused.
//!
//! So: a `str` is taken as it is, an `os.PathLike` is asked for its `__fspath__`,
//! and a `bytes` path is refused with `USAGE`. Rust's `PathBuf` is the lossless
//! form on every platform this binding ships on, and `std` does the wide-character
//! conversion on Windows, which is why nothing here mentions an encoding.

use std::path::{Path, PathBuf};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::error::Failure;

/// A path that arrived from Python, in the form Rust's filesystem calls take.
pub struct OsPath(PathBuf);

impl OsPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for OsPath {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> Result<Self, Self::Error> {
        Ok(OsPath(from_obj(&obj)?))
    }
}

fn from_obj(obj: &Bound<'_, PyAny>) -> PyResult<PathBuf> {
    if let Ok(text) = obj.cast::<PyString>() {
        return Ok(PathBuf::from(text.to_cow()?.as_ref()));
    }
    // `os.fspath` accepts these; an arbitrary byte sequence has no defined
    // meaning as a path on Windows and would be decoded by guesswork on the rest.
    if obj.cast::<PyBytes>().is_ok() {
        return Err(rejected(obj, "a bytes path"));
    }
    let fspath = obj
        .call_method0("__fspath__")
        .map_err(|_| rejected(obj, "none"))?;
    if let Ok(text) = fspath.cast::<PyString>() {
        return Ok(PathBuf::from(text.to_cow()?.as_ref()));
    }
    Err(rejected(obj, "a __fspath__ that is not str"))
}

fn rejected(obj: &Bound<'_, PyAny>, why: &str) -> PyErr {
    let kind = obj
        .get_type()
        .name()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "?".to_string());
    Failure::usage(format!(
        "expected a str or os.PathLike path, got {kind} returning {why}"
    ))
    .into_pyerr(obj.py())
}
