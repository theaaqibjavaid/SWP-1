//! What initializing a project produced, and the session it left behind.
//!
//! `Session.init` is the one operation in this build where a root secret exists,
//! and it is the one place the binding must be careful about what it says *about*
//! that secret. So this module copies out of [`InitResult`] the fields that are
//! already public and already printed by `swp init`, and the disclosure about the
//! key stops at three values: which scheme sealed it, the 40-bit non-secret handle
//! that lets a restored `root.key` be recognised as the same key, and what the
//! access-list check actually found. There is no path to a key byte from here, and
//! `init` never accepts one — a secret drawn by somebody else would have to cross
//! into garbage-collected memory this project cannot zeroize.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{InitOutcome, InitResult, Measurement, Settings};

use crate::error::repr_of;
use crate::session::PySession;

/// A project that is ready to protect, and what initializing it produced.
#[pyclass(module = "swp", name = "InitOutcome", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyInitOutcome {
    /// The opened session for the project `init` just created or re-opened.
    #[pyo3(get)]
    pub session: PySession,
    /// What the run did: the identity, the seal's metadata, the measurement, the
    /// settings it wrote or left alone.
    #[pyo3(get)]
    result: PyInitResult,
}

/// What a store now holds, in the form an application can act on.
#[pyclass(module = "swp", name = "InitResult", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyInitResult {
    #[pyo3(get)]
    project_id: String,
    #[pyo3(get)]
    display_name: String,
    /// Whether the store was already there. A pre-existing store keeps its
    /// identity and its secret: SWP never replaces a project secret.
    #[pyo3(get)]
    pre_existing: bool,
    /// `"created"` when this run drew the secret, `"kept"` when one was there.
    #[pyo3(get)]
    secret_state: String,
    /// `"dpapi"` or `"plain"` — how the key on disk is protected.
    #[pyo3(get)]
    secret_scheme: String,
    /// A 40-bit non-secret handle, so a restored `root.key` can be recognised as
    /// the same key without printing it.
    #[pyo3(get)]
    secret_handle: String,
    /// Whether the access list on the private half was read back and checked.
    #[pyo3(get)]
    permissions_verified: bool,
    /// What that check saw, in the tool's own words.
    #[pyo3(get)]
    permissions_detail: String,
    /// `"created"`, `"updated"`, `"already ignored"` or `"not written"`.
    #[pyo3(get)]
    gitignore: String,
    /// Paths this run created, store-relative and forward-slashed.
    #[pyo3(get)]
    created: Vec<String>,
    /// Whether this run changed the project's display label.
    #[pyo3(get)]
    renamed: bool,
    #[pyo3(get)]
    measurement: PyMeasurement,
    #[pyo3(get)]
    settings: PySettings,
}

/// What the tree holds, measured the way a scan would measure it.
#[pyclass(module = "swp", name = "Measurement", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyMeasurement {
    /// Files with a parser-covered extension.
    #[pyo3(get)]
    files: u32,
    #[pyo3(get)]
    bytes: u64,
    /// Files skipped by the walk, whatever it skipped them for.
    #[pyo3(get)]
    skipped: u32,
    languages: Vec<(String, u32)>,
    tops: Vec<(String, u32)>,
}

/// The `[protect]` section this run left behind.
#[pyclass(module = "swp", name = "Settings", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySettings {
    #[pyo3(get)]
    targets: Vec<String>,
    #[pyo3(get)]
    target_sites: u32,
    #[pyo3(get)]
    tag_bits: u8,
    #[pyo3(get)]
    embed_strings: bool,
    /// Whether this run wrote the config, or left the operator's alone.
    #[pyo3(get)]
    written: bool,
    /// What the measurement suggested, whether or not it was applied.
    #[pyo3(get)]
    suggestion: u32,
}

#[pymethods]
impl PyInitOutcome {
    /// The two things this outcome is: the project it opened and what the run
    /// wrote. The session is named by its root and id and not printed, because a
    /// repr of a handle is a second way to lose track of which object owns what.
    fn __repr__(&self) -> String {
        format!(
            "InitOutcome(project_id='{}', pre_existing={})",
            self.result.project_id,
            if self.result.pre_existing {
                "True"
            } else {
                "False"
            }
        )
    }
}

#[pymethods]
impl PyInitResult {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("project_id", &self.project_id)?;
        d.set_item("display_name", &self.display_name)?;
        d.set_item("pre_existing", self.pre_existing)?;
        d.set_item("secret_state", &self.secret_state)?;
        d.set_item("secret_scheme", &self.secret_scheme)?;
        d.set_item("secret_handle", &self.secret_handle)?;
        d.set_item("permissions_verified", self.permissions_verified)?;
        d.set_item("permissions_detail", &self.permissions_detail)?;
        d.set_item("gitignore", &self.gitignore)?;
        d.set_item("created", &self.created)?;
        d.set_item("renamed", self.renamed)?;
        d.set_item("measurement", self.measurement.to_dict(py)?)?;
        d.set_item("settings", self.settings.to_dict(py)?)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("InitResult", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyMeasurement {
    /// Source files per language, in the SDK's own (alphabetical) order.
    fn languages<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        pairs(py, &self.languages)
    }

    /// Source files per top-level directory, which is what `[protect] targets` is
    /// chosen from.
    fn tops<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        pairs(py, &self.tops)
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("files", self.files)?;
        d.set_item("bytes", self.bytes)?;
        d.set_item("skipped", self.skipped)?;
        d.set_item("languages", self.languages(py)?)?;
        d.set_item("tops", self.tops(py)?)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Measurement", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PySettings {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("targets", &self.targets)?;
        d.set_item("target_sites", self.target_sites)?;
        d.set_item("tag_bits", self.tag_bits)?;
        d.set_item("embed_strings", self.embed_strings)?;
        d.set_item("written", self.written)?;
        d.set_item("suggestion", self.suggestion)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Settings", &self.to_dict(py)?)
    }
}

fn pairs<'py>(py: Python<'py>, rows: &[(String, u32)]) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for (name, count) in rows {
        d.set_item(name, *count)?;
    }
    Ok(d)
}

impl PyInitOutcome {
    pub(crate) fn from_outcome(inner: InitOutcome) -> Self {
        PyInitOutcome {
            session: PySession {
                inner: inner.session,
            },
            result: project_result(inner.result),
        }
    }
}

fn project_result(inner: InitResult) -> PyInitResult {
    PyInitResult {
        project_id: inner.project_id.as_str().to_string(),
        display_name: inner.display_name.clone(),
        pre_existing: inner.pre_existing,
        secret_state: inner.secret_state.to_string(),
        secret_scheme: inner.secret_scheme.to_string(),
        secret_handle: inner.secret_handle.clone(),
        permissions_verified: inner.permissions_verified,
        permissions_detail: inner.permissions_detail.clone(),
        gitignore: inner.gitignore.to_string(),
        created: inner.created.clone(),
        renamed: inner.renamed,
        measurement: project_measurement(inner.measurement),
        settings: project_settings(inner.settings),
    }
}

fn project_measurement(inner: Measurement) -> PyMeasurement {
    PyMeasurement {
        files: inner.files,
        bytes: inner.bytes,
        skipped: inner.skipped,
        languages: inner.languages.into_iter().collect::<Vec<(String, u32)>>(),
        tops: inner.tops.into_iter().collect::<Vec<(String, u32)>>(),
    }
}

fn project_settings(inner: Settings) -> PySettings {
    PySettings {
        targets: inner.targets.clone(),
        target_sites: inner.target_sites,
        tag_bits: inner.tag_bits,
        embed_strings: inner.embed_strings,
        written: inner.written,
        suggestion: inner.suggestion,
    }
}
