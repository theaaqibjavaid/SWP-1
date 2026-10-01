//! The five values a caller passes *in*.
//!
//! Each one is a `#[pyclass]` holding the Rust type by value, so the conversion
//! into what the façade expects is a field copy and not a re-interpretation: a
//! `tag_bits` that arrives as an `int` leaves this module as the same `u8` the CLI
//! would have parsed from `--tag-bits`. Nothing is defaulted in Python — where the
//! Rust side has no `Default`, there is no default here either, because a binding
//! that invented one would be making the choice the protocol refused to make.
//!
//! `Mode` is the one Rust *enum* that crosses, because it is the only one a caller
//! has to choose. The enums a scan hands *back* — `Outcome`, `EvidenceLevel`,
//! `EvidenceKind`, `Verdict` — cross as the strings their own `as_str()` produces,
//! which is the form the saved documents use and the form a caller compares
//! against.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{
    InitOptions, Mode, Overrides, ProtectOptions, ReleaseId, ReleaseSelection, VerifyOptions,
};

use crate::error::{repr_of, Failure};

/// How a run behaves: record and apply, record only, or nothing at all.
#[pyclass(module = "swp", name = "Mode", eq, eq_int, frozen, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyMode {
    /// Compute and save the constellation, modify nothing. `swp generate`.
    Plan,
    /// Compute, record, and apply. `swp protect`.
    Release,
    /// Compute and report, and write nothing anywhere. `swp protect --dry-run`.
    DryRun,
}

impl From<PyMode> for Mode {
    fn from(m: PyMode) -> Self {
        match m {
            PyMode::Plan => Mode::Plan,
            PyMode::Release => Mode::Release,
            PyMode::DryRun => Mode::DryRun,
        }
    }
}

impl From<Mode> for PyMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Plan => PyMode::Plan,
            Mode::Release => PyMode::Release,
            Mode::DryRun => PyMode::DryRun,
        }
    }
}

#[pymethods]
impl PyMode {
    /// The word the tool uses for this mode, and the word a saved plan uses.
    #[getter]
    pub(crate) fn name(&self) -> &'static str {
        Mode::from(*self).as_str()
    }

    /// Whether choosing this mode may touch a project's source.
    ///
    /// Read from `swp_embedding::Mode::writes_source`, so this page and the
    /// implementation of `protect` cannot disagree about what writes.
    #[getter]
    fn writes_source(&self) -> bool {
        Mode::from(*self).writes_source()
    }

    /// Whether choosing this mode may leave anything in `.swp/`.
    #[getter]
    fn writes_store(&self) -> bool {
        Mode::from(*self).writes_store()
    }

    fn __str__(&self) -> &'static str {
        self.name()
    }

    /// Python clears `__hash__` on any class that defines `__eq__`, and this one
    /// compares by value, so without this a mode could not go in a set or key a dict.
    ///
    /// The answer is the variant's index, which is the number `eq_int` compares an
    /// `int` against: `hash(Mode.Release) == hash(1)`, so equal values hash equal
    /// however the caller spelled the mode.
    fn __hash__(&self) -> isize {
        match self {
            PyMode::Plan => 0,
            PyMode::Release => 1,
            PyMode::DryRun => 2,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<Mode.{}>",
            match self {
                PyMode::Plan => "Plan",
                PyMode::Release => "Release",
                PyMode::DryRun => "DryRun",
            }
        )
    }
}

/// The `[protect]` settings one call overrides, and the releases it selects.
#[pyclass(module = "swp", name = "Overrides", frozen, skip_from_py_object)]
pub struct PyOverrides {
    pub(crate) inner: Overrides,
}

#[pymethods]
impl PyOverrides {
    #[new]
    #[pyo3(signature = (*, targets = None, excludes = None, target_sites = None,
                        tag_bits = None, embed_strings = None))]
    fn new(
        targets: Option<Vec<String>>,
        excludes: Option<Vec<String>>,
        target_sites: Option<u32>,
        tag_bits: Option<u8>,
        embed_strings: Option<bool>,
    ) -> Self {
        PyOverrides {
            inner: Overrides {
                targets: targets.unwrap_or_default(),
                excludes: excludes.unwrap_or_default(),
                target_sites,
                tag_bits,
                embed_strings,
            },
        }
    }

    #[getter]
    fn targets(&self) -> Vec<String> {
        self.inner.targets.clone()
    }

    #[getter]
    fn excludes(&self) -> Vec<String> {
        self.inner.excludes.clone()
    }

    #[getter]
    fn target_sites(&self) -> Option<u32> {
        self.inner.target_sites
    }

    #[getter]
    fn tag_bits(&self) -> Option<u8> {
        self.inner.tag_bits
    }

    #[getter]
    fn embed_strings(&self) -> Option<bool> {
        self.inner.embed_strings
    }

    /// Which settings this object leaves alone.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("targets", self.targets())?;
        d.set_item("excludes", self.excludes())?;
        d.set_item("target_sites", self.target_sites())?;
        d.set_item("tag_bits", self.tag_bits())?;
        d.set_item("embed_strings", self.embed_strings())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Overrides", &self.to_dict(py)?)
    }
}

/// Which of a project's releases an operation reads.
#[pyclass(module = "swp", name = "ReleaseSelection", frozen, skip_from_py_object)]
pub struct PyReleaseSelection {
    pub(crate) inner: ReleaseSelection,
}

#[pymethods]
impl PyReleaseSelection {
    /// Every release the project has published.
    #[staticmethod]
    fn all() -> Self {
        PyReleaseSelection {
            inner: ReleaseSelection::All,
        }
    }

    /// The newest one.
    #[staticmethod]
    fn latest() -> Self {
        PyReleaseSelection {
            inner: ReleaseSelection::Latest,
        }
    }

    /// Exactly these, by id. An id this project never published is an error at
    /// the call that uses the selection, not here.
    #[staticmethod]
    fn ids(ids: Vec<String>) -> PyResult<Self> {
        let mut out = Vec::with_capacity(ids.len());
        for raw in ids {
            out.push(ReleaseId::new(raw).map_err(Failure::from)?);
        }
        Ok(PyReleaseSelection {
            inner: ReleaseSelection::Ids(out),
        })
    }

    /// `"all"`, `"latest"` or `"ids"`: which of the three this is.
    #[getter]
    fn kind(&self) -> &'static str {
        match &self.inner {
            ReleaseSelection::All => "all",
            ReleaseSelection::Latest => "latest",
            ReleaseSelection::Ids(_) => "ids",
        }
    }

    /// The ids, for a `"ids"` selection, and empty for the other two.
    #[getter]
    fn release_ids(&self) -> Vec<String> {
        match &self.inner {
            ReleaseSelection::Ids(ids) => ids.iter().map(|i| i.as_str().to_string()).collect(),
            _ => Vec::new(),
        }
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("kind", self.kind())?;
        d.set_item("release_ids", self.release_ids())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ReleaseSelection", &self.to_dict(py)?)
    }
}

/// What `Session.init` is told.
#[pyclass(module = "swp", name = "InitOptions", frozen, skip_from_py_object)]
pub struct PyInitOptions {
    pub(crate) inner: InitOptions,
}

#[pymethods]
impl PyInitOptions {
    #[new]
    #[pyo3(signature = (*, name = None, force = false))]
    fn new(name: Option<String>, force: bool) -> Self {
        PyInitOptions {
            inner: InitOptions { name, force },
        }
    }

    /// The label the project asked for. Never hashed, never trusted.
    #[getter]
    fn name(&self) -> Option<String> {
        self.inner.name.clone()
    }

    #[getter]
    fn force(&self) -> bool {
        self.inner.force
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("name", self.name())?;
        d.set_item("force", self.force())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("InitOptions", &self.to_dict(py)?)
    }
}

/// What one `protect_summary` call is told.
#[pyclass(module = "swp", name = "ProtectOptions", frozen, skip_from_py_object)]
pub struct PyProtectOptions {
    pub(crate) inner: ProtectOptions,
}

#[pymethods]
impl PyProtectOptions {
    #[new]
    #[pyo3(signature = (mode, *, release_id = None, revision = None))]
    fn new(mode: PyMode, release_id: Option<String>, revision: Option<String>) -> PyResult<Self> {
        // `ProtectOptions::new` is the only constructor the façade offers, on
        // purpose: it is where a mode's defaults come from, and there is no
        // `Default` here to guess at them.
        let mut inner = ProtectOptions::new(Mode::from(mode));
        if let Some(raw) = release_id {
            inner.release_id = Some(ReleaseId::new(raw).map_err(Failure::from)?);
        }
        inner.revision = revision;
        Ok(PyProtectOptions { inner })
    }

    #[getter]
    fn mode(&self) -> PyMode {
        PyMode::from(self.inner.mode)
    }

    #[getter]
    fn release_id(&self) -> Option<String> {
        self.inner
            .release_id
            .as_ref()
            .map(|r| r.as_str().to_string())
    }

    /// A label for the source this run protected, recorded but never trusted.
    #[getter]
    fn revision(&self) -> Option<String> {
        self.inner.revision.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        // The mode's *word*, exactly as `ProtectSummary.to_dict` spells it: the
        // attribute `.mode` stays a `Mode` object, and the document form has to
        // survive `json.dumps`.
        d.set_item("mode", self.mode().name())?;
        d.set_item("release_id", self.release_id())?;
        d.set_item("revision", self.revision())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ProtectOptions", &self.to_dict(py)?)
    }
}

/// What one `verify` call is told.
#[pyclass(module = "swp", name = "VerifyOptions", frozen, skip_from_py_object)]
pub struct PyVerifyOptions {
    pub(crate) inner: VerifyOptions,
}

#[pymethods]
impl PyVerifyOptions {
    #[new]
    #[pyo3(signature = (*, release = None, save = false, rows = None))]
    fn new(release: Option<String>, save: bool, rows: Option<usize>) -> PyResult<Self> {
        Ok(PyVerifyOptions {
            inner: VerifyOptions {
                release: release
                    .map(ReleaseId::new)
                    .transpose()
                    .map_err(Failure::from)?,
                save,
                rows,
            },
        })
    }

    #[getter]
    fn release(&self) -> Option<String> {
        self.inner.release.as_ref().map(|r| r.as_str().to_string())
    }

    /// Whether the run writes its document into `.swp/private/reports/`.
    #[getter]
    fn save(&self) -> bool {
        self.inner.save
    }

    /// How many site rows to render; `None` is the build's own limit.
    #[getter]
    fn rows(&self) -> Option<usize> {
        self.inner.rows
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("release", self.release())?;
        d.set_item("save", self.save())?;
        d.set_item("rows", self.rows())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("VerifyOptions", &self.to_dict(py)?)
    }
}
