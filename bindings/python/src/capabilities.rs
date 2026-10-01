//! What this build can do, as Python values rather than as a README.
//!
//! `swp_sdk::capabilities()` is the Rust call this module exists to re-speak. It is
//! here because the alternative is a caller carrying its own guess at the language
//! list and the numeric ranges. Every number below is read from the crate that
//! enforces it, by `swp-sdk`, and this module only turns those values into Python
//! objects — it derives no range, orders no list, and adds no language.
//!
//! What a listing does *not* promise: a language named here is one this build
//! **parses**. It says nothing about which literal forms survive a safety check.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{Capabilities, DefaultPolicy, LanguageInfo, SiteRange, TagRange};

use crate::error::repr_of;

/// Everything about this build a caller may need to know without asking a human.
#[pyclass(module = "swp", name = "Capabilities", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyCapabilities {
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    swp_version: String,
    #[pyo3(get)]
    report_schema: String,
    #[pyo3(get)]
    canonicalizer_version: u16,
    #[pyo3(get)]
    languages: Vec<PyLanguageInfo>,
    #[pyo3(get)]
    tag_bits: PyTagRange,
    #[pyo3(get)]
    target_sites: PySiteRange,
    #[pyo3(get)]
    defaults: PyDefaultPolicy,
}

/// A language this build analyzes, and the file names it answers to.
#[pyclass(module = "swp", name = "LanguageInfo", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyLanguageInfo {
    /// The stable identifier a manifest records. Never renamed.
    #[pyo3(get)]
    name: String,
    /// Lowercase, without the dot.
    #[pyo3(get)]
    extensions: Vec<String>,
}

/// The inclusive range of tag widths a site may carry.
#[pyclass(module = "swp", name = "TagRange", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyTagRange {
    #[pyo3(get)]
    min: u8,
    #[pyo3(get)]
    max: u8,
    #[pyo3(get)]
    default: u8,
}

/// The inclusive range of constellation sizes a project may aim at.
#[pyclass(module = "swp", name = "SiteRange", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySiteRange {
    #[pyo3(get)]
    min: u32,
    #[pyo3(get)]
    default: u32,
    #[pyo3(get)]
    max: u32,
}

/// The settings a project starts from before it edits its config.
#[pyclass(module = "swp", name = "DefaultPolicy", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyDefaultPolicy {
    /// Directories and patterns never walked, whatever a project configures.
    #[pyo3(get)]
    excludes: Vec<String>,
}

#[pymethods]
impl PyCapabilities {
    /// The names of the parsed languages, for a caller that only branches on them.
    fn language_names(&self) -> Vec<String> {
        self.languages.iter().map(|l| l.name.clone()).collect()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("protocol", &self.protocol)?;
        d.set_item("swp_version", &self.swp_version)?;
        d.set_item("report_schema", &self.report_schema)?;
        d.set_item("canonicalizer_version", self.canonicalizer_version)?;
        let rows = PyDict::new(py);
        for l in &self.languages {
            rows.set_item(&l.name, l.extensions.clone())?;
        }
        d.set_item("languages", rows)?;
        d.set_item("tag_bits", self.tag_bits.to_dict(py)?)?;
        d.set_item("target_sites", self.target_sites.to_dict(py)?)?;
        d.set_item("defaults", self.defaults.to_dict(py)?)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Capabilities", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyLanguageInfo {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("name", &self.name)?;
        d.set_item("extensions", &self.extensions)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("LanguageInfo", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyTagRange {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("min", self.min)?;
        d.set_item("max", self.max)?;
        d.set_item("default", self.default)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("TagRange", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PySiteRange {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("min", self.min)?;
        d.set_item("default", self.default)?;
        d.set_item("max", self.max)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("SiteRange", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyDefaultPolicy {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("excludes", &self.excludes)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("DefaultPolicy", &self.to_dict(py)?)
    }
}

/// The machine-readable answer to "what can this build do".
///
/// It touches nothing: no filesystem, no project, no secret. It cannot fail.
#[pyfunction]
pub fn capabilities() -> PyCapabilities {
    project(&swp_sdk::capabilities())
}

pub(crate) fn project(inner: &Capabilities) -> PyCapabilities {
    PyCapabilities {
        protocol: inner.protocol.clone(),
        swp_version: inner.swp_version.clone(),
        report_schema: inner.report_schema.clone(),
        canonicalizer_version: inner.canonicalizer_version,
        languages: inner.languages.iter().map(project_language).collect(),
        tag_bits: project_tag(&inner.tag_bits),
        target_sites: project_site(&inner.target_sites),
        defaults: project_defaults(&inner.defaults),
    }
}

fn project_language(inner: &LanguageInfo) -> PyLanguageInfo {
    PyLanguageInfo {
        name: inner.name.to_string(),
        extensions: inner.extensions.clone(),
    }
}

fn project_tag(inner: &TagRange) -> PyTagRange {
    PyTagRange {
        min: inner.min,
        max: inner.max,
        default: inner.default,
    }
}

fn project_site(inner: &SiteRange) -> PySiteRange {
    PySiteRange {
        min: inner.min,
        default: inner.default,
        max: inner.max,
    }
}

fn project_defaults(inner: &DefaultPolicy) -> PyDefaultPolicy {
    PyDefaultPolicy {
        excludes: inner.excludes.clone(),
    }
}
