//! What a scan of somebody else's artifact returned.
//!
//! [`ScanOutcome`] is three things: the graded `SWP-1-report-v2` document, where a
//! saved copy went if the caller asked for one, and the per-site rows the document
//! only carries summed. The division of labour underneath it is the protocol's —
//! `swp-detection` reads the candidate and matches keyed addresses, `swp-evidence`
//! decides what the matches mean — and this module holds the result of both. It
//! grades nothing: `result`, `evidence_level` and the exit code are read off the
//! report by [`crate::report`], and the rows here are copied out of the detector's
//! own rows, so a site graded `absent` here is graded `absent` in the document.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{SavedReport, ScanOutcome, ScannedSite};

use crate::error::repr_of;
use crate::report::PyReport;

/// What a scan returned: the graded document, and where a saved copy went.
#[pyclass(module = "swp", name = "ScanOutcome", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyScanOutcome {
    pub(crate) inner: ScanOutcome,
}

/// The name and the path of one report a run saved.
#[pyclass(module = "swp", name = "SavedReport", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySavedReport {
    /// What `Session.read_report` takes to get this document back. When two saves
    /// land in the same second the store numbers the collision, so this is the name
    /// it wrote under, which is not necessarily the one it was given.
    #[pyo3(get)]
    name: String,
    /// Store-relative and forward-slashed, so it is safe to print and will not
    /// reveal where the project lives.
    #[pyo3(get)]
    path: String,
}

/// One expected site, and what the candidate presented at its address.
///
/// Deliberately free of anything keyed: the location ids and the expected codes a
/// match was decided against stay inside `swp-detection`, so a row here says
/// *that* a span confirmed and how much work reaching it took, without being a list
/// of the values that would let a caller test a guess against a site that was never
/// hit.
#[pyclass(module = "swp", name = "ScannedSite", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyScannedSite {
    /// Which release this site belongs to. The report's `releases` are ordered best
    /// first; these rows are in scan order, so the id is what joins a row to its
    /// tally.
    #[pyo3(get)]
    release_id: String,
    /// Index into that release's site list, matching `swp inspect manifest`.
    #[pyo3(get)]
    site: usize,
    /// `absent`, `location-only`, `tag-confirmed` or `exact-rendering`.
    #[pyo3(get)]
    status: String,
    /// Spans at this site's address that reached a tag comparison.
    #[pyo3(get)]
    probes: u32,
    /// Distinct codes those spans presented: this site's share of the draws the
    /// report's coincidence bound is computed from.
    #[pyo3(get)]
    distinct_codes: u32,
    /// How many tokens the confirming span covers. `255` stands for "at least 255":
    /// the count saturates rather than wrapping.
    #[pyo3(get)]
    found_tokens: u8,
    /// Where the match actually was, when the candidate had it at all.
    #[pyo3(get)]
    found_in: Option<String>,
    #[pyo3(get)]
    found_line: Option<u32>,
    /// The literal found there, truncated to the report hint bound — the same text
    /// an evidence item quotes as its `excerpt`.
    #[pyo3(get)]
    found_excerpt: Option<String>,
}

#[pymethods]
impl PyScanOutcome {
    /// The document `swp-evidence` graded, verbatim.
    #[getter]
    fn report(&self) -> PyReport {
        PyReport::from(self.inner.report.clone())
    }

    /// `None` unless the caller asked for a copy under `.swp/private/reports/`.
    #[getter]
    fn saved(&self) -> Option<PySavedReport> {
        self.inner.saved.as_ref().map(project_saved)
    }

    /// Every site the scan looked for, in the order the releases were scanned and
    /// then the order the release records them.
    #[getter]
    fn sites(&self) -> Vec<PyScannedSite> {
        self.inner
            .sites
            .iter()
            .map(project_site)
            .collect::<Vec<PyScannedSite>>()
    }

    /// The verdict word, the level, and how many sites were looked for — the three
    /// values a caller reads first. The document itself is `report`.
    fn __repr__(&self) -> String {
        format!(
            "ScanOutcome(result='{}', evidence_level='{}', sites={})",
            self.inner.report.result.as_str(),
            self.inner.report.evidence_level.as_str(),
            self.inner.sites.len(),
        )
    }
}

#[pymethods]
impl PySavedReport {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("name", &self.name)?;
        d.set_item("path", &self.path)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("SavedReport", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyScannedSite {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("release_id", &self.release_id)?;
        d.set_item("site", self.site)?;
        d.set_item("status", &self.status)?;
        d.set_item("probes", self.probes)?;
        d.set_item("distinct_codes", self.distinct_codes)?;
        d.set_item("found_tokens", self.found_tokens)?;
        d.set_item("found_in", &self.found_in)?;
        d.set_item("found_line", self.found_line)?;
        d.set_item("found_excerpt", &self.found_excerpt)?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!(
            "ScannedSite(release_id='{}', site={}, status='{}')",
            self.release_id, self.site, self.status
        )
    }
}

impl PyScanOutcome {
    pub(crate) fn from_outcome(inner: ScanOutcome) -> Self {
        PyScanOutcome { inner }
    }
}

fn project_saved(inner: &SavedReport) -> PySavedReport {
    PySavedReport {
        name: inner.name.clone(),
        path: inner.path.clone(),
    }
}

fn project_site(inner: &ScannedSite) -> PyScannedSite {
    PyScannedSite {
        release_id: inner.release_id.clone(),
        site: inner.site,
        status: inner.status.to_string(),
        probes: inner.probes,
        distinct_codes: inner.distinct_codes,
        found_tokens: inner.found_tokens,
        found_in: inner.found_in.clone(),
        found_line: inner.found_line,
        found_excerpt: inner.found_excerpt.clone(),
    }
}
