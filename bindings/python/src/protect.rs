//! What a protection run decided, in the form a foreign binding may hold.
//!
//! This is the boundary [docs/adr/0001-protect-generate-binding-boundary.md] drew,
//! spelled as Python fields. `swp-sdk` offers two accounts of one run:
//! `Session::protect` returns the plan the run wrote, whose sites carry four keyed
//! location ids each, and `Session::protect_summary` returns the same account of
//! the run with the keyed half *never read into it*. The Python surface has the
//! second one only — `protect_summary` is the operation, and there is no Python
//! name for the other.
//!
//! The field list here is `ProtectSummary`'s, one for one, so the summary a caller
//! reads has the same twenty values the CLI reads. Nothing is re-derived: no site
//! identity, no tag, no coincidence arithmetic, and no second implementation of
//! the decision to skip a location.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use swp_sdk::{ProtectSummary, ProtectedFile, ProtectedSite, RefusedSite};

use crate::error::repr_of;
use crate::options::PyMode;

/// What a protection run decided, as far as a caller outside Rust may see it.
#[pyclass(module = "swp", name = "ProtectSummary", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProtectSummary {
    /// Which of the three modes ran. Only `release` rewrites source; `plan` leaves
    /// a plan document in the private store and `dry_run` leaves nothing at all,
    /// which is what `artifacts` reports.
    #[pyo3(get)]
    mode: PyMode,
    #[pyo3(get)]
    project_id: String,
    /// The release this run minted or was given. For `Mode.PLAN` this is the id to
    /// pass back as `release_id` to apply the constellation, and passing a
    /// different one derives different keys and silently makes a second release.
    #[pyo3(get)]
    release_id: String,
    /// RFC 3339, UTC.
    #[pyo3(get)]
    created_at: String,
    /// What the operator said the source was, trimmed; `None` when nothing was
    /// said. Display metadata, never hashed.
    #[pyo3(get)]
    revision: Option<String>,
    /// §16 fingerprint of the tree as it now stands, hex.
    #[pyo3(get)]
    fingerprint: String,
    /// How that fingerprint was taken, so a later tree can be compared honestly.
    #[pyo3(get)]
    fingerprint_level: String,
    #[pyo3(get)]
    tag_bits: u8,
    /// Sites the caller asked for, before the ceilings trimmed it.
    #[pyo3(get)]
    requested_sites: u32,
    /// Sites the ceilings allowed.
    #[pyo3(get)]
    target_sites: u32,
    #[pyo3(get)]
    sites_embedded: u32,
    #[pyo3(get)]
    sites_skipped: u32,
    /// Files analyzed inside the project's `[protect] targets`.
    #[pyo3(get)]
    files_walked: usize,
    /// Files counted into the fingerprint across the whole tree.
    #[pyo3(get)]
    files_in_scope: usize,
    /// Literals that could have carried a fragment.
    #[pyo3(get)]
    candidates: usize,
    /// Every file the constellation lands in, in write order, with the byte counts
    /// of the rewrite it produces. `release` leaves those bytes on disk; `plan` and
    /// `dry_run` report the same list as what they *would* change and touch no
    /// source, so `mode` and `artifacts` — not this list — say whether the tree moved.
    #[pyo3(get)]
    files_changed: Vec<PyProtectedFile>,
    /// Every site the release carries, in plan order. Its length is
    /// `sites_embedded`.
    #[pyo3(get)]
    sites: Vec<PyProtectedSite>,
    /// Every candidate the run did not use, in the order the refusals were
    /// recorded. Its length is `sites_skipped`.
    #[pyo3(get)]
    refusals: Vec<PyRefusedSite>,
    /// Every artifact the run wrote, in write order: store-relative under `.swp/`,
    /// project-relative for protected source. Empty for `dry_run`.
    #[pyo3(get)]
    artifacts: Vec<String>,
    /// What the walk and the ceilings reported but did not act on.
    #[pyo3(get)]
    notes: Vec<String>,
}

/// One file a protection run changes, or would change, and how much of it moves.
#[pyclass(module = "swp", name = "ProtectedFile", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProtectedFile {
    /// Canonical project-relative path, forward-slashed.
    #[pyo3(get)]
    file: String,
    /// Sites this run embedded in this file.
    #[pyo3(get)]
    sites: u32,
    #[pyo3(get)]
    bytes_before: u64,
    #[pyo3(get)]
    bytes_after: u64,
}

/// One site the release carries, as far as a caller outside Rust may see it.
///
/// Which four keyed addresses a site answers to decides which tags a copy must
/// carry, so a list of them is the private constellation in printable form. What a
/// caller acts on is where the mark went and how it was carried, which is every
/// field here.
#[pyclass(module = "swp", name = "ProtectedSite", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProtectedSite {
    /// Canonical project-relative path.
    #[pyo3(get)]
    file: String,
    /// 1-based line in the protected text, where a reader will look. A hint: it is
    /// measured before the rewrite, so the line of a multi-line literal is
    /// approximate by design.
    #[pyo3(get)]
    line_hint: u32,
    #[pyo3(get)]
    language: String,
    /// `"ast"` or `"lexical"`: how much the tool understood here.
    #[pyo3(get)]
    adapter: String,
    /// `"integer"` or `"string"`, as the Python attribute `class_`: `class` is a
    /// keyword, so the value is reached with a trailing underscore here and with
    /// the document's own key in `to_dict()`.
    class: String,
    /// The equivalent-form family that carried the mark.
    #[pyo3(get)]
    family: String,
    /// Bits the tag carries, which equals `ProtectSummary.tag_bits`.
    #[pyo3(get)]
    width: u8,
    /// The radius kind the tag derived from: `0` statement+identifiers, `1`
    /// scope+identifiers, `2` statement+names, `3` scope+names. A slot selector,
    /// not a key and not keyed material.
    #[pyo3(get)]
    primary: u8,
}

/// One candidate location the run refused, and why.
///
/// The refusal's *sentence* stays out, because the sentence interpolates a
/// rendered tag. `reason` is the stable token from the same record and carries
/// nothing.
#[pyclass(module = "swp", name = "RefusedSite", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyRefusedSite {
    #[pyo3(get)]
    file: String,
    #[pyo3(get)]
    line_hint: u32,
    /// `overlapping-radius`, `constellation-full`, `changed-after-scan`,
    /// `refused-by-validation`, and the other tokens `swp-embedding` uses.
    #[pyo3(get)]
    reason: String,
}

#[pymethods]
impl PyProtectSummary {
    /// Files that hold at least one embedded site.
    fn files_with_sites(&self) -> usize {
        self.files_changed.iter().filter(|f| f.sites > 0).count()
    }

    /// The distinct languages this run wrote sites into.
    fn languages(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for site in &self.sites {
            if !seen.iter().any(|l| l == &site.language) {
                seen.push(site.language.clone());
            }
        }
        seen.sort();
        seen
    }

    /// The refusal tokens this run produced, with how often each one fired.
    ///
    /// Sorted, so the dict a caller prints is the same dict on every run that
    /// produced the same refusals.
    fn refusal_counts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let mut counts: Vec<(String, u32)> = Vec::new();
        for site in &self.refusals {
            match counts.iter_mut().find(|(reason, _)| *reason == site.reason) {
                Some((_, n)) => *n += 1,
                None => counts.push((site.reason.clone(), 1)),
            }
        }
        counts.sort();
        let d = PyDict::new(py);
        for (reason, n) in counts {
            d.set_item(reason, n)?;
        }
        Ok(d)
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        // The mode's *name*, so the dict is JSON-serializable end to end: the
        // attribute `ProtectSummary.mode` stays a `Mode`, and the document form is
        // the word the saved plan uses.
        d.set_item("mode", self.mode.name())?;
        d.set_item("project_id", &self.project_id)?;
        d.set_item("release_id", &self.release_id)?;
        d.set_item("created_at", &self.created_at)?;
        d.set_item("revision", &self.revision)?;
        d.set_item("fingerprint", &self.fingerprint)?;
        d.set_item("fingerprint_level", &self.fingerprint_level)?;
        d.set_item("tag_bits", self.tag_bits)?;
        d.set_item("requested_sites", self.requested_sites)?;
        d.set_item("target_sites", self.target_sites)?;
        d.set_item("sites_embedded", self.sites_embedded)?;
        d.set_item("sites_skipped", self.sites_skipped)?;
        d.set_item("files_walked", self.files_walked)?;
        d.set_item("files_in_scope", self.files_in_scope)?;
        d.set_item("candidates", self.candidates)?;
        let files = PyList::empty(py);
        for file in &self.files_changed {
            files.append(file.to_dict(py)?)?;
        }
        d.set_item("files_changed", files)?;
        let sites = PyList::empty(py);
        for site in &self.sites {
            sites.append(site.to_dict(py)?)?;
        }
        d.set_item("sites", sites)?;
        let refusals = PyList::empty(py);
        for site in &self.refusals {
            refusals.append(site.to_dict(py)?)?;
        }
        d.set_item("refusals", refusals)?;
        d.set_item("artifacts", &self.artifacts)?;
        d.set_item("notes", &self.notes)?;
        Ok(d)
    }

    /// The four values a caller branches on, and nothing else. A run's whole
    /// account is what `to_dict` is for; this line is what appears in a traceback,
    /// so it names the release and the counts and stops.
    fn __repr__(&self) -> String {
        format!(
            "ProtectSummary(mode='{}', release_id='{}', sites_embedded={}, sites_skipped={})",
            self.mode.name(),
            self.release_id,
            self.sites_embedded,
            self.sites_skipped
        )
    }
}

#[pymethods]
impl PyProtectedFile {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("file", &self.file)?;
        d.set_item("sites", self.sites)?;
        d.set_item("bytes_before", self.bytes_before)?;
        d.set_item("bytes_after", self.bytes_after)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ProtectedFile", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyProtectedSite {
    /// `"integer"` or `"string"`, spelled `class_` because `class` is a keyword.
    #[getter]
    fn class_(&self) -> String {
        self.class.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("file", &self.file)?;
        d.set_item("line_hint", self.line_hint)?;
        d.set_item("language", &self.language)?;
        d.set_item("adapter", &self.adapter)?;
        d.set_item("class", &self.class)?;
        d.set_item("family", &self.family)?;
        d.set_item("width", self.width)?;
        d.set_item("primary", self.primary)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ProtectedSite", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyRefusedSite {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("file", &self.file)?;
        d.set_item("line_hint", self.line_hint)?;
        d.set_item("reason", &self.reason)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("RefusedSite", &self.to_dict(py)?)
    }
}

impl PyProtectSummary {
    pub(crate) fn from_summary(inner: ProtectSummary) -> Self {
        PyProtectSummary {
            mode: PyMode::from(inner.mode),
            project_id: inner.project_id.as_str().to_string(),
            release_id: inner.release_id.as_str().to_string(),
            created_at: inner.created_at.to_rfc3339(),
            revision: inner.revision.clone(),
            fingerprint: inner.fingerprint.hex(),
            fingerprint_level: inner.fingerprint_level.clone(),
            tag_bits: inner.tag_bits,
            requested_sites: inner.requested_sites,
            target_sites: inner.target_sites,
            sites_embedded: inner.sites_embedded,
            sites_skipped: inner.sites_skipped,
            files_walked: inner.files_walked,
            files_in_scope: inner.files_in_scope,
            candidates: inner.candidates,
            files_changed: inner.files_changed.iter().map(project_file).collect(),
            sites: inner.sites.iter().map(project_site).collect(),
            refusals: inner.refusals.iter().map(project_refusal).collect(),
            artifacts: inner.artifacts.clone(),
            notes: inner.notes.clone(),
        }
    }
}

fn project_file(inner: &ProtectedFile) -> PyProtectedFile {
    PyProtectedFile {
        file: inner.file.clone(),
        sites: inner.sites,
        bytes_before: inner.bytes_before,
        bytes_after: inner.bytes_after,
    }
}

fn project_site(inner: &ProtectedSite) -> PyProtectedSite {
    PyProtectedSite {
        file: inner.file.clone(),
        line_hint: inner.line_hint,
        language: inner.language.clone(),
        adapter: inner.adapter.clone(),
        class: inner.class.clone(),
        family: inner.family.clone(),
        width: inner.width,
        primary: inner.primary,
    }
}

fn project_refusal(inner: &RefusedSite) -> PyRefusedSite {
    PyRefusedSite {
        file: inner.file.clone(),
        line_hint: inner.line_hint,
        reason: inner.reason.clone(),
    }
}
