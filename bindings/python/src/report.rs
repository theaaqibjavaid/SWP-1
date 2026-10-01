//! The `SWP-1-report-v2` document, and the saved copies of it.
//!
//! `swp-evidence` owns this document: it grades a detection run, states the
//! evidence level with the numbers that produced it, and carries the §51 boundary
//! inside the file so a forwarded report cannot lose it. This module holds that
//! value and reads it. Specifically, it does *not*:
//!
//! * grade evidence, sum confirmations, or compare a probability against a floor;
//! * decide whether a finding is a finding — [`Report::result`] and
//!   [`Report::exit_code`] are the document's own;
//! * render text of its own — `to_text()` calls `swp-evidence`'s renderer, the one
//!   the CLI prints, so a Python program and a terminal show the same sentences;
//! * invent a dict shape of the document. `to_json()` is the serialization the
//!   schema defines, and `from_json()` is the reader that refuses a document it was
//!   not written under.
//!
//! `result` and `evidence_level` come out as the strings a stored report uses
//! (`Outcome::as_str`, `EvidenceLevel::as_str`). `swp-sdk` does not re-export
//! those two Rust enum names — `docs/SDK_API.md` §12 records that as a known gap,
//! not a bug to fix from a binding — and a Python caller needs the words, not the
//! Rust type identity.
//!
//! The same gap shapes how the blocks below are written. `Report` is nameable
//! because `swp-sdk` re-exports it; the types of its `run`, `candidate`,
//! `releases` and `evidence` fields are not, because it does not re-export those.
//! They are still reachable — a field read on an inferred value needs no type
//! name — which is why each projection is written where its argument's type is
//! already known instead of as a free function taking `&ReleaseTally`. Naming
//! those five types here would mean a dependency this crate must not take.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use swp_sdk::{Report, StoredReport};

use crate::error::{repr_of, Failure};

/// The whole document, as `swp-evidence` graded it.
#[pyclass(module = "swp", name = "Report", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyReport {
    pub(crate) inner: Report,
}

/// One saved report, and where it came from.
#[pyclass(module = "swp", name = "StoredReport", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyStoredReport {
    /// The document as it was graded. Re-serializing it yields the stored bytes
    /// unchanged, because the report *is* this type.
    #[pyo3(get)]
    pub report: PyReport,
    /// The stem `Session.read_report` accepts for this document.
    #[pyo3(get)]
    name: String,
    /// Store-relative and forward-slashed.
    #[pyo3(get)]
    path: String,
}

/// The `run` block: who made this document, and when.
#[pyclass(module = "swp", name = "Run", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyRun {
    /// `scan`, `verify`, or `report`: the command whose output this is.
    #[pyo3(get)]
    command: String,
    /// RFC 3339 UTC, supplied by the caller because this crate takes no clock.
    #[pyo3(get)]
    created_at: String,
    /// The build that wrote the document, so an old report can be re-read with the
    /// rules that produced it in hand.
    #[pyo3(get)]
    generator: String,
}

/// The `candidate` block: what was looked at, and how completely.
#[pyclass(module = "swp", name = "Candidate", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyCandidate {
    /// How the input was described on the command line, or where it was staged.
    #[pyo3(get)]
    described: String,
    /// `file`, `directory`, `zip`, `tar`, `tar.gz`, …
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    files_scanned: u32,
    #[pyo3(get)]
    bytes_scanned: u64,
    /// True when something in the candidate was not examined.
    #[pyo3(get)]
    partial: bool,
}

/// One release's tally: the strongest match first.
#[pyclass(module = "swp", name = "ReleaseTally", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyReleaseTally {
    #[pyo3(get)]
    project_id: String,
    #[pyo3(get)]
    release_id: String,
    /// Keyed sites this release holds.
    #[pyo3(get)]
    sites: usize,
    /// Sites whose literal carries this project's code.
    #[pyo3(get)]
    fragments: usize,
    /// Sites present as an address without a code.
    #[pyo3(get)]
    stripped: usize,
    /// Sites with no matching span.
    #[pyo3(get)]
    absent: usize,
    /// Confirmations that are byte-for-byte the recorded rendering.
    #[pyo3(get)]
    exact_renderings: usize,
    /// Confirmations reached only through the rename-tolerant radii.
    #[pyo3(get)]
    canonical_only: usize,
    /// Confirmations found in a file other than the one we protected.
    #[pyo3(get)]
    moved: usize,
    /// Confirmations found as a multi-token rendering.
    #[pyo3(get)]
    renderings: usize,
    /// Distinct candidate files holding a confirmation.
    #[pyo3(get)]
    files: usize,
    /// Keyed bits carried by the confirmed sites.
    #[pyo3(get)]
    bits: u32,
    #[pyo3(get)]
    tag_bits: u8,
    /// Spans that reached a tag comparison.
    #[pyo3(get)]
    probes: u32,
    /// Distinct keyed codes the candidate presented, summed over sites: the draws
    /// `chance` is computed from.
    #[pyo3(get)]
    draws: u32,
    #[pyo3(get)]
    literals_tried: u64,
    #[pyo3(get)]
    windows_tried: u64,
    /// `"match"`, `"no-match"` or `"not-comparable"`.
    #[pyo3(get)]
    fingerprint: String,
    /// `Σ_s [1 − (1 − 2^-tag_bits)^d_s]` over the sites' distinct-code counts: the
    /// upper bound on coincidental confirmations. Printed beside the verdict,
    /// always as the document's own number.
    #[pyo3(get)]
    chance: f64,
    /// Confirmations above that bound — the size of the excess. The verdict is
    /// decided by `coincidence_probability`, not by this.
    #[pyo3(get)]
    guarantee: f64,
    /// The probability that an unrelated tree holding these addresses and none of
    /// this project's codes produces `fragments` confirmations or more: the upper
    /// tail of `Poisson(chance)`.
    #[pyo3(get)]
    coincidence_probability: f64,
    /// `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
    #[pyo3(get)]
    level: String,
    /// The rules that produced `level`, in plain sentences with the numbers in
    /// them.
    #[pyo3(get)]
    reasons: Vec<String>,
}

/// One thing a scan observed.
#[pyclass(module = "swp", name = "EvidenceItem", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyEvidenceItem {
    /// Stable handle for a citation: `EV-001`. Ordering is deterministic.
    #[pyo3(get)]
    id: String,
    /// `EXACT_SOURCE_MATCH`, `WATERMARK_FRAGMENT_MATCH`,
    /// `PARTIAL_WATERMARK_MATCH`, `CANONICAL_MATCH`, `STRUCTURAL_MATCH`,
    /// `TOKEN_MATCH`, `NEGATIVE_CONTROL`.
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    project_id: String,
    #[pyo3(get)]
    release_id: String,
    /// Where it was found in the candidate.
    #[pyo3(get)]
    location: Option<PyRegion>,
    /// Where the corresponding site was in our protected release. Never a lookup
    /// key, but the line a reviewer opens first.
    #[pyo3(get)]
    source_region: Option<PyRegion>,
    /// Why this counts, in words, with the measured numbers in it.
    #[pyo3(get)]
    basis: String,
    /// The strength of *this item*, on the same ladder as the overall level.
    #[pyo3(get)]
    strength: String,
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    schema: u16,
}

/// Where an observation was: a file, a line, and what was seen there.
#[pyclass(module = "swp", name = "Region", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyRegion {
    /// Project-relative path, forward slashes.
    #[pyo3(get)]
    file: String,
    /// One-based line, as the adapter counted it.
    #[pyo3(get)]
    line: u32,
    /// The matched text, truncated to the report hint bound. Absent for a
    /// source-side region.
    #[pyo3(get)]
    excerpt: Option<String>,
    /// How many tokens the matched span covers.
    #[pyo3(get)]
    tokens: Option<u8>,
    /// Which of the release's four keyed radii reproduced this span.
    #[pyo3(get)]
    radii: Vec<String>,
}

#[pymethods]
impl PyReport {
    /// `SWP-1-report-v2`.
    #[getter]
    fn schema(&self) -> String {
        self.inner.schema.clone()
    }

    /// The protocol this build speaks: `SWP-1`.
    #[getter]
    fn protocol(&self) -> String {
        self.inner.protocol.clone()
    }

    #[getter]
    fn run(&self) -> PyRun {
        let inner = &self.inner.run;
        PyRun {
            command: inner.command.clone(),
            created_at: inner.created_at.clone(),
            generator: inner.generator.clone(),
        }
    }

    #[getter]
    fn candidate(&self) -> PyCandidate {
        let inner = &self.inner.candidate;
        PyCandidate {
            described: inner.described.clone(),
            kind: inner.kind.clone(),
            files_scanned: inner.files_scanned,
            bytes_scanned: inner.bytes_scanned,
            partial: inner.partial,
        }
    }

    /// `PROVENANCE_DETECTED`, `NO_PROVENANCE_DETECTED`, `INCONCLUSIVE`.
    #[getter]
    fn result(&self) -> String {
        self.inner.result.as_str().to_string()
    }

    /// The §23 level: `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
    #[getter]
    fn evidence_level(&self) -> String {
        self.inner.evidence_level.as_str().to_string()
    }

    /// Why that level, one sentence per rule that fired, with the measured numbers.
    #[getter]
    fn explanation(&self) -> Vec<String> {
        self.inner.explanation.clone()
    }

    /// One entry per release the candidate was scanned against, strongest first.
    ///
    /// The projections below are written as closures rather than as `fn` items
    /// taking `&ReleaseTally` or `&EvidenceItem`, because those are the same five
    /// unnameable types: the closure's argument type is inferred from the field
    /// read, so the copy is spelled once and no crate this one must not depend on
    /// gets named.
    #[getter]
    fn releases(&self) -> Vec<PyReleaseTally> {
        self.inner
            .releases
            .iter()
            .map(|tally| PyReleaseTally {
                project_id: tally.project_id.clone(),
                release_id: tally.release_id.clone(),
                sites: tally.sites,
                fragments: tally.fragments,
                stripped: tally.stripped,
                absent: tally.absent,
                exact_renderings: tally.exact_renderings,
                canonical_only: tally.canonical_only,
                moved: tally.moved,
                renderings: tally.renderings,
                files: tally.files,
                bits: tally.bits,
                tag_bits: tally.tag_bits,
                probes: tally.probes,
                draws: tally.draws,
                literals_tried: tally.literals_tried,
                windows_tried: tally.windows_tried,
                fingerprint: tally.fingerprint.clone(),
                chance: tally.chance,
                guarantee: tally.guarantee,
                coincidence_probability: tally.coincidence_probability,
                level: tally.level.as_str().to_string(),
                reasons: tally.reasons.clone(),
            })
            .collect()
    }

    #[getter]
    fn evidence(&self) -> Vec<PyEvidenceItem> {
        self.inner
            .evidence
            .iter()
            .map(|item| PyEvidenceItem {
                id: item.id.clone(),
                kind: item.kind.as_str().to_string(),
                project_id: item.project_id.clone(),
                release_id: item.release_id.clone(),
                location: item.location.as_ref().map(|r| PyRegion {
                    file: r.file.clone(),
                    line: r.line,
                    excerpt: r.excerpt.clone(),
                    tokens: r.tokens,
                    radii: r.radii.clone(),
                }),
                source_region: item.source_region.as_ref().map(|r| PyRegion {
                    file: r.file.clone(),
                    line: r.line,
                    excerpt: r.excerpt.clone(),
                    tokens: r.tokens,
                    radii: r.radii.clone(),
                }),
                basis: item.basis.clone(),
                strength: item.strength.as_str().to_string(),
                protocol: item.protocol.clone(),
                schema: item.schema,
            })
            .collect()
    }

    /// Files the walk refused, with the reason.
    #[getter]
    fn omissions(&self) -> Vec<String> {
        self.inner.omissions.clone()
    }

    /// Caveats: hypothesis caps, widths probed, containers not opened.
    #[getter]
    fn notes(&self) -> Vec<String> {
        self.inner.notes.clone()
    }

    /// The §51 boundary, carried inside the document rather than left to a README.
    #[getter]
    fn limitations(&self) -> Vec<String> {
        self.inner.limitations.clone()
    }

    /// What `swp scan` exits with: `0` nothing confirmed, `1` something was, `10`
    /// the scan could not have said either way.
    fn exit_code(&self) -> i32 {
        self.inner.exit_code()
    }

    /// Machine-readable form, pretty-printed with a trailing newline, byte-for-byte
    /// the document a saved report holds.
    fn to_json(&self) -> String {
        self.inner.to_json()
    }

    /// The human-facing rendering, the same text `swp scan` prints. `full` prints
    /// every evidence item; without it the list is windowed and the remainder
    /// counted.
    #[pyo3(signature = (*, full = false))]
    fn to_text(&self, full: bool) -> String {
        self.inner.to_text(full)
    }

    /// As `to_text()`, with the evidence window sized by the caller — which is
    /// what `swp scan --limit <n>` asks for. Only the text is ever windowed.
    fn to_text_items(&self, items: usize) -> String {
        self.inner.to_text_items(items)
    }

    /// Read a stored report back, refusing anything that is not this schema.
    ///
    /// A document from another schema is not damage: it is a record of arithmetic
    /// this build does not apply, and the refusal says so rather than re-grading
    /// it under rules it was not written under.
    #[staticmethod]
    fn from_json(text: &str) -> Result<Self, Failure> {
        Report::from_json(text)
            .map(PyReport::from)
            .map_err(Failure::from)
    }

    /// The verdict line, and nothing else: this object's whole account is the
    /// document, and a repr that tried to list twelve fields would be a second
    /// copy of it in a traceback.
    fn __repr__(&self) -> String {
        format!(
            "Report(schema='{}', result='{}', evidence_level='{}')",
            self.inner.schema,
            self.inner.result.as_str(),
            self.inner.evidence_level.as_str(),
        )
    }
}

#[pymethods]
impl PyStoredReport {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("name", &self.name)?;
        d.set_item("path", &self.path)?;
        d.set_item("result", self.report.inner.result.as_str())?;
        d.set_item("evidence_level", self.report.inner.evidence_level.as_str())?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("StoredReport", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyRun {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("command", &self.command)?;
        d.set_item("created_at", &self.created_at)?;
        d.set_item("generator", &self.generator)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Run", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyCandidate {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("described", &self.described)?;
        d.set_item("kind", &self.kind)?;
        d.set_item("files_scanned", self.files_scanned)?;
        d.set_item("bytes_scanned", self.bytes_scanned)?;
        d.set_item("partial", self.partial)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Candidate", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyReleaseTally {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("project_id", &self.project_id)?;
        d.set_item("release_id", &self.release_id)?;
        d.set_item("sites", self.sites)?;
        d.set_item("fragments", self.fragments)?;
        d.set_item("stripped", self.stripped)?;
        d.set_item("absent", self.absent)?;
        d.set_item("exact_renderings", self.exact_renderings)?;
        d.set_item("canonical_only", self.canonical_only)?;
        d.set_item("moved", self.moved)?;
        d.set_item("renderings", self.renderings)?;
        d.set_item("files", self.files)?;
        d.set_item("bits", self.bits)?;
        d.set_item("tag_bits", self.tag_bits)?;
        d.set_item("probes", self.probes)?;
        d.set_item("draws", self.draws)?;
        d.set_item("literals_tried", self.literals_tried)?;
        d.set_item("windows_tried", self.windows_tried)?;
        d.set_item("fingerprint", &self.fingerprint)?;
        d.set_item("chance", self.chance)?;
        d.set_item("guarantee", self.guarantee)?;
        d.set_item("coincidence_probability", self.coincidence_probability)?;
        d.set_item("level", &self.level)?;
        d.set_item("reasons", &self.reasons)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ReleaseTally", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyEvidenceItem {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("id", &self.id)?;
        d.set_item("kind", &self.kind)?;
        d.set_item("project_id", &self.project_id)?;
        d.set_item("release_id", &self.release_id)?;
        let location = match &self.location {
            Some(r) => Some(r.to_dict(py)?),
            None => None,
        };
        d.set_item("location", location)?;
        let source = match &self.source_region {
            Some(r) => Some(r.to_dict(py)?),
            None => None,
        };
        d.set_item("source_region", source)?;
        d.set_item("basis", &self.basis)?;
        d.set_item("strength", &self.strength)?;
        d.set_item("protocol", &self.protocol)?;
        d.set_item("schema", self.schema)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("EvidenceItem", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyRegion {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("file", &self.file)?;
        d.set_item("line", self.line)?;
        d.set_item("excerpt", &self.excerpt)?;
        d.set_item("tokens", self.tokens)?;
        let radii = PyList::new(py, self.radii.iter())?;
        d.set_item("radii", radii)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Region", &self.to_dict(py)?)
    }
}

impl From<Report> for PyReport {
    fn from(inner: Report) -> Self {
        PyReport { inner }
    }
}

impl PyStoredReport {
    pub(crate) fn from_stored(inner: StoredReport) -> Self {
        PyStoredReport {
            report: PyReport::from(inner.report),
            name: inner.name,
            path: inner.path,
        }
    }
}
