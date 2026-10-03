//! A verification's answer: the `SWP-1-verify-v1` document, with its own words.
//!
//! The document is `swp-evidence`'s. It is built by `grade()` inside
//! `Session::verify`, from the detection run and the release's authenticated
//! manifest, and this module holds that value: every getter below reads a field
//! off it, and `to_json()` serializes it. Nothing here decides a verdict, counts a
//! site, compares a probability, or maps a result to an exit code — the document
//! already carries all four, because the same numbers have to be readable by
//! whoever receives the file later.
//!
//! Holding the Rust document rather than copying its fields is deliberate: a copy
//! could go stale against the schema, and `to_json()` on a copy would be the
//! binding's own document with a familiar name.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use swp_sdk::{SiteRow, VerifyDocument, VerifyOutcome};

use crate::error::{repr_of, Failure};

/// A verification's answer: the document, and where a saved copy went.
#[pyclass(module = "swp", name = "VerifyOutcome", frozen, skip_from_py_object)]
pub struct PyVerifyOutcome {
    document: VerifyDocument,
    report_saved: Option<String>,
}

/// One site of the release, and whether it is still there.
///
/// `SiteRow` is not `Clone`, so these rows are copied out when the outcome is
/// built. `confirmed` is not this binding's judgement: it is `SiteRow::confirmed`,
/// which asks the one place the protocol draws the watermark/not-watermark line.
#[pyclass(module = "swp", name = "SiteRow", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySiteRow {
    /// Index into the release's site list, matching `swp inspect manifest`.
    #[pyo3(get)]
    site: usize,
    /// Where this site was when the release was made. A hint for a human, never a
    /// lookup key — a site that moved is still the same site.
    #[pyo3(get)]
    file: String,
    #[pyo3(get)]
    line_hint: u32,
    #[pyo3(get)]
    language: String,
    #[pyo3(get)]
    adapter: String,
    /// `"integer"` or `"string"`, as the Python attribute `class_`.
    class: String,
    #[pyo3(get)]
    family: String,
    #[pyo3(get)]
    width: u8,
    /// `absent`, `location-only`, `tag-confirmed` or `exact-rendering`.
    #[pyo3(get)]
    status: String,
    /// Whether this row is watermark evidence, as `swp-evidence` grades it.
    #[pyo3(get)]
    confirmed: bool,
    /// Which of the four keyed radii the tree reproduced.
    #[pyo3(get)]
    slots: Vec<String>,
    /// Where the site was actually found, when that differs from `file`.
    #[pyo3(get)]
    found_in: Option<String>,
    #[pyo3(get)]
    found_line: Option<u32>,
    #[pyo3(get)]
    refactored: bool,
    #[pyo3(get)]
    moved: bool,
}

#[pymethods]
impl PyVerifyOutcome {
    /// `SWP-1-verify-v1`.
    #[getter]
    fn schema(&self) -> String {
        self.document.schema.to_string()
    }

    /// The protocol this document speaks: `SWP-1`.
    #[getter]
    fn protocol(&self) -> String {
        self.document.protocol.to_string()
    }

    #[getter]
    fn project_id(&self) -> String {
        self.document.project_id.clone()
    }

    #[getter]
    fn display_name(&self) -> String {
        self.document.display_name.clone()
    }

    /// How the tree being verified was described by the code that opened it.
    #[getter]
    fn tree(&self) -> String {
        self.document.tree.clone()
    }

    #[getter]
    fn release_id(&self) -> String {
        self.document.release_id.clone()
    }

    /// RFC 3339, UTC, as the release record recorded it.
    #[getter]
    fn release_created_at(&self) -> String {
        self.document.release_created_at.clone()
    }

    /// The label the release recorded, or `None` when it recorded content only.
    /// Display metadata: an attacker can write anything here and the detector
    /// reads nothing from it.
    #[getter]
    fn revision(&self) -> Option<String> {
        self.document.revision.clone()
    }

    /// Whether the release's manifest authenticated against the identity in
    /// `.swp/public/identity.json` — the precondition for every claim below.
    #[getter]
    fn manifest_authenticated(&self) -> bool {
        self.document.manifest_authenticated
    }

    #[getter]
    fn sites_expected(&self) -> usize {
        self.document.sites_expected
    }

    #[getter]
    fn sites_confirmed(&self) -> usize {
        self.document.sites_confirmed
    }

    #[getter]
    fn sites_exact(&self) -> usize {
        self.document.sites_exact
    }

    #[getter]
    fn sites_stripped(&self) -> usize {
        self.document.sites_stripped
    }

    #[getter]
    fn sites_absent(&self) -> usize {
        self.document.sites_absent
    }

    #[getter]
    fn sites_moved(&self) -> usize {
        self.document.sites_moved
    }

    #[getter]
    fn sites_refactored(&self) -> usize {
        self.document.sites_refactored
    }

    #[getter]
    fn tag_bits(&self) -> u8 {
        self.document.tag_bits
    }

    /// Keyed bits the confirmed sites carry.
    #[getter]
    fn confirmed_bits(&self) -> u32 {
        self.document.confirmed_bits
    }

    #[getter]
    fn files_scanned(&self) -> u32 {
        self.document.files_scanned
    }

    #[getter]
    fn bytes_scanned(&self) -> u64 {
        self.document.bytes_scanned
    }

    /// `"match"`, `"no-match"` or `"not-comparable"`: did the tree hash to the §16
    /// fingerprint this release published?
    #[getter]
    fn fingerprint(&self) -> String {
        self.document.fingerprint.clone()
    }

    /// The fingerprint this release published, hex.
    #[getter]
    fn fingerprint_expected(&self) -> String {
        self.document.fingerprint_expected.clone()
    }

    /// `INTACT`, `INCOMPLETE` or `INCONCLUSIVE` — the document's own word.
    #[getter]
    fn verdict(&self) -> String {
        self.document.verdict.as_str().to_string()
    }

    /// True when some of the tree was never read, which is what separates
    /// `INCOMPLETE` from `INCONCLUSIVE`.
    #[getter]
    fn partial(&self) -> bool {
        self.document.partial
    }

    /// Every site of the release, in the order the document records them.
    #[getter]
    fn sites(&self) -> Vec<PySiteRow> {
        self.document.sites.iter().map(project_row).collect()
    }

    /// Rows the text rendering left out, counted rather than hidden.
    #[getter]
    fn omitted_rows(&self) -> usize {
        self.document.omitted_rows
    }

    #[getter]
    fn omissions(&self) -> Vec<String> {
        self.document.omissions.clone()
    }

    #[getter]
    fn notes(&self) -> Vec<String> {
        self.document.notes.clone()
    }

    /// Where `save` wrote the underlying `SWP-1-report-v2` copy, when it did.
    #[getter]
    fn report_saved(&self) -> Option<String> {
        self.report_saved.clone()
    }

    /// The §51 boundary, carried inside the document so a forwarded copy cannot
    /// lose it.
    #[getter]
    fn limitations(&self) -> Vec<String> {
        self.document.limitations.clone()
    }

    /// What the tool would suggest next, as sentences in the document.
    #[getter]
    fn next(&self) -> Vec<String> {
        self.document.next.clone()
    }

    /// The code a shell would have got, as data: `0` intact, `5` a site is not
    /// carrying its code, `10` this run could not have said either way.
    #[getter]
    fn exit_code(&self) -> i32 {
        self.document.exit_code
    }

    /// The document as its schema defines it — the same bytes `swp verify
    /// --format json` prints, because this is the same value `swp-evidence`
    /// graded.
    fn to_json(&self) -> Result<String, Failure> {
        serde_json::to_string_pretty(&self.document)
            .map(|text| text + "\n")
            .map_err(|e| {
                Failure::from(swp_sdk::SwpError::internal(format!(
                    "document is not serializable: {e}"
                )))
            })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("schema", self.schema())?;
        d.set_item("protocol", self.protocol())?;
        d.set_item("project_id", self.project_id())?;
        d.set_item("display_name", self.display_name())?;
        d.set_item("tree", self.tree())?;
        d.set_item("release_id", self.release_id())?;
        d.set_item("release_created_at", self.release_created_at())?;
        d.set_item("revision", self.revision())?;
        d.set_item("manifest_authenticated", self.manifest_authenticated())?;
        d.set_item("sites_expected", self.sites_expected())?;
        d.set_item("sites_confirmed", self.sites_confirmed())?;
        d.set_item("sites_exact", self.sites_exact())?;
        d.set_item("sites_stripped", self.sites_stripped())?;
        d.set_item("sites_absent", self.sites_absent())?;
        d.set_item("sites_moved", self.sites_moved())?;
        d.set_item("sites_refactored", self.sites_refactored())?;
        d.set_item("tag_bits", self.tag_bits())?;
        d.set_item("confirmed_bits", self.confirmed_bits())?;
        d.set_item("files_scanned", self.files_scanned())?;
        d.set_item("bytes_scanned", self.bytes_scanned())?;
        d.set_item("fingerprint", self.fingerprint())?;
        d.set_item("fingerprint_expected", self.fingerprint_expected())?;
        d.set_item("verdict", self.verdict())?;
        d.set_item("partial", self.partial())?;
        let rows = pyo3::types::PyList::empty(py);
        for row in self.sites() {
            rows.append(row.to_dict(py)?)?;
        }
        d.set_item("sites", rows)?;
        d.set_item("omitted_rows", self.omitted_rows())?;
        d.set_item("omissions", self.omissions())?;
        d.set_item("notes", self.notes())?;
        d.set_item("report_saved", self.report_saved())?;
        d.set_item("limitations", self.limitations())?;
        d.set_item("next", self.next())?;
        d.set_item("exit_code", self.exit_code())?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!(
            "VerifyOutcome(release_id='{}', verdict='{}', sites_confirmed={}/{})",
            self.document.release_id,
            self.document.verdict.as_str(),
            self.document.sites_confirmed,
            self.document.sites_expected,
        )
    }
}

#[pymethods]
impl PySiteRow {
    /// `"integer"` or `"string"`, spelled `class_` because `class` is a keyword.
    #[getter]
    fn class_(&self) -> String {
        self.class.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("site", self.site)?;
        d.set_item("file", &self.file)?;
        d.set_item("line_hint", self.line_hint)?;
        d.set_item("language", &self.language)?;
        d.set_item("adapter", &self.adapter)?;
        d.set_item("class", &self.class)?;
        d.set_item("family", &self.family)?;
        d.set_item("width", self.width)?;
        d.set_item("status", &self.status)?;
        d.set_item("confirmed", self.confirmed)?;
        d.set_item("slots", &self.slots)?;
        d.set_item("found_in", &self.found_in)?;
        d.set_item("found_line", self.found_line)?;
        d.set_item("refactored", self.refactored)?;
        d.set_item("moved", self.moved)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("SiteRow", &self.to_dict(py)?)
    }
}

fn project_row(row: &SiteRow) -> PySiteRow {
    PySiteRow {
        site: row.site,
        file: row.file.clone(),
        line_hint: row.line_hint,
        language: row.language.clone(),
        adapter: row.adapter.clone(),
        class: row.class.to_string(),
        family: row.family.to_string(),
        width: row.width,
        status: row.status.to_string(),
        confirmed: row.confirmed(),
        slots: row.slots.iter().map(|s| s.to_string()).collect(),
        found_in: row.found_in.clone(),
        found_line: row.found_line,
        refactored: row.refactored,
        moved: row.moved,
    }
}

impl PyVerifyOutcome {
    pub(crate) fn from_outcome(inner: VerifyOutcome) -> Self {
        PyVerifyOutcome {
            document: inner.document,
            report_saved: inner.report_saved,
        }
    }
}
