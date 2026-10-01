//! The session, and the documents a session reads about its own project.
//!
//! `Session` is the façade's project handle: a resolved root, the public identity
//! document, the config in force, and the warnings that came with opening it. What
//! it is *not* is a key holder — the root secret is loaded inside the operations
//! that need it and dropped before they return — which is why a `Session` can be
//! handed to Python at all, and why the one accessor on it that leads to the store,
//! `open_store`, is not on this type and is not reachable from anything that is.
//! docs/BINDING_SURFACE.json classifies `Session::open_store` and `Store` as the
//! two `rust_only` items, and `swp-cli` is the only reason either is public.
//!
//! Every call goes through [`crate::error::detached`], so every one of them runs
//! with the GIL released and a panic turned into `Error`.
//!
//! ## Why some of these objects hold a Rust value and some hold copies
//!
//! A `#[pyclass]` here holds a `swp_sdk::Session` by value and reads its fields.
//! It cannot hold a `swp_identity::PublicKeys`, because this crate does not depend
//! on `swp-identity` and cannot name that type — it can only read the fields off
//! the value the SDK hands back. That constraint is the reason the leaf objects
//! below are *projections*: they copy out `String`s and integers and nothing else,
//! so the type a Python object is made of is never a type this crate had to be
//! given.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use swp_sdk::{
    Limits, Overrides, ProjectIdentity, ReleaseId, ReleaseRecord, ReleaseSelection, Session,
    SwpConfig, VerifyOptions,
};

use crate::error::{detached, repr_of, Failure};
use crate::init::PyInitOutcome;
use crate::options::{
    PyInitOptions, PyOverrides, PyProtectOptions, PyReleaseSelection, PyVerifyOptions,
};
use crate::paths::OsPath;
use crate::protect::PyProtectSummary;
use crate::report::PyStoredReport;
use crate::scan::PyScanOutcome;
use crate::verify::PyVerifyOutcome;

/// An opened SWP-1 project.
///
/// Cloning a session is copying a path and two parsed documents: it opens nothing,
/// locks nothing, and reads nothing. Two threads may hold two sessions for the same
/// project, exactly as two shells can.
#[pyclass(module = "swp", name = "Session", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySession {
    pub(crate) inner: Session,
}

#[pymethods]
impl PySession {
    /// Open the project rooted at `project_root`.
    ///
    /// A directory with no `.swp/` raises `Error` with `code == "NOT_PROTECTED"`,
    /// and a store this build cannot read raises `PROTOCOL_VERSION_UNSUPPORTED`.
    /// Both are refusals to guess rather than partial results.
    #[staticmethod]
    #[pyo3(signature = (project_root, overrides = None))]
    fn open(
        py: Python<'_>,
        project_root: OsPath,
        overrides: Option<&PyOverrides>,
    ) -> PyResult<Self> {
        let none = Overrides::default();
        let overrides = overrides.map(|o| &o.inner).unwrap_or(&none);
        let session = detached(py, || {
            Session::open(project_root.as_path(), overrides).map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(PySession { inner: session })
    }

    /// Walk up from `from` until a project root is found.
    #[staticmethod]
    #[pyo3(signature = (from, overrides = None))]
    fn discover(py: Python<'_>, from: OsPath, overrides: Option<&PyOverrides>) -> PyResult<Self> {
        let none = Overrides::default();
        let overrides = overrides.map(|o| &o.inner).unwrap_or(&none);
        let session = detached(py, || {
            Session::discover(from.as_path(), overrides).map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(PySession { inner: session })
    }

    /// Draw and seal a project secret, measure the tree, and write the store.
    ///
    /// This is the one operation that creates a project, and the only place a root
    /// secret exists: it is drawn here, sealed by the operating system, and never
    /// returned. What comes back is *where* it went — `secret_scheme` and
    /// `secret_handle` on the result — which is the whole of the disclosure.
    /// `init` on a directory that already has a `.swp/` is idempotent rather than
    /// an error: the existing identity and secret are kept (`pre_existing` and
    /// `secret_state == "kept"` say so on the result), because SWP never replaces a
    /// project secret. Importing somebody else's secret is not offered, in any
    /// language.
    #[staticmethod]
    #[pyo3(signature = (project_root, *, options = None))]
    fn init(
        py: Python<'_>,
        project_root: OsPath,
        options: Option<&PyInitOptions>,
    ) -> PyResult<PyInitOutcome> {
        let none = swp_sdk::InitOptions::default();
        let options = options.map(|o| &o.inner).unwrap_or(&none);
        let outcome = detached(py, || {
            Session::init(project_root.as_path(), options).map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(PyInitOutcome::from_outcome(outcome))
    }

    /// The directory the project is rooted at, as the caller named it.
    #[getter]
    fn project_root(&self) -> String {
        self.inner.project_root().to_string_lossy().into_owned()
    }

    /// `.swp/public/identity.json` — the half of the identity meant to be
    /// distributed, and the one that needs no key to read.
    #[getter]
    fn identity(&self) -> PyProjectIdentity {
        project_identity(self.inner.identity())
    }

    /// The `[protect]` settings in force for this session, overrides included.
    #[getter]
    fn config(&self) -> PySwpConfig {
        swp_config(self.inner.config())
    }

    /// The config as the file on disk reads, without this session's overrides.
    fn stored_config(&self, py: Python<'_>) -> PyResult<PySwpConfig> {
        let session = &self.inner;
        let config = detached(py, || session.stored_config().map_err(Failure::from))
            .map_err(|f| f.into_pyerr(py))?;
        Ok(swp_config(&config))
    }

    /// What opening the project had to say about itself: a clamped limit, a config
    /// key it ignored, a stored config that did not validate.
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings().to_vec()
    }

    /// The resource ceilings this build enforces.
    #[getter]
    fn limits(&self) -> PyLimits {
        limits(self.inner.limits())
    }

    /// The release ids a selection names, in the order the store keeps them.
    fn releases(&self, py: Python<'_>, selection: &PyReleaseSelection) -> PyResult<Vec<String>> {
        let session = &self.inner;
        let selection = &selection.inner;
        detached(py, || {
            session
                .releases(selection)
                .map(|v| v.iter().map(|r| r.as_str().to_string()).collect::<Vec<_>>())
                .map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))
    }

    /// The one release a selection names, refusing a selection that names several.
    fn one_release(&self, py: Python<'_>, selection: &PyReleaseSelection) -> PyResult<String> {
        let session = &self.inner;
        let selection = &selection.inner;
        detached(py, || {
            session
                .one_release(selection)
                .map(|r| r.as_str().to_string())
                .map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))
    }

    /// Every release record: the public history, signatures and all.
    fn release_history(&self, py: Python<'_>) -> PyResult<Vec<PyReleaseRecord>> {
        let session = &self.inner;
        let records = detached(py, || session.release_history().map_err(Failure::from))
            .map_err(|f| f.into_pyerr(py))?;
        Ok(records.into_iter().map(release_record).collect())
    }

    /// One release record by id.
    fn release(&self, py: Python<'_>, release_id: &str) -> PyResult<PyReleaseRecord> {
        let session = &self.inner;
        let raw = release_id.to_string();
        let record = detached(py, || {
            let id = ReleaseId::new(raw).map_err(Failure::from)?;
            session.release(&id).map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(release_record(record))
    }

    /// Protect the tree and return the summary of the run.
    ///
    /// This is the only protection operation on the type. The Rust `protect`
    /// returns the plan the run wrote, and that plan's site identities are keyed
    /// under the project secret; [ADR-0001](https://github.com/theaaqibjavaid/SWP-1)
    /// settled that a foreign binding reads the summary instead, so
    /// `protect_summary` is that decision rather than a shorter spelling of the
    /// same call. Nothing about the run is smaller here: the same three modes, the
    /// same refusal list, the same release id.
    fn protect_summary(
        &self,
        py: Python<'_>,
        options: &PyProtectOptions,
    ) -> PyResult<PyProtectSummary> {
        let session = &self.inner;
        let options = &options.inner;
        let summary = detached(py, || {
            session.protect_summary(options).map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(PyProtectSummary::from_summary(summary))
    }

    /// Grade this project's own tree against one of its releases.
    #[pyo3(signature = (*, options = None))]
    fn verify(
        &self,
        py: Python<'_>,
        options: Option<&PyVerifyOptions>,
    ) -> PyResult<Py<PyVerifyOutcome>> {
        let session = self.inner.clone();
        let none = VerifyOptions::default();
        let options = options.map(|o| &o.inner).unwrap_or(&none);
        let outcome = detached(py, || session.verify(options).map_err(Failure::from))
            .map_err(|f| f.into_pyerr(py))?;
        Py::new(py, PyVerifyOutcome::from_outcome(outcome))
    }

    /// Look for this project's provenance in a candidate tree or archive.
    ///
    /// `save` writes the document under `.swp/private/reports/`: it names your
    /// source paths and the sites you protect, so it belongs with the secret and
    /// not with the release.
    #[pyo3(signature = (candidate, *, releases = None, save = false))]
    fn scan(
        &self,
        py: Python<'_>,
        candidate: OsPath,
        releases: Option<&PyReleaseSelection>,
        save: bool,
    ) -> PyResult<PyScanOutcome> {
        let session = &self.inner;
        let all = ReleaseSelection::All;
        let selection = releases.map(|r| &r.inner).unwrap_or(&all);
        let outcome = detached(py, || {
            session
                .scan(candidate.as_path(), selection, save)
                .map_err(Failure::from)
        })
        .map_err(|f| f.into_pyerr(py))?;
        Ok(PyScanOutcome::from_outcome(outcome))
    }

    /// The names of the reports this store holds, newest first.
    fn reports(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        let session = &self.inner;
        detached(py, || session.reports().map_err(Failure::from)).map_err(|f| f.into_pyerr(py))
    }

    /// Read one saved report back as the document it says it is.
    fn read_report(&self, py: Python<'_>, name: &str) -> PyResult<PyStoredReport> {
        let session = &self.inner;
        let name = name.to_string();
        let stored = detached(py, || session.read_report(&name).map_err(Failure::from))
            .map_err(|f| f.into_pyerr(py))?;
        Ok(PyStoredReport::from_stored(stored))
    }

    /// The root and the project id, and nothing else. A session is a path and two
    /// parsed documents, and this is the whole of what it can be asked to print.
    fn __repr__(&self) -> String {
        format!(
            "Session(project_root='{}', project_id='{}')",
            self.project_root(),
            self.inner.identity().project_id.as_str()
        )
    }
}

/// `.swp/public/identity.json`.

#[pyclass(module = "swp", name = "ProjectIdentity", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProjectIdentity {
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    schema: u16,
    #[pyo3(get)]
    project_id: String,
    /// RFC 3339, UTC.
    #[pyo3(get)]
    created_at: String,
    #[pyo3(get)]
    verification: PyPublicKeys,
    #[pyo3(get)]
    canonicalizer_version: u16,
    #[pyo3(get)]
    generator: PyGeneratorInfo,
    #[pyo3(get)]
    display_name: String,
}

/// The Ed25519 verify key, and the scheme that produced it.

#[pyclass(module = "swp", name = "PublicKeys", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyPublicKeys {
    /// Base64. Public by design — releases are signed against it.
    #[pyo3(get)]
    verify_key_b64: String,
    #[pyo3(get)]
    algorithm: String,
}

/// The build that wrote a document.

#[pyclass(module = "swp", name = "GeneratorInfo", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyGeneratorInfo {
    #[pyo3(get)]
    swp_version: String,
    #[pyo3(get)]
    generator: String,
}

/// `.swp/public/config.toml`, or the built-in defaults where it is silent.

#[pyclass(module = "swp", name = "SwpConfig", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySwpConfig {
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    protect: PyProtectConfig,
    #[pyo3(get)]
    limits: PyLimits,
}

/// The `[protect]` table.

#[pyclass(module = "swp", name = "ProtectConfig", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProtectConfig {
    /// Paths, project-relative, that may hold protected source.
    #[pyo3(get)]
    targets: Vec<String>,
    #[pyo3(get)]
    excludes: Vec<String>,
    #[pyo3(get)]
    target_sites: u32,
    #[pyo3(get)]
    tag_bits: u8,
    #[pyo3(get)]
    embed_strings: bool,
}

/// The ceilings one operation will not go past.

#[pyclass(module = "swp", name = "Limits", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyLimits {
    #[pyo3(get)]
    max_file_bytes: u64,
    #[pyo3(get)]
    max_parse_bytes: u64,
    #[pyo3(get)]
    max_nodes_per_tree: u32,
    #[pyo3(get)]
    max_depth: u32,
    #[pyo3(get)]
    max_parse_millis: u64,
    #[pyo3(get)]
    max_files: u64,
    #[pyo3(get)]
    max_total_bytes: u64,
    #[pyo3(get)]
    max_sites_per_file: u32,
    #[pyo3(get)]
    max_archive_entries: u64,
    #[pyo3(get)]
    max_archive_member_bytes: u64,
    #[pyo3(get)]
    max_archive_expanded_bytes: u64,
    #[pyo3(get)]
    max_archive_ratio: u64,
    /// `1` is "the container named on the command line and no further"; `0`
    /// refuses containers outright.
    #[pyo3(get)]
    max_archive_depth: u32,
    #[pyo3(get)]
    max_locations_per_manifest: u32,
    #[pyo3(get)]
    max_digest_set_entries: u64,
    #[pyo3(get)]
    max_shingles_per_region: u32,
    #[pyo3(get)]
    max_rendered_items: usize,
}

/// A signed, public record of one protected release.

#[pyclass(module = "swp", name = "ReleaseRecord", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyReleaseRecord {
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    schema: u16,
    #[pyo3(get)]
    project_id: String,
    #[pyo3(get)]
    release_id: String,
    #[pyo3(get)]
    created_at: String,
    /// The revision string, when the record carries one: `git`, `manual`, or
    /// `content`. `None` means content-only, and is the common case for a project
    /// that is not under git. Display metadata — an attacker can write anything
    /// here, and the detector reads nothing from it.
    #[pyo3(get)]
    revision: Option<String>,
    /// `SHA-256` over the L1 canonical tree, hex. An exact copy reproduces it; a
    /// refactoring does not.
    #[pyo3(get)]
    fingerprint: String,
    #[pyo3(get)]
    fingerprint_level: String,
    /// The digest of the *private* manifest, hex. One-way, and published by design
    /// so a restored backup can be confirmed against it.
    #[pyo3(get)]
    private_manifest_digest: String,
    #[pyo3(get)]
    watermark: PyWatermarkParams,
    #[pyo3(get)]
    generator: PyGeneratorInfo,
    /// The Ed25519 signature over this document, base64.
    #[pyo3(get)]
    signature: String,
    /// Why the record refuses itself, computed by the Rust document's own
    /// `validate`. Not a `#[pyo3(get)]` field, because a field named `error` on a
    /// DTO reads like the record is already a failure; `validation_error()` is the
    /// question, and `None` is the answer that means proceed.
    error: Option<String>,
}

/// The watermark parameters a release used, so a later scan can tell *why* an old
/// release behaves differently without revealing a single location.

#[pyclass(module = "swp", name = "WatermarkParams", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyWatermarkParams {
    #[pyo3(get)]
    target_sites: u32,
    #[pyo3(get)]
    tag_bits: u8,
    #[pyo3(get)]
    sites_embedded: u32,
    #[pyo3(get)]
    sites_skipped: u32,
    #[pyo3(get)]
    canonicalizer_version: u16,
    /// A digest of the sorted, deduplicated transformation-family names that were
    /// permitted — a digest rather than the list so the record stays fixed size.
    #[pyo3(get)]
    form_set: String,
    #[pyo3(get)]
    adapters: Vec<PyAdapterUse>,
}

/// Whether a language was parsed by an AST adapter or fell back to the lexical one.

#[pyclass(module = "swp", name = "AdapterUse", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyAdapterUse {
    #[pyo3(get)]
    language: String,
    #[pyo3(get)]
    mode: String,
    #[pyo3(get)]
    files: u32,
}

#[pymethods]
impl PyProjectIdentity {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("protocol", &self.protocol)?;
        d.set_item("schema", self.schema)?;
        d.set_item("project_id", &self.project_id)?;
        d.set_item("created_at", &self.created_at)?;
        d.set_item("verification", self.verification.to_dict(py)?)?;
        d.set_item("canonicalizer_version", self.canonicalizer_version)?;
        d.set_item("generator", self.generator.to_dict(py)?)?;
        d.set_item("display_name", &self.display_name)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ProjectIdentity", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyPublicKeys {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("verify_key_b64", &self.verify_key_b64)?;
        d.set_item("algorithm", &self.algorithm)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("PublicKeys", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyGeneratorInfo {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("swp_version", &self.swp_version)?;
        d.set_item("generator", &self.generator)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("GeneratorInfo", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PySwpConfig {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("protocol", &self.protocol)?;
        d.set_item("protect", self.protect.to_dict(py)?)?;
        d.set_item("limits", self.limits.to_dict(py)?)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("SwpConfig", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyProtectConfig {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("targets", &self.targets)?;
        d.set_item("excludes", &self.excludes)?;
        d.set_item("target_sites", self.target_sites)?;
        d.set_item("tag_bits", self.tag_bits)?;
        d.set_item("embed_strings", self.embed_strings)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ProtectConfig", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyLimits {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (name, value) in [
            ("max_file_bytes", self.max_file_bytes),
            ("max_parse_bytes", self.max_parse_bytes),
            ("max_nodes_per_tree", self.max_nodes_per_tree as u64),
            ("max_depth", self.max_depth as u64),
            ("max_parse_millis", self.max_parse_millis),
            ("max_files", self.max_files),
            ("max_total_bytes", self.max_total_bytes),
            ("max_sites_per_file", self.max_sites_per_file as u64),
            ("max_archive_entries", self.max_archive_entries),
            ("max_archive_member_bytes", self.max_archive_member_bytes),
            (
                "max_archive_expanded_bytes",
                self.max_archive_expanded_bytes,
            ),
            ("max_archive_ratio", self.max_archive_ratio),
            ("max_archive_depth", self.max_archive_depth as u64),
            (
                "max_locations_per_manifest",
                self.max_locations_per_manifest as u64,
            ),
            ("max_digest_set_entries", self.max_digest_set_entries),
            (
                "max_shingles_per_region",
                self.max_shingles_per_region as u64,
            ),
            ("max_rendered_items", self.max_rendered_items as u64),
        ] {
            d.set_item(name, value)?;
        }
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("Limits", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyReleaseRecord {
    /// Why the record refuses itself, or `None` when it does not.
    ///
    /// This asks the Rust document's own `validate`; the binding re-derives none
    /// of its rules, and a record that does not validate is a reason to stop
    /// rather than a set of fields to print anyway.
    fn validation_error(&self) -> Option<String> {
        self.error.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("protocol", &self.protocol)?;
        d.set_item("schema", self.schema)?;
        d.set_item("project_id", &self.project_id)?;
        d.set_item("release_id", &self.release_id)?;
        d.set_item("created_at", &self.created_at)?;
        d.set_item("revision", &self.revision)?;
        d.set_item("fingerprint", &self.fingerprint)?;
        d.set_item("fingerprint_level", &self.fingerprint_level)?;
        d.set_item("private_manifest_digest", &self.private_manifest_digest)?;
        d.set_item("watermark", self.watermark.to_dict(py)?)?;
        d.set_item("generator", self.generator.to_dict(py)?)?;
        d.set_item("signature", &self.signature)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("ReleaseRecord", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyWatermarkParams {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("target_sites", self.target_sites)?;
        d.set_item("tag_bits", self.tag_bits)?;
        d.set_item("sites_embedded", self.sites_embedded)?;
        d.set_item("sites_skipped", self.sites_skipped)?;
        d.set_item("canonicalizer_version", self.canonicalizer_version)?;
        d.set_item("form_set", &self.form_set)?;
        let rows = PyList::empty(py);
        for row in &self.adapters {
            rows.append(row.to_dict(py)?)?;
        }
        d.set_item("adapters", rows)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("WatermarkParams", &self.to_dict(py)?)
    }
}

#[pymethods]
impl PyAdapterUse {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("language", &self.language)?;
        d.set_item("mode", &self.mode)?;
        d.set_item("files", self.files)?;
        Ok(d)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr_of("AdapterUse", &self.to_dict(py)?)
    }
}

// --------------------------------------------------------------------------------
// The projections. Each one reads fields off a value the SDK produced and copies
// out only owned, unkeyed data, which is why none of them names a type this crate
// does not depend on.
// --------------------------------------------------------------------------------

fn project_identity(id: &ProjectIdentity) -> PyProjectIdentity {
    PyProjectIdentity {
        protocol: id.protocol.clone(),
        schema: id.schema,
        project_id: id.project_id.as_str().to_string(),
        created_at: id.created_at.to_rfc3339(),
        verification: PyPublicKeys {
            verify_key_b64: id.verification.verify_key_b64.clone(),
            algorithm: id.verification.algorithm.clone(),
        },
        canonicalizer_version: id.canonicalizer_version,
        generator: PyGeneratorInfo {
            swp_version: id.generator.swp_version.clone(),
            generator: id.generator.generator.clone(),
        },
        display_name: id.display_name.clone(),
    }
}

fn swp_config(config: &SwpConfig) -> PySwpConfig {
    PySwpConfig {
        protocol: config.protocol.clone(),
        protect: PyProtectConfig {
            targets: config.protect.targets.clone(),
            excludes: config.protect.excludes.clone(),
            target_sites: config.protect.target_sites,
            tag_bits: config.protect.tag_bits,
            embed_strings: config.protect.embed_strings,
        },
        limits: limits(config.limits.clone()),
    }
}

fn limits(inner: Limits) -> PyLimits {
    PyLimits {
        max_file_bytes: inner.max_file_bytes,
        max_parse_bytes: inner.max_parse_bytes,
        max_nodes_per_tree: inner.max_nodes_per_tree,
        max_depth: inner.max_depth,
        max_parse_millis: inner.max_parse_millis,
        max_files: inner.max_files,
        max_total_bytes: inner.max_total_bytes,
        max_sites_per_file: inner.max_sites_per_file,
        max_archive_entries: inner.max_archive_entries,
        max_archive_member_bytes: inner.max_archive_member_bytes,
        max_archive_expanded_bytes: inner.max_archive_expanded_bytes,
        max_archive_ratio: inner.max_archive_ratio,
        max_archive_depth: inner.max_archive_depth,
        max_locations_per_manifest: inner.max_locations_per_manifest,
        max_digest_set_entries: inner.max_digest_set_entries,
        max_shingles_per_region: inner.max_shingles_per_region,
        max_rendered_items: inner.max_rendered_items,
    }
}

fn release_record(record: ReleaseRecord) -> PyReleaseRecord {
    PyReleaseRecord {
        protocol: record.protocol.clone(),
        schema: record.schema,
        project_id: record.project_id.as_str().to_string(),
        release_id: record.release_id.as_str().to_string(),
        created_at: record.created_at.to_rfc3339(),
        revision: record.source_revision.as_str().map(str::to_string),
        fingerprint: record.fingerprint.hex(),
        fingerprint_level: record.fingerprint_level.clone(),
        private_manifest_digest: record.private_manifest_digest.hex(),
        watermark: PyWatermarkParams {
            target_sites: record.watermark.target_sites,
            tag_bits: record.watermark.tag_bits,
            sites_embedded: record.watermark.sites_embedded,
            sites_skipped: record.watermark.sites_skipped,
            canonicalizer_version: record.watermark.canonicalizer_version,
            form_set: record.watermark.form_set.clone(),
            adapters: record
                .watermark
                .adapters
                .iter()
                .map(|a| PyAdapterUse {
                    language: a.language.clone(),
                    mode: a.mode.clone(),
                    files: a.files,
                })
                .collect(),
        },
        generator: PyGeneratorInfo {
            swp_version: record.generator.swp_version.clone(),
            generator: record.generator.generator.clone(),
        },
        signature: record.signature.clone(),
        error: record.validate().err().map(|e| e.render()),
    }
}
