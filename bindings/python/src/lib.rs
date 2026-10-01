//! `swp` — the Python façade over `swp-sdk`.
//!
//! This crate is a *transport*, not a second implementation. Every operation here
//! is one call into `swp-sdk`, which is the same orchestration layer `swp-cli`
//! uses: the walk, the safety preconditions, the cryptography, the detection, the
//! evidence grading and the report arithmetic all stay in the Rust crates that
//! already do them. What this module adds is a Python object model, `os.PathLike`
//! handling, one exception type, and the GIL discipline — and it subtracts the
//! terminal, because a binding that printed a CLI help page would be quoting a
//! document about a program the caller is not running.
//!
//! Three properties the rest of the crate exists to keep:
//!
//! * **Only `binding_facing` crosses.** `docs/BINDING_SURFACE.json` classifies the
//!   Rust surface, and this crate wraps exactly the items that file permits. The
//!   private plan, the keyed site identities, the root secret and the store handle
//!   are not on any Python type, and are not reachable by walking a field graph
//!   from one that is.
//! * **No unwind crosses the boundary.** Every operation runs through
//!   [`error::detached`], which releases the GIL, catches a panic, and raises the
//!   documented `INTERNAL_ERROR` instead of aborting an interpreter.
//! * **Nothing is re-derived on this side.** No tag, no location id, no
//!   coincidence probability, no verdict, no exit-code mapping. Where a value is
//!   shown, it was read off the Rust document that decided it.

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use swp_sdk::ErrorCode;

mod capabilities;
mod error;
mod init;
mod options;
mod paths;
mod protect;
mod report;
mod scan;
mod session;
mod verify;

/// The build this binding drives, in the words a report's `generator` field uses.
///
/// One sentence rather than two guesses: this is the same string `swp --version`
/// prints and the same one a saved document records, so a finding made through
/// Python and a finding made through the CLI name the same rules.
#[pyfunction]
fn banner() -> String {
    swp_sdk::banner()
}

/// The §9 ladder: how many sites a project of this size should aim at.
///
/// It is a suggestion in the strongest sense available in the tool — `init`
/// measures the tree, calls this, and writes what it returns into a config the
/// operator owns. The step function is the SDK's, not a table copied here.
#[pyfunction]
fn suggest_sites(files: u32) -> u32 {
    swp_sdk::init::suggest_sites(files)
}

/// The name a report is stored under, from however it was spelled.
///
/// A stem, a file name and a store-relative path are three spellings of one entry,
/// and `Session.read_report` accepts all three; this is the normalisation, exposed
/// because the listing that shows a name is not where the path came from.
#[pyfunction]
fn report_stem(what: &str) -> String {
    swp_sdk::report_stem(what)
}

/// Every failure code this build can raise, in the order the Rust table lists them.
///
/// The codes are the stable half of the error contract; the messages are not. A
/// caller branches on `Error.code`, and this is the list to check a branch against.
/// What is deliberately *not* here is `ErrorCode::exit_code`, which is `swp`'s
/// contract with a shell and not a library caller's: the two numbers that do reach
/// Python are a [`Report`]'s and a `VerifyOutcome`'s, and there they are fields of a
/// document.
#[pyfunction]
fn error_codes() -> Vec<String> {
    ErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_string())
        .collect()
}

#[pymodule]
fn swp(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // The binding's own version, and the tool version it drives. Two numbers with
    // two lifecycles: a wheel can be rebuilt for a Python fix without the protocol
    // or the tool moving, and `docs/VERSIONING_POLICY.md` §1 keeps them apart.
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("swp_version", swp_sdk::VERSION)?;

    m.add_function(wrap_pyfunction!(banner, m)?)?;
    m.add_function(wrap_pyfunction!(suggest_sites, m)?)?;
    m.add_function(wrap_pyfunction!(report_stem, m)?)?;
    m.add_function(wrap_pyfunction!(error_codes, m)?)?;
    m.add_function(wrap_pyfunction!(capabilities::capabilities, m)?)?;

    // The one exception type. `create_exception!` gives it a Python-visible name;
    // adding the class here is what makes `except swp.Error` read the same as the
    // documentation spells it.
    m.add("Error", py.get_type::<error::Error>())?;

    m.add_class::<session::PySession>()?;
    m.add_class::<options::PyMode>()?;
    m.add_class::<options::PyOverrides>()?;
    m.add_class::<options::PyReleaseSelection>()?;
    m.add_class::<options::PyInitOptions>()?;
    m.add_class::<options::PyProtectOptions>()?;
    m.add_class::<options::PyVerifyOptions>()?;
    m.add_class::<init::PyInitOutcome>()?;
    m.add_class::<init::PyInitResult>()?;
    m.add_class::<init::PyMeasurement>()?;
    m.add_class::<init::PySettings>()?;
    m.add_class::<protect::PyProtectSummary>()?;
    m.add_class::<protect::PyProtectedFile>()?;
    m.add_class::<protect::PyProtectedSite>()?;
    m.add_class::<protect::PyRefusedSite>()?;
    m.add_class::<verify::PyVerifyOutcome>()?;
    m.add_class::<verify::PySiteRow>()?;
    m.add_class::<scan::PyScanOutcome>()?;
    m.add_class::<scan::PyScannedSite>()?;
    m.add_class::<scan::PySavedReport>()?;
    m.add_class::<report::PyReport>()?;
    m.add_class::<report::PyStoredReport>()?;
    m.add_class::<report::PyRun>()?;
    m.add_class::<report::PyCandidate>()?;
    m.add_class::<report::PyReleaseTally>()?;
    m.add_class::<report::PyEvidenceItem>()?;
    m.add_class::<report::PyRegion>()?;
    // The values a `Session` hands back. Registering them is what makes
    // `isinstance(x, swp.ReleaseRecord)` and `swp.Limits` in a type annotation
    // work; without the line below a caller can hold one of these but cannot name
    // its type, which is a surface the Rust boundary does document as facing.
    m.add_class::<session::PyProjectIdentity>()?;
    m.add_class::<session::PyPublicKeys>()?;
    m.add_class::<session::PyGeneratorInfo>()?;
    m.add_class::<session::PySwpConfig>()?;
    m.add_class::<session::PyProtectConfig>()?;
    m.add_class::<session::PyLimits>()?;
    m.add_class::<session::PyReleaseRecord>()?;
    m.add_class::<session::PyWatermarkParams>()?;
    m.add_class::<session::PyAdapterUse>()?;

    m.add_class::<capabilities::PyCapabilities>()?;
    m.add_class::<capabilities::PyLanguageInfo>()?;
    m.add_class::<capabilities::PyTagRange>()?;
    m.add_class::<capabilities::PySiteRange>()?;
    m.add_class::<capabilities::PyDefaultPolicy>()?;

    Ok(())
}
