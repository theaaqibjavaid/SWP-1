//! SWP-1 as a library: the operations `swp` performs, with the terminal removed.
//!
//! This crate is the orchestration layer between a program and the service
//! crates. It is *thin on purpose*: every operation here is a call the CLI
//! already made, in the same order, with the same checks. [`Session`] is the
//! project-opening and release-authenticating path `swp-cli`'s `ctx.rs` enforced,
//! [`Session::protect`] builds the same [`swp_embedding::Request`] and calls the
//! same function, [`Session::scan`] indexes the owner's releases and hands the
//! candidate to `swp-detection`. Nothing here implements cryptography, key
//! derivation, watermark generation, source rewriting, detection, evidence
//! grading, report arithmetic or parsing: those live in the crates this one
//! depends on, and a second implementation of any of them would be a second place
//! for a security property to be lost.
//!
//! ```no_run
//! use swp_sdk::{Overrides, ReleaseSelection, Session};
//! use std::path::Path;
//!
//! let project = Path::new(".");
//! let session = Session::open(project, &Overrides::default())?;
//! let found = session.scan(project, &ReleaseSelection::All, false)?;
//! println!("{}", found.report.result.as_str());
//! # Ok::<(), swp_core::error::SwpError>(())
//! ```
//!
//! ## What this crate does not do
//!
//! * **It does not format.** No function here returns terminal-aligned text, a
//!   help page, or a list of "next steps". Those belong to `swp-cli`, and a
//!   binding that showed a user a CLI help string would be quoting a document
//!   about a program they are not running. Structured values go out; the caller
//!   decides how wide a column is.
//! * **It does not choose an exit code.** [`ErrorCode::exit_code`] is the CLI's
//!   contract with a shell, so a caller branches on `error.code()` instead. The
//!   one code that does cross is a [`Report`]'s, because there it is a field of a
//!   document rather than a process instruction.
//! * **It does not hold a key.** A `Session` is a path and two parsed documents.
//!   The root secret is loaded inside the operations that need it, used to derive
//!   what that operation needs, and dropped before the call returns — the same
//!   lifetime the CLI gave it, kept rather than simplified. No public type in
//!   this crate carries a root secret, a derived key or an expected watermark tag;
//!   [`session`] documents the two accessors that are `pub(crate)` because they
//!   would lead to one.
//! * **It does not lock the store.** One mutating operation per project at a time
//!   is the caller's obligation here exactly as it is in a shell, because a lock
//!   at this layer would advertise a safety property `swp` itself does not have.
//!
//! ## Errors
//!
//! Every failure is a [`swp_core::error::SwpError`]: the same type the service
//! crates raise, with the same stable [`ErrorCode`] discriminant, the same
//! `path()`, the same `next_step()`. There is no `swp_sdk::Error`, because
//! re-projecting one Rust error type into another Rust error type adds a taxonomy
//! and no information. A binding that needs an exception object builds it from
//! `code()`, `message()`, `path()`, `caused_by()`, `next_step()` and `render()`,
//! all of which are already public. A panic stays a panic in Rust; only across an
//! FFI boundary is it the `INTERNAL_ERROR` the API contract asks for.
//!
//! ## The operations, and where each one's real work is
//!
//! | this crate | does | the work is |
//! | --- | --- | --- |
//! | [`Session::open`] | resolve a project, apply overrides | `swp-identity`'s store |
//! | [`Session::init`] | draw and seal a secret, measure, write config | `swp-crypto` + `swp-identity` |
//! | [`Session::protect`] | plan or apply a constellation | `swp-embedding` |
//! | [`Session::protect_summary`] | the same run, without its private plan | `swp-embedding` |
//! | [`Session::verify`] | grade this tree against one release | `swp-detection` + `swp-evidence` |
//! | [`Session::scan`] | look for provenance in a candidate | `swp-detection` + `swp-evidence` |
//! | [`Session::reports`] | name and read saved documents | `swp-identity` + `swp-evidence` |
//!
//! `swp inspect` is not here. It prints what a store holds, including the private
//! manifest — the keyed constellation itself — so it has no reusable answer that
//! is not also a secret export.

pub mod capabilities;
pub mod init;
pub mod protect;
pub mod report;
pub mod scan;
pub mod session;
pub mod verify;

use swp_core::version::SWP_PROTOCOL_NAME;

pub use crate::capabilities::{
    capabilities, Capabilities, DefaultPolicy, LanguageInfo, SiteRange, TagRange,
};
pub use crate::init::{InitOptions, InitOutcome, InitResult, Measurement, Settings};
pub use crate::protect::{
    ProtectOptions, ProtectOutcome, ProtectSummary, ProtectedFile, ProtectedSite, RefusedSite,
};
pub use crate::report::{report_stem, StoredReport};
pub use crate::scan::{SavedReport, ScanOutcome, ScannedSite};
pub use crate::session::{Overrides, ReleaseSelection, Session};
pub use crate::verify::{VerifyOptions, VerifyOutcome};
pub use swp_core::error::{ErrorCode, SwpError};
pub use swp_core::id::{ProjectId, ReleaseId};
pub use swp_core::Limits;
pub use swp_embedding::{Mode, Protection};
pub use swp_evidence::{Report, SiteRow, Verdict, VerifyDocument};
pub use swp_identity::{ProjectIdentity, ReleaseRecord, Store, SwpConfig};

/// The version this build reports: in [`banner()`], in a report's `generator`
/// field, and in [`capabilities()`].
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What a report's `generator` field says, and what `swp --version` prints.
///
/// One function rather than two copies of a format string, because the same
/// sentence ends up inside an evidence document a stranger reads: a library build
/// and a CLI build that described themselves differently would put two generators
/// on one release.
pub fn banner() -> String {
    format!(
        "{SWP_PROTOCOL_NAME} · swp {VERSION} · report schema {}",
        swp_evidence::REPORT_SCHEMA
    )
}
