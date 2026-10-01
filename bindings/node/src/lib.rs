//! `swp` — the Node façade over `swp-sdk`.
//!
//! This crate is a *transport*, not a second implementation. Every operation
//! here is one call into `swp-sdk`, which is the same orchestration layer
//! `swp-cli` uses: the walk, the safety preconditions, the cryptography, the
//! detection, the evidence grading and the report arithmetic all stay in the
//! Rust crates that already do them. What this module adds is a JavaScript
//! object model, one error type built by the loader's `SwpError` class, and the
//! JS-thread/worker-thread discipline — and it subtracts the terminal, because
//! a binding that printed a CLI help page would be quoting a document about a
//! program the caller is not running.
//!
//! Three properties the rest of the crate exists to keep:
//!
//! * **Only `binding_facing` crosses.** `docs/BINDING_SURFACE.json` classifies
//!   the Rust surface, and this crate wraps exactly the items that file
//!   permits. The private plan, the keyed site identities, the root secret and
//!   the store handle are not on any JavaScript object, and are not reachable
//!   by walking a field graph from one that is.
//! * **No unwind crosses the boundary.** Every operation runs through
//!   [`error::capture`] or [`error::guarded`], which catch a panic and raise
//!   the documented `INTERNAL_ERROR` instead of killing the host process.
//! * **Nothing is re-derived on this side.** No tag, no location id, no
//!   coincidence probability, no verdict, no exit-code mapping. Where a value
//!   is shown, it was read off the Rust document that decided it.

mod capabilities;
mod error;
mod init;
mod options;
mod protect;
mod report;
mod scan;
mod session;
mod verify;

use napi_derive::napi;
use swp_sdk::ErrorCode;

/// The build this binding drives, in the words a report's `generator` field
/// uses.
///
/// One sentence rather than two guesses: this is the same string `swp
/// --version` prints and the same one a saved document records, so a finding
/// made through Node and a finding made through the CLI name the same rules.
#[napi]
pub fn banner() -> String {
    swp_sdk::banner()
}

/// The §9 ladder: how many sites a project of this size should aim at.
///
/// It is a suggestion in the strongest sense available in the tool — `init`
/// measures the tree, calls this, and writes what it returns into a config the
/// operator owns. The step function is the SDK's, not a table copied here.
#[napi]
pub fn suggest_sites(files: u32) -> u32 {
    swp_sdk::init::suggest_sites(files)
}

/// The name a report is stored under, from however it was spelled.
///
/// A stem, a file name and a store-relative path are three spellings of one
/// entry, and `Session.readReport` accepts all three; this is the normalisation,
/// exposed because the listing that shows a name is not where the path came
/// from.
#[napi]
pub fn report_stem(what: String) -> String {
    swp_sdk::report_stem(&what)
}

/// Every failure code this build can raise, in the order the Rust table lists
/// them.
///
/// The codes are the stable half of the error contract; the messages are not. A
/// caller branches on `error.code`, and this is the list to check a branch
/// against. What is deliberately *not* here is `ErrorCode::exit_code`, which is
/// `swp`'s contract with a shell and not a library caller's: the two numbers
/// that do reach Node are a [`Report`](report::JsReport)'s and a
/// [`VerifyOutcome`](verify::JsVerifyOutcome)'s, and there they are fields of a
/// document.
#[napi]
pub fn error_codes() -> Vec<String> {
    ErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_string())
        .collect()
}

/// The machine-readable answer to "what can this build do".
///
/// It touches nothing: no filesystem, no project, no secret. It cannot fail.
#[napi]
pub fn capabilities() -> capabilities::JsCapabilities {
    capabilities::project(&swp_sdk::capabilities())
}

/// The version of the tool this binding drives, as `swp --version` prints it.
#[napi]
pub const SWP_VERSION: &str = swp_sdk::VERSION;

/// The binding's own version. Two numbers with two lifecycles: an addon can be
/// rebuilt for a Node fix without the protocol or the tool moving, and
/// `docs/VERSIONING_POLICY.md` §1 keeps them apart.
#[napi]
pub const BINDING_VERSION: &str = env!("CARGO_PKG_VERSION");
