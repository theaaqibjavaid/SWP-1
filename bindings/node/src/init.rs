//! What initializing a project produced, and the session it left behind.
//!
//! `Session.init` is the one operation in this build where a root secret exists,
//! and it is the one place the binding must be careful about what it says *about*
//! that secret — the same discipline `bindings/python/src/init.rs` records, kept
//! here in full: this module copies out of `InitResult` the fields that are
//! already public and already printed by `swp init`, and the disclosure about the
//! key stops at three values — which scheme sealed it, the 40-bit non-secret
//! handle that lets a restored `root.key` be recognised as the same key, and what
//! the access-list check actually found. There is no path to a key byte from
//! here, and `init` never accepts one: a secret drawn by somebody else would
//! have to cross into garbage-collected memory this project cannot zeroize.
//!
//! The outcome is a class because it holds the live `Session`; everything inside
//! it that is only data is a plain object.

use std::collections::BTreeMap;

use napi_derive::napi;
use swp_sdk::{
    InitOutcome as SdkInitOutcome, InitResult as SdkInitResult, Measurement as SdkMeasurement,
    Settings as SdkSettings,
};

use crate::session::Session;

/// A project that is ready to protect, and what initializing it produced.
#[napi(js_name = "InitOutcome")]
pub struct InitOutcome {
    pub(crate) session: Session,
    pub(crate) result: InitResult,
}

/// What a store now holds, in the form an application can act on.
#[napi(object, js_name = "InitResult")]
#[derive(Clone)]
pub struct InitResult {
    pub project_id: String,
    pub display_name: String,
    /// Whether the store was already there. A pre-existing store keeps its
    /// identity and its secret: SWP never replaces a project secret.
    pub pre_existing: bool,
    /// `'created'` when this run drew the secret, `'kept'` when one was there.
    pub secret_state: String,
    /// `'dpapi'` or `'plain'` — how the key on disk is protected. On the plain
    /// path a caller that expected sealing has to be able to *see* that it did
    /// not get it, which is the whole reason this field crosses.
    pub secret_scheme: String,
    /// A 40-bit non-secret handle, so a restored `root.key` can be recognised as
    /// the same key without printing it.
    pub secret_handle: String,
    /// Whether the access list on the private half was read back and checked.
    pub permissions_verified: bool,
    /// What that check saw, in the tool's own words.
    pub permissions_detail: String,
    /// `'created'`, `'updated'`, `'already ignored'` or `'not written'`.
    pub gitignore: String,
    /// Paths this run created, store-relative and forward-slashed.
    pub created: Vec<String>,
    /// Whether this run changed the project's display label.
    pub renamed: bool,
    pub measurement: Measurement,
    pub settings: Settings,
}

/// What the tree holds, measured the way a scan would measure it.
#[napi(object, js_name = "Measurement")]
#[derive(Clone)]
pub struct Measurement {
    /// Files with a parser-covered extension.
    pub files: u32,
    pub bytes: f64,
    /// Files skipped by the walk, whatever it skipped them for.
    pub skipped: u32,
    /// Source files per language. `BTreeMap` order is the SDK's alphabetical
    /// order, and JSON preserves insertion order, so a caller that prints this
    /// prints it the same way every run.
    pub languages: BTreeMap<String, u32>,
    /// Source files per top-level directory, which is what `[protect] targets`
    /// is chosen from.
    pub tops: BTreeMap<String, u32>,
}

/// The `[protect]` section this run left behind.
#[napi(object, js_name = "Settings")]
#[derive(Clone)]
pub struct Settings {
    pub targets: Vec<String>,
    pub target_sites: u32,
    pub tag_bits: u8,
    pub embed_strings: bool,
    /// Whether this run wrote the config, or left the operator's alone.
    pub written: bool,
    /// What the measurement suggested, whether or not it was applied.
    pub suggestion: u32,
}

#[napi]
impl InitOutcome {
    /// The opened session for the project `init` just created or re-opened.
    #[napi(getter)]
    pub fn session(&self) -> Session {
        self.session.clone()
    }

    /// What the run did: the identity, the seal's metadata, the measurement, the
    /// settings it wrote or left alone.
    #[napi(getter)]
    pub fn result(&self) -> InitResult {
        self.result.clone()
    }
}

impl InitOutcome {
    pub(crate) fn from_outcome(inner: SdkInitOutcome) -> Self {
        let result = project_result(inner.result);
        InitOutcome {
            session: Session::from_session(inner.session),
            result,
        }
    }
}

fn project_result(inner: SdkInitResult) -> InitResult {
    InitResult {
        project_id: inner.project_id.as_str().to_string(),
        display_name: inner.display_name.clone(),
        pre_existing: inner.pre_existing,
        secret_state: inner.secret_state.to_string(),
        secret_scheme: inner.secret_scheme.to_string(),
        secret_handle: inner.secret_handle.clone(),
        permissions_verified: inner.permissions_verified,
        permissions_detail: inner.permissions_detail.clone(),
        gitignore: inner.gitignore.to_string(),
        created: inner.created.clone(),
        renamed: inner.renamed,
        measurement: project_measurement(inner.measurement),
        settings: project_settings(inner.settings),
    }
}

fn project_measurement(inner: SdkMeasurement) -> Measurement {
    Measurement {
        files: inner.files,
        bytes: inner.bytes as f64,
        skipped: inner.skipped,
        languages: inner.languages,
        tops: inner.tops,
    }
}

fn project_settings(inner: SdkSettings) -> Settings {
    Settings {
        targets: inner.targets.clone(),
        target_sites: inner.target_sites,
        tag_bits: inner.tag_bits,
        embed_strings: inner.embed_strings,
        written: inner.written,
        suggestion: inner.suggestion,
    }
}
