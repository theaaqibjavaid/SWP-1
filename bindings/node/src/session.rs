//! The session, and the documents a session reads about its own project.
//!
//! `Session` is the façade's project handle: a resolved root, the public identity
//! document, the config in force, and the warnings that came with opening it. What
//! it is *not* is a key holder — the root secret is loaded inside the operations
//! that need it and dropped before they return — which is why a `Session` can be
//! handed to Node at all, and why the one accessor on the Rust type that leads to
//! the store, `open_store`, is not on this class and is not reachable from
//! anything that is. `docs/BINDING_SURFACE.json` classifies `Session::open_store`
//! and `Store` as the two `rust_only` items.
//!
//! Every call that can fail goes through [`crate::error::guarded`] (sync) or the
//! task's `compute` (async), so nothing unwinds into the host and every failure
//! arrives as the loader's `SwpError` object.
//!
//! ## Why some of these objects hold a Rust value and some hold copies
//!
//! `JsSession` holds a `swp_sdk::Session` by value and reads its fields. It
//! cannot hold a `swp_identity::PublicKeys`, because this crate does not depend
//! on `swp-identity` and cannot name that type — it can only read the fields off
//! the value the SDK hands back. That constraint is the reason the leaf objects
//! below are *projections*: they copy out `String`s and numbers and nothing
//! else, so the type a JavaScript object is made of is never a type this crate
//! had to be given.
//!
//! ## Sync and async
//!
//! `protectSummary` and `scan` are async and run on the libuv worker pool — they
//! are the two operations whose cost is a whole-tree walk. Neither can be
//! cancelled, on purpose: a cancelled protection can leave a tree half-rewritten
//! and a cancelled scan can leave a half-saved report, and the promise settling
//! eventually is the lesser burden. Everything else on the type is sync, exactly
//! as it is a directory read in the CLI.

use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{
    Limits, ProjectIdentity, ReleaseId, ReleaseRecord, ReleaseSelection, Session, SwpConfig,
    VerifyOptions,
};

use crate::error::{guarded, Failure};
use crate::init::JsInitOutcome;
use crate::options::{
    JsInitOptions, JsOverrides, JsProtectOptions, JsReleaseSelection, JsVerifyOptions,
};
use crate::protect::ProtectTask;
use crate::report::JsStoredReport;
use crate::scan::ScanTask;
use crate::verify::JsVerifyOutcome;

/// An opened SWP-1 project.
///
/// Cloning a session is copying a path and two parsed documents: it opens
/// nothing, locks nothing, and reads nothing. Two threads may hold two sessions
/// for the same project, exactly as two shells can.
#[napi(js_name = "Session")]
#[derive(Clone)]
pub struct JsSession {
    pub(crate) inner: Session,
}

#[napi]
impl JsSession {
    /// Open the project rooted at `projectRoot`.
    ///
    /// A directory with no `.swp/` rejects with `code === "NOT_PROTECTED"`, and a
    /// store this build cannot read rejects with `PROTOCOL_VERSION_UNSUPPORTED`.
    /// Both are refusals to guess rather than partial results.
    #[napi]
    pub fn open(
        env: &Env,
        project_root: String,
        overrides: Option<JsOverrides>,
    ) -> Result<JsSession> {
        let overrides = overrides.map(|o| o.into_inner()).unwrap_or_default();
        let inner = guarded(env, move || {
            Session::open(PathBuf::from(project_root).as_path(), &overrides).map_err(Failure::from)
        })?;
        Ok(JsSession { inner })
    }

    /// Walk up from `from` until a project root is found.
    #[napi]
    pub fn discover(env: &Env, from: String, overrides: Option<JsOverrides>) -> Result<JsSession> {
        let overrides = overrides.map(|o| o.into_inner()).unwrap_or_default();
        let inner = guarded(env, move || {
            Session::discover(PathBuf::from(from).as_path(), &overrides).map_err(Failure::from)
        })?;
        Ok(JsSession { inner })
    }

    /// Draw and seal a project secret, measure the tree, and write the store.
    ///
    /// This is the one operation that creates a project, and the only place a
    /// root secret exists: it is drawn here, sealed by the operating system, and
    /// never returned. What comes back is *where* it went — `secretScheme` and
    /// `secretHandle` on the result — which is the whole of the disclosure.
    /// `init` on a directory that already has a `.swp/` is idempotent rather
    /// than an error: the existing identity and secret are kept (`preExisting`
    /// and `secretState === 'kept'` say so on the result), because SWP never
    /// replaces a project secret. Importing somebody else's secret is not
    /// offered, in any language.
    #[napi]
    pub fn init(
        env: &Env,
        project_root: String,
        options: Option<JsInitOptions>,
    ) -> Result<JsInitOutcome> {
        let options = options.map(|o| o.into_inner()).unwrap_or_default();
        let outcome = guarded(env, move || {
            Session::init(PathBuf::from(project_root).as_path(), &options).map_err(Failure::from)
        })?;
        Ok(JsInitOutcome::from_outcome(outcome))
    }

    /// The directory the project is rooted at, as the caller named it.
    #[napi(getter)]
    pub fn project_root(&self) -> String {
        self.inner.project_root().to_string_lossy().into_owned()
    }

    /// `.swp/public/identity.json` — the half of the identity meant to be
    /// distributed, and the one that needs no key to read.
    #[napi(getter)]
    pub fn identity(&self) -> JsProjectIdentity {
        project_identity(self.inner.identity())
    }

    /// The `[protect]` settings in force for this session, overrides included.
    #[napi(getter)]
    pub fn config(&self) -> JsSwpConfig {
        swp_config(self.inner.config())
    }

    /// What opening the project had to say about itself: a clamped limit, a
    /// config key it ignored, a stored config that did not validate.
    #[napi(getter)]
    pub fn warnings(&self) -> Vec<String> {
        self.inner.warnings().to_vec()
    }

    /// The resource ceilings this build enforces.
    #[napi(getter)]
    pub fn limits(&self) -> JsLimits {
        limits(self.inner.limits())
    }

    /// The config as the file on disk reads, without this session's overrides.
    #[napi]
    pub fn stored_config(&self, env: &Env) -> Result<JsSwpConfig> {
        let session = &self.inner;
        let config = guarded(env, || session.stored_config().map_err(Failure::from))?;
        Ok(swp_config(&config))
    }

    /// The release ids a selection names, in the order the store keeps them.
    #[napi]
    pub fn releases(&self, env: &Env, selection: JsReleaseSelection) -> Result<Vec<String>> {
        let selection = selection.into_inner().map_err(|f| f.into_napi_error(env))?;
        let session = &self.inner;
        let ids = guarded(env, || {
            session
                .releases(&selection)
                .map(|v| {
                    v.iter()
                        .map(|r| r.as_str().to_string())
                        .collect::<Vec<String>>()
                })
                .map_err(Failure::from)
        })?;
        Ok(ids)
    }

    /// The one release a selection names, refusing a selection that names several.
    #[napi]
    pub fn one_release(&self, env: &Env, selection: JsReleaseSelection) -> Result<String> {
        let selection = selection.into_inner().map_err(|f| f.into_napi_error(env))?;
        let session = &self.inner;
        let id = guarded(env, || {
            session
                .one_release(&selection)
                .map(|r| r.as_str().to_string())
                .map_err(Failure::from)
        })?;
        Ok(id)
    }

    /// Every release record: the public history, signatures and all.
    #[napi]
    pub fn release_history(&self, env: &Env) -> Result<Vec<JsReleaseRecord>> {
        let session = &self.inner;
        let records = guarded(env, || session.release_history().map_err(Failure::from))?;
        Ok(records.into_iter().map(release_record).collect())
    }

    /// One release record by id.
    #[napi]
    pub fn release(&self, env: &Env, release_id: String) -> Result<JsReleaseRecord> {
        let session = &self.inner;
        let record = guarded(env, || {
            let id = ReleaseId::new(release_id).map_err(Failure::from)?;
            session.release(&id).map_err(Failure::from)
        })?;
        Ok(release_record(record))
    }

    /// Protect the tree and await the summary of the run.
    ///
    /// This is the only protection operation on the class. The Rust `protect`
    /// returns the plan the run wrote, and that plan's site identities are keyed
    /// under the project secret; ADR-0001 settled that a foreign binding reads the
    /// summary instead, so `protectSummary` is that decision rather than a
    /// shorter spelling of the same call. Nothing about the run is smaller here:
    /// the same three modes, the same refusal list, the same release id.
    ///
    /// The returned promise settles exactly once and cannot be cancelled: there
    /// is no `AbortSignal` here because a cancelled protection can leave a tree
    /// half-rewritten, and a promise that outlives its caller's patience is the
    /// designed outcome.
    #[napi]
    pub fn protect_summary(
        &self,
        env: &Env,
        options: JsProtectOptions,
    ) -> Result<AsyncTask<ProtectTask>> {
        let options = options.into_inner().map_err(|f| f.into_napi_error(env))?;
        Ok(AsyncTask::new(ProtectTask {
            session: self.inner.clone(),
            options,
        }))
    }

    /// Grade this project's own tree against one of its releases.
    #[napi]
    pub fn verify(&self, env: &Env, options: Option<JsVerifyOptions>) -> Result<JsVerifyOutcome> {
        let options = match options {
            Some(o) => o.into_inner().map_err(|f| f.into_napi_error(env))?,
            None => VerifyOptions::default(),
        };
        let session = self.inner.clone();
        let outcome = guarded(env, move || session.verify(&options).map_err(Failure::from))?;
        Ok(JsVerifyOutcome::from_outcome(outcome))
    }

    /// Look for this project's provenance in a candidate tree or archive.
    ///
    /// `save` writes the document under `.swp/private/reports/`: it names your
    /// source paths and the sites you protect, so it belongs with the secret and
    /// not with the release. Like `protectSummary`, the promise settles once and
    /// cannot be cancelled — a cancelled scan can leave a half-saved report.
    #[napi]
    pub fn scan(
        &self,
        env: &Env,
        candidate: String,
        releases: Option<JsReleaseSelection>,
        save: Option<bool>,
    ) -> Result<AsyncTask<ScanTask>> {
        let selection = match releases {
            Some(s) => s.into_inner().map_err(|f| f.into_napi_error(env))?,
            None => ReleaseSelection::All,
        };
        Ok(AsyncTask::new(ScanTask {
            session: self.inner.clone(),
            candidate: PathBuf::from(candidate),
            selection,
            save: save.unwrap_or(false),
        }))
    }

    /// The names of the reports this store holds, newest first.
    #[napi]
    pub fn reports(&self, env: &Env) -> Result<Vec<String>> {
        let session = &self.inner;
        guarded(env, || session.reports().map_err(Failure::from))
    }

    /// Read one saved report back as the document it says it is.
    #[napi]
    pub fn read_report(&self, env: &Env, name: String) -> Result<JsStoredReport> {
        let session = &self.inner;
        let stored = guarded(env, || session.read_report(&name).map_err(Failure::from))?;
        Ok(JsStoredReport::from_stored(stored))
    }

    /// The root and the project id, and nothing else. A session is a path and
    /// two parsed documents, and this is the whole of what it can be asked to
    /// print — the Node counterpart of the Python `__repr__`, kept off
    /// `console.log`'s own property dump so there is one obvious line to put in
    /// a log.
    #[napi(js_name = "toString")]
    pub fn to_string_(&self) -> String {
        format!(
            "Session(projectRoot='{}', projectId='{}')",
            self.project_root(),
            self.inner.identity().project_id.as_str()
        )
    }
}

impl JsSession {
    pub(crate) fn from_session(inner: Session) -> Self {
        JsSession { inner }
    }
}

/// `.swp/public/identity.json`.
#[napi(object, js_name = "ProjectIdentity")]
#[derive(Clone)]
pub struct JsProjectIdentity {
    pub protocol: String,
    pub schema: u16,
    pub project_id: String,
    /// RFC 3339, UTC.
    pub created_at: String,
    pub verification: JsPublicKeys,
    pub canonicalizer_version: u16,
    pub generator: JsGeneratorInfo,
    pub display_name: String,
}

/// The Ed25519 verify key, and the scheme that produced it.
#[napi(object, js_name = "PublicKeys")]
#[derive(Clone)]
pub struct JsPublicKeys {
    /// Base64. Public by design — releases are signed against it.
    pub verify_key_b64: String,
    pub algorithm: String,
}

/// The build that wrote a document.
#[napi(object, js_name = "GeneratorInfo")]
#[derive(Clone)]
pub struct JsGeneratorInfo {
    pub swp_version: String,
    pub generator: String,
}

/// `.swp/public/config.toml`, or the built-in defaults where it is silent.
#[napi(object, js_name = "SwpConfig")]
#[derive(Clone)]
pub struct JsSwpConfig {
    pub protocol: String,
    pub protect: JsProtectConfig,
    pub limits: JsLimits,
}

/// The `[protect]` table.
#[napi(object, js_name = "ProtectConfig")]
#[derive(Clone)]
pub struct JsProtectConfig {
    /// Paths, project-relative, that may hold protected source.
    pub targets: Vec<String>,
    pub excludes: Vec<String>,
    pub target_sites: u32,
    pub tag_bits: u8,
    pub embed_strings: bool,
}

/// The ceilings one operation will not go past. Byte-sized widths are `number`
/// (`f64`) for the reason recorded at the top of `protect.rs`.
#[napi(object, js_name = "Limits")]
#[derive(Clone)]
pub struct JsLimits {
    pub max_file_bytes: f64,
    pub max_parse_bytes: f64,
    pub max_nodes_per_tree: u32,
    pub max_depth: u32,
    pub max_parse_millis: f64,
    pub max_files: f64,
    pub max_total_bytes: f64,
    pub max_sites_per_file: u32,
    pub max_archive_entries: f64,
    pub max_archive_member_bytes: f64,
    pub max_archive_expanded_bytes: f64,
    pub max_archive_ratio: f64,
    /// `1` is "the container named on the command line and no further"; `0`
    /// refuses containers outright.
    pub max_archive_depth: u32,
    pub max_locations_per_manifest: u32,
    pub max_digest_set_entries: f64,
    pub max_shingles_per_region: u32,
    pub max_rendered_items: f64,
}

/// A signed, public record of one protected release.
#[napi(object, js_name = "ReleaseRecord")]
#[derive(Clone)]
pub struct JsReleaseRecord {
    pub protocol: String,
    pub schema: u16,
    pub project_id: String,
    pub release_id: String,
    pub created_at: String,
    /// The revision string, when the record carries one: `git`, `manual`, or
    /// `content`. `undefined` means content-only, and is the common case for a
    /// project that is not under git. Display metadata — an attacker can write
    /// anything here, and the detector reads nothing from it.
    pub revision: Option<String>,
    /// `SHA-256` over the L1 canonical tree, hex. An exact copy reproduces it;
    /// a refactoring does not.
    pub fingerprint: String,
    pub fingerprint_level: String,
    /// The digest of the *private* manifest, hex. One-way, and published by
    /// design so a restored backup can be confirmed against it.
    pub private_manifest_digest: String,
    pub watermark: JsWatermarkParams,
    pub generator: JsGeneratorInfo,
    /// The Ed25519 signature over this document, base64.
    pub signature: String,
    /// Why the record refuses itself, or `undefined` when it does not — the
    /// Python surface asks this as `validation_error()`; a plain object carries
    /// it as a field. It is still the Rust document's own `validate` answering:
    /// the binding re-derives none of its rules, and a record that does not
    /// validate is a reason to stop rather than a set of fields to print anyway.
    pub validation_error: Option<String>,
}

/// The watermark parameters a release used, so a later scan can tell *why* an
/// old release behaves differently without revealing a single location.
#[napi(object, js_name = "WatermarkParams")]
#[derive(Clone)]
pub struct JsWatermarkParams {
    pub target_sites: u32,
    pub tag_bits: u8,
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    pub canonicalizer_version: u16,
    /// A digest of the sorted, deduplicated transformation-family names that
    /// were permitted — a digest rather than the list so the record stays fixed
    /// size.
    pub form_set: String,
    pub adapters: Vec<JsAdapterUse>,
}

/// Whether a language was parsed by an AST adapter or fell back to the lexical
/// one.
#[napi(object, js_name = "AdapterUse")]
#[derive(Clone)]
pub struct JsAdapterUse {
    pub language: String,
    pub mode: String,
    pub files: u32,
}

// --------------------------------------------------------------------------------
// The projections. Each one reads fields off a value the SDK produced and copies
// out only owned, unkeyed data, which is why none of them names a type this crate
// does not depend on.
// --------------------------------------------------------------------------------

fn project_identity(id: &ProjectIdentity) -> JsProjectIdentity {
    JsProjectIdentity {
        protocol: id.protocol.clone(),
        schema: id.schema,
        project_id: id.project_id.as_str().to_string(),
        created_at: id.created_at.to_rfc3339(),
        verification: JsPublicKeys {
            verify_key_b64: id.verification.verify_key_b64.clone(),
            algorithm: id.verification.algorithm.clone(),
        },
        canonicalizer_version: id.canonicalizer_version,
        generator: JsGeneratorInfo {
            swp_version: id.generator.swp_version.clone(),
            generator: id.generator.generator.clone(),
        },
        display_name: id.display_name.clone(),
    }
}

fn swp_config(config: &SwpConfig) -> JsSwpConfig {
    JsSwpConfig {
        protocol: config.protocol.clone(),
        protect: JsProtectConfig {
            targets: config.protect.targets.clone(),
            excludes: config.protect.excludes.clone(),
            target_sites: config.protect.target_sites,
            tag_bits: config.protect.tag_bits,
            embed_strings: config.protect.embed_strings,
        },
        limits: limits(config.limits.clone()),
    }
}

fn limits(inner: Limits) -> JsLimits {
    JsLimits {
        max_file_bytes: inner.max_file_bytes as f64,
        max_parse_bytes: inner.max_parse_bytes as f64,
        max_nodes_per_tree: inner.max_nodes_per_tree,
        max_depth: inner.max_depth,
        max_parse_millis: inner.max_parse_millis as f64,
        max_files: inner.max_files as f64,
        max_total_bytes: inner.max_total_bytes as f64,
        max_sites_per_file: inner.max_sites_per_file,
        max_archive_entries: inner.max_archive_entries as f64,
        max_archive_member_bytes: inner.max_archive_member_bytes as f64,
        max_archive_expanded_bytes: inner.max_archive_expanded_bytes as f64,
        max_archive_ratio: inner.max_archive_ratio as f64,
        max_archive_depth: inner.max_archive_depth,
        max_locations_per_manifest: inner.max_locations_per_manifest,
        max_digest_set_entries: inner.max_digest_set_entries as f64,
        max_shingles_per_region: inner.max_shingles_per_region,
        max_rendered_items: inner.max_rendered_items as f64,
    }
}

fn release_record(record: ReleaseRecord) -> JsReleaseRecord {
    JsReleaseRecord {
        protocol: record.protocol.clone(),
        schema: record.schema,
        project_id: record.project_id.as_str().to_string(),
        release_id: record.release_id.as_str().to_string(),
        created_at: record.created_at.to_rfc3339(),
        revision: record.source_revision.as_str().map(str::to_string),
        fingerprint: record.fingerprint.hex(),
        fingerprint_level: record.fingerprint_level.clone(),
        private_manifest_digest: record.private_manifest_digest.hex(),
        watermark: JsWatermarkParams {
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
                .map(|a| JsAdapterUse {
                    language: a.language.clone(),
                    mode: a.mode.clone(),
                    files: a.files,
                })
                .collect(),
        },
        generator: JsGeneratorInfo {
            swp_version: record.generator.swp_version.clone(),
            generator: record.generator.generator.clone(),
        },
        signature: record.signature.clone(),
        validation_error: record.validate().err().map(|e| e.render()),
    }
}
