//! What a protection run decided, in the form a Node caller may hold.
//!
//! This is the boundary [docs/adr/0001-protect-generate-binding-boundary.md] drew,
//! spelled as JavaScript object fields: `Session::protect_summary` is the only
//! operation, its summary the only account, and there is no Node name for the
//! full `ProtectOutcome` whose sites carry keyed location ids. The field list is
//! `ProtectSummary`'s one for one — the same twenty values the CLI reads — plus
//! three the Python surface exposes as *methods* (`filesWithSites`, `languages`,
//! `refusalCounts`), precomputed here because a plain object has no methods.
//!
//! Nothing is re-derived: no site identity, no tag, no coincidence arithmetic,
//! and no second implementation of the decision to skip a location. The refusal's
//! *sentence* stays out, exactly as in Python, because the sentence interpolates
//! a rendered tag; `reason` is the stable token and carries nothing.
//!
//! Counts and byte sizes that Rust stores wider than 32 bits cross as `number`
//! (`f64`), because napi maps `usize`/`u64` to `bigint` and a `bigint` breaks
//! `JSON.stringify` — which the binding's own secret-leak sweep relies on. Every
//! value in that class here is a file or byte count of a project a human can
//! read, far under 2^53, and the widths are the *only* thing translated.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{
    ProtectOptions as SdkProtectOptions, ProtectSummary as SdkProtectSummary,
    ProtectedFile as SdkProtectedFile, ProtectedSite as SdkProtectedSite,
    RefusedSite as SdkRefusedSite, Session as SdkSession,
};

use crate::error::{capture, Failure};
use crate::options::mode_word;

/// What a protection run decided, as far as a caller outside Rust may see it.
#[napi(object, js_name = "ProtectSummary")]
#[derive(Clone)]
pub struct ProtectSummary {
    /// Which of the three modes ran. Only `'release'` rewrites source; `'plan'`
    /// leaves a plan document in the private store and `'dry-run'` leaves
    /// nothing at all, which is what `artifacts` reports.
    #[napi(ts_type = "'plan' | 'release' | 'dry-run'")]
    pub mode: String,
    pub project_id: String,
    /// The release this run minted or was given. For `'plan'` this is the id to
    /// pass back as `releaseId` to apply the constellation, and passing a
    /// different one derives different keys and silently makes a second release.
    pub release_id: String,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// What the operator said the source was, trimmed; `undefined` when nothing
    /// was said. Display metadata, never hashed.
    pub revision: Option<String>,
    /// §16 fingerprint of the tree as it now stands, hex.
    pub fingerprint: String,
    /// How that fingerprint was taken, so a later tree can be compared honestly.
    pub fingerprint_level: String,
    pub tag_bits: u8,
    /// Sites the caller asked for, before the ceilings trimmed it.
    pub requested_sites: u32,
    /// Sites the ceilings allowed.
    pub target_sites: u32,
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    /// Files analyzed inside the project's `[protect] targets`.
    pub files_walked: f64,
    /// Files counted into the fingerprint across the whole tree.
    pub files_in_scope: f64,
    /// Literals that could have carried a fragment.
    pub candidates: f64,
    /// Every file the constellation lands in, in write order, with the byte
    /// counts of the rewrite it produces. `'release'` leaves those bytes on
    /// disk; `'plan'` and `'dry-run'` report the same list as what they *would*
    /// change and touch no source — so `mode` and `artifacts`, not this list,
    /// say whether the tree moved.
    pub files_changed: Vec<ProtectedFile>,
    /// Every site the release carries, in plan order. Its length is
    /// `sitesEmbedded`.
    pub sites: Vec<ProtectedSite>,
    /// Every candidate the run did not use, in the order the refusals were
    /// recorded. Its length is `sitesSkipped`.
    pub refusals: Vec<RefusedSite>,
    /// Every artifact the run wrote, in write order: store-relative under
    /// `.swp/`, project-relative for protected source. Empty for `'dry-run'`.
    pub artifacts: Vec<String>,
    /// What the walk and the ceilings reported but did not act on.
    pub notes: Vec<String>,
    /// How many files hold at least one embedded site.
    pub files_with_sites: f64,
    /// The distinct languages this run wrote sites into, sorted.
    pub languages: Vec<String>,
    /// The refusal tokens this run produced with how often each fired, sorted by
    /// token, so a caller that prints this prints the same thing every run.
    pub refusal_counts: Vec<RefusalCount>,
}

/// One refusal token and its count.
#[napi(object, js_name = "RefusalCount")]
#[derive(Clone)]
pub struct RefusalCount {
    pub reason: String,
    pub count: u32,
}

/// One file a protection run changes, or would change, and how much of it moves.
#[napi(object, js_name = "ProtectedFile")]
#[derive(Clone)]
pub struct ProtectedFile {
    /// Canonical project-relative path, forward-slashed.
    pub file: String,
    /// Sites this run embedded in this file.
    pub sites: u32,
    pub bytes_before: f64,
    pub bytes_after: f64,
}

/// One site the release carries, as far as a caller outside Rust may see it.
///
/// Which four keyed addresses a site answers to decides which tags a copy must
/// carry, so a list of them is the private constellation in printable form. What
/// a caller acts on is where the mark went and how it was carried, which is every
/// field here.
#[napi(object, js_name = "ProtectedSite")]
#[derive(Clone)]
pub struct ProtectedSite {
    /// Canonical project-relative path.
    pub file: String,
    /// 1-based line in the protected text, where a reader will look. A hint: it
    /// is measured before the rewrite, so the line of a multi-line literal is
    /// approximate by design.
    pub line_hint: u32,
    pub language: String,
    /// `'ast'` or `'lexical'`: how much the tool understood here.
    pub adapter: String,
    /// `'integer'` or `'string'`. `class` is a reserved word only where the
    /// *parser* cares; an object property may carry the document's own key.
    #[napi(js_name = "class")]
    pub class_: String,
    /// The equivalent-form family that carried the mark.
    pub family: String,
    /// Bits the tag carries, which equals `ProtectSummary.tag_bits`.
    pub width: u8,
    /// The radius kind the tag derived from: `0` statement+identifiers, `1`
    /// scope+identifiers, `2` statement+names, `3` scope+names. A slot selector,
    /// not a key and not keyed material.
    pub primary: u8,
}

/// One candidate location the run refused, and why.
#[napi(object, js_name = "RefusedSite")]
#[derive(Clone)]
pub struct RefusedSite {
    pub file: String,
    pub line_hint: u32,
    /// `overlapping-radius`, `constellation-full`, `changed-after-scan`,
    /// `refused-by-validation`, and the other tokens `swp-embedding` uses.
    pub reason: String,
}

impl ProtectSummary {
    pub(crate) fn from_summary(inner: SdkProtectSummary) -> Self {
        let languages = {
            let mut seen: Vec<String> = Vec::new();
            for site in &inner.sites {
                if !seen.iter().any(|l| l == &site.language) {
                    seen.push(site.language.clone());
                }
            }
            seen.sort();
            seen
        };
        let refusal_counts = {
            let mut counts: Vec<(String, u32)> = Vec::new();
            for site in &inner.refusals {
                match counts.iter_mut().find(|(reason, _)| *reason == site.reason) {
                    Some((_, n)) => *n += 1,
                    None => counts.push((site.reason.clone(), 1)),
                }
            }
            counts.sort();
            counts
                .into_iter()
                .map(|(reason, count)| RefusalCount { reason, count })
                .collect::<Vec<RefusalCount>>()
        };
        ProtectSummary {
            mode: mode_word(inner.mode).to_string(),
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
            files_walked: inner.files_walked as f64,
            files_in_scope: inner.files_in_scope as f64,
            candidates: inner.candidates as f64,
            files_changed: inner.files_changed.iter().map(project_file).collect(),
            sites: inner.sites.iter().map(project_site).collect(),
            refusals: inner.refusals.iter().map(project_refusal).collect(),
            artifacts: inner.artifacts.clone(),
            notes: inner.notes.clone(),
            files_with_sites: inner.files_changed.iter().filter(|f| f.sites > 0).count() as f64,
            languages,
            refusal_counts,
        }
    }
}

fn project_file(inner: &SdkProtectedFile) -> ProtectedFile {
    ProtectedFile {
        file: inner.file.clone(),
        sites: inner.sites,
        bytes_before: inner.bytes_before as f64,
        bytes_after: inner.bytes_after as f64,
    }
}

fn project_site(inner: &SdkProtectedSite) -> ProtectedSite {
    ProtectedSite {
        file: inner.file.clone(),
        line_hint: inner.line_hint,
        language: inner.language.clone(),
        adapter: inner.adapter.clone(),
        class_: inner.class.clone(),
        family: inner.family.clone(),
        width: inner.width,
        primary: inner.primary,
    }
}

fn project_refusal(inner: &SdkRefusedSite) -> RefusedSite {
    RefusedSite {
        file: inner.file.clone(),
        line_hint: inner.line_hint,
        reason: inner.reason.clone(),
    }
}

/// The async half of `protectSummary`: the whole run happens on a libuv worker
/// thread and *always* finishes.
///
/// There is deliberately no cancellation path here (no `AbortSignal`, no
/// `cancel`): a cancelled protection can leave a tree half-rewritten, which is
/// the one outcome a caller must never be able to choose. The promise settles
/// exactly once — napi resolves or rejects after `compute` returns, and the
/// envelope is built on the JS thread, so the worker never touches a JavaScript
/// value.
pub struct ProtectTask {
    pub(crate) session: SdkSession,
    pub(crate) options: SdkProtectOptions,
}

#[napi]
impl Task for ProtectTask {
    type Output = std::result::Result<ProtectSummary, Failure>;
    type JsValue = ProtectSummary;

    fn compute(&mut self) -> Result<Self::Output> {
        let session = self.session.clone();
        let options = self.options.clone();
        Ok(capture(move || {
            session
                .protect_summary(&options)
                .map(ProtectSummary::from_summary)
                .map_err(Failure::from)
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> Result<Self::JsValue> {
        output.map_err(|failure| failure.into_napi_error(&env))
    }
}
