//! Deciding a constellation, and — in one of the three modes — applying it.
//!
//! [`Session::protect`] is `swp generate` and `swp protect` as they already are in
//! the CLI: one pipeline with one flag different. `mode: Plan` is what `Release`
//! would have chosen, run against the tree as it stands, so an operator can read
//! the plan before the diff exists.
//!
//! All of the actual work is `swp-embedding`'s: the walk, the candidate search,
//! the safety preconditions that refuse a location rather than force it, the
//! rewrite, and the order the three artifacts get written in. What this module
//! owns is the two decisions a caller has to make before any of that can run —
//! which release id this is, and what the source is claimed to be — and the
//! secret's lifetime, which ends when the call does.
//!
//! It owns one more thing: the boundary between what a run knows and what a
//! caller may hold. [`Session::protect`] returns [`ProtectOutcome`], whose
//! [`Protection`] carries the private plan document, including each planned
//! site's four keyed location ids. [`Session::protect_summary`] runs that same
//! call and returns [`ProtectSummary`], which holds the run's account with the
//! keyed half left out — not redacted from it, but never read into it. See
//! `docs/adr/0001-protect-generate-binding-boundary.md` for why the line is
//! drawn there and what crossing it costs.

use serde::Serialize;
use swp_core::error::SwpError;
use swp_core::id::{Digest, ProjectId, ReleaseId};
use swp_embedding::{Mode, Protection, Request};
use swp_identity::{new_release_id, SourceRevision, Timestamp};

use crate::session::Session;

/// What a protection run takes.
///
/// There is deliberately no `Default`: an options struct that a caller could
/// spell `ProtectOptions::default()` would be a struct whose default mode
/// rewrites the source tree, and that is not a thing to reach by accident.
/// Construct with [`ProtectOptions::new`], which makes the mode an argument.
///
/// The settings a run protects *with* are the session's: `[protect]` from
/// `.swp/config.toml`, patched by the [`Overrides`](crate::Overrides) the session
/// was opened with. Nothing here re-decides a target, a site count or a tag
/// width, so a caller who wants those changed changes them where the CLI's
/// `--target`, `--sites` and `--bits` do.
#[derive(Debug, Clone)]
pub struct ProtectOptions {
    /// A run that plans, applies or does neither.
    pub mode: Mode,
    /// The release to write. `None` allocates one, which is the ordinary case.
    ///
    /// This is the easiest option to get wrong, and getting it wrong is
    /// silent — so the rule is worth stating: a plan is keyed by its release id,
    /// which means applying a generated constellation requires **the same id**.
    /// `generate` returns one in [`ProtectOutcome::protection`]; `protect` passes
    /// it back. A caller that allocates a fresh id for the second run derives
    /// different keys, embeds different tags and produces a second release the
    /// plan does not describe — while still succeeding.
    pub release_id: Option<ReleaseId>,
    /// What the operator says this source is: a git ref, a version, a build
    /// number. Display metadata, recorded in the release and never hashed, so it
    /// cannot change the fingerprint.
    ///
    /// `None` records the content fingerprint as the revision; `Some(text)`
    /// records `text` trimmed. There is no stated-but-empty third state: a label
    /// that trims to nothing, runs over 200 bytes, or carries a control character
    /// is refused with `INVALID_MANIFEST` by the same validation the record applies
    /// to itself (`SourceRevision::validate`, `swp-identity/src/release.rs:70`),
    /// and the run that refuses it writes nothing at all — the label is checked
    /// with the identity and the config, before the store is consulted
    /// (`swp-embedding/src/protect.rs:200`). The refusal is mode-independent, so
    /// `Mode::Plan` and `Mode::DryRun` reject it too rather than silently dropping
    /// what the caller stated.
    pub revision: Option<String>,
}

impl ProtectOptions {
    /// Options for a run in `mode`, with everything else left to the project's
    /// config and a freshly allocated release id.
    pub fn new(mode: Mode) -> Self {
        ProtectOptions {
            mode,
            release_id: None,
            revision: None,
        }
    }
}

/// A protection run's account of itself.
#[derive(Debug, Clone)]
pub struct ProtectOutcome {
    /// `swp-embedding`'s own result, unaltered: the counts, the fingerprint and
    /// its level, the files changed, the artifacts written in write order, and
    /// the full [`Plan`](swp_embedding::Plan) including every refusal with its
    /// reason.
    pub protection: Protection,
    /// The revision label the run recorded, after trimming — `None` only when the
    /// caller passed none. A label that trims to nothing never reaches a recorded
    /// release: it is refused before anything is written. It is returned because the
    /// release record holds what was *stored*, and a caller that normalizes the
    /// label a second time can disagree with it.
    pub revision: Option<String>,
}

/// One file a protection run rewrote, and how much of it changed.
///
/// The same four measurements [`Protection`] keeps, spelled as this module's own
/// type: a type a binding may hold is allowed to reach only types a binding may
/// hold, so it cannot borrow `swp-embedding`'s row even though the fields match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedFile {
    /// Canonical project-relative path, forward-slashed.
    pub file: String,
    /// Sites this run embedded in this file.
    pub sites: u32,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// One site the release carries, as far as a caller outside Rust may see it.
///
/// This is a planned site with its keyed identity left out — not stripped from
/// it on the way out, but never read into this struct at all. Which four keyed
/// addresses a site answers to decides which tags a copy must carry, so a list
/// of them is the private constellation in a printable form; what a caller acts
/// on is where the mark went and how it was carried, which is every field here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedSite {
    /// Canonical project-relative path.
    pub file: String,
    /// 1-based line in the protected text, where a reader will look. A hint: it
    /// is measured before the rewrite, so the line of a multi-line literal is
    /// approximate by design.
    pub line_hint: u32,
    pub language: String,
    /// `"ast"` or `"lexical"`: how much the tool understood here.
    pub adapter: String,
    /// `"integer"` or `"string"`.
    pub class: String,
    /// The equivalent-form family that carried the mark.
    pub family: String,
    /// Bits the tag carries, which equals [`ProtectSummary::tag_bits`].
    pub width: u8,
    /// The `RadiusKind` code of the key the tag derived from: `0`
    /// statement+identifiers, `1` scope+identifiers, `2` statement+names, `3`
    /// scope+names. A slot selector, not a key and not keyed material.
    pub primary: u8,
}

/// One candidate location the run refused, and why.
///
/// The refusal's *sentence* stays out. A refusal is reported as
/// `no family reachable here rendered code <n>`, and that `<n>` is a rendered
/// tag — HMAC output (`swp-embedding/src/apply.rs:235, :256-266`, copied into
/// the plan at `plan.rs:132-139`). `reason` is the stable token from the same
/// record and carries nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedSite {
    pub file: String,
    pub line_hint: u32,
    /// `overlapping-radius`, `constellation-full`, `changed-after-scan`,
    /// `refused-by-validation`, and the other tokens `swp-embedding` uses.
    pub reason: String,
}

/// What a protection run decided, in the form a foreign binding may hold.
///
/// [`Session::protect`] returns the same account plus the private plan document;
/// this returns the account alone, for a caller that has no business holding a
/// plan. The field set is the one `docs/adr/0001-protect-generate-binding-boundary.md`
/// measured as what the CLI actually reads: its twenty fields carry the twenty-two
/// keys of the 29 that `swp protect --format json` prints out of a `Protection` —
/// eighteen one for one, `generated` and `modified` restated from `artifacts` and
/// `files_changed`, and the document's `families` and `skip_reasons` as the
/// per-site lists they count — with the remaining seven being the CLI's own
/// constants and advice. Nothing keyed is reachable from here, and `binding_surface`
/// checks that field by field rather than trusting the name.
///
/// It is a plain owned value: no borrow of the `Session`, no handle into the
/// store, and nothing to free or zeroize on the other side of an FFI boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectSummary {
    /// Which of the three modes ran. `plan` and `dry_run` wrote nothing the
    /// caller can see; `release` rewrote source.
    pub mode: Mode,
    pub project_id: ProjectId,
    /// The release this run minted or was given. For `Mode::Plan` this is the id
    /// to pass back as `--release` to apply the constellation, and passing a
    /// different one derives different keys and silently makes a second release.
    pub release_id: ReleaseId,
    pub created_at: Timestamp,
    /// What the operator said the source was, trimmed; `None` when nothing was
    /// said. A label that trims to nothing is refused before the run writes
    /// anything, so it is never here as a silent absence. Display metadata, never
    /// hashed.
    pub revision: Option<String>,
    /// §16 fingerprint of the tree as it now stands.
    pub fingerprint: Digest,
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
    pub files_walked: usize,
    /// Files counted into the fingerprint across the whole tree.
    pub files_in_scope: usize,
    /// Literals that could have carried a fragment.
    pub candidates: usize,
    /// Every file the constellation lands in, in write order. Only `release` writes them.
    pub files_changed: Vec<ProtectedFile>,
    /// Every site the release carries, in plan order. Its length is
    /// [`sites_embedded`](Self::sites_embedded).
    pub sites: Vec<ProtectedSite>,
    /// Every candidate the run did not use, in the order the refusals were
    /// recorded. Its length is [`sites_skipped`](Self::sites_skipped).
    pub refusals: Vec<RefusedSite>,
    /// Every artifact the run wrote, in write order: store-relative under
    /// `.swp/`, project-relative for protected source. Empty for `dry_run`.
    pub artifacts: Vec<String>,
    /// What the walk and the ceilings reported but did not act on.
    ///
    /// This crosses because every string that can appear here has been read, not
    /// because it is a `String`. Seven push sites in five files, all in `swp-embedding`:
    /// `candidates.rs:358-361` and `:385-388` (a project-relative path with a
    /// count of literals left out; the limits in force), `plan.rs:155-157` — one
    /// line per walk omission, whose reason is fixed prose, a path, a byte count
    /// or a limit number (`walk.rs:239-424`) — `plan.rs:158-164` with
    /// `select.rs:312-320` (the shortfall line: two counts of sites),
    /// `protect.rs:274-278` and `:281-286` (the `plan` and `dry_run`
    /// explanations, written at the call site), and `protect.rs:377-381` (how
    /// many source files were modified). None of them interpolates a key, a keyed
    /// id or a tag; a limit is a number from the config and a path is already in
    /// `files_changed`. `sdk_parity` sweeps the serialized summary of a real run
    /// against that run's own location ids, which is what keeps this a measured
    /// claim rather than a reading of five files.
    pub notes: Vec<String>,
}

impl Session {
    /// Plan or apply a constellation, and return what a foreign binding may hold
    /// about it.
    ///
    /// This is [`Session::protect`] — the same pipeline, the same modes, the same
    /// errors, one call underneath it — with the private plan document left in
    /// Rust. Use `protect` when you need the plan or the keyed site identities;
    /// use this when you need the account of the run. Nothing is re-derived to
    /// build it, so the two cannot disagree about what happened.
    ///
    /// The effects are the mode's, unchanged: `plan` writes the plan into the
    /// store, `release` writes the store and rewrites source, `dry_run` writes
    /// neither. This is still the one operation that loads the project's root
    /// secret, and the secret is dropped before it returns.
    pub fn protect_summary(&self, options: &ProtectOptions) -> Result<ProtectSummary, SwpError> {
        let outcome = self.protect(options)?;
        Ok(summarize(&outcome))
    }
}

/// Project a protection result onto the fields that carry no key.
///
/// Written as a copy out of named fields, not a filter over the whole struct: the
/// point of the boundary is that a keyed value has to be *read* to cross it, and
/// this function reads no `locations`, no `detail` and no plan document.
fn summarize(outcome: &ProtectOutcome) -> ProtectSummary {
    let p = &outcome.protection;
    ProtectSummary {
        mode: p.mode,
        project_id: p.project_id.clone(),
        release_id: p.release_id.clone(),
        created_at: p.created_at,
        revision: outcome.revision.clone(),
        fingerprint: p.fingerprint,
        fingerprint_level: p.fingerprint_level.clone(),
        tag_bits: p.tag_bits,
        requested_sites: p.requested_sites,
        target_sites: p.target_sites,
        sites_embedded: p.sites_embedded,
        sites_skipped: p.sites_skipped,
        files_walked: p.files_walked,
        files_in_scope: p.files_in_scope,
        candidates: p.candidates,
        files_changed: p
            .files_changed
            .iter()
            .map(|f| ProtectedFile {
                file: f.file.clone(),
                sites: f.sites,
                bytes_before: f.bytes_before,
                bytes_after: f.bytes_after,
            })
            .collect(),
        sites: p
            .plan
            .sites
            .iter()
            .map(|s| ProtectedSite {
                file: s.file.clone(),
                line_hint: s.line_hint,
                language: s.language.clone(),
                adapter: s.adapter.clone(),
                class: s.class.clone(),
                family: s.family.clone(),
                width: s.width,
                primary: s.primary,
            })
            .collect(),
        refusals: p
            .plan
            .skipped
            .iter()
            .map(|s| RefusedSite {
                file: s.file.clone(),
                line_hint: s.line_hint,
                reason: s.reason.clone(),
            })
            .collect(),
        artifacts: p.artifacts.clone(),
        notes: p.notes.clone(),
    }
}

impl Session {
    /// Plan or apply a constellation over this project's protected targets.
    ///
    /// `Mode::Plan` writes into the store and touches no source; `Mode::Release`
    /// writes both; `Mode::DryRun` writes neither. Which locations a release uses
    /// is keyed, and the key comes from the project's secret, so this is the one
    /// operation that both loads the secret and rewrites files — and the secret is
    /// dropped as soon as `swp-embedding` has derived what it needs, before this
    /// call returns.
    ///
    /// Two failures are designed outcomes rather than bugs to work around:
    /// `NO_SAFE_LOCATIONS` when every candidate location failed a safety
    /// precondition — the source is then unchanged, which is the point — and
    /// `LIMIT_REACHED` when a resource ceiling trimmed the run.
    pub fn protect(&self, options: &ProtectOptions) -> Result<ProtectOutcome, SwpError> {
        // `--release` on a protection run is how a generated plan gets applied:
        // the constellation is keyed by release id, so the same id over the same
        // tree is the same plan, byte for byte.
        let release_id = match &options.release_id {
            Some(id) => id.clone(),
            None => new_release_id()?,
        };
        // What the caller stated, trimmed. `Some("   ")` reaches the pipeline as
        // `Manual { value: "" }`, and the pipeline refuses it as the input it is —
        // `swp protect --revision "   "` is that refusal, not a blank label.
        let trimmed = options
            .revision
            .as_ref()
            .map(|text| text.trim().to_string());
        let revision = match &trimmed {
            Some(value) => SourceRevision::Manual {
                value: value.clone(),
            },
            // `Content`, always, unless the caller named a revision. There is no
            // shell-out to `git` anywhere in this build: §21 forbids running
            // things in a tree that may not be the operator's, and a protection
            // run may be pointed at a directory that is not a repository at all.
            None => SourceRevision::Content,
        };
        let secret = self.secret()?;
        let request = Request {
            root: self.project_root(),
            store: self.store(),
            secret: &secret,
            identity: self.identity(),
            config: self.config(),
            release_id,
            revision,
            created_at: Timestamp::now_utc(),
            mode: options.mode,
        };
        let protection = swp_embedding::protect(&request)?;
        drop(secret);
        Ok(ProtectOutcome {
            protection,
            revision: trimmed,
        })
    }
}
