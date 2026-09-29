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

use swp_core::error::SwpError;
use swp_core::id::ReleaseId;
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
    /// records `text` trimmed. A `Some("")` is therefore a stated-but-empty
    /// revision, which is what `swp protect --revision ""` means, and is not the
    /// same stored value as passing nothing.
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
    /// The revision label the run recorded, after trimming — `None` when the
    /// caller passed none or passed only spaces. It is returned because the
    /// release record holds what was *stored*, and a caller that normalizes the
    /// label a second time can disagree with it.
    pub revision: Option<String>,
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
        // What the caller stated, trimmed — including the empty case, which is a
        // stated revision of "" and is what `swp protect --revision "  "` records.
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
            revision: trimmed.filter(|s| !s.is_empty()),
        })
    }
}
