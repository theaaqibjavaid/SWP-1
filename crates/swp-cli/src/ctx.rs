//! Which project a command acts on, and what it is allowed to read there.
//!
//! The rules about whose instructions a command follows — a candidate never
//! supplies its own keys, the root secret is drawn per operation by the
//! operations that need it, overrides land in one place — are [`Session`]'s, and
//! [`swp_sdk::session`] states them. What is left here is the command line's own
//! share of the same work:
//!
//! * **Flags are not settings.** [`overrides`] turns `--target`, `--sites` and
//!   `--bits` into an [`Overrides`], and [`selection`] turns `--release` and
//!   `--latest` into a [`ReleaseSelection`]. The SDK takes structured choices and
//!   never sees a flag, which is what lets a bound caller make the same choice
//!   without a terminal.
//! * **A named directory is resolved, not searched.** `--project` and `swp scan
//!   <candidate>` both take a path as typed, and [`resolve`] makes it absolute
//!   without canonicalizing it — the report has to say what the operator wrote.
//! * **The private half of the store stays the CLI's.** `swp inspect` prints
//!   private manifests on purpose, and [`Session`] withholds them; the read is
//!   here, against [`Ctx::store`], and it authenticates through the same
//!   [`swp_manifest::PrivateManifest::from_store`] the SDK uses internally, so
//!   there is one implementation of the check rather than two that could drift.

use std::path::{Path, PathBuf};

use swp_core::error::SwpError;
use swp_core::id::ReleaseId;
use swp_core::Limits;
use swp_identity::{ProjectIdentity, ReleaseRecord, Store, SwpConfig};
use swp_sdk::{Overrides, ReleaseSelection, Session};

use crate::args::{Flag, Parsed};

/// The project a command is working on.
pub struct Ctx {
    /// The orchestration every command runs on: the store's documents, this run's
    /// overrides applied to them, and the operations that are not printing.
    pub session: Session,
    /// A second handle on the same store, for the reads a `Session` does not
    /// offer.
    ///
    /// Those are the private artifacts — a sealed root key, a private manifest —
    /// which the API contract keeps off the reusable surface (§10) while
    /// `swp inspect` goes on printing them for the person who owns the store.
    /// `Store` is a path plus the two documents it validates on open, so this is a
    /// second parse of files the session already read, not a second source of
    /// truth: nothing here writes through `store` and reads back through `session`.
    pub store: Store,
}

impl Ctx {
    /// Open the project `--project` names, or the nearest enclosing one to `cwd`.
    ///
    /// The error is the interesting part: a bare `swp verify` in an unprotected
    /// directory has to say both what it looked for and where it looked, because
    /// the two common causes — wrong directory, and a project whose `.swp/` was
    /// never backed up — need different answers. Both branches of that live in
    /// [`Session`], because a library caller standing in the same directory
    /// deserves the same diagnosis.
    pub fn open(parsed: &Parsed, cwd: &Path) -> Result<Ctx, SwpError> {
        let overrides = overrides(parsed)?;
        let session = match parsed.value(Flag::Project) {
            Some(path) => Session::open(&resolve(path, cwd)?, &overrides)?,
            None => Session::discover(cwd, &overrides)?,
        };
        Ok(Ctx {
            store: session.open_store()?,
            session,
        })
    }

    /// The store's published identity: project id, display name, verify key.
    pub fn identity(&self) -> &ProjectIdentity {
        self.session.identity()
    }

    /// The stored settings with this command's flags applied.
    pub fn config(&self) -> &SwpConfig {
        self.session.config()
    }

    /// Things the operator should see before the run's own output: a limit that
    /// was clamped, an override that replaced a configured target list.
    pub fn warnings(&self) -> &[String] {
        self.session.warnings()
    }

    /// The unmodified config, for a command that must not act on a flag it was
    /// not given: `swp inspect config` shows what is on disk, not what this run
    /// would have used.
    pub fn stored_config(&self) -> Result<SwpConfig, SwpError> {
        self.session.stored_config()
    }

    pub fn root(&self) -> &Path {
        self.session.project_root()
    }

    pub fn limits(&self) -> Limits {
        self.session.limits()
    }

    /// The release ids this command should act on.
    pub fn releases(&self, parsed: &Parsed) -> Result<Vec<ReleaseId>, SwpError> {
        self.session.releases(&selection(parsed)?)
    }

    /// The release to act on when exactly one is wanted, and the flag says which.
    pub fn one_release(&self, parsed: &Parsed) -> Result<ReleaseId, SwpError> {
        self.session.one_release(&selection(parsed)?)
    }

    /// Every release, oldest first, which is the order a history is printed in.
    pub fn release_history(&self) -> Result<Vec<ReleaseRecord>, SwpError> {
        self.session.release_history()
    }

    /// Read and authenticate one release's public record.
    pub fn release(&self, id: &ReleaseId) -> Result<ReleaseRecord, SwpError> {
        self.session.release(id)
    }

    /// Read and authenticate one release's private manifest.
    ///
    /// This is the one store read `Session` will not do for a caller, because what
    /// it returns is the keyed constellation itself and §10 keeps that off the
    /// reusable surface. `inspect` is exempt for the reason the contract gives: it
    /// runs at the operator's own terminal, in a project whose secret is already in
    /// their store.
    pub fn manifest(&self, id: &ReleaseId) -> Result<swp_manifest::PrivateManifest, SwpError> {
        swp_manifest::PrivateManifest::from_store(&self.store, self.identity(), id)
    }
}

/// What this run's flags change about the stored settings.
///
/// The target list is handed over as typed: whether a `--target` stays inside the
/// project is a question about the project root, and containment is decided where
/// the root is known — in `Session`, once, for a CLI and a library caller alike.
fn overrides(parsed: &Parsed) -> Result<Overrides, SwpError> {
    let mut overrides = Overrides {
        targets: parsed.many(Flag::Target),
        ..Overrides::default()
    };
    if let Some(n) = parsed.number(Flag::Sites)? {
        overrides.target_sites = Some(n);
    }
    if let Some(bits) = parsed.number(Flag::Bits)? {
        overrides.tag_bits = Some(u8::try_from(bits).map_err(|_| {
            SwpError::usage(format!(
                "--bits {bits} is outside the range this build supports"
            ))
        })?);
    }
    Ok(overrides)
}

/// Which releases the flags name.
///
/// `--release <id>` names one; `--latest` takes the newest; with neither, every
/// release in the store is loaded, because a copy could have come from any of them
/// and picking one silently would be a claim about which.
///
/// `pub(crate)` rather than private because `swp scan` states the release count it
/// is about to match against before it does the matching, and saying it twice —
/// once to print, once to load — is how a progress line starts disagreeing with
/// the run.
pub(crate) fn selection(parsed: &Parsed) -> Result<ReleaseSelection, SwpError> {
    if let Some(raw) = parsed.value(Flag::Release) {
        return Ok(ReleaseSelection::Ids(vec![ReleaseId::new(raw)?]));
    }
    if parsed.has(Flag::Latest) {
        return Ok(ReleaseSelection::Latest);
    }
    Ok(ReleaseSelection::All)
}

/// Make a path absolute against `cwd`, without touching the filesystem.
///
/// `canonicalize` is deliberately not used: it resolves symlinks, and a project
/// root reached through a symlink would then be reported under a different name
/// than the operator typed, which makes a store path in a report unfindable.
/// `swp scan ./copy` shares this rule for the candidate's path for the same
/// reason — the report must say what was typed.
pub(crate) fn resolve(path: &str, cwd: &Path) -> Result<PathBuf, SwpError> {
    if path.trim().is_empty() {
        return Err(SwpError::usage(
            "a path was asked for and nothing was given",
        ));
    }
    let p = Path::new(path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    Ok(without_current_dir_components(&joined))
}

/// Drop the `.` components a joined path picks up, so that `-p .` is reported as
/// the directory it names rather than as `…\project\.`.
///
/// `..` is left alone on purpose: cancelling it textually is not the same as
/// resolving it when a component in between is a symlink, and this build never
/// follows a symlink it has not been told to.
fn without_current_dir_components(path: &Path) -> PathBuf {
    let kept = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect::<PathBuf>();
    if kept.as_os_str().is_empty() {
        // `-p .` in a relative working directory: the directory itself, which an
        // empty path would not say.
        return PathBuf::from(".");
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::error::ErrorCode;

    #[test]
    fn relative_paths_are_resolved_against_the_working_directory_only() {
        assert_eq!(
            resolve("src", Path::new("/proj")).unwrap(),
            PathBuf::from("/proj/src")
        );
        assert_eq!(
            resolve("/x", Path::new("/proj")).unwrap(),
            PathBuf::from("/x")
        );
        assert_eq!(
            resolve("./x", Path::new("/proj")).unwrap(),
            PathBuf::from("/proj/./x")
        );
        assert_eq!(
            resolve("", Path::new("/proj")).unwrap_err().code(),
            ErrorCode::Usage
        );
    }
}
