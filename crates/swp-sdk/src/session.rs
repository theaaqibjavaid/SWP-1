//! Which project a call acts on, and what it is allowed to read there.
//!
//! [`Session`] is the same three rules the CLI's `ctx.rs` enforced, with
//! the command line taken out of them:
//!
//! * **A candidate never supplies its own keys.** A `Session` is built from a
//!   directory the *caller* names. The tree an operation reads — a candidate in
//!   [`Session::scan`] — is opened by a different function and never resolves the
//!   project: a repository under examination may ship its own `.swp/`, possibly a
//!   different project's, and if any part of the verdict depended on it, the
//!   examined party would be supplying the evidence used to judge them.
//! * **The root secret is loaded per operation, by the operations that need it.**
//!   A `Session` holds none between calls; [`Session::protect`](crate::Session::protect)
//!   and the release loader draw one, derive what they need, and drop it inside
//!   the call. The secret itself never crosses out of this crate: no public type
//!   here carries key bytes, a derived key or an expected tag.
//! * **Overrides are applied to the config in one place.** [`Overrides`] patches
//!   [`SwpConfig`] here and nothing downstream knows it happened, so
//!   `swp_embedding::protect` sees one coherent settings document and validates it
//!   as usual.

use std::path::{Path, PathBuf};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ReleaseId;
use swp_core::Limits;
use swp_crypto::RootSecret;
use swp_identity::{ProjectIdentity, ReleaseRecord, Store, SwpConfig, Timestamp, SWP_DIR};

/// What a caller wants changed about the stored settings for one run.
///
/// These are the knobs `swp`'s `--target`, `--sites`, `--bits` and
/// `--embed-strings` equivalents turn into; everything they do not name is read
/// from `.swp/config.toml` unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// Directories to protect, project-relative — or absolute, in which case they
    /// must resolve inside the project root. Appended to the configured targets.
    pub targets: Vec<String>,
    /// Patterns to skip, appended to `[protect] excludes`.
    pub excludes: Vec<String>,
    /// `[protect] target_sites`, when the caller chose a constellation size.
    pub target_sites: Option<u32>,
    /// `[protect] tag_bits`, when the caller chose a tag width.
    pub tag_bits: Option<u8>,
    /// `[protect] embed_strings`, when the caller chose whether string literals
    /// carry marks.
    pub embed_strings: Option<bool>,
}

/// Which releases an operation should load.
///
/// The default is every release the project has, and that is the protocol's
/// choice rather than a convenience: a copy could have come from any protected
/// build, and picking one silently would be an unstated claim about which.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ReleaseSelection {
    /// Every release in the store.
    #[default]
    All,
    /// The newest one, by recorded time.
    Latest,
    /// Exactly these, each of which must exist.
    Ids(Vec<ReleaseId>),
}

/// An opened project: its store, its published identity, and the settings its
/// operations run under.
///
/// A `Session` is a path plus two parsed documents. It holds no file handle, no
/// lock and no key, so two threads may hold two sessions and use them at the same
/// time. It is *not* a claim that the tree will not change underneath it: every
/// operation reloads what it needs when it is called, and one mutating operation
/// per project at a time is the caller's obligation, exactly as it is in a shell.
#[derive(Debug, Clone)]
pub struct Session {
    store: Store,
    identity: ProjectIdentity,
    config: SwpConfig,
    warnings: Vec<String>,
}

impl Session {
    /// Open the project whose root is `project_root`.
    ///
    /// The directory is named by the caller and is not searched for: a library
    /// that decided which project it was working on by looking at the process's
    /// working directory would be inheriting whatever the host application's cwd
    /// happens to be, and a protection run whose scope depends on that is not one
    /// anyone should script.
    pub fn open(project_root: &Path, overrides: &Overrides) -> Result<Session, SwpError> {
        // `--project`/`open` names one directory exactly, so the store's own
        // marker is tested there rather than by walking up from it.
        if !Store::exists(project_root) && project_root.join(SWP_DIR).is_dir() {
            return Err(incomplete_store(project_root));
        }
        Session::build(Store::open(project_root)?, overrides)
    }

    /// Open the nearest enclosing project at or above `from`.
    ///
    /// This is `swp`'s default. Prefer [`Session::open`] in an application: the
    /// error is the interesting part here, and the caller usually knows which
    /// directory it means.
    pub fn discover(from: &Path, overrides: &Overrides) -> Result<Session, SwpError> {
        let store = Store::discover(from)?.ok_or_else(|| match enclosing_swp_dir(from) {
            // A tree with a `.swp/` and no config is reported as an incomplete
            // store rather than an unprotected directory, because `swp init` is
            // the one thing that must not be recommended here.
            Some(dir) => incomplete_store(&dir),
            None => SwpError::new(
                ErrorCode::NotProtected,
                format!(
                    "no {dot_swp} directory here or above {cwd}; run `swp init` in the \
                     project, or name one with --project <path>",
                    dot_swp = ".swp/",
                    cwd = from.display(),
                ),
            )
            .with_path(from.display().to_string()),
        })?;
        Session::build(store, overrides)
    }

    pub(crate) fn build(store: Store, overrides: &Overrides) -> Result<Session, SwpError> {
        let identity = store.identity()?;
        let mut config = store.config()?;
        let mut warnings = Vec::new();
        for warning in config.apply_limit_ceiling() {
            warnings.push(warning);
        }
        let mut session = Session {
            store,
            identity,
            config,
            warnings,
        };
        session.apply(overrides)?;
        Ok(session)
    }

    /// Apply one run's overrides, then re-validate the result.
    fn apply(&mut self, overrides: &Overrides) -> Result<(), SwpError> {
        if !overrides.targets.is_empty() {
            let before = std::mem::take(&mut self.config.protect.targets);
            for t in &overrides.targets {
                // A target is project-relative by definition, and a path that
                // escapes the root would make protect write outside the project.
                let rel = if Path::new(t).is_absolute() {
                    let abs = without_current_dir_components(&PathBuf::from(t));
                    abs.strip_prefix(self.store.project_root())
                        .map_err(|_| {
                            // The text names the flag rather than the field,
                            // because an error message is the product's, not one
                            // call site's: docs/TROUBLESHOOTING.md quotes it, and a
                            // person who hits this in a binding is pointed at the
                            // same sentence the CLI says.
                            SwpError::usage(format!(
                                "--target {t:?} is outside the project at {}",
                                swp_core::text::display_path(
                                    &self.store.project_root().display().to_string()
                                )
                            ))
                        })?
                        .to_string_lossy()
                        .replace('\\', "/")
                } else {
                    t.clone()
                };
                if rel.is_empty() || rel == "." {
                    self.config.protect.targets = vec![".".to_string()];
                    break;
                }
                self.config.protect.targets.push(rel);
            }
            if self.config.protect.targets.is_empty() {
                self.config.protect.targets = before.clone();
            }
            if self.config.protect.targets != before {
                self.warnings.push(format!(
                    "[protect] targets for this run: {} (config.toml says {})",
                    self.config.protect.targets.join(", "),
                    if before.is_empty() {
                        "nothing".to_string()
                    } else {
                        before.join(", ")
                    }
                ));
            }
        }
        if !overrides.excludes.is_empty() {
            self.config
                .protect
                .excludes
                .extend(overrides.excludes.iter().cloned());
        }
        if let Some(n) = overrides.target_sites {
            self.config.protect.target_sites = n;
        }
        if let Some(bits) = overrides.tag_bits {
            self.config.protect.tag_bits = bits;
        }
        if let Some(on) = overrides.embed_strings {
            self.config.protect.embed_strings = on;
        }
        // Re-validate rather than trusting the pieces: a target that escapes the
        // root and a site count of one are both things a person has typed.
        self.config.validate().map_err(|e| {
            SwpError::new(
                e.code(),
                format!("the resulting settings are invalid: {}", e.message()),
            )
        })
    }

    /// The project's root directory, as the store resolved it.
    pub fn project_root(&self) -> &Path {
        self.store.project_root()
    }

    /// Open the store this session is about, as a [`Store`].
    ///
    /// A `Session` already holds one; this hands back a second handle to the same
    /// directory rather than the field, because `Store` is a path plus the two
    /// documents it validates on open, and the store's private surface — a sealed
    /// root key, a private manifest — is deliberately not reachable through a
    /// `Session`. A caller that needs those reads them here, and taking the second
    /// `Store::open` is one extra parse of a file the session already parsed.
    pub fn open_store(&self) -> Result<Store, SwpError> {
        Store::open(self.store.project_root())
    }

    /// The public identity: project id, display name, verify key, canonicalizer
    /// version. Nothing in it is secret — it is the file the repository commits.
    pub fn identity(&self) -> &ProjectIdentity {
        &self.identity
    }

    /// The settings operations on this session run under, overrides included.
    pub fn config(&self) -> &SwpConfig {
        &self.config
    }

    /// The config as it is on disk, without this session's overrides.
    ///
    /// For a caller that must not act on a flag it was not given: `swp inspect
    /// config` shows what the operator wrote, not what the next run would use.
    pub fn stored_config(&self) -> Result<SwpConfig, SwpError> {
        self.store.config()
    }

    /// What the caller should see before an operation's own output: a limit that
    /// was clamped against the hard ceiling, an override that replaced a
    /// configured target list.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The resource ceilings a walk, a parse or a scan may not exceed.
    pub fn limits(&self) -> Limits {
        self.config.limits.clone()
    }

    /// Load and unseal the project's root secret.
    pub(crate) fn secret(&self) -> Result<RootSecret, SwpError> {
        self.store.load_root()
    }

    /// Resolve a selection into the release ids it names, refusing one that is
    /// not in the store.
    pub fn releases(&self, selection: &ReleaseSelection) -> Result<Vec<ReleaseId>, SwpError> {
        let all = || -> Result<Vec<ReleaseId>, SwpError> {
            let list = self.store.releases()?;
            if list.is_empty() {
                return Err(SwpError::new(
                    ErrorCode::NotProtected,
                    "this project has no protected releases yet. Run `swp generate` to plan one, \
                     then `swp protect`",
                ));
            }
            Ok(list)
        };
        match selection {
            ReleaseSelection::All => all(),
            ReleaseSelection::Latest => Ok(vec![newest(&all()?, &self.store)?]),
            ReleaseSelection::Ids(ids) => {
                for id in ids {
                    if !self.store.release_path(id).is_file() {
                        let known = self.store.releases()?;
                        return Err(SwpError::new(
                            ErrorCode::NotProtected,
                            format!(
                                "this project has no release {id}. It has {} — `swp inspect \
                                 releases` lists them",
                                name_list(&known)
                            ),
                        ));
                    }
                }
                Ok(ids.clone())
            }
        }
    }

    /// The release to act on when exactly one is wanted: the one that was named,
    /// or the newest, because "is the tree I am standing in still the tree I
    /// protected?" is a question about the last protection run.
    pub fn one_release(&self, selection: &ReleaseSelection) -> Result<ReleaseId, SwpError> {
        let list = self.releases(selection)?;
        if list.len() == 1 {
            return Ok(list[0].clone());
        }
        newest(&list, &self.store)
    }

    /// Every release, oldest first, which is the order a history is printed in.
    pub fn release_history(&self) -> Result<Vec<ReleaseRecord>, SwpError> {
        let mut out = Vec::new();
        for id in self.store.releases()? {
            out.push(self.release(&id)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.release_id.as_str().cmp(b.release_id.as_str()))
        });
        Ok(out)
    }

    /// Read and authenticate one release's public record.
    ///
    /// The record is the document a report quotes — the release id, the
    /// fingerprint it compared, how many sites it claimed, when it was published —
    /// and unlike the manifest it is committed, so it is the one file in the store
    /// a stranger can edit without touching anything private. Checking it against
    /// the same key that signed the manifest is what stops those two from being
    /// made to disagree by editing the half that is public (§31).
    ///
    /// It needs no secret, which is why a listing can afford to authenticate every
    /// release it names.
    pub fn release(&self, id: &ReleaseId) -> Result<ReleaseRecord, SwpError> {
        let record = self.store.read_release(id)?;
        swp_manifest::sig::verify_release_record(&record, &self.identity.verify_key()?)?;
        Ok(record)
    }

    /// Load exactly these releases, authenticated and keyed.
    ///
    /// This is the whole bridge from "files in `.swp/`" to "something the detector
    /// can index", and it is one function rather than one per caller because four
    /// rules have to hold every time it is crossed:
    ///
    /// * the manifest is **authenticated** against the project's own public verify
    ///   key before a single site of it is trusted (§31) — an edited manifest would
    ///   report a clean copy as tampered with;
    /// * so is the **public record** beside it, which is the file a repository
    ///   carries and the one a report quotes its numbers from;
    /// * the keys are derived from **this** project's secret and **this** identity's
    ///   canonicalizer version, so a release from a tree whose `.swp/` was partly
    ///   restored fails the index's own agreement check rather than reporting "no
    ///   evidence";
    /// * the root secret is dropped as soon as the last key is derived, so no
    ///   operation that only scans holds one while it walks a stranger's tree.
    ///
    /// It is `pub(crate)` because what it hands back is the keyed constellation
    /// itself — every location id, every original literal, and the derived keys
    /// that turn one into the other — which §10 of the API contract keeps off this
    /// surface for the same reason it keeps expected tags off it. A caller chooses
    /// releases with [`ReleaseSelection`], which every operation here takes; none
    /// of them needs to be handed a `CandidateRelease` to do it.
    pub(crate) fn load_releases(
        &self,
        ids: &[ReleaseId],
    ) -> Result<Vec<swp_detection::CandidateRelease>, SwpError> {
        let secret = self.secret()?;
        let canonicalizer = swp_core::CanonicalizerVersion(self.identity.canonicalizer_version);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let manifest = self.private_manifest(id)?;
            if &manifest.release_id != id {
                return Err(SwpError::new(
                    ErrorCode::ReleaseMismatch,
                    format!(
                        "{} holds the manifest of release {}, not {id}",
                        self.store.relabel(&self.store.manifest_path(id)),
                        manifest.release_id
                    ),
                ));
            }
            let record = self.release(id)?;
            let keys = swp_manifest::ManifestKeys::derive(
                &secret,
                &self.identity.project_id,
                id,
                canonicalizer,
            );
            out.push(swp_detection::CandidateRelease {
                manifest,
                record,
                keys,
            });
        }
        drop(secret);
        if out.is_empty() {
            return Err(SwpError::new(
                ErrorCode::NotProtected,
                "no release of this project could be loaded",
            ));
        }
        Ok(out)
    }

    /// The releases an operation matches against.
    pub(crate) fn loaded(
        &self,
        selection: &ReleaseSelection,
    ) -> Result<Vec<swp_detection::CandidateRelease>, SwpError> {
        let ids = self.releases(selection)?;
        self.load_releases(&ids)
    }

    /// Index loaded releases with this project's own **public** verify key.
    ///
    /// `build_indexes` is where the detector checks that the keys it was handed
    /// belong to the manifests it was handed, so an operation cannot reach a scan
    /// without crossing that check. The key needs no secret: it is the one
    /// `identity.json` publishes.
    pub(crate) fn indexes<'a>(
        &self,
        releases: &'a [swp_detection::CandidateRelease],
    ) -> Result<Vec<swp_detection::ReleaseIndex<'a>>, SwpError> {
        swp_detection::build_indexes(releases, &self.identity.verify_key()?, &self.limits())
    }

    /// Read and authenticate one release's private manifest.
    ///
    /// Not public on purpose: a manifest is the keyed constellation itself — every
    /// location id, every original literal — and §10 of the API contract keeps
    /// private manifests off this surface for the same reason it keeps expected
    /// tags off it. `swp inspect manifest` prints one because it is a command a
    /// person runs at their own terminal, with the secret already in their store;
    /// it goes to [`swp_manifest::PrivateManifest::from_store`] directly for the
    /// same reason this does.
    fn private_manifest(&self, id: &ReleaseId) -> Result<swp_manifest::PrivateManifest, SwpError> {
        swp_manifest::PrivateManifest::from_store(&self.store, &self.identity, id)
    }

    /// The store-relative form of a path, for output.
    pub(crate) fn relabel(&self, path: &Path) -> String {
        self.store.relabel(path)
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }
}

/// The nearest project that has a `.swp/` directory, at or above `start`, whether
/// or not it is a store. Only the error path uses it, to tell "this project was
/// never initialized" apart from "this project's store is incomplete".
fn enclosing_swp_dir(start: &Path) -> Option<PathBuf> {
    let mut cur: Option<&Path> = Some(start);
    while let Some(dir) = cur {
        if dir.join(SWP_DIR).is_dir() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// A `.swp/` directory with no `config.toml` in it.
///
/// Discovery uses that one file as the store's marker, so this tree is not a store
/// to this build even though it plainly was one. Saying only "not protected" would
/// send the reader to `swp init`, which is the wrong advice twice over: it is the
/// command that rotates a secret when somebody runs it believing the project still
/// has its releases, and the file that is missing here holds settings only.
fn incomplete_store(project: &Path) -> SwpError {
    let missing = project.join(SWP_DIR).join("config.toml");
    SwpError::new(
        ErrorCode::NotProtected,
        format!(
            "there is a .swp/ directory at {}, but it has no config.toml for this command to \
             read, so it is not treated as a store. Restore that one file (settings only — \
             `swp init` writes the defaults again); do not re-initialize a project whose \
             releases you still need to verify.",
            project.display(),
        ),
    )
    .with_path(missing.display().to_string())
    .with_next(
        "Copy .swp/config.toml back from version control and the store opens again. `swp init` \
         will also rewrite it, in a project that still has its private/ directory — which is \
         the case this message is warning against confusing with the other one, where the whole \
         store is gone.",
    )
}

/// The release with the latest recorded time, ties broken by id so the answer is
/// stable even if two runs landed in the same second.
fn newest(list: &[ReleaseId], store: &Store) -> Result<ReleaseId, SwpError> {
    let mut stamped: Vec<(Timestamp, ReleaseId)> = Vec::with_capacity(list.len());
    for id in list {
        stamped.push((store.read_release(id)?.created_at, id.clone()));
    }
    stamped.sort();
    stamped
        .last()
        .map(|(_, id)| id.clone())
        .ok_or_else(|| SwpError::usage("no release was named and none exists"))
}

fn name_list(ids: &[ReleaseId]) -> String {
    match ids.len() {
        0 => "no releases".to_string(),
        1 => format!("release {}", ids[0]),
        n => format!(
            "{} releases, newest first: {}",
            n,
            ids.iter()
                .rev()
                .take(4)
                .map(|i| i.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Drop the `.` components a joined path picks up, so that a target of `.` is
/// reported as the directory it names rather than as `…\project\.`.
///
/// `..` is left alone on purpose: cancelling it textually is not the same as
/// resolving it when a component in between is a symlink, and this build never
/// follows a symlink it has not been told to.
pub(crate) fn without_current_dir_components(path: &Path) -> PathBuf {
    let kept = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect::<PathBuf>();
    if kept.as_os_str().is_empty() {
        // A bare `.` in a relative working directory: the directory itself, which
        // an empty path would not say.
        return PathBuf::from(".");
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch store in the temporary directory, removed at the end of the test
    /// that asks for it. A key of all-`fill` is not a secret worth keeping, and a
    /// store that outlives its test would be a store the next run refuses to
    /// initialize.
    struct Scratch {
        dir: PathBuf,
        store: Store,
    }

    impl Scratch {
        fn new(what: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "swp-sdk-{what}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let secret = RootSecret::from_bytes(&[7u8; 32]).unwrap();
            let store = Store::init(&dir, &secret).unwrap().store;
            Scratch { dir, store }
        }

        fn record(&self, id: &ReleaseId) -> ReleaseRecord {
            use swp_core::version::GeneratorInfo;
            use swp_core::{Digest, SchemaVersion, SWP_PROTOCOL_NAME};
            use swp_identity::{SourceRevision, WatermarkParams};
            ReleaseRecord {
                protocol: SWP_PROTOCOL_NAME.into(),
                schema: SchemaVersion::MANIFEST_V1.0,
                project_id: self.store.project_id().unwrap(),
                release_id: id.clone(),
                created_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
                source_revision: SourceRevision::Content,
                fingerprint: Digest([1u8; 32]),
                fingerprint_level: "L1".into(),
                private_manifest_digest: Digest([2u8; 32]),
                watermark: WatermarkParams {
                    target_sites: 16,
                    tag_bits: 4,
                    sites_embedded: 12,
                    sites_skipped: 3,
                    canonicalizer_version: 1,
                    form_set: "0123456789abcdef".into(),
                    adapters: vec![],
                },
                generator: GeneratorInfo::current(),
                signature: "AAA=".into(),
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    #[test]
    fn newest_prefers_the_recorded_time_and_breaks_ties_by_id() {
        let scratch = Scratch::new("newest");
        let older = ReleaseId::new("rel-aaaaaaaaaaaa").unwrap();
        let newer = ReleaseId::new("rel-bbbbbbbbbbbb").unwrap();
        for (id, when) in [
            (&older, "2026-01-01T00:00:00Z"),
            (&newer, "2026-06-01T00:00:00Z"),
        ] {
            let mut rec = scratch.record(id);
            rec.created_at = Timestamp::parse(when).unwrap();
            scratch.store.write_release(&rec).unwrap();
        }
        let got = newest(&[older.clone(), newer.clone()], &scratch.store).unwrap();
        assert_eq!(got, newer, "the older record was chosen");
        // Tie on time: the larger id wins, deterministically, so two releases
        // created inside one second still have one answer.
        let same = Timestamp::parse("2026-06-01T00:00:00Z").unwrap();
        for mut rec in [scratch.record(&older), scratch.record(&newer)] {
            rec.created_at = same;
            scratch.store.write_release(&rec).unwrap();
        }
        assert_eq!(
            newest(&[older.clone(), newer.clone()], &scratch.store).unwrap(),
            newer,
            "with the timestamps equal the id decides"
        );
        assert_eq!(
            newest(&[newer.clone(), older.clone()], &scratch.store).unwrap(),
            newer,
            "and it decides the same way whichever order the ids arrive in"
        );
        assert!(newest(&[], &scratch.store).is_err());
    }

    #[test]
    fn a_dot_component_is_dropped_but_a_bare_dot_stays_the_directory() {
        assert_eq!(
            without_current_dir_components(Path::new("./src")),
            PathBuf::from("src")
        );
        assert_eq!(
            without_current_dir_components(Path::new(".")),
            PathBuf::from(".")
        );
        assert_eq!(
            without_current_dir_components(Path::new("a/./b")),
            PathBuf::from("a/b")
        );
    }
}
