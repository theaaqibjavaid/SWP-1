//! Which project a command acts on, and what it is allowed to read there.
//!
//! Three rules, all of them about whose instructions are being followed:
//!
//! * **A candidate never supplies its own keys.** [`Ctx::open`] resolves the
//!   project from `--project` or by walking up from the working directory, and it
//!   is only ever called on the owner's tree. `swp scan ./copy` calls it on the
//!   current directory, not on `./copy`: a repository under examination may
//!   contain its own `.swp/` — possibly a *different* project's — and letting the
//!   scanned tree decide which keys judge it would hand the attacker the verdict.
//! * **The root secret is loaded per command, by the commands that need it.**
//!   [`Ctx::secret`] is the only way in, `inspect` never calls it, and the value
//!   is a `RootSecret`, which zeroizes itself and has no `Display` and no
//!   `Debug` that reveals bytes.
//! * **Overrides are applied to the config in one place.** `--target`, `--sites`
//!   and `--bits` patch [`SwpConfig`] here and nothing downstream knows they
//!   happened, so `swp_embedding::protect` sees one coherent settings document
//!   and validates it as usual.

use std::path::{Path, PathBuf};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ReleaseId;
use swp_core::Limits;
use swp_crypto::RootSecret;
use swp_identity::{ProjectIdentity, Store, SwpConfig, Timestamp};

use crate::args::{Flag, Parsed};

/// The project a command is working on.
pub struct Ctx {
    pub store: Store,
    pub identity: ProjectIdentity,
    /// The store's config with this command's overrides applied.
    pub config: SwpConfig,
    /// Things the operator should see before the run's own output: a limit that
    /// was clamped, an override that replaced a configured target list.
    pub warnings: Vec<String>,
}

impl Ctx {
    /// Open the project `--project` names, or the nearest enclosing one to `cwd`.
    ///
    /// The error is the interesting part: a bare `swp verify` in an unprotected
    /// directory has to say both what it looked for and where it looked, because
    /// the two common causes — wrong directory, and a project whose `.swp/` was
    /// never backed up — need different answers.
    pub fn open(parsed: &Parsed, cwd: &Path) -> Result<Ctx, SwpError> {
        let store = match parsed.value(Flag::Project) {
            Some(path) => {
                let dir = resolve(path, cwd)?;
                Store::open(&dir)?
            }
            None => Store::discover(cwd)?.ok_or_else(|| {
                SwpError::new(
                    ErrorCode::NotProtected,
                    format!(
                        "no {dot_swp} directory here or above {cwd}; run `swp init` in the \
                         project, or name one with --project <path>",
                        dot_swp = ".swp/",
                        cwd = cwd.display(),
                    ),
                )
                .with_path(cwd.display().to_string())
            })?,
        };
        let identity = store.identity()?;
        let mut config = store.config()?;
        let mut warnings = Vec::new();
        for warning in config.apply_limit_ceiling() {
            warnings.push(warning);
        }
        let mut ctx = Ctx {
            store,
            identity,
            config,
            warnings,
        };
        ctx.apply_overrides(parsed)?;
        Ok(ctx)
    }

    /// The unmodified config, for a command that must not act on a flag it was
    /// not given: `swp inspect config` shows what is on disk, not what this run
    /// would have used.
    pub fn stored_config(&self) -> Result<SwpConfig, SwpError> {
        self.store.config()
    }

    fn apply_overrides(&mut self, parsed: &Parsed) -> Result<(), SwpError> {
        let targets = parsed.many(Flag::Target);
        if !targets.is_empty() {
            let before = std::mem::take(&mut self.config.protect.targets);
            for t in &targets {
                // A target is project-relative by definition, and a path that
                // escapes the root would make protect write outside the project.
                let rel = if Path::new(t).is_absolute() {
                    let abs = resolve(t, self.store.project_root())?;
                    abs.strip_prefix(self.store.project_root())
                        .map_err(|_| {
                            SwpError::usage(format!(
                                "--target {t:?} is outside the project at {}",
                                self.store.project_root().display()
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
        if let Some(n) = parsed.number(Flag::Sites)? {
            self.config.protect.target_sites = n;
        }
        if let Some(bits) = parsed.number(Flag::Bits)? {
            let bits = u8::try_from(bits).map_err(|_| {
                SwpError::usage(format!("--bits {bits} is outside the range this build supports"))
            })?;
            self.config.protect.tag_bits = bits;
        }
        // Re-validate rather than trusting the pieces: `--sites 1` and a
        // `--target ../elsewhere` are both things a person has typed.
        self.config
            .validate()
            .map_err(|e| SwpError::new(e.code(), format!("the resulting settings are invalid: {}", e.message())))
    }

    pub fn root(&self) -> &Path {
        self.store.project_root()
    }

    pub fn limits(&self) -> Limits {
        self.config.limits.clone()
    }

    /// Load and unseal the project's root secret.
    pub fn secret(&self) -> Result<RootSecret, SwpError> {
        self.store.load_root()
    }

    /// The release ids this command should act on.
    ///
    /// `--release <id>` names one; `--latest` takes the newest; with neither,
    /// every release in the store is loaded, because a copy could have come from
    /// any of them and picking one silently would be a claim about which.
    pub fn releases(&self, parsed: &Parsed) -> Result<Vec<ReleaseId>, SwpError> {
        if let Some(raw) = parsed.value(Flag::Release) {
            let id = ReleaseId::new(raw)?;
            if !self.store.release_path(&id).is_file() {
                let known = self.store.releases()?;
                return Err(SwpError::new(
                    ErrorCode::NotProtected,
                    format!(
                        "this project has no release {id}. It has {} — `swp inspect releases` \
                         lists them",
                        name_list(&known)
                    ),
                ));
            }
            return Ok(vec![id]);
        }
        let all = self.store.releases()?;
        if all.is_empty() {
            return Err(SwpError::new(
                ErrorCode::NotProtected,
                "this project has no protected releases yet. Run `swp generate` to plan one, \
                 then `swp protect`",
            ));
        }
        if parsed.has(Flag::Latest) {
            return Ok(vec![newest(&all, &self.store)?]);
        }
        Ok(all)
    }

    /// The release to act on when exactly one is wanted, and the flag says which.
    pub fn one_release(&self, parsed: &Parsed) -> Result<ReleaseId, SwpError> {
        let list = self.releases(parsed)?;
        if list.len() == 1 {
            return Ok(list[0].clone());
        }
        // Without --release, `verify` means the newest: it asks "is the tree I am
        // standing in still the tree I protected?", and the answer to that is
        // about the last protection run.
        newest(&list, &self.store)
    }

    /// Every release, oldest first, which is the order a history is printed in.
    pub fn release_history(&self) -> Result<Vec<swp_identity::ReleaseRecord>, SwpError> {
        let mut out = Vec::new();
        for id in self.store.releases()? {
            out.push(self.store.read_release(&id)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.release_id.as_str().cmp(b.release_id.as_str()))
        });
        Ok(out)
    }

    /// Load the releases a scan or a verification will match against.
    ///
    /// This is the whole bridge from "files in `.swp/`" to "something the detector
    /// can index", and it is here rather than in each command because three rules
    /// have to hold every time it is crossed:
    ///
    /// * the manifest is **authenticated** against the project's own public verify
    ///   key before a single site of it is trusted (§31) — an edited manifest would
    ///   report a clean copy as tampered with;
    /// * the keys are derived from **this** project's secret and **this** identity's
    ///   canonicalizer version, so a release from a tree whose `.swp/` was partly
    ///   restored fails the index's own agreement check rather than reporting "no
    ///   evidence";
    /// * the root secret is dropped as soon as the last key is derived, so no
    ///   command that only scans holds one while it walks a stranger's tree.
    pub fn candidate_releases(
        &self,
        parsed: &Parsed,
    ) -> Result<Vec<swp_detection::CandidateRelease>, SwpError> {
        let ids = self.releases(parsed)?;
        self.load_releases(&ids)
    }

    /// Load exactly these releases, authenticated and keyed.
    pub fn load_releases(
        &self,
        ids: &[ReleaseId],
    ) -> Result<Vec<swp_detection::CandidateRelease>, SwpError> {
        let secret = self.secret()?;
        let canonicalizer = swp_core::CanonicalizerVersion(self.identity.canonicalizer_version);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let manifest = self.manifest(id)?;
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
            let record = self.store.read_release(id)?;
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

    /// Read and authenticate one release's private manifest.
    ///
    /// Authentication uses the project's **public** verify key, so this is the
    /// path `swp inspect` takes: reading what the store holds needs no secret,
    /// and a command that only lists artifacts should not be holding one while it
    /// does (§29). The signature check is not optional here — an edited manifest
    /// would otherwise make a clean copy look tampered with, or a tampered one look
    /// clean (§31).
    pub fn manifest(&self, id: &ReleaseId) -> Result<swp_manifest::PrivateManifest, SwpError> {
        let verify_key = self.identity.verify_key()?;
        let bytes = match self.store.read_private_manifest(id) {
            Ok(bytes) => bytes,
            Err(e) if !self.store.manifest_path(id).is_file() => {
                return Err(SwpError::new(
                    ErrorCode::InvalidManifest,
                    format!(
                        "release {id} has a public record but no private manifest at {}; \
                         the protection run was interrupted, or .swp/private/ was not \
                         restored with .swp/public/",
                        self.store.relabel(&self.store.manifest_path(id))
                    ),
                )
                .caused_by(&e))
            }
            Err(e) => return Err(e),
        };
        swp_manifest::PrivateManifest::load(&bytes, &verify_key)
    }
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

/// Make a path absolute against `cwd`, without touching the filesystem.
///
/// `canonicalize` is deliberately not used: it resolves symlinks, and a project
/// root reached through a symlink would then be reported under a different name
/// than the operator typed, which makes a store path in a report unfindable.
/// `swp scan ./copy` shares this rule for the candidate's path for the same
/// reason — the report must say what was typed.
pub(crate) fn resolve(path: &str, cwd: &Path) -> Result<PathBuf, SwpError> {
    if path.trim().is_empty() {
        return Err(SwpError::usage("a path was asked for and nothing was given"));
    }
    let p = Path::new(path);
    Ok(if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_prefers_the_recorded_time_and_breaks_ties_by_id() {
        let dir = std::env::temp_dir().join(format!(
            "swp-cli-newest-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = Store::init(&dir, &RootSecret::from_bytes(&[7u8; 32]).unwrap())
            .unwrap()
            .store;
        let older = ReleaseId::new("rel-aaaaaaaaaaaa").unwrap();
        let newer = ReleaseId::new("rel-bbbbbbbbbbbb").unwrap();
        for (id, when) in [
            (&older, "2026-01-01T00:00:00Z"),
            (&newer, "2026-06-01T00:00:00Z"),
        ] {
            let mut rec = sample_release(id, store.project_id().unwrap());
            rec.created_at = Timestamp::parse(when).unwrap();
            store.write_release(&rec).unwrap();
        }
        let got = newest(&[older.clone(), newer.clone()], &store).unwrap();
        assert_eq!(got, newer, "the older record was chosen");
        // Tie on time: the larger id wins, deterministically, so two releases
        // created inside one second still have one answer.
        let mut a = sample_release(&older, store.project_id().unwrap());
        let mut b = sample_release(&newer, store.project_id().unwrap());
        let same = Timestamp::parse("2026-06-01T00:00:00Z").unwrap();
        a.created_at = same;
        b.created_at = same;
        store.write_release(&a).unwrap();
        store.write_release(&b).unwrap();
        assert_eq!(
            newest(&[older.clone(), newer.clone()], &store).unwrap(),
            newer,
            "with the timestamps equal the id decides"
        );
        assert_eq!(
            newest(&[newer.clone(), older.clone()], &store).unwrap(),
            newer,
            "and it decides the same way whichever order the ids arrive in"
        );
        assert!(newest(&[], &store).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn relative_paths_are_resolved_against_the_working_directory_only() {
        assert_eq!(
            resolve("src", Path::new("/proj")).unwrap(),
            PathBuf::from("/proj/src")
        );
        assert_eq!(resolve("/x", Path::new("/proj")).unwrap(), PathBuf::from("/x"));
        assert_eq!(resolve("./x", Path::new("/proj")).unwrap(), PathBuf::from("/proj/./x"));
        assert_eq!(resolve("", Path::new("/proj")).unwrap_err().code(), ErrorCode::Usage);
    }

    fn sample_release(id: &ReleaseId, project: swp_core::ProjectId) -> swp_identity::ReleaseRecord {
        use swp_core::version::GeneratorInfo;
        use swp_core::{Digest, SchemaVersion, SWP_PROTOCOL_NAME};
        use swp_identity::{SourceRevision, WatermarkParams};
        swp_identity::ReleaseRecord {
            protocol: SWP_PROTOCOL_NAME.into(),
            schema: SchemaVersion::MANIFEST_V1.0,
            project_id: project,
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
