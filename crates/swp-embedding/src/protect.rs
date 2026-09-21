//! One protection run, end to end: walk, harvest, select, prove, record, write.
//!
//! This is the only place in the system that modifies a project's own source, so
//! the module is organized around two questions. **May this byte change?** —
//! answered by [`crate::apply`], which re-parses every rewrite and refuses any
//! site it cannot prove. **In what order may anything reach disk?** — answered
//! below, and the order is deliberate:
//!
//! ```text
//! derive keys   →   walk   →   harvest   →   select   →   prove (in memory)
//!     ↓
//! private manifest  →  plan  →  public release record  →  protected sources
//! ```
//!
//! The records land before the sources they describe, never after. A run
//! interrupted between the two leaves a release that `swp verify` reports as
//! incomplete — an honest answer about a half-finished job, recoverable by
//! re-running. The reverse order would leave protected source whose fragment
//! locations were never recorded anywhere, and a manifest cannot be reconstructed
//! after the fact without re-embedding, which changes the source again.
//!
//! ## The two trees
//!
//! A run walks the project twice. The first walk uses the project's own
//! `[protect] targets` and is the only set of files this command may modify. The
//! second uses [`ProtectConfig::scan_scope`] — every file a scanner would find —
//! and supplies the rest of the §16 fingerprint's inputs, because a fingerprint
//! over `src/` alone could never be reproduced by a scanner holding a copy of the
//! whole project. Neither walk substitutes for the other: a file outside the
//! targets is counted into the hash and left byte-for-byte alone.
//!
//! ## What leaves this module
//!
//! [`Protection`] is a summary: counts, the fingerprint, changed file names, and
//! the [`Plan`]. It carries no tag, no key and no literal text, so the CLI can
//! print it and a report can serialize it without a second redaction step. The
//! only artifacts holding site data are the private manifest and the plan, and
//! both land under `.swp/private/` through the store's hardened writer.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{Digest, ProjectId, ReleaseId};
use swp_core::limits::Limits;
use swp_core::site::TagWidth;
use swp_core::text::canonical_relpath;
use swp_core::version::{CanonicalizerVersion, GeneratorInfo, SWP_PROTOCOL_NAME};
use swp_core::SchemaVersion;
use swp_crypto::{ManifestSigningKey, RootSecret};
use swp_identity::{
    AdapterUse, ProjectIdentity, ProtectConfig, ReleaseRecord, SourceRevision, Store, SwpConfig,
    Timestamp, WatermarkParams,
};
use swp_manifest::{
    project_fingerprint, sha256,
    sig::{sign_release_record, verify_release_record},
    FileCanonical, ManifestKeys, PrivateManifest,
};

use crate::apply::{self, Applied, Rewritten};
use crate::candidates::{self, Scan};
use crate::plan::Plan;
use crate::select::{self, Selection};
use crate::walk::{self, ScannedFile, Walk};

/// The level a release fingerprint is taken at. Always `L1`: it is the only
/// canonicalization level that is stable under reformatting *and* defined for
/// every language including the lexical fallback, so a whole-tree hash of it
/// always exists and always means the same thing on both sides. See §16 and
/// [`swp_manifest::LEVELS`].
pub const FINGERPRINT_LEVEL: &str = "L1";

/// Whether a run writes source or only records what it would have done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Compute and save the constellation, modify nothing. `swp generate`.
    Plan,
    /// Compute, record, and apply. `swp protect`.
    Release,
    /// Compute and report, and write nothing anywhere. `swp protect --dry-run`.
    DryRun,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Plan => "plan",
            Mode::Release => "release",
            Mode::DryRun => "dry-run",
        }
    }

    /// Whether this mode may touch a project's source.
    pub fn writes_source(self) -> bool {
        self == Mode::Release
    }

    /// Whether this mode may leave an artifact in the store. A dry run is the one
    /// mode with no output at all, which is what makes it safe to point at a tree
    /// you are not sure about: it cannot record a release you did not ask for.
    pub fn writes_store(self) -> bool {
        self != Mode::DryRun
    }
}

/// Everything one run needs, gathered so the pipeline below is a straight line
/// instead of a ten-argument call. The secret is borrowed, used by the key
/// derivation, and held by nothing this module returns.
pub struct Request<'a> {
    /// Project root — the directory whose subtree is walked.
    pub root: &'a Path,
    pub store: &'a Store,
    pub secret: &'a RootSecret,
    pub identity: &'a ProjectIdentity,
    pub config: &'a SwpConfig,
    pub release_id: ReleaseId,
    /// Where this source came from, as the operator states it. Display metadata
    /// only; the detector never trusts it, and it is never hashed.
    pub revision: SourceRevision,
    /// When the run happened. The caller supplies it rather than letting each
    /// document pick its own, so the three artifacts a run writes carry one
    /// timestamp — and so a test can pin the whole output.
    pub created_at: Timestamp,
    pub mode: Mode,
}

/// One file this run rewrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileChange {
    pub file: String,
    pub sites: u32,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// What a run decided, and what it left on disk.
#[derive(Debug, Clone, Serialize)]
pub struct Protection {
    pub project_id: ProjectId,
    pub release_id: ReleaseId,
    pub created_at: Timestamp,
    pub mode: Mode,
    /// §16, over the tree as a scanner will walk it.
    pub fingerprint: Digest,
    pub fingerprint_level: String,
    pub tag_bits: u8,
    /// Sites the operator asked for.
    pub requested_sites: u32,
    /// Sites the run aimed at, after resource limits trimmed the request.
    pub target_sites: u32,
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    /// Files analyzed inside the project's own `[protect] targets`.
    pub files_walked: usize,
    /// Files counted into the fingerprint across the whole tree.
    pub files_in_scope: usize,
    /// Literals that could have carried a fragment.
    pub candidates: usize,
    pub files_changed: Vec<FileChange>,
    /// Every artifact this run wrote, in write order: store-relative under
    /// `.swp/`, project-relative for protected source.
    pub artifacts: Vec<String>,
    pub notes: Vec<String>,
    /// The full account of the constellation, including every refusal.
    pub plan: Plan,
}

/// Protect a project, or plan to.
///
/// Every failure but one happens before the first write of source. The
/// exception is a disk error partway through the final loop, which is reported by
/// naming the protected files that landed and the one that did not — with the
/// release records already on disk to explain what the tree is missing.
pub fn protect(req: &Request<'_>) -> Result<Protection, SwpError> {
    req.identity.validate()?;
    req.config.validate()?;
    let project_id = req.identity.project_id.clone();
    let canonicalizer = CanonicalizerVersion(req.identity.canonicalizer_version);
    let width = TagWidth::new(req.config.protect.tag_bits)?;
    let limits = req.config.limits.clone();
    let generator = GeneratorInfo::current();
    let created_at = req.created_at;
    let verifying = req.identity.verify_key()?;

    let keys = ManifestKeys::derive(req.secret, &project_id, &req.release_id, canonicalizer);
    let signing = ManifestSigningKey::from_root(req.secret, project_id.as_str())?;
    if req.mode.writes_store() {
        refuse_replaced_release(req)?;
    }

    let walked = walk::walk(req.root, &req.config.protect, &limits)?;
    let scan = candidates::scan(req.root, &walked, &keys, &req.config.protect, width, &limits)?;
    let selection = select::select(&scan, req.config.protect.target_sites, &limits)?;
    let applied = apply::apply(req.root, &scan, &selection, &keys, width, &limits)?;
    if applied.entries.is_empty() {
        // §11: skip, do not force. Nothing has been written and nothing will be.
        return Err(no_safe_locations(req, &selection, &applied));
    }

    let plan = Plan::build(
        project_id.clone(),
        req.release_id.clone(),
        created_at,
        canonicalizer.0,
        generator.clone(),
        &req.config.protect,
        req.config.protect.target_sites,
        &scan,
        &selection,
        &applied,
    )?;
    let (fingerprint, files_in_scope) =
        release_fingerprint(req, &scan, &applied, canonicalizer, &limits)?;

    let mut manifest = PrivateManifest::build(
        project_id.clone(),
        req.release_id.clone(),
        created_at,
        canonicalizer.0,
        fingerprint,
        FINGERPRINT_LEVEL,
        req.config.protect.tag_bits,
        generator.clone(),
        applied.entries.clone(),
    )?;
    manifest.sign(&signing)?;
    manifest.verify_signature(&verifying)?;

    let mut record = release_record(
        req,
        &scan,
        &selection,
        &plan,
        &manifest,
        fingerprint,
        created_at,
        &generator,
    )?;
    sign_release_record(&mut record, &signing)?;
    verify_release_record(&record, &verifying)?;

    let mut artifacts = Vec::new();
    let mut notes: Vec<String> = scan.notes.clone();
    match req.mode {
        Mode::Release => {
            write_release(
                req,
                &manifest,
                &plan,
                &record,
                &applied,
                &mut artifacts,
                &mut notes,
            )?;
        }
        Mode::Plan => {
            // The plan is the whole output of `swp generate`, and it is private for
            // the same reason the manifest is: it names files and literals.
            req.store.write_plan(&req.release_id, &plan.to_json_bytes())?;
            artifacts.push(req.store.relabel(&req.store.plan_path(&req.release_id)));
            notes.push(
                "plan mode: no source file was modified, and no release record or manifest \
                 exists for this run"
                    .to_string(),
            );
        }
        Mode::DryRun => {
            notes.push(
                "dry run: this is what `swp protect` would do. Nothing was written — no plan, \
                 no manifest, no release record, no source change. The release id above is the \
                 one a real run would mint, not one that exists."
                    .to_string(),
            );
        }
    }

    Ok(Protection {
        project_id,
        release_id: req.release_id.clone(),
        created_at,
        mode: req.mode,
        fingerprint,
        fingerprint_level: FINGERPRINT_LEVEL.to_string(),
        tag_bits: width.bits(),
        requested_sites: req.config.protect.target_sites,
        target_sites: plan.target_sites,
        sites_embedded: applied.entries.len() as u32,
        sites_skipped: plan.skipped.len() as u32,
        files_walked: scan.files.len(),
        files_in_scope,
        candidates: scan.total_candidates(),
        files_changed: applied
            .files
            .iter()
            .map(|f| FileChange {
                file: f.rel.clone(),
                sites: f.sites,
                bytes_before: f.bytes_before,
                bytes_after: f.bytes_after,
            })
            .collect(),
        artifacts,
        notes,
        plan,
    })
}

/// Records first, sources last, and every protected file read back once.
fn write_release(
    req: &Request<'_>,
    manifest: &PrivateManifest,
    plan: &Plan,
    record: &ReleaseRecord,
    applied: &Applied,
    artifacts: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<(), SwpError> {
    let manifest_path = req.store.manifest_path(&req.release_id);
    req.store
        .write_private_manifest(&req.release_id, &manifest.to_json_bytes())?;
    artifacts.push(req.store.relabel(&manifest_path));

    let plan_path = req.store.plan_path(&req.release_id);
    req.store.write_plan(&req.release_id, &plan.to_json_bytes())?;
    artifacts.push(req.store.relabel(&plan_path));

    let record_path = req.store.release_path(&req.release_id);
    req.store.write_release(record)?;
    artifacts.push(req.store.relabel(&record_path));

    let mut written: Vec<String> = Vec::with_capacity(applied.files.len());
    for file in &applied.files {
        if let Err(e) = write_source(req.root, file) {
            let mut msg = format!(
                "{} of {} protected {} written; {:?} failed: {}. ",
                written.len(),
                applied.files.len(),
                if applied.files.len() == 1 {
                    "file was"
                } else {
                    "files were"
                },
                file.rel,
                e.message(),
            );
            if written.is_empty() {
                msg.push_str("No source file was changed, so the project is still the tree the records do not describe.");
            } else {
                msg.push_str(&format!(
                    "These files were replaced: {}. The release record at {} describes the \
                     whole constellation, so the tree is now partially protected.",
                    written.join(", "),
                    req.store.relabel(&record_path),
                ));
            }
            msg.push_str(" Fix the disk condition and re-run `swp protect`, then `swp verify` to confirm every site is present.");
            return Err(SwpError::new(ErrorCode::Io, msg));
        }
        written.push(file.rel.clone());
    }
    artifacts.extend(applied.files.iter().map(|f| f.rel.clone()));
    if !applied.files.is_empty() {
        notes.push(format!(
            "{} source file{} modified in place",
            applied.files.len(),
            if applied.files.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    Ok(())
}

/// Write one protected file so an interrupted write cannot leave it half-rewritten,
/// then require the bytes on disk to be the bytes that were meant to land.
fn write_source(root: &Path, file: &Rewritten) -> Result<(), SwpError> {
    if canonical_relpath(&file.rel) != file.rel {
        return Err(SwpError::internal(format!(
            "protected path {:?} is not a canonical relative path",
            file.rel
        )));
    }
    let abs = root.join(&file.rel);
    let name = abs
        .file_name()
        .ok_or_else(|| SwpError::internal(format!("{:?} has no file name", abs)))?;
    let tmp = abs.with_file_name(format!(
        "{}.swp-tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let bytes = file.text.as_bytes();
    let wrote = (|| -> Result<(), SwpError> {
        let mut out = std::fs::File::create(&tmp)
            .map_err(|e| SwpError::io(format!("cannot create {}: {e}", tmp.display())))?;
        out.write_all(bytes)
            .map_err(|e| SwpError::io(format!("cannot write {}: {e}", tmp.display())))?;
        out.flush()?;
        out.sync_all()
            .map_err(|e| SwpError::io(format!("cannot flush {}: {e}", tmp.display())))?;
        drop(out);
        std::fs::rename(&tmp, &abs)
            .map_err(|e| SwpError::io(format!("cannot replace {:?}: {e}", abs)))?;
        Ok(())
    })();
    if wrote.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    wrote?;
    let back = std::fs::read(&abs)?;
    if back != bytes {
        return Err(SwpError::io(format!(
            "{:?} does not read back as the {} bytes of protected text that were written",
            abs,
            bytes.len()
        )));
    }
    Ok(())
}

/// The §16 fingerprint of the tree as released: protected text for the files this
/// run rewrote, as-found text for everything else in the targets, and the
/// scanner's own scope for everything the project's targets left out.
fn release_fingerprint(
    req: &Request<'_>,
    scan: &Scan,
    applied: &Applied,
    canonicalizer: CanonicalizerVersion,
    limits: &Limits,
) -> Result<(Digest, usize), SwpError> {
    let mut inputs = applied.fingerprint_inputs(scan);
    let scope = walk::walk(req.root, &ProtectConfig::scan_scope(), limits)?;
    let outside: Vec<ScannedFile> = scope
        .files
        .iter()
        .filter(|f| !inputs.contains_key(&f.rel))
        .cloned()
        .collect();
    if !outside.is_empty() {
        // One byte budget, spent across both passes on purpose: the scanner reads
        // the whole tree against a single `max_total_bytes`, so a fingerprint the
        // writer could afford but the scanner could not reproduce would be worse
        // than no fingerprint at all.
        let extra = Walk {
            files: outside,
            omissions: Vec::new(),
            dirs_pruned: 0,
        };
        let remaining = limits.max_total_bytes.saturating_sub(scan.bytes_read);
        let scoped = Limits {
            max_total_bytes: remaining,
            ..limits.clone()
        };
        for (rel, digest) in candidates::tree_digests(req.root, &extra, &scoped)? {
            inputs.insert(rel, digest);
        }
    }
    let count = inputs.len();
    let files = inputs
        .into_iter()
        .map(|(path, digest)| FileCanonical::new(path, digest))
        .collect::<Vec<_>>();
    Ok((
        project_fingerprint(FINGERPRINT_LEVEL, canonicalizer.0, &files)?,
        count,
    ))
}

/// The public half of the record. Nothing here names a location: the fingerprint
/// and the parameters are enough for a reader to know *which* release a copy came
/// from, and §19 wants the record to survive on its own.
///
/// The eight arguments are the eight artifacts one protect run produces; grouping
/// them into a struct would name a type that exists only to be taken apart again.
#[allow(clippy::too_many_arguments)]
fn release_record(
    req: &Request<'_>,
    scan: &Scan,
    selection: &Selection,
    plan: &Plan,
    manifest: &PrivateManifest,
    fingerprint: Digest,
    created_at: Timestamp,
    generator: &GeneratorInfo,
) -> Result<ReleaseRecord, SwpError> {
    let families: BTreeSet<&str> = manifest
        .sites
        .iter()
        .map(|e| e.family.as_str())
        .collect();
    let joined = families.into_iter().collect::<Vec<_>>().join(",");
    let hex = sha256(joined.as_bytes()).hex();
    Ok(ReleaseRecord {
        protocol: SWP_PROTOCOL_NAME.to_string(),
        schema: SchemaVersion::MANIFEST_V1.0,
        project_id: req.identity.project_id.clone(),
        release_id: req.release_id.clone(),
        created_at,
        source_revision: req.revision.clone(),
        fingerprint,
        fingerprint_level: FINGERPRINT_LEVEL.to_string(),
        private_manifest_digest: manifest.content_digest(),
        watermark: WatermarkParams {
            target_sites: selection.target as u32,
            tag_bits: req.config.protect.tag_bits,
            sites_embedded: manifest.sites.len() as u32,
            sites_skipped: plan.skipped.len() as u32,
            canonicalizer_version: req.identity.canonicalizer_version,
            form_set: hex[..16].to_string(),
            adapters: scan
                .adapters
                .iter()
                .map(|a| AdapterUse {
                    language: a.language.clone(),
                    mode: a.mode.to_string(),
                    files: a.files,
                })
                .collect(),
        },
        generator: generator.clone(),
        signature: String::new(),
    })
}

/// A release id names one signed document forever, so replacing one is not a
/// convenience but a loss of evidence — and the sources of the replaced release
/// would keep carrying a constellation no record describes any more.
fn refuse_replaced_release(req: &Request<'_>) -> Result<(), SwpError> {
    let record_path = req.store.release_path(&req.release_id);
    if record_path.is_file() {
        let label = req.store.relabel(&record_path);
        let existing = req.store.read_release(&req.release_id).map_err(|e| {
            SwpError::new(
                ErrorCode::InvalidManifest,
                format!(
                    "{label} already exists for release {} and cannot be read: {}. SWP-1 will \
                     not overwrite a release record it cannot account for.",
                    req.release_id,
                    e.message()
                ),
            )
        })?;
        return Err(SwpError::new(
            ErrorCode::Usage,
            format!(
                "{label} already records a signed release from {}. SWP-1 never replaces a \
                 release record: it is the evidence, and the sources of that release carry \
                 the sites only it describes. Run `swp protect` without --release to mint a \
                 new id, or `swp verify --release {}` to check the existing one.",
                existing.created_at,
                req.release_id
            ),
        ));
    }
    let manifest_path = req.store.manifest_path(&req.release_id);
    if manifest_path.is_file() {
        return Err(SwpError::new(
            ErrorCode::InvalidManifest,
            format!(
                "{} exists but its public release record does not, so this release id is \
                 half-recorded. Choose a new release id; the orphan is listed by \
                 `swp inspect store` and can be removed by hand.",
                req.store.relabel(&manifest_path)
            ),
        ));
    }
    Ok(())
}

/// Why §11 stopped a run, spelled out of the selection's own refusals rather than
/// as a bare "no locations".
fn no_safe_locations(req: &Request<'_>, selection: &Selection, applied: &Applied) -> SwpError {
    let mut msg = format!(
        "no location under [protect] targets {:?} could be proven safe to rewrite, so no file \
         was modified and no release was recorded",
        req.config.protect.targets
    );
    for (reason, count) in selection.skip_counts() {
        msg.push_str(&format!("\n  {count} site(s) refused: {reason}"));
    }
    if !applied.dropped.is_empty() {
        msg.push_str(&format!(
            "\n  {} site(s) were selected and then refused by re-validation",
            applied.dropped.len()
        ));
    }
    msg.push_str(
        "\n  Nothing was written: this is a refusal, not a partial success. Run `swp inspect \
         fragments` for each candidate's reason, then raise [protect] target_sites, widen \
         [protect] targets, or enable embed_strings in .swp/config.toml.",
    );
    SwpError::new(ErrorCode::NoSafeLocations, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use swp_core::id::ReleaseId;
    use swp_core::limits::Limits;
    use swp_crypto::RootSecret;

    /// The key these tests protect with. Fixed, not random: a test that cannot
    /// say which constellation it produced is not a test.
    const KEY: [u8; 32] = [3u8; 32];

    /// A project on disk with a store, which removes itself.
    struct Tree {
        root: PathBuf,
        store: Store,
        secret: RootSecret,
        identity: ProjectIdentity,
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// `sites` functions, each holding exactly one embeddable literal.
    fn module(sites: usize) -> String {
        let mut body = String::new();
        for s in 0..sites {
            body.push_str(&format!(
                "function calc_{s}(base, scale) {{\n  return base * scale + {};\n}}\n",
                1000 + s
            ));
        }
        body
    }

    fn tree(label: &str, files: &[(&str, &str)]) -> Tree {
        let mut root = std::env::temp_dir();
        root.push(format!("swp-protect-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (rel, text) in files {
            write(&root, rel, text);
        }
        let secret = RootSecret::from_bytes(&KEY).unwrap();
        let store = Store::init(&root, &secret).unwrap().store;
        let identity = store.identity().unwrap();
        Tree {
            root,
            store,
            secret,
            identity,
        }
    }

    fn config(sites: u32) -> SwpConfig {
        SwpConfig {
            protect: ProtectConfig {
                target_sites: sites,
                ..ProtectConfig::default()
            },
            ..SwpConfig::default()
        }
    }

    fn release(id: &str) -> ReleaseId {
        ReleaseId::new(id).unwrap()
    }

    const STAMP: &str = "2026-09-20T10:00:00Z";

    fn request<'a>(
        t: &'a Tree,
        cfg: &'a SwpConfig,
        id: &str,
        mode: Mode,
    ) -> Request<'a> {
        Request {
            root: &t.root,
            store: &t.store,
            secret: &t.secret,
            identity: &t.identity,
            config: cfg,
            release_id: release(id),
            revision: SourceRevision::Content,
            created_at: Timestamp::parse(STAMP).unwrap(),
            mode,
        }
    }

    /// The fingerprint of a tree exactly as a scanner would take it.
    fn scanned_fingerprint(root: &Path, canonicalizer: u16) -> Result<Digest, SwpError> {
        let limits = Limits::default();
        let walked = walk::walk(root, &ProtectConfig::scan_scope(), &limits)?;
        let files: Vec<FileCanonical> = candidates::tree_digests(root, &walked, &limits)?
            .into_iter()
            .map(|(path, digest)| FileCanonical::new(path, digest))
            .collect();
        project_fingerprint(FINGERPRINT_LEVEL, canonicalizer, &files)
    }

    fn read(t: &Tree, rel: &str) -> String {
        std::fs::read_to_string(t.root.join(rel)).unwrap()
    }

    #[test]
    fn a_release_lands_its_records_before_its_sources() {
        let t = tree("order", &[("src/a.js", &module(8)), ("src/b.js", &module(8))]);
        let cfg = config(8);
        let req = request(&t, &cfg, "rel-aaaaaaaaaaaa", Mode::Release);
        let out = protect(&req).unwrap();

        assert_eq!(out.mode, Mode::Release);
        assert_eq!(out.sites_embedded, 8, "{:?}", out.plan.skipped);
        assert_eq!(out.fingerprint_level, "L1");
        // Write order is the recovery property: records that describe a tree must
        // exist before the tree changes.
        assert_eq!(
            &out.artifacts[..3],
            &[
                ".swp/private/manifests/rel-aaaaaaaaaaaa.json".to_string(),
                ".swp/private/plans/rel-aaaaaaaaaaaa.json".to_string(),
                ".swp/public/releases/rel-aaaaaaaaaaaa.json".to_string(),
            ][..]
        );
        assert!(out.artifacts[3].starts_with("src/"), "{:?}", out.artifacts);
        assert_eq!(
            out.artifacts.len(),
            3 + out.files_changed.len(),
            "every rewritten file is reported"
        );

        let manifest = PrivateManifest::load(
            &t.store.read_private_manifest(&out.release_id).unwrap(),
            &t.identity.verify_key().unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.site_count(), 8);
        assert_eq!(manifest.fingerprint, out.fingerprint);
        assert_eq!(
            manifest.content_digest(),
            t.store.read_release(&out.release_id).unwrap().private_manifest_digest,
            "the record must point at the manifest that was actually written"
        );
        let record = t.store.read_release(&out.release_id).unwrap();
        verify_release_record(&record, &t.identity.verify_key().unwrap()).unwrap();
        assert_eq!(record.created_at.to_rfc3339(), STAMP);
        assert!(!record.watermark.form_set.is_empty());
        // The tree the records describe is the tree on disk.
        assert_ne!(read(&t, "src/a.js"), module(8));
        assert_eq!(
            scanned_fingerprint(&t.root, t.identity.canonicalizer_version).unwrap(),
            record.fingerprint
        );
    }

    #[test]
    fn a_source_file_outside_the_targets_is_counted_and_left_alone() {
        let t = tree(
            "outside",
            &[("src/a.js", &module(8)), ("tools/b.js", &module(6))],
        );
        let before = read(&t, "tools/b.js");
        let cfg = config(8);
        let first = protect(&request(&t, &cfg, "rel-aaaaaaaaaaaa", Mode::Release)).unwrap();
        assert_eq!(read(&t, "tools/b.js"), before, "targets are a boundary");
        assert!(
            !first.plan.sites.iter().any(|s| s.file.starts_with("tools/")),
            "{:?}",
            first.plan.sites
        );
        assert!(first.files_in_scope > first.files_walked);

        // The scanner sees the whole tree, so a change to a file that was never
        // touched has to move the published fingerprint.
        write(&t.root, "tools/b.js", &module(7));
        let second = protect(&request(&t, &cfg, "rel-bbbbbbbbbbbb", Mode::Release)).unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn a_tree_with_nothing_to_embed_modifies_nothing() {
        let t = tree("empty", &[("src/a.js", "function f(base, scale) {\n  return base;\n}\n")]);
        let cfg = config(8);
        let err = protect(&request(&t, &cfg, "rel-cccccccccccc", Mode::Release)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSafeLocations, "{err}");
        assert!(read(&t, "src/a.js").starts_with("function f"));
        for path in [
            t.store.release_path(&release("rel-cccccccccccc")),
            t.store.manifest_path(&release("rel-cccccccccccc")),
            t.store.plan_path(&release("rel-cccccccccccc")),
        ] {
            assert!(!path.exists(), "a refused run writes {:?}", path);
        }
    }

    #[test]
    fn a_signed_release_is_never_replaced() {
        let t = tree("replace", &[("src/a.js", &module(8))]);
        let cfg = config(8);
        protect(&request(&t, &cfg, "rel-dddddddddddd", Mode::Release)).unwrap();
        let id = release("rel-dddddddddddd");
        let bytes = std::fs::read(t.store.release_path(&id)).unwrap();

        let again = protect(&request(&t, &cfg, "rel-dddddddddddd", Mode::Release)).unwrap_err();
        assert_eq!(again.code(), ErrorCode::Usage, "{again}");
        assert!(again.message().contains("never replaces"));
        assert_eq!(std::fs::read(t.store.release_path(&id)).unwrap(), bytes);

        // The same tree under a new id is an ordinary second release.
        let next = protect(&request(&t, &cfg, "rel-eeeeeeeeeeee", Mode::Release)).unwrap();
        assert_eq!(next.sites_embedded, 8);
    }

    #[test]
    fn a_plan_writes_the_constellation_without_touching_a_single_byte() {
        let t = tree("plan", &[("src/a.js", &module(8))]);
        let cfg = config(8);
        let id = "rel-ffffffffffff";
        let planned = protect(&request(&t, &cfg, id, Mode::Plan)).unwrap();

        assert_eq!(planned.sites_embedded, 8);
        assert_eq!(
            planned.artifacts,
            vec![format!(".swp/private/plans/{id}.json")]
        );
        assert_eq!(read(&t, "src/a.js"), module(8), "plan mode rewrites nothing");
        assert!(!t.store.release_path(&release(id)).exists());
        assert!(!t.store.manifest_path(&release(id)).exists());
        assert!(planned.notes.iter().any(|n| n.starts_with("plan mode")));

        // The point of `swp generate`: the plan is the constellation the release
        // would write, so the two must agree site for site.
        let shipped = protect(&request(&t, &cfg, id, Mode::Release)).unwrap();
        let from_plan = Plan::from_json_bytes(&t.store.read_plan(&shipped.release_id).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&planned.plan).unwrap(),
            serde_json::to_string(&from_plan).unwrap()
        );
        assert_eq!(shipped.fingerprint, planned.fingerprint);
        assert_eq!(shipped.plan.sites, planned.plan.sites);
    }

    #[test]
    fn no_artifact_of_a_run_carries_the_key_that_produced_it() {
        // The §29 sweep in `swp-test-suite` does this over every artifact and
        // every CLI byte; this one pins the embedding side, where a change to
        // `SiteEntry` or to `Protection` would first show up.
        let t = tree("quiet", &[("src/a.js", &module(8))]);
        let cfg = config(8);
        let out = protect(&request(&t, &cfg, "rel-gggggggggggg", Mode::Release)).unwrap();
        let raw = KEY.to_vec();
        let hex = KEY
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut haystacks: Vec<(String, Vec<u8>)> = vec![(
            "protection.json".to_string(),
            serde_json::to_vec(&out).unwrap(),
        )];
        for artifact in &out.artifacts {
            let path = t.root.join(artifact);
            haystacks.push((artifact.clone(), std::fs::read(&path).unwrap()));
        }
        assert!(haystacks.len() > 3, "{:?}", out.artifacts);
        for (name, bytes) in haystacks {
            assert!(!bytes.windows(32).any(|w| w == raw), "{name} holds the root secret");
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(&hex), "{name} holds the root secret in hex");
            assert!(!text.contains(&t.secret.fingerprint()), "{name}");
        }
    }
}
