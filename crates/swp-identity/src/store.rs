//! The `.swp/` directory: where every artifact of a protected project lives.
//!
//! Three things this module is responsible for, and all three are safety
//! properties rather than conveniences:
//!
//! * **The public/private split is enforced by the accessor, not by the
//!   caller.** Anything written through a `*_private` path goes through
//!   [`write_private`], which tightens the file's access controls and then
//!   *reads them back*. On Windows `std::fs::set_permissions` reports success
//!   while changing nothing, so a permission call that is not verified is a
//!   permission call that did not happen.
//! * **A half-written store is not a store.** The root key is written before
//!   anything that references it, every artifact is written atomically, and
//!   `init` refuses to overwrite an existing key — because a second, different
//!   secret landing in `.swp/private` silently invalidates every manifest the
//!   first one ever signed. For the same reason a private artifact whose access
//!   could not be confirmed is removed on the way out: a write the store
//!   refused has to leave nothing behind for the next run to explain.
//! * **Discovery is lexical, not trust-based.** `discover` walks up from a
//!   directory to find the enclosing project. The scanner never calls it on
//!   candidate input: a third-party repository containing its own `.swp/` must
//!   not get to supply the keys this build verifies against.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{ProjectId, ReleaseId};
use swp_crypto::{harden_permissions, PermissionOutcome, RootSecret, SealedSecret};

use crate::config::SwpConfig;
use crate::project::ProjectIdentity;
use crate::release::ReleaseRecord;
use crate::{
    CONFIG_FILE, GITIGNORE_ENTRY, GITIGNORE_MARKER, IDENTITY_FILE, MANIFESTS_DIR, PLANS_DIR,
    PRIVATE_DIR, PUBLIC_DIR, RELEASES_DIR, REPORTS_DIR, ROOT_KEY_FILE, SWP_DIR,
};

/// An opened handle on a project's `.swp/` store.
#[derive(Debug, Clone)]
pub struct Store {
    project_root: PathBuf,
}

/// What creating a store did, so `swp init` can tell the user exactly what
/// exists now and what to back up (§35) rather than making them guess.
#[derive(Debug)]
pub struct StoreInit {
    pub store: Store,
    /// Paths created by this call, relative to the store, forward-slashed.
    pub created: Vec<String>,
    /// Result of hardening and verifying `root.key`.
    pub permissions: PermissionOutcome,
    /// `"created"`, `"updated"`, `"already ignored"` or `"not written"`.
    pub gitignore: &'static str,
    /// Whether an existing identity was kept rather than replaced.
    pub pre_existing: bool,
}

impl Store {
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub fn swp_dir(&self) -> PathBuf {
        self.project_root.join(SWP_DIR)
    }

    pub fn public_dir(&self) -> PathBuf {
        self.swp_dir().join(PUBLIC_DIR)
    }

    pub fn private_dir(&self) -> PathBuf {
        self.swp_dir().join(PRIVATE_DIR)
    }

    pub fn config_path(&self) -> PathBuf {
        self.swp_dir().join(CONFIG_FILE)
    }

    pub fn identity_path(&self) -> PathBuf {
        self.public_dir().join(IDENTITY_FILE)
    }

    pub fn root_key_path(&self) -> PathBuf {
        self.private_dir().join(ROOT_KEY_FILE)
    }

    pub fn releases_dir(&self) -> PathBuf {
        self.public_dir().join(RELEASES_DIR)
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.private_dir().join(MANIFESTS_DIR)
    }

    pub fn plans_dir(&self) -> PathBuf {
        self.private_dir().join(PLANS_DIR)
    }

    /// Where saved scan reports go. Under `private/` on purpose: a report names
    /// source paths and per-site literal text, and a candidate's owner should not
    /// be able to read which sites a project watches before the operator chooses
    /// to disclose the finding.
    pub fn reports_dir(&self) -> PathBuf {
        self.private_dir().join(REPORTS_DIR)
    }

    pub fn release_path(&self, id: &ReleaseId) -> PathBuf {
        self.releases_dir().join(format!("{}.json", id.as_str()))
    }

    pub fn manifest_path(&self, id: &ReleaseId) -> PathBuf {
        self.manifests_dir().join(format!("{}.json", id.as_str()))
    }

    pub fn plan_path(&self, id: &ReleaseId) -> PathBuf {
        self.plans_dir().join(format!("{}.json", id.as_str()))
    }

    /// A saved report's path, from its stem (the name without `.json`). The stem
    /// is checked rather than joined blindly: it comes back off a command line,
    /// and a `..` in it must not reach the filesystem.
    pub fn report_path(&self, stem: &str) -> Result<PathBuf, SwpError> {
        let usable = !stem.is_empty()
            && stem.len() <= 120
            && !stem.starts_with('.')
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !usable {
            return Err(SwpError::new(
                ErrorCode::PathRejected,
                format!("{stem:?} is not a report name SWP-1 would have written"),
            ));
        }
        Ok(self.reports_dir().join(format!("{stem}.json")))
    }

    pub fn exists(project_root: &Path) -> bool {
        project_root.join(SWP_DIR).join(CONFIG_FILE).is_file()
    }

    /// Walk up from `start` to the nearest enclosing protected project. Makes
    /// `swp verify` work from a subdirectory. Never follows symlinks, and stops
    /// at the filesystem root.
    ///
    /// Only ever call this on the *owner's* tree. See the module note.
    pub fn discover(start: &Path) -> Result<Option<Store>, SwpError> {
        let abs = absolute(start)?;
        let mut cur: Option<&Path> = Some(abs.as_path());
        while let Some(dir) = cur {
            if Self::exists(dir) {
                return Ok(Some(Store {
                    project_root: dir.to_path_buf(),
                }));
            }
            cur = dir.parent();
        }
        Ok(None)
    }

    /// Open an existing store, validating that the identity and config on disk
    /// are readable and belong to a protocol this build understands.
    pub fn open(project_root: &Path) -> Result<Self, SwpError> {
        let store = Store {
            project_root: absolute(project_root)?,
        };
        if !store.swp_dir().is_dir() {
            return Err(SwpError::new(
                ErrorCode::NotProtected,
                format!(
                    "there is no {SWP_DIR} directory in {}",
                    store.project_root.display()
                ),
            ));
        }
        store.config()?;
        store.identity()?;
        Ok(store)
    }

    /// Create the layout. Idempotent, and never rotates an existing key.
    pub fn init(project_root: &Path, root: &RootSecret) -> Result<StoreInit, SwpError> {
        let store = Store {
            project_root: absolute(project_root)?,
        };
        let mut created = Vec::new();
        for dir in [
            store.swp_dir(),
            store.public_dir(),
            store.private_dir(),
            store.releases_dir(),
            store.manifests_dir(),
            store.plans_dir(),
            store.reports_dir(),
        ] {
            if !dir.exists() {
                fs::create_dir_all(&dir)
                    .map_err(|e| SwpError::io(format!("cannot create {}: {e}", dir.display())))?;
                created.push(store.relabel(&dir));
            }
        }

        // Root key first: an identity without its key is unusable, and this
        // order means a crash leaves nothing that looks protected but is not.
        let key_path = store.root_key_path();
        let pre_existing = key_path.exists();
        let permissions = if pre_existing {
            PermissionOutcome::Verified(format!(
                "existing {ROOT_KEY_FILE} kept; SWP-1 never replaces a project secret"
            ))
        } else {
            let sealed = SealedSecret::seal(root)?;
            write_private(&key_path, &sealed.to_file_bytes())?;
            created.push(store.relabel(&key_path));
            harden_permissions(&key_path)
        };

        let identity_path = store.identity_path();
        if !identity_path.exists() {
            let identity = ProjectIdentity::new(
                root,
                crate::timestamp::Timestamp::now_utc(),
                default_display_name(&store.project_root),
            )?;
            write_public(&identity_path, &identity.to_json_bytes())?;
            created.push(store.relabel(&identity_path));
        }

        let config_path = store.config_path();
        if !config_path.exists() {
            write_public(&config_path, SwpConfig::default().to_toml().as_bytes())?;
            created.push(store.relabel(&config_path));
        }

        let gitignore = ensure_gitignore(&store.project_root)?;
        Ok(StoreInit {
            store,
            created,
            permissions,
            gitignore,
            pre_existing,
        })
    }

    /// Store-relative, forward-slashed form of a path, for user-facing output.
    ///
    /// Public because `swp protect` reports the artifacts it wrote by name, and a
    /// `.swp/private/...` label is both shorter and the same string the
    /// documentation uses. It never reveals anything: the paths are fixed by the
    /// layout, and the file names are release ids, which are public anyway.
    pub fn relabel(&self, path: &Path) -> String {
        match path.strip_prefix(self.swp_dir()) {
            Ok(rel) if rel.as_os_str().is_empty() => SWP_DIR.to_string(),
            Ok(rel) => format!("{SWP_DIR}/{}", rel.display()).replace('\\', "/"),
            Err(_) => path.display().to_string(),
        }
    }

    pub fn config(&self) -> Result<SwpConfig, SwpError> {
        let bytes = read(&self.config_path())?;
        let text = swp_core::text::decode_utf8_strict(&bytes)
            .ok_or_else(|| SwpError::invalid_manifest("config.toml is not valid UTF-8"))?;
        SwpConfig::parse(text)
    }

    pub fn write_config(&self, cfg: &SwpConfig) -> Result<(), SwpError> {
        cfg.validate()?;
        write_public(&self.config_path(), cfg.to_toml().as_bytes())
    }

    pub fn identity(&self) -> Result<ProjectIdentity, SwpError> {
        ProjectIdentity::from_json_bytes(&read(&self.identity_path())?)
    }

    /// Replace the public identity document.
    ///
    /// The only field `swp init` changes after the store exists is `display_name`,
    /// which is a label the owner chose; the project id and the verify key are
    /// derived, so rewriting them would be re-protecting the project under a new
    /// identity and silently invalidating every older release. `validate` rejects
    /// the shapes that cannot be written, and the caller has to have meant it.
    pub fn write_identity(&self, identity: &ProjectIdentity) -> Result<(), SwpError> {
        identity.validate()?;
        write_public(&self.identity_path(), &identity.to_json_bytes())
    }

    pub fn project_id(&self) -> Result<ProjectId, SwpError> {
        Ok(self.identity()?.project_id)
    }

    pub fn root_key_exists(&self) -> bool {
        self.root_key_path().is_file()
    }

    /// Load and unseal the root secret, checking it against the identity the
    /// store already published.
    ///
    /// The cross-check is the point: if `.swp/private/root.key` is a different
    /// project's key — a plausible accident when someone restores from the wrong
    /// backup — every fragment derivation below it would be wrong and a later
    /// scan would report "no evidence" for code that is plainly their own.
    /// Failing here turns that into one clear message.
    pub fn load_root(&self) -> Result<RootSecret, SwpError> {
        let path = self.root_key_path();
        if !path.is_file() {
            return Err(SwpError::new(
                ErrorCode::SecretUnavailable,
                format!(
                    "no root secret at {}. A protected project can only be re-protected or \
                     verified against its own releases using the secret that created it",
                    path.display()
                ),
            ));
        }
        let bytes = read(&path)?;
        let sealed = SealedSecret::parse_file_bytes(&bytes)?;
        let root = sealed.unseal()?;
        let expected = ProjectIdentity::from_json_bytes(&read(&self.identity_path())?)?.project_id;
        let actual = swp_crypto::project_id_from_root(&root)?;
        if actual != expected {
            return Err(SwpError::new(
                ErrorCode::SecretUnavailable,
                format!(
                    "{ROOT_KEY_FILE} belongs to project {actual} but this store's identity is \
                     {expected}; the secret and the public identity do not come from the same \
                     backup"
                ),
            ));
        }
        drop(bytes);
        Ok(root)
    }

    pub fn releases(&self) -> Result<Vec<ReleaseId>, SwpError> {
        list_json_ids(&self.releases_dir(), "release")
    }

    pub fn read_release(&self, id: &ReleaseId) -> Result<ReleaseRecord, SwpError> {
        ReleaseRecord::from_json_bytes(&read(&self.release_path(id))?)
    }

    pub fn write_release(&self, rec: &ReleaseRecord) -> Result<(), SwpError> {
        rec.validate()?;
        write_public(&self.release_path(&rec.release_id), &rec.to_json_bytes())
    }

    pub fn private_manifest_ids(&self) -> Result<Vec<ReleaseId>, SwpError> {
        list_json_ids(&self.manifests_dir(), "manifest")
    }

    pub fn write_private_manifest(&self, id: &ReleaseId, bytes: &[u8]) -> Result<(), SwpError> {
        write_private(&self.manifest_path(id), bytes)
    }

    pub fn read_private_manifest(&self, id: &ReleaseId) -> Result<Vec<u8>, SwpError> {
        read(&self.manifest_path(id))
    }

    pub fn write_plan(&self, id: &ReleaseId, bytes: &[u8]) -> Result<(), SwpError> {
        write_private(&self.plan_path(id), bytes)
    }

    pub fn read_plan(&self, id: &ReleaseId) -> Result<Vec<u8>, SwpError> {
        read(&self.plan_path(id))
    }

    /// Keep a scan report with the project that produced it, and return the
    /// store-relative name to print (§35's "where is this").
    ///
    /// A name already in the store is never overwritten. Report stems are
    /// second-precise because every other timestamp in the protocol is, so two
    /// saves inside one second collide — and a re-scan loop that kept only its
    /// last finding would be losing evidence without saying so. The collision is
    /// resolved by numbering, which is why callers print what this returned
    /// rather than what they asked for.
    pub fn save_report(&self, stem: &str, bytes: &[u8]) -> Result<String, SwpError> {
        let mut path = self.report_path(stem)?;
        if path.exists() {
            for n in 2u32.. {
                let candidate = self.report_path(&format!("{stem}-{n}"))?;
                if !candidate.exists() {
                    path = candidate;
                    break;
                }
            }
        }
        write_private(&path, bytes)?;
        Ok(self.relabel(&path))
    }

    pub fn read_report(&self, stem: &str) -> Result<Vec<u8>, SwpError> {
        read(&self.report_path(stem)?)
    }

    /// Saved report names, newest first: they are timestamp-stemmed, so sorting
    /// the stems lexically is sorting them chronologically.
    pub fn report_names(&self) -> Result<Vec<String>, SwpError> {
        let mut out: Vec<String> = sorted_entries(&self.reports_dir())?
            .into_iter()
            .filter_map(|n| n.strip_suffix(".json").map(|s| s.to_string()))
            .collect();
        out.sort();
        out.reverse();
        Ok(out)
    }

    /// Every artifact this store holds, with its classification, for
    /// `swp inspect store` and for the `init` summary.
    pub fn inventory(&self) -> Result<Vec<(String, bool)>, SwpError> {
        let mut out = vec![
            (self.relabel(&self.config_path()), true),
            (self.relabel(&self.identity_path()), true),
            (self.relabel(&self.root_key_path()), false),
        ];
        for (dir, is_public) in [
            (self.releases_dir(), true),
            (self.manifests_dir(), false),
            (self.plans_dir(), false),
            (self.reports_dir(), false),
        ] {
            for name in sorted_entries(&dir)? {
                out.push((format!("{}/{name}", self.relabel(&dir)), is_public));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Refuse to continue when the tree already carries an SWP-1 store, used by
    /// the scanner to report a candidate's own `.swp/` as data.
    pub fn candidate_has_store(path: &Path) -> bool {
        path.join(SWP_DIR).is_dir()
    }
}

fn default_display_name(project_root: &Path) -> String {
    project_root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string())
}

fn absolute(path: &Path) -> Result<PathBuf, SwpError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| SwpError::io(format!("cannot resolve the working directory: {e}")))?
            .join(path)
    };
    // Canonicalizing also proves the directory exists, which is what we want:
    // inventing a store path for a nonexistent directory produces a confusing
    // failure two steps later instead of one clear one now.
    joined.canonicalize().map_err(|e| {
        SwpError::new(
            ErrorCode::PathRejected,
            format!("{} is not a usable directory: {e}", joined.display()),
        )
    })
}

fn read(path: &Path) -> Result<Vec<u8>, SwpError> {
    fs::read(path).map_err(|e| {
        SwpError::new(
            ErrorCode::Io,
            format!("cannot read {}: {e}", path.display()),
        )
        .with_path(path.display().to_string())
    })
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), SwpError> {
    atomic_write(path, bytes, false)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SwpError> {
    atomic_write(path, bytes, true)
}

/// Write so a crash cannot leave a half-written document: bytes go to a
/// sibling temporary file, are flushed, then replace the target atomically.
/// Private files are additionally hardened, and an unverifiable hardening is an
/// error rather than a warning — the whole value of the private tier rests on
/// it. The file that could not be verified is removed on the way out, so the
/// error is the only thing the caller is left with; see
/// [`reject_unconfirmed_private`].
fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<(), SwpError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| SwpError::io(format!("cannot create {}: {e}", parent.display())))?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "swp".to_string())
    ));
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| SwpError::io(format!("cannot create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| SwpError::io(format!("cannot write {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        SwpError::io(format!("cannot replace {}: {e}", path.display()))
    })?;
    if private {
        return reject_unconfirmed_private(path, harden_permissions(path));
    }
    Ok(())
}

/// Refuse an artifact whose access could not be confirmed, and make the refusal
/// the whole truth by removing it.
///
/// The bytes are already in place by the time the answer comes back, so
/// "refused to keep" is a promise this function has to honour: keeping the file
/// leaves the operator to work out from the filesystem which of the two the tool
/// did. Retention is also the worse half of the choice. A `root.key` that
/// outlives its own failed `init` is an orphan no later run can clear — measured
/// on the previous build, the next `swp init` in that tree failed with "root.key
/// belongs to project X but this store's identity is Y", because `init` keeps an
/// existing secret while deriving the identity from the fresh one it just made,
/// and no third run could untangle it.
///
/// DPAPI keeps the contents unreadable to other accounts either way, so what
/// this decides is not confidentiality but whether the store's state matches its
/// sentence. A removal that itself fails is named as such in the message, because
/// a sentence that overstates what it managed to do is the exact thing this
/// function exists to prevent.
fn reject_unconfirmed_private(path: &Path, outcome: PermissionOutcome) -> Result<(), SwpError> {
    if outcome.is_verified() {
        return Ok(());
    }
    let detail = outcome.detail();
    let fate = match fs::remove_file(path) {
        Ok(()) => "it has been removed".to_string(),
        Err(e) => format!("removing it failed too, so it is still there: {e}"),
    };
    Err(SwpError::new(
        ErrorCode::SecretUnavailable,
        format!(
            "refused to keep a private artifact whose access could not be confirmed: {} — \
             {detail}; {fate}",
            path.display()
        ),
    ))
}

fn sorted_entries(dir: &Path) -> Result<Vec<String>, SwpError> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)
        .map_err(|e| SwpError::io(format!("cannot read {}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| SwpError::io(format!("directory entry: {e}")))?;
        if entry.path().is_file() {
            out.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn list_json_ids(dir: &Path, what: &str) -> Result<Vec<ReleaseId>, SwpError> {
    let mut out = Vec::new();
    for name in sorted_entries(dir)? {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        out.push(ReleaseId::new(stem).map_err(|e| {
            e.caused_by(format!(
                "a {what} file in {} has a name that is not a release id",
                dir.display()
            ))
        })?);
    }
    Ok(out)
}

/// Create or extend `.gitignore` so the private store is not committed by
/// accident. A convenience, not a boundary — but "I committed my root secret"
/// is a real and common failure, and this stops the most likely version of it.
fn ensure_gitignore(project_root: &Path) -> Result<&'static str, SwpError> {
    let path = project_root.join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(SwpError::io(format!("cannot read {}: {e}", path.display()))),
    };
    let Some(text) = existing else {
        // A missing .gitignore is normal in a non-git project; failing `init`
        // over it would be worse than not writing one.
        let body = format!("{GITIGNORE_MARKER}\n{GITIGNORE_ENTRY}\n");
        return match fs::write(&path, body) {
            Ok(()) => Ok("created"),
            Err(_) => Ok("not written"),
        };
    };
    if text.lines().map(str::trim).any(|l| l == GITIGNORE_ENTRY) {
        return Ok("already ignored");
    }
    let mut add = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        add.push('\n');
    }
    add.push_str(&format!("{GITIGNORE_MARKER}\n{GITIGNORE_ENTRY}\n"));
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(add.as_bytes()))
        .map_err(|e| SwpError::io(format!("cannot update {}: {e}", path.display())))?;
    Ok("updated")
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::hex_encode;
    use swp_crypto::{project_id_from_root, random_array};

    /// Per-test temporary directory, removed on drop.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "swp-idtest-{tag}-{}",
                hex_encode(&random_array::<8>().unwrap())
            ));
            fs::create_dir_all(&dir).unwrap();
            Tmp(dir)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root() -> RootSecret {
        RootSecret::from_bytes(&random_array::<32>().unwrap()).unwrap()
    }

    #[test]
    fn init_creates_the_expected_layout_and_reopens() {
        let tmp = Tmp::new("init");
        let init = Store::init(&tmp.0, &root()).unwrap();
        let store = &init.store;
        assert!(store.config_path().is_file());
        assert!(store.identity_path().is_file());
        assert!(store.root_key_path().is_file());
        assert!(store.releases_dir().is_dir());
        assert!(store.manifests_dir().is_dir());
        assert!(store.plans_dir().is_dir());
        assert!(store.reports_dir().is_dir());
        assert!(Store::open(&tmp.0).is_ok());
        assert!(
            init.permissions.is_verified(),
            "an unverified ACL must fail loudly: {}",
            init.permissions.detail()
        );
        assert_eq!(
            init.created,
            vec![
                ".swp",
                ".swp/public",
                ".swp/private",
                ".swp/public/releases",
                ".swp/private/manifests",
                ".swp/private/plans",
                ".swp/private/reports",
                ".swp/private/root.key",
                ".swp/public/identity.json",
                ".swp/config.toml",
            ],
            "the created list is what `swp init` shows the user; it must be complete and ordered"
        );
        assert!(init.created.iter().all(|p| p.starts_with(SWP_DIR)));
        assert!(init.created.iter().all(|p| !p.contains(':')));
        assert!(init.created.iter().all(|p| !p.contains('\\')));
    }

    #[test]
    fn init_is_idempotent_and_never_rotates_the_secret() {
        let tmp = Tmp::new("idem");
        let r = root();
        let first = Store::init(&tmp.0, &r).unwrap();
        assert!(!first.pre_existing);
        let id = first.store.identity().unwrap().project_id;
        let again = Store::init(&tmp.0, &root()).unwrap();
        assert!(again.pre_existing);
        assert_eq!(again.store.identity().unwrap().project_id, id);
        assert!(again.created.is_empty(), "{:?}", again.created);
        // The second, different secret must not have replaced the first.
        assert!(again.store.load_root().unwrap().same_as(&r));
    }

    /// The store's half of a refusal: an artifact whose access could not be
    /// confirmed is taken back off the disk, and the sentence says which of the
    /// two happened. `PermissionOutcome` is the real type and the real shapes
    /// `harden_permissions` returns on a machine that would not confirm an ACL;
    /// `swp-crypto`'s tests cover the tool producing them against live processes.
    #[test]
    fn an_unconfirmed_private_artifact_is_removed_and_says_so() {
        let tmp = Tmp::new("rollback");
        let key = tmp.0.join("root.key");
        fs::write(&key, b"sealed bytes").unwrap();
        let e = reject_unconfirmed_private(
            &key,
            PermissionOutcome::Unavailable("icacls exited with status 1332".into()),
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::SecretUnavailable);
        let rendered = e.render();
        assert!(rendered.contains("refused to keep"), "{rendered}");
        assert!(
            rendered.contains("icacls exited with status 1332"),
            "the reason was dropped: {rendered}"
        );
        assert!(rendered.contains("it has been removed"), "{rendered}");
        assert!(
            !key.exists(),
            "the artifact the store just refused to keep is still on disk"
        );
    }

    #[test]
    fn a_refusal_that_cannot_remove_the_artifact_says_that_it_cannot() {
        // A directory holding a file is the portable way to make `remove_file`
        // itself fail, which is the case a message must not paper over.
        let tmp = Tmp::new("sticky");
        let held = tmp.0.join("root.key");
        fs::create_dir(&held).unwrap();
        fs::write(held.join("inner"), b"x").unwrap();
        let e = reject_unconfirmed_private(
            &held,
            PermissionOutcome::Unverified("could not confirm the new ACL".into()),
        )
        .unwrap_err();
        let rendered = e.render();
        assert!(rendered.contains("still there"), "{rendered}");
        assert!(held.exists(), "the message and the filesystem disagree");
    }

    #[test]
    fn a_confirmed_hardening_keeps_the_artifact() {
        let tmp = Tmp::new("kept");
        let key = tmp.0.join("root.key");
        fs::write(&key, b"sealed bytes").unwrap();
        reject_unconfirmed_private(&key, PermissionOutcome::Verified("ACL limited".into()))
            .unwrap();
        assert!(key.exists());
    }

    #[test]
    fn the_root_secret_survives_the_store_round_trip() {
        let tmp = Tmp::new("roundtrip");
        let r = root();
        let store = Store::init(&tmp.0, &r).unwrap().store;
        assert!(store.load_root().unwrap().same_as(&r));
        assert_eq!(
            store.project_id().unwrap(),
            project_id_from_root(&r).unwrap()
        );
    }

    #[test]
    fn a_key_from_the_wrong_project_is_refused_at_load_time() {
        let tmp = Tmp::new("wrongkey");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let other = root();
        let sealed = SealedSecret::seal(&other).unwrap();
        fs::write(store.root_key_path(), sealed.to_file_bytes()).unwrap();
        let e = store.load_root().unwrap_err();
        assert_eq!(e.code(), ErrorCode::SecretUnavailable);
        let rendered = e.render();
        assert!(
            rendered.contains("do not come from the same backup"),
            "{rendered}"
        );
        // The message names projects, never keys.
        assert!(!rendered.contains(&hex_encode(&[0u8; 32])));
    }

    #[test]
    fn gitignore_hides_private_and_leaves_public_visible() {
        let tmp = Tmp::new("git");
        Store::init(&tmp.0, &root()).unwrap();
        let text = fs::read_to_string(tmp.0.join(".gitignore")).unwrap();
        assert!(text.contains(".swp/private/"), "{text}");
        assert!(!text.contains(".swp/public"));
        assert!(!text.contains(".swp/config.toml"));
        assert_eq!(ensure_gitignore(&tmp.0).unwrap(), "already ignored");
        let text = fs::read_to_string(tmp.0.join(".gitignore")).unwrap();
        assert_eq!(text.matches(".swp/private/").count(), 1);
    }

    #[test]
    fn gitignore_appends_without_clobbering_an_existing_file() {
        let tmp = Tmp::new("git2");
        fs::write(tmp.0.join(".gitignore"), "node_modules").unwrap();
        assert_eq!(ensure_gitignore(&tmp.0).unwrap(), "updated");
        let text = fs::read_to_string(tmp.0.join(".gitignore")).unwrap();
        assert!(text.starts_with("node_modules\n"), "{text:?}");
        assert!(text.contains(".swp/private/"));
    }

    #[test]
    fn discovery_walks_up_from_a_nested_directory() {
        let tmp = Tmp::new("discover");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let deep = tmp.0.join("src").join("a").join("b");
        fs::create_dir_all(&deep).unwrap();
        let found = Store::discover(&deep).unwrap().unwrap();
        assert_eq!(found.project_id().unwrap(), store.project_id().unwrap());
    }

    #[test]
    fn discovery_stops_when_there_is_no_store() {
        let tmp = Tmp::new("nodiscover");
        assert!(Store::discover(&tmp.0).unwrap().is_none());
    }

    #[test]
    fn opening_a_project_with_no_store_says_not_protected() {
        let tmp = Tmp::new("absent");
        let e = Store::open(&tmp.0).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NotProtected);
        assert!(e.render().contains("swp init"), "{}", e.render());
    }

    #[test]
    fn opening_a_store_with_a_corrupt_identity_fails() {
        let tmp = Tmp::new("badident");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        fs::write(store.identity_path(), b"{ not json").unwrap();
        assert!(Store::open(&tmp.0).is_err());
    }

    #[test]
    fn a_corrupt_root_key_is_an_error_not_a_panic() {
        let tmp = Tmp::new("corrupt");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        fs::write(
            store.root_key_path(),
            b"swp1-secret-v1\nscheme: plain\npayload: !!!not base64!!!\n",
        )
        .unwrap();
        assert!(store.load_root().is_err());
    }

    #[test]
    fn private_artifacts_round_trip_and_are_listed() {
        let tmp = Tmp::new("art");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let id: ReleaseId = "rel-abcdefghij".parse().unwrap();
        store.write_private_manifest(&id, b"{\"x\":1}").unwrap();
        assert_eq!(store.read_private_manifest(&id).unwrap(), b"{\"x\":1}");
        store.write_plan(&id, b"{\"y\":2}").unwrap();
        assert_eq!(store.read_plan(&id).unwrap(), b"{\"y\":2}");
        assert_eq!(store.private_manifest_ids().unwrap(), vec![id.clone()]);
    }

    #[test]
    fn a_saved_report_is_private_and_lists_newest_first() {
        let tmp = Tmp::new("reports");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let older = store
            .save_report("scan-2026-09-20T10-00-00Z", b"a")
            .unwrap();
        store
            .save_report("scan-2026-09-21T10-00-00Z", b"b")
            .unwrap();
        assert_eq!(
            older, ".swp/private/reports/scan-2026-09-20T10-00-00Z.json",
            "the name `swp scan --save` prints must be the name that was written"
        );
        assert_eq!(
            store.read_report("scan-2026-09-20T10-00-00Z").unwrap(),
            b"a"
        );
        assert_eq!(
            store.report_names().unwrap(),
            vec![
                "scan-2026-09-21T10-00-00Z".to_string(),
                "scan-2026-09-20T10-00-00Z".to_string()
            ],
            "the report index is read by `swp report`, which leads with the latest scan"
        );
        assert!(store
            .inventory()
            .unwrap()
            .iter()
            .any(|(p, public)| p.contains("reports") && !public));
    }

    #[test]
    fn saving_twice_inside_one_second_keeps_both_reports() {
        let tmp = Tmp::new("reportcollision");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let stem = "scan-2026-09-21T10-00-00Z";
        let first = store.save_report(stem, b"first").unwrap();
        let second = store.save_report(stem, b"second").unwrap();
        assert_ne!(first, second, "an existing name is not overwritten");
        assert_eq!(
            second, ".swp/private/reports/scan-2026-09-21T10-00-00Z-2.json",
            "the collision is numbered, and the numbered name is what the caller prints"
        );
        assert_eq!(store.read_report(stem).unwrap(), b"first");
        assert_eq!(store.read_report(&format!("{stem}-2")).unwrap(), b"second");
        assert_eq!(store.report_names().unwrap().len(), 2);
    }

    #[test]
    fn a_report_name_that_could_escape_the_store_is_refused() {
        let tmp = Tmp::new("reportname");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        for bad in [
            "../public/x",
            "src/../../etc/passwd",
            "..",
            "",
            "with space",
            ".hidden",
            "absolute/C:/x",
        ] {
            let e = store.report_path(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::PathRejected, "{bad:?} accepted");
        }
        assert!(store.report_path("scan-2026-09-21T10-00-00Z").is_ok());
    }

    #[test]
    fn a_misnamed_private_file_is_an_error_not_a_silent_skip() {
        let tmp = Tmp::new("misnamed");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        fs::write(store.manifests_dir().join("garbage.json"), b"{}").unwrap();
        assert!(store.private_manifest_ids().is_err());
        // A non-json sibling is fine to ignore: editors drop those everywhere.
        fs::write(store.manifests_dir().join("notes.txt"), b"x").unwrap();
        fs::remove_file(store.manifests_dir().join("garbage.json")).unwrap();
        assert!(store.private_manifest_ids().unwrap().is_empty());
    }

    #[test]
    fn public_and_private_roots_are_disjoint_siblings() {
        // Structural guard for the §18 classification: no public accessor may
        // resolve inside the private tree or the reverse.
        let tmp = Tmp::new("split");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let id: ReleaseId = "rel-abcdefghij".parse().unwrap();
        let (public, private) = (store.public_dir(), store.private_dir());
        assert!(!public.starts_with(&private));
        assert!(!private.starts_with(&public));
        assert!(!store.release_path(&id).starts_with(&private));
        assert!(!store.manifest_path(&id).starts_with(&public));
        assert!(!store.plan_path(&id).starts_with(&public));
        assert!(store.root_key_path().starts_with(&private));
        assert!(store.identity_path().starts_with(&public));
    }

    #[test]
    fn a_temp_file_never_survives_a_write() {
        let tmp = Tmp::new("tmpfile");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let id: ReleaseId = "rel-abcdefghij".parse().unwrap();
        store.write_private_manifest(&id, b"{}").unwrap();
        let leftovers: Vec<_> = sorted_entries(&store.manifests_dir())
            .unwrap()
            .into_iter()
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[test]
    fn inventory_classifies_every_artifact() {
        let tmp = Tmp::new("inv");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        let inv = store.inventory().unwrap();
        assert!(inv.iter().any(|(p, pub_)| p.ends_with("root.key") && !pub_));
        assert!(inv
            .iter()
            .any(|(p, pub_)| p.ends_with("identity.json") && *pub_));
        assert!(inv
            .iter()
            .any(|(p, pub_)| p.ends_with("config.toml") && *pub_));
        for (path, is_public) in &inv {
            let expect_private = path.contains(PRIVATE_DIR);
            assert_eq!(!is_public, expect_private, "{path} misclassified");
        }
    }

    #[test]
    fn a_config_that_is_not_toml_fails_open_not_silently() {
        let tmp = Tmp::new("badconfig");
        let store = Store::init(&tmp.0, &root()).unwrap().store;
        fs::write(store.config_path(), "target_sites = not a number").unwrap();
        assert!(store.config().is_err());
    }
}
