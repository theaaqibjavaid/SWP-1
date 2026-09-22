//! Which side of the public/private line every artifact falls on, and why.
//!
//! §18 asks for a classification rather than a comment; this module is that
//! classification in code, so `swp inspect store`, the CLI's init output, and
//! the tests all read the same table instead of each keeping their own idea of
//! what is safe to commit.
//!
//! ```text
//! PUBLIC   committable, and signed so a commit cannot be silently edited
//!          .swp/config.toml
//!          .swp/public/identity.json
//!          .swp/public/releases/<release>.json
//! PRIVATE  never committable; .swp/private/ is what `.gitignore` gets
//!          .swp/private/root.key
//!          .swp/private/manifests/<release>.json
//!          .swp/private/plans/<release>.json
//!          .swp/private/reports/<scan>.json
//! SOURCE   the project's own files, modified in place by `swp protect`
//! BACKUP   not an artifact of a run, but the two things that must be kept
//! ```
//!
//! The line is drawn by capability, not by field name. Public documents name the
//! project and describe a release; every location identifier in them is a keyed
//! HMAC output that an attacker with the file alone cannot reproduce for a new
//! site, and every tag is absent. Private documents hold plaintext paths,
//! original literal values, and — in `root.key` — the secret that derives every
//! tag. Losing a public file loses a record; losing `root.key` or the manifests
//! loses the ability to prove provenance at all, which is what §35's "what must
//! be backed up" answer is for.

use std::path::Path;

use swp_identity::{CONFIG_FILE, PRIVATE_DIR, PUBLIC_DIR, SWP_DIR};

/// What a path is, in provenance terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactClass {
    /// Safe to commit. Signed where it carries evidence.
    Public,
    /// Must never be committed. Holds keyed or secret material.
    Private,
    /// A `.swp/` file that is neither: it configures behaviour but reveals
    /// nothing. Committing it is recommended so a team protects identically.
    Config,
    /// One of the project's own source files.
    Source,
    /// Something outside a protected project.
    Foreign,
}

impl ArtifactClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactClass::Public => "public",
            ArtifactClass::Private => "private",
            ArtifactClass::Config => "config",
            ArtifactClass::Source => "source",
            ArtifactClass::Foreign => "foreign",
        }
    }

    /// Whether this class may be committed.
    pub fn committable(self) -> bool {
        matches!(self, ArtifactClass::Public | ArtifactClass::Config)
    }

    /// Whether losing this file loses provenance rather than being survivable.
    pub fn must_back_up(self) -> bool {
        matches!(self, ArtifactClass::Private)
    }

    pub fn explanation(self) -> &'static str {
        match self {
            ArtifactClass::Public => {
                "safe to commit: names the project and describes a release, signed, and keyed \
                 identifiers only"
            }
            ArtifactClass::Private => {
                "never commit: location keys, literal values and source paths, one of which is \
                 the root secret that derives every watermark"
            }
            ArtifactClass::Config => {
                "safe to commit: behaviour and resource limits, no key material"
            }
            ArtifactClass::Source => {
                "the project's own files; `swp protect` modified some of them in place"
            }
            ArtifactClass::Foreign => "not part of a protected project",
        }
    }
}

/// The public artifacts, in the order `swp init` reports them (§35).
pub const PUBLIC_ARTIFACTS: &[&str] = &[
    ".swp/config.toml",
    ".swp/public/identity.json",
    ".swp/public/releases/",
];

/// The private artifacts, in the order §35 asks them to be reported.
///
/// The first three are the backup answer — losing `root.key` or the manifests
/// loses the ability to prove provenance at all. `.swp/private/reports/` is on
/// this list because it names source paths and per-site literals, not because it
/// must be kept: a saved report is always regenerable by scanning again.
pub const PRIVATE_ARTIFACTS: &[&str] = &[
    ".swp/private/root.key",
    ".swp/private/manifests/",
    ".swp/private/plans/",
    ".swp/private/reports/",
];

/// The private artifacts that are also irreplaceable, which is §35's "what must
/// be backed up" answer stated once.
///
/// These two, and only these: `root.key` derives every tag every release ever
/// carried, and a manifest is the sole record of which locations a given release
/// used and what literal sat at each. Losing them does not weaken future
/// protection, it erases past protection.
///
/// A plan is not on the list because it is a working document: `swp generate`
/// rewrites it from the pre-protection source, which the operator has in version
/// control. A saved report is not on it because scanning again regenerates it.
/// Both stay private — they name paths and literals — but neither is a backup
/// obligation, and telling people to archive six things when two matter is how
/// backups stop being taken.
pub const BACKUP_ARTIFACTS: &[&str] = &[".swp/private/root.key", ".swp/private/manifests/"];

/// Classify a project-relative path. Forward or back slashes are both accepted,
/// because callers hand this whatever `walkdir` produced on the host platform.
pub fn classify(path: &str) -> ArtifactClass {
    let rel = swp_core::text::canonical_relpath(path);
    let segments: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    let Some((first, rest)) = segments.split_first() else {
        return ArtifactClass::Foreign;
    };
    if *first != SWP_DIR {
        // Anything the project owns that is not under `.swp/` is its own source.
        return if rel.is_empty() {
            ArtifactClass::Foreign
        } else {
            ArtifactClass::Source
        };
    }
    if rest.first().map(|s| *s == PRIVATE_DIR) == Some(true) {
        return ArtifactClass::Private;
    }
    if rest.first().map(|s| *s == PUBLIC_DIR) == Some(true) {
        return ArtifactClass::Public;
    }
    if rest.first().map(|s| *s == CONFIG_FILE) == Some(true) {
        return ArtifactClass::Config;
    }
    // `.swp/` itself, or a stray file inside it: not something the tool writes,
    // and certainly not something to publish.
    ArtifactClass::Private
}

/// Classify an absolute or relative path against a project root. Paths outside
/// the root are `Foreign`, which is how a scan of a third-party tree that
/// carries its own `.swp/` is described: those files are candidate *content*,
/// never this project's store.
pub fn classify_under(root: &Path, path: &Path) -> ArtifactClass {
    match path.strip_prefix(root) {
        Ok(rel) => classify(&rel.to_string_lossy().replace('\\', "/")),
        Err(_) => ArtifactClass::Foreign,
    }
}

/// What `.gitignore` must contain for the private half to stay private.
pub const GITIGNORE_NEEDLE: &str = ".swp/private/";

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use swp_identity::{IDENTITY_FILE, MANIFESTS_DIR, PLANS_DIR, RELEASES_DIR, ROOT_KEY_FILE};

    fn class(p: &str) -> ArtifactClass {
        classify(p)
    }

    #[test]
    fn the_store_layout_classifies_as_documented() {
        assert_eq!(class(".swp/config.toml"), ArtifactClass::Config);
        assert_eq!(class(".swp/public/identity.json"), ArtifactClass::Public);
        assert_eq!(
            class(".swp/public/releases/rel-a.json"),
            ArtifactClass::Public
        );
        assert_eq!(class(".swp/private/root.key"), ArtifactClass::Private);
        assert_eq!(
            class(".swp/private/manifests/rel-a.json"),
            ArtifactClass::Private
        );
        assert_eq!(
            class(".swp/private/plans/rel-a.json"),
            ArtifactClass::Private
        );
        assert_eq!(class("src/app.js"), ArtifactClass::Source);
        assert_eq!(class("README.md"), ArtifactClass::Source);
        assert_eq!(class(""), ArtifactClass::Foreign);
        // A stray file in the store root is treated as private: the tool writes
        // nothing there, so it is either a leftover or someone's experiment.
        assert_eq!(class(".swp/notes.txt"), ArtifactClass::Private);
    }

    #[test]
    fn windows_separators_and_dot_segments_do_not_confuse_it() {
        assert_eq!(class(".swp\\private\\root.key"), ArtifactClass::Private);
        assert_eq!(class("./.swp/public/identity.json"), ArtifactClass::Public);
        assert_eq!(class(".swp/./private/plans/a.json"), ArtifactClass::Private);
        // A path that escapes the project is not this project's store.
        assert_eq!(
            class("../other/.swp/private/root.key"),
            ArtifactClass::Source
        );
    }

    #[test]
    fn public_and_private_sets_are_disjoint_and_complete() {
        for p in PUBLIC_ARTIFACTS {
            assert!(
                class(p).committable(),
                "{p} is listed as public but classifies as {:?}",
                class(p)
            );
        }
        for p in PRIVATE_ARTIFACTS {
            assert_eq!(class(p), ArtifactClass::Private, "{p}");
            assert!(p.starts_with(GITIGNORE_NEEDLE));
            assert!(!class(p).committable());
            assert!(class(p).must_back_up());
        }
        let both = PUBLIC_ARTIFACTS
            .iter()
            .filter(|p| PRIVATE_ARTIFACTS.contains(p))
            .count();
        assert_eq!(both, 0);
    }

    #[test]
    fn nothing_public_is_secret_by_construction_of_the_table() {
        // The one file that can rebuild every tag lives in exactly one class.
        let key = format!("{SWP_DIR}/{PRIVATE_DIR}/{ROOT_KEY_FILE}");
        assert_eq!(class(&key), ArtifactClass::Private);
        assert!(!PUBLIC_ARTIFACTS.iter().any(|p| key.starts_with(p)));
    }

    #[test]
    fn classification_outside_the_root_is_foreign() {
        let root = PathBuf::from(if cfg!(windows) { r"C:\proj" } else { "/proj" });
        let inside = root.join(".swp").join(PRIVATE_DIR).join(ROOT_KEY_FILE);
        assert_eq!(classify_under(&root, &inside), ArtifactClass::Private);
        let outside = PathBuf::from(if cfg!(windows) { r"D:\other" } else { "/other" })
            .join(SWP_DIR)
            .join(PRIVATE_DIR)
            .join(ROOT_KEY_FILE);
        assert_eq!(classify_under(&root, &outside), ArtifactClass::Foreign);
    }

    #[test]
    fn the_directory_constants_agree_with_the_table() {
        // If swp-identity ever renames a directory, this table must not silently
        // keep classifying the old names.
        assert_eq!(
            format!("{SWP_DIR}/{PRIVATE_DIR}"),
            ".swp/private".to_string()
        );
        assert_eq!(
            format!("{SWP_DIR}/{PUBLIC_DIR}/{RELEASES_DIR}"),
            ".swp/public/releases"
        );
        assert_eq!(
            format!("{SWP_DIR}/{PUBLIC_DIR}/{IDENTITY_FILE}"),
            ".swp/public/identity.json"
        );
        assert_eq!(
            format!("{SWP_DIR}/{PRIVATE_DIR}/{MANIFESTS_DIR}"),
            ".swp/private/manifests"
        );
        assert_eq!(
            format!("{SWP_DIR}/{PRIVATE_DIR}/{PLANS_DIR}"),
            ".swp/private/plans"
        );
        assert_eq!(format!("{SWP_DIR}/{CONFIG_FILE}"), ".swp/config.toml");
    }
}
