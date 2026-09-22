//! The exact fingerprint of §16: a hash of the whole protected tree, taken over
//! its canonical representation.
//!
//! ```text
//! every source file → adapter canonicalization at level L → per-file digest
//!                                                      ↓
//!                       sorted (path, digest) list, length-prefixed
//!                                                      ↓
//!                                              SHA-256 = release fingerprint
//! ```
//!
//! Three properties make this useful rather than decorative:
//!
//! * **Unkeyed on purpose.** It appears in a *public* signed release record, and
//!   anyone must be able to recompute it from a copy of the tree to check that
//!   copy. Keying it would make it a second watermark and destroy its use.
//! * **Order-insensitive, content-sensitive.** Listing files in any order gives
//!   the same answer, because the list is sorted by path before hashing; adding,
//!   removing, renaming or editing a file changes it.
//! * **Level-declared, not level-assumed.** The level the digests were taken at
//!   is inside the hash input, so an L1 fingerprint can never be quietly
//!   compared against an L3 one. The release record carries the same string for
//!   exactly this reason.
//!
//! This is *not* the resilient watermark (§17): reformatting an L1 fingerprint
//! survives, renaming does not, and one edited file changes the whole value. A
//! refactored derivative matches the constellation and the structural channel,
//! not this.

use sha2::{Digest as _, Sha256};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::Digest;
use swp_core::version::SWP_PROTOCOL_NAME;

/// The label inside the hash input that says what the bytes below it are.
const FINGERPRINT_LABEL: &[u8] = b"fingerprint";

/// The levels a fingerprint may be taken at. `L1` is the default: it is the only
/// level that is stable under formatting *and* computable for every language,
/// including the lexical fallback, so a whole-tree hash of it always exists.
pub const LEVELS: [&str; 3] = ["L1", "L2", "L3"];

/// One file's contribution: its canonical path and the digest of its canonical
/// text. Callers get `digest` from `swp_core::canon::canonicalize(...).digest()`
/// and `path` from `swp_core::text::canonical_relpath`, so this module stays
/// free of both language knowledge and filesystem access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCanonical {
    pub path: String,
    pub digest: Digest,
}

impl FileCanonical {
    pub fn new(path: impl Into<String>, digest: Digest) -> Self {
        FileCanonical {
            path: path.into(),
            digest,
        }
    }
}

/// The bytes a fingerprint is the hash of. Exposed so `swp inspect` can show an
/// owner *what* was hashed instead of asking them to trust a 64-character value.
pub fn fingerprint_bytes(
    level: &str,
    canonicalizer_version: u16,
    files: &[FileCanonical],
) -> Result<Vec<u8>, SwpError> {
    if !LEVELS.contains(&level) {
        return Err(SwpError::invalid_manifest(format!(
            "fingerprint level {level:?} is not one of {LEVELS:?}"
        )));
    }
    let mut sorted: Vec<&FileCanonical> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(pair) = sorted.windows(2).find(|w| w[0].path == w[1].path) {
        return Err(SwpError::new(
            ErrorCode::Internal,
            format!("the project representation lists {:?} twice", pair[0].path),
        ));
    }

    let mut out = Vec::new();
    out.extend_from_slice(SWP_PROTOCOL_NAME.as_bytes());
    out.push(0x00);
    out.extend_from_slice(FINGERPRINT_LABEL);
    out.push(0x00);
    out.extend_from_slice(&canonicalizer_version.to_be_bytes());
    push_bytes(&mut out, level.as_bytes());
    push_bytes(&mut out, &sorted.len().to_be_bytes());
    for f in sorted {
        push_bytes(&mut out, f.path.as_bytes());
        out.extend_from_slice(f.digest.as_bytes());
    }
    Ok(out)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// SHA-256 over [`fingerprint_bytes`].
pub fn project_fingerprint(
    level: &str,
    canonicalizer_version: u16,
    files: &[FileCanonical],
) -> Result<Digest, SwpError> {
    let bytes = fingerprint_bytes(level, canonicalizer_version, files)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(Digest(h.finalize().into()))
}

/// SHA-256 of arbitrary bytes, for the manifest digest a release record binds.
pub fn sha256(bytes: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(bytes);
    Digest(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::hex_encode;

    fn file(path: &str, b: u8) -> FileCanonical {
        FileCanonical::new(path, Digest([b; 32]))
    }

    const V: u16 = 1;

    #[test]
    fn file_order_does_not_change_the_fingerprint() {
        let a = project_fingerprint("L1", V, &[file("src/a.js", 1), file("src/b.js", 2)]).unwrap();
        let b = project_fingerprint("L1", V, &[file("src/b.js", 2), file("src/a.js", 1)]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn any_edit_to_the_tree_changes_it() {
        let base =
            project_fingerprint("L1", V, &[file("src/a.js", 1), file("src/b.js", 2)]).unwrap();
        let edited =
            project_fingerprint("L1", V, &[file("src/a.js", 9), file("src/b.js", 2)]).unwrap();
        let added = project_fingerprint(
            "L1",
            V,
            &[
                file("src/a.js", 1),
                file("src/b.js", 2),
                file("src/c.js", 3),
            ],
        )
        .unwrap();
        let removed = project_fingerprint("L1", V, &[file("src/a.js", 1)]).unwrap();
        let renamed =
            project_fingerprint("L1", V, &[file("src/other.js", 1), file("src/b.js", 2)]).unwrap();
        for other in [edited, added, removed, renamed] {
            assert_ne!(base, other);
        }
    }

    /// Length prefixes are what make the encoding injective: without them,
    /// `["ab","c"]` and `["a","bc"]` would hash the same, and a path could
    /// swallow a digest.
    #[test]
    fn the_encoding_is_injective_across_field_boundaries() {
        let mut seen = std::collections::BTreeMap::new();
        let cases: Vec<Vec<FileCanonical>> = vec![
            vec![file("ab", 1), file("c", 2)],
            vec![file("a", 1), file("bc", 2)],
            vec![file("abc", 1)],
            vec![file("", 1)],
            vec![file("ab", 1), file("c", 3)],
        ];
        for case in &cases {
            let bytes = fingerprint_bytes("L1", V, case).unwrap();
            if let Some(prev) = seen.insert(bytes, format!("{case:?}")) {
                panic!("fingerprint encoding collided: {prev} vs {case:?}");
            }
        }
        assert_eq!(seen.len(), cases.len());
    }

    #[test]
    fn level_and_canonicalizer_version_are_part_of_the_hash() {
        let files = [file("a.js", 1)];
        let l1 = project_fingerprint("L1", V, &files).unwrap();
        let l2 = project_fingerprint("L2", V, &files).unwrap();
        let l3 = project_fingerprint("L3", V, &files).unwrap();
        let v2 = project_fingerprint("L1", 2, &files).unwrap();
        assert_ne!(l1, l2);
        assert_ne!(l2, l3);
        assert_ne!(l1, v2);
        assert!(project_fingerprint("L9", V, &files).is_err());
        assert!(project_fingerprint("l1", V, &files).is_err());
    }

    #[test]
    fn duplicate_paths_are_refused_not_merged() {
        let e =
            project_fingerprint("L1", V, &[file("src/a.js", 1), file("src/a.js", 2)]).unwrap_err();
        assert!(e.message().contains("twice"));
    }

    #[test]
    fn an_empty_tree_still_has_a_well_defined_fingerprint() {
        // Recording "this release protected nothing" needs a value, and it must
        // not collide with any non-empty tree's.
        let empty = project_fingerprint("L1", V, &[]).unwrap();
        assert_eq!(empty, project_fingerprint("L1", V, &[]).unwrap());
        assert_ne!(
            empty,
            project_fingerprint("L1", V, &[file("a", 1)]).unwrap()
        );
    }

    #[test]
    fn fingerprint_is_sha256_of_the_stated_bytes() {
        let files = [file("src/a.js", 1)];
        let bytes = fingerprint_bytes("L1", V, &files).unwrap();
        assert_eq!(
            project_fingerprint("L1", V, &files).unwrap(),
            sha256(&bytes)
        );
        assert_eq!(sha256(b"").hex().len(), 64);
        // The published label opens the encoding, so an auditor can reproduce it.
        assert!(bytes.starts_with(b"SWP-1\0fingerprint\0"));
        assert_eq!(hex_encode(&[0xab]), "ab");
    }
}
