//! SWP-1 manifests: the private record of what was embedded where, the public
//! fingerprint of the release it was embedded into, and the derivations that
//! connect the two.
//!
//! Four rules shape this crate, and all four are security properties:
//!
//! 1. **The expected tag is never stored.** A manifest lists *where* the
//!    watermark sits and *which radius key* identifies it; the value each site
//!    must carry is recomputed from the root secret at verification time
//!    (§8: `F = HMAC(project_key, location)`). Storing the codes would turn the
//!    manifest into a copy of the watermark, so that stealing one file and
//!    reading it would be enough to forge or strip every site. Nothing in a
//!    manifest, plan, report or release record is a tag.
//! 2. **Site identity is release-independent, tags follow it.** A location id is
//!    derived from the project and the canonical text of the site, never from
//!    the release, so re-protecting a project keeps the same code at an
//!    unchanged site and each new release *adds* coverage instead of churning
//!    the existing one. Which release a copy came from is the fingerprint's and
//!    the release record's job (§19), not the tag's.
//! 3. **Nothing here is keyed by a path.** Location ids deliberately exclude the
//!    file name: renaming or copying a source file keeps its sites. The `file`
//!    and `line_hint` fields exist for human reports only, and the detector is
//!    documented — and tested — never to read them.
//! 4. **Both halves of every document are signed with the same bytes rule.**
//!    Canonical JSON of the document with the `signature` field removed, Ed25519
//!    over those bytes, base64 in the field. [`sig::signing_bytes`] is the only
//!    place that rule is expressed, which is why the private manifest and the
//!    public release record cannot drift apart.

pub mod classify;
pub mod fingerprint;
pub mod keys;
pub mod private;
pub mod sig;

pub use classify::{
    classify, ArtifactClass, PRIVATE_ARTIFACTS, PUBLIC_ARTIFACTS, BACKUP_ARTIFACTS,
};
pub use fingerprint::{fingerprint_bytes, project_fingerprint, sha256, FileCanonical, LEVELS};
pub use keys::{ManifestKeys, SLOTS};
pub use private::{PrivateManifest, SiteEntry, MAX_HINT_LEN};
pub use sig::{sign_json_document, signing_bytes, verify_json_document};
