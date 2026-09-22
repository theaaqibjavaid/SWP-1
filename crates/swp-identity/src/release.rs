//! The release record — what was protected, when, and under what settings.
//!
//! One per `swp protect`, written to `.swp/public/releases/<id>.json` and
//! signed. This is the artifact that lets an owner answer "which protected
//! build was this copy taken from?" months later, after the working tree has
//! moved on. §19 of the brief requires it to be preservable independently of the
//! private manifest, so it carries no site data at all.

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{base32_lower, Digest, ProjectId, ReleaseId};
use swp_core::version::{GeneratorInfo, SWP_PROTOCOL_NAME};
use swp_core::SchemaVersion;

use crate::timestamp::Timestamp;

/// Bytes of CSPRNG output behind a fresh release id. Eight gives 64 bits, which
/// is 4 billion pairs before the birthday bound — far past any project's release
/// count, and the store refuses to overwrite an existing release anyway.
const RELEASE_ID_BYTES: usize = 8;

/// Mint a release id for a run that is about to happen.
///
/// Random rather than derived from the tree, because two protects of the same
/// tree *should* be different releases: that is what makes "which build was this
/// copy taken from?" an answerable question. The id is not secret and carries no
/// meaning; it is a label, and everything keyed mixes it in only for *selection*,
/// never for site identity.
pub fn new_release_id() -> Result<ReleaseId, SwpError> {
    let bytes = swp_crypto::random_array::<RELEASE_ID_BYTES>()?;
    ReleaseId::new(format!("rel-{}", base32_lower(&bytes)))
}

/// How the source revision was identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRevision {
    /// A git commit hash, recorded because it is useful to a human reading the
    /// report. Never trusted by the detector: an attacker can write any value
    /// here, and a copy that was `git init`-ed again will not match.
    Git { commit: String },
    /// Content-only, when the project is not under git or git was unavailable.
    Content,
    /// Supplied by the operator with `--revision`.
    Manual { value: String },
}

impl SourceRevision {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SourceRevision::Git { commit } => Some(commit),
            SourceRevision::Manual { value } => Some(value),
            SourceRevision::Content => None,
        }
    }

    /// A revision string is display metadata, never a hash input, so it is
    /// bounded and control-character-free rather than parsed.
    pub fn validate(&self) -> Result<(), SwpError> {
        if let Some(s) = self.as_str() {
            if s.is_empty() || s.len() > 200 || s.chars().any(|c| c.is_control()) {
                return Err(SwpError::invalid_manifest("source revision is not usable"));
            }
        }
        Ok(())
    }
}

/// The watermark parameters a release used. Recorded publicly so a later scan
/// can tell *why* an old release behaves differently, without revealing a
/// single location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkParams {
    pub target_sites: u32,
    pub tag_bits: u8,
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    pub canonicalizer_version: u16,
    /// Which transformation families were permitted. A digest of the sorted,
    /// deduplicated family names — the names themselves are protocol constants
    /// and publishing them costs nothing, but the digest keeps the record fixed
    /// size if the family set ever grows.
    pub form_set: String,
    /// Languages that had an AST adapter versus fell back to the lexical one.
    pub adapters: Vec<AdapterUse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterUse {
    pub language: String,
    pub mode: String,
    pub files: u32,
}

/// A signed, public record of one protected release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    pub protocol: String,
    pub schema: u16,
    pub project_id: ProjectId,
    pub release_id: ReleaseId,
    pub created_at: Timestamp,
    pub source_revision: SourceRevision,
    /// `SHA-256` over the L1 canonical representation of the whole protected
    /// tree. An exact copy of this release reproduces it; refactoring does not.
    pub fingerprint: Digest,
    /// Level the fingerprint was taken at, so a future L3 fingerprint cannot be
    /// silently compared against an L1 one.
    pub fingerprint_level: String,
    /// Digest of the *private* manifest bytes, so the owner can confirm a
    /// restored backup is the manifest this release was shipped with, and so
    /// `swp verify` can say the public record and the private one agree.
    ///
    /// Publishing it is safe because a digest is one-way; it is not safe in the
    /// sense of "reveals nothing about the manifest", because the manifest lists
    /// this project's file paths and the literal text at each site, and an
    /// attacker who already has a candidate tree can test a guessed manifest
    /// against this digest in one hash. The manifest's confidentiality comes
    /// from `.swp/private/` being ACLed and gitignored, not from its contents
    /// being keyed.
    pub private_manifest_digest: Digest,
    pub watermark: WatermarkParams,
    pub generator: GeneratorInfo,
    /// Ed25519 signature over the canonical JSON encoding of this document with
    /// `signature` removed, base64. Filled in by `swp-manifest`.
    pub signature: String,
}

impl ReleaseRecord {
    pub fn validate(&self) -> Result<(), SwpError> {
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("release record declares protocol {:?}", self.protocol),
            ));
        }
        if self.schema != SchemaVersion::MANIFEST_V1.0 {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("release record schema {} is not supported", self.schema),
            ));
        }
        self.source_revision.validate()?;
        if self.fingerprint_level != "L1" && self.fingerprint_level != "L2" {
            return Err(SwpError::invalid_manifest(format!(
                "unknown fingerprint canonicalization level {:?}",
                self.fingerprint_level
            )));
        }
        if self.watermark.tag_bits == 0 || self.watermark.tag_bits > 8 {
            return Err(SwpError::invalid_manifest(
                "recorded tag width is out of range",
            ));
        }
        if self.watermark.sites_embedded == 0 {
            // A release with no embedded sites proves nothing; recording it as a
            // protected release would let `verify` pass on an unprotected tree.
            return Err(SwpError::new(
                ErrorCode::NoSafeLocations,
                "this release embedded zero watermark sites, so it is not protected",
            ));
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s =
            serde_json::to_string_pretty(self).expect("release record is serializable by shape");
        s.push('\n');
        s.into_bytes()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("release record is not valid UTF-8"))?;
        let rec: ReleaseRecord = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("release record: {e}")))?;
        rec.validate()?;
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::Digest;

    fn record() -> ReleaseRecord {
        ReleaseRecord {
            protocol: SWP_PROTOCOL_NAME.into(),
            schema: SchemaVersion::MANIFEST_V1.0,
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            created_at: Timestamp::parse("2026-09-21T14:03:22Z").unwrap(),
            source_revision: SourceRevision::Git {
                commit: "b".repeat(40),
            },
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
                adapters: vec![AdapterUse {
                    language: "javascript".into(),
                    mode: "ast".into(),
                    files: 9,
                }],
            },
            generator: GeneratorInfo::current(),
            signature: "AAA=".into(),
        }
    }

    #[test]
    fn record_round_trips_and_keeps_a_stable_shape() {
        let r = record();
        let bytes = r.to_json_bytes();
        let back = ReleaseRecord::from_json_bytes(&bytes).unwrap();
        assert_eq!(r, back);
        // Re-serializing a parsed record must be byte-identical, or a signature
        // over the original bytes would not survive a read/rewrite cycle.
        assert_eq!(bytes, back.to_json_bytes());
    }

    #[test]
    fn a_release_with_no_embedded_sites_is_not_a_release() {
        let mut r = record();
        r.watermark.sites_embedded = 0;
        assert_eq!(r.validate().unwrap_err().code(), ErrorCode::NoSafeLocations);
    }

    #[test]
    fn bad_revision_strings_are_rejected() {
        let mut r = record();
        r.source_revision = SourceRevision::Manual {
            value: "ok\nsecond line".into(),
        };
        assert!(r.validate().is_err());
        let mut r = record();
        r.source_revision = SourceRevision::Manual {
            value: String::new(),
        };
        assert!(r.validate().is_err());
        assert_eq!(SourceRevision::Content.as_str(), None);
    }

    #[test]
    fn unknown_fields_in_a_record_are_refused() {
        let text = String::from_utf8(record().to_json_bytes()).unwrap();
        let hacked = text.replace("\"signature\"", "\"sigature\": \"x\", \"signature\"");
        assert!(ReleaseRecord::from_json_bytes(hacked.as_bytes()).is_err());
    }

    #[test]
    fn a_minted_release_id_is_valid_distinct_and_short() {
        let a = new_release_id().unwrap();
        let b = new_release_id().unwrap();
        assert_ne!(a, b, "two mints drew the same 64-bit id");
        assert!(a.as_str().starts_with("rel-"));
        // 8 bytes is 13 unpadded base32 characters, inside ReleaseId's 32-char cap.
        assert!(a.as_str().len() <= 36, "{a}");
        assert_eq!(ReleaseId::new(a.as_str()).unwrap(), a);
    }
}
