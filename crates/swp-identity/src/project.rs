//! The project identity document — the thing that makes two protected copies
//! of the same file belong to the same project.

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ProjectId;
use swp_core::version::{CanonicalizerVersion, GeneratorInfo, ProtocolVersion, SWP_PROTOCOL_NAME};
use swp_core::SchemaVersion;
use swp_crypto::{project_id_from_root, ManifestSigningKey, PublicKeys, RootSecret, VerifyingKey};

/// Derive the project identifier from the root secret.
///
/// Re-exported from `swp-crypto`, where the implementation has to live: minting
/// an id is the one operation that reads raw bytes out of a derived key, and
/// those bytes are confined to that crate.
pub fn make_project_id(root: &RootSecret) -> Result<ProjectId, SwpError> {
    project_id_from_root(root)
}

use crate::timestamp::Timestamp;

/// The public half of a project's identity. Written to
/// `.swp/public/identity.json` and safe to commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectIdentity {
    pub protocol: String,
    pub schema: u16,
    pub project_id: ProjectId,
    pub created_at: Timestamp,
    /// Ed25519 verify key. Signatures on releases and manifests check against
    /// this. Public by design; distributing it is the point.
    pub verification: PublicKeys,
    /// Canonicalizer rules this project's locations were hashed under. A scan
    /// that loads a manifest under a different value refuses rather than
    /// reporting "no evidence".
    pub canonicalizer_version: u16,
    pub generator: GeneratorInfo,
    /// Free-form label the owner chose at init. Never hashed, never trusted by
    /// the detector, purely for the report header.
    pub display_name: String,
}

impl ProjectIdentity {
    pub fn new(
        root: &RootSecret,
        created_at: Timestamp,
        display_name: impl Into<String>,
    ) -> Result<Self, SwpError> {
        let project_id = project_id_from_root(root)?;
        let signing = ManifestSigningKey::from_root(root, project_id.as_str())?;
        Ok(ProjectIdentity {
            protocol: SWP_PROTOCOL_NAME.to_string(),
            schema: SchemaVersion::IDENTITY_V1.0,
            project_id,
            created_at,
            verification: signing.verifying_key().to_public_keys(),
            canonicalizer_version: CanonicalizerVersion::V1.0,
            generator: GeneratorInfo::current(),
            display_name: display_name.into(),
        })
    }

    pub fn protocol_version(&self) -> Result<ProtocolVersion, SwpError> {
        // `SWP-1` carries the version in its name; parse the suffix rather than
        // keeping a second copy that could disagree with the first.
        let n = self.protocol.strip_prefix("SWP-").ok_or_else(|| {
            SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("unrecognized protocol name {:?}", self.protocol),
            )
        })?;
        n.parse::<ProtocolVersion>()
    }

    pub fn verify_key(&self) -> Result<VerifyingKey, SwpError> {
        VerifyingKey::from_public_keys(&self.verification)
    }

    /// Reject a document this build cannot interpret. Called before anything
    /// trusts a field.
    pub fn validate(&self) -> Result<(), SwpError> {
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "identity is for protocol {:?}, this build speaks {SWP_PROTOCOL_NAME:?}",
                    self.protocol
                ),
            ));
        }
        if self.schema != SchemaVersion::IDENTITY_V1.0 {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("identity schema {} is not supported", self.schema),
            ));
        }
        if self.canonicalizer_version != CanonicalizerVersion::V1.0 {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "identity was protected under canonicalizer v{}, this build is v{}",
                    self.canonicalizer_version,
                    CanonicalizerVersion::V1.0
                ),
            ));
        }
        if self.verification.algorithm != "ed25519" {
            return Err(SwpError::invalid_manifest(format!(
                "unknown verification key algorithm {:?}",
                self.verification.algorithm
            )));
        }
        self.verify_key()?;
        // A display name lands in report headers and terminal output. Control
        // characters there would let a cloned project's name spoof a line of the
        // report, and an over-long one breaks table rendering.
        if self.display_name.chars().any(|c| c.is_control()) || self.display_name.len() > 200 {
            return Err(SwpError::invalid_manifest(
                "display name must be short and free of control characters",
            ));
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s =
            serde_json::to_string_pretty(self).expect("identity is serializable by construction");
        s.push('\n');
        s.into_bytes()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("identity file is not valid UTF-8"))?;
        let doc: ProjectIdentity = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("identity file: {e}")))?;
        doc.validate()?;
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::hex_encode;
    use swp_crypto::RootSecret;

    fn root(b: u8) -> RootSecret {
        RootSecret::from_bytes(&[b; 32]).unwrap()
    }

    fn doc() -> ProjectIdentity {
        ProjectIdentity::new(&root(0x33), Timestamp::now_utc(), "Demo").unwrap()
    }

    #[test]
    fn identity_round_trips_through_json() {
        let d = doc();
        let bytes = d.to_json_bytes();
        let back = ProjectIdentity::from_json_bytes(&bytes).unwrap();
        assert_eq!(d, back);
        assert_eq!(back.project_id, d.project_id);
        assert_eq!(d.protocol_version().unwrap(), ProtocolVersion::V1);
    }

    #[test]
    fn identity_never_contains_key_material() {
        let key = [0x41u8; 32];
        let r = RootSecret::from_bytes(&key).unwrap();
        let text = String::from_utf8(
            ProjectIdentity::new(&r, Timestamp::now_utc(), "k")
                .unwrap()
                .to_json_bytes(),
        )
        .unwrap();
        assert!(!text.contains(&hex_encode(&key)), "raw key hex in identity");
        assert!(
            !text.contains(String::from_utf8_lossy(&key).as_ref()),
            "raw key bytes in identity"
        );
    }

    #[test]
    fn two_projects_get_two_ids() {
        let a = ProjectIdentity::new(&root(1), Timestamp::now_utc(), "a").unwrap();
        let b = ProjectIdentity::new(&root(2), Timestamp::now_utc(), "b").unwrap();
        assert_ne!(a.project_id, b.project_id);
        assert_ne!(a.verification, b.verification);
    }

    #[test]
    fn a_foreign_version_is_refused_not_ignored() {
        let mut d = doc();
        d.protocol = "SWP-2".into();
        assert!(d.validate().is_err());
        let mut d = doc();
        d.canonicalizer_version = 99;
        assert_eq!(
            d.validate().unwrap_err().code(),
            ErrorCode::ProtocolVersionUnsupported
        );
        let mut d = doc();
        d.verification.algorithm = "rsa".into();
        assert!(d.validate().is_err());
        let mut d = doc();
        d.schema = 7;
        assert!(d.validate().is_err());
        let mut d = doc();
        d.display_name = "bad\nname".into();
        assert!(d.validate().is_err());
    }

    #[test]
    fn signing_key_matches_the_published_verify_key() {
        let r = root(0x55);
        let d = ProjectIdentity::new(&r, Timestamp::now_utc(), "s").unwrap();
        let sk = ManifestSigningKey::from_root(&r, d.project_id.as_str()).unwrap();
        assert_eq!(sk.verifying_key().to_public_keys(), d.verification);
        let msg = br#"{"a":1}"#;
        assert!(d.verify_key().unwrap().verify(msg, &sk.sign(msg)).is_ok());
        assert!(d.verify_key().unwrap().verify(msg, &[0u8; 64]).is_err());
    }
}
