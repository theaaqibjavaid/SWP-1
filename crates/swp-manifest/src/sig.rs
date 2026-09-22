//! The one place the signature byte-rule is written down.
//!
//! Both documents SWP-1 signs — the private manifest and the public release
//! record — are signed the same way, because they must be checkable by the same
//! three lines of code in `swp inspect`:
//!
//! ```text
//! canonical JSON of the document with "signature" removed
//!     → Ed25519
//!     → base64 in the "signature" field
//! ```
//!
//! Removing the field rather than signing a hand-written prefix matters: a signed
//! prefix that later forgets a newly added field silently un-binds that field
//! from the signature. Here a new field is covered the moment it appears in the
//! struct, and [`tests::every_field_is_covered`] proves it for the current ones.

use base64::Engine as _;
use serde::Serialize;

use swp_core::cjson;
use swp_core::error::SwpError;
use swp_crypto::{ManifestSigningKey, VerifyingKey};
use swp_identity::ReleaseRecord;

/// The field that holds the signature, and which is therefore absent from the
/// signed bytes.
pub const SIGNATURE_FIELD: &str = "signature";

/// The bytes a signature is computed over.
pub fn signing_bytes<T: Serialize>(doc: &T) -> Result<Vec<u8>, SwpError> {
    let mut value = serde_json::to_value(doc)
        .map_err(|e| SwpError::internal(format!("document is not JSON-serializable: {e}")))?;
    let Some(map) = value.as_object_mut() else {
        return Err(SwpError::internal(
            "only JSON objects can be signed; a document must not be an array or scalar",
        ));
    };
    if map.remove(SIGNATURE_FIELD).is_none() {
        return Err(SwpError::internal(format!(
            "signed document has no {SIGNATURE_FIELD} field to remove"
        )));
    }
    cjson::encode_value(&value)
}

/// Sign a document and return the base64 value for its `signature` field. The
/// caller stores it; this crate never holds a signing key.
pub fn sign_json_document<T: Serialize>(
    doc: &T,
    key: &ManifestSigningKey,
) -> Result<String, SwpError> {
    let bytes = signing_bytes(doc)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.sign(&bytes)))
}

/// Verify a document against a signature already present in it.
pub fn verify_json_document<T: Serialize>(
    doc: &T,
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), SwpError> {
    let bytes = signing_bytes(doc)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| SwpError::invalid_manifest(format!("signature is not base64: {e}")))?;
    key.verify(&bytes, &raw)
}

/// Fill in a release record's signature from the project's signing key.
pub fn sign_release_record(
    record: &mut ReleaseRecord,
    key: &ManifestSigningKey,
) -> Result<(), SwpError> {
    record.signature = sign_json_document(record, key)?;
    Ok(())
}

/// Check a release record against a project's public verification key.
///
/// The record is what `swp inspect release` prints and what a report names as the
/// release that was found, so every field in it is a claim. The cross-checks in
/// `swp-detection` cover the four the detector compares against the private
/// manifest; this covers the rest, and covers them against the same key that
/// signed the manifest, which is what makes the two agree rather than merely
/// fail to contradict each other.
pub fn verify_release_record(record: &ReleaseRecord, key: &VerifyingKey) -> Result<(), SwpError> {
    if record.signature.is_empty() {
        return Err(SwpError::invalid_manifest("release record is unsigned"));
    }
    verify_json_document(record, &record.signature, key)
        .map_err(|e| SwpError::new(e.code(), format!("release record: {}", e.message())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_crypto::RootSecret;
    use swp_identity::{ProjectIdentity, Timestamp};

    fn root() -> RootSecret {
        RootSecret::from_bytes(&[0x33u8; 32]).unwrap()
    }

    fn signing_key() -> ManifestSigningKey {
        ManifestSigningKey::from_root(&root(), "swp1-abcdefghijklmnop").unwrap()
    }

    fn record() -> ReleaseRecord {
        ReleaseRecord {
            protocol: swp_core::SWP_PROTOCOL_NAME.to_string(),
            schema: swp_core::SchemaVersion::MANIFEST_V1.0,
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaa").unwrap(),
            created_at: Timestamp::from_unix(1_700_000_000),
            source_revision: swp_identity::SourceRevision::Content,
            fingerprint: swp_core::Digest([7u8; 32]),
            fingerprint_level: "L1".to_string(),
            private_manifest_digest: swp_core::Digest([8u8; 32]),
            watermark: swp_identity::WatermarkParams {
                target_sites: 16,
                tag_bits: 4,
                sites_embedded: 12,
                sites_skipped: 3,
                canonicalizer_version: 1,
                form_set: "add,radix".to_string(),
                adapters: vec![],
            },
            generator: swp_core::GeneratorInfo::current(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_signed_record_round_trips() {
        let mut rec = record();
        sign_release_record(&mut rec, &signing_key()).unwrap();
        assert!(!rec.signature.is_empty());
        let vk = signing_key().verifying_key();
        assert!(verify_release_record(&rec, &vk).is_ok());
    }

    #[test]
    fn any_field_change_breaks_the_signature() {
        let mut rec = record();
        sign_release_record(&mut rec, &signing_key()).unwrap();
        let vk = signing_key().verifying_key();

        rec.watermark.sites_embedded += 1;
        assert!(verify_release_record(&rec, &vk).is_err());
        rec.watermark.sites_embedded -= 1;
        assert!(verify_release_record(&rec, &vk).is_ok());

        rec.fingerprint = swp_core::Digest([9u8; 32]);
        assert!(verify_release_record(&rec, &vk).is_err());
    }

    /// Every field of a signed document must reach the signed bytes. The way a
    /// document grows is by adding a struct field, and a field that is not in
    /// the encoding is a field an attacker can rewrite for free.
    #[test]
    fn every_field_is_covered() {
        let rec = record();
        let bytes = signing_bytes(&rec).unwrap();
        let full = serde_json::to_value(&rec).unwrap();
        let touched = serde_json::from_slice::<Value>(&bytes).unwrap();
        let map = touched.as_object().unwrap();
        assert_eq!(map.len(), full.as_object().unwrap().len() - 1);
        assert!(!map.contains_key(SIGNATURE_FIELD));
        for key in full.as_object().unwrap().keys() {
            if key == SIGNATURE_FIELD {
                assert!(!map.contains_key(key), "signature must be absent");
                continue;
            }
            assert!(
                map.contains_key(key),
                "field {key} is not covered by the signature"
            );
            assert_eq!(map[key], full[key], "field {key} was altered");
        }
    }

    #[test]
    fn signing_is_deterministic_over_equal_documents() {
        let a = record();
        let mut b = record();
        b.generator = a.generator.clone();
        assert_eq!(signing_bytes(&a).unwrap(), signing_bytes(&b).unwrap());
    }

    #[test]
    fn a_non_object_or_a_missing_signature_field_is_an_internal_error() {
        assert!(signing_bytes(&[1u8, 2, 3]).is_err());
        // ProjectIdentity is unsigned by design and has no `signature` field, so
        // signing it would silently mean "sign every byte", a different rule.
        let id = ProjectIdentity::new(&root(), Timestamp::from_unix(1), "demo").unwrap();
        let e = signing_bytes(&id).unwrap_err();
        assert!(e.message().contains("signature"));
    }
}
