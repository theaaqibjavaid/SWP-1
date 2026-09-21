//! Ed25519 manifest signatures.
//!
//! The signing key is *derived from the root secret* rather than stored
//! separately, so a project owner backs up exactly one secret and compromising
//! one key purpose does not hand over the other. Verification needs only the
//! public key, which travels in the public identity file.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey as DalekVerifyingKey};
use zeroize::Zeroizing;

use swp_core::error::{ErrorCode, SwpError};

use crate::secret::PublicKeys;

/// A signing key. Only constructible from a 32-byte seed.
pub struct ManifestSigningKey {
    inner: SigningKey,
}

impl ManifestSigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        ManifestSigningKey {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// Build the signing key for a project from its root secret.
    pub fn from_root(root: &crate::secret::RootSecret, project_id: &str) -> Result<Self, SwpError> {
        let key = crate::derive::derive_key(
            root,
            crate::derive::Domain::Signing,
            &[project_id.as_bytes()],
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(key.as_slice());
        Ok(Self::from_seed(&seed))
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        // Deterministic per RFC 8032: ed25519-dalek's signing uses a
        // nonce derived from key+message, so the same canonical bytes always
        // produce the same signature and release records stay diffable.
        use ed25519_dalek::Signer;
        self.inner.sign(message).to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.inner.verifying_key().to_bytes())
    }
}

/// The public half. Distributable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyingKey(pub [u8; 32]);

impl VerifyingKey {
    pub fn from_bytes(b: [u8; 32]) -> Result<Self, SwpError> {
        // Reject non-canonical public keys at construction: a malformed point
        // must not survive to verification time.
        DalekVerifyingKey::from_bytes(&b)
            .map_err(|e| SwpError::invalid_manifest(format!("invalid ed25519 verify key: {e}")))?;
        Ok(VerifyingKey(b))
    }

    pub fn from_public_keys(p: &PublicKeys) -> Result<Self, SwpError> {
        Self::from_bytes(p.verify_key_bytes()?)
    }

    pub fn to_public_keys(self) -> PublicKeys {
        PublicKeys::new(&self.0)
    }

    /// Strict verification: cofactor elimination and correct point validation,
    /// which closes the signature-malleability footgun that the lenient
    /// `verify` path leaves open.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SwpError> {
        if signature.len() != 64 {
            return Err(SwpError::new(
                ErrorCode::InvalidManifest,
                format!("expected a 64-byte signature, found {}", signature.len()),
            ));
        }
        let mut raw = [0u8; 64];
        raw.copy_from_slice(signature);
        let sig = Signature::from_bytes(&raw);
        let vk = DalekVerifyingKey::from_bytes(&self.0)
            .map_err(|e| SwpError::invalid_manifest(format!("invalid ed25519 verify key: {e}")))?;
        vk.verify_strict(message, &sig)
            .map_err(|_| SwpError::invalid_manifest("manifest signature does not verify"))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Zeroize a seed after use.
pub fn seed_from_key(key: &crate::secret::DerivedKey) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(key.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::RootSecret;

    #[test]
    fn signatures_verify_and_tampering_is_caught() {
        let root = RootSecret::from_bytes(&[0x22u8; 32]).unwrap();
        let sk = ManifestSigningKey::from_root(&root, "swp1-abcdefghijklmnop").unwrap();
        let vk = sk.verifying_key();
        let msg = br#"{"protocol":"SWP-1","release":"rel-a"}"#;
        let sig = sk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());

        let mut tampered = msg.to_vec();
        tampered[0] = b'X';
        assert!(vk.verify(&tampered, &sig).is_err());

        let mut bad_sig = sig;
        bad_sig[63] ^= 1;
        assert!(vk.verify(msg, &bad_sig).is_err());
        assert!(vk.verify(msg, &sig[..32]).is_err());
    }

    #[test]
    fn signing_is_deterministic_over_identical_bytes() {
        let root = RootSecret::from_bytes(&[0x22u8; 32]).unwrap();
        let sk = ManifestSigningKey::from_root(&root, "swp1-abcdefghijklmnop").unwrap();
        assert_eq!(sk.sign(b"same"), sk.sign(b"same"));
    }

    #[test]
    fn different_projects_get_different_signing_keys() {
        let root = RootSecret::from_bytes(&[0x22u8; 32]).unwrap();
        let a = ManifestSigningKey::from_root(&root, "swp1-aaaaaaaaaaaaaaaa").unwrap();
        let b = ManifestSigningKey::from_root(&root, "swp1-bbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(a.verifying_key(), b.verifying_key());
        let msg = b"shared manifest bytes";
        assert!(b.verifying_key().verify(msg, &a.sign(msg)).is_err());
    }

    #[test]
    fn verify_key_round_trips_through_the_public_document() {
        let root = RootSecret::from_bytes(&[0x22u8; 32]).unwrap();
        let vk = ManifestSigningKey::from_root(&root, "swp1-abcdefghijklmnop")
            .unwrap()
            .verifying_key();
        let doc = vk.to_public_keys();
        assert_eq!(doc.algorithm, "ed25519");
        assert_eq!(VerifyingKey::from_public_keys(&doc).unwrap(), vk);
    }
}
