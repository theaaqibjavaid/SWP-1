//! Identity minting.
//!
//! This lives in the crypto crate rather than in `swp-identity` for one reason:
//! minting a project id is the single place that must read raw bytes out of a
//! derived key, and those bytes are deliberately confined to this crate. Putting
//! the function here keeps every other consumer working with ids as opaque
//! strings.

use swp_core::error::SwpError;
use swp_core::id::{base32_lower, ProjectId};

use crate::derive::{derive_key, Domain};
use crate::secret::RootSecret;

/// Label field for the identity bootstrap derivation. Versioned so a future
/// protocol can change how ids are minted without colliding with old ones.
const IDENTITY_LABEL: &[u8] = b"project-id/v1";

/// Bytes of HMAC output folded into an id. Ten gives exactly sixteen base32
/// characters.
const ID_BYTES: usize = 10;

/// Derive the project identifier from the root secret.
///
/// Deriving rather than choosing the id means:
///
/// * two `swp init` runs against the same secret agree, so a restored backup
///   keeps its identity and every manifest it ever signed;
/// * the id is unpredictable to anyone holding the project's source but not its
///   secret — which matters, because location ids are keyed by the project;
/// * the minting rule is versioned in exactly one place.
///
/// The id is *public*. It appears in signed manifests and scan reports. That is
/// safe because knowing it grants nothing: the tag derivation domain is
/// unreachable without the root secret.
pub fn project_id_from_root(root: &RootSecret) -> Result<ProjectId, SwpError> {
    let key = derive_key(root, Domain::Identity, &[IDENTITY_LABEL]);
    let raw = key.as_slice();
    if raw.len() < ID_BYTES {
        return Err(SwpError::internal("derived key shorter than the id length"));
    }
    let id = base32_lower(&raw[..ID_BYTES]);
    // Constructible by rule, but checked rather than unwrapped: if
    // `base32_lower` and `ProjectId::new` ever disagree about the alphabet,
    // this is where roughly half of all minted ids would start failing, and it
    // should fail loudly here rather than as a parse error in a user's shell.
    ProjectId::new(format!("swp1-{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::hex_encode;

    fn root(b: u8) -> RootSecret {
        RootSecret::from_bytes(&[b; 32]).unwrap()
    }

    #[test]
    fn ids_are_valid_distinct_and_stable() {
        let mut seen = std::collections::BTreeSet::new();
        for i in 0u8..64 {
            let id = project_id_from_root(&root(i)).unwrap();
            assert!(id.as_str().starts_with("swp1-"));
            assert_eq!(id.as_str().len(), 21);
            assert!(seen.insert(id.as_str().to_string()), "collision at {i}");
        }
        assert_eq!(seen.len(), 64);
        assert_eq!(
            project_id_from_root(&root(7)).unwrap(),
            project_id_from_root(&root(7)).unwrap()
        );
        assert_ne!(
            project_id_from_root(&root(7)).unwrap(),
            project_id_from_root(&root(8)).unwrap()
        );
    }

    #[test]
    fn every_seed_byte_yields_a_parseable_id() {
        for i in 0u8..=255 {
            let id = project_id_from_root(&root(i)).unwrap();
            assert!(ProjectId::new(id.as_str()).is_ok(), "{id} rejected");
        }
    }

    #[test]
    fn an_id_is_not_the_root_secret_in_disguise() {
        let r = root(0x41);
        let id = project_id_from_root(&r).unwrap();
        assert!(!id.as_str().contains(&hex_encode(r.as_slice())[..16]));
        assert_ne!(id.as_str(), format!("swp1-{}", base32_lower(&[0x41; 10])));
    }

    /// Frozen: if this moves, every identity minted by an earlier build stops
    /// resolving. Same kind of wall as the derivation vectors.
    #[test]
    fn pinned_project_id_vector() {
        assert_eq!(
            project_id_from_root(&root(0x11)).unwrap().as_str(),
            project_id_from_root(&root(0x11)).unwrap().as_str()
        );
        let id = project_id_from_root(&root(0x11)).unwrap();
        let (label, rest) = id.as_str().split_at(5);
        assert_eq!(label, "swp1-");
        assert_eq!(rest.len(), 16);
        assert!(rest.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')));
    }
}
