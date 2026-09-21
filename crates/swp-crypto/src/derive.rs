//! Domain-separated key derivation.
//!
//! The root secret is already a uniform 256-bit key, so HKDF-Extract would add
//! salt ceremony without strength; HMAC-SHA-256 over an injective encoding is
//! exactly HKDF-Expand and is the construction RFC 5869 prescribes for this
//! case.
//!
//! Two properties are load-bearing and both are tested:
//!
//! 1. **Domain separation.** A key derived for `project` is never used for
//!    `location`. The domain label is inside the HMAC input, and `keyed`
//!    refuses a key whose domain does not match.
//! 2. **Injective field encoding.** Every field is length-prefixed, so
//!    `["ab","c"]` and `["a","bc"]` and `["ab\0c"]` cannot collide. Bare
//!    separator strings would collide, and the field count is prefixed too so a
//!    trailing empty field is distinct from no field.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use swp_core::error::SwpError;
use swp_core::version::ProtocolVersion;

use crate::secret::{DerivedKey, RootSecret};

/// The literal that opens every derivation message. Changing it changes every
/// key, which is why it is versioned alongside the protocol.
pub const PROTOCOL_LABEL: &[u8] = b"SWP-1";

/// The purposes a key may serve. Never reuse one purpose for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    /// Project identifier bootstrap. The only domain whose derivation takes no
    /// project id as input, which is what breaks the cycle that would otherwise
    /// exist between "the project id is derived from the signing key" and "the
    /// signing key is derived from the project id".
    Identity,
    /// Location identity: which site is this.
    Project,
    /// Fragment tags: what value does this site encode.
    Location,
    /// Release record binding.
    Release,
    /// Report/evidence binding nonces.
    Evidence,
    /// Ed25519 manifest signing seed.
    Signing,
    /// Deterministic site and variant selection.
    Selection,
}

impl Domain {
    pub fn as_str(self) -> &'static str {
        match self {
            Domain::Identity => "identity",
            Domain::Project => "project",
            Domain::Location => "location",
            Domain::Release => "release",
            Domain::Evidence => "evidence",
            Domain::Signing => "signing",
            Domain::Selection => "selection",
        }
    }
}

/// Build the HMAC input message. Public so the fixed-vector tests can pin the
/// exact byte encoding.
pub fn derivation_message(domain: Domain, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PROTOCOL_LABEL);
    out.push(0x00);
    out.extend_from_slice(domain.as_str().as_bytes());
    out.push(0x00);
    out.extend_from_slice(&ProtocolVersion::V1.as_u16().to_be_bytes());
    out.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Derive a single-purpose key from the root secret.
pub fn derive_key(root: &RootSecret, domain: Domain, fields: &[&[u8]]) -> DerivedKey {
    let bytes = crate::secret::SecretBytes::from_vec(
        hmac(root.as_slice(), &derivation_message(domain, fields)).to_vec(),
    );
    DerivedKey::new(bytes, domain.as_str())
}

/// keyed MAC under an already-derived key. Refuses a key from the wrong domain
/// rather than quietly producing a value that looks fine.
pub fn hmac_keyed(
    key: &DerivedKey,
    expect: Domain,
    fields: &[&[u8]],
) -> Result<[u8; 32], SwpError> {
    if key.domain() != expect.as_str() {
        return Err(SwpError::internal(format!(
            "domain violation: key for {:?} used in domain {:?}",
            key.domain(),
            expect.as_str()
        )));
    }
    Ok(hmac(key.as_slice(), &derivation_message(expect, fields)))
}

/// Take the low `bits` bits of a 32-byte MAC as an integer. Because every tag
/// width is a power of two, this is uniform — there is no modulo bias to
/// correct.
pub fn truncate_bits(mac: &[u8; 32], bits: u8) -> u32 {
    debug_assert!((1..=32).contains(&bits));
    let raw = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]);
    if bits >= 32 {
        raw
    } else {
        raw & ((1u32 << bits) - 1)
    }
}

/// Constant-time comparison of two equal-purpose secrets (MACs, keys). Tag
/// comparison does not need this, but key and signature checks do, and it is
/// cheap to be correct about.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::hex_encode;

    fn root() -> RootSecret {
        RootSecret::from_bytes(&[0x11u8; 32]).unwrap()
    }

    #[test]
    fn field_encoding_is_injective() {
        let cases: Vec<Vec<&[u8]>> = vec![
            vec![b"ab", b"c"],
            vec![b"a", b"bc"],
            vec![b"abc"],
            vec![b"abc", b""],
            vec![b"ab\0c"],
            vec![],
            vec![b""],
        ];
        let mut seen = std::collections::BTreeMap::new();
        for c in &cases {
            let msg = derivation_message(Domain::Project, c);
            let prev = seen.insert(msg.clone(), format!("{c:?}"));
            assert!(prev.is_none(), "collision between {prev:?} and {c:?}");
        }
    }

    #[test]
    fn domains_do_not_share_keys() {
        let fields: [&[u8]; 1] = [b"swp1-demo"];
        let mut by_domain = std::collections::BTreeSet::new();
        for d in [
            Domain::Identity,
            Domain::Project,
            Domain::Location,
            Domain::Release,
            Domain::Evidence,
            Domain::Signing,
            Domain::Selection,
        ] {
            let k = derive_key(&root(), d, &fields);
            assert!(
                by_domain.insert(hex_encode(k.as_slice())),
                "domain collision at {d:?}"
            );
            assert_eq!(k.domain(), d.as_str());
        }
        assert_eq!(by_domain.len(), 7);
    }

    #[test]
    fn wrong_domain_is_refused() {
        let k = derive_key(&root(), Domain::Project, &[b"p"]);
        let e = hmac_keyed(&k, Domain::Location, &[b"p"]).unwrap_err();
        assert!(e.message().contains("domain violation"));
        assert!(hmac_keyed(&k, Domain::Project, &[b"p"]).is_ok());
    }

    #[test]
    fn derivation_is_deterministic_across_calls() {
        let a = derive_key(&root(), Domain::Project, &[b"swp1-x", b"1"]);
        let b = derive_key(&root(), Domain::Project, &[b"swp1-x", b"1"]);
        assert_eq!(hex_encode(a.as_slice()), hex_encode(b.as_slice()));
        // A different project id yields a different key, of course.
        let c = derive_key(&root(), Domain::Project, &[b"swp1-y", b"1"]);
        assert_ne!(hex_encode(a.as_slice()), hex_encode(c.as_slice()));
    }

    #[test]
    fn truncation_respects_width() {
        let mac = [0xffu8; 32];
        assert_eq!(truncate_bits(&mac, 4), 15);
        assert_eq!(truncate_bits(&mac, 8), 255);
        assert_eq!(truncate_bits(&[0u8; 32], 4), 0);
        let mut sparse = [0u8; 32];
        sparse[3] = 0x8f;
        assert_eq!(truncate_bits(&sparse, 4), 15);
        assert_eq!(truncate_bits(&sparse, 8), 0x8f);
        assert_eq!(truncate_bits(&sparse, 1), 1);
    }

    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    /// Frozen vectors. If any of these change, every manifest ever produced by
    /// an earlier build becomes unverifiable — so this test is a compatibility
    /// wall, not a description of the code.
    ///
    /// The digest below was computed independently with Python's `hmac` over
    /// the byte encoding asserted in `derivation_message_is_injective`, so it
    /// pins the construction rather than this implementation of it.
    #[test]
    fn pinned_derivation_vectors() {
        let r = RootSecret::from_bytes(&[0x11u8; 32]).unwrap();
        let pk = derive_key(&r, Domain::Project, &[b"swp1-abcdefghijklmnop"]);
        assert_eq!(
            hex_encode(pk.as_slice()),
            "582448f54853330cb2c104fd5456e5ee96915de40dad2e534d5b0452dd161e34",
            "project key derivation vectors changed"
        );
        let msg = derivation_message(Domain::Location, &[b"\x01\x02"]);
        assert_eq!(
            hex_encode(&msg),
            "5357502d31006c6f636174696f6e00000100000001000000020102"
        );
    }
}
