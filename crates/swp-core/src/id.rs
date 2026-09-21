//! Identity types. These are strings and byte arrays with strict validation;
//! key material itself never appears here (see `swp-crypto`).

use crate::error::SwpError;

/// SHA-256 output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Short rendering used in human output and evidence ids.
    pub fn short(&self) -> String {
        hex_encode(&self.0[..8])
    }

    pub fn from_hex(s: &str) -> Result<Self, SwpError> {
        let b = hex_decode(s)?;
        if b.len() != 32 {
            return Err(SwpError::invalid_manifest("expected 32-byte digest"));
        }
        let mut o = [0u8; 32];
        o.copy_from_slice(&b);
        Ok(Digest(o))
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.short())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Keyed, per-project location identity of a watermark site (see protocol spec
/// section "Location identity"). 128 bits of HMAC output: collision-free for
/// the number of sites any real project has, and unforgeable without the root
/// secret, which is what keeps identical boilerplate in two projects from
/// sharing an id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct LocationId(pub [u8; 16]);

impl LocationId {
    pub fn from_bytes(b: &[u8]) -> Result<Self, SwpError> {
        if b.len() != 16 {
            return Err(SwpError::invalid_manifest("location id must be 16 bytes"));
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(b);
        Ok(LocationId(o))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, SwpError> {
        let b = hex_decode(s)?;
        LocationId::from_bytes(&b)
    }
}

impl std::fmt::Debug for LocationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Loc({})", self.hex())
    }
}

impl std::fmt::Display for LocationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl serde::Serialize for LocationId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> serde::Deserialize<'de> for LocationId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        LocationId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Stable identifier of the protected project, derived from the public half of
/// the manifest signing key: `swp1-<base32(verify_key[0..10])>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProjectId(pub String);

/// RFC 4648 base32 alphabet, lowercase, unpadded: `[a-z2-7]`.
fn is_b32(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'2'..=b'7')
}

impl ProjectId {
    const PREFIX: &'static str = "swp1-";

    pub fn new(raw: impl AsRef<str>) -> Result<Self, SwpError> {
        let s = raw.as_ref().to_ascii_lowercase();
        let rest = s.strip_prefix(Self::PREFIX).ok_or_else(|| {
            SwpError::invalid_manifest(format!("project id must start with {:?}", Self::PREFIX))
        })?;
        // Must accept exactly what `base32_lower` can emit. An earlier range of
        // `a-v` here rejected every id containing w, x, y or z — which is about
        // half of all randomly generated identities.
        if rest.len() != 16 || !rest.bytes().all(is_b32) {
            return Err(SwpError::invalid_manifest(
                "project id has an unexpected character set or length",
            ));
        }
        Ok(ProjectId(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ProjectId {
    type Err = SwpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProjectId::new(s)
    }
}

impl serde::Serialize for ProjectId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ProjectId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ProjectId::new(s).map_err(serde::de::Error::custom)
    }
}

/// Identifier of one protected release.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReleaseId(pub String);

impl ReleaseId {
    pub fn new(raw: impl AsRef<str>) -> Result<Self, SwpError> {
        let s = raw.as_ref().to_ascii_lowercase();
        let rest = s
            .strip_prefix("rel-")
            .ok_or_else(|| SwpError::invalid_manifest("release id must start with \"rel-\""))?;
        if rest.is_empty() || rest.len() > 32 || !rest.bytes().all(is_b32) {
            return Err(SwpError::invalid_manifest("release id is malformed"));
        }
        Ok(ReleaseId(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ReleaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ReleaseId {
    type Err = SwpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ReleaseId::new(s)
    }
}

impl serde::Serialize for ReleaseId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ReleaseId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ReleaseId::new(s).map_err(serde::de::Error::custom)
    }
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32 (lowercased, unpadded) over an exact byte count. Used for
/// ids so they stay URL- and filename-safe.
pub fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, SwpError> {
    if s.len() % 2 != 0 {
        return Err(SwpError::invalid_manifest("odd-length hex string"));
    }
    let bs = s.as_bytes();
    let mut out = Vec::with_capacity(bs.len() / 2);
    let mut i = 0;
    while i < bs.len() {
        let hi = nibble(bs[i])?;
        let lo = nibble(bs[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, SwpError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(SwpError::invalid_manifest("invalid hex character")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_id_round_trips_and_rejects_junk() {
        let id = ProjectId::new("swp1-abcdefghijklmnop").unwrap();
        assert_eq!(id.as_str(), "swp1-abcdefghijklmnop");
        assert!(ProjectId::new("evil-abcdefghijklmnop").is_err());
        assert!(ProjectId::new("swp1-short").is_err());
        assert!(ProjectId::new("swp1-abcdefghijklmnop").unwrap() == id);
        // Every character base32_lower can produce must be accepted, and ids
        // generated from real random bytes must never fail at construction.
        for seed in 0u8..=255 {
            let raw = base32_lower(&[seed; 10]);
            assert_eq!(raw.len(), 16);
            assert!(
                ProjectId::new(format!("swp1-{raw}")).is_ok(),
                "generated id {raw} rejected"
            );
        }
        assert!(ProjectId::new("swp1-abcdefghijklmno0").is_err());
        assert!(ProjectId::new("swp1-abcdefghijklmnop").is_ok());
    }

    #[test]
    fn digest_hex_round_trips() {
        let mut d = [0u8; 32];
        for (i, v) in d.iter_mut().enumerate() {
            *v = i as u8;
        }
        let dg = Digest(d);
        assert_eq!(Digest::from_hex(&dg.hex()).unwrap(), dg);
        assert_eq!(dg.short().len(), 16);
    }

    #[test]
    fn location_id_rejects_wrong_length() {
        assert!(LocationId::from_hex("aabb").is_err());
        let hex = "00112233445566778899aabbccddeeff";
        assert_eq!(LocationId::from_hex(hex).unwrap().hex(), hex);
    }

    #[test]
    fn base32_matches_rfc4648_lowercase_unpadded() {
        // Cross-checked against Python's base64.b32encode.
        assert_eq!(base32_lower(&[0xde, 0xad, 0xbe, 0xef]), "32w353y");
        assert_eq!(base32_lower(&[0x00]), "aa");
        assert_eq!(base32_lower(&[]), "");
        // Ids must stay filename- and URL-safe: only [a-z2-7].
        let id = base32_lower(&[0xff; 10]);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'2'..=b'7')));
    }

    #[test]
    fn hex_rejects_non_hex() {
        assert!(hex_decode("zz").is_err());
    }
}
