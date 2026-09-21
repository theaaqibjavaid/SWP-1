/// The protocol name carried by every SWP-1 artifact.
pub const SWP_PROTOCOL_NAME: &str = "SWP-1";

/// Version of the SWP-1 protocol itself. An artifact declaring any other value
/// must be rejected with `PROTOCOL_VERSION_UNSUPPORTED`, never treated as a
/// non-match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub const V1: ProtocolVersion = ProtocolVersion(1);

    pub fn is_supported(self) -> bool {
        self == Self::V1
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ProtocolVersion {
    type Err = crate::error::SwpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u16 = s.trim().parse().map_err(|_| {
            crate::error::SwpError::invalid_manifest(format!("bad protocol version {s:?}"))
        })?;
        Ok(ProtocolVersion(n))
    }
}

/// Version of a specific document schema (manifest, report, plan). Schemas
/// evolve independently of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SchemaVersion(pub u16);

impl SchemaVersion {
    pub const MANIFEST_V1: SchemaVersion = SchemaVersion(1);
    pub const IDENTITY_V1: SchemaVersion = SchemaVersion(1);
    pub const REPORT_V1: SchemaVersion = SchemaVersion(1);
    pub const PLAN_V1: SchemaVersion = SchemaVersion(1);
}

impl std::fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version of the canonicalization rules. Changing these rules changes every
/// location id, so it is part of every manifest and refuses cross-version
/// verification instead of silently returning no match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CanonicalizerVersion(pub u16);

impl CanonicalizerVersion {
    pub const V1: CanonicalizerVersion = CanonicalizerVersion(1);
}

impl std::fmt::Display for CanonicalizerVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which build of SWP-1 produced an artifact. Recorded for diagnosis only; it
/// never participates in a hashed value, so a tool upgrade cannot break the
/// fingerprint of unchanged code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeneratorInfo {
    pub swp_version: String,
    pub generator: String,
}

impl GeneratorInfo {
    pub fn current() -> Self {
        GeneratorInfo {
            swp_version: env!("CARGO_PKG_VERSION").to_string(),
            generator: "swp-cli".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_v1_is_supported() {
        assert!(ProtocolVersion::V1.is_supported());
        assert!(!ProtocolVersion(2).is_supported());
        assert!(!ProtocolVersion(0).is_supported());
    }

    #[test]
    fn version_parses_strictly() {
        assert_eq!("1".parse::<ProtocolVersion>().unwrap(), ProtocolVersion(1));
        assert!("two".parse::<ProtocolVersion>().is_err());
    }
}
