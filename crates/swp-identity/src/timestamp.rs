//! Machine-readable timestamps, UTC, RFC 3339 with second precision.
//!
//! A separate type because these appear in signed documents: the format has to
//! be stable or a reserialized release record stops verifying. Second precision
//! is deliberate — sub-second noise makes no difference to a provenance record
//! and would make every test fixture and golden file flap.

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Wall clock now, truncated to seconds so it survives a document
    /// round-trip unchanged.
    pub fn now_utc() -> Self {
        Timestamp(truncate(OffsetDateTime::now_utc()))
    }

    pub fn from_unix(secs: i64) -> Self {
        Timestamp(OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH))
    }

    pub fn parse(s: &str) -> Result<Self, SwpError> {
        OffsetDateTime::parse(s, &Rfc3339)
            .map(Timestamp)
            .map_err(|e| {
                SwpError::new(
                    ErrorCode::InvalidManifest,
                    format!("timestamp {s:?} is not RFC 3339 UTC: {e}"),
                )
            })
    }

    pub fn to_rfc3339(self) -> String {
        // `macros` gives us this formatter without a build-time dependency.
        self.0
            .to_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
    }

    pub fn unix(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Sortable filename component: `2026-09-21T14-03-22Z`. Used for release
    /// record names so they list in chronological order.
    pub fn filename_stem(self) -> String {
        let s = self.to_rfc3339();
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            out.push(match c {
                ':' => '-',
                _ => c,
            });
        }
        out
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl TryFrom<String> for Timestamp {
    type Error = SwpError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Timestamp::parse(&s)
    }
}

impl From<Timestamp> for String {
    fn from(t: Timestamp) -> String {
        t.to_rfc3339()
    }
}

fn truncate(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_nanosecond(0).unwrap_or(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trips() {
        let t = Timestamp::parse("2026-09-21T14:03:22Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-09-21T14:03:22Z");
        assert_eq!(t.filename_stem(), "2026-09-21T14-03-22Z");
        assert!(Timestamp::parse("yesterday").is_err());
        assert!(Timestamp::parse("2026-09-21").is_err());
    }

    #[test]
    fn now_is_second_precise_and_ordered() {
        let a = Timestamp::now_utc();
        let b = Timestamp::now_utc();
        assert!(a.to_rfc3339().ends_with('Z'));
        assert!(!a.to_rfc3339().contains('.'));
        assert!(b >= a);
        assert_eq!(Timestamp::parse(&a.to_rfc3339()).unwrap(), a);
    }

    #[test]
    fn serde_as_string() {
        let t = Timestamp::from_unix(1_700_000_000);
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}
