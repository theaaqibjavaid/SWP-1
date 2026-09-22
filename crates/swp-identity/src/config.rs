//! `.swp/config.toml` — the project's protection settings.
//!
//! Deliberately small, and deliberately **not** trusted as evidence. A candidate
//! repository may contain its own `.swp/config.toml` written by its attacker;
//! the scanner never reads config from the tree it is scanning, only from the
//! project doing the scanning. That distinction is why `Store::open` requires
//! the caller to say which side of that line it is on.

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::Limits;

/// Default number of watermark sites for a project of unspecified size. §9 of
/// the brief forbids hard-coding a universal number *without documentation*:
/// this is a starting suggestion that `swp init` adjusts from the measured size
/// of the tree, and the value actually used is recorded per release.
pub const DEFAULT_TARGET_SITES: u32 = 16;
pub const MIN_TARGET_SITES: u32 = 4;
pub const MAX_TARGET_SITES: u32 = 4096;

/// Directories never walked, whatever the user configures. These are dependency
/// and build-output directories: scanning them is slow, and vendored third-party
/// code is the single largest source of false positives (§27).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "**/node_modules/**",
    "**/.git/**",
    "**/target/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/.swp/**",
    "**/vendor/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SwpConfig {
    /// Which protocol this file was written for. Checked, not assumed.
    pub protocol: String,
    pub protect: ProtectConfig,
    /// Resource limits. Absent means the built-in defaults; values above the
    /// hard ceiling are clamped and the clamp is reported, never applied
    /// silently.
    pub limits: Limits,
}

impl Default for SwpConfig {
    fn default() -> Self {
        SwpConfig {
            protocol: swp_core::SWP_PROTOCOL_NAME.to_string(),
            protect: ProtectConfig::default(),
            limits: Limits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProtectConfig {
    /// Paths, relative to the project root, that may hold protected source.
    pub targets: Vec<String>,
    /// Additional glob exclusions merged onto [`DEFAULT_EXCLUDES`].
    pub excludes: Vec<String>,
    /// How many watermark sites to aim for.
    pub target_sites: u32,
    /// Bits carried per site. Raising this raises per-site evidence strength
    /// and lowers how many sites can be embedded safely.
    pub tag_bits: u8,
    /// Rewrite string literals as well as numbers.
    ///
    /// On by default, because a string-only tree has nothing else to carry a
    /// site and a constellation chosen from numbers alone is a thinner one. A
    /// string rewrite is the more visible diff and the more likely to upset a
    /// formatter, so a project that cares about either sets this to `false`; the
    /// cost is stated where it is paid, as a count of literals that were not
    /// offered as sites in the run's notes.
    pub embed_strings: bool,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        ProtectConfig {
            targets: vec!["src".to_string()],
            excludes: Vec::new(),
            target_sites: DEFAULT_TARGET_SITES,
            tag_bits: swp_core::TagWidth::DEFAULT.bits(),
            embed_strings: true,
        }
    }
}

impl ProtectConfig {
    /// The one scope definition both halves of the protocol agree on: every file
    /// a walk would admit from a tree's root, under the built-in exclusions only.
    ///
    /// The scanner uses it to decide what a candidate tree contains. `swp protect`
    /// uses it to decide what a release's §16 fingerprint is taken over — which is
    /// why it cannot be the *project's* configured targets: a fingerprint of
    /// `src/` only could never be reproduced by a scanner that walked a copy of the
    /// whole project, and the exact-copy channel would silently stop firing on any
    /// tree with parseable source outside its targets.
    ///
    /// A candidate's own configuration is never read: a tree being scanned may
    /// have smuggled in its own `.swp/config.toml`, and letting attacker content
    /// decide how it is judged is not a thing a scanner does.
    pub fn scan_scope() -> Self {
        ProtectConfig {
            targets: vec![".".to_string()],
            excludes: Vec::new(),
            target_sites: 1,
            tag_bits: swp_core::TagWidth::DEFAULT.bits(),
            // Both literal classes are in scope, whatever a given release chose: a
            // copy of a string-watermarked release must be findable from a project
            // whose config never enabled strings.
            embed_strings: true,
        }
    }
}

impl SwpConfig {
    pub fn parse(text: &str) -> Result<Self, SwpError> {
        let cfg: SwpConfig = toml::from_str(text).map_err(|e| {
            // `INVALID_MANIFEST`'s standing advice is about release manifests, which
            // is the wrong remedy for a settings file: this one is in version
            // control and regenerable, and that one is not.
            SwpError::invalid_manifest(format!("config.toml: {e}")).with_next(
                "The line the parser named above is the whole fix: a duplicated key, a \
                 misspelled one, or a value in the wrong type. This file holds settings \
                 only, so restoring the committed copy — or deleting it and letting \
                 `swp init` write the defaults — loses no watermark data.",
            )
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("config is serializable by construction")
    }

    /// Clamp limits to the hard ceiling, returning the warnings a CLI must show.
    /// A user may lower a limit; they may not raise one above what the scanner
    /// was designed to survive, because those ceilings are what make scanning a
    /// hostile repository safe (§45).
    pub fn apply_limit_ceiling(&mut self) -> Vec<String> {
        let current = std::mem::take(&mut self.limits);
        let (clamped, warnings) = current.clamped_to_ceiling();
        self.limits = clamped;
        warnings
    }

    pub fn validate(&self) -> Result<(), SwpError> {
        if self.protocol != swp_core::SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("config.toml declares protocol {:?}", self.protocol),
            ));
        }
        if self.protect.target_sites < MIN_TARGET_SITES
            || self.protect.target_sites > MAX_TARGET_SITES
        {
            return Err(SwpError::new(
                ErrorCode::Usage,
                format!(
                    "target_sites must be between {MIN_TARGET_SITES} and {}, found {}",
                    MAX_TARGET_SITES, self.protect.target_sites
                ),
            ));
        }
        if !swp_core::TagWidth::is_supported(self.protect.tag_bits) {
            return Err(SwpError::new(
                ErrorCode::Usage,
                format!(
                    "tag_bits must be between {} and {}, found {}",
                    swp_core::TagWidth::MIN,
                    swp_core::TagWidth::MAX,
                    self.protect.tag_bits
                ),
            ));
        }
        for t in &self.protect.targets {
            if t.starts_with('/') || t.starts_with('\\') || t.contains("..") {
                return Err(SwpError::new(
                    ErrorCode::Usage,
                    format!("target {t:?} must be a relative path inside the project"),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_toml() {
        let c = SwpConfig::default();
        let text = c.to_toml();
        let back = SwpConfig::parse(&text).unwrap();
        assert_eq!(c, back);
        assert!(text.contains("target_sites"));
    }

    #[test]
    fn an_empty_file_is_the_defaults() {
        assert_eq!(SwpConfig::parse("").unwrap(), SwpConfig::default());
    }

    #[test]
    fn unknown_keys_are_a_hard_error() {
        // A typo like `tag_bit` silently doing nothing is worse than a failure.
        assert!(SwpConfig::parse("protect = { tag_bit = 4 }").is_err());
        assert!(SwpConfig::parse("protocol = \"SWP-2\"").is_err());
    }

    #[test]
    fn nonsense_settings_are_rejected() {
        let mut c = SwpConfig::default();
        c.protect.target_sites = 0;
        assert!(c.validate().is_err());
        c.protect.target_sites = 100_000;
        assert!(c.validate().is_err());
        c.protect.target_sites = 12;
        c.protect.tag_bits = 99;
        assert!(c.validate().is_err());
        c.protect.tag_bits = 4;
        c.protect.targets = vec!["../outside".into()];
        assert!(c.validate().is_err());
        assert!(c.validate().is_err());
        c.protect.targets = vec!["src".into()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn limits_are_clamped_and_the_clamp_is_reported() {
        let mut c = SwpConfig::default();
        c.limits.max_file_bytes = u64::MAX;
        let warnings = c.apply_limit_ceiling();
        assert!(!warnings.is_empty(), "silent clamp is the bug this catches");
        assert!(c.limits.max_file_bytes <= Limits::ceiling().max_file_bytes);
        let c2 = SwpConfig::default();
        assert!(c2.clone().apply_limit_ceiling().is_empty());
    }
}
