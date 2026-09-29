//! What this build can do, as one value rather than as a README.
//!
//! [`capabilities()`] exists because the alternative is a caller — a binding, a
//! CI job, a build script — carrying its own guess at the language list and the
//! numeric ranges, and three ecosystems guessing differently is how a language
//! stops being "supported" in one of them. Every number here is read from the
//! crate that enforces it, so this cannot go stale the way a table in prose does.
//!
//! What a listing does *not* promise: a language named here is one this build
//! **parses**. It says nothing about which literal forms survive a safety check —
//! adjacent-string concatenation is Python-only, and a JavaScript template literal
//! whose spans overlap is refused — and it says nothing about how many sites a
//! given tree will yield, because that is a property of the tree.

use serde::Serialize;
use swp_adapters::Registry;
use swp_core::TagWidth;
use swp_core::{CanonicalizerVersion, SWP_PROTOCOL_NAME};
use swp_identity::{DEFAULT_EXCLUDES, DEFAULT_TARGET_SITES, MAX_TARGET_SITES, MIN_TARGET_SITES};

/// A language this build analyzes, and the file names it answers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LanguageInfo {
    /// The stable identifier a manifest records. Never renamed: it is part of
    /// what a release stores.
    pub name: &'static str,
    /// Lowercase, without the dot — the extensions this adapter claims.
    pub extensions: Vec<String>,
}

/// The inclusive range of tag widths a site may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TagRange {
    pub min: u8,
    pub max: u8,
    pub default: u8,
}

impl Default for TagRange {
    fn default() -> Self {
        TagRange {
            min: TagWidth::MIN,
            max: TagWidth::MAX,
            default: TagWidth::DEFAULT.bits(),
        }
    }
}

/// The inclusive range of constellation sizes a project may aim at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SiteRange {
    pub min: u32,
    pub default: u32,
    pub max: u32,
}

impl Default for SiteRange {
    fn default() -> Self {
        SiteRange {
            min: MIN_TARGET_SITES,
            default: DEFAULT_TARGET_SITES,
            max: MAX_TARGET_SITES,
        }
    }
}

/// The settings a project starts from before it edits its config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultPolicy {
    /// Directories and patterns never walked, whatever a project configures. A
    /// caller that offers its own picker needs this list to keep vendored
    /// third-party code out of a scan, which is §27's largest source of false
    /// positives.
    pub excludes: Vec<String>,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        DefaultPolicy {
            excludes: DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Everything about this build a caller may need to know without asking a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// The protocol this build speaks: `SWP-1`.
    pub protocol: String,
    /// The tool version, as a report's `generator` field records it.
    pub swp_version: String,
    /// The report format this build writes and reads: `SWP-1-report-v2`. A stored
    /// document under another schema is refused rather than re-graded by rules it
    /// was not written under.
    pub report_schema: String,
    /// The canonicalization rules whose version every location id carries; a
    /// release from another one fails rather than reporting "no match".
    pub canonicalizer_version: u16,
    /// The languages this build parses.
    pub languages: Vec<LanguageInfo>,
    /// Bits per site.
    pub tag_bits: TagRange,
    /// Sites per release.
    pub target_sites: SiteRange,
    /// The built-in excludes.
    pub defaults: DefaultPolicy,
}

/// The machine-readable answer to "what can this build do".
///
/// It touches nothing: no filesystem, no project, no secret. It cannot fail.
pub fn capabilities() -> Capabilities {
    let registry = Registry::standard();
    let languages = registry
        .parsed_languages()
        .into_iter()
        .map(|name| LanguageInfo {
            extensions: adapter_extensions(&registry, name),
            name,
        })
        .collect();
    Capabilities {
        protocol: SWP_PROTOCOL_NAME.to_string(),
        swp_version: crate::VERSION.to_string(),
        // The report's own const, not a composition: `SchemaVersion::REPORT_V2`
        // carries the *number* 2, and `SWP-1-report-2` is not the string
        // `Report::from_json` accepts. The name lives in one place.
        report_schema: swp_evidence::REPORT_SCHEMA.to_string(),
        canonicalizer_version: CanonicalizerVersion::V1.0,
        languages,
        tag_bits: TagRange::default(),
        target_sites: SiteRange::default(),
        defaults: DefaultPolicy::default(),
    }
}

/// The extensions the adapter for `name` claims.
///
/// No single call in `swp-adapters` returns both the parsed-language list and a
/// language's extensions, which is the whole reason this function exists: a
/// caller that wants the pair has to compose it, and composing it three ways in
/// three bindings is how one of them ends up wrong.
fn adapter_extensions(registry: &Registry, name: &'static str) -> Vec<String> {
    registry
        .for_language(name)
        .extensions()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_and_ranges_come_from_the_crates_that_enforce_them() {
        let c = capabilities();
        assert_eq!(c.protocol, "SWP-1");
        assert_eq!(c.report_schema, swp_evidence::REPORT_SCHEMA);
        assert_eq!(c.canonicalizer_version, 1);
        assert_eq!(c.tag_bits.min, TagWidth::MIN);
        assert_eq!(c.tag_bits.max, TagWidth::MAX);
        assert!(
            TagWidth::is_supported(c.tag_bits.default) && c.tag_bits.default > c.tag_bits.min,
            "the advertised default is one the protocol accepts"
        );
        assert_eq!(c.target_sites.min, MIN_TARGET_SITES);
        assert_eq!(c.target_sites.default, DEFAULT_TARGET_SITES);
        assert_eq!(c.target_sites.max, MAX_TARGET_SITES);
        assert!(c
            .defaults
            .excludes
            .iter()
            .any(|p| p == "**/node_modules/**"));
    }

    #[test]
    fn every_language_it_names_has_extensions_and_a_real_adapter() {
        let c = capabilities();
        assert!(
            !c.languages.is_empty(),
            "a build that parses nothing would report an empty list here"
        );
        let registry = Registry::standard();
        for lang in &c.languages {
            assert!(!lang.name.is_empty());
            assert!(
                !lang.extensions.is_empty(),
                "{} claims no extension",
                lang.name
            );
            // `for_language` falls back to the lexical adapter, so the name has to
            // be checked against the parsed list rather than through it.
            assert!(
                registry.parsed_languages().contains(&lang.name),
                "{} is not a parsed language",
                lang.name
            );
            assert_eq!(
                lang.extensions,
                adapter_extensions(&registry, lang.name),
                "{}'s extensions drifted from its adapter",
                lang.name
            );
        }
    }
}
