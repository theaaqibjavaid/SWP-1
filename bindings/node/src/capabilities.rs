//! What this build can do, as a JavaScript value rather than as a README.
//!
//! `swp_sdk::capabilities()` is the Rust call this module exists to re-speak.
//! Every number below is read from the crate that enforces it, by `swp-sdk`, and
//! this module only turns those values into object fields — it derives no range,
//! orders no list, and adds no language.
//!
//! What a listing does *not* promise: a language named here is one this build
//! **parses**. It says nothing about which literal forms survive a safety check.
//!
//! The Python surface answers `language_names()` as a method; a plain object has
//! none, so the names ship precomputed beside the per-language rows. That is a
//! field copy of strings already present, not new derivation, and it keeps the
//! whole value `JSON.stringify`-able for the binding's own leak sweep.

use napi_derive::napi;
use swp_sdk::{Capabilities, DefaultPolicy, LanguageInfo, SiteRange, TagRange};

/// Everything about this build a caller may need to know without asking a human.
#[napi(object, js_name = "Capabilities")]
#[derive(Clone)]
pub struct JsCapabilities {
    pub protocol: String,
    pub swp_version: String,
    pub report_schema: String,
    pub canonicalizer_version: u16,
    pub languages: Vec<JsLanguageInfo>,
    /// The parsed language names on their own, for a caller that only branches
    /// on them.
    pub language_names: Vec<String>,
    pub tag_bits: JsTagRange,
    pub target_sites: JsSiteRange,
    pub defaults: JsDefaultPolicy,
}

/// A language this build analyzes, and the file names it answers to.
#[napi(object, js_name = "LanguageInfo")]
#[derive(Clone)]
pub struct JsLanguageInfo {
    /// The stable identifier a manifest records. Never renamed.
    pub name: String,
    /// Lowercase, without the dot.
    pub extensions: Vec<String>,
}

/// The inclusive range of tag widths a site may carry.
#[napi(object, js_name = "TagRange")]
#[derive(Clone)]
pub struct JsTagRange {
    pub min: u8,
    pub max: u8,
    pub default: u8,
}

/// The inclusive range of constellation sizes a project may aim at.
#[napi(object, js_name = "SiteRange")]
#[derive(Clone)]
pub struct JsSiteRange {
    pub min: u32,
    pub default: u32,
    pub max: u32,
}

/// The settings a project starts from before it edits its config.
#[napi(object, js_name = "DefaultPolicy")]
#[derive(Clone)]
pub struct JsDefaultPolicy {
    /// Directories and patterns never walked, whatever a project configures.
    pub excludes: Vec<String>,
}

pub(crate) fn project(inner: &Capabilities) -> JsCapabilities {
    JsCapabilities {
        protocol: inner.protocol.clone(),
        swp_version: inner.swp_version.clone(),
        report_schema: inner.report_schema.clone(),
        canonicalizer_version: inner.canonicalizer_version,
        languages: inner.languages.iter().map(project_language).collect(),
        language_names: inner
            .languages
            .iter()
            .map(|l| l.name.to_string())
            .collect::<Vec<String>>(),
        tag_bits: project_tag(&inner.tag_bits),
        target_sites: project_site(&inner.target_sites),
        defaults: project_defaults(&inner.defaults),
    }
}

fn project_language(inner: &LanguageInfo) -> JsLanguageInfo {
    JsLanguageInfo {
        name: inner.name.to_string(),
        extensions: inner.extensions.clone(),
    }
}

fn project_tag(inner: &TagRange) -> JsTagRange {
    JsTagRange {
        min: inner.min,
        max: inner.max,
        default: inner.default,
    }
}

fn project_site(inner: &SiteRange) -> JsSiteRange {
    JsSiteRange {
        min: inner.min,
        default: inner.default,
        max: inner.max,
    }
}

fn project_defaults(inner: &DefaultPolicy) -> JsDefaultPolicy {
    JsDefaultPolicy {
        excludes: inner.excludes.clone(),
    }
}
