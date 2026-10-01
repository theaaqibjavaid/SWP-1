//! The five values a caller passes *in*.
//!
//! Each is a plain `#[napi(object)]` — the JavaScript idiom for an options bag —
//! and the conversion out of it is a field copy into what the façade expects: a
//! `tagBits` that arrives as a number leaves this module as the same `u8` the CLI
//! would have parsed from `--tag-bits`. Where the Rust side has no `Default`, no
//! default is invented here either; where it does (`Overrides`, `InitOptions`,
//! `VerifyOptions`), an absent field means the same thing it means to `swp`.
//!
//! `Mode` is the one Rust *enum* a caller has to choose, and it crosses as the
//! string union of `Mode::as_str()`'s own words — `'plan'`, `'release'`,
//! `'dry-run'` — because those are the words the saved plan and the CLI use, and
//! a binding may not mint a fourth spelling. The enums a scan hands *back* cross
//! as strings the same way, in their own modules.

use napi_derive::napi;
use swp_sdk::{
    InitOptions, Mode, Overrides, ProtectOptions, ReleaseId, ReleaseSelection, VerifyOptions,
};

use crate::error::Failure;

/// The §8 `Overrides`: what one session's run changes about `[protect]`.
#[napi(object, js_name = "Overrides")]
#[derive(Default)]
pub struct JsOverrides {
    /// Directories to protect, project-relative or absolute-inside-the-project,
    /// appended to the configured targets.
    pub targets: Option<Vec<String>>,
    /// Patterns to skip, appended to `[protect] excludes`.
    pub excludes: Option<Vec<String>>,
    /// `[protect] target_sites`, when the caller chose a constellation size.
    pub target_sites: Option<u32>,
    /// `[protect] tag_bits`, when the caller chose a tag width.
    pub tag_bits: Option<u8>,
    /// `[protect] embed_strings`, when the caller chose whether string literals
    /// carry marks.
    pub embed_strings: Option<bool>,
}

impl JsOverrides {
    pub(crate) fn into_inner(self) -> Overrides {
        Overrides {
            targets: self.targets.unwrap_or_default(),
            excludes: self.excludes.unwrap_or_default(),
            target_sites: self.target_sites,
            tag_bits: self.tag_bits,
            embed_strings: self.embed_strings,
        }
    }
}

/// Which of a project's releases an operation reads. Omit it, and — exactly as in
/// the CLI and in `swp-sdk` — every release the project has is loaded, because
/// picking one silently would be an unstated claim about which.
#[napi(object, js_name = "ReleaseSelection")]
pub struct JsReleaseSelection {
    /// Which of the three this is.
    #[napi(ts_type = "'all' | 'latest' | 'ids'")]
    pub kind: String,
    /// The ids, for `'ids'` only. An id this project never published is an error
    /// at the call that uses the selection, not here.
    pub ids: Option<Vec<String>>,
}

impl JsReleaseSelection {
    pub(crate) fn into_inner(self) -> std::result::Result<ReleaseSelection, Failure> {
        match self.kind.as_str() {
            "all" => Ok(ReleaseSelection::All),
            "latest" => Ok(ReleaseSelection::Latest),
            "ids" => {
                let raw = self.ids.ok_or_else(|| {
                    Failure::usage("a release selection of kind 'ids' needs an `ids` array")
                })?;
                let mut out = Vec::with_capacity(raw.len());
                for id in raw {
                    out.push(ReleaseId::new(id).map_err(Failure::from)?);
                }
                Ok(ReleaseSelection::Ids(out))
            }
            other => Err(Failure::usage(format!(
                "release selection kind must be 'all', 'latest' or 'ids'; got '{other}'"
            ))),
        }
    }
}

/// What `Session.init` is told.
#[napi(object, js_name = "InitOptions")]
#[derive(Default)]
pub struct JsInitOptions {
    /// The label the project asked for. Never hashed, never trusted.
    pub name: Option<String>,
    pub force: Option<bool>,
}

impl JsInitOptions {
    pub(crate) fn into_inner(self) -> InitOptions {
        InitOptions {
            name: self.name,
            force: self.force.unwrap_or_default(),
        }
    }
}

/// What one `protectSummary` call is told.
#[napi(object, js_name = "ProtectOptions")]
pub struct JsProtectOptions {
    /// A run that plans, applies or does neither.
    #[napi(ts_type = "'plan' | 'release' | 'dry-run'")]
    pub mode: String,
    /// The release to write; `undefined` allocates one, which is the ordinary
    /// case. A plan is keyed by its release id, so applying a generated
    /// constellation requires passing back the id the plan reported.
    pub release_id: Option<String>,
    /// A label for the source this run protected, recorded but never trusted.
    /// `undefined` records the content fingerprint; `''` records an
    /// intentionally-empty label — the same distinction `swp protect --revision`
    /// makes, carried here because JS can spell both.
    pub revision: Option<String>,
}

impl JsProtectOptions {
    /// Built through `ProtectOptions::new`, the only constructor the façade
    /// offers, on purpose: it is where a mode's defaults come from.
    pub(crate) fn into_inner(self) -> std::result::Result<ProtectOptions, Failure> {
        let mut inner = ProtectOptions::new(parse_mode(&self.mode)?);
        if let Some(raw) = self.release_id {
            inner.release_id = Some(ReleaseId::new(raw).map_err(Failure::from)?);
        }
        inner.revision = self.revision;
        Ok(inner)
    }
}

/// What one `verify` call is told.
#[napi(object, js_name = "VerifyOptions")]
#[derive(Default)]
pub struct JsVerifyOptions {
    /// The release to check against; `undefined` is the newest, because "is the
    /// tree I am standing in still the tree I protected?" is a question about
    /// the last protection run.
    pub release: Option<String>,
    /// Whether the run writes its `SWP-1-report-v2` copy into
    /// `.swp/private/reports/`. The verification document itself is returned,
    /// never written.
    pub save: Option<bool>,
    /// How many site rows the caller intends to render; `undefined` is the
    /// build's own limit. Only `omittedRows` depends on this — the document
    /// always carries every row.
    pub rows: Option<u32>,
}

impl JsVerifyOptions {
    pub(crate) fn into_inner(self) -> std::result::Result<VerifyOptions, Failure> {
        Ok(VerifyOptions {
            release: self
                .release
                .map(ReleaseId::new)
                .transpose()
                .map_err(Failure::from)?,
            save: self.save.unwrap_or_default(),
            rows: self.rows.map(|r| r as usize),
        })
    }
}

/// The one word-list the protocol already has, matched case-sensitively: these
/// strings appear in saved plans and in CLI flags, and a binding that accepted
/// `'Release'` would be inventing a spelling nothing else speaks.
pub(crate) fn parse_mode(word: &str) -> std::result::Result<Mode, Failure> {
    match word {
        "plan" => Ok(Mode::Plan),
        "release" => Ok(Mode::Release),
        "dry-run" => Ok(Mode::DryRun),
        other => Err(Failure::usage(format!(
            "mode must be one of 'plan', 'release', 'dry-run'; got '{other}'"
        ))),
    }
}

/// The mode's own word, read from `Mode::as_str()` so the summary and the saved
/// plan cannot disagree about how the run is named.
pub(crate) fn mode_word(mode: Mode) -> &'static str {
    mode.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three words `Mode::as_str` prints are exactly the three this module
    /// accepts — the union and the enum cannot have drifted apart.
    #[test]
    fn the_accepted_modes_are_exactly_the_documented_words() {
        for mode in [Mode::Plan, Mode::Release, Mode::DryRun] {
            assert_eq!(parse_mode(mode.as_str()).unwrap(), mode);
        }
        assert!(parse_mode("dry_run").is_err());
        assert!(parse_mode("Release").is_err());
        assert!(parse_mode("").is_err());
    }

    /// A bad word is a `USAGE` failure naming what was given, the same code the
    /// CLI gives for a bad flag value.
    #[test]
    fn a_bad_mode_word_is_a_usage_error_that_quotes_the_input() {
        let err = parse_mode("protected").expect_err("not a mode");
        assert_eq!(err.0.code().as_str(), "USAGE");
        assert!(err.0.message().contains("'protected'"));
    }

    /// `'ids'` with no array is the caller's mistake at the moment they made it,
    /// not a silent `'all'`.
    #[test]
    fn an_ids_selection_without_ids_is_refused() {
        let sel = JsReleaseSelection {
            kind: "ids".to_string(),
            ids: None,
        };
        let err = sel.into_inner().expect_err("refused");
        assert_eq!(err.0.code().as_str(), "USAGE");
    }

    /// The other three kinds need no array at all, and an empty id list is the
    /// caller's own choice — it selects nothing, which the using call reports.
    #[test]
    fn the_three_kinds_convert_what_the_protocol_defines() {
        assert_eq!(
            JsReleaseSelection {
                kind: "all".to_string(),
                ids: Some(vec!["ignored".to_string()]),
            }
            .into_inner()
            .unwrap(),
            ReleaseSelection::All
        );
        assert!(matches!(
            JsReleaseSelection {
                kind: "ids".to_string(),
                ids: Some(vec![]),
            }
            .into_inner()
            .unwrap(),
            ReleaseSelection::Ids(v) if v.is_empty()
        ));
    }
}
