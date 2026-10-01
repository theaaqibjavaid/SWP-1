//! What a scan of somebody else's artifact returned.
//!
//! `ScanOutcome` is three things: the graded `SWP-1-report-v2` document, where a
//! saved copy went if the caller asked for one, and the per-site rows the
//! document only carries summed. The division of labour underneath it is the
//! protocol's — `swp-detection` reads the candidate and matches keyed addresses,
//! `swp-evidence` decides what the matches mean — and this module holds the
//! result of both. It grades nothing: `result`, `evidenceLevel` and the exit code
//! are read off the report by `crate::report`, and the rows here are copied out
//! of the detector's own rows, so a site graded `absent` here is graded `absent`
//! in the document.
//!
//! The rows are deliberately free of anything keyed: the location ids and the
//! expected codes a match was decided against stay inside `swp-detection`, so a
//! row here says *that* a span confirmed and how much work reaching it took,
//! without being a list of the values that would let a caller test a guess
//! against a site that was never hit.

use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{
    ReleaseSelection as SdkReleaseSelection, SavedReport as SdkSavedReport,
    ScanOutcome as SdkScanOutcome, ScannedSite as SdkScannedSite, Session as SdkSession,
};

use crate::error::{capture, Failure};
use crate::report::Report;

/// What a scan returned: the graded document, and where a saved copy went.
#[napi(js_name = "ScanOutcome")]
#[derive(Clone)]
pub struct ScanOutcome {
    pub(crate) inner: SdkScanOutcome,
}

/// The name and the path of one report a run saved.
#[napi(object, js_name = "SavedReport")]
#[derive(Clone)]
pub struct SavedReport {
    /// What `readReport` takes to get this document back. When two saves land in
    /// the same second the store numbers the collision, so this is the name it
    /// wrote under, which is not necessarily the one it was given.
    pub name: String,
    /// Store-relative and forward-slashed, so it is safe to print and will not
    /// reveal where the project lives.
    pub path: String,
}

/// One expected site, and what the candidate presented at its address.
#[napi(object, js_name = "ScannedSite")]
#[derive(Clone)]
pub struct ScannedSite {
    /// Which release this site belongs to. The report's `releases` are ordered
    /// best first; these rows are in scan order, so the id is what joins a row
    /// to its tally.
    pub release_id: String,
    /// Index into that release's site list, matching `swp inspect manifest`.
    pub site: f64,
    /// `'absent'`, `'location-only'`, `'tag-confirmed'` or `'exact-rendering'`.
    pub status: String,
    /// Spans at this site's address that reached a tag comparison.
    pub probes: u32,
    /// Distinct codes those spans presented: this site's share of the draws the
    /// report's coincidence bound is computed from.
    pub distinct_codes: u32,
    /// How many tokens the confirming span covers. `255` stands for "at least
    /// 255": the count saturates rather than wrapping.
    pub found_tokens: u8,
    /// Where the match actually was, when the candidate had it at all.
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    /// The literal found there, truncated to the report hint bound — the same
    /// text an evidence item quotes as its `excerpt`.
    pub found_excerpt: Option<String>,
}

#[napi]
impl ScanOutcome {
    /// The document `swp-evidence` graded, verbatim.
    #[napi(getter)]
    pub fn report(&self) -> Report {
        Report::from(self.inner.report.clone())
    }

    /// `undefined` unless the caller asked for a copy under
    /// `.swp/private/reports/`.
    #[napi(getter)]
    pub fn saved(&self) -> Option<SavedReport> {
        self.inner.saved.as_ref().map(project_saved)
    }

    /// Every site the scan looked for, in the order the releases were scanned
    /// and then the order the release records them.
    #[napi(getter)]
    pub fn sites(&self) -> Vec<ScannedSite> {
        self.inner.sites.iter().map(project_site).collect()
    }

    /// The verdict word, the level, and how many sites were looked for — the
    /// three values a caller reads first, the Python `__repr__` carried across.
    /// The document itself is `report`.
    #[napi(js_name = "toString")]
    pub fn to_string_(&self) -> String {
        format!(
            "ScanOutcome(result='{}', evidenceLevel='{}', sites={})",
            self.inner.report.result.as_str(),
            self.inner.report.evidence_level.as_str(),
            self.inner.sites.len(),
        )
    }
}

/// The async half of `scan`: the candidate walk and the match run on a libuv
/// worker thread, and the run always finishes.
///
/// A cancelled scan can leave a half-saved report under `.swp/private/`, so
/// there is no cancellation path here either — the same rule `ProtectTask`
/// records, for the same reason.
pub struct ScanTask {
    pub(crate) session: SdkSession,
    pub(crate) candidate: PathBuf,
    pub(crate) selection: SdkReleaseSelection,
    pub(crate) save: bool,
}

#[napi]
impl Task for ScanTask {
    type Output = std::result::Result<ScanOutcome, Failure>;
    type JsValue = ScanOutcome;

    fn compute(&mut self) -> Result<Self::Output> {
        let session = self.session.clone();
        let candidate = self.candidate.clone();
        let selection = self.selection.clone();
        let save = self.save;
        Ok(capture(move || {
            session
                .scan(&candidate, &selection, save)
                .map(|inner| ScanOutcome { inner })
                .map_err(Failure::from)
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> Result<Self::JsValue> {
        output.map_err(|failure| failure.into_napi_error(&env))
    }
}

fn project_saved(inner: &SdkSavedReport) -> SavedReport {
    SavedReport {
        name: inner.name.clone(),
        path: inner.path.clone(),
    }
}

fn project_site(inner: &SdkScannedSite) -> ScannedSite {
    ScannedSite {
        release_id: inner.release_id.clone(),
        site: inner.site as f64,
        status: inner.status.to_string(),
        probes: inner.probes,
        distinct_codes: inner.distinct_codes,
        found_tokens: inner.found_tokens,
        found_in: inner.found_in.clone(),
        found_line: inner.found_line,
        found_excerpt: inner.found_excerpt.clone(),
    }
}
