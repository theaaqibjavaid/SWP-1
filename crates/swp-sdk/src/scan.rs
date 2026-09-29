//! Looking for this project's provenance in somebody else's artifact.
//!
//! [`Session::scan`] is the operation; the types here are what it hands back. The
//! division of labour is the protocol's: `swp-detection` reads the candidate and
//! matches keyed addresses, `swp-evidence` decides what the matches mean, and this
//! crate only supplies the releases, the key and the path.

use std::path::Path;

use swp_core::error::SwpError;
use swp_evidence::Report;
use swp_identity::Timestamp;

use crate::session::{ReleaseSelection, Session};

/// What a scan returned: the graded document, and where a saved copy went.
///
/// The report is `swp-evidence`'s, verbatim. This crate does not re-grade,
/// re-order or annotate it, because a second document of the same scan is a
/// second place for the §51 boundary — "this is provenance, not authorship" — to
/// be lost.
///
/// The exit code a shell would have got is [`Report::exit_code`], and it is a
/// property of the document rather than of this call: `0` nothing was confirmed,
/// `1` something was, `10` the scan could not have said either way.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub report: Report,
    /// `Some` only when the caller asked for a copy under
    /// `.swp/private/reports/`.
    pub saved: Option<SavedReport>,
    /// Every site the scan looked for, in the order the releases were scanned and
    /// then the order the release records them.
    ///
    /// The report carries the same counts *summed* over a release, because that is
    /// what a verdict needs; this carries them per site, which is what a caller
    /// drawing the distribution needs. It is a companion to the document rather
    /// than a second copy of it: nothing here re-grades, and no stored report ever
    /// contained these rows.
    pub sites: Vec<ScannedSite>,
}

/// One expected site, and what the candidate presented at its address.
///
/// Deliberately free of anything keyed. The location ids and the expected codes a
/// match was decided against stay inside `swp-detection`, so a row here says *that*
/// a span confirmed and how much work reaching it took — the same claim the report's
/// evidence items make — without being a list of the values that would let a caller
/// test a guess against a site that was never hit.
#[derive(Debug, Clone)]
pub struct ScannedSite {
    /// Which release this site belongs to. The report's `releases` are ordered best
    /// first; these rows are in scan order, so the id is what joins a row to its
    /// tally.
    pub release_id: String,
    /// Index into that release's site list, matching `swp inspect manifest`.
    pub site: usize,
    /// `absent`, `location-only`, `tag-confirmed` or `exact-rendering`.
    pub status: &'static str,
    /// Spans at this site's address that reached a tag comparison.
    pub probes: u32,
    /// Distinct codes those spans presented: this site's share of the draws the
    /// report's coincidence bound is computed from.
    pub distinct_codes: u32,
    /// How many tokens the confirming span covers. `255` stands for "at least 255":
    /// the count saturates rather than wrapping.
    pub found_tokens: u8,
    /// Where the match actually was, when the candidate had it at all.
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    /// The literal found there, truncated to the report hint bound — the same text
    /// an evidence item quotes as its `excerpt`.
    pub found_excerpt: Option<String>,
}

/// The name and the path of one report a run saved.
#[derive(Debug, Clone)]
pub struct SavedReport {
    /// What [`Session::read_report`](crate::Session::read_report) takes to get
    /// this document back. When two saves land in the same second the store
    /// numbers the collision, so this is the name it wrote under, which is not
    /// necessarily the one it was given.
    pub name: String,
    /// Store-relative and forward-slashed, so it is safe to print and will not
    /// reveal where the project lives.
    pub path: String,
}

impl Session {
    /// Look for this project's provenance in `candidate`: a directory, a file, or
    /// a `.zip`/`.tar`/`.tar.gz` archive.
    ///
    /// Four rules, all inherited from the CLI path this replaces:
    ///
    /// * the keys come from **this** project, never from the candidate. A tree
    ///   under examination may ship its own `.swp/` — another project's, or a
    ///   forged one — and if any part of the verdict depended on it, the examined
    ///   party would be supplying the evidence used to judge them;
    /// * the candidate is **read, not run**: no process is spawned and no manifest
    ///   interpreted (§21). An archive is unpacked into a temporary directory that
    ///   its own `Drop` removes, and the only thing done to the bytes inside is
    ///   parsing;
    /// * **every release the project has** is a suspect unless the caller narrows
    ///   the selection, because a copy could have come from any of them and
    ///   picking one silently would be a claim about which;
    /// * grading is [`Report::build`]'s, in `swp-evidence`, and what comes back is
    ///   that document (`SWP-1-report-v2`) unchanged.
    ///
    /// `save` writes the document under `.swp/private/reports/`: it names your
    /// source paths and the sites you protect, so it belongs with the secret and
    /// not with the release.
    pub fn scan(
        &self,
        candidate: &Path,
        releases: &ReleaseSelection,
        save: bool,
    ) -> Result<ScanOutcome, SwpError> {
        let limits = self.limits();
        let loaded = self.loaded(releases)?;
        let indexes = self.indexes(&loaded)?;
        let opened = swp_detection::input::open(candidate, &limits)?;
        let detection = swp_detection::scan_against(&opened, &indexes, &limits)?;
        let at = Timestamp::now_utc();
        let report = Report::build(&detection, "scan", &at.to_rfc3339(), &crate::banner());
        let saved = if save {
            let stem = format!("scan-{}", at.filename_stem());
            let path = self
                .store()
                .save_report(&stem, report.to_json().as_bytes())?;
            let name = written_name(&path, &stem);
            Some(SavedReport { name, path })
        } else {
            None
        };
        Ok(ScanOutcome {
            report,
            saved,
            sites: scan_sites(&detection),
        })
    }
}

/// The per-site rows, with their release's id attached.
///
/// The detection has already decided what each site is — this copies the counts out
/// of its rows and nothing else, so a site graded `absent` here is graded `absent`
/// in the document.
fn scan_sites(detection: &swp_detection::Detection) -> Vec<ScannedSite> {
    detection
        .releases
        .iter()
        .flat_map(|release| {
            let id = release.release_id.to_string();
            release.sites.iter().map(move |site| ScannedSite {
                release_id: id.clone(),
                site: site.site,
                status: site.status.as_str(),
                probes: site.probes,
                distinct_codes: site.distinct_codes,
                found_tokens: site.found_tokens,
                found_in: site.found_in.clone(),
                found_line: site.found_line,
                found_excerpt: site.found_text.clone(),
            })
        })
        .collect()
}

/// The store-relative name a save actually went under.
///
/// `Store::save_report` numbers a collision rather than overwriting, so the name
/// to hand back is the one in the path it returned and not the one that was asked
/// for — and that name is the one [`Session::read_report`] accepts.
fn written_name(path: &str, asked_for: &str) -> String {
    path.rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".json"))
        .unwrap_or(asked_for)
        .to_string()
}
