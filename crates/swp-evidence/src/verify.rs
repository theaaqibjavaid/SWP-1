//! `SWP-1-verify-v1` — the answer to "is the tree I am standing in still the tree
//! I protected?", as a document rather than as a terminal rendering.
//!
//! This model used to live in the CLI, which was honest about it being one
//! command's output and unhelpful about everything else: a report is evidence, and
//! §19 keeps evidence per release, so the shape of a verification answer belongs
//! with the crate that owns what a scan means — not with the program that happens
//! to print it. The fields, their order, their names and their wording are
//! unchanged by the move; a document written by the old code and one written by
//! this differ in nothing.
//!
//! ## What a verification is not
//!
//! It is not a scan of the project's own root, reported under a different name. A
//! scan answers "is my provenance present in this artifact?" and grades what it
//! finds on the §12 ladder; this answers "did *every* site of *one* release
//! survive?", which is a per-site accounting with no ladder in it. The three
//! verdicts are exhaustive over the sites a release recorded:
//!
//! ```text
//! INTACT         every site still carries its code
//! INCOMPLETE     some do not, and the whole tree was examined
//! INCONCLUSIVE   some do not, and part of the tree was never read
//! ```
//!
//! The last two differ by nothing about the watermark and everything about the
//! claim a caller may make, which is why [`Verdict`] is a verdict and not a count.
//!
//! ## What this document does not print
//!
//! No location ids, no `original`/`rendered` literals, no expected tags. A site is
//! named by the file and line it was recorded at and by its family and width,
//! which is enough to go look at it, and enough again for a document that exists
//! in CI logs and build artifacts to be a copy of the watermark — which is the one
//! thing §29 forbids. `.swp/private/manifests/<release>.json` holds the full
//! record.

use serde::Serialize;
use swp_core::error::ErrorCode;
use swp_core::id::{ProjectId, ReleaseId};
use swp_core::SWP_PROTOCOL_NAME;
use swp_detection::{Detection, ReleaseDetection, SiteMatch, SiteStatus};
use swp_identity::ReleaseRecord;

/// The `schema` field below, and the string a reader of a saved report matches on.
pub const SCHEMA: &str = "SWP-1-verify-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Every site of the release is present with its code.
    Intact,
    /// Some site is not, and the tree was read completely enough to say so.
    Incomplete,
    /// Some site is not, and part of the tree was never examined.
    Inconclusive,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Intact => "INTACT",
            Verdict::Incomplete => "INCOMPLETE",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }

    /// The exit code the command that renders this document returns.
    ///
    /// It is a property of the verdict rather than of a process because a caller
    /// that branches on a *stored* verification reads the same three words and
    /// needs the same three answers; `swp report` still exits `0` for a re-render.
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Intact => 0,
            Verdict::Incomplete => ErrorCode::ReleaseMismatch.exit_code(),
            Verdict::Inconclusive => ErrorCode::InsufficientEvidence.exit_code(),
        }
    }
}

/// One site of the release, and whether it is still there.
#[derive(Debug, Serialize)]
pub struct SiteRow {
    /// Index into the release's site list, matching `swp inspect manifest`.
    pub site: usize,
    /// Where this site was when the release was made. A hint for a human, never a
    /// lookup key — a site that moved is still the same site.
    pub file: String,
    pub line_hint: u32,
    pub language: String,
    pub adapter: String,
    pub class: &'static str,
    pub family: &'static str,
    pub width: u8,
    pub status: &'static str,
    /// Which of the four keyed radii the tree reproduced.
    pub slots: Vec<&'static str>,
    /// Where the site was actually found, when that differs from `file`.
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    pub refactored: bool,
    pub moved: bool,
}

impl SiteRow {
    /// Whether this row is watermark evidence, read off its own status.
    ///
    /// A caller that has the document but not the [`SiteMatch`]es the rows were
    /// built from still needs to answer "which sites are not carrying their code",
    /// so the question goes through [`SiteStatus::is_watermark`] — the one place
    /// the line is drawn — and an unknown word is not evidence.
    pub fn confirmed(&self) -> bool {
        SiteStatus::parse(self.status).is_some_and(|s| s.is_watermark())
    }

    fn of(site: usize, s: &SiteMatch) -> SiteRow {
        SiteRow {
            site,
            file: s.manifest_file.clone(),
            line_hint: s.manifest_line,
            language: s.language.clone(),
            adapter: s.adapter.clone(),
            class: s.class.as_str(),
            family: s.family.as_str(),
            width: s.width,
            status: s.status.as_str(),
            slots: s.slots.iter().map(|k| k.as_str()).collect(),
            found_in: s.found_in.clone(),
            found_line: s.found_line,
            refactored: s.refactored(),
            moved: s.moved(),
        }
    }
}

/// `SWP-1-verify-v1`.
#[derive(Debug, Serialize)]
pub struct VerifyDocument {
    pub schema: &'static str,
    pub protocol: &'static str,
    pub project_id: String,
    pub display_name: String,
    pub tree: String,
    pub release_id: String,
    pub release_created_at: String,
    /// The label the release recorded for its source (`--revision`, or a git ref
    /// it was given), or `None` when it recorded the content fingerprint instead:
    /// `SourceRevision::Content::as_str()` is `None`, so a content-derived release
    /// has no revision here — never the word `content`. Display metadata only.
    pub revision: Option<String>,
    /// Whether the release's manifest authenticated against the identity in
    /// `.swp/public/identity.json` — the precondition for every claim below.
    pub manifest_authenticated: bool,
    pub sites_expected: usize,
    pub sites_confirmed: usize,
    pub sites_exact: usize,
    pub sites_stripped: usize,
    pub sites_absent: usize,
    pub sites_moved: usize,
    pub sites_refactored: usize,
    pub tag_bits: u8,
    pub confirmed_bits: u32,
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    /// `"match"`, `"no-match"` or `"not-comparable"`: did the tree hash to the
    /// §16 fingerprint this release published?
    pub fingerprint: String,
    pub fingerprint_expected: String,
    pub verdict: Verdict,
    /// True when some of the tree was never read, which is what separates
    /// `INCOMPLETE` from `INCONCLUSIVE`.
    pub partial: bool,
    pub sites: Vec<SiteRow>,
    /// Rows the text rendering left out, counted rather than hidden.
    pub omitted_rows: usize,
    pub omissions: Vec<String>,
    pub notes: Vec<String>,
    pub report_saved: Option<String>,
    pub limitations: Vec<String>,
    pub next: Vec<String>,
    pub exit_code: i32,
}

/// Everything [`grade`] reads that is not already in the detection: who asked, and
/// what the caller did around the scan.
pub struct Verification<'a> {
    pub detection: &'a Detection,
    /// The one release this verification is about, as the detector saw it.
    pub found: &'a ReleaseDetection,
    pub project_id: &'a ProjectId,
    pub display_name: &'a str,
    /// How the tree being verified was described by the code that opened it.
    pub tree: &'a str,
    /// The authenticated public record of the release, for its time and label.
    pub record: &'a ReleaseRecord,
    /// The fingerprint the release published, which the detector compared the tree
    /// against but does not itself carry into [`Detection`].
    pub fingerprint_expected: &'a str,
    /// Rows the rendering window left out. A document always holds them all; this
    /// count is the text rendering's admission that it did not print them.
    pub omitted_rows: usize,
    /// Where `--save` wrote the report, when it did.
    pub report_saved: Option<String>,
}

/// Turn a scan of the project's own tree against one of its own releases into the
/// document that says whether the release survived.
pub fn grade(v: &Verification) -> VerifyDocument {
    let rows: Vec<SiteRow> = v
        .found
        .sites
        .iter()
        .map(|s| SiteRow::of(s.site, s))
        .collect();
    let confirmed = v.found.confirmed();
    let verdict = if confirmed == rows.len() {
        Verdict::Intact
    } else if v.detection.partial {
        Verdict::Inconclusive
    } else {
        Verdict::Incomplete
    };
    VerifyDocument {
        schema: SCHEMA,
        protocol: SWP_PROTOCOL_NAME,
        project_id: v.project_id.to_string(),
        display_name: v.display_name.to_string(),
        tree: v.tree.to_string(),
        release_id: v.found.release_id.to_string(),
        release_created_at: v.record.created_at.to_rfc3339(),
        revision: v.record.source_revision.as_str().map(|s| s.to_string()),
        manifest_authenticated: true,
        sites_expected: rows.len(),
        sites_confirmed: confirmed,
        sites_exact: v
            .found
            .sites
            .iter()
            .filter(|s| s.status == SiteStatus::ExactRendering)
            .count(),
        sites_stripped: v.found.stripped(),
        sites_absent: v.found.absent(),
        sites_moved: v.found.moved(),
        sites_refactored: v.found.refactored(),
        tag_bits: v.found.tag_bits,
        confirmed_bits: v.found.confirmed_bits(),
        files_scanned: v.detection.files_scanned,
        bytes_scanned: v.detection.bytes_scanned,
        fingerprint: v.found.fingerprint.as_str().to_string(),
        fingerprint_expected: v.fingerprint_expected.to_string(),
        verdict,
        partial: v.detection.partial,
        sites: rows,
        omitted_rows: v.omitted_rows,
        omissions: v.detection.omissions.clone(),
        notes: v.detection.notes.clone(),
        report_saved: v.report_saved.clone(),
        limitations: limitations(verdict),
        next: next_steps(verdict, &v.found.release_id),
        exit_code: verdict.exit_code(),
    }
}

fn limitations(verdict: Verdict) -> Vec<String> {
    let mut out = vec![
        "a site that carries its code is a statement about this artifact, not about who wrote \
         it or what rights attach to it",
        "an absent site means the watermark is not here, which a deleted function, a formatter \
         that removed a literal and a deliberate strip all produce identically",
        "the fingerprint is a hash of the whole tree: it can say no-match while every site is \
         intact, because ordinary edits change the tree hash without touching a watermark",
    ];
    if verdict == Verdict::Inconclusive {
        out.push(
            "part of this tree was never examined (see notes), so a site counted absent here \
             may simply be in a file the scan refused to read",
        );
    }
    out.into_iter().map(|s| s.to_string()).collect()
}

fn next_steps(verdict: Verdict, release: &ReleaseId) -> Vec<String> {
    let mut out = vec![format!("swp inspect manifest --release {release}")];
    match verdict {
        Verdict::Intact => {
            out.push("swp scan <candidate> --format json".to_string());
        }
        Verdict::Incomplete | Verdict::Inconclusive => {
            out.push("swp protect".to_string());
            out.push(
                "if a limit or an unread file caused the gap, raise [limits] in \
                 .swp/config.toml and re-run this command"
                    .to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_carry_their_exit_codes_and_the_document_is_named() {
        assert_eq!(SCHEMA, "SWP-1-verify-v1");
        assert_eq!(Verdict::Intact.exit_code(), 0);
        assert_eq!(
            Verdict::Incomplete.exit_code(),
            ErrorCode::ReleaseMismatch.exit_code()
        );
        assert_eq!(
            Verdict::Inconclusive.exit_code(),
            ErrorCode::InsufficientEvidence.exit_code()
        );
        assert_eq!(Verdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(
            serde_json::to_value(Verdict::Incomplete).unwrap(),
            "INCOMPLETE",
            "the text and the JSON must be the same three words"
        );
    }

    #[test]
    fn an_inconclusive_verdict_says_why_it_cannot_be_a_negative() {
        assert!(limitations(Verdict::Incomplete)
            .iter()
            .all(|l| !l.contains("never examined")));
        assert!(limitations(Verdict::Inconclusive)
            .iter()
            .any(|l| l.contains("never examined")));
    }

    #[test]
    fn a_site_row_names_a_site_by_hint_and_status_only() {
        // The row type is the document's only per-site surface. It must carry
        // hints and statuses and never an address, a literal or a code (§29).
        let row = SiteRow {
            site: 3,
            file: "src/a.js".to_string(),
            line_hint: 12,
            language: "javascript".to_string(),
            adapter: "tree-sitter".to_string(),
            class: "integer",
            family: "add",
            width: 4,
            status: "tag-confirmed",
            slots: vec!["statement+identifiers"],
            found_in: None,
            found_line: None,
            refactored: false,
            moved: false,
        };
        let doc = serde_json::to_value(&row).unwrap();
        assert_eq!(doc["status"], "tag-confirmed");
        assert_eq!(doc["slots"], serde_json::json!(["statement+identifiers"]));
        for forbidden in [
            "locations",
            "original",
            "rendered",
            "primary",
            "tag",
            "secret",
        ] {
            assert!(doc.get(forbidden).is_none(), "the row printed {forbidden}");
        }
        assert_eq!(
            swp_detection::SLOT_COUNT,
            4,
            "four radii per site; `slots` lists which hit"
        );
    }
}
