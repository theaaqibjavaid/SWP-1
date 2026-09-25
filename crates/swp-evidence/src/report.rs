//! The report §33 asks for: one versioned document, rendered as JSON or as text.
//!
//! JSON is the artifact and text is a view of it. That ordering is deliberate — a
//! report a user can only read cannot also be a report they can diff, archive, or
//! hand to a lawyer, and every field of the text rendering comes from the same
//! struct so the two cannot drift into telling different stories.
//!
//! ## The schema line
//!
//! `schema` is `SWP-1-report-v2` and it is checked on load, not assumed. A report
//! written by a later protocol must fail loudly when this build reads it, because
//! the fields that would be new are exactly the fields whose meaning would have
//! changed underneath: evidence levels are defined by their rules, and a rule that
//! moved would silently re-grade old evidence. That is also why this token moved
//! from `v1` to `v2` when the verdict began gating on a coincidence *probability*
//! and the document gained the two fields that record it (`draws`,
//! `coincidence_probability`): a report written under the older additive rule is not
//! a report this build should grade by the new one without saying so.
//!
//! ## Sizing
//!
//! The JSON carries every evidence item, because a truncated record is a record
//! that cannot be audited. The text rendering is the one that gets a window: it
//! prints the first [`TEXT_EVIDENCE_ITEMS`] with a count of the rest, since the
//! common failure mode of a terminal report is a finding nobody scrolled to.

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::version::SWP_PROTOCOL_NAME;
use swp_detection::Detection;

use crate::item::{self, EvidenceItem, EvidenceKind};
use crate::level::{self, Assessment, EvidenceLevel, Outcome, ReleaseTally};

/// The versioned schema name, printed first in both renderings.
pub const REPORT_SCHEMA: &str = "SWP-1-report-v2";

/// How many evidence items the text rendering lists before summarising the rest.
pub const TEXT_EVIDENCE_ITEMS: usize = 24;

/// The `run` block: who produced this, and in response to what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// `scan`, `verify`, or `report`: the command whose output this is.
    pub command: String,
    /// RFC 3339 UTC, supplied by the caller because this crate takes no clock.
    pub created_at: String,
    /// The build that wrote the document, so an old report can be re-read with the
    /// rules that produced it in hand.
    pub generator: String,
}

/// The `candidate` block: what was looked at, and how completely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// How the input was described on the command line, or where it was staged.
    pub described: String,
    /// `file`, `directory`, `zip`, `tar`, `tar.gz`, …
    pub kind: String,
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    /// True when something in the candidate was not examined.
    pub partial: bool,
}

/// The whole document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: String,
    pub protocol: String,
    pub run: Run,
    pub candidate: Candidate,
    /// `PROVENANCE_DETECTED`, `NO_PROVENANCE_DETECTED`, `INCONCLUSIVE`.
    pub result: Outcome,
    /// The §23 level: `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
    pub evidence_level: EvidenceLevel,
    /// Why that level, one sentence per rule that fired, with the measured numbers.
    pub explanation: Vec<String>,
    /// One entry per release the candidate was scanned against, strongest first.
    pub releases: Vec<ReleaseTally>,
    pub evidence: Vec<EvidenceItem>,
    /// Files the walk refused, with the reason.
    pub omissions: Vec<String>,
    /// Caveats: hypothesis caps, widths probed, containers not opened.
    pub notes: Vec<String>,
    /// The §51 boundary, carried inside the document rather than left to a README,
    /// so a forwarded report cannot lose it.
    pub limitations: Vec<String>,
}

impl Report {
    /// Build the report for one detection run.
    pub fn build(detection: &Detection, command: &str, created_at: &str, generator: &str) -> Self {
        let assessment: Assessment = level::assess(detection);
        let boundary = limitations(detection, &assessment);
        Report {
            schema: REPORT_SCHEMA.to_string(),
            protocol: SWP_PROTOCOL_NAME.to_string(),
            run: Run {
                command: command.to_string(),
                created_at: created_at.to_string(),
                generator: generator.to_string(),
            },
            candidate: Candidate {
                described: detection.described.clone(),
                kind: detection.kind.as_str().to_string(),
                files_scanned: detection.files_scanned,
                bytes_scanned: detection.bytes_scanned,
                partial: detection.partial,
            },
            result: assessment.outcome,
            evidence_level: assessment.level,
            explanation: assessment.reasons,
            releases: assessment.releases,
            evidence: item::collect(detection),
            omissions: detection.omissions.clone(),
            notes: detection.notes.clone(),
            limitations: boundary,
        }
    }

    /// What `swp scan` should exit with.
    pub fn exit_code(&self) -> i32 {
        self.result.exit_code()
    }

    /// Machine-readable form, pretty-printed with a trailing newline so the file
    /// is diffable.
    pub fn to_json(&self) -> String {
        let mut text =
            serde_json::to_string_pretty(self).expect("a report is serializable by construction");
        text.push('\n');
        text
    }

    /// Read a stored report back, refusing anything that is not this schema.
    pub fn from_json(text: &str) -> Result<Self, SwpError> {
        // The two identity fields are read out of the untyped document first, because
        // a report from another schema differs in its *fields* too, and a missing-field
        // error would call a foreign document damaged. It is not damage; it is a record
        // of arithmetic this build does not apply, and it says so.
        let declared: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("report: {e}")))?;
        if let Some(schema) = declared.get("schema").and_then(|v| v.as_str()) {
            if schema != REPORT_SCHEMA {
                return Err(SwpError::new(
                    ErrorCode::ProtocolVersionUnsupported,
                    format!("report declares schema {schema:?}; this build reads {REPORT_SCHEMA}"),
                ));
            }
        }
        if let Some(protocol) = declared.get("protocol").and_then(|v| v.as_str()) {
            if protocol != SWP_PROTOCOL_NAME {
                return Err(SwpError::new(
                    ErrorCode::ProtocolVersionUnsupported,
                    format!("report declares protocol {protocol:?}"),
                ));
            }
        }
        let report: Report = serde_json::from_value(declared)
            .map_err(|e| SwpError::invalid_manifest(format!("report: {e}")))?;
        Ok(report)
    }

    /// The human-facing rendering. `full` prints every evidence item; without it,
    /// the list is windowed and the remainder counted.
    pub fn to_text(&self, full: bool) -> String {
        self.render_text(if full {
            usize::MAX
        } else {
            TEXT_EVIDENCE_ITEMS
        })
    }

    /// As [`Report::to_text`], with the window sized by the caller — which is what
    /// `swp scan --limit <n>` asks for. Only the text is ever windowed: the JSON
    /// document stays complete, because a record with items missing from it is not
    /// an auditable record.
    pub fn to_text_items(&self, items: usize) -> String {
        self.render_text(items)
    }

    fn render_text(&self, limit: usize) -> String {
        let full = limit == usize::MAX;
        let mut out = String::new();
        out.push_str(&format!(
            "SWP-1 report · schema {} · protocol {}\n",
            self.schema, self.protocol
        ));
        out.push_str(&format!(
            "run       {} at {} by {}\n",
            self.run.command, self.run.created_at, self.run.generator
        ));
        out.push_str(&format!(
            "candidate {} ({})\n",
            swp_core::text::display_path(&self.candidate.described),
            self.candidate.kind
        ));
        out.push_str(&format!(
            "scope     {} file(s), {} byte(s){}\n",
            self.candidate.files_scanned,
            self.candidate.bytes_scanned,
            if self.candidate.partial {
                " — PARTIAL, see notes"
            } else {
                ""
            }
        ));
        out.push_str(&format!("result    {}\n", self.result.as_str()));
        out.push_str(&format!("evidence  {}\n\n", self.evidence_level.as_str()));

        for tally in &self.releases {
            out.push_str(&release_text(tally));
        }

        out.push_str("Why this level\n");
        if self.explanation.is_empty() {
            out.push_str("  (no rule fired)\n");
        }
        for reason in &self.explanation {
            out.push_str(&wrap("  ", "    ", reason));
        }

        out.push_str(&format!("\nEvidence ({} item(s))\n", self.evidence.len()));
        if self.evidence.is_empty() {
            out.push_str("  none\n");
        }
        for entry in self.evidence.iter().take(limit) {
            out.push_str(&item_text(entry));
        }
        if self.evidence.len() > limit {
            out.push_str(&format!(
                "  … and {} more; re-run with --format json, --full, or a larger --limit for the complete list\n",
                self.evidence.len() - limit
            ));
        }

        if !self.omissions.is_empty() {
            out.push_str(&format!(
                "\nSkipped ({}): not examined, so not cleared\n",
                self.omissions.len()
            ));
            for line in self
                .omissions
                .iter()
                .take(if full { usize::MAX } else { 20 })
            {
                out.push_str(&format!("  - {line}\n"));
            }
            if !full && self.omissions.len() > 20 {
                out.push_str(&format!("  … and {} more\n", self.omissions.len() - 20));
            }
        }
        if !self.notes.is_empty() {
            out.push_str("\nNotes\n");
            for note in &self.notes {
                out.push_str(&wrap("  ", "    ", note));
            }
        }
        out.push_str("\nWhat this report does not say\n");
        for line in &self.limitations {
            out.push_str(&wrap("  ", "    ", line));
        }
        out
    }
}

/// §51's prohibitions, instantiated: the generic list, plus the two things a
/// particular scan genuinely cannot rule out.
fn limitations(detection: &Detection, assessment: &Assessment) -> Vec<String> {
    let mut out = vec![
        "This is an observation about artifacts. It does not establish authorship, \
         ownership, copyright, licence status, or who typed anything."
            .to_string(),
        "A finding means the candidate contains source this tool protected, or a \
         rendering carrying a code this project's key derives. An innocent copy of a \
         protected build produces it identically to an infringing one."
            .to_string(),
        "No probability of copying is stated, because none is computed. The only \
         numbers of that kind here are the coincidence bound over the comparisons \
         actually performed and the probability of this many confirmations under it, \
         which bound chance and not anybody's conduct."
            .to_string(),
        "Absence of evidence is not evidence of absence: a rewrite that removed every \
         protected literal, or a reimplementation from memory, leaves nothing for this \
         scan to key on."
            .to_string(),
    ];
    if detection.partial {
        out.push(
            "Part of this candidate was not examined (see Notes/Skipped), so a \
             NO_PROVENANCE_DETECTED reading of it would be wrong."
                .to_string(),
        );
    }
    if assessment.level == EvidenceLevel::None && detection.releases.len() > 1 {
        out.push(format!(
            "Nothing was confirmed against any of the {} release(s) loaded. Those are the \
             only releases this scan could see; a copy from a project with no local release \
             record is invisible to it by construction.",
            detection.releases.len()
        ));
    }
    out
}

fn release_text(tally: &ReleaseTally) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Project {} · release {}\n",
        tally.project_id, tally.release_id
    ));
    out.push_str(&format!(
        "  Watermark fragments: {}/{}\n",
        tally.fragments, tally.sites
    ));
    // The name this line carried before said "structural regions", which is a
    // feature this build does not have; the number it printed was always
    // `stripped`, the count of addresses found without their code. `verify` calls
    // the same thing `address-without-code`, so this page now uses that word too.
    out.push_str(&format!("  Address without its code: {}\n", tally.stripped));
    out.push_str(&format!("  Exact renderings: {}\n", tally.exact_renderings));
    out.push_str(&format!(
        "  Present as canonicalized content only: {}\n",
        tally.canonical_only
    ));
    out.push_str(&format!(
        "  Found outside their original file: {}\n",
        tally.moved
    ));
    out.push_str(&format!(
        "  Keyed bits confirmed: {} at {} bits per site\n",
        tally.bits, tally.tag_bits
    ));
    out.push_str(&format!(
        "  Hypotheses probed: {} literal(s), {} rendering(s), {} span(s) at {} site(s) \
         reached a tag comparison\n",
        tally.literals_tried, tally.windows_tried, tally.probes, tally.sites
    ));
    out.push_str(&format!(
        "  Expected coincidental confirmations: {:.4} from {} distinct code(s) ({:.4} if every \
         span carried its own)\n",
        tally.chance,
        tally.draws,
        crate::level::union_bound_of_coincidence(tally.probes, tally.tag_bits)
    ));
    // The number the verdict was actually gated on, with the floor it had to clear, so
    // a reader sees how much room the finding left instead of taking the level's word.
    out.push_str(&format!(
        "  Probability an unrelated tree produces this many: {:.2e} (a verdict needs < \
         {:.0e})\n",
        tally.coincidence_probability,
        crate::level::COINCIDENCE_MAX_ABOVE_WEAK
    ));
    out.push_str(&format!(
        "  Fingerprint ({}): {}\n",
        tally.sites, tally.fingerprint
    ));
    out.push_str(&format!("  Evidence: {}\n\n", tally.level.as_str()));
    out
}

fn item_text(entry: &EvidenceItem) -> String {
    let where_found = match &entry.location {
        Some(r) => format!("{}:{}", r.file, r.line),
        None => "-".to_string(),
    };
    let ours = match &entry.source_region {
        Some(r) => format!(", our copy at {}:{}", r.file, r.line),
        None => String::new(),
    };
    let head = format!(
        "  [{}] {} at {}{} - {}",
        entry.id,
        entry.kind.as_str(),
        where_found,
        ours,
        entry.strength.as_str()
    );
    let mut out = head + "\n";
    out.push_str(&wrap("      ", "      ", &entry.basis));
    out
}

/// Fold a long sentence to a width, so the report stays readable in an 80-column
/// terminal without cutting any of it.
fn wrap(first: &str, rest: &str, text: &str) -> String {
    const WIDTH: usize = 76;
    let mut out = String::new();
    let mut line = String::from(first);
    let mut started = false;
    for word in text.split_whitespace() {
        if line.trim_end().len() + word.len() + 1 > WIDTH && started {
            out.push_str(line.trim_end());
            out.push('\n');
            line = rest.to_string();
        }
        line.push_str(word);
        line.push(' ');
        started = true;
    }
    if started {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Every category, with how many items of it the scan produced — which is what
/// `swp inspect evidence` prints and what the §42 matrix asserts on.
pub fn kind_counts(evidence: &[EvidenceItem]) -> Vec<(EvidenceKind, usize)> {
    EvidenceKind::ALL
        .iter()
        .map(|kind| (*kind, evidence.iter().filter(|e| e.kind == *kind).count()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_core::{FormFamily, LiteralClass, RadiusKind};
    use swp_detection::{
        FingerprintCheck, InputKind, ReleaseDetection, SiteMatch, SiteStatus, SLOT_COUNT,
    };

    fn site(status: SiteStatus, tokens: u8) -> SiteMatch {
        site_at(status, "copy/a.js", tokens)
    }

    fn site_at(status: SiteStatus, file: &str, tokens: u8) -> SiteMatch {
        SiteMatch {
            site: 0,
            manifest_file: "src/a.js".into(),
            manifest_line: 3,
            language: "javascript".into(),
            adapter: "ast".into(),
            class: LiteralClass::Integer,
            family: FormFamily::Add,
            width: 4,
            primary: RadiusKind::StatementId.code(),
            locations: [swp_core::LocationId::default(); SLOT_COUNT],
            status,
            slots: vec![RadiusKind::StatementId],
            found_in: Some(file.into()),
            found_line: Some(11),
            found_text: Some("(995 + 5)".into()),
            found_tokens: tokens,
            probes: if status == SiteStatus::Absent { 0 } else { 1 },
            distinct_codes: if status == SiteStatus::Absent { 0 } else { 1 },
        }
    }

    fn detection(releases: Vec<ReleaseDetection>, partial: bool) -> Detection {
        Detection {
            described: "./candidate".into(),
            kind: InputKind::Zip,
            releases,
            files_scanned: 3,
            bytes_scanned: 100,
            omissions: vec!["src/huge.js: over the per-file limit".into()],
            notes: vec!["extracted from a zip container".into()],
            partial,
        }
    }

    fn release(sites: Vec<SiteMatch>, fingerprint: FingerprintCheck) -> ReleaseDetection {
        ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: 4,
            sites,
            fingerprint,
            candidate_files: 3,
            literals_tried: 4000,
            windows_tried: 900,
        }
    }

    fn report() -> Report {
        Report::build(
            &detection(
                vec![release(
                    (0..8)
                        // Three candidate files, so the spread rule as well as the
                        // count rule is satisfied.
                        .map(|i| {
                            site_at(SiteStatus::ExactRendering, &format!("copy/{}.js", i / 3), 5)
                        })
                        .collect(),
                    FingerprintCheck::NotMatched,
                )],
                false,
            ),
            "scan",
            "2026-01-01T00:00:00Z",
            "swp 1.0.0",
        )
    }

    #[test]
    fn the_json_document_leads_with_the_versioned_schema_of_the_task() {
        let value: serde_json::Value = serde_json::from_str(&report().to_json()).unwrap();
        assert_eq!(value["schema"], REPORT_SCHEMA);
        assert_eq!(value["protocol"], SWP_PROTOCOL_NAME);
        assert_eq!(value["result"], "PROVENANCE_DETECTED");
        assert!(value["evidence"].is_array());
        // Eight exact renderings over eight draws at a 4-bit tag are excused by chance
        // with probability 6.2e-8, which is STRONG's floor and not VERY_STRONG's: the
        // ladder's counts said VERY_STRONG and the grade says STRONG. See
        // `level::tests::a_spread_constellation_survives_the_bound_and_is_graded_by_the_counts`.
        assert_eq!(value["evidence_level"], "STRONG", "{value:#}");
        // The numbers the verdict was gated on are in the document, not only in prose.
        let release = &value["releases"][0];
        assert_eq!(release["draws"], 8, "{release:#}");
        assert!(
            release["coincidence_probability"].as_f64().unwrap() < 1e-3,
            "{release:#}"
        );
    }

    #[test]
    fn a_report_survives_a_json_round_trip() {
        let original = report();
        let back = Report::from_json(&original.to_json()).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn a_foreign_schema_is_refused_rather_than_misread() {
        let mut text = report().to_json();
        text = text.replace(REPORT_SCHEMA, "SWP-2-report-v1");
        let e = Report::from_json(&text).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ProtocolVersionUnsupported, "{e:?}");

        let garbage = Report::from_json("{\"schema\":").unwrap_err();
        assert_eq!(garbage.code(), ErrorCode::InvalidManifest);
    }

    #[test]
    fn an_older_report_is_refused_as_older_rather_than_as_malformed() {
        // What a `1.0.0-beta.1` saved report looks like to this build: the v1 token,
        // and none of the two fields v2 added. Read as JSON it is simply missing data,
        // which would be reported as a corrupt artifact, so the schema is checked on
        // the way in and the refusal names the difference between the documents.
        let mut value: serde_json::Value =
            serde_json::from_str(&report().to_json()).expect("a report is serializable");
        value["schema"] = "SWP-1-report-v1".into();
        for release in value["releases"].as_array_mut().unwrap() {
            release.as_object_mut().unwrap().remove("draws");
            release
                .as_object_mut()
                .unwrap()
                .remove("coincidence_probability");
        }
        let e = Report::from_json(&value.to_string()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ProtocolVersionUnsupported, "{e:?}");
        assert!(e.message().contains("SWP-1-report-v1"), "{}", e.message());
    }

    #[test]
    fn the_text_rendering_carries_the_level_the_json_states() {
        let original = report();
        let text = original.to_text(false);
        assert!(text.contains("result    PROVENANCE_DETECTED"), "{text}");
        assert!(text.contains("Evidence: STRONG"), "{text}");
        assert!(text.contains("Watermark fragments: 8/8"), "{text}");
        assert!(text.contains("What this report does not say"), "{text}");
        assert!(text.contains("WATERMARK_FRAGMENT_MATCH"), "{text}");
        assert!(text.contains("Exact renderings: 8"), "{text}");
        // The bound, the draws behind it and the probability the gate compared are all
        // on the page, so the verdict can be read without trusting the level word.
        assert!(
            text.contains("Expected coincidental confirmations: 0.5000 from 8 distinct code(s)"),
            "{text}"
        );
        assert!(
            text.contains("Probability an unrelated tree produces this many: 6.22e-8"),
            "{text}"
        );
    }

    #[test]
    fn a_long_item_list_is_windowed_and_says_so() {
        let sites: Vec<SiteMatch> = (0..40).map(|_| site(SiteStatus::TagConfirmed, 1)).collect();
        let big = Report::build(
            &detection(vec![release(sites, FingerprintCheck::NotMatched)], false),
            "scan",
            "2026-01-01T00:00:00Z",
            "swp 1.0.0",
        );
        let short = big.to_text(false);
        assert!(short.contains("more; re-run with --format json"), "{short}");
        assert!(big.to_text(true).len() > short.len());
        assert_eq!(
            kind_counts(&big.evidence)
                .into_iter()
                .find(|(k, _)| *k == EvidenceKind::WatermarkFragmentMatch)
                .unwrap()
                .1,
            40
        );
    }

    #[test]
    fn a_custom_window_sizes_the_list_without_touching_the_document() {
        let sites: Vec<SiteMatch> = (0..40).map(|_| site(SiteStatus::TagConfirmed, 1)).collect();
        let big = Report::build(
            &detection(vec![release(sites, FingerprintCheck::NotMatched)], false),
            "scan",
            "2026-01-01T00:00:00Z",
            "swp 1.0.0",
        );
        // Each confirmed site reports two channels — the fragment that decoded and
        // the rename-tolerant radius it was reached through — so 40 sites publish an
        // 80-item document. The window sizes the text only; the document below it is
        // whatever the scan found.
        let total = big.evidence.len();
        assert_eq!(
            total, 80,
            "the fixture's own shape, restated so the counts mean something"
        );
        let five = big.to_text_items(5);
        assert_eq!(five.matches("\n  [").count(), 5, "{five}");
        assert!(
            five.contains(&format!("… and {} more", total - 5)),
            "{five}"
        );
        assert_eq!(big.to_text_items(5000).matches("\n  [").count(), total);
        // The default window and `--full` are both expressible through the one
        // renderer, so they cannot disagree with it.
        assert_eq!(big.to_text(false), big.to_text_items(TEXT_EVIDENCE_ITEMS));
        assert_eq!(big.to_text(true), big.to_text_items(usize::MAX));
        let value: serde_json::Value = serde_json::from_str(&big.to_json()).unwrap();
        assert_eq!(value["evidence"].as_array().unwrap().len(), total);
    }

    #[test]
    fn an_inconclusive_scan_says_which_of_the_two_negatives_it_is() {
        let d = detection(
            vec![release(
                vec![site(SiteStatus::Absent, 0)],
                FingerprintCheck::NotMatched,
            )],
            true,
        );
        let r = Report::build(&d, "scan", "2026-01-01T00:00:00Z", "swp 1.0.0");
        assert_eq!(r.result, Outcome::Inconclusive);
        assert_eq!(r.exit_code(), ErrorCode::InsufficientEvidence.exit_code());
        assert!(
            r.limitations.iter().any(|l| l.contains("not examined")),
            "{:?}",
            r.limitations
        );
    }

    #[test]
    fn wrapping_never_loses_a_word() {
        let text = "supercalifragilistic extraordinarily lengthy explanation of a basis";
        let wrapped = crate::report::wrap("  ", "    ", text);
        assert_eq!(
            wrapped.split_whitespace().collect::<Vec<_>>().join(" "),
            text
        );
        assert!(wrapped.lines().all(|l| l.len() <= 80), "{wrapped:?}");
    }
}
