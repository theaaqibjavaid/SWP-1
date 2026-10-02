//! `swp scan --compliance` — one more view over the numbers a report already holds.
//!
//! The grade answers one question about the release the report graded: are all the
//! keyed sites that release holds present in the candidate, each carrying its code?
//! Everything it prints is a field of [`Report`] or of the [`EvidenceItem`]s inside it.
//! A row is never generated from a count, because a count says how many and a reader
//! would take a table of rows as saying which — and which is not measured for a site
//! that produced no evidence at all.
//!
//! ## What the flag does not do
//!
//! It does not re-grade the verdict and it does not move the exit code: `scan` exits on
//! the outcome the detection produced, whichever flags were set. It adds no requirement
//! beyond what `swp verify` states about a tree's own release. And it cannot exceed the
//! measurement it is printed under: a complete count over a candidate that was only
//! partly examined, or one whose confirmations sit inside the coincidence bound the
//! verdict itself refused to stand on, is capped at `PARTIAL` with the reason named —
//! because a second, softer document saying MORE is exactly how an instrument starts
//! to overclaim.
//!
//! ## The document
//!
//! `--compliance` prints a `SWP-1-compliance-v1` document with the unchanged
//! `SWP-1-report-v2` report nested inside it as `report`. It is a separate schema
//! rather than an extra member of the report because the report's reader is strict: a
//! document that declared `SWP-1-report-v2` while carrying one more top-level field
//! would be rejected as damaged, which is a different claim from the one being made.
//! A reader that wants the standard report takes `.report`, which is that document
//! verbatim.

use serde::{Deserialize, Serialize};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::version::SWP_PROTOCOL_NAME;
use swp_evidence::{EvidenceItem, ReleaseTally, Report, REPORT_SCHEMA};

/// The schema this document declares. The nested report keeps its own.
pub const COMPLIANCE_SCHEMA: &str = "SWP-1-compliance-v1";

/// The grade, on the coverage of one release's keyed sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceLevel {
    /// No keyed site of that release is confirmed in the candidate.
    None,
    /// Some are, or all are but the candidate was not wholly examined.
    Partial,
    /// Every keyed site the release holds is confirmed, in a candidate that was
    /// examined completely.
    Full,
}

impl ComplianceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ComplianceLevel::None => "NONE",
            ComplianceLevel::Partial => "PARTIAL",
            ComplianceLevel::Full => "FULL",
        }
    }
}

/// The counters the grade was computed from, named as the report names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredCounts {
    /// Keyed sites the release holds — the denominator, and not the plan's site count.
    pub sites: usize,
    /// Sites whose literal carries this project's code.
    pub fragments: usize,
    /// Sites present as an address without a code.
    pub stripped: usize,
    /// Sites with no matching span.
    pub absent: usize,
    /// Confirmations that are byte-for-byte the recorded rendering.
    pub exact_renderings: usize,
    /// Confirmations reached only through the rename-tolerant radii.
    pub canonical_only: usize,
    /// Confirmations found in a file other than the one protected.
    pub moved: usize,
    /// Confirmations found as a multi-token rendering.
    pub renderings: usize,
}

/// One evidence item, as the report recorded it. `id` is the citation handle the
/// report's own evidence list uses, so a compliance row can be traced back to the
/// item it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceSite {
    pub id: String,
    pub release_id: String,
    /// `WATERMARK_FRAGMENT_MATCH`, `TOKEN_MATCH`, `STRUCTURAL_MATCH`, …
    pub kind: String,
    /// This item's own strength, copied from the report rather than re-derived.
    pub strength: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// The compliance view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceBlock {
    pub level: ComplianceLevel,
    /// The release the grade is about, or empty when the report holds none.
    pub release_id: String,
    pub measured: MeasuredCounts,
    pub sites: Vec<ComplianceSite>,
    pub notes: Vec<String>,
}

/// A `SWP-1-compliance-v1` document: the standard report, unchanged, plus the view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceReport {
    pub schema: String,
    pub protocol: String,
    pub report: Report,
    pub compliance: ComplianceBlock,
}

impl ComplianceReport {
    /// Wrap a finished report. The report is not modified on the way in.
    pub fn from_report(report: Report) -> Self {
        let compliance = compute(&report);
        ComplianceReport {
            schema: COMPLIANCE_SCHEMA.to_string(),
            protocol: SWP_PROTOCOL_NAME.to_string(),
            report,
            compliance,
        }
    }

    /// The document as JSON. Pretty, with a trailing newline, on the report's own
    /// terms: the nested report serialises exactly as `swp scan` would have.
    pub fn to_json(&self) -> Result<String, SwpError> {
        let mut text = serde_json::to_string_pretty(self).map_err(|e| {
            SwpError::new(
                ErrorCode::Internal,
                format!("could not write the compliance document: {e}"),
            )
        })?;
        text.push('\n');
        Ok(text)
    }

    /// Read a compliance document back and hand out the report inside it.
    ///
    /// The schema check comes first and it is strict in one direction only: this
    /// build reads `SWP-1-compliance-v1`, and a plain report is a report, not a
    /// damaged compliance view.
    pub fn from_json(text: &str) -> Result<Report, SwpError> {
        let declared: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("compliance: {e}")))?;
        let schema = declared
            .get("schema")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if schema != COMPLIANCE_SCHEMA {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "document declares schema {schema:?}; this build reads {COMPLIANCE_SCHEMA:?} \
                     for a compliance view and {REPORT_SCHEMA:?} for a report"
                ),
            ));
        }
        let doc: ComplianceReport = serde_json::from_value(declared)
            .map_err(|e| SwpError::invalid_manifest(format!("compliance: {e}")))?;
        Ok(doc.report)
    }
}

/// The grade: the two counters, and the two things that decide whether a complete
/// count is a complete coverage — whether the candidate was read whole, and whether
/// the report treats these confirmations as more than chance.
///
/// `sites == 0` is `None` rather than a vacuous `Full`: a release holding no keyed
/// site has nothing to be complete about, and printing FULL for it would be a grade
/// about the shape of a store.
///
/// The last condition is what stops this block outranking the verdict it sits under.
/// A release can hold one keyed site, have that site confirmed, and still be read as
/// `INCONCLUSIVE` because one confirmation at four tag bits is inside the coincidence
/// bound (§12). Coverage measured that way is a count and not a finding, so the grade
/// stops at `PARTIAL` and says which of the two holds.
fn grade(
    counts: &MeasuredCounts,
    examined_completely: bool,
    beyond_chance: bool,
) -> ComplianceLevel {
    if counts.sites == 0 || counts.fragments == 0 {
        return ComplianceLevel::None;
    }
    if counts.fragments < counts.sites {
        return ComplianceLevel::Partial;
    }
    if examined_completely && beyond_chance {
        ComplianceLevel::Full
    } else {
        ComplianceLevel::Partial
    }
}

/// The release the grade is about: the report's own lead, which is the release its
/// verdict and its evidence level were reached on. Choosing a different one here
/// would have the block and the document it came from agreeing on nothing.
fn lead(report: &Report) -> Option<&ReleaseTally> {
    report.releases.first()
}

fn compute(report: &Report) -> ComplianceBlock {
    let top = lead(report);
    let empty = MeasuredCounts {
        sites: 0,
        fragments: 0,
        stripped: 0,
        absent: 0,
        exact_renderings: 0,
        canonical_only: 0,
        moved: 0,
        renderings: 0,
    };
    let (release_id, measured) = match top {
        Some(t) => (
            t.release_id.clone(),
            MeasuredCounts {
                sites: t.sites,
                fragments: t.fragments,
                stripped: t.stripped,
                absent: t.absent,
                exact_renderings: t.exact_renderings,
                canonical_only: t.canonical_only,
                moved: t.moved,
                renderings: t.renderings,
            },
        ),
        None => (String::new(), empty),
    };

    let examined_completely = !report.candidate.partial;
    let beyond_chance = top.is_some_and(ReleaseTally::clears_chance);
    let level = grade(&measured, examined_completely, beyond_chance);

    // One row per evidence item of that release. Absent sites have no item, and are
    // counted in `measured.absent` rather than invented here.
    let sites: Vec<ComplianceSite> = report
        .evidence
        .iter()
        .filter(|item| release_id.is_empty() || item.release_id == release_id)
        .map(row)
        .collect();

    let mut notes = vec![
        "This is a coverage grade over the keyed sites the named release holds. It says \
         nothing about who wrote the copy, and §51 still applies."
            .to_string(),
    ];
    if release_id.is_empty() {
        notes
            .push("the report holds no release, so there are no keyed sites to cover.".to_string());
    } else {
        notes.push(format!(
            "sites: {}, confirmed with their code: {} — the denominator is {}'s keyed sites, \
             not the sites its plan proposed.",
            measured.sites, measured.fragments, release_id
        ));
    }
    if level == ComplianceLevel::Partial
        && measured.sites > 0
        && measured.fragments == measured.sites
    {
        // Both caps apply to a count that looks complete, and each says which of the
        // two measurements kept the grade from being one.
        if !examined_completely {
            notes.push(
                "the candidate was not examined completely, so a site counted as absent here \
                 may only be unexamined; the grade is capped rather than rounded up"
                    .to_string(),
            );
        }
        if !beyond_chance {
            if let Some(t) = top {
                notes.push(format!(
                    "every keyed site of {} that this scan counted carries its code, but the \
                     report does not treat that as a finding: its coincidence probability is \
                     {:.1e} against the 1e-3 bound, at level {}. A complete-coverage grade \
                     would claim more than the verdict above it does.",
                    t.release_id,
                    t.coincidence_probability,
                    t.level.as_str()
                ));
            }
        }
    }
    if measured.sites == 0 && !release_id.is_empty() {
        notes.push(
            "the named release holds no keyed site for this candidate, so there is no \
             coverage to grade"
                .to_string(),
        );
    }

    ComplianceBlock {
        level,
        release_id,
        measured,
        sites,
        notes,
    }
}

fn row(item: &EvidenceItem) -> ComplianceSite {
    ComplianceSite {
        id: item.id.clone(),
        release_id: item.release_id.clone(),
        kind: item.kind.as_str().to_string(),
        strength: item.strength.as_str().to_string(),
        file: item.location.as_ref().map(|r| r.file.clone()),
        line: item.location.as_ref().map(|r| r.line),
    }
}

/// The compliance block as text, appended after the report's own rendering.
pub fn render_text(block: &ComplianceBlock, limit: usize) -> Vec<String> {
    let mut lines = vec![
        format!("Compliance grade: {}", block.level.as_str()),
        format!(
            "  release   {}",
            if block.release_id.is_empty() {
                "— none in this report"
            } else {
                block.release_id.as_str()
            }
        ),
        format!(
            "  sites     {} held, {} confirmed, {} address without code, {} absent",
            block.measured.sites,
            block.measured.fragments,
            block.measured.stripped,
            block.measured.absent
        ),
        format!(
            "  reached   {} exact, {} canonical-only, {} moved, {} as renderings",
            block.measured.exact_renderings,
            block.measured.canonical_only,
            block.measured.moved,
            block.measured.renderings
        ),
    ];
    if !block.sites.is_empty() {
        lines.push(
            "  evidence  id       kind                          strength   where".to_string(),
        );
        for site in block.sites.iter().take(limit) {
            let where_line = match (&site.file, site.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                _ => "—".to_string(),
            };
            lines.push(format!(
                "            {:<8} {:<27} {:<9} {}",
                site.id, site.kind, site.strength, where_line
            ));
        }
        if block.sites.len() > limit {
            lines.push(format!(
                "            … and {} more; re-run with --full for the complete list",
                block.sites.len() - limit
            ));
        }
    } else {
        lines.push("  evidence  no evidence item to list for that release".to_string());
    }
    for note in &block.notes {
        lines.push(format!("  · {note}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(sites: usize, fragments: usize) -> MeasuredCounts {
        MeasuredCounts {
            sites,
            fragments,
            stripped: 0,
            absent: sites - fragments,
            exact_renderings: fragments,
            canonical_only: 0,
            moved: 0,
            renderings: 0,
        }
    }

    #[test]
    fn a_release_holding_no_site_is_not_reported_complete() {
        assert_eq!(grade(&counts(0, 0), true, true), ComplianceLevel::None);
    }

    #[test]
    fn nothing_confirmed_is_none() {
        assert_eq!(grade(&counts(6, 0), true, true), ComplianceLevel::None);
    }

    #[test]
    fn some_but_not_all_is_partial() {
        assert_eq!(grade(&counts(6, 3), true, true), ComplianceLevel::Partial);
    }

    #[test]
    fn all_confirmed_in_a_fully_examined_candidate_is_full() {
        assert_eq!(grade(&counts(6, 6), true, true), ComplianceLevel::Full);
    }

    #[test]
    fn a_partly_examined_candidate_caps_the_grade() {
        // The point of the cap: `absent` cannot be told apart from `not read` here, so
        // a complete-looking count over an incomplete reading is not a full grade.
        assert_eq!(grade(&counts(6, 6), false, true), ComplianceLevel::Partial);
    }

    #[test]
    fn confirmations_the_report_does_not_call_a_findings_cap_the_grade() {
        // The other half of the same property: a count can be complete and still be
        // one the verdict above it refuses to stand on. The block may not be the place
        // where that refusal is quietly reversed.
        assert_eq!(grade(&counts(6, 6), true, false), ComplianceLevel::Partial);
    }

    use swp_evidence::{
        Candidate, EvidenceKind, EvidenceLevel, Outcome, Region, ReleaseTally, Run,
    };

    fn tally(release_id: &str, sites: usize, fragments: usize) -> ReleaseTally {
        ReleaseTally {
            project_id: "swp1-project".into(),
            release_id: release_id.into(),
            sites,
            fragments,
            stripped: 0,
            absent: sites - fragments,
            exact_renderings: fragments,
            canonical_only: 0,
            moved: 0,
            renderings: 0,
            files: 1,
            bits: (fragments * 32) as u32,
            tag_bits: 4,
            probes: 100,
            draws: fragments as u32,
            literals_tried: 10,
            windows_tried: 0,
            fingerprint: "no-match".into(),
            chance: 0.0,
            guarantee: fragments as f64,
            coincidence_probability: 0.0,
            level: EvidenceLevel::Moderate,
            reasons: vec!["measured".into()],
        }
    }

    fn item(id: &str, release_id: &str) -> EvidenceItem {
        EvidenceItem {
            id: id.into(),
            kind: EvidenceKind::WatermarkFragmentMatch,
            project_id: "swp1-project".into(),
            release_id: release_id.into(),
            location: Some(Region {
                file: "src/app.js".into(),
                line: 12,
                excerpt: None,
                tokens: None,
                radii: vec![],
            }),
            source_region: None,
            basis: "the keyed address is present and the literal carries the code".into(),
            strength: EvidenceLevel::Moderate,
            protocol: "SWP-1".into(),
            schema: 2,
        }
    }

    fn report(partial: bool, releases: Vec<ReleaseTally>, items: Vec<EvidenceItem>) -> Report {
        Report {
            schema: REPORT_SCHEMA.to_string(),
            protocol: SWP_PROTOCOL_NAME.to_string(),
            run: Run {
                command: "scan".into(),
                created_at: "2026-10-02T00:00:00Z".into(),
                generator: "swp-cli test".into(),
            },
            candidate: Candidate {
                described: "candidate".into(),
                kind: "directory".into(),
                files_scanned: 3,
                bytes_scanned: 300,
                partial,
            },
            result: match releases.first() {
                // The same mapping `swp-evidence`'s ladder makes: a lead the arithmetic
                // clears is a finding, a lead it does not is inconclusive, and nothing
                // confirmed is a clean reading.
                Some(t) if t.clears_chance() => Outcome::ProvenanceDetected,
                Some(_) => Outcome::Inconclusive,
                None => Outcome::NoProvenanceDetected,
            },
            evidence_level: if releases.is_empty() {
                EvidenceLevel::None
            } else {
                EvidenceLevel::Moderate
            },
            explanation: vec![],
            releases,
            evidence: items,
            omissions: if partial {
                vec!["src/big.js: too large".into()]
            } else {
                vec![]
            },
            notes: vec![],
            limitations: vec![],
        }
    }

    #[test]
    fn the_grade_is_a_separate_document_with_the_report_inside_it() {
        let original = report(
            false,
            vec![tally("rel-1", 2, 2)],
            vec![item("EV-001", "rel-1"), item("EV-002", "rel-1")],
        );
        let doc = ComplianceReport::from_report(original.clone());
        let text = doc.to_json().unwrap();
        let declared: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(declared["schema"], COMPLIANCE_SCHEMA);
        // The nested report is the standard document verbatim, so a reader that only
        // wants the report takes `.report` and needs no second implementation.
        assert_eq!(declared["report"]["schema"], REPORT_SCHEMA);
        assert_eq!(declared["compliance"]["level"], "FULL");
        assert_eq!(ComplianceReport::from_json(&text).unwrap(), original);
    }

    #[test]
    fn a_plain_report_is_not_read_as_a_compliance_document() {
        // Both documents are strict about unknown fields, so the only way to print a
        // grade inside a `SWP-1-report-v2` shape was to break the reader. This is the
        // refusal that keeps the two apart, and it names both schemas.
        let text = report(false, vec![], vec![]).to_json();
        let error = ComplianceReport::from_json(&text).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProtocolVersionUnsupported);
        let message = error.message();
        assert!(message.contains(COMPLIANCE_SCHEMA), "{message}");
        assert!(message.contains(REPORT_SCHEMA), "{message}");
    }

    #[test]
    fn the_rows_are_the_reports_evidence_items_and_no_more() {
        let doc = ComplianceReport::from_report(report(
            false,
            vec![tally("rel-1", 4, 2)],
            vec![item("EV-001", "rel-1"), item("EV-002", "rel-1")],
        ));
        let block = &doc.compliance;
        assert_eq!(block.level, ComplianceLevel::Partial);
        assert_eq!(
            block.sites.len(),
            2,
            "one row per item, not per counted site"
        );
        assert_eq!(block.measured.sites, 4);
        assert_eq!(block.measured.absent, 2);
        let ids: Vec<&str> = block.sites.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["EV-001", "EV-002"]);
        assert_eq!(block.sites[0].file.as_deref(), Some("src/app.js"));
    }

    #[test]
    fn an_inconclusive_reading_is_never_graded_full() {
        // Every site of the release carried its code, and the walk still refused a
        // file: the candidate-visible count cannot be a statement about the copy.
        let doc = ComplianceReport::from_report(report(
            true,
            vec![tally("rel-1", 2, 2)],
            vec![item("EV-001", "rel-1"), item("EV-002", "rel-1")],
        ));
        assert_eq!(doc.compliance.level, ComplianceLevel::Partial);
        assert!(
            doc.compliance
                .notes
                .iter()
                .any(|n| n.contains("not examined completely")),
            "{:?}",
            doc.compliance.notes
        );
    }

    #[test]
    fn a_complete_count_the_verdict_does_not_stand_on_is_not_graded_full() {
        // This is the reading a real one-site release at four tag bits produces: every
        // keyed site confirmed, nothing skipped, and a verdict of INCONCLUSIVE because
        // one confirmation is inside the coincidence bound. The grade follows the
        // verdict and prints the number that made it do so.
        let mut t = tally("rel-1", 1, 1);
        t.level = EvidenceLevel::Weak;
        t.coincidence_probability = 0.0605;
        let doc =
            ComplianceReport::from_report(report(false, vec![t], vec![item("EV-001", "rel-1")]));
        assert_eq!(doc.compliance.level, ComplianceLevel::Partial);
        let note = doc
            .compliance
            .notes
            .iter()
            .find(|n| n.contains("does not treat that as a finding"))
            .expect("the cap says which measurement held the grade back");
        assert!(note.contains("rel-1"), "{note}");
        assert!(note.contains("6.0e-2"), "{note}");
        assert!(note.contains("WEAK"), "{note}");
    }

    #[test]
    fn a_report_with_no_release_grades_nothing_and_names_nobody() {
        let doc = ComplianceReport::from_report(report(false, vec![], vec![]));
        assert_eq!(doc.compliance.level, ComplianceLevel::None);
        assert!(doc.compliance.release_id.is_empty());
        assert_eq!(doc.compliance.measured.sites, 0);
        assert!(doc.compliance.sites.is_empty());
    }

    #[test]
    fn the_grade_is_about_the_release_the_report_graded() {
        // Two releases, and the second holds more keyed sites. The block still grades
        // the report's lead — the release its level and its verdict were reached on —
        // because a grade about a different release than the document it is printed
        // under is two answers to one question.
        let doc = ComplianceReport::from_report(report(
            false,
            vec![tally("rel-1", 3, 3), tally("rel-other", 6, 1)],
            vec![
                item("EV-001", "rel-1"),
                item("EV-002", "rel-1"),
                item("EV-003", "rel-other"),
            ],
        ));
        assert_eq!(doc.compliance.release_id, "rel-1");
        assert_eq!(doc.compliance.level, ComplianceLevel::Full);
        assert_eq!(doc.compliance.measured.sites, 3);
        assert_eq!(
            doc.compliance.sites.len(),
            2,
            "the third item belongs to the other release"
        );
    }

    #[test]
    fn the_text_rendering_lists_the_measured_counts() {
        let doc = ComplianceReport::from_report(report(
            false,
            vec![tally("rel-1", 4, 3)],
            (1..=4)
                .map(|n| item(&format!("EV-00{n}"), "rel-1"))
                .collect(),
        ));
        let lines = render_text(&doc.compliance, 3);
        let text = lines.join("\n");
        assert!(text.contains("Compliance grade: PARTIAL"), "{text}");
        assert!(text.contains("sites     4 held, 3 confirmed"), "{text}");
        assert!(text.contains("EV-001"), "{text}");
        assert!(text.contains("and 1 more"), "{text}");
        assert!(!text.contains("EV-004"), "{text}");
        assert!(render_text(&doc.compliance, usize::MAX)
            .iter()
            .any(|l| l.contains("EV-004")));
    }

    #[test]
    fn the_document_carries_no_key_material() {
        // The grade is a view over a report, and a report is already swept for secret
        // bytes; this asserts the fields the view adds are the ones it claims.
        let doc = ComplianceReport::from_report(report(
            false,
            vec![tally("rel-1", 1, 1)],
            vec![item("EV-001", "rel-1")],
        ));
        let text = doc.to_json().unwrap();
        for field in [
            "anchor_key",
            "root",
            "expected_tag",
            "keyed_address",
            "secret",
        ] {
            assert!(!text.contains(field), "{field} appeared in the document");
        }
    }
}
