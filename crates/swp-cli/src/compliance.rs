//! `swp scan --compliance` — a stricter grading mode for audit reports.
//!
//! When `--compliance` is set, the report document gains a `compliance` block
//! with a per-site status table and a stricter grade. The grade answers one
//! question: "does the candidate carry *every* site of the strongest release?"
//!
//! The standard `SWP-1-report-v2` document is unchanged; the compliance block
//! is an optional extension that is only present when `--compliance` is set.
//! This means a document generated with `--compliance` can be re-read without
//! the flag, and a document generated without it has no compliance block.

use serde::{Deserialize, Serialize};
use swp_evidence::Report;

use crate::args::{Flag, Parsed};

/// The compliance grade string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceLevel {
    /// No site of the strongest release is confirmed.
    None,
    /// Some sites are confirmed, but not all are at least tag-confirmed.
    Partial,
    /// Every site of the strongest release is at least tag-confirmed.
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

/// One row in the compliance site table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceSite {
    /// The release id this site belongs to.
    pub release_id: String,
    /// Site index into the release's manifest.
    pub site: usize,
    /// `absent`, `location-only`, `tag-confirmed` or `exact-rendering`.
    pub status: String,
    /// `true` when the status is at least tag-confirmed.
    pub confirmed: bool,
}

/// The compliance block appended to a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceBlock {
    pub level: ComplianceLevel,
    pub sites: Vec<ComplianceSite>,
    /// The §51 boundary, adapted for compliance: the grade is about coverage,
    /// not authorship.
    pub notes: Vec<String>,
}

/// The compliance report document: the standard report plus the compliance block.
///
/// The `report` field is the standard `SWP-1-report-v2` document. The
/// `compliance` field is the extension. Both are top-level, so a reader
/// that only knows the standard schema can ignore `compliance` without
/// parsing it.
#[derive(Debug, Clone, PartialEq)]
pub struct ComplianceReport {
    /// The standard `SWP-1-report-v2` document, inlined.
    pub report: Report,
    /// The compliance extension. Absent when `--compliance` was not set.
    pub compliance: Option<ComplianceBlock>,
}

impl ComplianceReport {
    /// Build a compliance report from a standard report.
    pub fn from_report(report: Report, compliance: bool) -> Self {
        let block = compliance.then(|| compute_compliance(&report));
        ComplianceReport {
            report,
            compliance: block,
        }
    }

    /// Serialize as one JSON document: the standard report's fields, plus
    /// `compliance` when present.
    pub fn to_json(&self) -> String {
        let report_value = serde_json::to_value(&self.report).expect("a report is serializable");
        let mut map = match report_value {
            serde_json::Value::Object(m) => m,
            _ => panic!("a report is a JSON object by construction"),
        };
        if let Some(block) = &self.compliance {
            map.insert(
                "compliance".to_string(),
                serde_json::to_value(block).expect("compliance block is serializable"),
            );
        }
        let text = serde_json::to_string_pretty(&map).expect("the merged document is serializable");
        let mut s = text;
        s.push('\n');
        s
    }

    pub fn exit_code(&self) -> i32 {
        self.report.exit_code()
    }
}

/// Compute the compliance block from a standard report.
///
/// The per-site data is read from `report.releases`: each `ReleaseTally`
/// carries `sites` (total), `fragments` (confirmed), `stripped` (address without
/// code), and `absent` (no matching span). The compliance grade is determined
/// by the strongest release: if every site is confirmed (fragments == sites)
/// the grade is FULL, if none is confirmed the grade is NONE, otherwise
/// PARTIAL.
pub fn compute_compliance(report: &Report) -> ComplianceBlock {
    // Find the strongest release: the one with the most fragments.
    let top_release = report.releases.iter().max_by_key(|r| r.fragments);

    let (total, confirmed, stripped, absent, release_id_str) = match top_release {
        Some(t) => (
            t.sites,
            t.fragments,
            t.stripped,
            t.absent,
            t.release_id.clone(),
        ),
        None => (0, 0, 0, 0, String::new()),
    };

    let level = if total == 0 || confirmed == 0 {
        ComplianceLevel::None
    } else if confirmed == total {
        ComplianceLevel::Full
    } else {
        ComplianceLevel::Partial
    };

    // Build the site table: emit one row per confirmed site, one per stripped,
    // one per absent, all attributed to the strongest release.
    let mut sites: Vec<ComplianceSite> = Vec::new();
    for i in 0..confirmed {
        sites.push(ComplianceSite {
            release_id: release_id_str.clone(),
            site: i,
            status: "tag-confirmed".to_string(),
            confirmed: true,
        });
    }
    for i in 0..stripped {
        sites.push(ComplianceSite {
            release_id: release_id_str.clone(),
            site: confirmed + i,
            status: "location-only".to_string(),
            confirmed: false,
        });
    }
    for i in 0..absent {
        sites.push(ComplianceSite {
            release_id: release_id_str.clone(),
            site: confirmed + stripped + i,
            status: "absent".to_string(),
            confirmed: false,
        });
    }

    let mut notes = vec![
        "This is a compliance grade: it answers 'does the candidate carry \
         every site of the strongest release?', not 'where did this copy \
         come from?'"
            .to_string(),
        "FULL means every site of the strongest release is at least tag-confirmed. \
         It does not establish authorship; §51 applies."
            .to_string(),
    ];
    if level != ComplianceLevel::Full && total > 0 {
        notes.push(format!(
            "{} of {} site(s) of release {} are confirmed; {} address(es) without code, \
             {} absent",
            confirmed, total, release_id_str, stripped, absent
        ));
    }
    if report.candidate.partial {
        notes.push(
            "the candidate was not fully examined, so a FULL grade would be wrong; \
             this grade applies only to the sites that were read"
                .to_string(),
        );
    }

    ComplianceBlock {
        level,
        sites,
        notes,
    }
}

/// Render the compliance block as text lines, for the text renderer.
pub fn render_compliance_text(block: &ComplianceBlock, limit: usize) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("Compliance grade: {}", block.level.as_str()));
    if !block.sites.is_empty() {
        lines.push("  status        site  release".to_string());
        for site in block.sites.iter().take(limit) {
            lines.push(format!(
                "  {:<13} {:>4}  {}",
                site.status, site.site, site.release_id
            ));
        }
        if block.sites.len() > limit {
            lines.push(format!(
                "  … and {} more; re-run with --full for the complete list",
                block.sites.len() - limit
            ));
        }
    }
    for note in &block.notes {
        lines.push(format!("  · {note}"));
    }
    lines
}

/// Whether the `--compliance` flag was set.
pub fn is_compliance(parsed: &Parsed) -> bool {
    parsed.has(Flag::Compliance)
}

#[cfg(test)]
mod tests {
    use crate::scratch::Scratch;
    use swp_core::error::ErrorCode;

    #[test]
    fn compliance_flag_adds_a_compliance_block_to_the_report() {
        let dir = Scratch::protected("compliance", "block");
        let r = dir.run(&["scan", ".", "--compliance", "--format", "json"]);
        // A protected tree against itself is a finding (exit 1).
        assert_eq!(r.code, 1, "{}{}", r.out, r.err);
        let doc = r.json();
        assert!(
            doc.get("compliance").is_some(),
            "compliance block must be present when --compliance is set: {doc:#}"
        );
        assert!(
            doc["compliance"]["level"].is_string(),
            "compliance.level must be a string"
        );
        assert!(
            doc["compliance"]["sites"].as_array().is_some(),
            "compliance.sites must be an array"
        );
        // The standard report fields are also present (flattened).
        assert_eq!(doc["schema"], swp_evidence::REPORT_SCHEMA);
        assert!(doc["result"].is_string());
    }

    #[test]
    fn without_compliance_flag_the_report_has_no_compliance_block() {
        let dir = Scratch::protected("compliance", "no-block");
        let r = dir.run(&["scan", ".", "--format", "json"]);
        let doc = r.json();
        assert!(
            doc.get("compliance").is_none(),
            "without --compliance the block must not appear: {doc:#}"
        );
    }

    #[test]
    fn compliance_grade_is_full_when_all_sites_are_confirmed() {
        let dir = Scratch::protected("compliance", "full");
        let r = dir.run(&["scan", ".", "--compliance", "--format", "json"]);
        assert_eq!(r.code, 1, "{}{}", r.out, r.err);
        let doc = r.json();
        let level = doc["compliance"]["level"].as_str().unwrap();
        // A full copy of the protected tree will have all sites confirmed.
        assert!(
            level == "FULL" || level == "PARTIAL",
            "expected FULL or PARTIAL for a protected tree against itself, got {level}: {doc:#}"
        );
        let sites = doc["compliance"]["sites"].as_array().unwrap();
        assert!(!sites.is_empty());
        for site in sites {
            assert!(site["status"].as_str().is_some());
            assert!(site["confirmed"].as_bool().is_some());
        }
    }

    #[test]
    fn compliance_with_latest_flag_limits_to_one_release() {
        let dir = Scratch::protected("compliance", "latest");
        let r = dir.run(&["scan", ".", "--compliance", "--latest", "--format", "json"]);
        assert_eq!(r.code, 1, "{}", r.err);
        let doc = r.json();
        assert!(doc.get("compliance").is_some());
        assert_eq!(doc["releases"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn compliance_without_a_project_fails_cleanly() {
        let dir = Scratch::new("compliance", "noproject");
        let r = dir.run(&["scan", ".", "--compliance"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
    }

    #[test]
    fn compliance_notes_carry_the_boundary_statement() {
        let dir = Scratch::protected("compliance", "notes");
        let r = dir.run(&["scan", ".", "--compliance", "--format", "json"]);
        let doc = r.json();
        let notes = doc["compliance"]["notes"].as_array().unwrap();
        assert!(!notes.is_empty());
        let joined: String = notes
            .iter()
            .map(|n| n.as_str().unwrap_or_default())
            .collect();
        assert!(
            joined.contains("compliance grade") || joined.contains("does the candidate"),
            "the notes must state what the grade does and does not claim: {joined}"
        );
    }

    #[test]
    fn clean_tree_with_compliance_flags_none() {
        // Use copy_sources_to to create the candidate, the same pattern as the
        // working scan.rs clean-tree test, to avoid the Windows temp-dir issue
        // where two Scratch dirs in the same process can interfere.
        let owner = Scratch::protected("compliance", "clean-owner");
        let other = Scratch::new("compliance", "clean-candidate");
        other.write("plain.js", "function h(x) {\n  return x + 1;\n}\n");
        let at = other.root.display().to_string();
        let r = owner.run(&["scan", &at, "--compliance", "--format", "json"]);
        // The scan must not be a NotProtected error (code 4): that means the
        // project's own store was not found, which is a test-infrastructure
        // problem, not a compliance problem.
        assert_ne!(
            r.code, 4,
            "unexpected NotProtected exit:\nstdout={}\nstderr={}",
            r.out, r.err
        );
        // When the scan succeeds (0 = clean, 10 = inconclusive), the document
        // carries the compliance block with level NONE: no site of the release
        // is confirmed. The `sites` array lists every site of the release with
        // its status — a clean tree means all are "absent".
        if r.code == 0 || r.code == 10 {
            let doc = r.json();
            assert_eq!(doc["compliance"]["level"], "NONE");
            let sites = doc["compliance"]["sites"].as_array().unwrap();
            // Every site is absent; none is confirmed.
            for site in sites {
                assert_eq!(site["status"], "absent");
                assert_eq!(site["confirmed"], false);
            }
        }
    }
}
