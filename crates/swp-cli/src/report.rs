//! `swp report` — the saved reports, printed as they were graded.
//!
//! §19 asks for evidence to be kept *per release* rather than recomputed against
//! whatever the ladder believes today, and `--save` is where that evidence lands:
//! one JSON document per run under `.swp/private/reports/`. This command is the
//! read side of that store, and the one promise it keeps is that it never
//! re-grades. [`swp_evidence::Report::build`] scores a detection run; `swp report`
//! re-renders a document that was scored already, so a finding made before the
//! ladder changed still reads the way it read on the day it was made — and the
//! `generator` field says which build made it, which is the only way that
//! distinction survives.
//!
//! Two shapes, one flag list:
//!
//! * `swp report` indexes the store. Every saved document, what command wrote it,
//!   what it concluded, and which releases it names. `--release <id>` filters that
//!   list to the reports about one release, which is §19's per-release history
//!   viewed from the evidence side rather than from the release records.
//! * `swp report <name>` re-renders one. The name may be the stem the save
//!   printed, the file name, or the store-relative path: all three normalize to
//!   the same stem, and the stem goes through [`Store::report_path`] before it
//!   touches the filesystem, so `..` in it is refused rather than resolved.
//!
//! ## The document is the stored one
//!
//! In single-report mode the JSON this command emits *is* the bytes in the store,
//! which is why it serializes the [`Report`] itself rather than a re-serialization
//! of a parsed [`serde_json::Value`] — the two differ in key order, and a command
//! that rewrites the bytes of an evidence document is not one a reviewer can
//! trust to have left it alone. `--output` is therefore an export, and an export
//! that is byte-identical to the original can be diffed against it.
//!
//! ## Why this command exits 0
//!
//! The exit-code contract gives `1` to *a scan that found evidence*. Re-printing
//! last month's finding is not finding evidence now: this command observed
//! nothing, and a caller that branches on a stored result reads `result` from the
//! JSON, which is the stable half of the document. Say so in the text, because the
//! alternative is a script that thinks a re-render is a new detection.

use std::path::Path;

use serde::Serialize;
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ReleaseId;
use swp_core::SWP_PROTOCOL_NAME;
use swp_evidence::Report;
use swp_identity::Store;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

/// The `schema` field the index document carries. A re-rendered report keeps its
/// own `SWP-1-report-v1`, because it *is* that document.
const INDEX_SCHEMA: &str = "SWP-1-report-index-v1";

/// What `swp report` can emit: an index of the store, or one stored document.
#[derive(Serialize)]
#[serde(untagged)]
enum Document {
    Index(Index),
    Stored(Report),
}

/// One saved report, summarized. Every field here is read out of the stored
/// document, so the listing is only as accurate as the file it describes.
#[derive(Serialize)]
struct Row {
    /// The name `swp report <name>` takes.
    name: String,
    path: String,
    /// `scan` or `verify`: which command wrote it.
    command: String,
    created_at: String,
    generator: String,
    result: String,
    evidence_level: String,
    /// How the candidate was described on the command line.
    candidate: String,
    kind: String,
    files_scanned: u32,
    bytes_scanned: u64,
    partial: bool,
    /// The releases this report scanned against, strongest evidence first.
    releases: Vec<String>,
    evidence_items: usize,
    omissions: usize,
}

/// A file in the reports directory that is not a report this build can read.
#[derive(Serialize)]
struct Unreadable {
    name: String,
    path: String,
    error: String,
}

/// `swp report` with no argument.
#[derive(Serialize)]
struct Index {
    schema: &'static str,
    protocol: &'static str,
    project_id: String,
    display_name: String,
    /// The `--release` filter, `null` when the whole store was listed.
    release_filter: Option<String>,
    /// Files in the directory, before filtering.
    saved: usize,
    /// Reports this listing contains.
    listed: usize,
    reports: Vec<Row>,
    unreadable: Vec<Unreadable>,
    notes: Vec<String>,
    next: Vec<String>,
}

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in &project.warnings {
        sink.warn(warning);
    }
    let filter = match parsed.value(Flag::Release) {
        Some(raw) => Some(ReleaseId::new(raw)?),
        None => None,
    };
    let limit = output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let (doc, lines) = match parsed.positional.as_slice() {
        [] => {
            let index = index(&project, filter.as_ref())?;
            let lines = index_text(&index, limit);
            (Document::Index(index), lines)
        }
        [one] => {
            let (report, at, stem) = read_one(&project.store, one)?;
            if let Some(id) = &filter {
                if !report.releases.iter().any(|t| t.release_id == id.as_str()) {
                    sink.warn(&format!(
                        "{stem} does not mention release {id}; it is printed anyway. \
                         `swp report --release {id}` lists the ones that do."
                    ));
                }
            }
            let lines = stored_text(&report, &at, &stem, limit);
            (Document::Stored(report), lines)
        }
        many => {
            return Err(SwpError::usage(format!(
                "report takes at most one saved report to name, {} were given: {}. List with \
                 `swp report`, or re-render one at a time so each keeps its own document.",
                many.len(),
                many.iter()
                    .map(|p| format!("{p:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

// --------------------------------------------------------------------------------------
// index
// --------------------------------------------------------------------------------------

fn index(project: &Ctx, filter: Option<&ReleaseId>) -> Result<Index, SwpError> {
    let names = project.store.report_names()?;
    let mut rows: Vec<Row> = Vec::new();
    let mut unreadable: Vec<Unreadable> = Vec::new();
    for name in &names {
        let path = project.store.report_path(name)?;
        let rel = project.store.relabel(&path);
        let report = match Report::from_json(&read_text(&project.store, name)?) {
            Ok(r) => r,
            // A file that is not a report is a fact about the store, and the
            // operator is the only party who can do anything about it. Refusing to
            // list the readable half of the store because one entry is corrupt
            // would hide the findings that are fine.
            Err(e) => {
                unreadable.push(Unreadable {
                    name: name.clone(),
                    path: rel,
                    error: e.message().to_string(),
                });
                continue;
            }
        };
        if let Some(id) = filter {
            if !report.releases.iter().any(|t| t.release_id == id.as_str()) {
                continue;
            }
        }
        rows.push(row_of(name.clone(), rel, &report));
    }
    let notes = vec![
        "A saved report keeps the grade it was given. This listing prints the level stored in \
         the file; it does not re-run the ladder, so a finding from before a rule change still \
         reads the way it read on the day it was made."
            .to_string(),
        "Reports live under .swp/private/reports/ and are private: one names your source \
         paths, the sites you protect and the files a candidate had in it. Share the document \
         you mean to share, not the directory."
            .to_string(),
        format!(
            "{} file(s) in the store, {} listed here{}.",
            names.len(),
            rows.len(),
            match filter {
                Some(id) => format!(" that name release {id}"),
                None => String::new(),
            }
        ),
    ];
    Ok(Index {
        schema: INDEX_SCHEMA,
        protocol: SWP_PROTOCOL_NAME,
        project_id: project.identity.project_id.to_string(),
        display_name: project.identity.display_name.clone(),
        release_filter: filter.map(|id| id.to_string()),
        saved: names.len(),
        listed: rows.len(),
        reports: rows,
        unreadable,
        notes,
        next: index_next(filter),
    })
}

fn index_next(filter: Option<&ReleaseId>) -> Vec<String> {
    let mut out = Vec::new();
    match filter {
        Some(id) => {
            out.push(format!("swp report --release {id} --format json"));
            out.push("swp report   (the whole store, without the filter)".to_string());
        }
        None => out.push("swp report --format json   (the same index as one document)".to_string()),
    }
    out.push("swp report <name>   (re-render one report as it was graded)".to_string());
    out.push(
        "swp report <name> --output out.json   (export it; the bytes are unchanged)".to_string(),
    );
    out
}

fn row_of(name: String, path: String, report: &Report) -> Row {
    Row {
        evidence_items: report.evidence.len(),
        omissions: report.omissions.len(),
        releases: report
            .releases
            .iter()
            .map(|t| t.release_id.clone())
            .collect(),
        result: report.result.as_str().to_string(),
        evidence_level: report.evidence_level.as_str().to_string(),
        created_at: report.run.created_at.clone(),
        generator: report.run.generator.clone(),
        command: report.run.command.clone(),
        candidate: report.candidate.described.clone(),
        kind: report.candidate.kind.clone(),
        files_scanned: report.candidate.files_scanned,
        bytes_scanned: report.candidate.bytes_scanned,
        partial: report.candidate.partial,
        name,
        path,
    }
}

fn index_text(index: &Index, limit: usize) -> Vec<String> {
    let mut out = vec![
        format!(
            "saved reports — {} ({})",
            index.display_name, index.project_id
        ),
        format!(
            "  {} of {} file(s) under .swp/private/reports/, newest first{}",
            index.listed,
            index.saved,
            match &index.release_filter {
                Some(id) => format!(", filtered to release {id}"),
                None => String::new(),
            }
        ),
        String::new(),
    ];
    if index.reports.is_empty() {
        if index.saved == 0 {
            out.push("  nothing has been saved yet.".to_string());
            out.push(
                "  `swp scan <candidate> --save` and `swp verify --save` write reports here; \
               this command only reads them."
                    .to_string(),
            );
        } else {
            // The store is not empty; the filter is what selected nothing. Saying
            // "nothing saved" here would send the operator off to re-scan.
            out.push(format!(
                "  none of the {} saved report(s){}.",
                index.saved,
                match &index.release_filter {
                    Some(id) => format!(" names release {id}"),
                    None => " can be read by this build".to_string(),
                }
            ));
            out.push("  `swp report` without --release lists the whole store.".to_string());
        }
        out.push(String::new());
    }
    if !index.reports.is_empty() {
        out.push(format!(
            "  {:<30} {:<7} {:<22} {:<12} {:>7}",
            "report", "run", "result", "evidence", "items"
        ));
        let (shown, omitted) = output::head(&index.reports, limit);
        for r in shown {
            out.push(format!(
                "  {:<30} {:<7} {:<22} {:<12} {:>7}",
                output::clip(&r.name, 30),
                output::clip(&r.command, 7),
                r.result,
                r.evidence_level,
                r.evidence_items
            ));
            out.push(format!(
                "  {:<30} {} ({}) · {} file(s){} · {}",
                "",
                output::clip(&r.candidate, 46),
                r.kind,
                r.files_scanned,
                if r.partial { ", PARTIAL" } else { "" },
                if r.releases.is_empty() {
                    "no release named".to_string()
                } else {
                    format!("{} release(s): {}", r.releases.len(), r.releases.join(", "))
                }
            ));
        }
        if omitted > 0 {
            out.push(format!("  … and {omitted} more; --full lists every one"));
        }
    }
    if !index.unreadable.is_empty() {
        out.push(format!(
            "\nNot a report this build can read ({}):",
            index.unreadable.len()
        ));
        for u in &index.unreadable {
            out.push(format!("  {} — {}", u.name, output::clip(&u.error, 60)));
        }
        out.push(format!(
            "  The {} file(s) above are still on disk. Read them by hand if they matter; \
             `swp report` will not print a conclusion it cannot verify.",
            index.unreadable.len()
        ));
    }
    out.push(String::new());
    out.push("Notes".to_string());
    for n in &index.notes {
        out.push(format!("  · {n}"));
    }
    out.push(String::new());
    out.push("Next".to_string());
    for n in &index.next {
        out.push(format!("  {n}"));
    }
    out.push(String::new());
    out.push("exit 0 — a listing is not a finding; see `result` above for that".to_string());
    out
}

// --------------------------------------------------------------------------------------
// one report
// --------------------------------------------------------------------------------------

/// Read one saved report by whatever name the operator gave it, and return it
/// with the store-relative path it came from.
fn read_one(store: &Store, what: &str) -> Result<(Report, String, String), SwpError> {
    let stem = stem_of(what);
    let path = store.report_path(&stem)?;
    if !path.is_file() {
        let saved = store.report_names()?.len();
        return Err(SwpError::new(
            ErrorCode::Usage,
            format!(
                "there is no saved report {stem:?} in this project ({saved} report(s) are \
                 stored). `swp report` lists them; a report is written by \
                 `swp scan <candidate> --save` or `swp verify --save`."
            ),
        )
        .with_path(store.relabel(&path)));
    }
    let text = read_text(store, &stem)?;
    let report = Report::from_json(&text)?;
    let at = store.relabel(&path);
    Ok((report, at, stem))
}

/// Bytes of one saved report, decoded.
fn read_text(store: &Store, stem: &str) -> Result<String, SwpError> {
    let bytes = store.read_report(stem)?;
    String::from_utf8(bytes).map_err(|_| {
        SwpError::invalid_manifest(format!(
            "the saved report {stem:?} is not UTF-8, so it is not a report this tool wrote"
        ))
    })
}

/// The name a report is stored under, from however the operator spelled it.
///
/// `swp scan --save` prints a stem, `swp report` prints a store-relative path,
/// and a shell completion offers the file name. All three mean the same entry, so
/// all three are accepted, and the store's own check on the result is what stops
/// a path from leaving the reports directory.
fn stem_of(what: &str) -> String {
    let trimmed = what.trim();
    let last = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_string();
    match last.strip_suffix(".json") {
        Some(stripped) if !stripped.is_empty() => stripped.to_string(),
        _ => last,
    }
}

fn stored_text(report: &Report, at: &str, stem: &str, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = report
        .to_text_items(limit)
        .lines()
        .map(|l| l.to_string())
        .collect();
    out.push(String::new());
    out.push(format!("  read from   {at}"));
    out.push(format!("  graded by   {}", report.run.generator));
    out.push(format!(
        "  stored      {} at {} — printed as it was graded, not re-computed",
        report.result.as_str(),
        report.evidence_level.as_str()
    ));
    out.push(String::new());
    out.push("Next".to_string());
    out.push(format!(
        "swp report {stem} --format json   (this document as JSON)"
    ));
    out.push(format!(
        "swp report {stem} --output out.json   (export the stored bytes unchanged)"
    ));
    out.push("swp report   (the index of saved reports)".to_string());
    out.push(String::new());
    out.push(format!(
        "exit 0 — this command re-rendered a document. The finding it records is in \
         `result`: {}; a scan that observes that today is `swp scan`, which exits 1 for it.",
        report.result.as_str()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use serde_json::Value;
    use swp_evidence::{EvidenceItem, EvidenceKind, EvidenceLevel, Outcome, REPORT_SCHEMA};

    /// A report of one's own, so a test can put a document in the store without
    /// running a scan to produce it.
    fn stored(command: &str, result: Outcome, level: EvidenceLevel, releases: &[&str]) -> Report {
        Report {
            schema: REPORT_SCHEMA.to_string(),
            protocol: SWP_PROTOCOL_NAME.to_string(),
            run: swp_evidence::Run {
                command: command.to_string(),
                created_at: "2026-09-21T10:00:00Z".to_string(),
                generator: "SWP-1 · swp 1.0.0 · report schema SWP-1-report-v1".to_string(),
            },
            candidate: swp_evidence::Candidate {
                described: "./copy".to_string(),
                kind: "directory".to_string(),
                files_scanned: 12,
                bytes_scanned: 4096,
                partial: false,
            },
            result,
            evidence_level: level,
            explanation: vec![
                "two sites carry their code, which is more than chance explains".to_string(),
            ],
            releases: releases
                .iter()
                .map(|r| swp_evidence::ReleaseTally {
                    project_id: "prj-01".to_string(),
                    release_id: r.to_string(),
                    sites: 4,
                    fragments: 2,
                    stripped: 0,
                    absent: 2,
                    exact_renderings: 2,
                    canonical_only: 0,
                    moved: 0,
                    renderings: 0,
                    files: 1,
                    bits: 32,
                    tag_bits: 16,
                    probes: 40,
                    literals_tried: 900,
                    windows_tried: 1200,
                    fingerprint: "no-match".to_string(),
                    chance: 0.0006,
                    guarantee: 32.0,
                    level,
                    reasons: vec![],
                })
                .collect(),
            evidence: (0..30)
                .map(|i| EvidenceItem {
                    id: format!("EV-{i:03}"),
                    kind: EvidenceKind::WatermarkFragmentMatch,
                    project_id: "prj-01".to_string(),
                    release_id: releases.first().copied().unwrap_or("rel-0").to_string(),
                    location: None,
                    source_region: None,
                    basis: format!("site {i} carries its 16-bit code"),
                    strength: EvidenceLevel::Strong,
                    protocol: SWP_PROTOCOL_NAME.to_string(),
                    schema: swp_core::SchemaVersion::REPORT_V1.0,
                })
                .collect(),
            omissions: vec![],
            notes: vec![],
            limitations: vec!["does not establish authorship".to_string()],
        }
    }

    fn save(dir: &Scratch, stem: &str, report: &Report) -> String {
        dir.store()
            .save_report(stem, report.to_json().as_bytes())
            .unwrap()
    }

    #[test]
    fn an_empty_store_says_so_and_points_at_the_commands_that_fill_it() {
        let dir = Scratch::protected("report", "empty");
        let r = dir.run(&["report"]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(r.out.contains("nothing has been saved yet"), "{}", r.out);
        assert!(r.out.contains("--save"), "{}", r.out);
        let j: Value = serde_json::from_str(&dir.run(&["report", "--format", "json"]).out).unwrap();
        assert_eq!(j["schema"], INDEX_SCHEMA);
        assert_eq!(j["saved"], 0);
        assert!(j["reports"].as_array().unwrap().is_empty());
        assert!(
            j["release_filter"].is_null(),
            "no filter is a value, not a key"
        );
    }

    #[test]
    fn the_index_lists_what_was_saved_and_who_wrote_it() {
        let dir = Scratch::protected("report", "index");
        save(
            &dir,
            "scan-2026-09-20T10-00-00Z",
            &stored(
                "scan",
                Outcome::ProvenanceDetected,
                EvidenceLevel::Strong,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        save(
            &dir,
            "verify-2026-09-21T10-00-00Z",
            &stored(
                "verify",
                Outcome::NoProvenanceDetected,
                EvidenceLevel::None,
                &["rel-bbbbbbbbbbbbbbbb"],
            ),
        );
        let r = dir.run(&["report"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let newest = r
            .out
            .find("verify-2026-09-21T10-00-00Z")
            .expect("the verify report is listed");
        let oldest = r
            .out
            .find("scan-2026-09-20T10-00-00Z")
            .expect("the scan report is listed");
        assert!(
            newest < oldest,
            "the header promises newest first, and the rows do not follow it:\n{}",
            r.out
        );
        assert!(r.out.contains("STRONG"), "{}", r.out);
        assert!(r.out.contains("2 of 2 file(s)"), "{}", r.out);
        let j: Value = serde_json::from_str(&dir.run(&["report", "--format", "json"]).out).unwrap();
        assert_eq!(j["listed"], 2);
        assert_eq!(j["reports"][0]["name"], "verify-2026-09-21T10-00-00Z");
        assert_eq!(j["reports"][0]["command"], "verify");
        assert_eq!(j["reports"][0]["evidence_items"], 30);
        assert_eq!(j["reports"][1]["evidence_level"], "STRONG");
        assert_eq!(j["reports"][1]["releases"][0], "rel-aaaaaaaaaaaaaaaa");
    }

    #[test]
    fn a_release_filter_lists_only_the_reports_that_name_it() {
        let dir = Scratch::protected("report", "filter");
        save(
            &dir,
            "scan-2026-09-20T10-00-00Z",
            &stored(
                "scan",
                Outcome::ProvenanceDetected,
                EvidenceLevel::Moderate,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        save(
            &dir,
            "scan-2026-09-21T10-00-00Z",
            &stored(
                "scan",
                Outcome::NoProvenanceDetected,
                EvidenceLevel::None,
                &["rel-bbbbbbbbbbbbbbbb"],
            ),
        );
        let r = dir.run(&["report", "--release", "rel-aaaaaaaaaaaaaaaa"]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(r.out.contains("1 of 2 file(s)"), "{}", r.out);
        assert!(r.out.contains("scan-2026-09-20"), "{}", r.out);
        assert!(!r.out.contains("scan-2026-09-21"), "{}", r.out);
        let j: Value = serde_json::from_str(
            &dir.run(&[
                "report",
                "--release",
                "rel-bbbbbbbbbbbbbbbb",
                "--format",
                "json",
            ])
            .out,
        )
        .unwrap();
        assert_eq!(j["release_filter"], "rel-bbbbbbbbbbbbbbbb");
        assert_eq!(j["listed"], 1);
        assert_eq!(
            j["saved"], 2,
            "the filter hides rows, not the size of the store"
        );
        // A release with no reports is an empty listing, not an error: the filter
        // does not require the release to still be in the store.
        let none = dir.run(&["report", "--release", "rel-cccccccccccccccc"]);
        assert_eq!(none.code, 0, "{}", none.err);
        assert!(none.out.contains("0 of 2 file(s)"), "{}", none.out);
    }

    #[test]
    fn a_file_in_the_store_that_is_not_a_report_is_listed_not_fatal() {
        let dir = Scratch::protected("report", "unreadable");
        save(
            &dir,
            "scan-2026-09-20T10-00-00Z",
            &stored(
                "scan",
                Outcome::ProvenanceDetected,
                EvidenceLevel::Strong,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        dir.store()
            .save_report("scan-2026-09-19T10-00-00Z", b"{\"schema\":\"other\"}")
            .unwrap();
        let r = dir.run(&["report"]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(
            r.out.contains("Not a report this build can read"),
            "{}",
            r.out
        );
        assert!(r.out.contains("scan-2026-09-20"), "{}", r.out);
        let j: Value = serde_json::from_str(&dir.run(&["report", "--format", "json"]).out).unwrap();
        assert_eq!(j["listed"], 1);
        assert_eq!(j["saved"], 2);
        assert_eq!(j["unreadable"][0]["name"], "scan-2026-09-19T10-00-00Z");
    }

    #[test]
    fn re_rendering_prints_the_grade_that_is_stored_and_exits_zero() {
        let dir = Scratch::protected("report", "rerender");
        let stem = "scan-2026-09-20T10-00-00Z";
        save(
            &dir,
            stem,
            &stored(
                "scan",
                Outcome::ProvenanceDetected,
                EvidenceLevel::Strong,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        let r = dir.run(&["report", stem]);
        // The document it re-states found evidence; the re-statement did not.
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(r.out.contains("PROVENANCE_DETECTED"), "{}", r.out);
        assert!(r.out.contains("exit 0"), "{}", r.out);
        assert!(
            r.out.contains("more than chance explains"),
            "the stored explanation is printed verbatim: {}",
            r.out
        );
        assert!(r.out.contains(".swp/private/reports/"), "{}", r.out);
        assert!(r.out.contains("not re-computed"), "{}", r.out);
    }

    #[test]
    fn any_spelling_of_the_name_finds_the_same_report() {
        let dir = Scratch::protected("report", "spellings");
        let stem = "scan-2026-09-20T10-00-00Z";
        save(
            &dir,
            stem,
            &stored(
                "scan",
                Outcome::NoProvenanceDetected,
                EvidenceLevel::None,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        let at = dir.store().report_path(stem).unwrap().display().to_string();
        let by_stem = dir.run(&["report", stem]);
        let by_file = dir.run(&["report", &format!("{stem}.json")]);
        let by_path = dir.run(&["report", &at]);
        assert_eq!(by_stem.code, 0, "{}", by_stem.err);
        assert_eq!(by_file.code, 0, "{}", by_file.err);
        assert_eq!(by_path.code, 0, "{}", by_path.err);
        assert_eq!(by_stem.out, by_file.out, "the file name means the entry");
        assert_eq!(by_stem.out, by_path.out, "so does the path it lives at");
        assert_eq!(stem_of(&at), stem);
        assert_eq!(stem_of("scan-x.json"), "scan-x");
        assert_eq!(stem_of("scan-x"), "scan-x");
        // A stem that is only `.json` is not a name, and a `..` never reaches the
        // filesystem.
        assert_eq!(stem_of(".json"), ".json");
        // `..` in the name is stripped, not resolved: the last segment is the
        // entry's name and the check below is what keeps it inside the reports
        // directory. So this asks for a report that does not exist rather than
        // opening a file somewhere else in the project.
        let outside = dir.run(&["report", "../manifests/rel-aaaaaaaaaaaaaaaa"]);
        assert_eq!(
            outside.code,
            ErrorCode::Usage.exit_code(),
            "{}",
            outside.err
        );
        assert!(
            outside
                .err
                .contains("no saved report \"rel-aaaaaaaaaaaaaaaa\""),
            "the name it actually looked for is the one it should report: {}",
            outside.err
        );
        assert!(
            !outside.err.contains(".."),
            "a traversal in the argument must not reach the printed path: {}",
            outside.err
        );
        // A name that could never be a stored entry is refused before the lookup.
        let hidden = dir.run(&["report", ".swp-private"]);
        assert_eq!(
            hidden.code,
            ErrorCode::PathRejected.exit_code(),
            "{}",
            hidden.err
        );
        let spaced = dir.run(&["report", "with space"]);
        assert_eq!(
            spaced.code,
            ErrorCode::PathRejected.exit_code(),
            "{}",
            spaced.err
        );
    }

    #[test]
    fn a_missing_report_is_named_and_the_listing_is_offered() {
        let dir = Scratch::protected("report", "missing");
        save(
            &dir,
            "scan-2026-09-20T10-00-00Z",
            &stored(
                "scan",
                Outcome::NoProvenanceDetected,
                EvidenceLevel::None,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        let r = dir.run(&["report", "scan-2020-01-01T00-00-00Z"]);
        assert_eq!(r.code, ErrorCode::Usage.exit_code(), "{}", r.err);
        assert!(r.err.contains("no saved report"), "{}", r.err);
        assert!(r.err.contains("1 report(s) are stored"), "{}", r.err);
        assert!(r.err.contains("--save"), "{}", r.err);
    }

    #[test]
    fn exporting_a_report_writes_the_bytes_that_are_stored() {
        let dir = Scratch::protected("report", "export");
        let stem = "scan-2026-09-20T10-00-00Z";
        let original = stored(
            "scan",
            Outcome::ProvenanceDetected,
            EvidenceLevel::VeryStrong,
            &["rel-aaaaaaaaaaaaaaaa"],
        );
        save(&dir, stem, &original);
        let at = dir.root.join("exported.json");
        let r = dir.run(&["report", stem, "--output", &at.display().to_string()]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(
            r.out.is_empty(),
            "--output leaves stdout empty: {:?}",
            r.out
        );
        assert_eq!(
            std::fs::read_to_string(&at).unwrap(),
            original.to_json(),
            "an export of an evidence document must be that document, key order included"
        );
    }

    #[test]
    fn the_text_window_is_a_rendering_choice_and_not_a_change_to_the_record() {
        let dir = Scratch::protected("report", "window");
        let stem = "scan-2026-09-20T10-00-00Z";
        save(
            &dir,
            stem,
            &stored(
                "scan",
                Outcome::ProvenanceDetected,
                EvidenceLevel::Strong,
                &["rel-aaaaaaaaaaaaaaaa"],
            ),
        );
        let paged = dir.run(&["report", stem]);
        assert!(
            paged.out.contains("… and 6 more"),
            "thirty items, twenty-four printed: {}",
            paged.out
        );
        let capped = dir.run(&["report", stem, "--limit", "3"]);
        assert!(capped.out.contains("… and 27 more"), "{}", capped.out);
        let every = dir.run(&["report", stem, "--full"]);
        assert!(!every.out.contains("more; re-run with"), "{}", every.out);
        assert!(every.out.contains("EV-029"), "{}", every.out);
        // None of the three touched the document.
        let j: Value = serde_json::from_str(
            &dir.run(&["report", stem, "--limit", "3", "--format", "json"])
                .out,
        )
        .unwrap();
        assert_eq!(j["evidence"].as_array().unwrap().len(), 30);
    }

    #[test]
    fn a_report_of_a_real_scan_round_trips_through_the_store() {
        let owner = Scratch::protected("report", "roundtrip");
        let other = Scratch::new("report", "roundtrip-tree");
        other.write("plain.js", "function h(x) {\n  return x + 5;\n}\n");
        let saved = owner.run(&["scan", &other.root.display().to_string(), "--save"]);
        assert_eq!(saved.code, 0, "{}", saved.err);
        let names = owner.store().report_names().unwrap();
        assert_eq!(names.len(), 1, "{names:?}");
        let again = owner.run(&["report", &names[0], "--format", "json"]);
        assert_eq!(again.code, 0, "{}", again.err);
        let doc: Value = serde_json::from_str(&again.out).unwrap();
        assert_eq!(doc["schema"], REPORT_SCHEMA);
        assert_eq!(doc["run"]["command"], "scan");
        let listed = owner.run(&["report"]);
        assert!(listed.out.contains(&names[0]), "{}", listed.out);
        assert!(
            listed.out.contains("NO_PROVENANCE_DETECTED"),
            "{}",
            listed.out
        );
    }
}
