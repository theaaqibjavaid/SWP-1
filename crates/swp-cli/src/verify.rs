//! `swp verify` — is the tree I am standing in still the tree I protected?
//!
//! Verification is a scan of the project's *own* root against one of its own
//! releases, which is the narrowest possible claim and the most useful one: the
//! release's manifest says which keyed locations it used and what each one must
//! carry, and a scan recomputes both from the root secret. Nothing is looked up
//! by path, so the answer survives the project's own refactoring; what does not
//! survive is deleting a watermarked literal, which is exactly what the command
//! is for.
//!
//! ## The three answers, and the exit code each one gets
//!
//! ```text
//! INTACT         every site of the release still carries its code        0
//! INCOMPLETE     some do not, and the whole tree was examined            5  (RELEASE_MISMATCH)
//! INCONCLUSIVE   some do not, and part of the tree was never read        10
//! ```
//!
//! `5` is [`ErrorCode::ReleaseMismatch`]'s code, and the message that goes with
//! it in the error table is the advice this command is really giving: the tree
//! moved on, so record a new release. A `5` is not an accusation about anybody —
//! a site can go absent because a developer deleted a function, and because a
//! copier stripped a fragment, and this command cannot tell those apart (§51).
//!
//! ## What this document does not print
//!
//! No location ids, no `original`/`rendered` literals, no expected tags. A site
//! is named by the file and line it was recorded at and by its family and width,
//! which is enough to go look at it, and enough again for a document that exists
//! in CI logs and build artifacts to be a copy of the watermark — which is the
//! one thing §29 forbids. `.swp/private/manifests/<release>.json` holds the full
//! record, and `swp inspect manifest` prints it on a terminal the operator is
//! standing at.

use serde::Serialize;
use swp_core::error::{ErrorCode, SwpError};
use swp_detection::{build_indexes, input, scan_against, SiteStatus};
use swp_evidence::Report;
use swp_identity::Timestamp;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

/// The `schema` field of the document below, and the string a reader of a saved
/// report matches on.
const SCHEMA: &str = "SWP-1-verify-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Verdict {
    /// Every site of the release is present with its code.
    Intact,
    /// Some site is not, and the tree was read completely enough to say so.
    Incomplete,
    /// Some site is not, and part of the tree was never examined.
    Inconclusive,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Intact => "INTACT",
            Verdict::Incomplete => "INCOMPLETE",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Verdict::Intact => 0,
            Verdict::Incomplete => ErrorCode::ReleaseMismatch.exit_code(),
            Verdict::Inconclusive => ErrorCode::InsufficientEvidence.exit_code(),
        }
    }
}

/// One site of the release, and whether it is still there.
#[derive(Debug, Serialize)]
struct SiteRow {
    /// Index into the release's site list, matching `swp inspect manifest`.
    site: usize,
    /// Where this site was when the release was made. A hint for a human, never a
    /// lookup key — a site that moved is still the same site.
    file: String,
    line_hint: u32,
    language: String,
    adapter: String,
    class: &'static str,
    family: &'static str,
    width: u8,
    status: &'static str,
    /// Which of the four keyed radii the tree reproduced.
    slots: Vec<&'static str>,
    /// Where the site was actually found, when that differs from `file`.
    found_in: Option<String>,
    found_line: Option<u32>,
    refactored: bool,
    moved: bool,
}

/// `SWP-1-verify-v1`.
#[derive(Debug, Serialize)]
struct VerifyDocument {
    schema: &'static str,
    protocol: &'static str,
    project_id: String,
    display_name: String,
    tree: String,
    release_id: String,
    release_created_at: String,
    /// `content`, or the label `--revision` stated. Display metadata only.
    revision: Option<String>,
    /// Whether the release's manifest authenticated against the identity in
    /// `.swp/public/identity.json` — the precondition for every claim below.
    manifest_authenticated: bool,
    sites_expected: usize,
    sites_confirmed: usize,
    sites_exact: usize,
    sites_stripped: usize,
    sites_absent: usize,
    sites_moved: usize,
    sites_refactored: usize,
    tag_bits: u8,
    confirmed_bits: u32,
    files_scanned: u32,
    bytes_scanned: u64,
    /// `"match"`, `"no-match"` or `"not-comparable"`: did the tree hash to the
    /// §16 fingerprint this release published?
    fingerprint: String,
    fingerprint_expected: String,
    verdict: Verdict,
    /// True when some of the tree was never read, which is what separates
    /// `INCOMPLETE` from `INCONCLUSIVE`.
    partial: bool,
    sites: Vec<SiteRow>,
    /// Rows the text rendering left out, counted rather than hidden.
    omitted_rows: usize,
    omissions: Vec<String>,
    notes: Vec<String>,
    report_saved: Option<String>,
    limitations: Vec<String>,
    next: Vec<String>,
    exit_code: i32,
}

pub fn run(parsed: &Parsed, cwd: &std::path::Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in &project.warnings {
        sink.warn(warning);
    }
    let release = project.one_release(parsed)?;
    let limits = project.limits();
    let releases = project.load_releases(std::slice::from_ref(&release))?;
    let verify_key = project.identity.verify_key()?;
    let indexes = build_indexes(&releases, &verify_key, &limits)?;
    let root = project.root().to_path_buf();
    let opened = input::open(&root, &limits)?;
    let detection = scan_against(&opened, &indexes, &limits)?;
    let found = detection
        .releases
        .first()
        .ok_or_else(|| SwpError::internal("a scan of one release returned none"))?;
    let fingerprint = found.fingerprint.as_str().to_string();
    let expected = indexes[0].fingerprint().to_string();

    let rows: Vec<SiteRow> = found
        .sites
        .iter()
        .map(|s| SiteRow {
            site: s.site,
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
        })
        .collect();

    let confirmed = found.confirmed();
    let verdict = if confirmed == rows.len() {
        Verdict::Intact
    } else if detection.partial {
        Verdict::Inconclusive
    } else {
        Verdict::Incomplete
    };
    let limit = output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let omitted_rows = rows.len().saturating_sub(limit);
    let saved = save(parsed, &project, &detection)?;

    let doc = VerifyDocument {
        schema: SCHEMA,
        protocol: swp_core::SWP_PROTOCOL_NAME,
        project_id: project.identity.project_id.to_string(),
        display_name: project.identity.display_name.clone(),
        tree: opened.described.clone(),
        release_id: release.to_string(),
        release_created_at: releases[0].record.created_at.to_rfc3339(),
        revision: releases[0]
            .record
            .source_revision
            .as_str()
            .map(|s| s.to_string()),
        manifest_authenticated: true,
        sites_expected: rows.len(),
        sites_confirmed: confirmed,
        sites_exact: found
            .sites
            .iter()
            .filter(|s| s.status == SiteStatus::ExactRendering)
            .count(),
        sites_stripped: found.stripped(),
        sites_absent: found.absent(),
        sites_moved: found.moved(),
        sites_refactored: found.refactored(),
        tag_bits: found.tag_bits,
        confirmed_bits: found.confirmed_bits(),
        files_scanned: detection.files_scanned,
        bytes_scanned: detection.bytes_scanned,
        fingerprint,
        fingerprint_expected: expected,
        verdict,
        partial: detection.partial,
        sites: rows,
        omitted_rows,
        omissions: detection.omissions.clone(),
        notes: detection.notes.clone(),
        report_saved: saved,
        limitations: limitations(verdict),
        next: next_steps(verdict, &release),
        exit_code: verdict.exit_code(),
    };
    // The document holds the rows, so both tables the text prints are read back out
    // of it: the `sites` array in the JSON and the rows on the page are then the
    // same values, rather than two copies that could disagree.
    let (shown, _) = output::head(&doc.sites, limit);
    // Rows were built from `found.sites` in order, so the site's own verdict — the
    // one place the watermark/not-watermark line is drawn — selects them here.
    let missing: Vec<&SiteRow> = doc
        .sites
        .iter()
        .enumerate()
        .filter(|(i, _)| !found.sites[*i].confirmed())
        .map(|(_, r)| r)
        .collect();
    let lines = text_lines(&doc, shown, &missing, verdict);
    if verdict != Verdict::Intact {
        sink.warn(&format!(
            "{} of {} site(s) of release {} are not carrying their code",
            doc.sites_expected - doc.sites_confirmed,
            doc.sites_expected,
            doc.release_id
        ));
    }
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(doc.exit_code)
}

/// `--save` keeps a verification report beside the release it describes.
fn save(
    parsed: &Parsed,
    project: &Ctx,
    detection: &swp_detection::Detection,
) -> Result<Option<String>, SwpError> {
    if !parsed.has(Flag::Save) {
        return Ok(None);
    }
    let now = Timestamp::now_utc();
    let report = Report::build(
        detection,
        "verify",
        &now.to_rfc3339(),
        &crate::help::banner(),
    );
    let stem = format!("verify-{}", now.filename_stem());
    Ok(Some(project.store.save_report(&stem, report.to_json().as_bytes())?))
}

fn limitations(verdict: Verdict) -> Vec<String> {
    let mut out = vec![
        "a site that carries its code is a statement about this artifact, not about who wrote \
         it or what rights attach to it",
        "an absent site means the watermark is not here, which a deleted function, a formatter \
         that removed a literal and a deliberate strip all produce identically",
        "the §16 fingerprint is about the whole tree: it can say no-match while every site is \
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

fn next_steps(verdict: Verdict, release: &swp_core::ReleaseId) -> Vec<String> {
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

fn text_lines(
    d: &VerifyDocument,
    shown: &[SiteRow],
    missing: &[&SiteRow],
    verdict: Verdict,
) -> Vec<String> {
    let mut out = vec![
        format!(
            "verify {} ({}) against release {}",
            d.display_name, d.project_id, d.release_id
        ),
        format!("  tree        {}", d.tree),
        format!(
            "  manifest    {} · {} site(s) at {} bit(s) each",
            if d.manifest_authenticated {
                "authenticated"
            } else {
                "NOT AUTHENTICATED"
            },
            d.sites_expected,
            d.tag_bits
        ),
        format!(
            "  scope       {} file(s), {} byte(s) read{}",
            d.files_scanned,
            d.bytes_scanned,
            if d.partial { " — PARTIAL" } else { "" }
        ),
        format!(
            "  fingerprint {} (release published {})",
            d.fingerprint, d.fingerprint_expected
        ),
        format!(
            "  verdict     {} — {}/{} site(s) still carry their code, {} keyed bit(s)",
            verdict.as_str(),
            d.sites_confirmed,
            d.sites_expected,
            d.confirmed_bits
        ),
    ];
    if d.sites_exact > 0 || d.sites_stripped > 0 || d.sites_absent > 0 {
        out.push(format!(
            "  channels    {} exact rendering(s), {} address-without-code, {} absent",
            d.sites_exact, d.sites_stripped, d.sites_absent
        ));
    }
    if d.sites_moved > 0 || d.sites_refactored > 0 {
        out.push(format!(
            "  survived    {} site(s) found in another file, {} only under the rename-tolerant keys",
            d.sites_moved, d.sites_refactored
        ));
    }
    out.push(String::new());
    if missing.is_empty() {
        out.push(
            "Every site of this release is present with its code. That is the whole claim; \
             it says nothing about the tree being otherwise unchanged."
                .to_string(),
        );
    } else {
        out.push(format!(
            "What is no longer carrying its code ({} site(s))",
            missing.len()
        ));
        out.push("  status        site  file:line                  family  width".to_string());
        for row in missing {
            out.push(format!(
                "  {:<13} {:>4}  {:<26} {:<8} {:>5}",
                row.status,
                row.site,
                shorten(&format!("{}:{}", row.file, row.line_hint), 26),
                row.family,
                row.width
            ));
        }
        out.push(String::new());
    }
    out.push(if shown.len() == d.sites.len() {
        format!("Sites (all {})", d.sites.len())
    } else {
        format!("Sites (first {} of {})", shown.len(), d.sites.len())
    });
    out.push("  status        site  file:line                  family  width  keys hit".to_string());
    for row in shown {
        out.push(format!(
            "  {:<13} {:>4}  {:<26} {:<8} {:>5}  {}",
            row.status,
            row.site,
            shorten(
                &format!("{}:{}", row.file, row.found_line.unwrap_or(row.line_hint)),
                26
            ),
            row.family,
            row.width,
            if row.slots.is_empty() {
                "—".to_string()
            } else {
                row.slots.join(", ")
            }
        ));
    }
    if d.omitted_rows > 0 {
        out.push(format!(
            "  … and {} more; re-run with --full or --limit <n>, or read the JSON document",
            d.omitted_rows
        ));
    }
    out.push(String::new());
    out.push("What this cannot say".to_string());
    for l in &d.limitations {
        out.push(format!("  · {l}"));
    }
    if let Some(path) = &d.report_saved {
        out.push(String::new());
        out.push(format!("Saved report: {path}"));
    }
    out.push(String::new());
    out.push("Next".to_string());
    for n in &d.next {
        out.push(format!("  {n}"));
    }
    out.push(String::new());
    out.push(format!("exit {}", d.exit_code));
    out
}

/// Shorten a path for a fixed table column without losing its tail.
///
/// Counted in `char`s, not bytes: a path with a non-ASCII directory name would
/// otherwise panic on slicing into the middle of a codepoint, which is a poor way
/// to lose a report.
fn shorten(path: &str, width: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= width {
        return path.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut out = String::from("…");
    out.extend(chars[chars.len() - keep..].iter());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use swp_detection::SLOT_COUNT;

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
    fn shortening_a_path_keeps_its_tail_and_stays_in_its_column() {
        assert_eq!(shorten("src/a.js", 24), "src/a.js");
        let long = "vendor/packages/deeply/nested/dir/module/index.js";
        let cut = shorten(long, 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with("index.js"), "{cut}");
        assert!(cut.starts_with('…'));
        // A non-ASCII path is cut between characters, not between bytes: the byte
        // version of this panicked on a directory named `src/é/…`.
        let unicode = "src/é/ü/naïve/module/index.js";
        let cut = shorten(unicode, 9);
        assert_eq!(cut.chars().count(), 9);
        assert!(cut.ends_with("index.js"), "{cut}");
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
        for forbidden in ["locations", "original", "rendered", "primary", "tag", "secret"] {
            assert!(
                doc.get(forbidden).is_none(),
                "the row printed {forbidden}"
            );
        }
        assert_eq!(SLOT_COUNT, 4, "four radii per site; `slots` lists which hit");
    }

    #[test]
    fn verify_without_a_project_fails_before_any_secret_is_read() {
        let dir = Scratch::new("verify", "noproject");
        dir.write("src/a.js", "var a = 1;\n");
        let r = dir.run(&["verify"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("swp init"), "{}", r.err);
        assert!(r.out.is_empty(), "a failure writes no document: {:?}", r.out);
    }

    #[test]
    fn a_tree_that_was_just_protected_verifies_intact() {
        let dir = Scratch::protected("verify", "intact");
        let r = dir.run(&["verify", "--format", "json"]);
        let doc = r.json();
        assert_eq!(
            r.code,
            0,
            "a fresh release must verify against itself:\n{}{}",
            r.out,
            r.err
        );
        assert_eq!(doc["schema"], SCHEMA);
        assert_eq!(doc["verdict"], "INTACT");
        assert_eq!(doc["manifest_authenticated"], true);
        assert!(doc["sites_expected"].as_u64().unwrap() >= 4);
        assert_eq!(doc["sites_confirmed"], doc["sites_expected"]);
        assert_eq!(doc["sites_absent"], 0);
        assert_eq!(doc["fingerprint"], "match", "the tree is the tree it hashed");
        assert!(doc["release_created_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(doc["exit_code"], 0);
    }

    #[test]
    fn stripping_a_protected_file_downgrades_the_verdict_and_the_exit_code() {
        let dir = Scratch::protected("verify", "stripped");
        // Replace the protected source with an unprotected version of the same
        // functions: the sites are gone, the tree is still readable.
        dir.write(
            "src/a.js",
            "function gone(base, scale) {\n  return base * scale;\n}\n",
        );
        let r = dir.run(&["verify", "--format", "json"]);
        let doc = r.json();
        assert_eq!(r.code, ErrorCode::ReleaseMismatch.exit_code(), "{}", r.out);
        assert_eq!(doc["verdict"], "INCOMPLETE");
        assert_eq!(doc["partial"], false);
        assert!(
            doc["sites_confirmed"].as_u64().unwrap()
                < doc["sites_expected"].as_u64().unwrap()
        );
        // The four counts are a partition of the release's sites, and this is
        // where that is pinned: a site that stopped carrying its code is either
        // gone or an address without a code, and the two are never conflated.
        let stripped = doc["sites_stripped"].as_u64().unwrap();
        let absent = doc["sites_absent"].as_u64().unwrap();
        assert_eq!(
            doc["sites_confirmed"].as_u64().unwrap() + stripped + absent,
            doc["sites_expected"].as_u64().unwrap(),
            "confirmed + stripped + absent is the release"
        );
        assert!(stripped + absent > 0, "the strip went unnoticed: {doc}");
        assert_eq!(doc["fingerprint"], "no-match");
        // The text rendering names the sites that went missing, and says what it
        // cannot tell them apart from (§51).
        let t = dir.run(&["verify"]);
        assert!(t.out.contains("INCOMPLETE"), "{}", t.out);
        assert!(
            t.out.contains("What is no longer carrying its code"),
            "{}",
            t.out
        );
        assert!(t.err.contains("warning:"), "{}", t.err);
        assert!(t.out.contains("nothing about the tree being otherwise unchanged") || t.out.contains("cannot say"), "{}", t.out);
    }

    #[test]
    fn save_keeps_a_verification_report_beside_the_release_it_describes() {
        let dir = Scratch::protected("verify", "save");
        let r = dir.run(&["verify", "--save"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let names = dir.store().report_names().unwrap();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("verify-"), "{}", names[0]);
        let bytes = dir.store().read_report(&names[0]).unwrap();
        let saved = Report::from_json(&String::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(saved.run.command, "verify");
        assert!(r.out.contains(&names[0]), "the text says where it went:\n{}", r.out);
    }

    #[test]
    fn a_labeled_revision_is_recorded_as_the_operators_words() {
        let dir = Scratch::new("verify", "revision");
        dir.write(
            "src/a.js",
            "function one(v) {\n  return v + 1000;\n}\nfunction two(v) {\n  return v * 1002;\n}\nfunction three(v) {\n  return v - 1003;\n}\nfunction four(v) {\n  return v | 1004;\n}\n",
        );
        assert_eq!(dir.run(&["init"]).code, 0);
        let p = dir.run(&["protect", "--revision", "v2.3-rc1"]);
        assert_eq!(p.code, 0, "{}{}", p.out, p.err);
        let r = dir.run(&["verify", "--format", "json"]);
        assert_eq!(r.json()["revision"], "v2.3-rc1");
    }

    #[test]
    fn text_and_json_answer_the_same_question() {
        let dir = Scratch::protected("verify", "two-renderings");
        let t = dir.run(&["verify"]);
        let j = dir.run(&["verify", "--format", "json"]);
        let doc = j.json();
        assert_eq!(t.code, j.code);
        assert!(t
            .out
            .contains(doc["sites_confirmed"].as_u64().unwrap().to_string().as_str()));
        assert!(t.out.contains(doc["release_id"].as_str().unwrap()));
        // The text window counts what it left out rather than hiding it.
        assert!(t.out.contains("Sites (all") || t.out.contains("first"), "{}", t.out);
    }
}
