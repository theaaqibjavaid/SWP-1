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
//! `5` is [`ErrorCode::ReleaseMismatch`](swp_core::error::ErrorCode::ReleaseMismatch)'s code,
//! and the message that goes with it in the error table is the advice this command
//! is really giving: the tree moved on, so record a new release. A `5` is not an
//! accusation about anybody — a site can go absent because a developer deleted a
//! function, and because a copier stripped a fragment, and this command cannot tell
//! those apart (§51).
//!
//! The `SWP-1-verify-v1` document itself is built by [`swp_evidence`], which owns
//! what a scan means, and [`swp_sdk::Session::verify`] runs the scan that fills it
//! in; this file prints the answer, and the comment on that evidence module is
//! where the rules about what the document may name live.

use swp_core::error::SwpError;
use swp_evidence::{SiteRow, Verdict, VerifyDocument};
use swp_sdk::VerifyOptions;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

pub fn run(parsed: &Parsed, cwd: &std::path::Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let limit = output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let outcome = project.session.verify(&VerifyOptions {
        release: Some(project.one_release(parsed)?),
        save: parsed.has(Flag::Save),
        // The document carries every row whatever the window; saying how many the
        // page leaves out is the renderer's business, and the run reports it.
        rows: Some(limit),
    })?;
    let doc = &outcome.document;
    // The document holds the rows, so both tables the text prints are read back out
    // of it: the `sites` array in the JSON and the rows on the page are then the
    // same values, rather than two copies that could disagree.
    let (shown, _) = output::head(&doc.sites, limit);
    // Rows were built from the scan's sites in order, so a row's own status — the
    // one place the watermark/not-watermark line is drawn — selects them here.
    let missing: Vec<&SiteRow> = doc.sites.iter().filter(|r| !r.confirmed()).collect();
    let lines = text_lines(doc, "verify", shown, &missing);
    if doc.verdict != Verdict::Intact {
        sink.warn(&format!(
            "{} of {} site(s) of release {} are not carrying their code",
            doc.sites_expected - doc.sites_confirmed,
            doc.sites_expected,
            doc.release_id
        ));
    }
    output::deliver(sink, doc, &lines, parsed.value(Flag::Output))?;
    Ok(doc.exit_code)
}

/// The verification page.
///
/// `head` is the verb that ran it: `swp verify` and `swp pre-commit` measure the
/// same thing over the same tree and print the same rows, and a second renderer
/// for the second command is a second place for the two to disagree about what a
/// site's status means.
pub(crate) fn text_lines(
    d: &VerifyDocument,
    head: &str,
    shown: &[SiteRow],
    missing: &[&SiteRow],
) -> Vec<String> {
    let verdict = d.verdict;
    let mut out = vec![
        format!(
            "{head} {} ({}) against release {}",
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
    out.push(
        "  status        site  file:line                  family  width  keys hit".to_string(),
    );
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
    use swp_core::error::ErrorCode;
    use swp_evidence::Report;

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
    fn verify_without_a_project_fails_before_any_secret_is_read() {
        let dir = Scratch::new("verify", "noproject");
        dir.write("src/a.js", "var a = 1;\n");
        let r = dir.run(&["verify"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("swp init"), "{}", r.err);
        assert!(
            r.out.is_empty(),
            "a failure writes no document: {:?}",
            r.out
        );
    }

    #[test]
    fn a_tree_that_was_just_protected_verifies_intact() {
        let dir = Scratch::protected("verify", "intact");
        let r = dir.run(&["verify", "--format", "json"]);
        let doc = r.json();
        assert_eq!(
            r.code, 0,
            "a fresh release must verify against itself:\n{}{}",
            r.out, r.err
        );
        assert_eq!(doc["schema"], swp_evidence::VERIFY_SCHEMA);
        assert_eq!(doc["verdict"], "INTACT");
        assert_eq!(doc["manifest_authenticated"], true);
        assert!(doc["sites_expected"].as_u64().unwrap() >= 4);
        assert_eq!(doc["sites_confirmed"], doc["sites_expected"]);
        assert_eq!(doc["sites_absent"], 0);
        assert_eq!(
            doc["fingerprint"], "match",
            "the tree is the tree it hashed"
        );
        assert!(doc["release_created_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(doc["exit_code"], 0);
    }

    #[test]
    fn stripping_the_protected_sources_downgrades_the_verdict_and_the_exit_code() {
        let dir = Scratch::protected("verify", "stripped");
        // Which file the key put a site in is not knowable from here — selection is
        // keyed over the tree — so stripping one named file is a test that passes or
        // fails on the draw. Every source file is replaced with an unprotected
        // version of the same shape instead: the sites are gone wherever they
        // landed, and the tree is still readable.
        for rel in dir.sources() {
            dir.write(
                &rel,
                "function gone(base, scale) {\n  return base * scale;\n}\n",
            );
        }
        let r = dir.run(&["verify", "--format", "json"]);
        let doc = r.json();
        assert_eq!(r.code, ErrorCode::ReleaseMismatch.exit_code(), "{}", r.out);
        assert_eq!(doc["verdict"], "INCOMPLETE");
        assert_eq!(doc["partial"], false);
        assert!(
            doc["sites_confirmed"].as_u64().unwrap() < doc["sites_expected"].as_u64().unwrap(),
            "no site survived the strip: {doc}"
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
        assert!(
            t.out
                .contains("nothing about the tree being otherwise unchanged")
                || t.out.contains("cannot say"),
            "{}",
            t.out
        );
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
        assert!(
            r.out.contains(&names[0]),
            "the text says where it went:\n{}",
            r.out
        );
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
        assert!(t.out.contains(
            doc["sites_confirmed"]
                .as_u64()
                .unwrap()
                .to_string()
                .as_str()
        ));
        assert!(t.out.contains(doc["release_id"].as_str().unwrap()));
        // The text window counts what it left out rather than hiding it.
        assert!(
            t.out.contains("Sites (all") || t.out.contains("first"),
            "{}",
            t.out
        );
    }
}
