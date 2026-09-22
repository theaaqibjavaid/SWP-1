//! `swp scan <candidate>` — the §22 evidence engine pointed at somebody else's tree.
//!
//! This is the command the whole protocol exists for, and the one with the most
//! rules about what it may say. Four of them are structural rather than stylistic:
//!
//! * **The keys come from the owner's project, never from the candidate.** The
//!   project is found by [`Ctx::open`] walking up from the *working directory*, and
//!   the candidate is only ever opened by [`input::open`]. A repository under
//!   examination may ship its own `.swp/` — possibly a different project's,
//!   possibly a forged one — and if any part of the verdict depended on it, the
//!   examined party would be supplying the evidence used to judge them.
//! * **The candidate is read, not run.** No process is spawned, no manifest is
//!   interpreted, no dependency is resolved (§21). Archives are unpacked into a
//!   temporary directory that is removed afterwards, and the only thing done to
//!   the bytes inside is parsing.
//! * **Every release the owner has is a suspect.** With no `--release`, all of them
//!   are loaded: a copy could have come from any protected build, and picking one
//!   silently would be an unstated claim about which. The report then attributes
//!   the finding to a release rather than to "the project".
//! * **The document is `swp-evidence`'s, not this command's.** §22 makes the
//!   evidence engine the thing that decides what a scan means, so the JSON here is
//!   the engine's `SWP-1-report-v1` verbatim. A second schema for the same facts
//!   would be a second place for the §51 boundary to be lost.
//!
//! The exit code is the three-way answer a caller can branch on: `0` nothing was
//! confirmed, `1` something was, `10` this scan could not have said either way.

use std::path::Path;

use swp_core::error::{ErrorCode, SwpError};
use swp_detection::{build_indexes, input, scan_against};
use swp_evidence::{Outcome, Report};
use swp_identity::Timestamp;

use crate::args::{Flag, Parsed};
use crate::ctx::{self, Ctx};
use crate::output::{self, Sink};

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let candidate = candidate_path(parsed, cwd)?;
    let project = Ctx::open(parsed, cwd)?;
    for warning in &project.warnings {
        sink.warn(warning);
    }
    let limits = project.limits();
    let releases = project.candidate_releases(parsed)?;
    let verify_key = project.identity.verify_key()?;
    let indexes = build_indexes(&releases, &verify_key, &limits)?;
    if parsed.verbose() {
        sink.note(&format!(
            "scanning {} against {} release(s) of project {}",
            candidate.display(),
            indexes.len(),
            project.identity.project_id
        ));
    }
    let opened = input::open(&candidate, &limits)?;
    if parsed.verbose() {
        sink.note(&format!(
            "{} ({}) read; matching keyed addresses",
            opened.described,
            opened.kind.as_str()
        ));
    }
    let detection = scan_against(&opened, &indexes, &limits)?;

    let now = Timestamp::now_utc();
    let report = Report::build(
        &detection,
        "scan",
        &now.to_rfc3339(),
        &crate::help::banner(),
    );
    let saved = if parsed.has(Flag::Save) {
        let stem = format!("scan-{}", now.filename_stem());
        let path = project
            .store
            .save_report(&stem, report.to_json().as_bytes())?;
        sink.note(&format!("report saved to {path}"));
        // The store numbers a collision rather than overwriting, so the name to
        // print — and the name `swp report` will accept — is the one it returned.
        let written = path
            .rsplit('/')
            .next()
            .and_then(|f| f.strip_suffix(".json"))
            .unwrap_or(stem.as_str())
            .to_string();
        Some(Saved {
            stem: written,
            path,
        })
    } else {
        None
    };

    match report.result {
        Outcome::ProvenanceDetected => {}
        Outcome::NoProvenanceDetected => {}
        // A refusal is not a result, and `--quiet` is not allowed to make it one.
        Outcome::Inconclusive => sink.warn(&format!(
            "this scan could not examine the whole candidate ({} omission(s)); it can say \
             nothing was confirmed, not that nothing is there",
            report.omissions.len()
        )),
    }
    let lines = render(&report, parsed, saved.as_ref())?;
    output::deliver(sink, &report, &lines, parsed.value(Flag::Output))?;
    Ok(report.exit_code())
}

/// The one positional this command takes, and nothing else.
///
/// `swp scan` with no candidate is a usage error rather than a scan of `.`: a
/// command whose accident is "read the entire current directory and tell me what
/// you find" is a command nobody leaves in a shared script.
fn candidate_path(parsed: &Parsed, cwd: &Path) -> Result<std::path::PathBuf, SwpError> {
    match parsed.positional.as_slice() {
        [] => Err(SwpError::new(
            ErrorCode::Usage,
            "scan needs a candidate to look at: a directory, a file, or a .zip/.tar/.tar.gz \
             archive. Nothing is executed while it is read.",
        )
        .with_path("swp scan <candidate>".to_string())),
        [one] => ctx::resolve(one, cwd),
        many => Err(SwpError::usage(format!(
            "scan takes one candidate, {} were given: {}. Scan them separately so each gets \
             its own report and exit code",
            many.len(),
            many.iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The text rendering: the evidence report's own, plus the two lines only the
/// command knows — where the saved copy went, and what to do next.
fn render(
    report: &Report,
    parsed: &Parsed,
    saved: Option<&Saved>,
) -> Result<Vec<String>, SwpError> {
    let limit = crate::output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let text = report.to_text_items(limit);
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    if let Some(at) = saved {
        lines.push(format!("\nSaved: {}", at.path));
    }
    lines.push(String::new());
    lines.push("Next".to_string());
    for step in next_steps(report, parsed.json()?, saved) {
        lines.push(format!("  {step}"));
    }
    lines.push(String::new());
    lines.push(format!("exit {}", report.exit_code()));
    Ok(lines)
}

/// What `--save` produced: the name to re-render it by, and the path that holds it.
struct Saved {
    stem: String,
    path: String,
}

fn next_steps(report: &Report, json: bool, saved: Option<&Saved>) -> Vec<String> {
    let mut out = Vec::new();
    match report.result {
        Outcome::ProvenanceDetected => {
            if let Some(tally) = report.releases.first() {
                out.push(format!(
                    "swp verify --release {} --save   (re-check your own tree)",
                    tally.release_id
                ));
            }
            out.push(
                "keep .swp/private/root.key and this report; the finding is reproducible only \
                 with the secret that derived these keys"
                    .to_string(),
            );
            if saved.is_none() {
                out.push(
                    "re-run with --save to keep this report under .swp/private/reports/"
                        .to_string(),
                );
            } else {
                out.push(format!(
                    "swp report {} --format json   (re-render the saved copy)",
                    saved.map(|s| s.stem.as_str()).unwrap_or_default()
                ));
            }
        }
        Outcome::NoProvenanceDetected => {
            out.push(
                "a clean reading is about this candidate and the releases loaded, nothing more"
                    .to_string(),
            );
            out.push("swp inspect releases   (which releases were searched)".to_string());
        }
        Outcome::Inconclusive => {
            out.push(
                "raise [limits] in .swp/config.toml, or scan a smaller input, then re-run"
                    .to_string(),
            );
            out.push("the Omissions list above names what was never opened".to_string());
        }
    }
    if !json {
        out.push("--format json for the same facts as one document".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::{Run, Scratch};

    #[test]
    fn a_candidate_is_required_and_two_are_refused() {
        let dir = Scratch::new("scan", "arity");
        let r = dir.run(&["scan"]);
        assert_eq!(r.code, ErrorCode::Usage.exit_code());
        assert!(r.err.contains("needs a candidate"), "{}", r.err);
        let r = dir.run(&["scan", "a", "b"]);
        assert_eq!(r.code, ErrorCode::Usage.exit_code());
        assert!(r.err.contains("one candidate"), "{}", r.err);
    }

    #[test]
    fn scanning_a_copy_reports_the_release_it_came_from() {
        let owner = Scratch::protected("scan", "copy");
        let leak = Scratch::new("scan", "copy-tree");
        owner.copy_sources_to(&leak);
        let r = owner.run(&["scan", &leak.root.display().to_string(), "--format", "json"]);
        assert_eq!(
            r.code, 1,
            "a copy of protected source is a finding:\n{}{}",
            r.out, r.err
        );
        let doc = r.json();
        assert_eq!(doc["schema"], "SWP-1-report-v1");
        assert_eq!(doc["protocol"], "SWP-1");
        assert_eq!(doc["result"], "PROVENANCE_DETECTED");
        assert_eq!(doc["run"]["command"], "scan");
        let releases = doc["releases"].as_array().unwrap();
        assert_eq!(releases.len(), 1, "{releases:?}");
        assert_eq!(releases[0]["project_id"], owner.project_id());
        assert!(releases[0]["fragments"].as_u64().unwrap() > 0);
        assert!(releases[0]["release_id"].is_string());
        assert!(doc["limitations"].as_array().unwrap().len() >= 4);
        assert!(!doc["evidence"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_clean_tree_exits_0_and_still_prints_the_whole_boundary() {
        let owner = Scratch::protected("scan", "clean");
        let other = Scratch::new("scan", "clean-tree");
        other.write("plain.js", "function h(x) {\n  return x + 1;\n}\n");
        let r = owner.run(&["scan", &other.root.display().to_string()]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert!(r.out.contains("NO_PROVENANCE_DETECTED"), "{}", r.out);
        assert!(
            r.out.contains("does not establish authorship"),
            "the authorship boundary travels with the report text too:\n{}",
            r.out
        );
        // The exit code is the last line of the text, so a reader who pipes the
        // report to a file sees the verdict and the grade in one place. Every
        // line Sink prints ends in a newline, hence `trim_end`.
        assert!(r.out.trim_end().ends_with("exit 0"), "{}", r.out);
    }

    #[test]
    fn a_missing_project_is_reported_before_the_candidate_is_touched() {
        let dir = Scratch::new("scan", "noproject");
        dir.write("x.js", "var a = 1;\n");
        let r = dir.run(&["scan", "."]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("swp init"), "{}", r.err);
    }

    #[test]
    fn the_candidate_cannot_supply_the_keys_that_judge_it() {
        // Both trees are protected projects, so the other one has its own `.swp/`
        // and its own keys, and its source is a different source rather than the
        // same files re-watermarked: keyed site addresses are a fact about the
        // tree's shape, so two identical trees would agree on them whatever the
        // keys were. Scanning it from the owner's directory must produce a verdict
        // about the *owner's* project: if the candidate's identity could reach the
        // index, the examined party would be supplying the evidence used to judge
        // them.
        let owner = Scratch::protected("scan", "keys-owner");
        let other = Scratch::protected_variant("scan", "keys-other", 1);
        assert_ne!(owner.project_id(), other.project_id());
        let r = owner.run(&[
            "scan",
            &other.root.display().to_string(),
            "--format",
            "json",
        ]);
        let doc = r.json();
        assert_eq!(
            doc["releases"][0]["project_id"].as_str(),
            Some(owner.project_id().as_str()),
            "the verdict was reached with somebody else's keys"
        );
        // The stable property is that an unrelated tree is never *claimed*, not
        // which of the two honest negatives this particular pair of keys happens
        // to produce: at the default width a 112-probe scan of a 4-site release
        // confirms a site or two by chance every time, and whether the count
        // reaches zero is a coin flip over the keys. What must never vary is the
        // verdict direction — the bound covers every confirmation this fixture
        // can produce, so the outcome is "clean" or "not enough to say", never
        // "found".
        assert_ne!(
            r.code,
            swp_evidence::Outcome::ProvenanceDetected.exit_code(),
            "an unrelated project's source was reported as carrying this release:\n{}",
            r.out
        );
        assert!(
            r.code == 0 || r.code == ErrorCode::InsufficientEvidence.exit_code(),
            "expected a clean or inconclusive verdict, got {}:\n{}",
            r.code,
            r.out
        );
        assert_ne!(doc["result"], "PROVENANCE_DETECTED", "{doc:#}");
        assert!(
            !doc["candidate"]["partial"].as_bool().unwrap(),
            "a complete scan must not describe itself as partial:\n{doc:#}"
        );
        if doc["result"] == "INCONCLUSIVE" {
            assert!(
                doc["explanation"].as_array().unwrap().iter().any(|l| l
                    .as_str()
                    .unwrap_or_default()
                    .contains("the bound covers them")),
                "an inconclusive verdict owed its reader the arithmetic behind it:\n{doc:#}"
            );
        }
        // The candidate's own store is reported as data, never opened as config.
        assert_eq!(doc["candidate"]["kind"], "directory");
    }

    #[test]
    fn save_keeps_the_report_with_the_owner_and_output_writes_the_document() {
        let owner = Scratch::protected("scan", "save");
        let other = Scratch::new("scan", "save-tree");
        other.write("plain.js", "function h(x) {\n  return x + 2;\n}\n");
        let at = owner.root.join("scan-doc.json");
        let r = owner.run(&[
            "scan",
            &other.root.display().to_string(),
            "--save",
            "--output",
            &at.display().to_string(),
        ]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(
            r.out.is_empty(),
            "--output leaves stdout empty: {:?}",
            r.out
        );
        let written = std::fs::read_to_string(&at).unwrap();
        assert!(
            written.contains("\"schema\": \"SWP-1-report-v1\""),
            "{written}"
        );
        let names = owner.store().report_names().unwrap();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("scan-"), "{}", names[0]);
        assert!(
            r.err.contains(&names[0]),
            "the saved name is told to the operator: {}",
            r.err
        );
        // The saved copy is the same document, and re-reads under the same rules.
        let bytes = owner.store().read_report(&names[0]).unwrap();
        let back = Report::from_json(&String::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(back.result, Outcome::NoProvenanceDetected);
        assert_eq!(back.run.command, "scan");
    }

    #[test]
    fn quiet_saves_and_reports_nothing_but_the_document() {
        let owner = Scratch::protected("scan", "quiet");
        let other = Scratch::new("scan", "quiet-tree");
        other.write("plain.js", "function h(x) {\n  return x + 3;\n}\n");
        let r = owner.run(&[
            "scan",
            &other.root.display().to_string(),
            "--quiet",
            "--save",
            "--verbose",
        ]);
        assert_eq!(r.code, 0, "{}", r.err);
        assert!(r.out.contains("NO_PROVENANCE_DETECTED"), "{}", r.out);
        // --verbose asks for progress; --quiet is what removes it again.
        assert!(!r.err.contains("read; matching"), "{}", r.err);
    }

    #[test]
    fn an_unknown_release_is_refused_with_the_list_of_what_exists() {
        let owner = Scratch::protected("scan", "unknown-release");
        let r = owner.run(&["scan", ".", "--release", "rel-aaaaaaaaaaaaaaaa"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("no release"), "{}", r.err);
        assert!(r.err.contains("inspect releases"), "{}", r.err);
    }

    #[test]
    fn limit_sizes_the_evidence_list_and_full_removes_the_cap() {
        let owner = Scratch::protected("scan", "limit");
        let leak = Scratch::new("scan", "limit-tree");
        owner.copy_sources_to(&leak);
        let at = leak.root.display().to_string();
        let few = owner.run(&["scan", &at, "--limit", "1"]);
        let all = owner.run(&["scan", &at, "--full"]);
        assert_eq!(few.code, 1);
        assert_eq!(all.code, 1);
        assert!(
            few.out.contains("more; re-run with"),
            "a windowed list says it is windowed:\n{}",
            few.out
        );
        assert!(!all.out.contains("more; re-run with"), "{}", all.out);
        // Both readings printed the same document size in JSON, window or not.
        let j = |r: Run| r.json()["evidence"].as_array().unwrap().len();
        assert_eq!(
            j(owner.run(&["scan", &at, "--limit", "1", "--format", "json"])),
            j(owner.run(&["scan", &at, "--full", "--format", "json"])),
            "--limit must not cut the JSON document"
        );
    }
}
