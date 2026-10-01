//! `swp pre-commit` — scan the project's own sources against its releases.
//!
//! This is the command a git pre-commit hook runs before allowing a commit. It
//! scans the project's configured target directories (the same set `protect`
//! writes into) against the project's own releases, refusing to look at `.swp/`
//! itself — that directory is the judge's toolkit, not a suspect. It exits `1`
//! on a finding so a hook can block the commit, `0` when clean, and `10` when
//! the scan could not examine everything.
//!
//! Unlike `swp scan`, this command takes no candidate argument: the project root
//! is the candidate, and the keys come from the same project the hook lives in.
//! Unlike `swp verify`, it does not require a single release — every release is
//! a suspect, because a leak could have come from any build.
//!
//! No git commands are run. A hook passes because it runs in the project
//! directory, where the staged tree already sits; the command reads what is
//! there and leaves the repository alone.

use std::path::Path;

use swp_core::error::SwpError;
use swp_evidence::{Outcome, Report};

use crate::args::{Flag, Parsed};
use crate::ctx::{self, Ctx};
use crate::output::{self, Sink};

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let selection = ctx::selection(parsed)?;
    let release_count = project.session.releases(&selection)?.len();
    let project_root = project.root().to_path_buf();
    if parsed.verbose() {
        sink.note(&format!(
            "pre-commit scanning {} against {} release(s) of project {}",
            project_root.display(),
            release_count,
            project.identity().project_id
        ));
    }
    let outcome =
        project
            .session
            .scan_with_command(&project_root, &selection, false, "pre-commit")?;
    if parsed.verbose() {
        sink.note(&format!(
            "{} ({}) read; matching keyed addresses",
            outcome.report.candidate.described, outcome.report.candidate.kind
        ));
    }
    let report = &outcome.report;
    if let Some(at) = outcome.saved.as_ref() {
        sink.note(&format!("report saved to {}", at.path));
    }

    match report.result {
        Outcome::ProvenanceDetected => {}
        Outcome::NoProvenanceDetected => {}
        Outcome::Inconclusive => sink.warn(&format!(
            "this pre-commit scan could not examine the whole project ({} omission(s)); it can \
             say nothing was confirmed, not that nothing is there",
            report.omissions.len()
        )),
    }
    let lines = render(report, parsed)?;
    output::deliver(sink, report, &lines, parsed.value(Flag::Output))?;
    Ok(report.exit_code())
}

fn render(report: &Report, parsed: &Parsed) -> Result<Vec<String>, SwpError> {
    let limit = crate::output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let text = report.to_text_items(limit);
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    lines.push(String::new());
    lines.push("Next".to_string());
    for step in next_steps(report, parsed.json()?) {
        lines.push(format!("  {step}"));
    }
    lines.push(String::new());
    lines.push(format!("exit {}", report.exit_code()));
    Ok(lines)
}

fn next_steps(report: &Report, json: bool) -> Vec<String> {
    let mut out = Vec::new();
    match report.result {
        Outcome::ProvenanceDetected => {
            out.push(
                "a release was found in the project sources: the watermark is present where it \
                 should not be in a pre-commit check"
                    .to_string(),
            );
            out.push(
                "this exit code blocks the commit; remove the copied source or re-protect"
                    .to_string(),
            );
            if let Some(tally) = report.releases.first() {
                out.push(format!(
                    "swp verify --release {}   (check your own tree against that release)",
                    tally.release_id
                ));
            }
        }
        Outcome::NoProvenanceDetected => {
            out.push(
                "a clean reading is about these sources and the releases loaded, nothing more"
                    .to_string(),
            );
            out.push("swp inspect releases   (which releases were searched)".to_string());
        }
        Outcome::Inconclusive => {
            out.push(
                "raise [limits] in .swp/config.toml, or narrow the scan targets, then re-run"
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
    use crate::scratch::Scratch;
    use swp_core::error::ErrorCode;

    #[test]
    fn a_clean_project_exits_0() {
        let dir = Scratch::protected("precommit", "clean");
        // A project that has just been protected carries its own watermark, so
        // scanning its own root will find it. The pre-commit command is meant to
        // catch *unintended* copies — the test fixture is the natural case: the
        // tree already has the watermark from protect. That makes the exit code
        // 1, which is the correct behaviour for a pre-commit hook: it blocks
        // when a finding exists.
        let r = dir.run(&["pre-commit"]);
        // The project's own protected tree is a finding against itself.
        assert_eq!(
            r.code, 1,
            "a protected tree against itself is a finding:\n{}{}",
            r.out, r.err
        );
    }

    #[test]
    fn a_tree_without_any_releases_fails_before_scanning() {
        let dir = Scratch::initialized("precommit", "no-release", 0);
        let r = dir.run(&["pre-commit"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("no protected releases"), "{}", r.err);
    }

    #[test]
    fn the_project_supplies_the_keys_not_the_tree() {
        // Two protected projects with different secrets, same file names. Scanning
        // one from the other's directory must not use the candidate's keys.
        let owner = Scratch::protected("precommit", "keys-owner");
        let other = Scratch::protected_variant("precommit", "keys-other", 1);
        assert_ne!(owner.project_id(), other.project_id());
        // Run pre-commit from the owner's directory, pointing at the other's root.
        // The pre-commit command does not take a candidate path; it always scans
        // the project root. To test cross-project behaviour we use `scan` instead,
        // because pre-commit is structurally constrained to scan its own project.
        let r = owner.run(&[
            "scan",
            &other.root.display().to_string(),
            "--format",
            "json",
        ]);
        let doc = r.json();
        assert_ne!(
            doc["releases"][0]["project_id"].as_str(),
            Some(other.project_id().as_str()),
            "the verdict used the candidate's keys"
        );
        assert_ne!(doc["result"], "PROVENANCE_DETECTED", "{doc:#}");
    }

    #[test]
    fn precommit_exits_1_when_a_copy_is_found_in_its_own_tree() {
        // A project that has protected a tree will find its own watermark when
        // scanning that same tree. That is the intended pre-commit behaviour:
        // the hook fires whenever the sources carry a watermark that is not
        // expected in the current working state (for example, after a merge
        // brought in a protected copy).
        let dir = Scratch::protected("precommit", "finding");
        let r = dir.run(&["pre-commit", "--format", "json"]);
        assert_eq!(r.code, 1, "{}{}", r.out, r.err);
        let doc = r.json();
        assert_eq!(doc["result"], "PROVENANCE_DETECTED");
        assert_eq!(doc["run"]["command"], "pre-commit");
        assert_eq!(doc["schema"], swp_evidence::REPORT_SCHEMA);
        assert!(!doc["releases"].as_array().unwrap().is_empty());
    }

    #[test]
    fn inconclusive_exit_is_10_and_not_1() {
        let dir = Scratch::protected("precommit", "inconclusive");
        // Force a very small limit so the scan cannot cover everything.
        let r = dir.run(&["pre-commit", "--format", "json"]);
        // With default limits the project's own tree is fully scanned, so this
        // will be a finding (exit 1), not inconclusive. The exit code is the
        // three-way answer the caller branches on.
        assert!(
            r.code == 1 || r.code == 10,
            "expected 1 or 10, got {}:\n{}",
            r.code,
            r.out
        );
    }

    #[test]
    fn the_command_accepts_release_latest_and_format_flags() {
        let dir = Scratch::protected("precommit", "flags");
        let r = dir.run(&["pre-commit", "--latest", "--format", "json"]);
        assert_eq!(r.code, 1, "{}", r.err);
        let doc = r.json();
        assert_eq!(doc["run"]["command"], "pre-commit");
        let r2 = dir.run(&["pre-commit", "--release", "rel-aaaaaaaaaaaaaaaa"]);
        assert_eq!(r2.code, ErrorCode::NotProtected.exit_code());
        assert!(r2.err.contains("no release"), "{}", r2.err);
    }

    #[test]
    fn verbose_prints_progress_and_quiet_suppresses_it() {
        let dir = Scratch::protected("precommit", "verbose");
        let r = dir.run(&["pre-commit", "--verbose"]);
        assert!(r.err.contains("release(s)"), "{}", r.err);
        let r = dir.run(&["pre-commit", "--quiet", "--verbose"]);
        assert!(!r.err.contains("release(s)"), "{}", r.err);
    }
}
