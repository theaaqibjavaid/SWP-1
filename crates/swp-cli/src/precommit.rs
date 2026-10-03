//! `swp pre-commit` — the verification a git hook can branch an exit code on.
//!
//! A hook wants one answer about the tree it is about to commit: does it still
//! carry the release this project last recorded? That is exactly what
//! [`swp_sdk::Session::verify`] measures, so this command is that call over the
//! project's own root with the document's exit code handed back to git — `0`
//! allows the commit, `5` blocks it, `10` says the run could not have told either
//! way. Nothing here re-implements the grading, the per-site rows, or the mapping
//! from a verdict to a code: `swp verify` and this command print the same page
//! because they read the same document.
//!
//! ## What it is not
//!
//! It is not a leak detector, and the difference matters more than the shared
//! machinery. `swp scan` asks whether *somebody else's* artifact carries this
//! project's provenance, against every release, because a copy could have come
//! from any build. This command has no candidate: the tree it reads is the tree
//! the release was made from, so a `5` here is not evidence about anybody — it
//! says the working copy no longer renders the literals your last `protect`
//! recorded. A reverted file, a merge that took the unprotected side, and a
//! deliberate strip all produce the same reading, and this command cannot tell
//! them apart (§51); `swp verify`'s module documents why.
//!
//! It checks **one** release per run — the newest, or the one `--release` names —
//! because a per-site verdict needs a single manifest to grade against. That is
//! the same limit `swp verify` carries, not a weakening added here.
//!
//! No git command is run, nothing is written, and the store's `.swp/` directory is
//! not part of the tree examined: a hook passes because it runs in the project
//! directory, where the working copy already sits.

use std::path::Path;

use swp_core::error::SwpError;
use swp_evidence::Verdict;
use swp_sdk::VerifyOptions;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};
use crate::verify;

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let limit = output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let release = project.one_release(parsed)?;
    if parsed.verbose() {
        sink.note(&format!(
            "pre-commit checking {} against release {} of project {}",
            project.root().display(),
            release,
            project.identity().project_id
        ));
    }
    let outcome = project.session.verify(&VerifyOptions {
        release: Some(release),
        // A hook blocks or allows; keeping a document is `swp verify --save`'s
        // job, and writing into the store from a commit step would change what
        // the commit contains.
        save: false,
        // The document carries every row whatever the window; the page counts the
        // ones it leaves out.
        rows: Some(limit),
    })?;
    let doc = &outcome.document;
    let (shown, _) = output::head(&doc.sites, limit);
    let missing: Vec<_> = doc.sites.iter().filter(|r| !r.confirmed()).collect();
    let lines = verify::text_lines(doc, "pre-commit", shown, &missing);
    // `--quiet` suppresses progress, not a refusal: the reason a commit was
    // blocked has to reach the developer even when the page does not.
    match doc.verdict {
        Verdict::Intact => {}
        Verdict::Incomplete => sink.warn(&format!(
            "commit blocked: {} of {} site(s) of release {} are not carrying their code",
            doc.sites_expected - doc.sites_confirmed,
            doc.sites_expected,
            doc.release_id
        )),
        Verdict::Inconclusive => sink.warn(&format!(
            "commit blocked: this run did not examine the whole tree ({} omission(s)), so it \
             cannot say the remaining {} site(s) still carry their code",
            doc.omissions.len(),
            doc.sites_expected - doc.sites_confirmed
        )),
    }
    // No `--output` in this command's grammar: a hook's answer is its exit code and
    // its own streams, not a file nobody asked for.
    output::deliver(sink, doc, &lines, None)?;
    Ok(doc.exit_code)
}

#[cfg(test)]
mod tests {
    use crate::scratch::Scratch;
    use swp_core::error::ErrorCode;

    #[test]
    fn a_tree_still_carrying_its_release_allows_the_commit() {
        let dir = Scratch::protected("precommit", "intact");
        let r = dir.run(&["pre-commit", "--format", "json"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let doc = r.json();
        assert_eq!(doc["schema"], swp_evidence::VERIFY_SCHEMA);
        assert_eq!(doc["verdict"], "INTACT");
        assert_eq!(doc["exit_code"], 0);
        assert_eq!(doc["sites_confirmed"], doc["sites_expected"]);
        assert_eq!(doc["partial"], false);
    }

    #[test]
    fn a_commit_that_would_lose_the_watermark_is_blocked() {
        let dir = Scratch::protected("precommit", "blocked");
        // Which file the key put a site in is not knowable from here, so every
        // source file is replaced rather than one: the sites are gone wherever
        // they landed.
        for rel in dir.sources() {
            dir.write(
                &rel,
                "function gone(base, scale) {\n  return base * scale;\n}\n",
            );
        }
        let r = dir.run(&["pre-commit", "--format", "json"]);
        assert_eq!(
            r.code,
            ErrorCode::ReleaseMismatch.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        let doc = r.json();
        assert_eq!(doc["verdict"], "INCOMPLETE");
        assert!(
            doc["sites_confirmed"].as_u64().unwrap() < doc["sites_expected"].as_u64().unwrap(),
            "the strip went unnoticed: {doc}"
        );
        let t = dir.run(&["pre-commit"]);
        assert!(t.out.contains("pre-commit "), "the page says who ran it");
        assert!(t.err.contains("commit blocked"), "{}", t.err);
    }

    #[test]
    fn a_run_that_could_not_read_the_whole_tree_is_inconclusive() {
        let dir = Scratch::protected("precommit", "partial");
        // Every source file is above this bound, so no site is examined and the
        // run cannot grade the tree it failed to read. That is the third answer,
        // not a weak version of the first.
        shrink_max_file_bytes(&dir, 100);
        let r = dir.run(&["pre-commit", "--format", "json"]);
        assert_eq!(
            r.code,
            ErrorCode::InsufficientEvidence.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        let doc = r.json();
        assert_eq!(doc["verdict"], "INCONCLUSIVE");
        assert_eq!(doc["partial"], true);
        assert!(
            !doc["omissions"].as_array().unwrap().is_empty(),
            "the document names what was never opened: {doc}"
        );
        assert!(
            r.err.contains("did not examine the whole tree"),
            "{}",
            r.err
        );
    }

    #[test]
    fn a_tree_without_any_releases_fails_before_grading() {
        let dir = Scratch::initialized("precommit", "no-release", 0);
        let r = dir.run(&["pre-commit"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("no protected releases"), "{}", r.err);
    }

    #[test]
    fn a_release_that_was_never_published_is_refused_by_name() {
        let dir = Scratch::protected("precommit", "unknown-release");
        let r = dir.run(&["pre-commit", "--release", "rel-aaaaaaaaaaaaaaaa"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code(), "{}", r.err);
        assert!(r.err.contains("no release"), "{}", r.err);
    }

    #[test]
    fn the_hook_writes_nothing_anywhere() {
        // A command that runs inside `git commit` must not change what is
        // committed: not a source file, not a store artifact, not a saved report.
        let dir = Scratch::protected("precommit", "readonly");
        let before_sources = dir.sources();
        let before_bodies: Vec<String> = before_sources
            .iter()
            .map(|rel| dir.read(rel))
            .collect::<Vec<_>>();
        let before_store = dir.store_files();
        let r = dir.run(&["pre-commit"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert_eq!(dir.sources(), before_sources);
        for (rel, body) in before_sources.iter().zip(&before_bodies) {
            assert_eq!(dir.read(rel), *body, "{rel} moved under the hook");
        }
        assert_eq!(dir.store_files(), before_store);
    }

    #[test]
    fn latest_and_a_named_release_name_the_same_release() {
        let dir = Scratch::protected("precommit", "latest-named");
        let first = dir.run(&["pre-commit", "--latest", "--format", "json"]);
        assert_eq!(first.code, 0, "{}", first.err);
        let id = first.json()["release_id"].as_str().unwrap().to_string();
        let named = dir.run(&["pre-commit", "--release", &id, "--format", "json"]);
        assert_eq!(named.code, 0, "{}", named.err);
        assert_eq!(named.json()["release_id"], id);
    }

    #[test]
    fn verbose_prints_progress_and_quiet_suppresses_it() {
        let dir = Scratch::protected("precommit", "verbose");
        let r = dir.run(&["pre-commit", "--verbose"]);
        assert!(r.err.contains("pre-commit checking"), "{}", r.err);
        let r = dir.run(&["pre-commit", "--quiet", "--verbose"]);
        assert!(!r.err.contains("pre-commit checking"), "{}", r.err);
    }

    #[test]
    fn compliance_is_not_an_option_here() {
        // `--compliance` grades a scan of somebody else's artifact against several
        // releases. A single-release verdict has no such tally to attach, so the
        // flag is refused rather than accepted and ignored.
        let dir = Scratch::protected("precommit", "compliance");
        let r = dir.run(&["pre-commit", "--compliance"]);
        assert_eq!(r.code, ErrorCode::Usage.exit_code(), "{}", r.err);
        assert!(
            r.err.contains("is not an option of `swp pre-commit`"),
            "the refusal names the command: {}",
            r.err
        );
    }

    /// Rewrite the stored `[limits] max_file_bytes` so a scan of this tree is
    /// knowingly incomplete.
    fn shrink_max_file_bytes(dir: &Scratch, bytes: u64) {
        let text = dir.read(".swp/config.toml");
        let shrunk: Vec<String> = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("max_file_bytes") {
                    format!("max_file_bytes = {bytes}")
                } else {
                    line.to_string()
                }
            })
            .collect();
        dir.write(".swp/config.toml", &(shrunk.join("\n") + "\n"));
    }
}
