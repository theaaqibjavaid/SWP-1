//! `swp generate` and `swp protect` — decide a constellation, then apply it.
//!
//! Both commands are the same pipeline with one flag different, which is the
//! point of splitting them: `generate` is what `protect` would have chosen, run
//! against the tree as it is now, so an operator can read the plan before the
//! diff exists. [`swp_embedding::protect`] does the work and returns a
//! [`Protection`]; this file turns that into §35's answer — what was generated,
//! what was modified, where the private data is, what to back up, what may be
//! committed, and what may never be.
//!
//! ## What this file refuses to print
//!
//! The JSON document here carries counts, names, a fingerprint and the plan's
//! *refusals* — never the plan's site list. A location id is a keyed value, and
//! while nothing in the protocol recovers a key from one, a command whose stdout
//! is a list of every keyed address in the project is a command that ends up in
//! CI logs. The full constellation is in `.swp/private/plans/<id>.json`, which is
//! the file the store already hardened, and the document says so.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use swp_core::error::SwpError;
use swp_core::id::Digest;
use swp_embedding::{Mode, Protection, Request};
use swp_identity::{new_release_id, SourceRevision};
use swp_manifest::{BACKUP_ARTIFACTS, PRIVATE_ARTIFACTS, PUBLIC_ARTIFACTS};

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::Sink;

#[derive(Debug, Serialize)]
struct Changed {
    file: String,
    sites: u32,
    bytes_before: u64,
    bytes_after: u64,
}

/// `SWP-1-protection-v1` — one run's account of itself.
#[derive(Debug, Serialize)]
struct ProtectionDocument {
    schema: &'static str,
    protocol: &'static str,
    /// `generate` or `protect`, because the two wrote the same shape of document
    /// and only the command name tells them apart.
    command: String,
    mode: String,
    project_id: String,
    release_id: String,
    created_at: String,
    /// What the operator said this source was. Display metadata, never hashed.
    revision: Option<String>,
    /// The §16 fingerprint of the tree as it now stands.
    fingerprint: Digest,
    fingerprint_level: String,
    tag_bits: u8,
    requested_sites: u32,
    target_sites: u32,
    sites_embedded: u32,
    sites_skipped: u32,
    files_walked: usize,
    files_in_scope: usize,
    candidates: usize,
    files_changed: Vec<Changed>,
    /// Why each refused candidate was refused, counted.
    skip_reasons: BTreeMap<String, u32>,
    /// Where the families the release used came from, so a report reader can see
    /// how much of the constellation is arithmetic and how much is structural.
    families: BTreeMap<String, u32>,
    /// Every artifact this run wrote, in write order.
    artifacts: Vec<String>,
    generated: Vec<String>,
    modified: Vec<String>,
    commit: &'static [&'static str],
    never_commit: &'static [&'static str],
    back_up: &'static [&'static str],
    notes: Vec<String>,
    next: Vec<String>,
}

pub fn run(
    parsed: &Parsed,
    cwd: &Path,
    sink: &mut Sink<'_>,
    mode: Mode,
) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in &project.warnings {
        sink.warn(warning);
    }
    // `--release` on a protection run is how a generated plan gets applied: the
    // constellation is keyed by release id, so the same id over the same tree is
    // the same plan, byte for byte.
    let release_id = match parsed.value(Flag::Release) {
        Some(raw) => swp_core::ReleaseId::new(raw)?,
        None => new_release_id()?,
    };
    let revision = match parsed.value(Flag::Revision) {
        Some(text) => SourceRevision::Manual {
            value: text.trim().to_string(),
        },
        // `Content`, always, unless the operator named a revision. There is no
        // shell-out to `git` anywhere in this build: §21 forbids running things
        // in a tree that may not be the operator's, and a protection run is
        // allowed to be pointed at a directory that is not a repository at all.
        None => SourceRevision::Content,
    };
    let secret = project.secret()?;
    let request = Request {
        root: project.root(),
        store: &project.store,
        secret: &secret,
        identity: &project.identity,
        config: &project.config,
        release_id: release_id.clone(),
        revision,
        created_at: swp_identity::Timestamp::now_utc(),
        mode,
    };
    let protection = swp_embedding::protect(&request)?;
    drop(secret);
    let stated = parsed
        .value(Flag::Revision)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let doc = document(&protection, mode, stated);
    let lines = text_lines(&doc, mode);
    for note in &protection.notes {
        sink.note(note);
    }
    if protection.sites_skipped > 0 {
        sink.warn(&format!(
            "{} candidate location(s) were refused for safety; the release carries {} sites",
            protection.sites_skipped, protection.sites_embedded
        ));
    }
    sink.result(&doc, &lines)?;
    Ok(0)
}

fn document(p: &Protection, mode: Mode, revision: Option<String>) -> ProtectionDocument {
    let mut families: BTreeMap<String, u32> = BTreeMap::new();
    for site in &p.plan.sites {
        *families.entry(site.family.clone()).or_insert(0) += 1;
    }
    let mut skip_reasons: BTreeMap<String, u32> = BTreeMap::new();
    for skipped in &p.plan.skipped {
        *skip_reasons.entry(skipped.reason.clone()).or_insert(0) += 1;
    }
    let command = match mode {
        Mode::Plan => "generate",
        Mode::Release => "protect",
        Mode::DryRun => "protect --dry-run",
    };
    let next = match mode {
        Mode::Plan => vec![
            format!("swp inspect fragments --release {}", p.release_id),
            format!("swp protect --release {}", p.release_id),
            "swp verify".to_string(),
        ],
        Mode::Release => vec![
            "swp verify".to_string(),
            format!("swp inspect release --release {}", p.release_id),
            "commit .swp/public/releases/, and back up .swp/private/".to_string(),
        ],
        Mode::DryRun => vec!["swp protect".to_string()],
    };
    ProtectionDocument {
        schema: "SWP-1-protection-v1",
        protocol: swp_core::SWP_PROTOCOL_NAME,
        command: command.to_string(),
        mode: p.mode.as_str().to_string(),
        project_id: p.project_id.to_string(),
        release_id: p.release_id.to_string(),
        created_at: p.created_at.to_rfc3339(),
        revision,
        fingerprint: p.fingerprint,
        fingerprint_level: p.fingerprint_level.clone(),
        tag_bits: p.tag_bits,
        requested_sites: p.requested_sites,
        target_sites: p.target_sites,
        sites_embedded: p.sites_embedded,
        sites_skipped: p.sites_skipped,
        files_walked: p.files_walked,
        files_in_scope: p.files_in_scope,
        candidates: p.candidates,
        files_changed: p
            .files_changed
            .iter()
            .map(|f| Changed {
                file: f.file.clone(),
                sites: f.sites,
                bytes_before: f.bytes_before,
                bytes_after: f.bytes_after,
            })
            .collect(),
        skip_reasons,
        families,
        artifacts: p.artifacts.clone(),
        generated: p.artifacts.clone(),
        modified: p.files_changed.iter().map(|f| f.file.clone()).collect(),
        commit: PUBLIC_ARTIFACTS,
        never_commit: PRIVATE_ARTIFACTS,
        back_up: BACKUP_ARTIFACTS,
        notes: p.notes.clone(),
        next,
    }
}

fn text_lines(d: &ProtectionDocument, mode: Mode) -> Vec<String> {
    let mut out = vec![
        format!(
            "{} {} — release {}",
            match mode {
                Mode::Plan => "planned",
                Mode::Release => "protected",
                Mode::DryRun => "would protect",
            },
            d.project_id,
            d.release_id
        ),
        format!("  sites       {}/{} embedded, {} refused", d.sites_embedded, d.target_sites, d.sites_skipped),
        format!("  tag         {} bits per site", d.tag_bits),
        format!("  fingerprint {} ({})", d.fingerprint, d.fingerprint_level),
        format!(
            "  scope       {} file(s) analyzed, {} file(s) hashed into the fingerprint",
            d.files_walked, d.files_in_scope
        ),
        String::new(),
    ];
    out.push(match mode {
        Mode::Plan => "What was generated".to_string(),
        Mode::DryRun => "What would be generated".to_string(),
        Mode::Release => "What was generated".to_string(),
    });
    if d.generated.is_empty() {
        out.push("  nothing on disk: a dry run writes no artifact".to_string());
    } else {
        out.extend(d.generated.iter().map(|a| format!("  {a}")));
    }
    out.push(String::new());
    out.push(if mode.writes_source() {
        format!("What was modified ({} file(s))", d.modified.len())
    } else {
        "What was modified".to_string()
    });
    if d.modified.is_empty() {
        out.push(match mode {
            Mode::Plan => "  no source file. The plan is saved; `swp protect` applies it."
                .to_string(),
            Mode::DryRun => "  nothing. This run wrote no artifact and edited no file."
                .to_string(),
            Mode::Release => "  nothing, which cannot happen for a release.".to_string(),
        });
    }
    for change in &d.files_changed {
        out.push(format!(
            "  {} — {} site(s), {} → {} bytes",
            change.file, change.sites, change.bytes_before, change.bytes_after
        ));
    }
    out.push(String::new());
    out.push("How the constellation is built".to_string());
    for (family, n) in &d.families {
        out.push(format!("  {family:<12} {n} site(s)"));
    }
    if !d.skip_reasons.is_empty() {
        out.push(String::new());
        out.push("What was refused, and why (§11: skipped, never forced)".to_string());
        for (reason, n) in &d.skip_reasons {
            out.push(format!("  {reason:<24} {n}"));
        }
        out.push(format!(
            "  read them with: swp inspect fragments --release {}",
            d.release_id
        ));
    }
    out.push(String::new());
    out.push("Where the private data is".to_string());
    out.extend(d.never_commit.iter().map(|p| format!("  {p}")));
    out.push(String::new());
    out.push("Back this up".to_string());
    out.extend(d.back_up.iter().map(|p| format!("  {p}")));
    out.push(String::new());
    out.push("You may commit".to_string());
    out.extend(d.commit.iter().map(|p| format!("  {p}")));
    out.push(String::new());
    out.push("Next".to_string());
    out.extend(d.next.iter().map(|n| format!("  {n}")));
    out.push(String::new());
    out.push(match mode {
        Mode::Plan => format!(
            "This release is not protected yet: {} site(s) exist only in a plan. Nothing here \
             is verifiable until `swp protect --release {}` writes them.",
            d.sites_embedded, d.release_id
        ),
        Mode::DryRun => format!(
            "A dry run records nothing. `swp protect --release {}` would embed {} site(s) in \
             {} file(s).",
            d.release_id,
            d.sites_embedded,
            d.modified.len()
        ),
        Mode::Release => format!(
            "{} site(s) across {} file(s) are now part of this project's source. `swp verify` \
             checks them against release {}; `swp scan <copy>` looks for them elsewhere.",
            d.sites_embedded,
            d.modified.len(),
            d.release_id
        ),
    });
    out
}

#[cfg(test)]
mod tests {
    use crate::scratch::Scratch;
    use serde_json::Value;

    /// Every source file and its exact bytes, which is what "changed nothing" has
    /// to be measured against.
    fn snapshot(dir: &Scratch) -> Vec<(String, String)> {
        dir.sources().into_iter().map(|f| (f.clone(), dir.read(&f))).collect()
    }

    /// The keyed addresses one release published privately — the strings that must
    /// never reach a terminal, a CI log or a JSON document on stdout.
    fn addresses(dir: &Scratch, release: &str) -> Vec<String> {
        let raw = dir.read(&format!(".swp/private/manifests/{release}.json"));
        let doc: Value = serde_json::from_str(&raw).unwrap();
        let mut out = Vec::new();
        for site in doc["sites"].as_array().unwrap() {
            for id in site["locations"].as_array().unwrap() {
                out.push(id.as_str().unwrap_or_default().to_string());
            }
        }
        assert!(out.len() >= 4, "the manifest published no keyed addresses: {raw}");
        out
    }

    #[test]
    fn a_protect_run_answers_every_part_of_the_operators_question() {
        // §35 is six questions, and the tool is expected to answer them in one
        // place rather than in documentation the operator has to trust.
        let dir = Scratch::initialized("protect", "account", 0);
        let before = snapshot(&dir);
        let r = dir.run(&["protect"]);
        assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
        for heading in [
            "What was generated",
            "What was modified",
            "Where the private data is",
            "Back this up",
            "You may commit",
            "Next",
        ] {
            assert!(r.out.contains(heading), "no {heading:?} section:\n{}", r.out);
        }
        // Naming the categories is not answering them: the private list has to
        // point at the file that can rebuild every tag.
        assert!(r.out.contains(".swp/private/root.key"), "{}", r.out);
        assert!(r.out.contains(".swp/public/releases/"), "{}", r.out);

        // And the modification list is the truth about the tree, not a summary of
        // it: every source file the run edited is named, and every file it names it
        // really edited.
        let after = snapshot(&dir);
        let edited: Vec<String> = before
            .iter()
            .zip(&after)
            .filter(|(_, (was, now))| was != now)
            .map(|((file, _), _)| file.to_string())
            // Bookkeeping at the project root — the `.gitignore` line that keeps the
            // private store out of a commit — is not a source modification, and the
            // §35 list is about the source.
            .filter(|file| file.contains('/'))
            .collect();
        assert!(!edited.is_empty(), "protect wrote a release and edited no source");
        assert_eq!(before.len(), after.len(), "protect added or deleted a file");
        let claimed: Vec<String> = r
            .out
            .split("What was modified")
            .nth(1)
            .unwrap_or_else(|| panic!("no modification section:
{}", r.out))
            .split("How the constellation is built")
            .next()
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once(" — ").map(|(file, _)| file.trim().to_string()))
            .collect();
        assert_eq!(claimed, edited, "the modification list is not the tree's diff");
    }

    #[test]
    fn the_protection_answer_publishes_counts_not_keyed_addresses() {
        let dir = Scratch::initialized("protect", "addresses", 0);
        let r = dir.run(&["protect", "--format", "json"]);
        assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
        let doc = r.json();
        assert_eq!(doc["schema"], "SWP-1-protection-v1");
        assert_eq!(doc["protocol"], "SWP-1");
        assert_eq!(doc["command"], "protect");
        assert_eq!(doc["mode"], "release");
        let release = doc["release_id"].as_str().unwrap().to_string();
        assert_eq!(doc["project_id"], dir.project_id());
        assert!(doc["sites_embedded"].as_u64().unwrap() > 0, "{doc:#}");

        // The document is the machine-readable answer, so it is the one that has to
        // keep the promise the module doc makes: counts and a fingerprint, never
        // the constellation itself.
        let text = serde_json::to_string(&doc).unwrap();
        for id in addresses(&dir, &release) {
            assert!(!text.contains(&id), "stdout carried keyed address {id}");
            assert!(!r.err.contains(&id), "stderr carried keyed address {id}");
        }
        assert!(
            doc.get("sites").is_none() && text.contains("\"sites_embedded\""),
            "the site list belongs in the private plan, not here: {text}"
        );
        // Where it does live, stated as a path the operator can back up.
        assert!(
            doc["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str().unwrap_or_default().contains(".swp/private/manifests/")),
            "{doc:#}"
        );
    }

    #[test]
    fn a_dry_run_changes_neither_the_source_nor_the_store() {
        // `--dry-run` is the flag an operator only reaches for when they do not
        // trust the tool not to write, so the claim has to be about every file.
        let dir = Scratch::initialized("protect", "dry", 0);
        let before = snapshot(&dir);
        let store_before = dir.store_files();
        let r = dir.run(&["protect", "--dry-run"]);
        assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
        assert_eq!(snapshot(&dir), before, "a dry run edited the source");
        assert_eq!(dir.store_files(), store_before, "a dry run wrote into the store");
        assert!(r.out.contains("A dry run records nothing"), "{}", r.out);
        assert!(r.out.contains("nothing on disk"), "{}", r.out);
    }

    #[test]
    fn generate_plans_a_release_that_protect_then_applies() {
        // The two commands are one pipeline, and the plan is the handoff: what
        // `generate` counted is what `protect --release` must embed, or the
        // operator read a plan that was not the one applied.
        let dir = Scratch::initialized("protect", "plan", 0);
        let before = snapshot(&dir);
        let g = dir.run(&["generate", "--format", "json"]);
        assert_eq!(g.code, 0, "{}\n{}", g.out, g.err);
        let planned = g.json();
        assert_eq!(planned["command"], "generate");
        assert_eq!(planned["mode"], "plan");
        assert_eq!(snapshot(&dir), before, "generate edited the source");
        let release = planned["release_id"].as_str().unwrap().to_string();
        let count = planned["sites_embedded"].as_u64().unwrap();
        assert!(count > 0, "{planned:#}");
        assert!(dir
            .read(&format!(".swp/private/plans/{release}.json"))
            .contains("\"sites\""));

        let p = dir.run(&["protect", "--release", &release, "--format", "json"]);
        assert_eq!(p.code, 0, "{}\n{}", p.out, p.err);
        let applied = p.json();
        assert_eq!(applied["release_id"], release.as_str());
        assert_eq!(
            applied["sites_embedded"].as_u64(),
            Some(count),
            "protect applied a different constellation than the plan printed"
        );
        // The tree now says what the record claims: the point of `verify`.
        let v = dir.run(&["verify"]);
        assert_eq!(v.code, 0, "{}\n{}", v.out, v.err);
    }

    #[test]
    fn a_stated_revision_is_printed_and_never_watermarked() {
        // `--revision` is a label the operator typed, recorded so a person reading
        // the release record months later knows which build this was. It is not
        // content, so it must not reach the source or change the fingerprint.
        let dir = Scratch::initialized("protect", "revision", 0);
        let r = dir.run(&["protect", "--revision", "  v2.3-beta  ", "--format", "json"]);
        assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
        let doc = r.json();
        assert_eq!(doc["revision"], "v2.3-beta", "the label should be trimmed: {doc:#}");
        for file in dir.sources() {
            assert!(!dir.read(&file).contains("v2.3-beta"), "{file} carries the label");
        }
        let release = doc["release_id"].as_str().unwrap();
        let record = dir.read(&format!(".swp/public/releases/{release}.json"));
        assert!(record.contains("v2.3-beta"), "the release record lost the revision: {record}");
        assert!(
            record.contains(doc["fingerprint"].as_str().unwrap()),
            "the record's fingerprint is the one the command printed: {record}"
        );
    }
}
