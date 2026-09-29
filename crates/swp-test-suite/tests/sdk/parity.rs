//! The two doors, one answer.
//!
//! `swp-sdk` claims to be the orchestration `swp-cli` already performed, not a
//! second way of doing it. That claim is checkable, and this suite is the check:
//! the same project state is driven through `swp_cli::run_in` and through the
//! SDK, and the two answers are compared as *data* — the CLI's JSON document
//! against the SDK's serialized value, field for field.
//!
//! What is deliberately not compared: the text a terminal gets. `swp verify`
//! aligns a path into a 24-column cell and `swp scan` writes a list of next steps;
//! neither is a claim about the state of the tree, and a parity test that quoted
//! them would fail for a reason that means nothing. Error *codes* are compared,
//! because those are a contract; their prose is not.
//!
//! The nine cases below cover the four operations the SDK owns — initialize,
//! protect, verify, scan — the read side of the saved reports, and the two
//! boundaries the crate exists to keep: release selection and identity (so a
//! session resolved through either door is the same project), and the root secret
//! (so the debug output of every type the SDK hands back is swept for it).

use std::path::Path;

use serde_json::Value;
use swp_core::error::ErrorCode;
use swp_crypto::{derive_key, hmac_keyed, Domain, RootSecret};
use swp_identity::Store;
use swp_sdk::{
    Mode, Overrides, ProtectOptions, ReleaseId, ReleaseSelection, Session, VerifyOptions,
};
use swp_test_suite::project::{bare_dir, Project};
use swp_test_suite::sweep::{sweep_bytes, NeedleSet, SweepReport};
use swp_test_suite::{fixtures, Run, TempDir};

/// A release id both doors can be told to use: base32-lower, which is what
/// [`ReleaseId::new`] accepts, and fixed, so a difference between the two runs
/// cannot be blamed on the id.
const PINNED: &str = "rel-abcdefghijkl2345";

/// A release id no project publishes.
const ABSENT: &str = "rel-zzzzzzzzzzzzzzzz";

// --------------------------------------------------------------------------------------
// the two doors
// --------------------------------------------------------------------------------------

/// The CLI door: `swp … --format json`, run in `cwd`.
fn cli(argv: &[&str], cwd: &Path) -> Run {
    Run::of(argv, cwd)
}

/// The SDK door: a session opened on the same directory, with no overrides — the
/// same settings the CLI runs under when it is given no flags.
fn sdk(cwd: &Path) -> Session {
    Session::open(cwd, &Overrides::default()).expect("every project here was initialized first")
}

/// The CLI's JSON document, with the one field that names the moment it was run
/// removed.
///
/// A scan stamps `run.created_at` with the wall clock, and no two runs of the same
/// command agree on it; every other field of the two documents is a claim about the
/// tree, and is compared exactly.
fn comparable(mut doc: Value) -> Value {
    if let Some(run) = doc.get_mut("run").and_then(Value::as_object_mut) {
        run.remove("created_at");
    }
    doc
}

/// The SDK's document as a JSON value, taken the same road the CLI's came down.
///
/// `run.json()` is the command's stdout parsed back into a value, and parsing a
/// printed float can land one unit in the last place off the value that was
/// printed. Comparing that against a value built directly from the struct would
/// fail on `coincidence_probability` for a reason that has nothing to do with the
/// two doors, so both documents are printed and read back here.
fn through_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::from_str(&serde_json::to_string(value).unwrap())
        .expect("a document that prints must parse")
}

/// A project with a tree to protect and no release yet.
fn unguarded(label: &str) -> Project {
    Project::synthetic_wide(label, 8, 12)
}

/// The string half of one JSON field.
fn text(doc: &Value, key: &str) -> String {
    doc[key]
        .as_str()
        .unwrap_or_else(|| panic!("no string field {key:?} in {doc}"))
        .to_string()
}

/// The integer half of one JSON field.
fn number(doc: &Value, key: &str) -> u64 {
    doc[key]
        .as_u64()
        .unwrap_or_else(|| panic!("no integer field {key:?} in {doc}"))
}

// --------------------------------------------------------------------------------------
// protection
// --------------------------------------------------------------------------------------

#[test]
fn a_dry_run_from_either_door_produces_the_same_protection() {
    let project = unguarded("parity-dry-run");
    // The same release id through both doors, because the constellation is keyed by
    // it: two ids would mean two different sets of expected tags, and a difference
    // between the documents would then say nothing about the doors.
    let run = cli(
        &[
            "protect",
            "--dry-run",
            "--release",
            PINNED,
            "--format",
            "json",
        ],
        project.root(),
    )
    .ok();
    let outcome = sdk(project.root())
        .protect(&ProtectOptions {
            mode: Mode::DryRun,
            release_id: Some(ReleaseId::new(PINNED).unwrap()),
            revision: None,
        })
        .expect("the same line the CLI just ran");

    let doc = run.json();
    let p = &outcome.protection;
    assert_eq!(text(&doc, "project_id"), p.project_id.to_string());
    assert_eq!(text(&doc, "release_id"), PINNED);
    assert_eq!(text(&doc, "mode"), p.mode.as_str());
    assert_eq!(number(&doc, "tag_bits"), u64::from(p.tag_bits));
    assert_eq!(
        number(&doc, "requested_sites"),
        u64::from(p.requested_sites)
    );
    assert_eq!(number(&doc, "target_sites"), u64::from(p.target_sites));
    assert_eq!(number(&doc, "sites_embedded"), u64::from(p.sites_embedded));
    assert_eq!(number(&doc, "sites_skipped"), u64::from(p.sites_skipped));
    assert_eq!(number(&doc, "files_walked"), p.files_walked as u64);
    assert_eq!(number(&doc, "files_in_scope"), p.files_in_scope as u64);
    assert_eq!(number(&doc, "candidates"), p.candidates as u64);
    assert_eq!(text(&doc, "fingerprint"), p.fingerprint.to_string());
    assert_eq!(text(&doc, "fingerprint_level"), p.fingerprint_level.clone());
    // The plan the command prints is the plan the call returned, at the same
    // addresses in the same order — which is the only way `--dry-run` means
    // "this is what the release would do" rather than "here is an estimate".
    let changed: Vec<String> = p.files_changed.iter().map(|c| c.file.clone()).collect();
    let listed: Vec<String> = doc["files_changed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| text(c, "file"))
        .collect();
    assert_eq!(listed, changed, "the same locations, in the same order");
    assert_eq!(
        p.sites_embedded as usize,
        p.plan.sites.len(),
        "the account of the constellation holds exactly the sites that were embedded"
    );
    let mut refusals: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for site in &p.plan.skipped {
        *refusals.entry(site.reason.as_str()).or_insert(0) += 1;
    }
    assert_eq!(
        doc["skip_reasons"],
        serde_json::to_value(&refusals).unwrap(),
        "one refusal counted per reason, the same way by both doors"
    );
    // A dry run writes neither source nor store, which is why both doors could run
    // on one project at all.
    assert!(p.artifacts.is_empty(), "a dry run wrote: {:?}", p.artifacts);
    assert_eq!(project.releases(), Vec::<String>::new());
}

#[test]
fn a_tree_protected_by_the_sdk_publishes_what_the_cli_would() {
    // Two projects with byte-identical sources. Each has its own key, so each
    // embeds different values and the two trees are no longer identical after the
    // run — which is the point. What has to agree is everything that is a property
    // of the *tree*: how many sites it offered, how many were refused, and at what
    // width.
    let via_cli = unguarded("parity-protect-a");
    let via_sdk = unguarded("parity-protect-b");
    for rel in via_cli.sources() {
        via_sdk.write(&rel, &via_cli.read(&rel));
    }
    assert_eq!(via_cli.sources(), via_sdk.sources());

    let cli_release = via_cli.protect();
    let outcome = sdk(via_sdk.root())
        .protect(&ProtectOptions::new(Mode::Release))
        .expect("the same tree the other project just protected");
    let p = &outcome.protection;

    assert_eq!(cli_release.sites_embedded, p.sites_embedded);
    assert_eq!(cli_release.sites_skipped, p.sites_skipped);
    assert_eq!(cli_release.tag_bits, p.tag_bits);
    assert_eq!(
        cli_release.fingerprint_level, p.fingerprint_level,
        "the level is a claim about how the fingerprint was taken, not about the key"
    );
    assert_ne!(
        cli_release.fingerprint,
        p.fingerprint.to_string(),
        "two projects on identical source embed different values, so §16 hashes two \
         different trees — a fingerprint the two shared would mean the mark was not keyed"
    );
    assert_eq!(via_sdk.releases(), vec![p.release_id.to_string()]);
    // The release the SDK path wrote is a complete one: a public record, a private
    // manifest, and rewritten source.
    assert!(
        p.artifacts.iter().any(|a| a.contains("private/manifests/")),
        "the private manifest is written by the SDK path too: {:?}",
        p.artifacts
    );
    assert!(
        p.artifacts.iter().any(|a| a.contains("public/releases/")),
        "the public record is written by the SDK path too: {:?}",
        p.artifacts
    );
    assert!(!p.files_changed.is_empty());
    assert!(
        !p.artifacts.iter().any(|a| a.contains("root.key")),
        "a protection run never rewrites the secret it read: {:?}",
        p.artifacts
    );
}

// --------------------------------------------------------------------------------------
// verification and scanning
// --------------------------------------------------------------------------------------

#[test]
fn a_protected_tree_verifies_the_same_through_both_doors() {
    let project = unguarded("parity-verify");
    project.protect();
    // `--full` on the CLI and no `rows` on the SDK are the same window: neither
    // leaves a row out, so `omitted_rows` is a comparable zero rather than a
    // difference in how many lines a terminal had room for.
    let run = cli(&["verify", "--full", "--format", "json"], project.root());
    let outcome = sdk(project.root())
        .verify(&VerifyOptions::default())
        .expect("the same verification");
    assert_eq!(
        run.json(),
        serde_json::to_value(&outcome.document).unwrap(),
        "the CLI's verify document and the SDK's are one document"
    );
    assert_eq!(run.code, outcome.document.exit_code);
    assert_eq!(outcome.document.report_saved, None);
}

#[test]
fn a_scan_of_one_candidate_yields_one_document() {
    let project = unguarded("parity-scan");
    project.protect();
    let candidate = project.copy_whole("parity-scan-cand");
    let run = cli(
        &[
            "scan",
            &candidate.path().display().to_string(),
            "--format",
            "json",
        ],
        project.root(),
    );
    assert!(
        run.code == 0 || run.code == 1 || run.code == 10,
        "scan exited {}: {}{}",
        run.code,
        run.out,
        run.err
    );
    let outcome = sdk(project.root())
        .scan(candidate.path(), &ReleaseSelection::All, false)
        .expect("the same scan");
    let document = through_json(&outcome.report);
    assert_eq!(
        comparable(run.json()),
        comparable(document.clone()),
        "the report the command printed is the report the call returned"
    );
    // The exit code is a property of the document on both doors.
    assert_eq!(run.code, outcome.report.exit_code());
    assert!(outcome.saved.is_none());

    // The per-site rows are the same measurement the tally summed into the report,
    // not a second grading: for each release scanned, the rows add up to that
    // release's own tally.
    let tallies = document["releases"].as_array().unwrap();
    assert_eq!(tallies.len(), 1, "this project has one release");
    let release_id = text(&tallies[0], "release_id");
    let rows: Vec<&swp_sdk::ScannedSite> = outcome
        .sites
        .iter()
        .filter(|s| s.release_id == release_id)
        .collect();
    assert_eq!(rows.len(), number(&tallies[0], "sites") as usize);
    let confirmed = rows
        .iter()
        .filter(|s| matches!(s.status, "tag-confirmed" | "exact-rendering"))
        .count();
    assert_eq!(confirmed, number(&tallies[0], "fragments") as usize);
    let probes: u64 = rows.iter().map(|s| u64::from(s.probes)).sum();
    assert_eq!(probes, number(&tallies[0], "probes"));
    let draws: u64 = rows.iter().map(|s| u64::from(s.distinct_codes)).sum();
    assert_eq!(draws, number(&tallies[0], "draws"));
    // A copy of the whole protected tree is the strongest case there is.
    assert_eq!(outcome.report.result.as_str(), "PROVENANCE_DETECTED");
}

// --------------------------------------------------------------------------------------
// saved reports
// --------------------------------------------------------------------------------------

#[test]
fn the_report_a_scan_saved_is_the_document_both_doors_print() {
    let project = unguarded("parity-report");
    project.protect();
    let candidate = project.copy_whole("parity-report-cand");
    let outcome = sdk(project.root())
        .scan(candidate.path(), &ReleaseSelection::All, true)
        .expect("a scan that saves");
    let saved = outcome.saved.clone().expect("--save was asked for");
    let run = cli(&["report", &saved.name, "--format", "json"], project.root()).ok();
    assert_eq!(
        run.json(),
        through_json(&outcome.report),
        "a saved report is the document, re-read unchanged"
    );
    let reloaded = sdk(project.root()).read_report(&saved.path).unwrap();
    assert_eq!(
        run.json(),
        through_json(&reloaded.report),
        "the stem, the file name and the stored path all mean one entry"
    );
    assert_eq!(reloaded.name, saved.name);
    assert_eq!(reloaded.path, saved.path);
    // The listing names it the same way.
    let list = cli(&["report", "--format", "json"], project.root())
        .ok()
        .json();
    let rows = list["reports"].as_array().unwrap();
    let names: Vec<String> = rows.iter().map(|r| text(r, "name")).collect();
    assert!(names.contains(&saved.name), "{names:?}");
    assert_eq!(
        sdk(project.root()).reports().unwrap(),
        names,
        "the SDK lists exactly what the command lists, in the same order"
    );
    let row = rows
        .iter()
        .find(|r| text(r, "name") == saved.name)
        .expect("the save is listed");
    assert_eq!(text(row, "path"), saved.path);
    assert_eq!(text(row, "command"), "scan");
}

// --------------------------------------------------------------------------------------
// identity, releases and errors
// --------------------------------------------------------------------------------------

#[test]
fn both_doors_act_on_the_same_project_and_the_same_releases() {
    let project = unguarded("parity-identity");
    project.protect();
    project.protect();
    let session = sdk(project.root());
    let listed = cli(&["inspect", "releases", "--format", "json"], project.root())
        .ok()
        .json();
    assert_eq!(
        text(&listed, "project_id"),
        session.identity().project_id.to_string()
    );
    assert_eq!(
        text(&listed, "display_name"),
        session.identity().display_name.clone()
    );
    // The listing is the history, in the history's order: newest protection last.
    let from_cli: Vec<String> = listed["data"]["releases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| text(r, "release_id"))
        .collect();
    let history = session.release_history().unwrap();
    let from_sdk: Vec<String> = history.iter().map(|r| r.release_id.to_string()).collect();
    assert_eq!(from_cli, from_sdk, "same releases, same order");
    assert_eq!(history.len(), 2);
    let all = session.releases(&ReleaseSelection::All).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(
        session.one_release(&ReleaseSelection::Latest).unwrap(),
        history.last().unwrap().release_id.clone(),
        "the newest by recorded time is the one the listing puts last"
    );
    // The record the SDK authenticates is the one the CLI's listing printed.
    let newest = &from_sdk[1];
    let record = session
        .release(&ReleaseId::new(newest).unwrap())
        .expect("the release just listed");
    assert_eq!(
        record.fingerprint.to_string(),
        project.release(newest).fingerprint
    );
}

#[test]
fn both_doors_refuse_the_same_thing_with_the_same_code() {
    let project = unguarded("parity-errors");
    project.protect();

    // A candidate that is not there. The store is opened first, so a project that
    // has releases reaches the candidate and fails on it.
    let missing = project.root().join("not-here");
    let run = cli(
        &["scan", &missing.display().to_string(), "--format", "json"],
        project.root(),
    );
    let error = sdk(project.root())
        .scan(&missing, &ReleaseSelection::All, false)
        .unwrap_err();
    assert_eq!(run.code, error.code().exit_code());
    assert_eq!(error.code(), ErrorCode::Io);

    // A release that was never published.
    let run = cli(
        &["verify", "--release", ABSENT, "--format", "json"],
        project.root(),
    );
    let error = sdk(project.root())
        .verify(&VerifyOptions {
            release: Some(ReleaseId::new(ABSENT).unwrap()),
            ..VerifyOptions::default()
        })
        .unwrap_err();
    assert_eq!(run.code, error.code().exit_code());
    assert_eq!(error.code(), ErrorCode::NotProtected);

    // A saved report that is not there, and a name that reaches out of the reports
    // directory: both doors answer with a usage error, and neither reads a file
    // outside the store.
    for (name, want) in [
        ("scan-2020-01-01T00-00-00Z", ErrorCode::Usage),
        ("../manifests/rel-aaaaaaaaaaaaaaaa", ErrorCode::Usage),
    ] {
        let run = cli(&["report", name], project.root());
        let error = sdk(project.root()).read_report(name).unwrap_err();
        assert_eq!(run.code, error.code().exit_code(), "{name}");
        assert_eq!(error.code(), want, "{name}");
    }

    // A site count no project is protected at, given as a flag on one door and as
    // an override on the other.
    let run = cli(&["protect", "--sites", "0", "--dry-run"], project.root());
    let error = Session::open(
        project.root(),
        &Overrides {
            target_sites: Some(0),
            ..Overrides::default()
        },
    )
    .unwrap_err();
    assert_eq!(run.code, error.code().exit_code());
    assert_eq!(error.code(), ErrorCode::Usage);

    // A project that has no releases at all, which `verify` cannot answer.
    let empty = unguarded("parity-no-releases");
    let run = cli(&["verify", "--format", "json"], empty.root());
    let error = sdk(empty.root())
        .verify(&VerifyOptions::default())
        .unwrap_err();
    assert_eq!(run.code, error.code().exit_code());
    assert_eq!(error.code(), ErrorCode::NotProtected);
}

// --------------------------------------------------------------------------------------
// initialization
// --------------------------------------------------------------------------------------

#[test]
fn initializing_through_the_sdk_leaves_what_initializing_through_the_cli_leaves() {
    let via_cli = bare_dir("parity-init-cli");
    let via_sdk = bare_dir("parity-init-sdk");
    for dir in [&via_cli, &via_sdk] {
        fixtures::synthetic_variant(dir, 8, 0);
    }
    let run = cli(&["init", "--format", "json"], &via_cli).ok();
    let outcome = Session::init(&via_sdk, &swp_sdk::InitOptions::default())
        .expect("the same tree, initialized");
    let doc = run.json();
    let r = &outcome.result;
    // The measured half is a property of the tree, so it is equal field for field;
    // the identity is not, because two projects are two projects.
    assert_eq!(
        doc["measurement"],
        serde_json::to_value(&r.measurement).unwrap()
    );
    assert_eq!(doc["settings"], serde_json::to_value(&r.settings).unwrap());
    assert_eq!(doc["generated"], serde_json::to_value(&r.created).unwrap());
    assert_eq!(text(&doc, "secret"), r.secret_state);
    assert_eq!(text(&doc, "gitignore"), r.gitignore);
    assert_eq!(text(&doc, "permissions"), r.permissions_detail);
    assert_eq!(
        doc["permissions_verified"].as_bool().unwrap(),
        r.permissions_verified
    );
    assert!(!r.pre_existing);
    assert!(Store::exists(&via_cli) && Store::exists(&via_sdk));
    assert_ne!(
        outcome.session.identity().project_id.to_string(),
        text(&doc, "project_id"),
        "two stores on two keys are two projects, and parity must not hide that"
    );
    for dir in [&via_cli, &via_sdk] {
        std::fs::remove_dir_all(dir).ok();
    }
}

// --------------------------------------------------------------------------------------
// the secret boundary
// --------------------------------------------------------------------------------------

/// The test key. A run of identical bytes would match formatted output by
/// accident, so the value is arbitrary but fixed — the same one `secret_leak`
/// sweeps for.
fn key_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = 0x6bu8.wrapping_add((i as u8).wrapping_mul(0x17)) ^ 0xa5;
    }
    b
}

#[test]
fn no_value_the_sdk_hands_back_prints_the_key_it_just_used() {
    let tmp = TempDir::new("parity-secret").sensitive();
    fixtures::synthetic_variant(tmp.path(), 8, 0);
    let secret = RootSecret::from_bytes(&key_bytes()).expect("32 bytes is a key");
    let store = Store::init(tmp.path(), &secret).expect("store init").store;
    std::fs::write(
        tmp.path().join(".swp/config.toml"),
        "[protect]\ntargets = [\"src\"]\ntarget_sites = 12\ntag_bits = 4\nembed_strings = true\n",
    )
    .unwrap();
    // The master, and one keyed output computed from it: a build that never prints
    // the root secret but prints the per-location MAC it derived would be nearly as
    // bad, so both are needles here.
    let project_id = store.project_id().unwrap();
    let tag_key = derive_key(&secret, Domain::Location, &[project_id.as_str().as_bytes()]);
    let keyed = hmac_keyed(
        &tag_key,
        Domain::Location,
        &[b"src/mod0.js", b"numeric", b"255"],
    )
    .expect("the key was just derived in the Location domain");
    let needles = vec![
        NeedleSet::new("root-secret", &key_bytes()),
        NeedleSet::new("location-mac", &keyed),
    ];

    let session = sdk(tmp.path());
    let protect = session
        .protect(&ProtectOptions::new(Mode::Release))
        .expect("a tree this suite just configured");
    let candidate = copied_sources(tmp.path());
    let scan = session
        .scan(&candidate, &ReleaseSelection::All, true)
        .expect("a scan of a copy of itself");
    let verify = session
        .verify(&VerifyOptions::default())
        .expect("a verification of the tree");
    let names = session.reports().unwrap();
    let stored = session.read_report(&names[0]).unwrap();

    let mut report = SweepReport::default();
    for (label, value) in [
        ("session", format!("{session:?}")),
        ("protect", format!("{protect:?}")),
        (
            "protect-json",
            serde_json::to_string(&protect.protection).unwrap(),
        ),
        ("scan", format!("{scan:?}")),
        ("scan-json", serde_json::to_string(&scan.report).unwrap()),
        (
            "scan-sites",
            scan.sites
                .iter()
                .map(|s| {
                    format!(
                        "{s:?} {} {} {}",
                        s.status,
                        s.found_in.clone().unwrap_or_default(),
                        s.found_excerpt.clone().unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        ("verify", format!("{verify:?}")),
        (
            "verify-json",
            serde_json::to_string(&verify.document).unwrap(),
        ),
        ("stored-report", format!("{stored:?}")),
        ("reports", format!("{names:?}")),
        ("capabilities", format!("{:?}", swp_sdk::capabilities())),
        ("identity", format!("{:?}", session.identity())),
        ("config", format!("{:?}", session.config())),
    ] {
        sweep_bytes(label, value.as_bytes(), &needles, &mut report);
    }
    report.assert_clean();
}

/// A copy of `root`'s sources with no `.swp/` in it — a candidate, not a project.
///
/// The keys come from the project doing the scanning (§21), so the thing being read
/// must hold none of its own.
fn copied_sources(root: &Path) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("swp-parity-cand-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temporary candidate directory");
    let src = root.join("src");
    let mut copied = 0;
    for entry in std::fs::read_dir(src).expect("the fixture has a src/") {
        let entry = entry.unwrap();
        if entry.path().extension().map(|e| e == "js").unwrap_or(false) {
            std::fs::copy(entry.path(), dir.join(entry.path().file_name().unwrap())).unwrap();
            copied += 1;
        }
    }
    assert!(copied > 0, "the fixture wrote no source to copy");
    dir
}
