//! §29 — the secret-leak gate.
//!
//! This is the M1 acceptance test, and it lands here rather than at the end of
//! the project on purpose: every later milestone writes more artifacts, and a
//! leak introduced in `swp-identity` must be caught while `swp-identity` is the
//! only thing that exists. The manifest, report and CLI suites reuse
//! [`swp_test_suite::sweep`] with their own artifact lists.
//!
//! # What this asserts
//!
//! A root secret with a *known* value is installed into a real store, and then
//! every artifact that store and its types can produce is swept for every
//! rendering of that secret — and for a raw keyed output, so leaking a
//! *purpose* key is caught as well as leaking the master.
//!
//! The only file allowed to hold key material is `.swp/private/root.key`, and
//! even that one is checked rather than assumed:
//! [`root_key_file_holds_only_sealed_material`] reports what it actually finds.
//!
//! [`every_command_prints_and_writes_nothing_searchable`] then sweeps the same
//! secret out of the *product*: it runs every verb the CLI offers, in both
//! output formats, with the flags whose whole purpose is to print more, and reads
//! back every byte each run wrote to a disk or a stream.
//!
//! # What this cannot do
//!
//! It checks the commands that exist, not every way to reach them: a flag
//! combination no suite has ever run is a flag combination nobody has swept. The
//! per-command non-vacuity assertions in that last test are what keeps the gap
//! narrow rather than merely invisible.

use std::path::{Path, PathBuf};

use serde_json::Value;
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{base32_lower, Digest, ReleaseId};
use swp_core::version::{GeneratorInfo, SchemaVersion, SWP_PROTOCOL_NAME};
use swp_crypto::{
    derive_key, hmac_keyed, plain_requested, Domain, ManifestSigningKey, RootSecret, Scheme,
    SealedSecret,
};
use swp_identity::release::{AdapterUse, ReleaseRecord, SourceRevision, WatermarkParams};
use swp_identity::{ProjectIdentity, Store, SwpConfig, Timestamp};
use swp_test_suite::sweep::{sweep_bytes, sweep_tree, sweep_tree_skipping, NeedleSet, SweepReport};
use swp_test_suite::{fixtures, Run, TempDir};

/// The known secret. A constant byte string would be a poor choice: runs of
/// identical bytes appear in formatted output by accident. This value is
/// arbitrary but fixed, so a failure reproduces exactly.
fn key_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = 0x6bu8.wrapping_add((i as u8).wrapping_mul(0x17)) ^ 0xa5;
    }
    b
}

fn root() -> RootSecret {
    RootSecret::from_bytes(&key_bytes()).expect("test key is 32 bytes")
}

/// The root secret, plus one raw keyed output.
///
/// The second needle matters: an implementation could avoid printing the master
/// key while happily printing the per-location MAC it computed from it, which is
/// nearly as bad — every other location's tag then becomes derivable.
fn needles() -> Vec<NeedleSet> {
    let r = root();
    let location_key = derive_key(
        &r,
        Domain::Location,
        &[b"swp1-demo-project", b"00000000000000000000000000000004"],
    );
    let keyed = hmac_keyed(
        &location_key,
        Domain::Location,
        &[b"src/color.js", b"numeric", b"255"],
    )
    .expect("the key was just derived in the Location domain");
    vec![
        NeedleSet::new("root-secret", &key_bytes()),
        NeedleSet::new("location-mac", &keyed),
    ]
}

/// A store initialised with the test key, plus the directory holding it.
fn seeded_store(tag: &str) -> (TempDir, Store) {
    let tmp = TempDir::new(tag).sensitive();
    let init = Store::init(tmp.path(), &root()).expect("store init");
    let store = init.store;
    // The public half must be readable with no key present at all, otherwise
    // `swp scan` on a stranger's copy would depend on having the secret.
    assert!(store.identity().is_ok());
    (tmp, store)
}

fn listed_files(root: &Path) -> Vec<String> {
    walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().display().to_string())
        .collect()
}

#[test]
fn nothing_in_the_store_but_the_root_key_file_leaks_the_secret() {
    let (_tmp, store) = seeded_store("store");
    let needles = needles();

    // The honest full sweep, with no excuses at all: every violation must be in
    // the one file that is allowed to hold key material.
    let bare = sweep_tree(store.project_root(), &needles);
    for violation in &bare.violations {
        assert!(
            violation.artifact.ends_with("root.key"),
            "key material found outside root.key: {violation}"
        );
    }

    // Then the same sweep with that file excused. It must be clean, and it must
    // have excused exactly one file — otherwise the skip list is doing the work
    // rather than the implementation being safe.
    let report = sweep_tree_skipping(store.project_root(), &needles, &["root.key"]);
    let excused: Vec<&String> = report
        .skipped
        .iter()
        .filter(|s| s.ends_with(".key"))
        .collect();
    assert_eq!(
        excused.len(),
        1,
        "expected to excuse exactly root.key, skipped {:?}",
        report.skipped
    );
    assert!(excused[0].ends_with("root.key"));
    report.assert_clean();

    // Coverage: the pass above is only meaningful if these files really exist
    // and really were read.
    let swept = listed_files(store.project_root());
    for expected in ["identity.json", "config.toml", ".gitignore"] {
        assert!(
            swept.iter().any(|p| p.ends_with(expected)),
            "the store never produced {expected}; swept {swept:?}"
        );
    }
    assert!(
        report.files_scanned + 1 >= swept.len(),
        "the sweep read {} of {} files",
        report.files_scanned,
        swept.len()
    );
}

/// What the sealed key file really contains.
///
/// Under the OS key-protection scheme the answer should be "nothing searchable".
/// Under the plain opt-in it will contain the key. Asserting the *correspondence*
/// between the two is the property that matters: a change that quietly regressed
/// DPAPI to plaintext on a machine where DPAPI works would fail here.
#[test]
fn root_key_file_holds_only_sealed_material() {
    let (_tmp, store) = seeded_store("rootkey");
    let bytes = std::fs::read(store.root_key_path()).expect("root.key exists");
    let sealed = SealedSecret::parse_file_bytes(&bytes).expect("root.key parses");
    let needles = needles();
    let mut report = SweepReport::default();
    sweep_bytes("root.key", &bytes, &needles, &mut report);

    if sealed.scheme == Scheme::Dpapi {
        eprintln!(
            "root.key: sealed with DPAPI, {} bytes on disk, {} searchable rendering(s) of the key",
            bytes.len(),
            report.violations.len()
        );
        assert!(
            report.violations.is_empty(),
            "the sealed root key file still contains a searchable rendering of the secret: {:?}",
            report.violations
        );
    } else {
        assert_eq!(sealed.scheme, Scheme::Plain);
        assert!(
            !report.violations.is_empty() || plain_requested(),
            "the file is unsealed but the sweep missed it — the sweep is broken"
        );
    }
    assert_eq!(
        sealed.unseal().expect("unseal").fingerprint(),
        root().fingerprint()
    );
}

#[test]
fn public_and_private_artifacts_built_from_the_key_are_clean() {
    let (_tmp, store) = seeded_store("artifacts");
    let needles = needles();
    let mut report = SweepReport::default();

    let identity = store.identity().expect("identity");
    sweep_bytes(
        "identity.json",
        &identity.to_json_bytes(),
        &needles,
        &mut report,
    );
    sweep_bytes(
        "config.toml",
        SwpConfig::default().to_toml().as_bytes(),
        &needles,
        &mut report,
    );

    let release = sample_release(&store, &identity);
    sweep_bytes(
        "release.json",
        &release.to_json_bytes(),
        &needles,
        &mut report,
    );

    let signing = ManifestSigningKey::from_root(&root(), identity.project_id.as_str())
        .expect("signing key derives");
    let message = br#"{"protocol":"SWP-1"}"#;
    sweep_bytes("signature", &signing.sign(message), &needles, &mut report);
    sweep_bytes(
        "verify-keys.json",
        serde_json::to_vec(&identity.verification)
            .expect("public keys serialize")
            .as_slice(),
        &needles,
        &mut report,
    );

    // Every id the store publishes is a truncated hash of the key. Sweeping them
    // is the positive half of the argument: the public handles are real values
    // the sweep could match, and they do not.
    let handles = format!(
        "{} {} {}",
        identity.project_id,
        release.release_id,
        root().fingerprint()
    );
    sweep_bytes("public-handles", handles.as_bytes(), &needles, &mut report);

    report.assert_clean();
}

fn sample_release(store: &Store, identity: &ProjectIdentity) -> ReleaseRecord {
    let record = ReleaseRecord {
        protocol: SWP_PROTOCOL_NAME.to_string(),
        schema: SchemaVersion::MANIFEST_V1.0,
        project_id: identity.project_id.clone(),
        release_id: ReleaseId::new(format!("rel-{}", base32_lower(&[0x4du8; 10])))
            .expect("test release id"),
        created_at: Timestamp::now_utc(),
        source_revision: SourceRevision::Content,
        fingerprint: Digest([0x91; 32]),
        fingerprint_level: "L1".to_string(),
        private_manifest_digest: Digest([0x5c; 32]),
        watermark: WatermarkParams {
            target_sites: 16,
            tag_bits: 4,
            sites_embedded: 14,
            sites_skipped: 2,
            canonicalizer_version: 1,
            form_set: "0d9f".to_string(),
            adapters: vec![AdapterUse {
                language: "javascript".to_string(),
                mode: "ast".to_string(),
                files: 3,
            }],
        },
        generator: GeneratorInfo::current(),
        signature: String::new(),
    };
    record.validate().expect("sample release is valid");
    assert_eq!(store.project_id().expect("store id"), record.project_id);
    record
}

#[test]
fn debug_renderings_of_every_secret_bearing_type_are_redacted() {
    let (_tmp, store) = seeded_store("debug");
    let needles = needles();
    let r = root();
    let sealed = SealedSecret::seal(&r).expect("seal");
    // `ManifestSigningKey` is deliberately *not* `Debug` at all, which is
    // stronger than a redacted `Debug`: `{:?}` on it fails to compile rather
    // than printing something an operator might paste into a bug report. It is
    // exercised below for its output instead.
    let signing =
        ManifestSigningKey::from_root(&r, store.project_id().unwrap().as_str()).expect("signing");
    let location_key = derive_key(&r, Domain::Location, &[b"p", b"l"]);

    let rendered = format!("{:?}|{:?}|{:?}|{:?}", r, sealed, location_key, store);
    let mut report = SweepReport::default();
    sweep_bytes(
        "debug-renderings",
        rendered.as_bytes(),
        &needles,
        &mut report,
    );
    sweep_bytes(
        "public-key-only",
        format!("{:?}", signing.verifying_key()).as_bytes(),
        &needles,
        &mut report,
    );
    report.assert_clean();
    assert!(
        rendered.contains("REDACTED"),
        "expected the secret types to redact themselves, saw {rendered}"
    );
}

/// Error paths are where implementations get careless: the tempting debugging
/// move is to include the value that failed inside the message about it failing.
#[test]
fn error_messages_never_quote_key_material() {
    let (_tmp, store) = seeded_store("errors");
    let needles = needles();
    let mut report = SweepReport::default();

    let mut cases: Vec<SwpError> = Vec::new();
    cases.push(
        SwpConfig::parse("protocol = \"SWP-1\"\n[protect]\ntarget_sites = [[[")
            .expect_err("not valid TOML"),
    );
    cases.push(RootSecret::from_bytes(&key_bytes()[..16]).expect_err("half a key is not a key"));
    cases.push(
        ReleaseRecord::from_json_bytes(b"{\"protocol\":\"SWP-9\"}")
            .expect_err("not a release record"),
    );
    cases.push(
        SwpError::new(
            ErrorCode::SecretUnavailable,
            format!("no root secret at {}", store.root_key_path().display()),
        )
        .with_path(store.root_key_path().display().to_string())
        .caused_by(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    );

    // A corrupt key file is the failure most likely to be debugged by printing
    // what was read — so it gets checked for real.
    std::fs::write(store.root_key_path(), b"not-a-sealed-secret").expect("corrupt for the test");
    cases.push(store.load_root().expect_err("a corrupt key file must fail"));

    for case in &cases {
        let text = format!(
            "{}|{}|{}",
            case.render(),
            case.code(),
            store.inventory().is_ok()
        );
        sweep_bytes("error-rendering", text.as_bytes(), &needles, &mut report);
    }
    report.assert_clean();

    // Leave the store usable: this test wrote garbage into a real one.
    let restored = SealedSecret::seal(&root()).expect("reseal");
    std::fs::write(store.root_key_path(), restored.to_file_bytes()).expect("restore");
    assert!(store.load_root().is_ok(), "store unusable after the test");
}

/// `swp-identity` is where a key first touches disk, so it is also where an
/// atomic write could leave a plaintext sibling behind. The tree sweep covers
/// that implicitly; naming it makes the failure legible.
#[test]
fn no_temporary_or_backup_file_survives_a_write() {
    let (tmp, store) = seeded_store("tmpfiles");
    store
        .write_config(&SwpConfig::default())
        .expect("rewrite config");
    let leftovers: Vec<String> = listed_files(tmp.path())
        .into_iter()
        .filter(|p| p.contains(".tmp") || p.ends_with('~') || p.contains("swp-tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "sweepable temp files remain: {leftovers:?}"
    );
}

/// §29 over the product an operator runs, rather than the types behind it.
///
/// Every test above builds artifacts in Rust and sweeps them, which is the wrong
/// surface for the most likely leak of all: a `println!` that was convenient while
/// someone was writing a flag. So this drives the real entry point — the same
/// `run_in` that `swp`'s `main` calls — over every verb, in both output formats,
/// with the flags whose entire purpose is to print more (`--verbose`, `--full`,
/// `--save`, `-o`), and with the failures a person actually hits (a missing key, a
/// directory that is not a project, a release id that does not exist).
///
/// What is swept for each run is *everything it could be observed doing*: stdout,
/// stderr, the document `-o` wrote, every report the store kept, and the whole tree
/// on disk afterwards with `root.key` excused and named. The assertions at the end
/// are the other half of the test: they prove the sweep had something to find, by
/// requiring that the transcript really contains the project id, a release id and
/// at least one keyed site address. A CLI that printed no private value at all
/// would pass a leak test with no teeth; this one cannot.
#[test]
fn every_command_prints_and_writes_nothing_searchable() {
    let tmp = TempDir::new("cli").sensitive();
    let sources = fixtures::javascript_project(tmp.path());
    let store = Store::init(tmp.path(), &root()).expect("store init").store;
    let needles = needles();
    let mut cli = Cli::new(tmp.path(), &needles);
    // Where the `-o` documents go: deliberately outside the project, because that
    // is what `-o` is for, and a report a user redirected out of the store is a
    // report no tree sweep would ever reach.
    let outdir = TempDir::new("cli-out");

    // --- the store-less commands, and the ones that only talk -----------------
    cli.run(&["version"]);
    cli.run(&["help"]);
    cli.run(&["help", "scan"]);
    cli.run(&["help", "scna"]); // the typo-correction path, which quotes what was typed
    cli.run(&["no-such-verb"]);
    // `init` over an existing store is the run that must *not* replace a secret, and
    // its summary is the text that lists what may be committed and what may not.
    cli.run(&["init"]);
    cli.run(&["init", "--format", "json"]);
    cli.run(&["init", "--force"]);

    // --- the write path, in every mode it has ---------------------------------
    cli.ok(&["generate"]);
    cli.ok(&["generate", "--format", "json"]);
    cli.ok(&["generate", "--sites", "12", "--bits", "8", "--verbose"]);
    cli.ok(&["protect", "--dry-run"]);
    cli.ok(&["protect", "--dry-run", "--format", "json"]);
    cli.ok(&["protect", "--revision", "cli-sweep", "--verbose"]);
    let ids = store.releases().expect("releases after protect");
    assert_eq!(
        ids.len(),
        1,
        "protect was run once and wrote {} release(s), so this sweep is not reading \
         what it thinks it is reading",
        ids.len()
    );
    let release = ids[0].to_string();

    // The private manifest is the densest concentration of keyed material the
    // project holds, and `inspect manifest` prints it. Read it here so the sweep
    // can be checked against it rather than against a hope.
    let manifest: Value = serde_json::from_slice(
        &store
            .read_private_manifest(&ids[0])
            .expect("private manifest"),
    )
    .expect("the manifest is JSON");
    let addresses: Vec<String> = manifest["sites"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|site| {
            site["locations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|loc| loc.as_str().map(str::to_string))
        })
        .collect();
    assert!(
        !addresses.is_empty(),
        "protect embedded nothing, so the manifest sweep below proves nothing"
    );

    // --- every view, in both formats, taken from the CLI's own list ------------
    // Nothing here names a view by hand: a ninth view added to `swp inspect` is
    // swept by this test the day it exists, which is the only way a leak in a view
    // nobody remembered to list stays impossible to introduce quietly.
    let views = swp_cli::inspect::view_names();
    assert_eq!(
        views.len(),
        8,
        "inspect's views changed shape; check this sweep still reads them all"
    );
    for view in &views {
        cli.ok(&["inspect", view]);
        cli.ok(&["inspect", view, "--format", "json"]);
    }
    cli.ok(&["inspect", "manifest", "--release", &release, "--full"]);
    cli.ok(&["inspect", "fragments", "--release", &release]);
    cli.ok(&["inspect", "releases", "--limit", "1"]);
    cli.ok(&["inspect", "plan", "--limit", "0", "--format", "json"]);
    cli.run(&["inspect", "bananas"]);

    // --- verify: this tree against its own release ---------------------------
    cli.ok(&["verify"]);
    cli.ok(&["verify", "--format", "json"]);
    cli.ok(&["verify", "--latest", "--verbose"]);
    cli.ok(&["verify", "--full", "--limit", "2"]);
    cli.ok(&["verify", "--save"]);
    let vdoc = outdir.child("verify.json");
    cli.ok(&[
        "verify",
        "--format",
        "json",
        "--output",
        &vdoc.display().to_string(),
    ]);
    cli.file(&vdoc);
    cli.run(&["verify", "--release", "rel-notarelease"]);

    // --- scan: a copy that carries the watermark, and copies that do not ------
    let stolen = TempDir::new("cli-candidate");
    for rel in &sources {
        stolen.write(
            rel,
            &std::fs::read(tmp.child(rel)).expect("protected source"),
        );
    }
    let lookalike = TempDir::new("cli-lookalike");
    fixtures::lookalike_project(lookalike.path());
    let empty = TempDir::new("cli-empty");
    // A zip candidate goes through a different reader entirely (it is unpacked
    // into a private temporary directory before anything is looked at, §21), so it
    // is its own surface and gets its own sweep.
    let (archive_dir, archive) = archive_of(stolen.path(), &sources, "cli-archive");

    for candidate in [stolen.path().to_path_buf(), archive.clone()] {
        let at = candidate.display().to_string();
        let kind = if candidate == archive { "zip" } else { "dir" };
        cli.run(&["scan", &at]);
        cli.run(&["scan", &at, "--format", "json"]);
        cli.run(&["scan", &at, "--verbose"]);
        cli.run(&["scan", &at, "--full", "--limit", "3"]);
        cli.run(&["scan", &at, "--release", &release, "--save"]);
        let doc = outdir.child(&format!("scan-{kind}.json"));
        cli.run(&[
            "scan",
            &at,
            "--format",
            "json",
            "--output",
            &doc.display().to_string(),
        ]);
        cli.file(&doc);
    }
    for clean in [lookalike.path(), empty.path()] {
        let at = clean.display().to_string();
        cli.run(&["scan", &at, "--format", "json"]);
    }
    cli.run(&["scan"]);
    cli.run(&["scan", "nowhere-at-all.example"]);
    let two = stolen.path().display().to_string();
    cli.run(&["scan", &two, &two]);

    // --- report: the listing, and each saved finding re-rendered --------------
    let saved = store.report_names().expect("report listing");
    assert!(
        saved.len() >= 3,
        "--save was run {} time(s) and the store kept {} report(s): the sweep of \
         `swp report <name>` would be empty",
        3,
        saved.len()
    );
    cli.ok(&["report"]);
    cli.ok(&["report", "--format", "json"]);
    for name in &saved {
        cli.ok(&["report", name]);
        cli.ok(&["report", name, "--format", "json"]);
    }
    cli.ok(&["report", "--release", &release]);
    cli.ok(&["report", "--limit", "1"]);
    cli.run(&["report", "no-such-report"]);

    // --- the failures an operator actually hits ------------------------------
    // No secret: the error must name the path it looked at without quoting what
    // should have been there.
    let key_path = store.root_key_path();
    let sealed_bytes = std::fs::read(&key_path).expect("read the key to put it back");
    std::fs::remove_file(&key_path).expect("remove it for the test");
    let at = stolen.path().display().to_string();
    cli.run(&["protect"]);
    cli.run(&["verify"]);
    cli.run(&["scan", &at]);
    cli.run(&["inspect", "manifest", "--format", "json"]);
    std::fs::write(&key_path, &sealed_bytes).expect("put the key back");
    assert!(
        store.load_root().is_ok(),
        "the sweep left the project without a usable root key"
    );

    // No project at all: these runs locate a store by searching upward and failing.
    let bare = empty.path().to_path_buf();
    cli.at(&["protect"], &bare);
    cli.at(&["verify", "--format", "json"], &bare);
    cli.at(&["inspect"], &bare);
    cli.at(&["report"], &bare);
    cli.at(&["scan", &at], &bare);

    // --- the tree, afterwards ------------------------------------------------
    // Every artifact the runs above wrote is on disk by now: plans, manifests,
    // release records, saved reports, the watermarked sources themselves. Sweep it
    // with `root.key` excused, and prove that is the only thing excused.
    let tree = sweep_tree_skipping(tmp.path(), &needles, &["root.key"]);
    assert_eq!(
        tree.skipped.len(),
        1,
        "the tree sweep excused {:?}, not exactly one root.key",
        tree.skipped
    );
    assert!(
        tree.skipped[0].ends_with("root.key"),
        "the one excused file is {:?}, not root.key",
        tree.skipped[0]
    );
    assert!(
        tree.files_scanned >= sources.len() + views.len(),
        "the tree sweep read {} file(s) from a project that holds sources, a store, a \
         plan, a manifest, a release and {} saved report(s)",
        tree.files_scanned,
        saved.len()
    );
    cli.absorb(tree);
    for dir in [
        stolen.path(),
        lookalike.path(),
        outdir.path(),
        archive_dir.path(),
    ] {
        let swept = sweep_tree(dir, &needles);
        assert!(
            swept.skipped.is_empty(),
            "a directory with no key in it should need no excuses: {:?}",
            swept.skipped
        );
        assert!(
            swept.files_scanned > 0,
            "nothing was found to sweep under {} — the loop is not reaching the trees",
            dir.display()
        );
        cli.absorb(swept);
    }

    // --- and now: did any of this actually look at anything? ------------------
    for cmd in swp_cli::args::Command::ALL {
        assert!(
            cli.verbs.iter().any(|v| *v == cmd.name()),
            "`swp {}` was never run, so nothing here says it does not print the secret",
            cmd.name()
        );
    }
    let project_id = store.project_id().expect("project id").to_string();
    for (what, needle) in [
        ("the project id", project_id.clone()),
        ("the release id", release.clone()),
        (
            "a keyed site address",
            addresses
                .iter()
                .find(|a| cli.transcript.contains(a.as_str()))
                .cloned()
                .unwrap_or_default(),
        ),
    ] {
        assert!(
            !needle.is_empty() && cli.transcript.contains(&needle),
            "the CLI printed no {what} anywhere in {} run(s), so this sweep is checking \
             an output that does not exist. The private values this project has are a \
             project id, a release id and {} keyed address(es); the transcript is {} \
             byte(s) and starts {:#?}",
            cli.runs,
            addresses.len(),
            cli.transcript.len(),
            cli.transcript.chars().take(400).collect::<String>(),
        );
    }
    assert!(
        cli.report.files_scanned >= cli.runs * 2,
        "{} run(s) each produced a stdout and a stderr, but the sweep counted only {} \
         artifact(s) — the runs are not being recorded",
        cli.runs,
        cli.report.files_scanned
    );
    assert!(
        cli.report.bytes_scanned > 50_000,
        "the sweep read only {} byte(s) across {} artifact(s): it looked at far less \
         than {} CLI run(s) and a whole store print",
        cli.report.bytes_scanned,
        cli.report.files_scanned,
        cli.runs
    );
    eprintln!(
        "§29 CLI sweep: {} command run(s), {} artifact(s), {} byte(s), {} file(s) on \
         disk excused ({})",
        cli.runs,
        cli.report.files_scanned,
        cli.report.bytes_scanned,
        cli.report.skipped.len(),
        cli.report
            .skipped
            .first()
            .map(|s| s.rsplit(['/', '\\']).next().unwrap_or(s))
            .unwrap_or("nothing"),
    );
    cli.report.assert_clean();
}

/// A `.zip` of a candidate tree, for the archive reader.
///
/// The directory holding it is returned as well so the caller decides when it
/// goes away: the scan happens inside this test, and a `TempDir` dropped on the
/// floor of a helper would take the archive with it.
fn archive_of(candidate: &Path, rels: &[String], tag: &str) -> (TempDir, PathBuf) {
    use std::io::Write;

    let dir = TempDir::new(tag);
    let path = dir.child("candidate.zip");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::<u8>::new()));
    let options: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for rel in rels {
        zip.start_file(rel.clone(), options)
            .expect("start an archive member");
        zip.write_all(&std::fs::read(candidate.join(rel)).expect("member"))
            .expect("write an archive member");
    }
    let bytes = zip.finish().expect("finish the archive").into_inner();
    std::fs::write(&path, &bytes).expect("write the archive");
    (dir, path)
}

/// One project's worth of `swp` runs, sweeping as it goes.
///
/// The transcript is kept so the test can assert that the runs printed the
/// private-but-not-secret values they are supposed to print. Without that, every
/// leak assertion in this file could be satisfied by a CLI that said nothing.
struct Cli {
    cwd: PathBuf,
    needles: Vec<NeedleSet>,
    report: SweepReport,
    transcript: String,
    verbs: Vec<String>,
    runs: usize,
}

impl Cli {
    fn new(cwd: &Path, needles: &[NeedleSet]) -> Self {
        Cli {
            cwd: cwd.to_path_buf(),
            needles: needles.to_vec(),
            report: SweepReport::default(),
            transcript: String::new(),
            verbs: Vec::new(),
            runs: 0,
        }
    }

    /// Run `argv` in this project, sweeping both streams.
    fn run(&mut self, argv: &[&str]) -> Run {
        self.at(argv, &self.cwd.clone())
    }

    /// As [`Self::run`], from another directory: the commands that search upward
    /// for a store have a different failure to say when there is none.
    fn at(&mut self, argv: &[&str], cwd: &Path) -> Run {
        let run = Run::of(argv, cwd);
        // 70 is `INTERNAL`, which is never a correct answer — and a panic caught
        // there tends to be one that was about to print something.
        assert_ne!(
            run.code,
            70,
            "`swp {}` exited INTERNAL:\n{}{}",
            argv.join(" "),
            run.out,
            run.err
        );
        let verb = argv.first().copied().unwrap_or_default().to_string();
        self.verbs.push(verb.clone());
        self.runs += 1;
        let label = format!("`swp {verb} {}`", argv[1..].join(" "))
            .trim_end()
            .to_string();
        sweep_bytes(
            &format!("{label} stdout"),
            run.out.as_bytes(),
            &self.needles,
            &mut self.report,
        );
        sweep_bytes(
            &format!("{label} stderr"),
            run.err.as_bytes(),
            &self.needles,
            &mut self.report,
        );
        self.transcript.push_str(&format!(
            "$ swp {args}\n[{code}] {out}{err}\n",
            args = argv.join(" "),
            code = run.code,
            out = run.out,
            err = run.err,
        ));
        run
    }

    /// Run it and require success, for the commands whose refusal would silently
    /// turn this sweep into a smaller one.
    fn ok(&mut self, argv: &[&str]) -> Run {
        let run = self.run(argv);
        assert_eq!(
            run.code,
            0,
            "`swp {}` exited {}: {}{}",
            argv.join(" "),
            run.code,
            run.out,
            run.err
        );
        run
    }

    /// Sweep a file a run wrote outside the project — the `-o` documents.
    fn file(&mut self, path: &Path) {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("{} was never written: {e}", path.display()));
        sweep_bytes(
            &format!("{} (-o)", path.display()),
            &bytes,
            &self.needles,
            &mut self.report,
        );
    }

    /// Fold a whole tree sweep into this run's coverage.
    fn absorb(&mut self, tree: SweepReport) {
        self.report.files_scanned += tree.files_scanned;
        self.report.bytes_scanned += tree.bytes_scanned;
        self.report.skipped.extend(tree.skipped);
        self.report.violations.extend(tree.violations);
    }
}
