//! The harness behind the protect/generate binding-boundary decision: measures what
//! a foreign binding would actually be handed, and what anything downstream of a
//! protection run reads it back for.
//!
//! Run it with `cargo run --locked -p swp-test-suite --example
//! protect-binding-boundary`. Output is tab-separated lines on stdout: `M1` is the
//! carriage table (which artifact of a run contains a keyed location id), `M2` the
//! cross-release behaviour of those ids, `M3` what the published half of a store can
//! do alone, `M4` what stops working when a plan's location ids are destroyed, `M5`
//! whether applying a generated plan needs the plan document, `M6` which parts of the
//! CLI's protect document a result type without location ids can still produce.
//!
//! The decision it supports is `docs/adr/0001-protect-generate-binding-boundary.md`,
//! which cites these rows by number; each synthetic project is protected with a fresh
//! root secret, so the relations between rows are the result and the raw counts are
//! not.
//!
//! Every row is a measurement of a real run over a real tree, through the calls `swp`
//! makes. Nothing here changes what the product does: the harness corrupts only
//! documents it wrote into its own temporary projects, and reads them back through
//! the product's own loaders.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;
use swp_core::error::ErrorCode;
use swp_sdk::{Mode, ProtectOptions, ReleaseId, ReleaseSelection, Session, VerifyOptions};
use swp_test_suite::project::{bare_dir, Project};

const ID_ONE: &str = "rel-aaaaaaaaaaaaaaaa";
const ID_TWO: &str = "rel-bbbbbbbbbbbbbbbb";

/// A location id rendered the way every document renders one: 32 lowercase hex.
const ZERO_ID: &str = "00000000000000000000000000000000";

fn main() {
    carriage();
    cross_release();
    public_half_alone();
    plan_is_descriptive();
    generate_then_apply();
    cli_read_set();
}

fn row(tag: &str, key: &str, value: impl std::fmt::Display) {
    println!("{tag}\t{key}\t{value}");
}

fn session(root: &Path) -> Session {
    Session::open(root, &swp_sdk::Overrides::default())
        .expect("every project here was initialized first")
}

fn options(mode: Mode, id: &str) -> ProtectOptions {
    ProtectOptions {
        mode,
        release_id: Some(ReleaseId::new(id).unwrap()),
        revision: None,
    }
}

/// Every location id of a run's plan, in document order, as the hex a document holds.
fn hex_ids(outcome: &swp_sdk::ProtectOutcome) -> Vec<String> {
    outcome
        .protection
        .plan
        .sites
        .iter()
        .flat_map(|site| site.locations.iter().map(|id| id.hex()))
        .collect()
}

/// `(how many of the given ids appear, total occurrences)` in one blob of bytes.
fn carries(bytes: &[u8], ids: &[String]) -> (usize, usize) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut present = 0usize;
    let mut total = 0usize;
    for id in ids {
        let hits = text.matches(id.as_str()).count();
        if hits > 0 {
            present += 1;
        }
        total += hits;
    }
    (present, total)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// A store-relative, forward-slashed name resolved against one project's `.swp/`.
fn store_file(root: &Path, rel: &str) -> Vec<u8> {
    let native = rel.replace('/', std::path::MAIN_SEPARATOR_STR);
    read(&root.join(".swp").join(native))
}

fn write_tree_file(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// M1 — of the documents one protection run leaves behind, which carry a keyed
/// location id at all?
///
/// The question a binding-facing allowlist has to answer before it can say anything
/// about a type. The ids are expected in the two private documents and nowhere else;
/// the row that says otherwise is the finding.
fn carriage() {
    let project = Project::synthetic_wide("bb-carriage", 8, 12);
    let root = project.root().to_path_buf();
    let store = project.store();
    let id = ReleaseId::new(ID_ONE).unwrap();
    let s = session(&root);
    let outcome = s.protect(&options(Mode::Release, ID_ONE)).unwrap();
    let ids = hex_ids(&outcome);
    row("M1", "sites", outcome.protection.plan.sites.len());
    row("M1", "ids", ids.len());

    let verify = s
        .verify(&VerifyOptions {
            release: Some(id.clone()),
            save: true,
            rows: None,
        })
        .unwrap();
    let saved_verify = store_file(&root, verify.report_saved.as_ref().unwrap());
    let candidate = project.copy_whole("bb-carriage-cand");
    let scan = s
        .scan(candidate.path(), &ReleaseSelection::All, true)
        .expect("a scan of the project's own tree");
    let saved_scan = store_file(&root, &scan.saved.as_ref().unwrap().path);

    let artifacts: [(&str, Vec<u8>); 7] = [
        ("public_release_record", read(&store.release_path(&id))),
        ("private_manifest", read(&store.manifest_path(&id))),
        ("private_plan", read(&store.plan_path(&id))),
        ("saved_verify_report", saved_verify),
        ("saved_scan_report", saved_scan),
        (
            "verify_document_json",
            serde_json::to_vec(&verify.document).unwrap(),
        ),
        (
            "sdk_protection_envelope_json",
            serde_json::to_vec(&outcome.protection).unwrap(),
        ),
    ];
    for (label, bytes) in &artifacts {
        let (present, total) = carries(bytes, &ids);
        row("M1", label, format!("{present}/{} ({total})", ids.len()));
    }
    let cli = project.run(&[
        "protect",
        "--dry-run",
        "--release",
        ID_TWO,
        "--format",
        "json",
    ]);
    let (present, total) = carries(cli.out.as_bytes(), &ids);
    row(
        "M1",
        "cli_protect_stdout_json",
        format!("{present}/{} ({total})", ids.len()),
    );
    // A document that described no site would print no id for a reason that proves
    // nothing, so state how much of a constellation the run did describe.
    let cli_doc: serde_json::Value =
        serde_json::from_str(cli.out.trim()).expect("the CLI prints one JSON document");
    row(
        "M1",
        "cli_describes_sites",
        cli_doc["families"]
            .as_object()
            .map(|families| {
                families
                    .values()
                    .filter_map(serde_json::Value::as_u64)
                    .sum::<u64>()
            })
            .unwrap_or(0),
    );
    let text = project.run(&["protect", "--dry-run", "--release", ID_TWO]);
    let (present, _) = carries(text.out.as_bytes(), &ids);
    row("M1", "cli_protect_stdout_text", present);
}

/// M2 — is a location id a per-site name or a per-release one?
///
/// `ManifestKeys::location_id` mixes the project id, the radius code, the
/// canonicalizer version and the site's canonical digest into the MAC — and no
/// release id (`swp-manifest/src/keys.rs`), while the *selection* key does take one.
/// So two releases of one project must name an unchanged site with the same id, and
/// the only measurement that can show it is the overlap of the two plans' id sets:
/// 128-bit values that two independent derivations agree on are not agreeing by luck.
/// The positions cannot be used as the join, because a plan's line hint is the line
/// in the *protected* text, and which equivalent form carries a site's code is itself
/// keyed by the release — hence the tuple and set rows rather than a per-line compare.
fn cross_release() {
    let project = Project::synthetic_wide("bb-two-releases", 8, 12);
    let root = project.root().to_path_buf();
    let s = session(&root);
    let one = s.protect(&options(Mode::Plan, ID_ONE)).unwrap();
    let two = s.protect(&options(Mode::Plan, ID_TWO)).unwrap();

    let set1: std::collections::BTreeSet<String> = hex_ids(&one).into_iter().collect();
    let set2: std::collections::BTreeSet<String> = hex_ids(&two).into_iter().collect();
    let shared = set1.iter().filter(|id| set2.contains(*id)).count();
    let tuples_shared = one
        .protection
        .plan
        .sites
        .iter()
        .filter(|a| {
            two.protection
                .plan
                .sites
                .iter()
                .any(|b| a.locations == b.locations)
        })
        .count();
    row("M2", "sites_release_one", one.protection.plan.sites.len());
    row("M2", "sites_release_two", two.protection.plan.sites.len());
    row("M2", "distinct_ids_release_one", set1.len());
    row("M2", "distinct_ids_release_two", set2.len());
    row("M2", "ids_in_both_sets", shared);
    row("M2", "ids_only_in_one", set1.len() - shared);
    row("M2", "ids_only_in_two", set2.len() - shared);
    row("M2", "four_id_tuples_in_both", tuples_shared);
    row(
        "M2",
        "plan_mode_published_no_release",
        match s.releases(&ReleaseSelection::All) {
            Ok(list) => list.is_empty(),
            Err(e) => e.code() == ErrorCode::NotProtected,
        },
    );
    // The release fingerprint is taken over the tree *as this run would protect it*,
    // and the form that carries a site's code is keyed by the release, so two plans
    // over one untouched tree disagree on the fingerprint as well as on which sites
    // they picked. Measured because a binding that shows the number has to know which
    // of the two it is showing.
    row(
        "M2",
        "fingerprint_identical",
        one.protection.fingerprint == two.protection.fingerprint,
    );
    row(
        "M2",
        "touched_files_identical",
        one.protection.plan.touched_files() == two.protection.plan.touched_files(),
    );
}

/// M3 — what can the published half of a store do on its own?
///
/// A binding that handed out ids would be handing out a description of the private
/// constellation. This measures the other side: with every published artifact and none
/// of the private half, which operations still answer.
fn public_half_alone() {
    let project = Project::synthetic_wide("bb-public-only", 8, 12);
    let root = project.root().to_path_buf();
    let s = session(&root);
    let outcome = s.protect(&options(Mode::Release, ID_ONE)).unwrap();
    let ids = hex_ids(&outcome);
    let candidate = project.copy_whole("bb-public-only-cand");

    let mirror = bare_dir("bb-public-only-mirror");
    copy_tree(&root.join(".swp/public"), &mirror.join(".swp/public"));
    for rel in project.sources() {
        write_tree_file(&mirror, &rel, project.read(&rel).as_bytes());
    }
    write_tree_file(
        &mirror,
        ".swp/config.toml",
        std::fs::read(root.join(".swp/config.toml"))
            .unwrap_or_default()
            .as_slice(),
    );

    let opened = Session::open(&mirror, &swp_sdk::Overrides::default());
    row("M3", "session_open", opened.is_ok());
    let Ok(mirror_session) = opened else {
        row("M3", "note", "the public half does not open a session");
        return;
    };
    row(
        "M3",
        "releases_listed",
        mirror_session
            .releases(&ReleaseSelection::All)
            .unwrap_or_default()
            .len(),
    );
    let record = mirror_session.release(&ReleaseId::new(ID_ONE).unwrap());
    row("M3", "read_public_record", code_of(&record));
    row(
        "M3",
        "record_carries_ids",
        carries(
            serde_json::to_vec(&record.unwrap()).unwrap().as_slice(),
            &ids,
        )
        .0,
    );
    row(
        "M3",
        "verify",
        code_of(&mirror_session.verify(&VerifyOptions::default())),
    );
    row(
        "M3",
        "scan",
        code_of(&mirror_session.scan(candidate.path(), &ReleaseSelection::All, false)),
    );
    row(
        "M3",
        "protect_dry_run",
        code_of(&mirror_session.protect(&options(Mode::DryRun, ID_TWO))),
    );
    row("M3", "caller_holds_ids", format!("{}", ids.len()));
}

fn code_of<T>(result: &Result<T, swp_core::error::SwpError>) -> String {
    match result {
        Ok(_) => "OK".to_string(),
        Err(e) => e.code().as_str().to_string(),
    }
}

/// A document read as text, with every wall-clock stamp replaced by `<stamp>`.
///
/// A report and the plan views record the moment they were produced, so two
/// observations of one unchanged store differ everywhere and the comparison would
/// say nothing. Only the clock is taken out: the shape removed is
/// `YYYY-MM-DDTHH:MM:SS`, which no keyed value, path or count in these documents
/// has, so a real difference in the location ids still shows through it.
fn stampless(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let digit = |i: usize| i < c.len() && c[i].is_ascii_digit();
    let four = |i: usize| i + 4 <= c.len() && (0..4).all(|k| digit(i + k));
    let shape = |i: usize| -> bool {
        four(i)
            && i + 20 <= c.len()
            && c[i + 4] == '-'
            && digit(i + 5)
            && digit(i + 6)
            && c[i + 7] == '-'
            && digit(i + 8)
            && digit(i + 9)
            && c[i + 10] == 'T'
            && digit(i + 11)
            && digit(i + 12)
            && c[i + 13] == ':'
            && digit(i + 14)
            && digit(i + 15)
            && c[i + 16] == ':'
            && digit(i + 17)
            && digit(i + 18)
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < c.len() {
        if shape(i) {
            let mut j = i + 19;
            if j < c.len() && c[j] == '.' {
                j += 1;
                while digit(j) {
                    j += 1;
                }
            }
            if j < c.len() && (c[j] == 'Z' || c[j] == '+' || c[j] == '-') {
                j += 1;
                while j < c.len() && (digit(j) || c[j] == ':') {
                    j += 1;
                }
            }
            out.push_str("<stamp>");
            i = j;
            continue;
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    let _ = std::fs::create_dir_all(to);
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name() else {
            continue;
        };
        let dest = to.join(name);
        if path.is_dir() {
            copy_tree(&path, &dest);
        } else {
            let _ = std::fs::copy(&path, &dest);
        }
    }
}

/// M4 — does anything read a plan's location ids back?
///
/// The plan is unsigned and the manifest is signed, so the two tolerate the same
/// tamper in opposite ways. This destroys the ids in the plan document on disk and
/// re-runs every operation that could plausibly read them, then changes one id in the
/// manifest to show which document verification is actually built on.
fn plan_is_descriptive() {
    let project = Project::synthetic_wide("bb-plan-tamper", 8, 12);
    let root = project.root().to_path_buf();
    let store = project.store();
    let id = ReleaseId::new(ID_ONE).unwrap();
    let s = session(&root);
    s.protect(&options(Mode::Release, ID_ONE)).unwrap();
    let candidate = project.copy_whole("bb-plan-tamper-cand");

    let before = observe(&project, &s, &id, candidate.path());
    let zeroed = zero_plan_locations(&store.read_plan(&id).unwrap());
    store.write_plan(&id, &zeroed).unwrap();
    let after = observe(&project, &s, &id, candidate.path());

    for key in [
        "verify_document",
        "scan_report",
        "release_record",
        "inspect_plan_text",
        "inspect_plan_json",
        "inspect_fragments_text",
        "inspect_manifest_text",
    ] {
        let raw = before[key] == after[key];
        let clock_only =
            !raw && stampless(&before[key].to_string()) == stampless(&after[key].to_string());
        row(
            "M4",
            key,
            match (raw, clock_only) {
                (true, _) => "identical",
                (false, true) => "identical but for the moment it ran",
                (false, false) => "DIFFERS",
            },
        );
    }

    let manifest = read(&store.manifest_path(&id));
    let broken = break_one_manifest_id(&manifest);
    store.write_private_manifest(&id, &broken).unwrap();
    row(
        "M4",
        "verify_after_manifest_tamper",
        code_of(&s.verify(&VerifyOptions {
            release: Some(id.clone()),
            save: false,
            rows: None,
        })),
    );
    row(
        "M4",
        "inspect_manifest_after_tamper",
        project
            .run(&["inspect", "manifest", "--release", ID_ONE])
            .code,
    );
    row(
        "M4",
        "scan_after_manifest_tamper",
        code_of(&s.scan(candidate.path(), &ReleaseSelection::All, false)),
    );
}

/// Everything a caller can observe about one protected release, as values. A CLI row
/// keeps its exit code, so a command that began refusing shows up as a difference.
fn observe(project: &Project, s: &Session, id: &ReleaseId, candidate: &Path) -> Value {
    let mut map = serde_json::Map::new();
    let verify = s
        .verify(&VerifyOptions {
            release: Some(id.clone()),
            save: false,
            rows: None,
        })
        .map(|o| serde_json::to_value(&o.document).unwrap())
        .unwrap_or_else(|e| Value::String(format!("error {}", e.code().as_str())));
    map.insert("verify_document".into(), verify);
    let scan = s
        .scan(candidate, &ReleaseSelection::All, false)
        .map(|o| serde_json::to_value(&o.report).unwrap())
        .unwrap_or_else(|e| Value::String(format!("error {}", e.code().as_str())));
    map.insert("scan_report".into(), scan);
    let record = s
        .release(id)
        .map(|r| serde_json::to_value(&r).unwrap())
        .unwrap_or_else(|e| Value::String(format!("error {}", e.code().as_str())));
    map.insert("release_record".into(), record);
    for (key, argv) in [
        (
            "inspect_plan_text",
            vec!["inspect", "plan", "--release", ID_ONE, "--full"],
        ),
        (
            "inspect_plan_json",
            vec![
                "inspect",
                "plan",
                "--release",
                ID_ONE,
                "--full",
                "--format",
                "json",
            ],
        ),
        (
            "inspect_fragments_text",
            vec!["inspect", "fragments", "--release", ID_ONE, "--full"],
        ),
        (
            "inspect_manifest_text",
            vec!["inspect", "manifest", "--release", ID_ONE, "--full"],
        ),
    ] {
        let run = project.run(&argv);
        map.insert(
            key.into(),
            Value::String(format!("exit {}\n{}", run.code, run.out)),
        );
    }
    Value::Object(map)
}

/// Rewrite a plan document with every location id set to the all-zero id.
fn zero_plan_locations(bytes: &[u8]) -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(bytes).unwrap();
    let sites = doc["sites"].as_array_mut().unwrap();
    for site in sites.iter_mut() {
        for slot in site["locations"].as_array_mut().unwrap().iter_mut() {
            *slot = Value::String(ZERO_ID.to_string());
        }
    }
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    text.into_bytes()
}

/// Change one hex character of one location id in the signed manifest.
fn break_one_manifest_id(bytes: &[u8]) -> Vec<u8> {
    let mut text = String::from_utf8(bytes.to_vec()).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let first = doc["sites"][0]["locations"][0]
        .as_str()
        .expect("a manifest site has a location id")
        .to_string();
    let flipped = match first.split_at(1) {
        ("0", rest) => format!("f{rest}"),
        (_, rest) => format!("0{rest}"),
    };
    text = text.replacen(&first, &flipped, 1);
    text.into_bytes()
}

/// M5 — is a generated plan an input to applying it?
///
/// `swp protect --release <id>` is documented to reproduce `swp generate --release
/// <id>`'s constellation. If the constellation is re-derived from the key and the id
/// rather than read back from the plan file, then the plan is an operator log, and a
/// binding needs only the id to apply a plan it was never shown.
fn generate_then_apply() {
    let project = Project::synthetic_wide("bb-generate-apply", 8, 12);
    let root = project.root().to_path_buf();
    let store = project.store();
    let id = ReleaseId::new(ID_ONE).unwrap();
    let s = session(&root);
    let planned = s.protect(&options(Mode::Plan, ID_ONE)).unwrap();

    std::fs::remove_file(store.plan_path(&id)).unwrap();
    row("M5", "plan_deleted", !store.plan_path(&id).exists());

    let applied = s.protect(&options(Mode::Release, ID_ONE)).unwrap();
    let a = hex_ids(&planned);
    let b = hex_ids(&applied);
    row("M5", "ids_planned", a.len());
    row("M5", "ids_applied", b.len());
    row("M5", "identical_constellation", a == b);
    row(
        "M5",
        "identical_sites",
        planned.protection.plan.sites == applied.protection.plan.sites,
    );
    let verify = s.verify(&VerifyOptions {
        release: Some(id.clone()),
        save: false,
        rows: None,
    });
    row(
        "M5",
        "verify",
        verify
            .as_ref()
            .map(|o| o.document.verdict.as_str().to_string())
            .unwrap_or_else(|_| code_of(&verify)),
    );
    row(
        "M5",
        "inspect_plan_after_apply_exit",
        project
            .run(&["inspect", "plan", "--release", ID_ONE])
            .code
            .to_string(),
    );
}

/// M6 — can a result type that carries no location id still produce everything the
/// CLI's protect document says?
///
/// Each row is one top-level key of `SWP-1-protection-v1`: `sdk` when the harness
/// rebuilt that key's exact value out of the non-plan fields of `Protection` plus the
/// plan's *strings*, `cli` when the value is the CLI's own prose or constants, and
/// `differs` when neither produced it — which is the list a binding would have to
/// argue about.
fn cli_read_set() {
    let project = Project::synthetic_wide("bb-cli-read-set", 8, 12);
    let root = project.root().to_path_buf();
    let s = session(&root);
    let dry = s.protect(&options(Mode::DryRun, ID_ONE)).unwrap();
    let p = &dry.protection;

    let mut families: BTreeMap<String, u32> = BTreeMap::new();
    for site in &p.plan.sites {
        *families.entry(site.family.clone()).or_insert(0) += 1;
    }
    let mut skip_reasons: BTreeMap<String, u32> = BTreeMap::new();
    for skipped in &p.plan.skipped {
        *skip_reasons.entry(skipped.reason.clone()).or_insert(0) += 1;
    }

    let mut rebuilt = serde_json::Map::new();
    insert(
        &mut rebuilt,
        "schema",
        Value::String("SWP-1-protection-v1".into()),
    );
    insert(
        &mut rebuilt,
        "protocol",
        Value::String(swp_core::SWP_PROTOCOL_NAME.into()),
    );
    insert(&mut rebuilt, "mode", Value::String(p.mode.as_str().into()));
    insert(
        &mut rebuilt,
        "project_id",
        Value::String(p.project_id.to_string()),
    );
    insert(
        &mut rebuilt,
        "release_id",
        Value::String(p.release_id.to_string()),
    );
    insert(&mut rebuilt, "tag_bits", Value::from(u64::from(p.tag_bits)));
    insert(
        &mut rebuilt,
        "requested_sites",
        Value::from(u64::from(p.requested_sites)),
    );
    insert(
        &mut rebuilt,
        "target_sites",
        Value::from(u64::from(p.target_sites)),
    );
    insert(
        &mut rebuilt,
        "sites_embedded",
        Value::from(u64::from(p.sites_embedded)),
    );
    insert(
        &mut rebuilt,
        "sites_skipped",
        Value::from(u64::from(p.sites_skipped)),
    );
    insert(&mut rebuilt, "files_walked", Value::from(p.files_walked));
    insert(
        &mut rebuilt,
        "files_in_scope",
        Value::from(p.files_in_scope),
    );
    insert(&mut rebuilt, "candidates", Value::from(p.candidates));
    insert(
        &mut rebuilt,
        "fingerprint",
        Value::String(p.fingerprint.to_string()),
    );
    insert(
        &mut rebuilt,
        "fingerprint_level",
        Value::String(p.fingerprint_level.clone()),
    );
    insert(
        &mut rebuilt,
        "revision",
        dry.revision.clone().map_or(Value::Null, Value::String),
    );
    let changed: Vec<Value> = p
        .files_changed
        .iter()
        .map(|f| {
            let mut o = serde_json::Map::new();
            insert(&mut o, "file", Value::String(f.file.clone()));
            insert(&mut o, "sites", Value::from(u64::from(f.sites)));
            insert(&mut o, "bytes_before", Value::from(f.bytes_before));
            insert(&mut o, "bytes_after", Value::from(f.bytes_after));
            Value::Object(o)
        })
        .collect();
    insert(&mut rebuilt, "files_changed", Value::Array(changed));
    insert(
        &mut rebuilt,
        "artifacts",
        serde_json::to_value(&p.artifacts).unwrap(),
    );
    insert(
        &mut rebuilt,
        "generated",
        serde_json::to_value(&p.artifacts).unwrap(),
    );
    insert(
        &mut rebuilt,
        "modified",
        serde_json::to_value(
            p.files_changed
                .iter()
                .map(|f| f.file.clone())
                .collect::<Vec<String>>(),
        )
        .unwrap(),
    );
    insert(
        &mut rebuilt,
        "notes",
        serde_json::to_value(&p.notes).unwrap(),
    );
    insert(
        &mut rebuilt,
        "skip_reasons",
        serde_json::to_value(&skip_reasons).unwrap(),
    );
    insert(
        &mut rebuilt,
        "families",
        serde_json::to_value(&families).unwrap(),
    );

    let cli = project.run(&[
        "protect",
        "--dry-run",
        "--release",
        ID_ONE,
        "--format",
        "json",
    ]);
    let doc: Value =
        serde_json::from_str(cli.out.trim()).expect("the CLI prints one JSON document");
    let ids = hex_ids(&dry);
    row(
        "M6",
        "location_ids_in_cli_document",
        carries(cli.out.as_bytes(), &ids).0,
    );
    let Some(map) = doc.as_object() else {
        row("M6", "keys", "the document is not an object");
        return;
    };
    row("M6", "keys", map.len());
    let sum = |key: &str| {
        map.get(key)
            .and_then(serde_json::Value::as_object)
            .map(|tally| {
                tally
                    .values()
                    .filter_map(serde_json::Value::as_u64)
                    .sum::<u64>()
            })
            .unwrap_or(0)
    };
    // The two keys the CLI derives from the plan, and how much of the plan they
    // stand for: a rebuild that matched only empty tallies would say nothing.
    row("M6", "sites_behind_families", sum("families"));
    row("M6", "sites_behind_skip_reasons", sum("skip_reasons"));
    for (key, value) in map {
        if key == "created_at" {
            // `Protection.created_at` is what the CLI prints, so the value is
            // SDK-supplied — but it is this run's clock, and the SDK run above and
            // the CLI run here are two runs, so equality cannot be tested.
            row(
                "M6",
                key,
                "sdk, per-run clock: not comparable across two runs",
            );
            continue;
        }
        match rebuilt.get(key) {
            Some(mine) if *mine == *value => row("M6", key, "sdk"),
            Some(_) => row("M6", key, "differs"),
            None => row("M6", key, "cli"),
        }
    }
}

fn insert(map: &mut serde_json::Map<String, Value>, key: &str, value: Value) {
    map.insert(key.to_string(), value);
}
