//! §24 partial copy, §25 refactoring resistance, §26 adversarial removal.
//!
//! These are measurements, not unit tests with a pass/fail opinion about a
//! number: §24 says *determine empirically how detection behaves* and *do not
//! invent thresholds*, and §26 says *document what survives, what fails, what
//! becomes weaker*. So each suite prints a table a person can quote, and asserts
//! only the invariants that must hold whatever the table says:
//!
//! * an exact copy of a protected tree is found, and an empty one is not;
//! * a scan that confirmed no fragment never prints a finding (§51 — it would be
//!   accusing a candidate on no evidence at all);
//! * copying more of a project never confirms fewer sites than copying less of
//!   it, for the nested slices used here;
//! * deleting every fragment an attacker can locate confirms fewer sites than
//!   leaving them in.
//!
//! Anything else the table shows is recorded, not required.

use swp_test_suite::project::{Candidate, Project, Verdict};
use swp_test_suite::transform::{read_tree, write_tree, SiteText, Transform};
use swp_test_suite::TempDir;

/// Big enough that a tenth of it is more than one file, small enough that all of
/// this runs in the time a test suite is allowed to take.
const MODULES: usize = 12;
/// The constellation the measurements need: §25's per-file attacks read better
/// when a site is in most modules rather than concentrated in three files.
const TARGET_SITES: u32 = 24;

fn protected_project(label: &str) -> Project {
    let project = Project::synthetic_wide(label, MODULES, TARGET_SITES);
    project.protect();
    project
}

/// Scan `candidate` as an outsider's copy, from the protecting project's keys.
fn judge(project: &Project, candidate: &Candidate) -> Verdict {
    project.scan(candidate.path())
}

/// One row of every table here: what the scan said, in the three numbers that
/// matter — how many sites it confirmed, how many files that took, and what the
/// verdict was.
fn report(heading: &str, rows: &[(String, Verdict)]) {
    println!("\n{heading}");
    println!(
        "  {:<26} {:>9} {:>7} {:>6} {:>6} {:>13}  verdict",
        "case", "confirmed", "probes", "chance", "fingerprint", "guarantee"
    );
    for (name, v) in rows {
        println!(
            "  {:<26} {:>9} {:>7} {:>6.1} {:>13} {:>9.1}  {} / {}",
            name, v.fragments, v.probes, v.chance, v.fingerprint, v.guarantee, v.result, v.level,
        );
    }
}

/// The invariant every table in this file must satisfy, whatever it measures.
fn assert_never_accuses_on_no_evidence(name: &str, v: &Verdict) {
    assert!(
        !v.detected() || v.fragments > 0 || v.fingerprint == "match",
        "{name}: a finding with no confirmed fragment and no exact fingerprint"
    );
    let expected = match v.result.as_str() {
        "PROVENANCE_DETECTED" => 1,
        "INCONCLUSIVE" => 10,
        "NO_PROVENANCE_DETECTED" => 0,
        other => panic!("{name}: unknown result {other:?}"),
    };
    assert_eq!(
        v.run.code, expected,
        "{name}: verdict {} and exit code {} are not the same statement\n{}",
        v.result, v.run.code, v.run.out
    );
}

// --------------------------------------------------------------------------------------
// §24 — partial copy
// --------------------------------------------------------------------------------------

#[test]
fn an_exact_copy_is_found_and_no_copy_is_not() {
    let project = protected_project("exact-copy");
    let whole = project.copy_whole("exact-copy-candidate");
    let v = judge(&project, &whole);
    assert_never_accuses_on_no_evidence("whole copy", &v);
    assert!(
        v.detected(),
        "a byte-for-byte copy of the protected tree was not found:\n{}",
        v.run.out
    );
    assert_eq!(
        v.fingerprint, "match",
        "the copy lost the fingerprint: {v:?}"
    );

    // The control: a candidate with none of this project in it. §27's cheapest
    // case, and the reason a "0% of the project" row is in the table at all.
    let none = project.copy_to_candidate("empty-copy", |_| false);
    assert!(none.sources().is_empty(), "a 0% copy copied something");
    let empty = judge(&project, &none);
    assert_never_accuses_on_no_evidence("empty candidate", &empty);
    // Not "clean". A scan that read no file cannot tell an unprotected copy from
    // an absent one, and §51 says the difference is the point of `INCONCLUSIVE`.
    assert_eq!(
        empty.result, "INCONCLUSIVE",
        "an empty tree got a verdict:\n{}",
        empty.run.out
    );
    assert!(empty.partial, "the report did not say it examined nothing");
    assert_eq!(
        empty.run.code, 10,
        "cannot-say must exit 10:\n{}",
        empty.run.out
    );
    let listed = |key: &str| {
        empty.run.json()[key]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        listed("notes").contains("no source this protocol can read"),
        "the refusal did not say what it could not read:\n{}",
        empty.run.out
    );
    assert!(
        listed("explanation").contains("cannot distinguish"),
        "the verdict did not say why it refused to say:\n{}",
        empty.run.out
    );
}

#[test]
fn the_partial_copy_ladder_is_measured() {
    let project = protected_project("partial-ladder");
    let release = project.latest();
    let total = release.sites.len();
    let mut rows = Vec::new();
    let mut found = Vec::new();

    // The brief's seven steps. 0% is the empty candidate above, so the ladder
    // starts at 10%.
    for (num, den, label) in [
        (1, 10, "10%"),
        (1, 4, "25%"),
        (1, 2, "50%"),
        (3, 4, "75%"),
        (9, 10, "90%"),
        (1, 1, "100%"),
    ] {
        let candidate = project.copy_fraction(&format!("ladder-{label}"), num, den);
        let v = judge(&project, &candidate);
        assert_never_accuses_on_no_evidence(label, &v);
        println!(
            "  {label:>4} of {} files kept: {} confirmed of {total}, {} file(s), {}/{}",
            candidate.sources().len(),
            v.fragments,
            v.files,
            v.result,
            v.level,
        );
        found.push((label.to_string(), v.fragments, v.detected()));
        rows.push((label.to_string(), v));
    }
    report(
        &format!(
            "§24 partial copy of a {total}-site release ({} modules)",
            MODULES
        ),
        &rows,
    );

    // 25/50/75 are nested slices of the same sorted file list, so a bigger slice
    // cannot confirm fewer sites. Non-nested steps (10%, 90%) are printed but not
    // compared: they draw a different subset, and calling that a trend would be
    // reading a number that was never measured.
    let quarters: Vec<(String, usize)> = found
        .iter()
        .filter(|(l, _, _)| matches!(l.as_str(), "25%" | "50%" | "75%" | "100%"))
        .map(|(l, f, _)| (l.clone(), *f))
        .collect();
    for pair in quarters.windows(2) {
        assert!(
            pair[1].1 >= pair[0].1,
            "copying more of the project confirmed fewer sites: {} then {}",
            pair[0].0,
            pair[1].0,
        );
    }
    assert_eq!(found.last().unwrap().1, total, "the 100% row lost sites");
    assert!(found.last().unwrap().2, "the 100% row was not a finding");
}

// --------------------------------------------------------------------------------------
// §25 — refactoring
// --------------------------------------------------------------------------------------

#[test]
fn each_refactoring_form_is_measured() {
    let project = protected_project("refactoring");
    let release = project.latest();
    let total = release.sites.len();
    let mut rows = Vec::new();
    let mut survived = 0usize;

    for t in Transform::REFACTORING {
        let candidate = project.copy_whole(&format!("refac-{}", t.slug()));
        let mut tree = read_tree(candidate.path());
        let changed = t.apply(&mut tree, &site_texts(&release));
        assert!(
            changed > 0,
            "{} changed nothing, so it measures nothing",
            t.slug()
        );
        write_tree(candidate.path(), &tree);
        let v = judge(&project, &candidate);
        assert_never_accuses_on_no_evidence(t.slug(), &v);
        if v.detected() {
            survived += 1;
        }
        rows.push((t.slug().to_string(), v));
    }
    report(
        &format!("§25 refactoring a {total}-site release thirteen ways"),
        &rows,
    );

    // The claim §10 and §15 make is that a name-preserving radius and an
    // abstracted one are computed from *structure*, so renaming and reformatting
    // cannot be the thing that loses every site. That is what this asserts; how
    // many sites each form actually cost is printed above, not demanded here.
    for name in [
        "variable_rename",
        "function_rename",
        "class_rename",
        "formatting",
    ] {
        let v = &rows.iter().find(|(n, _)| n == name).expect("row missing").1;
        assert!(
            v.fragments > 0,
            "{name} lost every site: a rename is exactly what an abstracted radius \
             exists to survive\n{}",
            v.run.out
        );
    }
    let untouched = judge(&project, &project.copy_whole("refac-control"));
    assert!(
        untouched.detected(),
        "the control copy was not detected, so the ladder below it is measuring nothing"
    );
    for (name, v) in &rows {
        assert!(
            v.fragments <= untouched.fragments,
            "{name} confirmed {} sites when the unmodified copy confirmed {}: a refactoring \
             edits what is there, it cannot add confirmations",
            v.fragments,
            untouched.fragments,
        );
    }
    println!(
        "\n  {survived} of {} refactoring forms still produced a finding on a {total}-site \
         release; the table above is the per-form detail.",
        Transform::REFACTORING.len()
    );
}

// --------------------------------------------------------------------------------------
// §26 — adversarial removal
// --------------------------------------------------------------------------------------

#[test]
fn removal_attacks_take_sites_away_and_say_so() {
    let project = protected_project("adversarial");
    let release = project.latest();
    let sites = site_texts(&release);
    let untouched = judge(&project, &project.copy_whole("adv-control"));
    let mut rows = vec![("(unmodified copy)".to_string(), untouched.clone())];
    let mut text_left: Vec<(String, usize)> = Vec::new();

    for t in Transform::ADVERSARIAL {
        let candidate = project.copy_whole(&format!("adv-{}", t.slug()));
        let mut tree = read_tree(candidate.path());
        let changed = t.apply(&mut tree, &sites);
        write_tree(candidate.path(), &tree);
        // How many fragment renderings are still sitting in the source as text.
        // A row that confirms nothing has to be read together with this: "the
        // attacker removed the watermark" and "the attacker removed the sites,
        // and the detector lost the rest" are different claims.
        let left = sites
            .iter()
            .filter(|s| tree.get(&s.file).is_some_and(|b| b.contains(&s.rendered)))
            .count();
        println!(
            "  {}: changed {changed} file(s), {left} of {} renderings still in the text",
            t.slug(),
            sites.len(),
        );
        text_left.push((t.slug().to_string(), left));
        let v = judge(&project, &candidate);
        assert_never_accuses_on_no_evidence(t.slug(), &v);
        assert!(
            v.fragments <= untouched.fragments,
            "{} confirmed more sites than the unmodified copy",
            t.slug()
        );
        rows.push((t.slug().to_string(), v));
    }
    report(
        &format!(
            "§26 removal, on a {}-site release whose fragments an attacker can locate",
            untouched.fragments
        ),
        &rows,
    );

    // Deleting every fragment the manifest names has to cost something, or the
    // watermark is being found somewhere the watermark is not.
    let removed = &rows[1].1;
    assert!(
        removed.fragments < untouched.fragments || removed.fragments == 0,
        "artifact removal left {} of {} sites and found nothing to report",
        removed.fragments,
        untouched.fragments,
    );
    // §26's last line: never claim the watermark cannot be removed. The suite's
    // own shape says so — the more of the tree an attacker rebuilds, the less the
    // detector can see, and that is the result the documentation must print.
    let rebuilt = rows.last().expect("module_rebuild row").1.clone();
    let rebuilt_left = text_left.last().expect("module_rebuild row").1;
    assert!(
        rebuilt.fragments <= untouched.fragments,
        "a rebuilt module confirmed MORE than the original: {} vs {}",
        rebuilt.fragments,
        untouched.fragments,
    );
    // The row has to be read together with the rendering counts printed above: a
    // rebuild leaves some fragments in the file as text and confirms almost none
    // of them, because one site that survives inside a constellation the attacker
    // took apart is not yet evidence — it is one more probe against the same
    // bound. Asking the two counts to agree would assert that the watermark is a
    // set of strings, which is exactly what §9 says it is not.
    println!(
        "\n  after rebuild: {} of {} sites confirmed, {rebuilt_left} of {} renderings still in \
         the text, verdict {}",
        rebuilt.fragments,
        untouched.fragments,
        sites.len(),
        if rebuilt.detected() {
            "found"
        } else {
            "not found"
        },
    );
}

/// The evasion that touches no watermark bit: copy the protected tree intact and
/// surround it with boilerplate of your own.
///
/// §52's question is whether a defender's weakness is cheap to reach, and the
/// coincidence bound is computed from *spans that reached a tag comparison* — so
/// a candidate that hands one site ninety spans of the same statement raises the
/// bound without removing one confirmation. Padding is the opposite of removal:
/// it leaves the watermark in place and argues that finding it proved nothing.
/// This test measures whether that argument holds, in the four numbers the ladder
/// reads, and never asserts an outcome the project has not earned.
#[test]
fn a_padded_copy_is_measured_against_an_unpadded_one() {
    // A dense tree, because a thief's padding has to collide with a site's keyed
    // address to raise the bound at all, and unrelated files rarely do. Sharing
    // one house style — the same constants restated in eighty modules, which is
    // what one team's repository looks like from the inside — is the strongest
    // version of the attack that does not require the private manifest.
    let project = Project::dense_wide("padded", MODULES, TARGET_SITES, 0);
    project.protect();
    let release = project.latest();

    let plain = project.copy_whole("padded-plain");
    let plain_v = judge(&project, &plain);
    assert_never_accuses_on_no_evidence("unpadded copy", &plain_v);

    let sdk = project.copy_whole("padded-tree");
    let filler = TempDir::new("padded-filler");
    let written = swp_test_suite::fixtures::Corpus::Generated.write(filler.path());
    for (rel, body) in read_tree(filler.path()) {
        sdk.write(&format!("pkg/{rel}"), &body);
    }
    let sdk_v = judge(&project, &sdk);
    assert_never_accuses_on_no_evidence("copy padded with another team's generated code", &sdk_v);

    let house = project.copy_whole("padded-house");
    let twin = Project::dense_wide("padded-twins", 80, TARGET_SITES, 1);
    for rel in twin.sources() {
        // Under `pkg/`, for two reasons. The generator names its modules
        // `src/modN.js` and so does the protected tree, so an unprefixed copy
        // lands on top of the evidence — which is exactly what happened first
        // time this ran, and read as a total detection failure. And the prefix
        // has to be one the scanner does not prune: `vendor/` is in the default
        // excludes, so padding there is padding the scan never opens.
        let body = twin.read(&rel);
        house.write(&format!("pkg/{rel}"), &body);
    }
    let house_v = judge(&project, &house);
    assert_never_accuses_on_no_evidence("copy padded in the same house style", &house_v);

    assert_eq!(
        written.len(),
        82,
        "the padding corpus changed size; the rows below no longer differ by one thing"
    );
    // The rows only mean something if the stolen tree is still in all three
    // candidates, byte for byte.
    for (name, candidate) in [("exact copy", &plain), ("sdk", &sdk), ("house", &house)] {
        for rel in release.files() {
            assert_eq!(
                candidate.read(&rel),
                project.read(&rel),
                "{name}: the padding changed {rel}, so this row is not the same copy"
            );
        }
    }
    for (name, v) in [("sdk padding", &sdk_v), ("house padding", &house_v)] {
        assert!(
            v.files_scanned > plain_v.files_scanned,
            "{name}: the scan read {} file(s), the same as the unpadded copy, so it never \
             opened the padding at all and this row measures nothing. Check the default \
             excludes first — node_modules, dist, build, target, vendor and *.min.js are \
             pruned by design — before reading a flat row as a detection result.",
            v.files_scanned
        );
        assert!(
            v.fragments >= plain_v.fragments,
            "{name}: adding files made sites *disappear* — {} vs {} ({} / {}, partial {})",
            v.fragments,
            plain_v.fragments,
            v.result,
            v.level,
            v.partial,
        );
    }

    report(
        "§52 — one stolen tree, padded three ways: the bound is the only thing that moves",
        &[
            ("exact copy".to_string(), plain_v.clone()),
            ("+ 82 generated files".to_string(), sdk_v.clone()),
            ("+ 80 same-style files".to_string(), house_v.clone()),
        ],
    );
    println!(
        "  {} site(s) protected into {} file(s); the three candidates differ only in what was \
         added around them — the fragments, their files and their bytes are identical in all \
         three rows (checked above).",
        release.sites_embedded,
        release.files().len()
    );
    let verdict_of = |v: &Verdict| format!("{} / {}", v.result, v.level);
    for (name, v) in [
        ("exact copy          ", &plain_v),
        ("padded, unrelated   ", &sdk_v),
        ("padded, same style  ", &house_v),
    ] {
        println!(
            "  {name} {} of {TARGET_SITES} confirmed on {} probes: bound {:.1}, above it {:.1}, \
             {verdict}\n",
            v.fragments,
            v.probes,
            v.chance,
            v.guarantee,
            verdict = verdict_of(v),
        );
    }
    if plain_v.detected() && house_v.detected() && sdk_v.detected() {
        println!(
            "  dilution did not hold on this build: the same {} confirmations carried all three \
             verdicts, and the bound rose from {:.1} to {:.1} without overtaking them.",
            house_v.fragments, plain_v.chance, house_v.chance
        );
    } else if house_v.fragments > 0 && !house_v.detected() {
        println!(
            "  dilution holds: {} fragment(s) confirmed, and no finding, because the bound \
             ({:.1}) rose with the padding to meet them. Nothing was removed in that row — only \
             the arithmetic about coincidence moved. §51's boundary applies to the report as much \
             as to the claim: a verdict can be argued out of existence by adding files.",
            house_v.fragments, house_v.chance
        );
    }
}

/// The other half of "the scan found nothing": a tree the scan was told not to
/// open.
///
/// `node_modules`, `dist`, `build`, `target`, `vendor`, `*.min.js` and friends
/// are excluded from every run, protect and scan alike — which is right, because
/// a scanner that walked a project's dependency tree would never finish, and a
/// build directory is not source. It is also the cheapest place in this design
/// for a copy to sit unseen. §51 says a product may not claim more than its
/// mechanism gives, so the boundary has to be measured and said out loud rather
/// than discovered by someone relying on a clean report.
#[test]
fn a_copy_hiding_in_an_excluded_directory_is_said_so() {
    let project = protected_project("excluded");
    let hidden = project.copy_to_candidate("excluded-hidden", |_| false);
    for rel in project.sources() {
        let body = project.read(&rel);
        hidden.write(&format!("vendor/{rel}"), &body);
    }
    assert!(
        read_tree(hidden.path()).len() > 4,
        "the hidden candidate holds no files, so this measures an empty directory rather than \
         an excluded one"
    );
    let v = judge(&project, &hidden);
    report(
        "§51 — the same tree, one directory name away from being read",
        &[("copy under vendor/".to_string(), v.clone())],
    );
    println!(
        "  {} file(s) in the candidate, {} read by the scan, partial {}, verdict {} / {}",
        read_tree(hidden.path()).len(),
        v.files_scanned,
        v.partial,
        v.result,
        v.level,
    );
    assert_eq!(
        v.files_scanned, 0,
        "the scan opened a directory the excludes name — the boundary below is not what the \
         product promises"
    );
    assert!(
        v.partial || v.result == "INCONCLUSIVE",
        "a tree nobody examined got a verdict of {} with no note that part of the candidate was \
         never read. That is the reading §51 forbids: \"nothing found\" about files the scanner \
         was told to skip is not a statement about them.\n{}",
        v.result,
        v.run.out
    );
}

fn site_texts(release: &swp_test_suite::project::Release) -> Vec<SiteText> {
    release.site_texts()
}
