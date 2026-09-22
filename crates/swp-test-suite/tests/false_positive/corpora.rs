//! §27 — false-positive testing: "the detector must distinguish these from
//! genuine watermark evidence".
//!
//! §27 is the highest-priority test category in the brief, and the only way to
//! pass it honestly is to point the scanner at source that has nothing to do
//! with the protected project and record what it says. So this file does three
//! things, in this order:
//!
//! 1. A **positive control**: the same keys that are about to look at unrelated
//!    code must find a real leak. Without it, a table of clean rows only proves
//!    the scanner is broken.
//! 2. The **§27 sweep**: six corpora — common algorithms, framework patterns,
//!    common constants, boilerplate, standard-library usage in a second language,
//!    and popular open-source structures — scanned against several independently
//!    keyed protected projects. A `PROVENANCE_DETECTED` here is a false positive
//!    and fails the suite. The last of the six is a code generator's output at
//!    repository scale, eighty-odd files of one template, because a §27 sweep over
//!    two-file packages never reaches the volume where a coincidental
//!    confirmation is likely on arithmetic alone.
//! 3. The **hardest candidate** the brief does not name: a second project
//!    written by the same generator, so it shares every idiom and none of the
//!    names, constants or keys. This is the case where "unrelated" and
//!    "structurally indistinguishable" start to mean the same thing, and it is
//!    measured rather than asserted away.
//!
//! What the sweep prints is the observed false-positive distribution — including
//! any *lead* (a fragment confirmed with too little behind it to accuse anyone),
//! which is recorded and reported, not tuned out. §24's "do not invent
//! thresholds" applies here in both directions: there is no target rate in this
//! file, and no threshold was moved to make a row come out clean.

use std::path::Path;

use swp_test_suite::fixtures::{self, Corpus};
use swp_test_suite::project::{Project, Verdict};
use swp_test_suite::transform::read_tree;
use swp_test_suite::TempDir;

/// The measurement tree, as §24/§25/§26 use it: same module count, same
/// constellation, so every table in the test-suite describes one project.
const MODULES: usize = 12;
const TARGET_SITES: u32 = 24;

/// How many independent identities each corpus is swept against. One key proves
/// a scan came out clean; several prove it came out clean for a *key*, not for a
/// tree. The tags are 4 bits wide, so a single identity is a sample of one out
/// of a large space of unlucky coincidences.
const KEYS: usize = 5;

/// Sibling projects to generate for the same-shape control.
const SIBLINGS: usize = 6;

fn protected_project(label: &str) -> Project {
    let project = Project::synthetic_wide(label, MODULES, TARGET_SITES);
    project.protect();
    project
}

/// A candidate directory is a tree with sources and no store (§21): here built
/// from a corpus, from a generator variant, or from a copy. Returns the
/// directory and the number of files the fixture says it wrote, which is the
/// number `swp scan` has to be able to read back.
fn corpus_candidate(corpus: Corpus) -> (TempDir, usize) {
    let dir = TempDir::new(&format!("fp-{}", corpus.slug()));
    let written = corpus.write(dir.path());
    (dir, written.len())
}

fn variant_candidate(variant: usize) -> (TempDir, usize) {
    let dir = TempDir::new(&format!("fp-variant-{variant}"));
    let written = fixtures::synthetic_variant(dir.path(), MODULES, variant);
    (dir, written.len())
}

/// The invariant behind every assertion in this file: a scanner that reads a
/// tree and finds nothing must still be able to read the tree. An adapter that
/// silently accepted zero files would turn this whole suite into a tautology, so
/// each candidate is checked for the sources it was written with.
fn assert_readable(dir: &Path, want: usize, name: &str) {
    let found = read_tree(dir);
    assert!(
        found.len() >= want,
        "{name}: {} file(s) expected in the candidate, {} read from {}",
        want,
        found.len(),
        dir.display()
    );
}

fn row(name: &str, v: Verdict) -> (String, Verdict) {
    (name.to_string(), v)
}

fn report(heading: &str, rows: &[(String, Verdict)]) {
    println!("\n{heading}");
    println!(
        "  {:<30} {:>9} {:>7} {:>7} {:>7} {:>6} {:>10} {:>9} {:>6}  verdict",
        "case",
        "confirmed",
        "probes",
        "chance",
        "loose",
        "hits",
        "fingerprint",
        "guarantee",
        "read"
    );
    for (name, v) in rows {
        println!(
            "  {:<30} {:>9} {:>7} {:>7.2} {:>7.2} {:>6} {:>10} {:>9.1} {:>6}  {} / {}",
            name,
            v.fragments,
            v.probes,
            v.chance,
            v.union_bound(),
            v.files,
            v.fingerprint,
            v.guarantee,
            v.files_scanned,
            v.result,
            v.level,
        );
    }
}

/// The other half of "the detector must distinguish": it can only distinguish a
/// file it opened. A corpus the scanner could not parse would produce the same
/// empty table as a corpus it correctly cleared, so every scan in this suite has
/// to report having read every file the fixture wrote, and read all of it.
fn assert_examined(name: &str, v: &Verdict, want_files: usize) {
    assert!(
        v.files_scanned as usize >= want_files,
        "{name}: the candidate held {want_files} file(s) and the scan read {} — a clean verdict on \
         a tree nobody opened is not a clean verdict.\n{}",
        v.files_scanned,
        v.run.out
    );
    assert!(
        !v.partial,
        "{name}: the scan left part of the candidate unexamined, so its \"nothing found\" is only \
         about the part it read:\n{}",
        v.run.out
    );
}

/// §27's rule, stated as a check: a verdict of `PROVENANCE_DETECTED` about a
/// tree that was never touched by this project is an accusation on no evidence.
fn assert_not_accused(name: &str, v: &Verdict) {
    assert_ne!(
        v.result, "PROVENANCE_DETECTED",
        "{name}: §27 false positive — unrelated source got a finding.\n{}",
        v.run.out
    );
    let expected = match v.result.as_str() {
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

/// The control that makes every clean row below mean something: these very keys
/// must find a byte-for-byte leak.
#[test]
fn the_keys_that_clear_the_corpora_would_catch_a_real_leak() {
    let project = protected_project("fp-control");
    let leak = project.copy_whole("fp-control-leak");
    let v = project.scan(leak.path());
    assert!(
        v.detected(),
        "the positive control failed, so a clean sweep would prove nothing:\n{}",
        v.run.out
    );
    assert_eq!(v.fingerprint, "match");
    assert_eq!(v.run.code, 1, "a finding must exit 1:\n{}", v.run.out);
    println!(
        "\npositive control: {} site(s) protected, an exact copy of the tree confirmed {} of them \
         across {} file(s) -> {} / {}",
        project.latest().sites_embedded,
        v.fragments,
        v.files,
        v.result,
        v.level
    );
}

/// §27's list, swept against several independent identities.
#[test]
fn unrelated_corpora_are_not_mistaken_for_watermark_evidence() {
    let projects: Vec<Project> = (0..KEYS)
        .map(|k| protected_project(&format!("fp-key-{k}")))
        .collect();

    let corpora: Vec<(Corpus, TempDir, usize)> = Corpus::ALL
        .iter()
        .map(|&c| {
            let (dir, files) = corpus_candidate(c);
            assert_readable(dir.path(), files, c.slug());
            (c, dir, files)
        })
        .collect();

    let mut rows: Vec<(String, Verdict)> = Vec::new();
    let mut leads = 0usize;
    let mut probes_total = 0u64;
    let mut scans = 0usize;

    for (corpus, dir, files) in &corpora {
        for (k, project) in projects.iter().enumerate() {
            let v = project.scan(dir.path());
            scans += 1;
            probes_total += v.probes as u64;
            if v.fragments > 0 {
                leads += 1;
            }
            let name = format!("{} against key {k}", corpus.slug());
            assert_examined(&name, &v, *files);
            assert_not_accused(&name, &v);
            rows.push(row(&format!("{} key {}", corpus.slug(), k), v));
        }
    }

    report(
        &format!(
            "§27 — {} unrelated scans over {} corpora x {KEYS} independent identities",
            scans,
            corpora.len()
        ),
        &rows,
    );
    let worst = rows
        .iter()
        .map(|(_, v)| v.fragments)
        .max()
        .unwrap_or_default();
    let read = rows
        .iter()
        .map(|(_, v)| v.files_scanned as u64)
        .sum::<u64>();
    let bytes = rows.iter().map(|(_, v)| v.bytes_scanned).sum::<u64>();
    let loose = rows.iter().map(|(_, v)| v.union_bound()).sum::<f64>();
    println!(
        "  observed: {leads} of {scans} scans confirmed at least one site (a lead, none of them a \
         finding); {probes_total} span(s) reached a tag comparison; {read} file(s) and \
         {bytes} byte(s) were read in total, none of them left unexamined; the largest single \
         confirmation count was {worst}"
    );
    println!(
        "  bounds: {probes_total} probe(s) imply {loose:.1} coincidental confirmation(s) if \
         every span is counted separately and {:.1} if spans sharing a keyed address are taken \
         to be one draw. `chance` is the second figure and `loose` the first; a verdict built \
         on the gap between them is a verdict resting on an assumption, which is why both are \
         printed and neither is tuned.",
        rows.iter().map(|(_, v)| v.chance).sum::<f64>()
    );
    println!(
        "  the `{}` row is the suite's hardest case, and not because it is clever: eighty \
         modules of one template hand the matcher more spans at a site's address than it keeps \
         (§45's memory bound), which is the shape that would manufacture a confirmation out of \
         volume if the bound could be fooled by counting the same statement twice.",
        Corpus::Generated.slug()
    );
    println!(
        "  claim boundary: NO_PROVENANCE_DETECTED means \"these keys found nothing\", not \n\
         \"this code is original\"; §51 forbids the second reading and this suite never makes it."
    );

    // Non-vacuity, in the direction that matters here. A corpus that never handed
    // the matcher a second span at the same address would pass this suite by being
    // easy rather than by being unrelated, so the scale case has to demonstrably
    // be the loud one — and it does, by a wide margin, because eighty files of one
    // template restate the same literal-bearing statements.
    let probes_of = |slug: &str| {
        rows.iter()
            .filter(|(name, _)| name.starts_with(&format!("{slug} key ")))
            .map(|(_, v)| v.probes)
            .max()
            .unwrap_or(0)
    };
    let big = probes_of(Corpus::Generated.slug());
    let small = Corpus::ALL
        .iter()
        .filter(|c| **c != Corpus::Generated)
        .map(|c| probes_of(c.slug()))
        .max()
        .unwrap_or(0);
    assert!(
        big > small * 2,
        "§27 stopped testing scale: the {}-module corpus reached {big} probe(s) and the busiest \
         hand-written corpus reached {small}, so the sweep no longer distinguishes a big \
         unrelated tree from a small one",
        Corpus::Generated.slug(),
    );
}

/// The case §27 does not list and §28 is about: two projects that are *not*
/// unrelated in style, because one generator wrote both.
#[test]
fn a_sibling_from_the_same_generator_is_not_mistaken_for_a_leak() {
    let project = protected_project("fp-sibling");
    let mut rows = Vec::new();
    let mut leads = 0usize;
    for variant in 1..=SIBLINGS {
        let (dir, files) = variant_candidate(variant);
        assert_readable(dir.path(), files, &format!("variant {variant}"));
        let v = project.scan(dir.path());
        if v.fragments > 0 {
            leads += 1;
        }
        let name = format!("variant {variant}");
        assert_examined(&name, &v, files);
        assert_not_accused(&name, &v);
        rows.push(row(&format!("same generator variant {variant}"), v));
    }
    report(
        &format!("§27/§28 — {SIBLINGS} projects generated by the same templates, different keys"),
        &rows,
    );
    println!(
        "  {leads} of {SIBLINGS} siblings confirmed at least one shared idiom; a shared idiom is \
         not a shared project, and the verdict says so"
    );
}

/// §27's "common constants" bullet, aimed straight at the fingerprint: the
/// lookalike fixture repeats the JavaScript fixture's constants and none of its
/// code, so a fingerprint match here would be a hash of round numbers rather
/// than of this project.
#[test]
fn shared_constants_do_not_reconstruct_a_fingerprint() {
    let project = protected_project("fp-constants");
    let dir = TempDir::new("fp-lookalike");
    let written = fixtures::lookalike_project(dir.path());
    assert_readable(dir.path(), written.len(), "lookalike");
    let v = project.scan(dir.path());
    assert_not_accused("the constant lookalike", &v);
    assert_examined("the constant lookalike", &v, written.len());
    assert_ne!(
        v.fingerprint, "match",
        "the fingerprint was reconstructed from shared constants alone:\n{}",
        v.run.out
    );
    report(
        "§27 — identical constants, different code",
        &[row("lookalike", v)],
    );
}
