//! §52 — behave as an attacker, and write down what actually happened.
//!
//! The brief's list is seven attempts: *find watermark locations, remove them,
//! rewrite them, restructure the source, preserve behavior while changing syntax,
//! copy only core algorithms, combine fragments from projects*. Each is a test
//! here, driven through `swp` the way an operator runs it, and each prints the
//! numbers a document can quote. §26's four removal attacks are measured in
//! `tests/detection/matrix.rs` and are **not** repeated: what §52 asks that §26
//! does not is what an attacker can do **without** the private manifest, and what
//! they can do with something better than it.
//!
//! Like the other measurement suites this one asserts invariants, not outcomes:
//!
//! * a scan that confirmed nothing never prints a finding, whatever the attack;
//! * an attack that changed no file measured nothing, and fails loudly rather than
//!   printing a survival rate;
//! * a mutation that leaves broken source is not an attack, it is a fallback-parser
//!   measurement, so every row checks the candidate still analyzes cleanly;
//! * a verdict has to be supported by the numbers printed beside it, and a number
//!   this suite dislikes is recorded rather than corrected.
//!
//! What it does not do is pretend the watermark is hard to remove. §26's rule —
//! never claim that — binds hardest here, because two of these attacks beat it
//! outright and are printed as beating it. The finding is what each victory costs
//! the attacker, and what the report still says afterwards.

use std::collections::BTreeMap;
use std::path::Path;

use swp_test_suite::fixtures;
use swp_test_suite::locate::{self, Shape};
use swp_test_suite::project::{Project, Release, Verdict};
use swp_test_suite::transform::{read_tree, write_tree};
use swp_test_suite::TempDir;

/// The same tree shape and constellation §24, §25 and §26 measure, so a site lost
/// in this table and a site lost in those mean the same twenty-four sites.
const MODULES: usize = 12;
const TARGET_SITES: u32 = 24;

fn protected(label: &str) -> (Project, Release) {
    let project = Project::synthetic_wide(label, MODULES, TARGET_SITES);
    let release = project.protect();
    (project, release)
}

/// One line of every table here.
fn numbers(v: &Verdict, total: usize) -> String {
    format!(
        "{:>3} of {:>3} confirmed {:>6} probes bound {:>6.3} guarantee {:>6.3} {} / {}",
        v.fragments,
        total,
        v.probes,
        v.chance,
        v.guarantee,
        v.result,
        v.level,
    )
}

fn header(title: &str, total: usize) {
    println!("\n{title}");
    println!(
        "  {:<34} confirmed of {total}, then probes, the coincidence bound, what clears it, \
         and the verdict",
        "attack"
    );
}

fn measurement(name: &str, v: &Verdict, total: usize) {
    println!("  {:<34} {}", name, numbers(v, total));
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

/// Files the product's own parser would not accept — including the ones it refuses
/// outright, which are the loudest form of broken.
fn broken_files(root: &Path) -> Vec<String> {
    let registry = swp_adapters::Registry::standard();
    let limits = swp_core::limits::Limits::default();
    read_tree(root)
        .iter()
        .filter_map(|(rel, body)| match registry.analyze(Path::new(rel), body, &limits) {
            Ok(analysis) if analysis.parse_errors > 0 => {
                Some(format!("{rel} ({} error(s))", analysis.parse_errors))
            }
            Ok(_) => None,
            Err(e) => Some(format!("{rel} (refused: {})", e.message())),
        })
        .collect()
}

fn assert_still_a_program(name: &str, root: &Path) {
    let broken = broken_files(root);
    assert!(
        broken.is_empty(),
        "{name} left unparseable source behind: {broken:?} — the row after it would measure \
         the lexical fallback on broken code, not the watermark"
    );
}

// --------------------------------------------------------------------------------------
// §52.1 and §52.2 — find the sites, then remove them, from the source alone
// --------------------------------------------------------------------------------------

/// The first two attempts are one attack, because the second depends on the first:
/// an adversary with no manifest has to *locate* before they can *delete*.
///
/// Locating is not the hard part, and this suite says so out loud. Every family the
/// writer uses has a spelling, and a search for those spellings took 36 of 36
/// fragments out of the form corpus while raising **no** flag across the 91
/// unrelated files of §27's corpora — `locate`'s own tests measure both halves, per
/// shape and per corpus. So no document may describe the watermark as hidden, and no
/// threat model may price removal at "the attacker would have to guess where to
/// look". What the search yields is *where*. It yields nothing about *whose*, and
/// that gap is the only concealment this protocol ever claimed.
#[test]
fn a_shape_search_finds_the_sites_and_folding_them_takes_the_finding_away() {
    let (project, release) = protected("adv-shape");
    let total = release.sites_embedded as usize;
    let candidate = project.copy_whole("adv-shape-copy");
    let plain = project.scan(candidate.path());
    assert_never_accuses_on_no_evidence("unmodified copy", &plain);
    assert!(
        plain.detected(),
        "the control copy was not found, so the row under it measures nothing:\n{}",
        plain.run.out
    );

    let mut tree = read_tree(candidate.path());
    let flags = locate::locate(&tree);
    let by_shape: BTreeMap<&str, usize> = flags.iter().fold(BTreeMap::new(), |mut m, f| {
        *m.entry(f.shape.slug()).or_default() += 1;
        m
    });
    assert!(!flags.is_empty(), "the search found nothing in a tree holding {total} sites");

    let changed = locate::normalize(&mut tree, &flags);
    assert!(
        changed > 0,
        "folding the located spans changed no file, so the row below measures an attack that \
         did not happen"
    );
    write_tree(candidate.path(), &tree);
    assert_still_a_program("shape folding", candidate.path());
    let folded = project.scan(candidate.path());
    assert_never_accuses_on_no_evidence("shape-folded copy", &folded);

    header(
        "§52.1/52.2 — locate from the source alone, then fold what was located",
        total,
    );
    println!(
        "  no manifest, no key, no knowledge of which literal was chosen: a search for the four \
         rendering shapes located {} span(s) in {changed} file(s).",
        flags.len()
    );
    for shape in Shape::ALL {
        println!(
            "  {:<34} {:>3}  {}",
            shape.slug(),
            by_shape.get(shape.slug()).copied().unwrap_or(0),
            shape.tells(),
        );
    }
    measurement("unmodified copy", &plain, total);
    measurement("every located span folded", &folded, total);
    println!(
        "  after the fold: {} exact rendering(s), {} confirmation(s) in a file we did not \
         protect, {} probe(s) still compared.",
        folded.exact, folded.moved, folded.probes
    );

    // The claim this row has to earn: folding what the shapes point at costs the
    // detector something. It is the reverse of the sentence §26 forbids — the
    // watermark is removable, and here is the removal, carried out by someone who
    // never saw a manifest.
    assert!(
        folded.fragments < plain.fragments,
        "folding every located span left {} of {} sites confirmed, so either the shape search \
         is not finding the fragments or the confirmations are not coming from them",
        folded.fragments,
        plain.fragments
    );
    assert!(
        folded.exact <= plain.exact,
        "the folded copy confirmed more byte-exact renderings ({}) than the untouched one ({})",
        folded.exact,
        plain.exact
    );
}

// --------------------------------------------------------------------------------------
// §52.3 — rewrite the sites, with something better than a manifest
// --------------------------------------------------------------------------------------

/// The third attempt does not need to find anything, because the attacker already
/// has the answer: **the source from before protection**.
///
/// `swp protect` is a reversible text transform over a tree the operator already
/// had. Anyone holding that earlier copy — a teammate's git history, the tarball
/// that went to a customer last quarter, a laptop imaged before the release — can
/// take the watermark out by putting the files back, with no knowledge of the
/// format at all. This is the strongest thing the threat model has to admit about
/// itself: **protection is not a barrier against someone who has both versions**,
/// and a watermark is not a substitute for access control.
///
/// The ladder is the part worth reading. A full revert is unsurprising; a *share*
/// reverted is what a real leak looks like — the attacker restores the files they
/// had and leaves the ones they did not — and the question is how much of the
/// finding survives that, which is the same question §24 asks of a partial copy.
#[test]
fn the_previous_version_of_the_source_unwrites_the_watermark() {
    let (project, release) = protected("adv-revert");
    let total = release.sites_embedded as usize;

    // The unprotected tree, byte for byte: same generator, same variant, a store it
    // never uses. This is the copy sitting in the attacker's older checkout.
    let pristine = Project::synthetic_variant("adv-revert-pristine", MODULES, 0);
    let before = read_tree(pristine.root());

    let candidate = project.copy_whole("adv-revert-copy");
    let whole = read_tree(candidate.path());

    let mut tree = whole.clone();
    let mut differed = 0;
    for (rel, body) in tree.iter_mut() {
        if let Some(original) = before.get(rel) {
            if original != body {
                *body = original.clone();
                differed += 1;
            }
        }
    }
    assert!(
        differed > 0,
        "no file differed from its unprotected version, so there was no revert to measure"
    );
    write_tree(candidate.path(), &tree);
    assert_still_a_program("a full revert", candidate.path());
    let full = project.scan(candidate.path());
    assert_never_accuses_on_no_evidence("full revert", &full);

    let site_files = release.files();
    let mut rows = Vec::new();
    for (num, den, label) in [(1, 4, "one site file in four"), (1, 2, "half the site files")] {
        let mut tree = whole.clone();
        for (rel, body) in tree.iter_mut() {
            let index = site_files.iter().position(|f| f == rel);
            if index.is_some_and(|i| i % den < num) {
                if let Some(original) = before.get(rel) {
                    *body = original.clone();
                }
            }
        }
        write_tree(candidate.path(), &tree);
        assert_still_a_program(label, candidate.path());
        let v = project.scan(candidate.path());
        assert_never_accuses_on_no_evidence(label, &v);
        rows.push((label.to_string(), v));
    }
    // The full revert last, so the table reads as an escalating attack: more files
    // restored, less evidence left.
    rows.push(("every changed file reverted".to_string(), full.clone()));

    header(
        "§52.3 — put the files back the way they were before protect",
        total,
    );
    println!(
        "  {differed} of {} file(s) differ between the protected tree and the same tree before \
         protection, and copying them back is the whole of the attack. {} file(s) carry the \
         {total} site(s).",
        whole.len(),
        site_files.len(),
    );
    for (name, v) in &rows {
        measurement(name, v, total);
    }
    // Restoring every changed file is exactly the inverse of protection, so it
    // cannot leave a fragment behind — anything else would mean the writer changed
    // text the manifest does not name, which §11 forbids.
    assert_eq!(
        full.fragments, 0,
        "a byte-exact revert of every changed file still confirmed {} site(s):\n{}",
        full.fragments, full.run.out
    );
    // And the partial reverts have to sit between the two ends, or the ladder is
    // not measuring what it says it measures: an attacker who restores more of the
    // older checkout cannot destroy *less* evidence.
    for pair in rows.windows(2) {
        assert!(
            pair[1].1.fragments <= pair[0].1.fragments,
            "{} left {} site(s) standing, but the milder {} left {}, which is not a ladder",
            pair[1].0,
            pair[1].1.fragments,
            pair[0].0,
            pair[0].1.fragments
        );
    }
    println!(
        "  what a leak costs: {} of {total} sites after a quarter of the site files, {} after \
         half, {} after every changed file. §51's boundary applies to this table as much as to \
         any other: a revert proves the watermark was there, for whoever can prove they hold \
         the earlier copy.",
        rows[0].1.fragments,
        rows[1].1.fragments,
        full.fragments,
    );
}

// --------------------------------------------------------------------------------------
// §52.4 and §52.5 — restructure, and change the syntax without changing the code
// --------------------------------------------------------------------------------------

/// §25's thirteen forms one at a time is a resilience table. All of them at once,
/// and then inside a bundler's output, is §52's: an attacker who is not trying to
/// stay within a style guide, and who has a build pipeline to hide in.
///
/// * **Bundled.** Every module's contents wrapped in its own function expression —
///   the shape a real `dist/bundle.js` has. Nothing is deleted and no behaviour
///   changes; what changes is every site's *scope*, which is one of the four keyed
///   radii, and the file names, which are keyed at all only in the report hint.
///   This is the row that tests §10's claim that a site is found by structure.
/// * **Compound.** All thirteen §25 forms applied to one tree in sequence. §43 draws
///   random orders and may never hit this one; this is the order a maintainer would
///   read as a single diff, and it is the worst case the measurements can name.
///   Several of the thirteen are keyed on a literal spelling, so applying them in
///   one diff makes the later ones no-ops — measured and printed, not smoothed
///   over, because the row is about the evidence, not about the form count.
#[test]
fn a_bundled_and_compound_rebuild_of_the_tree_is_measured() {
    let (project, release) = protected("adv-restructure");
    let total = release.sites_embedded as usize;
    let sites = release.site_texts();
    let untouched = project.copy_whole("adv-restructure-control");
    let base = project.scan(untouched.path());
    assert_never_accuses_on_no_evidence("unmodified copy", &base);
    assert!(base.detected(), "the control was not found:\n{}", base.run.out);

    let mut rows = Vec::new();

    // ---- all thirteen, in one diff ------------------------------------------
    let compound = project.copy_whole("adv-compound");
    let whole = read_tree(compound.path());
    let mut tree = whole.clone();
    let mut idle: Vec<&str> = Vec::new();
    for transform in swp_test_suite::Transform::REFACTORING {
        if transform.apply(&mut tree, &sites) == 0 {
            idle.push(transform.slug());
        }
    }
    let differing = tree
        .iter()
        .filter(|(rel, body)| whole.get(*rel).is_some_and(|before| before != *body))
        .count();
    assert!(
        differing > 0,
        "the compound rebuild wrote back every file unchanged, so the row below measures nothing"
    );
    write_tree(compound.path(), &tree);
    assert_still_a_program("the compound rebuild", compound.path());
    let compound_v = project.scan(compound.path());
    assert_never_accuses_on_no_evidence("compound rebuild", &compound_v);
    rows.push(("all 13 §25 forms at once".to_string(), compound_v.clone()));

    // ---- bundled, inside the tree the scan reads ------------------------------
    let bundle = project.copy_whole("adv-bundled");
    let mut tree = read_tree(bundle.path());
    let modules = tree.keys().filter(|rel| rel.ends_with(".js")).count();
    let bundled = bundle_modules(&mut tree, "src");
    assert_eq!(bundled, modules, "a module was left out of the bundle");
    write_tree(bundle.path(), &tree);
    assert_still_a_program("bundling", bundle.path());
    let bundle_v = project.scan(bundle.path());
    assert_never_accuses_on_no_evidence("bundled tree", &bundle_v);
    rows.push(("bundled into src/bundle_N.js".to_string(), bundle_v.clone()));

    // ---- both, which is what a real build looks like ------------------------
    let both = project.copy_whole("adv-everything");
    let mut tree = read_tree(both.path());
    for transform in swp_test_suite::Transform::REFACTORING {
        transform.apply(&mut tree, &sites);
    }
    bundle_modules(&mut tree, "src");
    write_tree(both.path(), &tree);
    assert_still_a_program("the whole stack", both.path());
    let both_v = project.scan(both.path());
    assert_never_accuses_on_no_evidence("reformatted and bundled", &both_v);
    rows.push(("compound, then bundled".to_string(), both_v.clone()));

    // ---- bundled the way a build actually ships: into dist/ -----------------
    let shipped = project.copy_whole("adv-shipped");
    let mut tree = read_tree(shipped.path());
    bundle_modules(&mut tree, "dist");
    write_tree(shipped.path(), &tree);
    assert_still_a_program("a dist/ bundle", shipped.path());
    let shipped_v = project.scan(shipped.path());
    assert_never_accuses_on_no_evidence("bundled into dist/", &shipped_v);

    header(
        "§52.4/52.5 — restructure and rewrite the syntax, keeping the behaviour",
        total,
    );
    println!(
        "  the bundle keeps every statement and gives every one of them a new enclosing \
         function; the compound row applies all {} of §25's forms to one tree; the last does \
         both. File names change in all three, and no keyed address contains one.",
        swp_test_suite::Transform::REFACTORING.len()
    );
    measurement("unmodified copy", &base, total);
    for (name, v) in &rows {
        measurement(name, v, total);
    }
    println!(
        "  {differing} of {} file(s) changed in the compound diff; {} of §25's thirteen forms \
         found nothing left to do once an earlier form in the same diff had consumed the text \
         they look for ({}). Those forms are style-guide edits keyed on a spelling, so they \
         overlap by construction, and §25 measures each of them on its own; what this row \
         measures is the combined effect on the evidence, which is what §52 asks about.",
        whole.len(),
        idle.len(),
        if idle.is_empty() {
            "none".to_string()
        } else {
            idle.join(", ")
        }
    );
    for (name, v) in &rows {
        println!(
            "  {name:<28} exact {}, canonical-only {}, moved {}, files with a confirmation {}",
            v.exact, v.canonical_only, v.moved, v.files
        );
    }

    // Restructuring is not deleting. If a site's statement is still in the tree, the
    // rename-tolerant radii exist for exactly this (§15), and a wrapper function
    // cannot be allowed to be the thing that erases a whole constellation — that
    // would mean the address was keyed on the scope it happened to sit in, which
    // §10's structural claim rules out.
    for (name, v) in &rows {
        assert!(
            v.fragments > 0,
            "{name} lost all {total} sites, so the keyed address is bound to a shape a bundler \
             changes and §10's claim is false\n{}",
            v.run.out
        );
        assert!(
            v.fragments <= total,
            "{name} confirmed {} sites from a {total}-site release",
            v.fragments
        );
    }

    // The other way a bundle escapes: not by moving the code out of a scope, but
    // by moving it out of the scan. `dist/` is one of the default excludes (§45),
    // and a candidate that ships only build output is therefore never opened.
    // Nothing here pretends that is a detection success — it is a coverage limit,
    // and §51's rule is that a limit has to be *said*, which is what `partial` and
    // the "cannot distinguish" note in the report are for.
    println!(
        "\n  §52.4's other half: the same {bundled} module(s) bundled into a `dist/`, which a \
         default exclude removes from the walk. {} file(s) scanned, verdict {} / {}, partial \
         {}. The report says so rather than saying \"no watermark\": {}",
        shipped_v.files_scanned,
        shipped_v.result,
        shipped_v.level,
        shipped_v.partial,
        shipped_v
            .run
            .out
            .lines()
            .find(|l| l.contains("no source this protocol can read"))
            .map(str::trim)
            .unwrap_or("(the note is worded differently)")
    );
    assert_eq!(
        shipped_v.fragments, 0,
        "a build directory the walk excludes somehow confirmed a site"
    );
    assert!(
        shipped_v.partial,
        "the scan examined no file and did not mark the result partial, so the report \
         presents an unread candidate as a clean one:\n{}",
        shipped_v.run.out
    );
}

/// Wrap each module's text in its own function expression, under `dir`: the
/// restructure a bundler performs, and the one that changes every scope.
///
/// Modules only. A bundler's input is the reachable graph, not the `README.md`
/// beside it, and wrapping non-JavaScript in a function expression would produce
/// a candidate the product's parser refuses — which `assert_still_a_program`
/// exists to catch, and which would turn this row into a fallback-parser
/// measurement instead of a restructure one.
///
/// The caller names the output directory, because §52.4 has to be measured twice:
/// once with the bundle still inside the scanned tree, where the restructure is the
/// only thing that changed, and once in a `dist/`, where an ordinary exclude
/// swallows it before any site is looked at.
fn bundle_modules(tree: &mut std::collections::BTreeMap<String, String>, dir: &str) -> usize {
    let sources: Vec<String> = tree
        .keys()
        .filter(|rel| rel.ends_with(".js"))
        .cloned()
        .collect();
    for (i, rel) in sources.iter().enumerate() {
        let Some(body) = tree.remove(rel) else { continue };
        tree.insert(
            format!("{dir}/bundle_{i}.js"),
            format!("const module_{i} = (function () {{\n{body}\n}})();\n"),
        );
    }
    sources.len()
}

// --------------------------------------------------------------------------------------
// §52.6 — copy only the core algorithms
// --------------------------------------------------------------------------------------

/// The thief who does not want your project, only the part that works.
///
/// §24 slices the tree by *file*, which models a leak of a subset. A person lifting
/// an algorithm takes a **function** out of one file and drops it into a project of
/// their own — the smallest amount of copied code that is still worth copying, and
/// the case where a distributed watermark should be expected to say the least.
/// Nothing here is executed (§21 binds the scanner); the host tree is an unrelated
/// corpus the suites already carry, so the candidate is that corpus plus their
/// stolen function, and nothing else of this project.
///
/// Measured at three sizes on purpose: one function is one or two sites at best,
/// and the honest verdict for that is `INCONCLUSIVE` or a `WEAK` lead, not a
/// finding. Printing the smallest lift is how the documentation earns the right to
/// quote the largest one.
#[test]
fn lifted_functions_are_measured_at_three_sizes() {
    let (project, release) = protected("adv-lift");
    let total = release.sites_embedded as usize;
    let sites = release.site_texts();
    let tree = read_tree(project.root());

    // The functions that carry a fragment, named by where they came from.
    let mut carriers: Vec<(String, String)> = Vec::new();
    for (rel, body) in &tree {
        for (name, text) in functions(body) {
            if sites.iter().any(|s| &s.file == rel && text.contains(&s.rendered)) {
                carriers.push((format!("{rel}::{name}"), text));
            }
        }
    }
    assert!(
        !carriers.is_empty(),
        "no function in a protected tree holds a fragment, so this attack has nothing to lift"
    );
    carriers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rows = Vec::new();
    for (count, label) in [
        (1, "one lifted function"),
        (3, "three lifted functions"),
        (carriers.len(), "every function that holds one"),
    ] {
        let take = count.min(carriers.len());
        let host = TempDir::new(&format!("adv-lift-host-{take}"));
        fixtures::Corpus::Oss.write(host.path());
        fixtures::Corpus::Boilerplate.write(host.path());
        let mut lifted = read_tree(host.path());
        for (i, (from, text)) in carriers.iter().take(take).enumerate() {
            lifted.insert(format!("lifted/lift_{i}.js"), format!("// {from}\n{text}\n"));
        }
        let candidate = TempDir::new(&format!("adv-lift-candidate-{take}"));
        write_tree(candidate.path(), &lifted);
        assert_still_a_program("a lifted function", candidate.path());
        let v = project.scan(candidate.path());
        assert_never_accuses_on_no_evidence(label, &v);
        rows.push((label.to_string(), take, v));
    }

    header("§52.6 — lift the functions that work, into somebody else's project", total);
    println!(
        "  {} of the {} file(s) hold at least one of the {total} fragments, and {} function(s) \
         contain one; a candidate below is an unrelated corpus plus their text, copied whole. \
         No file of this project is in it.",
        release.files().len(),
        tree.len(),
        carriers.len(),
    );
    for (label, take, v) in &rows {
        measurement(&format!("{label} [{take}]"), v, total);
    }
    // Copying more of the evidence cannot confirm less of it, for the nested subsets
    // used here — the monotonicity §24's ladder requires of its own slices.
    for pair in rows.windows(2) {
        assert!(
            pair[1].2.fragments >= pair[0].2.fragments,
            "lifting {} functions confirmed {} sites, fewer than {} did ({}), so the ladder is \
             not nested or the scan is not deterministic",
            pair[1].1,
            pair[1].2.fragments,
            pair[0].1,
            pair[0].2.fragments
        );
    }
    assert!(
        rows.last().expect("three rows").2.fragments <= total,
        "a tree of lifted functions confirmed more sites than the release has"
    );
    let smallest = &rows[0].2;
    println!(
        "  the smallest lift is the row the documentation has to carry: {} site(s) confirmed by \
         a candidate that is one function of this project inside somebody else's, verdict \
         {} / {} — a lead to look at, graded on its own numbers, and not a claim of copying \
         (§51).",
        smallest.fragments, smallest.result, smallest.level
    );
}

/// Top-level `function name (…) { … }` blocks of a module, by brace depth.
fn functions(body: &str) -> Vec<(String, String)> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(found) = body[i..].find("function ") {
        let start = i + found;
        let head = &body[start + 9..];
        let Some(name_end) = head.find(|c: char| !(c.is_alphanumeric() || c == '_')) else {
            break;
        };
        let name = head[..name_end].to_string();
        let Some(open) = body[start..].find('{') else {
            break;
        };
        let mut j = start + open;
        let mut depth = 0i32;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if depth != 0 {
            break;
        }
        out.push((name, body[start..=j].to_string()));
        i = j + 1;
    }
    out
}

// --------------------------------------------------------------------------------------
// §52.7 — combine fragments from projects
// --------------------------------------------------------------------------------------

/// Two questions in one attack, both about a tree that is a copy of nothing:
/// fragments from two protected projects, planted into a third party's source.
///
/// * **Framing.** If A's private manifest leaks, anyone can paste A's rendered
///   fragments into an innocent tree. Does A's scanner then point at that tree? If
///   it does, the blast radius of a leaked manifest is bigger than "they can remove
///   my watermark" — it is "they can make my tool accuse a stranger" — and SECURITY
///   and THREAT-MODEL have to carry that sentence. Measured, not assumed away.
/// * **Attribution.** The same tree then holds A's fragments *and* B's. Each scanner
///   should see its own and none of the other's. If B's scanner confirms anything in
///   a tree planted only with A's text, keyed addresses name a fragment rather than
///   a project, and §28's collision numbers would be false.
#[test]
fn fragments_planted_from_two_projects_are_attributed_and_not_confused() {
    let (a, a_release) = protected("adv-plant-a");
    let (b, b_release) = protected("adv-plant-b");
    let a_sites = a_release.site_texts();
    let b_sites = b_release.site_texts();
    assert_ne!(
        a.project_id(),
        b.project_id(),
        "two projects generated independently share an identity"
    );

    // The innocent tree: neither project's source, both projects' fragments.
    let host = TempDir::new("adv-plant-host");
    fixtures::lookalike_project(host.path());
    let mut tree = read_tree(host.path());
    for (i, site) in a_sites.iter().enumerate() {
        tree.insert(
            format!("src/planted_a_{i}.js"),
            format!("const planted_a_{i} = {};\n", site.rendered),
        );
    }
    let only_a = TempDir::new("adv-plant-only-a");
    write_tree(only_a.path(), &tree);
    assert_still_a_program("planting A's fragments", only_a.path());

    let with_a = a.scan(only_a.path());
    assert_never_accuses_on_no_evidence("A scans the planted tree", &with_a);
    let with_b = b.scan(only_a.path());
    assert_never_accuses_on_no_evidence("B scans the planted tree", &with_b);

    for (i, site) in b_sites.iter().enumerate() {
        tree.insert(
            format!("src/planted_b_{i}.js"),
            format!("const planted_b_{i} = {};\n", site.rendered),
        );
    }
    let mixed = TempDir::new("adv-plant-mixed");
    write_tree(mixed.path(), &tree);
    assert_still_a_program("planting both projects", mixed.path());
    let mixed_a = a.scan(mixed.path());
    assert_never_accuses_on_no_evidence("A scans the mixed tree", &mixed_a);
    let mixed_b = b.scan(mixed.path());
    assert_never_accuses_on_no_evidence("B scans the mixed tree", &mixed_b);

    header(
        "§52.7 — A's fragments pasted into an unrelated tree, then A's and B's together",
        a_sites.len(),
    );
    println!(
        "  A wrote {} site(s) across {} file(s), B {} of its own. Neither candidate below holds \
         one line of either project's source — only the rendered fragments, as new statements \
         in new files, next to an unrelated project.",
        a_sites.len(),
        a_release.files().len(),
        b_sites.len(),
    );
    measurement("A's keys, A's fragments planted", &with_a, a_sites.len());
    measurement("B's keys, A's fragments planted", &with_b, b_sites.len());
    measurement("A's keys, both planted", &mixed_a, a_sites.len());
    measurement("B's keys, both planted", &mixed_b, b_sites.len());
    println!(
        "  mixed tree: A's report sees {} exact and {} moved of its own, B's sees {} exact and \
         {} moved of its; the two reports name {} and {} as their best match.",
        mixed_a.exact,
        mixed_a.moved,
        mixed_b.exact,
        mixed_b.moved,
        name(&mixed_a),
        name(&mixed_b)
    );

    // Attribution, the part that must hold: each scanner's best match is its own
    // release, and a tree planted only with A's text confirms none of B's sites.
    assert_eq!(
        mixed_a.project_id,
        a.project_id(),
        "A's scan of a tree holding A's planted fragments blamed someone else: {}",
        mixed_a.project_id
    );
    assert_eq!(
        mixed_b.project_id,
        b.project_id(),
        "B's scan of the same tree blamed someone else: {}",
        mixed_b.project_id
    );
    assert!(
        with_b.fragments == 0 || with_b.fingerprint != "match",
        "B confirmed {} site(s) of {} with a fingerprint {} in a tree planted only with A's \
         text, so a fragment tag carries an identity another project's key can read",
        with_b.fragments,
        b_sites.len(),
        with_b.fingerprint
    );
    // Pasting text cannot achieve more than copying the code it came from.
    assert!(
        with_a.fragments <= a_sites.len(),
        "planting {} fragment renderings confirmed {} of A's sites",
        a_sites.len(),
        with_a.fragments
    );
    println!(
        "  {}",
        if with_a.detected() {
            "A's scanner DID report a finding on a tree that is not A's code. A leaked manifest \
             is therefore a framing tool as well as a removal tool, and SECURITY.md and \
             THREAT-MODEL.md have to say so in those words."
        } else {
            "A's scanner reported no finding on the planted tree: the fragments alone are not a \
             constellation, and the coincidence bound is the sentence that says so. A leaked \
             manifest is a removal tool; this run did not show it to be a framing one."
        }
    );
}

/// The project a report named, or `nobody` when it named none.
fn name(v: &Verdict) -> String {
    if v.project_id.is_empty() {
        "nobody".to_string()
    } else {
        v.project_id.clone()
    }
}
