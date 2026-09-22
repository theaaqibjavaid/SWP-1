//! §57 — the final acceptance scenario, end to end, establishing its own results.
//!
//! Three independent projects and six scans of them, run through `swp` exactly the
//! way an operator runs it: no in-process calls, no fixture that already knows the
//! answer. §57's closing rule is the one that shapes this file — *do not hard-code
//! these expected results into the detector, the tests must independently establish
//! them* — so nothing here compares a verdict against a literal level chosen in
//! advance. What it compares a verdict against is the **other projects' keys** and
//! the **store's own records**: the identity a scan names has to be the identity
//! `swp generate` wrote, the count it reports cannot exceed what `swp protect`
//! embedded, and a candidate holding none of that project's code must not be
//! attributed to it.
//!
//! Seven rows, in §57's order:
//!
//! | row | established by |
//! |---|---|
//! | A → detected as A | the scan's `project_id` equals A's, and A's equals neither B's nor C's |
//! | B → detected as B | same, against B's id, and B is Python while A is JavaScript |
//! | C → not falsely identified as A/B | `fragments == 0`, no exact fingerprint, and the exit code matches the verdict |
//! | A-copy → provenance detected | the verdict is a detection, at whatever level the numbers give |
//! | A-refactored → evidence evaluated | counts reconcile and the report explains the level it chose |
//! | A-partial → partial evidence | strictly fewer confirmations than the whole copy, more than none |
//! | A-watermark-damaged → remaining evidence | the tag channel is gone and what survives is still reported |
//!
//! The two cross-checks nobody asked for and the protocol needs: A's keys over B's
//! copy and B's keys over A's copy, both of which must come back empty. A
//! detector that fires on somebody else's watermark is not a provenance tool.

use std::collections::BTreeMap;
use std::path::Path;

use swp_test_suite::fixtures;
use swp_test_suite::project::{Candidate, Project, Verdict};
use swp_test_suite::transform::{read_tree, write_tree, Transform};
use swp_test_suite::TempDir;

/// Enough sites that "half of them damaged" and "a quarter of the files" are
/// different questions, small enough that the whole scenario runs in seconds.
const TARGET_SITES: u32 = 24;

/// The refactoring a maintainer would actually commit before noticing anything:
/// names, layout, comments, and one file moved. Every one of §25's thirteen at
/// once is `tests/adversarial`; this is the ordinary case.
const REFACTORING: [Transform; 5] = [
    Transform::VariableRename,
    Transform::FunctionRename,
    Transform::Reformat,
    Transform::CommentRemoval,
    Transform::FileMovement,
];

fn config() -> String {
    format!(
        "[protect]\ntargets = [\"src\"]\ntarget_sites = {TARGET_SITES}\ntag_bits = 4\n\
         embed_strings = true\n"
    )
}

/// Files the product's parser would not accept, so a "refactored" candidate that
/// is really a broken candidate cannot be scored as if the watermark survived it.
fn unparseable(root: &Path) -> Vec<String> {
    let registry = swp_adapters::Registry::standard();
    let limits = swp_core::limits::Limits::default();
    read_tree(root)
        .iter()
        .filter_map(
            |(rel, body)| match registry.analyze(Path::new(rel), body, &limits) {
                Ok(analysis) if analysis.parse_errors > 0 => Some(rel.clone()),
                Err(_) => Some(rel.clone()),
                _ => None,
            },
        )
        .collect()
}

/// §57's honesty rule, applied to every row: the exit code, the verdict string and
/// the fragment count have to be three ways of saying one thing.
fn assert_coherent(name: &str, v: &Verdict) {
    let expected = match v.result.as_str() {
        "PROVENANCE_DETECTED" => 1,
        "INCONCLUSIVE" => 10,
        "NO_PROVENANCE_DETECTED" => 0,
        other => panic!("{name}: result {other:?} is not one of the three verdicts"),
    };
    assert_eq!(
        v.run.code, expected,
        "{name}: verdict {} with exit code {}\n{}",
        v.result, v.run.code, v.run.out
    );
    assert!(
        !(v.detected() && v.fragments == 0 && v.fingerprint != "match"),
        "{name}: a finding stated with no confirmed site and no exact fingerprint — §51's \
         forbidden sentence"
    );
}

/// Edit a candidate in place, and refuse to score it if the edit broke the code.
fn edit(candidate: &Candidate, apply: impl FnOnce(&mut BTreeMap<String, String>)) {
    let mut tree = read_tree(candidate.path());
    apply(&mut tree);
    write_tree(candidate.path(), &tree);
    let broken = unparseable(candidate.path());
    assert!(
        broken.is_empty(),
        "the edit left {} behind — a broken candidate measures the fallback parser, not the \
         watermark",
        broken.join(", ")
    );
}

#[test]
fn the_acceptance_scenario_establishes_its_own_results() {
    // ---- the three projects -------------------------------------------------
    let a = Project::fixture("accept-a", "javascript");
    let b = Project::fixture("accept-b", "python");
    a.set_config(&config());
    b.set_config(&config());

    let a_release = a.protect();
    let b_release = b.protect();
    assert!(
        a_release.sites_embedded > 0 && b_release.sites_embedded > 0,
        "A embedded {} and B {} — with no watermark in either tree the whole scenario is a \
         measurement of nothing",
        a_release.sites_embedded,
        b_release.sites_embedded
    );
    let a_total = a_release.sites_embedded as usize;
    let a_sites = a_release.site_texts();

    // `swp verify` on each project's own tree: the tool's claim about its own work.
    for (name, project) in [("A", &a), ("B", &b)] {
        let v = project.verify();
        assert_eq!(
            v.code, 0,
            "{name} does not verify its own protected tree:\n{}{}",
            v.out, v.err
        );
    }

    // C: unrelated on purpose, and sharing the *shapes* a watermark collides with.
    let c_dir = TempDir::new("accept-c").sensitive();
    fixtures::lookalike_project(c_dir.path());

    // ---- the six candidates -------------------------------------------------
    let a_copy = a.copy_whole("accept-a-copy");
    let b_copy = b.copy_whole("accept-b-copy");
    let a_refactored = a.copy_whole("accept-a-refactored");
    edit(&a_refactored, |tree| {
        for t in REFACTORING {
            t.apply(tree, &a_sites);
        }
    });
    let a_partial = a.copy_fraction("accept-a-partial", 1, 2);
    // Half the fragments rewritten into a spelling that computes the same numbers
    // and carries the same *value* in neither sense: the code is untouched, the
    // tag is not. `ConstantNormalization` is the wrong tool to reach for here and
    // the measurement says why — it canonicalises a literal, and an `Add` site is
    // not a literal, it is a sum, so on this tree it damaged one site in three and
    // left the group intact and still decodable.
    let a_damaged = a.copy_whole("accept-a-damaged");
    let damaged_sites: Vec<_> = a_sites.iter().step_by(2).cloned().collect();
    edit(&a_damaged, |tree| {
        let n = Transform::SiteRewrite.apply(tree, &damaged_sites);
        assert!(n > 0, "the damage pass rewrote nothing");
    });

    // ---- the rows -----------------------------------------------------------
    let mut rows: Vec<(&str, Verdict)> = Vec::new();
    let mut note = |label: &'static str, v: Verdict| {
        assert_coherent(label, &v);
        rows.push((label, v));
    };

    note("A → A", a.scan(a_copy.path()));
    note("B → B", b.scan(b_copy.path()));
    note("C ↛ A", a.scan(c_dir.path()));
    note("C ↛ B", b.scan(c_dir.path()));
    note("A-copy", a.scan(a_copy.path()));
    note("A-refactored", a.scan(a_refactored.path()));
    note("A-partial", a.scan(a_partial.path()));
    note("A-damaged", a.scan(a_damaged.path()));
    // The cross-checks: each project's keys over the other project's copy.
    note("A's keys ↛ B", b.scan(a_copy.path()));
    note("B's keys ↛ A", a.scan(b_copy.path()));

    println!(
        "\n§57 acceptance — A is {} JavaScript file(s) with {} site(s), B is {} Python file(s) \
         with {}, C is {} file(s) of unrelated code that shares their shapes.",
        a.sources().len(),
        a_total,
        b.sources().len(),
        b_release.sites_embedded,
        read_tree(c_dir.path()).len(),
    );
    println!(
        "  {:<16} {:>9} {:>7} {:>10} {:>13}  whose keys ran",
        "row", "confirmed", "probes", "fingerprint", "verdict"
    );
    for (label, v) in &rows {
        println!(
            "  {label:<16} {:>9} {:>7} {:>10} {:>13}  {}{}",
            v.fragments,
            v.probes,
            v.fingerprint,
            format!("{}/{}", v.result, v.level),
            v.project_id,
            if v.partial { " (partial)" } else { "" }
        );
    }
    println!(
        "  the last column is the store the scan ran from, not a claim about the \
         candidate: a scan only ever holds one project's keys, so what identifies a \
         candidate is the confirmed count beside it and the two cross-checks below."
    );

    // Rows are pushed in a fixed order, so they are read by position: a lookup by
    // label would have to be a string that matches a string, and this file's
    // assertions are worth more than a typo can survive.
    let (a_row, b_row, c_on_a, c_on_b, copy_row, refactored_row, partial_row, damaged_row) =
        (0usize, 1, 2, 3, 4, 5, 6, 7);
    let (a_keys_on_b, b_keys_on_a) = (8usize, 9);
    let of = |i: usize| {
        rows.get(i)
            .unwrap_or_else(|| panic!("row {i} of {}", rows.len()))
            .1
            .clone()
    };
    let a_id = a.project_id();
    let b_id = b.project_id();
    assert_ne!(a_id, b_id, "two projects generated the same identity");

    // ---- A and B are detected, and by their own keys -------------------------
    for (i, id) in [(a_row, &a_id), (b_row, &b_id)] {
        let v = of(i);
        let label = rows[i].0;
        assert!(v.detected(), "{label} was not detected:\n{}", v.run.out);
        assert_eq!(
            &v.project_id, id,
            "{label}: the scan ran on {id}'s keys and the report names {}",
            v.project_id
        );
        assert_eq!(
            v.fingerprint, "match",
            "{label} lost the exact-copy fingerprint"
        );
    }

    // ---- C is not falsely identified ----------------------------------------
    for i in [c_on_a, c_on_b] {
        let v = of(i);
        let label = rows[i].0;
        assert_eq!(
            v.fragments, 0,
            "{label}: an unrelated tree confirmed {} of this release's site(s) — §27's \
             false-positive gate belongs to this scenario too\n{}",
            v.fragments, v.run.out
        );
        assert!(
            !v.detected(),
            "{label}: a finding against a candidate holding none of this project's code"
        );
        assert_ne!(
            v.fingerprint, "match",
            "{label} matched the release fingerprint"
        );
    }
    // And the cross-checks, which is where a keyed detector would fail if the key
    // were not doing its job: B's code holds A's *nothing*, and vice versa.
    for i in [a_keys_on_b, b_keys_on_a] {
        let v = of(i);
        assert_eq!(
            v.fragments, 0,
            "{}: one project's keys confirmed {} site(s) in the other project's tree",
            rows[i].0, v.fragments
        );
        assert!(
            !v.detected(),
            "{}: a project was accused of its neighbour's watermark\n{}",
            rows[i].0,
            v.run.out
        );
    }

    // ---- the four A variants -------------------------------------------------
    let copy = of(copy_row);
    assert!(
        copy.detected(),
        "a whole copy was not a finding:\n{}",
        copy.run.out
    );
    assert_eq!(
        copy.fragments, a_total,
        "the whole copy confirmed {} of {a_total} site(s)",
        copy.fragments
    );

    let refactored = of(refactored_row);
    // §57 asks that the evidence be *evaluated*, which is testable: the counts
    // reconcile, and the report states a reason for the tier it picked. How much
    // of the constellation a rename and a reflow cost is printed above, not
    // demanded here.
    assert!(
        refactored.fragments <= copy.fragments,
        "a refactoring confirmed {} sites when the untouched copy confirmed {}",
        refactored.fragments,
        copy.fragments
    );
    assert!(
        refactored.probes > 0,
        "the refactored tree produced no comparison at all, so it was never evaluated:\n{}",
        refactored.run.out
    );
    let reasons = refactored.run.json()["releases"][0]["reasons"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !reasons.is_empty(),
        "the refactored verdict carries no explanation, which §28 forbids for every tier"
    );

    let partial = of(partial_row);
    assert!(
        partial.fragments < copy.fragments,
        "half the files confirmed all {} site(s), so the fraction copied is not what was \
         measured",
        copy.fragments
    );
    assert!(
        partial.fragments > 0,
        "a candidate holding half of a {}-site release confirmed nothing:\n{}",
        a_total,
        partial.run.out
    );
    assert!(
        partial.files < copy.files,
        "half of A's files reported confirmations in all {} of them",
        copy.files
    );

    let damaged = of(damaged_row);
    assert!(
        damaged.fragments < copy.fragments,
        "rewriting half the fragments left all {} of them still decoding, so this row is not \
         measuring damage",
        damaged.fragments
    );
    println!(
        "  what is left after the damage: {} of {a_total} fragment(s), {} exact rendering(s), \
         {} canonical-only, {} moved, {} stripped, across {} file(s) — verdict {}/{}. §51's \
         rule binds the sentence beside it, not just the number: a rewrite that removed every \
         protected literal and a reimplementation from memory leave the same artifact, and \
         neither is evidence of absence.",
        damaged.fragments,
        damaged.exact,
        damaged.canonical_only,
        damaged.moved,
        damaged.stripped,
        damaged.files,
        damaged.result,
        damaged.level,
    );
    assert!(
        copy.exact == a_total,
        "the untouched copy reports {} exact rendering(s) of {a_total} site(s), so the \
         manifest's `rendered` text is not what the writer wrote",
        copy.exact
    );
}
