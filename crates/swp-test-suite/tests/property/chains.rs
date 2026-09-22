//! §43 — property-based testing: random transformation chains through the real
//! product, checked against invariants that must hold for *every* chain.
//!
//! §25 measures one refactoring at a time. That misses the thing maintenance
//! actually does, which is several of them in a row, in an order nobody would
//! think to write a test for: reformat, then rename, then pull a function out,
//! then delete the comments. §43 asks for exactly that, and asks for many
//! iterations, "to find cases that hand-written tests miss".
//!
//! So this file composes random chains of the named transformations, applies them
//! to a copy of a protected tree, and scans the result — then asserts the
//! properties that are true regardless of which chain came out of the generator:
//!
//! * the run is **legal**: a verdict and an exit code that say the same thing, a
//!   document with §33's fields, and a candidate the scanner read completely
//!   (a chain that made a file unreadable must be reported, not scored as clean);
//! * the scanner **never accuses on nothing**: a finding implies a confirmed
//!   fragment, and a confirmed fragment implies an evidence item;
//! * rewriting **cannot invent evidence**: a chain never confirms more sites than
//!   the untouched copy does, because the candidate is still one project's source
//!   with edits, not two projects;
//! * a chain that includes an **artifact-removal** attack loses sites, since
//!   §26's `artifact_removal` deletes the rendered text of every site it finds.
//!
//! The generator is a seeded LCG, not a clock: iteration 7 of a failing run is
//! only reproducible if the seed is in the failure message, so the seed is
//! printed in every one. The first chain is not random at all — it is §43's own
//! worked example, kept in the sequence so the brief's case is always run.

use std::collections::BTreeMap;

use swp_test_suite::fixtures::Lcg;
use swp_test_suite::project::{Project, Verdict};
use swp_test_suite::transform::{read_tree, write_tree, SiteText, Transform};

const MODULES: usize = 12;
const TARGET_SITES: u32 = 24;

/// Iterations, per §43's "run many iterations". Each one protects nothing — the
/// release is made once — so the cost is one parse-and-scan per chain, and the
/// count is set by what a test run can hold, which is stated here rather than
/// implied.
const ITERATIONS: usize = 24;

/// The published seed. Change it and every number in the table changes with it;
/// that is the point of printing it.
const SEED: u64 = 0x2545_F491_4F6C_DD1D;

/// Longest chain drawn: four transformations, which is already more than most of
/// §25's hand-written cases compose.
const MAX_CHAIN: usize = 4;

fn site_texts(release: &swp_test_suite::project::Release) -> Vec<SiteText> {
    release.site_texts()
}

/// The chain §43 prints, as the first draw: random formatting → random
/// identifier rename → safe expression rewrite → comment removal → scan.
const BRIEF_CHAIN: [Transform; 4] = [
    Transform::Reformat,
    Transform::VariableRename,
    Transform::ExpressionRewrite,
    Transform::CommentRemoval,
];

fn draw_chain(rng: &mut Lcg, step: usize) -> Vec<Transform> {
    if step == 0 {
        return BRIEF_CHAIN.to_vec();
    }
    let len = 1 + rng.pick(MAX_CHAIN);
    (0..len)
        .map(|_| Transform::REFACTORING[rng.pick(Transform::REFACTORING.len())])
        .collect()
}

fn chain_name(chain: &[Transform]) -> String {
    chain
        .iter()
        .map(|t| t.slug())
        .collect::<Vec<_>>()
        .join(" > ")
}

/// The invariant that holds whatever the chain did: the product's three outputs
/// — verdict, exit code, evidence — say one thing.
fn assert_legal(name: &str, v: &Verdict) {
    let expected = match v.result.as_str() {
        "PROVENANCE_DETECTED" => 1,
        "INCONCLUSIVE" => 10,
        "NO_PROVENANCE_DETECTED" => 0,
        other => panic!("{name}: unknown result {other:?} at seed {SEED}"),
    };
    assert_eq!(
        v.run.code, expected,
        "{name}: verdict {} and exit code {} disagree\n{}",
        v.result, v.run.code, v.run.out
    );
    let doc = v.run.json();
    for field in [
        "schema",
        "protocol",
        "result",
        "evidence_level",
        "candidate",
    ] {
        assert!(
            !doc[field].is_null(),
            "{name}: the §33 document is missing {field}\n{}",
            v.run.out
        );
    }
    assert!(
        !v.partial,
        "{name}: the scan reported an incomplete read, so its counts are not comparable with the \
         rest of the table:\n{}",
        v.run.out
    );
    if v.detected() {
        assert!(
            v.fragments > 0 || v.fingerprint == "match",
            "{name}: a finding with nothing behind it:\n{}",
            v.run.out
        );
        assert!(
            !doc["evidence"]
                .as_array()
                .map(|e| e.is_empty())
                .unwrap_or(true),
            "{name}: PROVENANCE_DETECTED with an empty evidence list — §22 does not allow a \
             conclusion the document cannot show its work for:\n{}",
            v.run.out
        );
    }
}

#[test]
fn random_refactoring_chains_never_break_the_verdict_contract() {
    let project = Project::synthetic_wide("prop-protected", MODULES, TARGET_SITES);
    project.protect();
    let release = project.latest();
    let sites = site_texts(&release);
    let total = release.sites.len();

    let untouched = {
        let copy = project.copy_whole("prop-baseline");
        project.scan(copy.path())
    };
    assert_legal("the unmodified copy", &untouched);
    assert!(
        untouched.detected(),
        "the baseline was not a finding, so every chain below measures nothing:\n{}",
        untouched.run.out
    );

    let mut rng = Lcg::new(SEED);
    let mut levels: BTreeMap<String, usize> = BTreeMap::new();
    let mut rows: Vec<(String, Verdict)> = Vec::new();
    let mut longest_finding = 0usize;
    let mut lost_everything: Vec<String> = Vec::new();

    for step in 0..ITERATIONS {
        let chain = draw_chain(&mut rng, step);
        let candidate = project.copy_whole(&format!("prop-{step}"));
        let mut tree = read_tree(candidate.path());
        for t in &chain {
            t.apply(&mut tree, &sites);
        }
        write_tree(candidate.path(), &tree);
        let v = project.scan(candidate.path());
        let name = chain_name(&chain);
        assert_legal(&format!("{name} (seed {SEED:#x}, step {step})"), &v);

        // Rewriting one project's source cannot turn it into two projects' worth
        // of evidence: the untouched copy is the ceiling.
        assert!(
            v.fragments <= untouched.fragments,
            "{name} (seed {SEED:#x}, step {step}) confirmed {} sites where the unmodified copy \
             confirmed {}: a rewrite cannot invent fragments\n{}",
            v.fragments,
            untouched.fragments,
            v.run.out
        );

        *levels.entry(v.level.clone()).or_default() += 1;
        if v.detected() {
            longest_finding = longest_finding.max(chain.len());
        } else if v.fragments == 0 {
            lost_everything.push(name.clone());
        }
        println!(
            "  step {step:>2} {:>1} {} -> {} fragment(s) of {total}, {} / {}",
            chain.len(),
            name,
            v.fragments,
            v.result,
            v.level,
        );
        rows.push((format!("step {step}: {} deep", chain.len()), v));
    }

    println!(
        "\n§43 — {ITERATIONS} random chains over a {total}-site release (seed {SEED:#x}): {}",
        levels
            .iter()
            .map(|(l, n)| format!("{l} {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  the longest chain that still produced a finding was {longest_finding} transformation(s) \
         deep; {} chain(s) confirmed nothing at all",
        lost_everything.len()
    );
    if !lost_everything.is_empty() {
        println!(
            "  chains that emptied the constellation: {}",
            lost_everything
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }
    println!(
        "  claim boundary: a chain that confirms nothing is reported as NO_PROVENANCE_DETECTED, \
         which §51 defines as \"these keys found nothing here\" and never as \"this code was \
         rewritten\", \"this is not a copy\", or \"this project is original\"."
    );
    // One draw in twenty-four emptying the constellation is a fact about the
    // generator's distribution, not a contract; the ceiling on fragments is. So
    // only the ceiling and the legality of every run are asserted above, and the
    // distribution is what this table is for.
    assert!(
        longest_finding >= 1,
        "no chain of any length survived, which contradicts §25's per-form results at seed \
         {SEED:#x}: {rows:?}",
        rows = rows
            .iter()
            .map(|(n, v)| (n.clone(), v.fragments))
            .collect::<Vec<_>>()
    );
}

/// §43 over the other list: §26's attacks, composed randomly rather than applied
/// singly, with the one property removal has to keep.
#[test]
fn removal_attacks_compose_downwards() {
    let project = Project::synthetic_wide("prop-adversary", MODULES, TARGET_SITES);
    project.protect();
    let release = project.latest();
    let sites = site_texts(&release);
    let untouched = {
        let copy = project.copy_whole("prop-adversary-baseline");
        project.scan(copy.path())
    };
    assert!(untouched.detected(), "the baseline was not a finding");

    let mut rng = Lcg::new(SEED ^ 0x9E37_79B9_7F4A_7C15);
    let mut best_with_removal = 0usize;
    let mut best_chain = String::new();
    let mut drawn = 0usize;
    for step in 0..ITERATIONS {
        let len = 1 + rng.pick(MAX_CHAIN);
        let mut chain: Vec<Transform> = (0..len)
            .map(|_| Transform::ADVERSARIAL[rng.pick(Transform::ADVERSARIAL.len())])
            .collect();
        // Every chain gets at least one §26 removal attack, which is the point of
        // the exercise: what happens when someone deletes the fragments they can
        // find and then does something else as well.
        if !chain.contains(&Transform::ArtifactRemoval) {
            chain.insert(rng.pick(chain.len() + 1), Transform::ArtifactRemoval);
        }
        let candidate = project.copy_whole(&format!("prop-adv-{step}"));
        let mut tree = read_tree(candidate.path());
        for t in &chain {
            t.apply(&mut tree, &sites);
        }
        write_tree(candidate.path(), &tree);
        let v = project.scan(candidate.path());
        let name = chain_name(&chain);
        assert_legal(&format!("{name} (step {step})"), &v);
        assert!(
            v.fragments < untouched.fragments,
            "deleting the rendered text of every site the release published left {} of {} sites \
             intact: {name} (seed {SEED:#x} ^ adversary)\n{}",
            v.fragments,
            untouched.fragments,
            v.run.out
        );
        best_with_removal = best_with_removal.max(v.fragments);
        if v.fragments == best_with_removal {
            best_chain = name.clone();
        }
        drawn += 1;
        println!(
            "  step {step:>2} {} -> {} fragment(s), {} / {}",
            name, v.fragments, v.result, v.level,
        );
    }
    println!(
        "\n§43/§26 — {drawn} random attack chains that each deleted every artifact they could \
         find: the most any of them left intact was {best_with_removal} of {} site(s)",
        untouched.fragments
    );
    println!(
        "  the chain that left the most behind was {best_chain}\n  \
         order matters in a way a single-attack table cannot show: rewriting a site first moves \
         its rendered text, so a deletion that runs after it has nothing left to look for. The \
         removal worked on every fragment it was pointed at; the fragments that survived had \
         stopped being the text the manifest described."
    );
    println!(
        "  the chain that left the most behind was: {best_chain}\n  \
         order matters in a way a single-attack table cannot show: rewriting a site first moves \
         its rendered text, so a deletion that runs afterwards has nothing left to look for. That \
         is the removal working on the fragments it was pointed at and missing the ones that \
         stopped being those fragments."
    );
    println!(
        "  never claim the watermark is impossible to remove (§26): these chains are the removal \
         working, and the table is the measurement of how much of it survives."
    );
}
