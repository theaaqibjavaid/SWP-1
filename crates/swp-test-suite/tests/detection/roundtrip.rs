//! §17's per-site promise, checked from the writer's side to the reader's.
//!
//! §17 says a site that was watermarked is a site that can be found, and it says
//! so *per site*, not per release: a release that confirms twenty of twenty-one
//! sites has broken the promise about the one it missed. The measurements in
//! `tests/detection/matrix.rs` ask a harder question (how much survives an attack)
//! and so tolerate a partial answer. This one tolerates none, because it asks the
//! easiest question in the suite: protect a tree, touch nothing, read it back.
//!
//! ## Why it is organized by family
//!
//! A watermark has no meaning apart from its spelling, and each family in
//! `swp-adapters`' two rendering tables spells the same code differently:
//! `( 995 + 5 )`, `0x3e8`, `"\x68\x65llo"`, `( "hel" + "lo" )`. The writer picks a
//! family per site from the keyed material, so no single run exercises all seven —
//! and a reader that can only find four of them passes four suites and fails one,
//! silently, on the day it matters.
//!
//! This suite therefore accumulates the family mix across several independent
//! projects — each with its own root key, so its own assignment — asserts that
//! every family the protocol can emit actually got written somewhere, and asserts
//! of each of those writings that the same release reads it back as
//! `exact-rendering`. The first assertion is what stops the second from passing
//! about a family it never tried.
//!
//! ## What this suite exists because of
//!
//! `str-escape` was written, signed, and then reported `absent` — in about half of
//! all runs on the shipped JavaScript example, which is the file a reader of the
//! documentation is most likely to protect first. Neither side was wrong on its
//! own terms: `swp-embedding` refuses to rewrite a literal containing a backslash
//! (so the escape family's output is not a *writable* site), and `swp-detection`'s
//! hypothesis pass assumed every lone literal was already offered by the scan pass
//! (so the escape family's output was not a *readable* site either). The gap was
//! precisely the space between two correct-looking assumptions, and only a
//! writer-to-reader test over all seven families could have found it. The fix is
//! in `swp-detection::spans::form_windows`; this file is what keeps the two sides
//! from drifting apart again without saying so.
//!
//! ## What it does not do
//!
//! It does not exercise a family the engine cannot reach in these trees. If a
//! future family appears and the coverage assertion below stays green, that is a
//! bug in *this* test, not a fact about the family — the expected set is read from
//! the adapter layer's own `NUMBER_FAMILIES` and `STRING_FAMILIES`, so a new
//! rendering is demanded here automatically.

use std::collections::{BTreeMap, BTreeSet};

use swp_adapters::{
    available_number_families, available_string_families, Dialect, StringForm, NUMBER_FAMILIES,
    STRING_FAMILIES,
};
use swp_core::site::FormFamily;
use swp_test_suite::project::Project;

/// The projects, and what each one is for.
///
/// The first four are the same form-corpus tree with four independent keys, which
/// is what makes the coverage assertion below a statement about the engine rather
/// than about luck: the writer's family choice is keyed, so four keys are four
/// independent draws over a tree built so that every draw can land anywhere. The
/// rest are the realistic example trees, at the shipped default configuration —
/// the invariant matters more there than the coverage, because a tree with two
/// string literals in it cannot be made to prove anything about seven families.
const PROJECTS: &[(&str, ProjectKind)] = &[
    ("forms-1", ProjectKind::Forms),
    ("forms-2", ProjectKind::Forms),
    ("forms-3", ProjectKind::Forms),
    ("forms-4", ProjectKind::Forms),
    ("gen-1", ProjectKind::Synthetic(0)),
    ("gen-2", ProjectKind::Synthetic(1)),
    ("example-js", ProjectKind::Fixture("javascript")),
    ("example-ts", ProjectKind::Fixture("typescript")),
    ("example-py", ProjectKind::Fixture("python")),
];

const TARGET_SITES: u32 = 24;
const MODULES: usize = 12;

/// The form corpus with a constellation wide enough to take most of it, at the
/// protocol's **default** four-bit width. Nothing here lowers `tag_bits` to make
/// a family reachable: reaching it at the width a real project ships at is the
/// point, and the difficulty of doing so is itself one of the measurements
/// (`docs/LANGUAGE-ADAPTERS.md` quotes it).
const FORMS_CONFIG: &str = "[protect]\ntargets = [\"src\"]\ntarget_sites = 48\ntag_bits = 4\n\
                            embed_strings = true\n";

#[derive(Clone, Copy)]
enum ProjectKind {
    /// The generated tree §24's ladder uses: number-heavy, realistic, wide.
    Synthetic(usize),
    /// `fixtures/forms`, built so every family is reachable.
    Forms,
    /// One of the hand-written examples, which is what an operator copies.
    Fixture(&'static str),
}

impl ProjectKind {
    fn build(self, label: &str) -> Project {
        match self {
            Self::Synthetic(variant) => {
                Project::synthetic_wide_variant(label, MODULES, TARGET_SITES, variant)
            }
            Self::Fixture(language) => Project::fixture(label, language),
            Self::Forms => {
                let project = Project::fixture(label, "forms");
                project.set_config(FORMS_CONFIG);
                project
            }
        }
    }
}

/// Why a project wrote what it wrote: the plan's own refusal tally and its
/// per-family counts, read back with `swp inspect plan`.
///
/// A missing family in the table is a question about reachability, and the
/// product already answers that question — §11 requires every location it
/// declined to be written down. So this suite reads the plan rather than
/// guessing at it, and prints the answer whether or not the run passed.
#[derive(Default)]
struct Plan {
    /// refusal reason → count
    refused: BTreeMap<String, usize>,
    /// family → sites planned
    families: BTreeMap<String, usize>,
    /// What the config asked for and what the ceilings allowed, which is the
    /// difference between a small constellation by choice and one by starvation.
    requested: u32,
    allowed: u32,
    notes: Vec<String>,
}

impl Plan {
    /// `asked 48 → 48 allowed`, the two numbers that say whether the run was
    /// limited by its config or by the tree.
    fn ceiling(&self) -> String {
        format!("asked {:>3} → {:>3}", self.requested, self.allowed)
    }
}

fn read_plan(project: &Project) -> Plan {
    let run = project.run(&["inspect", "plan", "--full", "--format", "json"]);
    assert_eq!(
        run.code, 0,
        "`swp inspect plan` failed on a release this suite just protected:\n{}",
        run.out
    );
    let envelope = run.json();
    assert_eq!(
        envelope["view"], "plan",
        "asked for the plan view and got {:?}\n{}",
        envelope["view"], run.out
    );
    // `swp inspect` puts the view's own document under `data`, so reading the
    // envelope's keys directly returns nothing at all — which is how this suite
    // first reported "nothing was refused" about a run that had refused most of
    // its tree. Assert the shape instead of tolerating an empty array.
    let doc = &envelope["data"];
    assert!(
        doc["sites"].is_array() && doc["skipped"].is_array(),
        "the plan document has no sites or skipped arrays: {doc}"
    );
    let mut plan = Plan::default();
    for s in doc["skipped"].as_array().unwrap() {
        *plan
            .refused
            .entry(s["reason"].as_str().unwrap_or("?").to_string())
            .or_insert(0) += 1;
    }
    for s in doc["sites"].as_array().unwrap() {
        *plan
            .families
            .entry(s["family"].as_str().unwrap_or("?").to_string())
            .or_insert(0) += 1;
    }
    for n in doc["notes"].as_array().unwrap_or(&Vec::new()) {
        if let Some(n) = n.as_str() {
            plan.notes.push(n.to_string());
        }
    }
    plan.requested = doc["requested_sites"].as_u64().unwrap_or(0) as u32;
    plan.allowed = doc["target_sites"].as_u64().unwrap_or(0) as u32;
    plan
}

/// One project, protected and read back with nothing touched.
struct RoundTrip {
    label: &'static str,
    /// family → how many sites the writer chose it for.
    families: BTreeMap<&'static str, usize>,
    /// `language/adapter` → the families written there, which is where the
    /// lexical fallback's smaller price shows up as a row rather than as a claim.
    adapters: BTreeMap<String, BTreeMap<&'static str, usize>>,
    plan: Plan,
    written: usize,
}

/// `swp protect` then `swp verify --full`, and every assertion that must hold
/// before the family table means anything.
fn round_trip(label: &'static str, project: &Project) -> RoundTrip {
    let release = project.protect();
    let run = project.run(&["verify", "--full", "--format", "json"]);
    let doc = run.json();

    // Read the tree's own numbers first, so a failure names the shape of the
    // problem rather than just the first symptom.
    let rows = doc["sites"]
        .as_array()
        .unwrap_or_else(|| panic!("{label}: verify printed no site rows:\n{}", run.out));
    assert_eq!(
        run.code, 0,
        "{label}: an untouched protected tree did not verify clean (exit {}):\n{}",
        run.code, run.out
    );
    assert_eq!(
        doc["verdict"], "INTACT",
        "{label}: verdict on a tree nothing was done to:\n{}",
        run.out
    );
    assert_eq!(
        rows.len() as u32,
        release.sites_embedded,
        "{label}: the release wrote {} site(s) and the read-back describes {}",
        release.sites_embedded,
        rows.len()
    );
    assert_eq!(
        doc["sites_confirmed"].as_u64(),
        doc["sites_expected"].as_u64(),
        "{label}: {} of {} site(s) confirmed on a tree that was never edited:\n{}",
        doc["sites_confirmed"],
        doc["sites_expected"],
        run.out
    );

    let mut families: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut adapters: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for row in rows {
        // Parsed through the product's own enum rather than compared as a string,
        // so a report label that drifted from `FormFamily::as_str` is a failure
        // here and not a table nobody can look up.
        let family = FormFamily::parse(row["family"].as_str().unwrap_or(""))
            .unwrap_or_else(|_| panic!("{label}: verify printed family {}", row["family"]))
            .as_str();
        let status = row["status"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: a site row has no status: {row}"));
        *families.entry(family).or_insert(0) += 1;
        let where_ = format!(
            "{}/{}",
            row["language"].as_str().unwrap_or("?"),
            row["adapter"].as_str().unwrap_or("?")
        );
        *adapters
            .entry(where_)
            .or_default()
            .entry(family)
            .or_insert(0) += 1;
        let at = format!(
            "{}:{}",
            row["file"].as_str().unwrap_or("?"),
            row["line_hint"]
        );
        // The one invariant this suite exists for, asserted per site rather than
        // per release, because §17 promises it per site.
        assert_eq!(
            status, "exact-rendering",
            "{label}: a {family} rendering at {at} came back {status} — the \
             `swp protect` output is not readable by `swp verify` on the same \
             bytes, which is §17 broken for that family.\n\
             A `{family}` rendering is looked for by `swp-detection`'s hypothesis \
             pass (`spans::form_windows`) whenever the scan pass cannot offer the \
             literal as a site; start there.\n\
             row: {row}"
        );
    }

    // The same claim in the document's own arithmetic, so a row that disagrees
    // with the summary cannot pass.
    assert_eq!(
        families.values().sum::<usize>(),
        doc["sites_exact"].as_u64().unwrap_or_default() as usize,
        "{label}: {families:?} vs {}",
        doc["sites_exact"]
    );
    RoundTrip {
        label,
        families,
        adapters,
        plan: read_plan(project),
        written: rows.len(),
    }
}

#[test]
fn every_family_the_writer_emits_the_reader_finds() {
    let mut trips = Vec::new();
    for (label, kind) in PROJECTS {
        let project = kind.build(label);
        trips.push(round_trip(label, &project));
    }

    let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_adapter: BTreeMap<&str, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for trip in &trips {
        for (family, count) in &trip.families {
            *seen.entry(*family).or_insert(0) += count;
        }
        for (where_, fams) in &trip.adapters {
            for (family, count) in fams {
                *by_adapter
                    .entry(where_.as_str())
                    .or_default()
                    .entry(*family)
                    .or_insert(0) += count;
            }
        }
    }

    println!("\n§17 round-trip — protect, touch nothing, read back");
    println!(
        "  {:<12} {:>7}  {:<19} families written (all read back exact-rendering)",
        "project", "sites", "plan ceiling"
    );
    for trip in &trips {
        let mix = trip
            .families
            .iter()
            .map(|(f, c)| format!("{f}:{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  {:<12} {:>7}  {}  {mix}",
            trip.label, trip.written, trip.plan.ceiling()
        );
    }
    println!(
        "  {:<12} {:>7}  {:<19} {}",
        "",
        trips.iter().map(|t| t.written).sum::<usize>(),
        "",
        seen.iter()
            .map(|(f, c)| format!("{f}:{c}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    println!("\n  by adapter and language, same data read the other way:");
    for (where_, fams) in &by_adapter {
        let mix = fams
            .iter()
            .map(|(f, c)| format!("{f}:{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let total: usize = fams.values().sum();
        println!("  {:<18} {:>4} site(s)  {mix}", where_, total);
    }

    // The refusals, aggregated: this is the section that says *why* a family is or
    // is not in the table above, in the product's own words.
    let mut refusals: BTreeMap<&str, usize> = BTreeMap::new();
    let mut notes: Vec<&String> = Vec::new();
    for trip in &trips {
        for (reason, count) in &trip.plan.refused {
            *refusals.entry(reason.as_str()).or_insert(0) += count;
        }
        notes.extend(trip.plan.notes.iter());
    }
    println!("\n  what §11 refused to touch, across every project:");
    if refusals.is_empty() {
        println!("    nothing was refused");
    }
    for (reason, count) in &refusals {
        println!("  {:>6}  {reason}", count);
    }
    let mut note_kinds: BTreeSet<&str> = BTreeSet::new();
    for n in &notes {
        note_kinds.insert(note_kind(n));
    }
    for n in note_kinds {
        println!("  note    {n}");
    }

    // The coverage assertion, off the renderer's own two tables so a new family is
    // required here the day it is possible at all. Without it, a suite that never
    // wrote `str-escape` would pass this file forever — which is exactly how the
    // defect described at the top of this module stayed alive.
    let missing: Vec<&'static str> = NUMBER_FAMILIES
        .iter()
        .chain(STRING_FAMILIES.iter())
        .map(|f| f.as_str())
        .filter(|f| !seen.contains_key(f))
        .collect();
    assert!(
        missing.is_empty(),
        "these families were never written by any project here, so nothing above says \
         the reader can find them: {missing:?}. Add trees that reach them rather than \
         lowering the assertion — a round-trip matrix that silently covers four of \
         seven families is the shape of the bug this file documents."
    );
    // The other direction, and the one that keeps the corpus honest: a tree built
    // so that every family is reachable has to *reach* most of them on a single
    // draw. If a `forms-*` project comes back narrow, either the corpus lost its
    // long literals or the renderer's reachability changed underneath it, and the
    // table printed above is then describing a different protocol than this file
    // claims to test.
    for trip in &trips {
        if !trip.label.starts_with("forms-") {
            continue;
        }
        assert!(
            trip.families.len() >= 5,
            "{} reached {} of 7 families ({}), from a corpus built so that all seven \
             are reachable — see the coverage note in this file's header",
            trip.label,
            trip.families.len(),
            trip.families.keys().copied().collect::<Vec<_>>().join(" ")
        );
    }
    // Realistic example trees are held to the invariant, not to the coverage, and
    // saying so out loud is itself a measurement: at the shipped default width a
    // string has to be longer than sixteen characters to carry a tag at all, which
    // is why `example-*` rows above are mostly arithmetic.
    for trip in trips.iter().filter(|t| t.label.starts_with("example-")) {
        println!(
            "  {} wrote {} site(s) at the default width: {}",
            trip.label,
            trip.written,
            trip.families.keys().copied().collect::<Vec<_>>().join(" ")
        );
    }
}

/// Plan notes name the file they are about; the table wants the kind of thing
/// said, not the same sentence once per file.
fn note_kind(note: &str) -> &str {
    match note.split_once(": ") {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => note,
    }
}

/// The literals `fixtures/forms` contains, as Rust copies of what is written in
/// those files.
///
/// Duplicated by hand rather than parsed out of the corpus on purpose: this list
/// is the *claim* about the corpus, and a claim derived from the files by the
/// same code that tests them proves nothing. `the_form_corpus_keeps_every_family_
/// reachable` fails if the two ever disagree, which is the point of writing the
/// literals twice.
const CORPUS_NUMBERS: &[i128] = &[
    720720, 1441440, 48879, 57005, 65535, 2400, 3600, 12, 90, 2,
];
/// `(text, quote)` for every string literal over sixteen characters in the
/// corpus, which is the width's modulus and therefore the shortest literal that
/// can carry a tag at all.
const CORPUS_STRINGS: &[(&str, char)] = &[
    ("starter plan, monthly renewal", '"'),
    ("credits per thousand requests", '"'),
    ("rates are reviewed every quarter", '"'),
    ("amount in account currency", '"'),
    ("support portal, business hours", '"'),
    ("community forum, best effort", '"'),
    ("escalation after sixteen hours", '"'),
    ("plan summary, billing and support", '"'),
    ("quota resets at the start of each cycle", '"'),
];

#[test]
fn the_form_corpus_keeps_every_family_reachable() {
    let width = swp_core::site::TagWidth::new(4).expect("4 bits is a protocol width");
    let dialects: [(&str, &Dialect); 3] =
        [("javascript", &Dialect::JS), ("typescript", &Dialect::TS), ("python", &Dialect::PY)];

    let mut reach: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for (language, dialect) in dialects {
        for value in CORPUS_NUMBERS {
            for family in available_number_families(*value, width, dialect) {
                reach
                    .entry(family.as_str())
                    .or_default()
                    .push(format!("{language}:{value}"));
            }
        }
        for (inner, quote) in CORPUS_STRINGS {
            let site = StringForm {
                inner,
                quote: *quote,
            };
            for family in available_string_families(&site, width, dialect) {
                reach
                    .entry(family.as_str())
                    .or_default()
                    .push(format!("{language}:{:?} ({} chars)", inner, inner.chars().count()));
            }
        }
    }

    println!("\ncorpus reachability — which literal lets which family be written at all");
    for family in NUMBER_FAMILIES.iter().chain(STRING_FAMILIES.iter()) {
        let where_ = reach.get(family.as_str());
        match where_ {
            Some(hits) => println!(
                "  {:<13} {} literal(s), first: {}",
                family.as_str(),
                hits.len(),
                hits[0]
            ),
            None => println!("  {:<13} unreachable in this corpus", family.as_str()),
        }
    }

    let missing: Vec<&'static str> = NUMBER_FAMILIES
        .iter()
        .chain(STRING_FAMILIES.iter())
        .map(|f| f.as_str())
        .filter(|f| !reach.contains_key(f))
        .collect();
    assert!(
        missing.is_empty(),
        "the corpus is supposed to make every family reachable, and these have no literal \
         that can carry them at the default four-bit width: {missing:?}. Either add one to \
         `fixtures/forms` and to the lists above, or say here why the family cannot be \
         reached by any literal."
    );
}

#[test]
fn a_standalone_protect_of_a_fixture_is_reproducible() {
    // The §57 acceptance scenario runs one protect of the JavaScript example and
    // quotes the result, so the example in `fixtures/` has to be a tree the whole
    // protocol can round-trip on its own — not only as part of the aggregate
    // above. This is the smallest honest version of "the documented example
    // works": one project, every site it wrote accounted for.
    let project = Project::fixture("example-solo", "javascript");
    let trip = round_trip("example-js (solo)", &project);
    assert!(
        trip.written >= 3,
        "the JavaScript example protected fewer than 3 sites, so this is measuring a \
         nearly-empty tree: {}",
        trip.written
    );
    let verdict = project.verify();
    assert_eq!(
        verdict.code,
        0,
        "`swp verify` on the documented example tree exited {}:\n{}",
        verdict.code,
        verdict.out
    );
}
