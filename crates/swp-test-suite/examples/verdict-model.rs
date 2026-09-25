//! The harness behind the verdict gate's numbers: records what a scan actually
//! contains, then scores it under the rule the product uses and under the
//! alternatives that rule was chosen against.
//!
//! Run it with `cargo run --release -p swp-test-suite --example verdict-model`,
//! optionally with `--iters N` (repetitions), `--matrix N` (look-alike projects per
//! repetition), `--tag-bits W` (the width to mint at) and `--only-foreign`, which
//! skips the copies, refactorings and removal attacks and scans only unrelated
//! trees. Output is tab-separated lines on stdout; `SCAN` is one scored scan,
//! `SITE` is one site of one scan. Every number is a measurement of a real
//! cross-scan, which is what the floors in `swp-evidence::level` and
//! `docs/VALIDATION.md` cite.

use std::path::Path;

use swp_detection::{build_indexes, input, scan_against, SiteStatus};
use swp_evidence::level::tally;

/// One scan, flattened to the numbers the rules read.
struct Obs {
    label: String,
    kind: &'static str,
    fragments: usize,
    files: usize,
    probes: u32,
    /// Distinct keyed codes the candidate presented, summed over sites.
    draws: u32,
    chance: f64,
    tag_bits: u8,
    fingerprint: String,
    detected_current: bool,
    level: String,
    /// P(X >= fragments) as the installed gate computes it: Poisson over the draws.
    p_gate: f64,
    /// P(X >= fragments) under the per-site independent model of the *span* counts —
    /// the statistic this build graded on before, whose tail is the same formula fed
    /// a number that counts one repeated statement once per copy.
    tail_independent: f64,
    /// P(X >= fragments) with nothing assumed: every probe an independent draw.
    tail_loose: f64,
    /// (spans at the address, distinct codes there, status).
    sites: Vec<(u32, u32, &'static str)>,
    /// Spans that confirmed more than one site of the same release.
    shared_span_sites: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters = arg(&args, "--iters").unwrap_or(12);
    let matrix = arg(&args, "--matrix").unwrap_or(6);
    // The production default is 4; the sweep over widths is what shows whether the
    // verdict rule's fixed slack is scale-blind.
    let bits = arg(&args, "--tag-bits").unwrap_or(4) as u8;
    let foreign_only = args.iter().any(|a| a == "--only-foreign");

    for i in 0..iters {
        foreign_matrix(i, matrix, bits);
        if !foreign_only {
            genuine(i, bits);
        }
    }
}

/// §28's `wide_config`, at a chosen width.
fn config(bits: u8) -> String {
    format!(
        "[protect]\ntargets = [\"src\"]\ntarget_sites = 12\ntag_bits = {bits}\nembed_strings = true\n"
    )
}

fn arg(args: &[String], name: &str) -> Option<usize> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
}

/// §28's shape: `matrix` look-alike projects, every tree scanned by every other.
fn foreign_matrix(iter: usize, matrix: usize, bits: u8) {
    use swp_test_suite::project::Project;
    let projects: Vec<Project> = (0..matrix)
        .map(|v| {
            let p = Project::synthetic_wide_variant(&format!("p29-x{v}-{iter}"), 8, 12, v);
            p.set_config(&config(bits));
            p.protect();
            p
        })
        .collect();
    for (i, owner) in projects.iter().enumerate() {
        for (j, other) in projects.iter().enumerate() {
            let cand = other.copy_whole(&format!("p29-c{i}-{j}-{iter}"));
            let kind = if i == j { "own-tree" } else { "foreign" };
            let o = observe(owner.root(), cand.path(), &format!("f{i}>{j}"), kind);
            emit(o, iter);
        }
    }
    // The same source under two keys, which is §28's hardest pair.
    let a = Project::synthetic_wide_variant(&format!("p29-same-a-{iter}"), 8, 12, 0);
    let b = Project::synthetic_wide_variant(&format!("p29-same-b-{iter}"), 8, 12, 0);
    assert_eq!(a.sources(), b.sources(), "the control needs one tree");
    a.set_config(&config(bits));
    b.set_config(&config(bits));
    a.protect();
    b.protect();
    emit(
        observe(a.root(), b.root(), "same-source", "foreign-key"),
        iter,
    );
}

/// The cases that must stay detectable: a copy, partial copies, refactorings and
/// removal attempts, all judged by the project that owns them.
fn genuine(iter: usize, bits: u8) {
    use swp_test_suite::project::Project;
    use swp_test_suite::transform::{read_tree, write_tree, Transform};
    let p = Project::synthetic_wide_variant(&format!("p29-g-{iter}"), 8, 12, 0);
    p.set_config(&config(bits));
    p.protect();
    let release = p.latest();
    let texts = release.site_texts();

    let whole = p.copy_whole(&format!("p29-g-whole-{iter}"));
    emit(observe(p.root(), whole.path(), "copy-all", "genuine"), iter);

    for (num, den, label) in [
        (1usize, 10usize, "copy-10pct"),
        (1, 4, "copy-25pct"),
        (1, 2, "copy-50pct"),
        (3, 4, "copy-75pct"),
    ] {
        let c = p.copy_fraction(&format!("p29-g-{label}-{iter}"), num, den);
        emit(observe(p.root(), c.path(), label, "genuine"), iter);
    }

    for t in Transform::REFACTORING {
        let c = p.copy_whole(&format!("p29-g-{}-{iter}", t.slug()));
        let mut tree = read_tree(c.path());
        t.apply(&mut tree, &texts);
        write_tree(c.path(), &tree);
        emit(observe(p.root(), c.path(), t.slug(), "refactored"), iter);
    }
    for t in Transform::ADVERSARIAL {
        let c = p.copy_whole(&format!("p29-r-{}-{iter}", t.slug()));
        let mut tree = read_tree(c.path());
        t.apply(&mut tree, &texts);
        write_tree(c.path(), &tree);
        emit(observe(p.root(), c.path(), t.slug(), "removal"), iter);
    }
    drop(release);
}

/// Reproduce `swp scan` down to the detection, so per-site data is visible.
fn observe(scanner: &Path, candidate: &Path, label: &str, kind: &'static str) -> Obs {
    let argv = vec![
        "scan".to_string(),
        candidate.display().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let parsed = swp_cli::args::parse(&argv).expect("the scan line parses");
    let ctx = swp_cli::ctx::Ctx::open(&parsed, scanner).expect("the scanner is a project");
    let limits = ctx.limits();
    let releases = ctx.candidate_releases(&parsed).expect("releases load");
    let verify_key = ctx.identity.verify_key().expect("identity has a key");
    let indexes = build_indexes(&releases, &verify_key, &limits).expect("indexes build");
    let opened = input::open(candidate, &limits).expect("candidate opens");
    let detection = scan_against(&opened, &indexes, &limits).expect("the scan completes");
    let t = tally(&detection, 0);
    let release = &detection.releases[0];
    let site_probes: Vec<u32> = release.sites.iter().map(|s| s.probes).collect();
    let mut sites = Vec::new();
    for s in &release.sites {
        sites.push((s.probes, s.distinct_codes, status(s.status)));
    }
    let mut per_span: std::collections::BTreeMap<(String, u32, String), usize> = Default::default();
    for s in release.sites.iter().filter(|s| s.confirmed()) {
        if let Some(f) = &s.found_in {
            *per_span
                .entry((
                    f.clone(),
                    s.found_line.unwrap_or(0),
                    s.found_text.clone().unwrap_or_default(),
                ))
                .or_default() += 1;
        }
    }
    Obs {
        label: label.to_string(),
        kind,
        fragments: t.fragments,
        files: t.files,
        probes: t.probes,
        draws: t.draws,
        chance: t.chance,
        tag_bits: t.tag_bits,
        fingerprint: t.fingerprint.clone(),
        detected_current: t.clears_chance() && t.level.is_finding(),
        level: t.level.to_string(),
        p_gate: t.coincidence_probability,
        tail_independent: tail_poisson_binomial(&site_probes, t.tag_bits, t.fragments),
        tail_loose: tail_binomial(t.probes as usize, t.tag_bits, t.fragments),
        sites,
        shared_span_sites: per_span.values().filter(|n| **n > 1).count(),
    }
}

fn status(s: SiteStatus) -> &'static str {
    match s {
        SiteStatus::Absent => "absent",
        SiteStatus::LocationOnly => "loc-only",
        SiteStatus::TagConfirmed => "tag",
        SiteStatus::ExactRendering => "exact",
    }
}

fn emit(o: Obs, iter: usize) {
    println!(
        "SCAN\t{iter}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{:.6e}\t{:.6e}\t{:.6e}\t{}\t{}\t{}\t{}\t{}",
        o.label,
        o.kind,
        o.fragments,
        o.probes,
        o.draws,
        o.tag_bits,
        o.chance,
        o.p_gate,
        o.tail_independent,
        o.tail_loose,
        o.files,
        o.fingerprint,
        o.level,
        if o.detected_current { "Y" } else { "N" },
        o.shared_span_sites,
    );
    for (n, d, st) in &o.sites {
        println!("SITE\t{iter}\t{}\t{}\t{n}\t{d}\t{st}", o.label, o.kind);
    }
}

/// P(X >= k) for the sum of independent Bernoullis with per-site rates
/// q_s = 1 - (1 - 2^-w)^n_s over the *span* counts, by exact dynamic programming —
/// the model the gate replaced, kept here so the two can be scored on one dataset.
fn tail_poisson_binomial(site_probes: &[u32], tag_bits: u8, k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let p = 0.5f64.powi(i32::from(tag_bits));
    let mut q: Vec<f64> = site_probes
        .iter()
        .map(|&n| {
            if n == 0 {
                0.0
            } else {
                1.0 - (1.0 - p).powi(n as i32)
            }
        })
        .collect();
    q.retain(|x| *x > 0.0);
    let m = q.len();
    if k > m {
        return 0.0;
    }
    let mut dp = vec![0.0f64; m + 1];
    dp[0] = 1.0;
    let mut live = 0usize;
    for qi in &q {
        live += 1;
        for j in (1..=live).rev() {
            dp[j] = dp[j] * (1.0 - qi) + dp[j - 1] * qi;
        }
        dp[0] *= 1.0 - qi;
    }
    (k..=m).map(|j| dp[j]).sum()
}

/// The assumption-free version: treat every probe as an independent draw.
fn tail_binomial(n: usize, tag_bits: u8, k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    let p = 0.5f64.powi(i32::from(tag_bits));
    let mut term = 1.0f64;
    let mut below = 0.0f64;
    for i in 0..k {
        if i > 0 {
            term *= (n - i + 1) as f64 / i as f64 * (p / (1.0 - p));
        }
        below += term;
    }
    1.0 - below * (1.0 - p).powi(n as i32)
}
