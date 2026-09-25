//! §23's evidence level: five named steps, one rule that fired, no percentage.
//!
//! ## Why a level and not a probability
//!
//! "97.2% probability of copying" would need a model of how often people copy code,
//! which nobody running this tool has measured for any population. What *is*
//! computable from a scan is the other side of the question: given how many
//! candidate literals were offered at this release's addresses, and given that a tag
//! is an HMAC output truncated to `w` bits, the number of confirmations an unrelated
//! tree should produce by chance is at most
//!
//! ```text
//! lambda = Σ_s [ 1 − (1 − 2^-w)^d_s ]
//! ```
//!
//! summed over sites, where `d_s` is how many *distinct keyed codes* the candidate
//! presented at site `s`. That is an upper bound on the expected count by linearity
//! of expectation, and it needs no independence assumption to be true: three spans
//! that reproduce one address by carrying one repeated literal are one chance at this
//! project's tag, not three. Counting spans instead of codes overstates the bound by
//! how much those repeats were worth — measured at 1.8% of `lambda` at 4 tag bits,
//! 0.5% at 6 and 0.1% at 8, so the correction is about the bound being admissible,
//! not about it being large, and it is the tail gate below that changes verdicts. A
//! span whose code this build cannot derive is still counted as one, so the statistic
//! never understates the chances.
//!
//! The verdict then asks the one question left that arithmetic can answer: how
//! likely is it that an unrelated tree with exactly these chances produces *at least*
//! the confirmations this scan counted? That probability is the upper tail of a
//! `Poisson(lambda)` count. Two measurements license the model and neither licenses
//! optimism: across 2,790 unrelated cross-scans the observed confirmation counts were
//! Poisson-shaped (variance/mean 0.95, 1.01 and 1.00 at 4, 6 and 8 bits), so a
//! Poisson is the right family; and its mean, `lambda`, came out 2.98x, 2.74x and
//! 3.26x *above* the observed mean, because draws that share one address are not
//! independent and a single draw hits an unrelated tree's tag less often than 2^-w.
//! The bound is therefore conservative by a measured factor and never liberal, so the
//! error it can make is refusing a verdict rather than granting one — at the cost
//! `docs/VALIDATION.md` states per tag width. [`ReleaseTally::clears_chance`] is the
//! line between "this carries our release" and "this is a lead": a scan that cannot
//! cross it says `INCONCLUSIVE` rather than accusing anybody (§27, §51). The floors
//! are constants below, and they were read off the measured false-accusation rate
//! rather than chosen for roundness (
//! chosen for roundness (§12 of `docs/SWP-1-SPEC.md` and the record in
//! `docs/VALIDATION.md`). Clearing them is necessary and not sufficient — the verdict
//! also needs the level to have reached `MODERATE`, so that a two-literal candidate
//! cannot buy a finding simply by being too small to set a wide bound. A verdict may
//! say no more than the ladder already said.
//!
//! The bound is not always small. A site's address is a digest of the code around
//! it with the site hidden, abstracted over local names and over every other
//! literal's value, which is what lets a renamed or reformatted copy still be
//! found — and what makes an ordinary one-line `var step = 4;` inside an ordinary
//! arithmetic function reproduce an address another project published. A scan of an
//! unrelated tree can therefore record hundreds of probes and a handful of
//! confirmations, all of it within what chance owes. That is the shape the
//! probability gate is for: it asks about the *count*, so a candidate that reproduces
//! many addresses does not buy a verdict by producing many coincidences.
//!
//! ## What the ladder is
//!
//! The steps are protocol conventions, not measurements: they are chosen so that
//! one 4-bit fragment cannot on its own produce more than `WEAK`, and so that a
//! level above `WEAK` needs either several addresses or several independent files.
//! They are stated here as constants, listed in `docs/SWP-1-SPEC.md`, and their
//! behaviour against the §24 partial-copy sweep is recorded in `docs/VALIDATION.md`
//! rather than asserted in prose here.
//!
//! ## What can never raise a level
//!
//! Structural hits. An unprotected copy of our own source reproduces every location
//! id in the manifest while carrying no code at all, so `stripped` and
//! `absent` counts appear in the explanation and weight nothing in the ladder. Same
//! for `partial`: an incomplete scan cannot *lower* a positive finding — a hit is a
//! hit — but it does turn a negative finding into `INCONCLUSIVE`.

use serde::{Deserialize, Serialize};
use swp_core::site::TagWidth;
use swp_detection::{Detection, SiteStatus};

/// The five deterministic steps, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLevel {
    None,
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

impl EvidenceLevel {
    pub const ALL: &'static [EvidenceLevel] = &[
        EvidenceLevel::None,
        EvidenceLevel::Weak,
        EvidenceLevel::Moderate,
        EvidenceLevel::Strong,
        EvidenceLevel::VeryStrong,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceLevel::None => "NONE",
            EvidenceLevel::Weak => "WEAK",
            EvidenceLevel::Moderate => "MODERATE",
            EvidenceLevel::Strong => "STRONG",
            EvidenceLevel::VeryStrong => "VERY_STRONG",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            EvidenceLevel::None => 0,
            EvidenceLevel::Weak => 1,
            EvidenceLevel::Moderate => 2,
            EvidenceLevel::Strong => 3,
            EvidenceLevel::VeryStrong => 4,
        }
    }

    /// Whether a scan that stopped here has something to report. A level that
    /// earns this is printed as evidence; whether it also earns the *verdict*
    /// `PROVENANCE_DETECTED` is a second question, answered by
    /// [`ReleaseTally::clears_chance`], because a lead chance could have produced
    /// is still a lead and still not a finding about a person.
    pub fn is_finding(self) -> bool {
        self.rank() >= EvidenceLevel::Weak.rank()
    }
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the scan says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// At least one release has confirmed watermark evidence in the candidate.
    ProvenanceDetected,
    /// Nothing was confirmed and the whole candidate was examined.
    NoProvenanceDetected,
    /// Nothing was confirmed *and* part of the candidate was never read, so the
    /// honest answer is that this scan cannot rule a copy in or out (§45).
    Inconclusive,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::ProvenanceDetected => "PROVENANCE_DETECTED",
            Outcome::NoProvenanceDetected => "NO_PROVENANCE_DETECTED",
            Outcome::Inconclusive => "INCONCLUSIVE",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::NoProvenanceDetected => 0,
            Outcome::ProvenanceDetected => 1,
            // `INSUFFICIENT_EVIDENCE`'s code, kept identical to the error table so
            // a script sees one meaning for one number.
            Outcome::Inconclusive => swp_core::ErrorCode::InsufficientEvidence.exit_code(),
        }
    }
}

/// Ladder constants. Changing any of these changes what a report calls `STRONG`,
/// so they are stated once, here, with the sentence that justifies each.
///
/// Two or more confirmations is the first step because a single 4-bit code is the
/// one quantity this protocol can state a coincidence rate for, and one event at
/// 1-in-16 is not a finding about a project.
pub const MODERATE_MIN_FRAGMENTS: usize = 2;
/// Four confirmations, in at least two files, is the second step because it needs
/// either four independent addresses or a copy that spans two compilation units.
pub const STRONG_MIN_FRAGMENTS: usize = 4;
pub const STRONG_MIN_FILES: usize = 2;
/// Without the file spread, a repeated statement in one generated file could
/// produce this count, so the bar is higher when the count is the only argument.
pub const STRONG_SOLO_MIN_FRAGMENTS: usize = 6;
pub const VERY_STRONG_MIN_FRAGMENTS: usize = 8;
pub const VERY_STRONG_MIN_FILES: usize = 3;
/// The largest coincidental probability each step above `WEAK` will accept, in
/// place of the additive confirmations-over-the-bound slack this build used to grade
/// with.
///
/// A probability is what the gate compares, because the old subtraction was
/// width-blind: `1.5` confirmations above the bound meant a very different chance of
/// an unrelated tree producing them at a 4-bit tag than at an 8-bit one, so the same
/// rule accused look-alike projects at one width and cleared them at another.
/// Measured on the rule this one replaced: 6 false accusations in the 3,000 foreign
/// cross-scans of 100 runs of the §28 suite — 0.20% per scan, 5 runs in 100 red — and
/// 7 more in 2,790 look-alike scans across the tag widths. On the same scans this
/// gate accused nobody: 0 in 5,790, which bounds its rate at 5.2e-4 per scan and 3.0%
/// per §28 run at 95% confidence. That residual is the honest limit of what the
/// suites show; `docs/VALIDATION.md` states it and how to reproduce it.
///
/// What it costs is measured too: 1,903 of the 2,100 findings the old rule reached
/// survive (90.6%, width by width 80 / 95 / 97%), the loss falling on half-and-under
/// partial copies and on site-removal attacks at the default 4-bit width, where a
/// finding now needs 10 confirmations of a 12-site constellation. No scan in the
/// sample was accused by this rule and cleared by the old one. The higher steps are a
/// decade and five stricter for the same reason the counts are higher: `STRONG` and
/// `VERY_STRONG` are words a report says about somebody's code.
pub const COINCIDENCE_MAX_ABOVE_WEAK: f64 = 1e-3;
pub const COINCIDENCE_MAX_FOR_STRONG: f64 = 1e-5;
pub const COINCIDENCE_MAX_FOR_VERY_STRONG: f64 = 1e-8;

/// Everything the ladder reads about one release, as measured numbers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTally {
    pub project_id: String,
    pub release_id: String,
    /// Keyed sites this release holds.
    pub sites: usize,
    /// Sites whose literal carries this project's code.
    pub fragments: usize,
    /// Sites present as an address without a code.
    pub stripped: usize,
    /// Sites with no matching span.
    pub absent: usize,
    /// Confirmations that are byte-for-byte the recorded rendering.
    pub exact_renderings: usize,
    /// Confirmations reached only through the rename-tolerant radii.
    pub canonical_only: usize,
    /// Confirmations found in a file other than the one we protected.
    pub moved: usize,
    /// Confirmations found as a multi-token rendering.
    pub renderings: usize,
    /// Distinct candidate files holding a confirmation.
    pub files: usize,
    /// Keyed bits carried by the confirmed sites.
    pub bits: u32,
    pub tag_bits: u8,
    /// Spans that reached a tag comparison.
    pub probes: u32,
    /// Distinct keyed codes the candidate presented, summed over sites: the draws
    /// [`ReleaseTally::chance`] is computed from.
    pub draws: u32,
    pub literals_tried: u64,
    pub windows_tried: u64,
    /// `"match"`, `"no-match"` or `"not-comparable"`.
    pub fingerprint: String,
    /// `Σ_s [1 − (1 − 2^-tag_bits)^d_s]` over the sites' distinct-code counts: the
    /// upper bound on coincidental confirmations, assuming nothing about codes being
    /// independent.
    pub chance: f64,
    /// Confirmations above that bound. Printed as the size of the excess; the verdict
    /// is decided by [`ReleaseTally::coincidence_probability`], not by this.
    pub guarantee: f64,
    /// The probability that an unrelated tree holding these addresses and none of
    /// this project's codes produces `fragments` confirmations or more: the upper
    /// tail of `Poisson(chance)`, which is measured to over-predict the null rather
    /// than under-predict it. This is the number the floors above are compared with.
    pub coincidence_probability: f64,
    pub level: EvidenceLevel,
    /// The rules that produced `level`, in plain sentences with the numbers in them.
    pub reasons: Vec<String>,
}

impl ReleaseTally {
    /// Whether this release is strong enough to be reported as a finding.
    ///
    /// Two requirements, and the second is not a restatement of the first:
    ///
    /// * the count has to be one the candidate's own draw volume cannot account
    ///   for — `Poisson(chance) ≥ fragments` has to come in under
    ///   [`COINCIDENCE_MAX_ABOVE_WEAK`], which is what
    ///   [`ReleaseTally::coincidence_probability`] measures; and
    /// * the grade has to reach `MODERATE`, or the §16 fingerprint has to have
    ///   matched.
    ///
    /// The first rule alone would be enough at the widths this build emits — a lone
    /// fragment's best possible probability is one draw's `2^-w`, which is 3.9e-3 at
    /// the widest supported tag and so cannot cross the floor — but the ladder is a
    /// protocol convention, not a consequence of the arithmetic, and §23 defines a
    /// single fragment as "a lead worth manual review" whatever the tag width
    /// becomes later. A verdict is allowed to say only what its evidence level
    /// already says — which is the §27 requirement, and the reason `WEAK` and `None`
    /// are excluded here rather than only in the explanation.
    pub fn clears_chance(&self) -> bool {
        self.fingerprint == "match"
            || (self.coincidence_probability < COINCIDENCE_MAX_ABOVE_WEAK
                && self.level >= EvidenceLevel::Moderate)
    }
}

/// Measure one release and grade it.
pub fn tally(detection: &Detection, position: usize) -> ReleaseTally {
    let release = &detection.releases[position];
    let mut files: Vec<&str> = Vec::new();
    let mut exact_renderings = 0usize;
    let mut canonical_only = 0usize;
    let mut moved = 0usize;
    let mut renderings = 0usize;
    for site in &release.sites {
        if !site.confirmed() {
            continue;
        }
        if let Some(found) = &site.found_in {
            if !files.contains(&found.as_str()) {
                files.push(found.as_str());
            }
        }
        if site.status == SiteStatus::ExactRendering {
            exact_renderings += 1;
        }
        if site.refactored() {
            canonical_only += 1;
        }
        if site.moved() {
            moved += 1;
        }
        if site.found_tokens > 1 {
            renderings += 1;
        }
    }
    let site_draws: Vec<u32> = release.sites.iter().map(|s| s.distinct_codes).collect();
    let draws: u32 = site_draws.iter().sum();
    let probes = release.probes();
    let chance = chance_of_coincidence(&site_draws, release.tag_bits);
    let loose = union_bound_of_coincidence(probes, release.tag_bits);
    let fragments = release.confirmed();
    let guarantee = fragments as f64 - chance;
    let probability = tail_of_coincidence(chance, fragments);
    let (level, mut reasons) = grade(
        fragments,
        files.len(),
        release.fingerprint.matched(),
        chance,
        probability,
    );
    reasons.push(format!(
        "coincidence bound: {probes} span(s) carrying {draws} distinct code(s) reached a \
         {}-bit tag comparison at {} site(s), so an unrelated tree holding those addresses and \
         none of this project's codes is expected to confirm at most {chance:.4} of them \
         ({loose:.4} if every span carried its own code) and produces this scan's {fragments} \
         confirmation(s) or more with probability {probability:.2e}; {:.4} remain above the \
         expectation",
        release.tag_bits,
        release.total(),
        guarantee.max(0.0)
    ));
    ReleaseTally {
        project_id: release.project_id.as_str().to_string(),
        release_id: release.release_id.as_str().to_string(),
        sites: release.total(),
        fragments,
        stripped: release.stripped(),
        absent: release.absent(),
        exact_renderings,
        canonical_only,
        moved,
        renderings,
        files: files.len(),
        bits: release.confirmed_bits(),
        tag_bits: release.tag_bits,
        probes: release.probes(),
        draws,
        literals_tried: release.literals_tried,
        windows_tried: release.windows_tried,
        fingerprint: release.fingerprint.as_str().to_string(),
        chance,
        guarantee,
        coincidence_probability: probability,
        level,
        reasons,
    }
}

/// Expected coincidental confirmations for one release, computed where the width
/// is validated rather than trusted.
///
/// `site_draws` is how many *distinct keyed codes* reached a tag comparison *at each
/// site*, so the sum is [`ReleaseTally::draws`]. A site contributes
/// `1 − (1 − 2^-w)^d`: the chance that at least one of its `d` codes carries this
/// project's `w`-bit tag. Two looser statistics are available and neither is used
/// here: counting the *spans* that reached the address instead of the codes they
/// carried, which measures 1.8% higher at a 4-bit tag, 0.5% at 6 and 0.1% at 8 on
/// look-alike trees; and the assumption-free union bound [`union_bound_of_coincidence`]
/// below, `Σ n × 2^-w`, which is 20% above this at 4 bits, 5% at 6 and 1% at 8, and
/// which the report prints beside this number rather than grading on.
///
/// None of those three is why the verdicts changed. This form needs no independence
/// assumption at all: it is an upper bound on the expected count by linearity of
/// expectation, whatever the dependence between sites, and it can only err by counting
/// a span whose code this build could not derive as one more chance to be fooled. What
/// it does not do is understate the chances, and the tail gate below is what turns
/// "an upper bound" into a verdict a reader can rely on.
pub fn chance_of_coincidence(site_draws: &[u32], tag_bits: u8) -> f64 {
    let rate = match TagWidth::new(tag_bits) {
        Ok(width) => width.null_hit_probability(),
        // A width this build does not know cannot be graded, and must not be
        // graded generously: rate 1.0 means every site it probed is expected.
        Err(_) => 1.0,
    };
    site_draws
        .iter()
        .map(|&d| match d {
            0 => 0.0,
            _ => 1.0 - (1.0 - rate).powf(d as f64),
        })
        .sum()
}

/// The same expectation with one assumption fewer and no subtraction at all: every
/// span at every address is billed as one chance, whether or not it carries a code
/// anything else carries. Printed alongside the tight figure so a reader can see the
/// bound that needs no account of what repeated — measured at 20% above
/// [`chance_of_coincidence`] at a 4-bit tag, 5% at 6 bits and 1% at 8, on look-alike
/// trees where about one site in twenty carries spans that share a code.
pub fn union_bound_of_coincidence(probes: u32, tag_bits: u8) -> f64 {
    let rate = match TagWidth::new(tag_bits) {
        Ok(width) => width.null_hit_probability(),
        Err(_) => 1.0,
    };
    probes as f64 * rate
}

/// The probability that a count with expectation `lambda` reaches `events` or more:
/// the upper tail of a `Poisson(lambda)`, which is what the coincidence floors are
/// compared against.
///
/// A Poisson is the right *shape* here because the events are rare draws over a
/// large number of candidate literals, and both halves of that were measured rather
/// than assumed. The shape holds: over 930 unrelated cross-scans at each of 4, 6 and
/// 8 bits the confirmation count came out with variance/mean 0.95, 1.01 and 1.00, and
/// 0.86 over the 3,000 foreign scans of §28. The mean does not: `lambda` sits 2.7x to
/// 3.3x above what an unrelated tree really confirms, because draws sharing one
/// address are not independent, so this tail is over-predicted by a factor that grows
/// with the count — at 4 bits it put `P(F >= 1)` at 0.94 where 930 scans measured
/// 0.62, and `P(F >= 4)` at 0.32 where 7,500 scans measured 0.0076. Never under, at
/// any bucket measured: the mistake this function can make is refusing a verdict
/// rather than granting one, and `docs/VALIDATION.md` prints what that costs in
/// confirmations per tag width.
pub fn tail_of_coincidence(lambda: f64, events: usize) -> f64 {
    if events == 0 {
        // Zero confirmations is what an unrelated tree always produces.
        return 1.0;
    }
    if lambda <= 0.0 {
        return 0.0;
    }
    // 1 − e^-λ Σ_{i<events} λ^i / i!, accumulated term by term so no factorial is
    // ever formed. A non-finite lower tail means λ is enormous next to `events`,
    // where the probability is 1 anyway; the guard refuses rather than dividing.
    let mut term = 1.0f64;
    let mut sum = 0.0f64;
    for i in 0..events {
        if i > 0 {
            term *= lambda / i as f64;
        }
        sum += term;
    }
    let kept = (-lambda).exp() * sum;
    if !kept.is_finite() {
        return 1.0;
    }
    (1.0 - kept).clamp(0.0, 1.0)
}

/// The ladder, as a function of measured counts, so the same rules grade a scan
/// and a verification run.
fn grade(
    fragments: usize,
    files: usize,
    fingerprint_matched: bool,
    chance: f64,
    probability: f64,
) -> (EvidenceLevel, Vec<String>) {
    let mut reasons = Vec::new();
    if fingerprint_matched {
        reasons.push(
            "the candidate's canonicalized tree hashes to the fingerprint this release \
             published, which is an exact copy of the protected source rather than an \
             inference from it"
                .to_string(),
        );
        return (EvidenceLevel::VeryStrong, reasons);
    }
    let counted = ladder(fragments, files);
    // Coincidence can only ever lower the level, never raise it: arithmetic about
    // chance is not a substitute for having the fragments.
    let allowed = if probability < COINCIDENCE_MAX_FOR_VERY_STRONG {
        EvidenceLevel::VeryStrong
    } else if probability < COINCIDENCE_MAX_FOR_STRONG {
        EvidenceLevel::Strong
    } else if probability < COINCIDENCE_MAX_ABOVE_WEAK {
        EvidenceLevel::Moderate
    } else {
        EvidenceLevel::Weak
    };
    let level = counted.min(allowed);
    if level < counted {
        reasons.push(format!(
            "{fragments} confirmation(s) against a coincidence bound of {chance:.4} expected by \
             chance: an unrelated tree produces that many of them or more with probability \
             {probability:.2e}, which is more than a claim above {level} can stand on, so the \
             level is capped at {level} whatever the count would otherwise have earned (it \
             reached {counted} on counts alone)"
        ));
    }
    reasons.extend(explain(fragments, files, level));
    (level, reasons)
}

/// The count-and-spread part of the ladder, before the coincidence cap.
fn ladder(fragments: usize, files: usize) -> EvidenceLevel {
    if fragments == 0 {
        EvidenceLevel::None
    } else if fragments >= VERY_STRONG_MIN_FRAGMENTS && files >= VERY_STRONG_MIN_FILES {
        EvidenceLevel::VeryStrong
    } else if fragments >= STRONG_SOLO_MIN_FRAGMENTS
        || (fragments >= STRONG_MIN_FRAGMENTS && files >= STRONG_MIN_FILES)
    {
        EvidenceLevel::Strong
    } else if fragments >= MODERATE_MIN_FRAGMENTS {
        EvidenceLevel::Moderate
    } else {
        EvidenceLevel::Weak
    }
}

fn explain(fragments: usize, files: usize, level: EvidenceLevel) -> Vec<String> {
    let rule = match level {
        EvidenceLevel::None => "no keyed site of this release is present with its code",
        EvidenceLevel::Weak => {
            "one confirmation is WEAK: at the recorded width a hit like this is within the \
             reach of chance, so it is printed as a lead worth looking at and not as proof of \
             copying"
        }
        EvidenceLevel::Moderate => {
            "the {f} rule: two or more sites of one constellation carry their code"
        }
        EvidenceLevel::Strong => {
            "the {s} rule: four or more confirmations across two or more files, or six in one file"
        }
        EvidenceLevel::VeryStrong => {
            "the {v} rule: eight or more confirmations across three or more files"
        }
    }
    .to_string();
    let rule = rule
        .replace("{f}", &MODERATE_MIN_FRAGMENTS.to_string())
        .replace("{s}", &STRONG_MIN_FRAGMENTS.to_string())
        .replace("{v}", &VERY_STRONG_MIN_FRAGMENTS.to_string());
    vec![
        format!("watermark fragments: {fragments}"),
        format!("candidate files holding them: {files}"),
        rule,
    ]
}

/// Strength of the aggregate "part of the constellation is here" statement, which
/// is about coverage rather than coincidence and says so.
pub fn partial_level(confirmed: usize, total: usize) -> EvidenceLevel {
    if total == 0 {
        return EvidenceLevel::None;
    }
    // Integer thirds: no floating-point boundary can make a report flip level.
    let scaled = confirmed * 3;
    if scaled >= total * 2 {
        EvidenceLevel::Strong
    } else if scaled >= total {
        EvidenceLevel::Moderate
    } else {
        EvidenceLevel::Weak
    }
}

/// The whole scan's assessment: the strongest release, and what to print.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub outcome: Outcome,
    pub level: EvidenceLevel,
    /// One entry per release scanned against, best first.
    pub releases: Vec<ReleaseTally>,
    /// The index into `releases` the level came from, for the report header.
    pub best: usize,
    pub reasons: Vec<String>,
}

/// Grade a scan.
pub fn assess(detection: &Detection) -> Assessment {
    let mut releases: Vec<ReleaseTally> = detection
        .releases
        .iter()
        .enumerate()
        .map(|(i, _)| tally(detection, i))
        .collect();
    // Best first, with the same tie-break the detection layer uses so the report's
    // ordering matches the evidence items' ordering.
    releases.sort_by(|a, b| {
        b.level
            .cmp(&a.level)
            .then(b.fragments.cmp(&a.fragments))
            .then(b.bits.cmp(&a.bits))
            .then((b.fingerprint == "match").cmp(&(a.fingerprint == "match")))
    });
    let best = 0usize;
    let top = releases.first();
    let level = top.map(|t| t.level).unwrap_or(EvidenceLevel::None);
    let lead = top.is_some_and(|t| t.level.is_finding());
    // A lead a verdict can stand on is a finding; one it cannot is reported as
    // evidence and refused as a verdict. §27 asks the detector to tell an
    // unrelated tree from a copy, and at these widths the only things that can do
    // that are the arithmetic and the level ladder, so both decide the verb rather
    // than only the adjective.
    let detected = lead && top.is_some_and(|t| t.clears_chance());
    let outcome = if detected {
        Outcome::ProvenanceDetected
    } else if lead || detection.partial {
        Outcome::Inconclusive
    } else {
        Outcome::NoProvenanceDetected
    };
    let mut reasons = top.map(|t| t.reasons.clone()).unwrap_or_default();
    if lead && !detected {
        if let Some(t) = top {
            reasons.push(if t.coincidence_probability >= COINCIDENCE_MAX_ABOVE_WEAK {
                format!(
                    "{} confirmation(s) against a bound of {:.4} an unrelated tree is expected to \
                     produce: it reaches this many of them with probability {:.2e}, above the \
                     {:.0e} a verdict must clear, so this scan reports the candidate as \
                     INCONCLUSIVE rather than as carrying this release. Nothing here distinguishes \
                     it from an unrelated project, and a wider tag or a larger constellation would.",
                    t.fragments,
                    t.chance,
                    t.coincidence_probability,
                    COINCIDENCE_MAX_ABOVE_WEAK
                )
            } else {
                format!(
                    "{} confirmation(s) clear the coincidence floor of {:.0e} at probability \
                     {:.2e}, but {level} is the grade a verdict cannot be printed on: a lead this \
                     thin is reported as evidence to look at and as INCONCLUSIVE, not as this \
                     release being present.",
                    t.fragments,
                    COINCIDENCE_MAX_ABOVE_WEAK,
                    t.coincidence_probability
                )
            });
        }
    }
    if detection.partial {
        reasons.push(
            "the candidate was not fully examined (see notes), so this scan cannot distinguish \
             an absent watermark from an unread file"
                .to_string(),
        );
    }
    if let Some(top) = top {
        if top.stripped > 0 {
            reasons.push(format!(
                "{} site(s) show this release's address without its code: the source is there, \
                 the fragment is not. A copy of an unprotected build and a deliberate strip are \
                 indistinguishable here, so this is not counted as evidence",
                top.stripped
            ));
        }
    }
    Assessment {
        outcome,
        level,
        releases,
        best,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_core::{FormFamily, LiteralClass, RadiusKind};
    use swp_detection::{FingerprintCheck, InputKind, ReleaseDetection, SiteMatch, SLOT_COUNT};

    fn site(status: SiteStatus, files: &str, slots: Vec<RadiusKind>) -> SiteMatch {
        SiteMatch {
            site: 0,
            manifest_file: "src/a.js".into(),
            manifest_line: 3,
            language: "javascript".into(),
            adapter: "ast".into(),
            class: LiteralClass::Integer,
            family: FormFamily::Add,
            width: 4,
            primary: RadiusKind::StatementId.code(),
            locations: [swp_core::LocationId::default(); SLOT_COUNT],
            status,
            slots,
            found_in: (status != SiteStatus::Absent).then(|| files.to_string()),
            found_line: (status != SiteStatus::Absent).then_some(1),
            found_text: (status != SiteStatus::Absent).then(|| "(995 + 5)".into()),
            found_tokens: if status == SiteStatus::Absent { 0 } else { 5 },
            probes: if status == SiteStatus::Absent { 0 } else { 1 },
            distinct_codes: if status == SiteStatus::Absent { 0 } else { 1 },
        }
    }

    /// One release made of the given sites, at 4 bits.
    fn release(sites: Vec<SiteMatch>) -> ReleaseDetection {
        release_at(4, sites)
    }

    /// The same, at a chosen tag width: the floors are probabilities, so the width a
    /// release was published at changes what its counts can be claimed to mean.
    fn release_at(bits: u8, sites: Vec<SiteMatch>) -> ReleaseDetection {
        ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: bits,
            sites,
            fingerprint: FingerprintCheck::NotMatched,
            candidate_files: 3,
            literals_tried: 10,
            windows_tried: 10,
        }
    }

    /// How many spans stood at this site's address, each carrying its own code.
    fn probed(mut m: SiteMatch, n: u32) -> SiteMatch {
        m.probes = n;
        m.distinct_codes = n;
        m
    }

    /// How many spans stood at this site's address when they all carried one code —
    /// the shape a tree has where a statement is repeated, which is what the
    /// distinct-code count exists for.
    fn shared(mut m: SiteMatch, n: u32) -> SiteMatch {
        m.probes = n;
        m.distinct_codes = 1;
        m
    }

    fn confirmed_at(file: &str) -> SiteMatch {
        site(
            SiteStatus::TagConfirmed,
            file,
            vec![RadiusKind::StatementId],
        )
    }

    fn detection(releases: Vec<ReleaseDetection>, partial: bool) -> Detection {
        Detection {
            described: "candidate".into(),
            kind: InputKind::Directory,
            releases,
            files_scanned: 3,
            bytes_scanned: 100,
            omissions: Vec::new(),
            notes: Vec::new(),
            partial,
        }
    }

    #[test]
    fn levels_are_ordered_and_only_the_top_four_are_findings() {
        assert!(EvidenceLevel::VeryStrong > EvidenceLevel::Strong);
        assert!(!EvidenceLevel::None.is_finding());
        assert!(EvidenceLevel::Weak.is_finding());
        for level in EvidenceLevel::ALL {
            assert_eq!(level.as_str(), level.to_string());
        }
    }

    #[test]
    fn the_coincidence_bound_counts_a_site_once_however_many_spans_reached_it() {
        assert_eq!(chance_of_coincidence(&[], 4), 0.0);
        assert_eq!(chance_of_coincidence(&[0, 0, 0], 4), 0.0);
        // One code each at sixteen sites: the two formulas agree, at one expected hit.
        assert!((chance_of_coincidence(&[1; 16], 4) - 1.0).abs() < 1e-12);
        assert!((union_bound_of_coincidence(16, 4) - 1.0).abs() < 1e-12);
        // Sixteen codes at ONE site cannot confirm it sixteen times.
        assert!(
            (chance_of_coincidence(&[16], 4) - (1.0 - (15.0f64 / 16.0).powi(16))).abs() < 1e-12
        );
        assert!(
            (chance_of_coincidence(&[100], 8) - (1.0 - (255.0f64 / 256.0).powi(100))).abs() < 1e-12
        );
        let tight = chance_of_coincidence(&[16, 16, 16], 4);
        assert!((tight - 3.0 * (1.0 - (15.0f64 / 16.0).powi(16))).abs() < 1e-9);
        assert!(tight < union_bound_of_coincidence(48, 4));
        // A huge code count cannot push the expectation past the sites it covers,
        // which is the failure a printed bound must never have.
        assert!(chance_of_coincidence(&[100_000; 24], 4) <= 24.0);
        // An unknown width is graded as if every probed site could coincide.
        assert_eq!(chance_of_coincidence(&[1, 1, 1], 9), 3.0);
        assert_eq!(union_bound_of_coincidence(3, 9), 3.0);
    }

    #[test]
    fn spans_sharing_a_code_are_one_chance_and_not_the_bound_sixteen_times_over() {
        // The shape a look-alike tree has: sixteen spans reproduce one address, and
        // they do it by carrying one repeated statement, so the site was offered one
        // code rather than sixteen. Measured over 11,400 cross-scans, a site of this
        // shape confirmed at 2^-w — one draw's rate — while the span count this build
        // used before predicted 0.57 to 0.64 of a hit at 4 bits.
        let one_code = chance_of_coincidence(&[1, 1, 1], 4);
        let counted_spans = chance_of_coincidence(&[16, 16, 16], 4);
        assert!((one_code - 3.0 / 16.0).abs() < 1e-12, "{one_code}");
        assert!(counted_spans > 3.0 * one_code);
        assert!(
            (union_bound_of_coincidence(48, 4) - 3.0).abs() < 1e-9,
            "counting spans, three sites at 4 bits expect three coincidences: more than \
             the sites that exist, which is the inflation removed"
        );
    }

    #[test]
    fn the_coincidence_probability_is_the_upper_tail_of_a_poisson_count() {
        // No chances at all: nothing can coincide.
        assert_eq!(tail_of_coincidence(0.0, 1), 0.0);
        // Zero confirmations is what an unrelated tree always produces.
        assert_eq!(tail_of_coincidence(3.0, 0), 1.0);
        // One event over an expectation of ln 2 sits on the 50% line: 1 − e^−λ = 0.5.
        assert!((tail_of_coincidence(std::f64::consts::LN_2, 1) - 0.5).abs() < 1e-6);
        // Two events over 0.125: 1 − e^-λ(1 + λ).
        assert!((tail_of_coincidence(0.125, 2) - 0.007_191).abs() < 1e-6);
        // Monotone both ways a verdict cares about: a wider bound excuses more,
        // and a larger count is harder to excuse.
        assert!(tail_of_coincidence(0.5, 8) > tail_of_coincidence(0.25, 8));
        assert!(tail_of_coincidence(0.25, 9) < tail_of_coincidence(0.25, 8));
        // A bound enormous next to the count is certainty, and a count enormous
        // next to the bound rounds to nothing; neither may come out negative.
        assert_eq!(tail_of_coincidence(400.0, 8), 1.0);
        assert!(tail_of_coincidence(0.25, 400) < 1e-300);
    }

    #[test]
    fn one_fragment_is_weak_even_though_the_ladder_would_not_say_so() {
        // 1 confirmation over 1 draw at 4 bits: expectation 0.0625, probability 6.1e-2.
        let (level, _) = grade(1, 1, false, 0.0625, tail_of_coincidence(0.0625, 1));
        assert_eq!(level, EvidenceLevel::Weak);
        // The widest tag the protocol emits does not buy the step with one fragment
        // either: its best case is one draw at 2^-8, a probability of 3.9e-3.
        let one_draw_at_eight = 1.0 / 256.0;
        let p = tail_of_coincidence(one_draw_at_eight, 1);
        assert!(p > COINCIDENCE_MAX_ABOVE_WEAK, "{p}");
        assert_eq!(
            grade(1, 1, false, one_draw_at_eight, p).0,
            EvidenceLevel::Weak
        );
        // Where chance cannot reach the count, the counts decide the level.
        let (eight, _) = grade(8, 4, false, 0.25, tail_of_coincidence(0.25, 8));
        assert_eq!(eight, EvidenceLevel::VeryStrong);
    }

    #[test]
    fn a_bound_that_explains_the_hits_caps_the_level_without_inventing_hits() {
        // Four confirmations at a bound of 3.2: chance accounts for the count, so
        // the level is WEAK whatever the numbers say about spread.
        let (level, reasons) = grade(4, 1, false, 3.2, tail_of_coincidence(3.2, 4));
        assert_eq!(level, EvidenceLevel::Weak, "{reasons:?}");
        assert!(
            reasons.iter().any(|r| r.contains("coincidence bound")),
            "{reasons:?}"
        );
    }

    #[test]
    fn the_floors_between_weak_and_very_strong_are_decided_by_probability() {
        // Eight confirmations over eight draws at 4 bits are excused by chance with
        // probability 6.2e-8: under the additive rule this scan left 7.5 confirmations
        // above the bound and read as VERY_STRONG, and it now reads as STRONG, which is
        // what its arithmetic supports. The verdict is unchanged either way.
        let (strong, reasons) = grade(8, 4, false, 0.5, tail_of_coincidence(0.5, 8));
        assert_eq!(strong, EvidenceLevel::Strong, "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("capped")), "{reasons:?}");
        // Ten times the same evidence clears the top floor.
        let (very, reasons) = grade(10, 4, false, 0.5, tail_of_coincidence(0.5, 10));
        assert_eq!(very, EvidenceLevel::VeryStrong, "{reasons:?}");
        assert!(!reasons.iter().any(|r| r.contains("capped")), "{reasons:?}");
    }

    #[test]
    fn an_exact_fingerprint_short_circuits_to_very_strong() {
        let (level, reasons) = grade(0, 0, true, 0.0, 0.0);
        assert_eq!(level, EvidenceLevel::VeryStrong);
        assert_eq!(reasons.len(), 1, "{reasons:?}");
    }

    #[test]
    fn partial_coverage_uses_integer_thirds() {
        assert_eq!(partial_level(1, 12), EvidenceLevel::Weak);
        assert_eq!(partial_level(4, 12), EvidenceLevel::Moderate);
        assert_eq!(partial_level(8, 12), EvidenceLevel::Strong);
        assert_eq!(partial_level(0, 0), EvidenceLevel::None);
    }

    #[test]
    fn a_clean_full_scan_is_negative_and_a_partial_one_is_inconclusive() {
        let clean = detection(
            vec![release(vec![site(SiteStatus::Absent, "", vec![])])],
            false,
        );
        let a = assess(&clean);
        assert_eq!(a.outcome, Outcome::NoProvenanceDetected);
        assert_eq!(a.level, EvidenceLevel::None);

        let unread = detection(
            vec![release(vec![site(SiteStatus::Absent, "", vec![])])],
            true,
        );
        assert_eq!(assess(&unread).outcome, Outcome::Inconclusive);
        assert!(assess(&unread).level == EvidenceLevel::None);
    }

    #[test]
    fn structural_hits_never_raise_a_level_above_none() {
        // Nine address matches at 4 bits is a 0.56 expected coincidence and zero
        // confirmations: the stripped channel is reported and weights nothing.
        let d = detection(
            vec![release(vec![probed(
                site(
                    SiteStatus::LocationOnly,
                    "src/a.js",
                    vec![RadiusKind::StatementRaw],
                ),
                9,
            )])],
            false,
        );
        let a = assess(&d);
        assert_eq!(a.level, EvidenceLevel::None);
        assert_eq!(a.releases[0].stripped, 1);
        assert_eq!(a.releases[0].fragments, 0);
        assert_eq!(a.releases[0].probes, 9);
        assert!(a
            .reasons
            .iter()
            .any(|r| r.contains("not counted as evidence")));
    }

    #[test]
    fn a_spread_constellation_survives_the_bound_and_is_graded_by_the_counts() {
        let sites: Vec<SiteMatch> = (0..8)
            .map(|i| {
                confirmed_at(match i {
                    0..=2 => "src/a.js",
                    3..=5 => "src/b.js",
                    _ => "src/c.js",
                })
            })
            .collect();
        let a = assess(&detection(vec![release(sites)], false));
        // Eight confirmations over eight draws at 4 bits: chance excuses them with
        // probability 6.2e-8, which is below STRONG's floor and above VERY_STRONG's,
        // so the counts say VERY_STRONG and the grade says STRONG. The verdict — which
        // is what the scan is *claiming* — is unaffected: this is a finding either way.
        assert_eq!(a.level, EvidenceLevel::Strong, "{:?}", a.reasons);
        assert_eq!(a.outcome, Outcome::ProvenanceDetected);
        assert_eq!(a.releases[0].files, 3);
        assert_eq!(a.releases[0].bits, 32);
        assert!(a.releases[0].guarantee > 7.4, "{:?}", a.releases[0]);
        assert!(
            a.releases[0].coincidence_probability < 1e-7,
            "{:?}",
            a.releases[0]
        );
    }

    #[test]
    fn the_same_constellation_at_a_wide_tag_is_graded_by_the_counts_alone() {
        // The top rung is still reachable on counts, because at an 8-bit tag eight
        // confirmations over eight draws sit at probability 2.2e-17 — five decades
        // below the floor. Width is what the old additive rule ignored.
        let sites: Vec<SiteMatch> = (0..8)
            .map(|i| {
                confirmed_at(match i {
                    0..=2 => "src/a.js",
                    3..=5 => "src/b.js",
                    _ => "src/c.js",
                })
            })
            .collect();
        let a = assess(&detection(vec![release_at(8, sites)], false));
        assert_eq!(a.level, EvidenceLevel::VeryStrong, "{:?}", a.reasons);
        assert!(
            !a.reasons.iter().any(|r| r.contains("capped")),
            "{:?}",
            a.reasons
        );
        assert_eq!(a.outcome, Outcome::ProvenanceDetected);
    }

    #[test]
    fn a_wide_tag_does_not_let_two_confirmations_become_a_verdict() {
        // Two sites, each visited by sixteen spans carrying sixteen *different* codes:
        // 32 real chances at an 8-bit tag. The additive rule this build used before
        // read the resulting bound (0.123) as slack — 1.88 confirmations clear of it —
        // and accused, which is the false-positive shape measured at 2.4e-3 per scan at
        // 8 bits. The probability an unrelated tree produces both of them is 6.8e-3, so
        // this scan cannot say anything about where the candidate came from.
        let sites = vec![
            probed(confirmed_at("src/a.js"), 16),
            probed(confirmed_at("src/b.js"), 16),
        ];
        let a = assess(&detection(vec![release_at(8, sites)], false));
        assert!(
            a.releases[0].guarantee > 1.5,
            "the old rule would have accused this: {:?}",
            a.releases[0].guarantee
        );
        assert_eq!(a.level, EvidenceLevel::Weak, "{:?}", a.reasons);
        assert_eq!(a.outcome, Outcome::Inconclusive, "{:?}", a.reasons);
        assert!(a.releases[0].coincidence_probability > COINCIDENCE_MAX_ABOVE_WEAK);
    }

    #[test]
    fn repeated_spans_that_share_a_code_no_longer_drown_a_genuine_finding() {
        // The other side of the same measurement: four sites of one release confirmed
        // at 4 bits in a candidate that repeats each protected statement sixteen
        // times. Counting spans set a bound of 4.0, which covered the whole count and
        // refused the verdict; the four codes the spans actually carry set a bound of
        // 0.25, whose tail past four is 1.3e-4. This is a copy and now says so.
        let sites: Vec<SiteMatch> = (0..4)
            .map(|i| {
                shared(
                    confirmed_at(if i < 2 { "src/a.js" } else { "src/b.js" }),
                    16,
                )
            })
            .collect();
        let a = assess(&detection(vec![release(sites)], false));
        assert_eq!(a.releases[0].probes, 64, "the spans the scan looked at");
        assert_eq!(a.releases[0].draws, 4, "the codes it was really offered");
        assert!(a.releases[0].chance < 0.26, "{:?}", a.releases[0]);
        assert_eq!(a.outcome, Outcome::ProvenanceDetected, "{:?}", a.reasons);
        assert_eq!(a.level, EvidenceLevel::Moderate, "{:?}", a.reasons);
    }

    #[test]
    fn the_bound_lowers_a_count_that_chance_could_have_produced() {
        // Eight confirmations, but 1_000 spans stood at *each* of their addresses:
        // at 4 bits a site with that many visitors is expected to confirm, so the
        // count says STRONG and the arithmetic says WEAK.
        let sites: Vec<SiteMatch> = (0..8)
            .map(|_| probed(confirmed_at("src/a.js"), 1_000))
            .collect();
        let a = assess(&detection(vec![release(sites)], false));
        assert_eq!(a.level, EvidenceLevel::Weak, "{:?}", a.reasons);
        // …and the verdict follows the arithmetic, not the count: eight probed
        // addresses owe the scan eight coincidences, so confirming all eight says
        // nothing about where the candidate came from.
        assert_eq!(a.outcome, Outcome::Inconclusive, "{:?}", a.reasons);
        assert!(
            a.reasons.iter().any(|r| r.contains("capped")),
            "{:?}",
            a.reasons
        );
        assert!(
            a.reasons.iter().any(|r| r.contains("coincidence bound")),
            "{:?}",
            a.reasons
        );
        // The difference between the two bounds is where the probes sit, not how
        // many there are: the same 8_000 comparisons over eight *separate* single
        // addresses expect 500 hits and cover nothing, while concentrated here they
        // expect eight — which is why the report prints both.
        assert_eq!(a.releases[0].probes, 8_000);
        assert!(a.releases[0].chance <= a.releases[0].sites as f64);
    }

    #[test]
    fn a_lead_the_bound_covers_is_reported_and_not_claimed() {
        // One confirmation among 112 spans standing at its address at 4 bits, which
        // is what the §27 corpus produced: that one site is nearly certain to
        // confirm by luck, and the three LocationOnly addresses add their own share,
        // so the bound expects 2.5 and this is an unrelated tree with a coincidence
        // in it. The honest verb is "cannot say".
        let mut sites = vec![probed(confirmed_at("src/a.js"), 112)];
        sites
            .extend((0..3).map(|_| probed(site(SiteStatus::LocationOnly, "src/b.js", vec![]), 11)));
        let a = assess(&detection(vec![release(sites)], false));
        assert_eq!(a.level, EvidenceLevel::Weak);
        assert_eq!(a.outcome, Outcome::Inconclusive, "{:?}", a.reasons);
        assert_eq!(
            a.outcome.exit_code(),
            swp_core::ErrorCode::InsufficientEvidence.exit_code()
        );
        // The lead is still in the document, with the number that covers it.
        assert_eq!(a.releases[0].fragments, 1);
        assert_eq!(a.releases[0].probes, 145);
        assert!(
            a.reasons.iter().any(|r| r.contains("INCONCLUSIVE")),
            "the reason must say what the scan refused to claim: {:?}",
            a.reasons
        );
        assert!(a
            .reasons
            .iter()
            .any(|r| r.contains("not counted as evidence")));
    }

    #[test]
    fn a_lead_a_verdict_cannot_stand_on_is_reported_and_not_claimed() {
        // Two spans at one site's address carry two codes, which expect 0.121
        // coincidences: one confirmation leaves 0.879 of the bound clear in the old
        // additive reading, and a probability of 0.11 that an unrelated tree produced
        // it. Both rules refuse it now — a lone fragment is WEAK on the ladder and
        // nowhere near the floor on the arithmetic — and the scan says so in words.
        let a = assess(&detection(
            vec![release(vec![probed(confirmed_at("src/a.js"), 2)])],
            false,
        ));
        assert_eq!(a.level, EvidenceLevel::Weak);
        assert!(a.releases[0].guarantee > 0.8, "{:?}", a.releases[0]);
        assert!(
            a.releases[0].coincidence_probability > COINCIDENCE_MAX_ABOVE_WEAK,
            "{:?}",
            a.releases[0]
        );
        assert_eq!(a.outcome, Outcome::Inconclusive, "{:?}", a.reasons);
        assert!(
            a.reasons
                .iter()
                .any(|r| r.contains("with probability") && r.contains("INCONCLUSIVE")),
            "the reason must name the rule that refused it: {:?}",
            a.reasons
        );

        // The floor itself, at the narrowest tag: two fragments of one constellation
        // over two draws are a 7.2e-3 event, which the counts call MODERATE and the
        // arithmetic refuses. This is the pair of confirmations the old rule accused
        // on, and it is why the gate is a probability now.
        let narrow = assess(&detection(
            vec![release(vec![
                probed(confirmed_at("src/a.js"), 1),
                probed(confirmed_at("src/b.js"), 1),
            ])],
            false,
        ));
        assert_eq!(narrow.level, EvidenceLevel::Weak, "{:?}", narrow.reasons);
        assert_eq!(
            narrow.outcome,
            Outcome::Inconclusive,
            "{:?}",
            narrow.reasons
        );
        assert!(
            narrow.releases[0].guarantee > 1.8,
            "{:?}",
            narrow.releases[0]
        );

        // The same two sites at an 8-bit tag: 3.0e-5, which clears the floor, and the
        // verdict follows the evidence.
        let wide = assess(&detection(
            vec![release_at(
                8,
                vec![
                    probed(confirmed_at("src/a.js"), 1),
                    probed(confirmed_at("src/b.js"), 1),
                ],
            )],
            false,
        ));
        assert_eq!(wide.level, EvidenceLevel::Moderate, "{:?}", wide.reasons);
        assert_eq!(
            wide.outcome,
            Outcome::ProvenanceDetected,
            "{:?}",
            wide.reasons
        );
    }

    #[test]
    fn a_fingerprint_clears_a_bound_the_tag_counts_do_not() {
        // The other half of `clears_chance`: an exact tree hash is not a truncated
        // tag that lined up, so it is a finding even with no fragments counted.
        let mut r = release(vec![]);
        r.fingerprint = FingerprintCheck::Matched;
        let a = assess(&detection(vec![r], false));
        assert_eq!(a.level, EvidenceLevel::VeryStrong, "{:?}", a.reasons);
        assert_eq!(a.outcome, Outcome::ProvenanceDetected, "{:?}", a.reasons);
        assert!(
            a.releases[0].guarantee <= 0.0,
            "the point of the test is that the counts alone would not carry it",
        );
    }
}
