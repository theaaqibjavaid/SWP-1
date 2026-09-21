//! §23's evidence level: five named steps, one rule that fired, no percentage.
//!
//! ## Why a level and not a probability
//!
//! "97.2% probability of copying" would need a model of how often people copy code,
//! which nobody running this tool has measured for any population. What *is*
//! computable from a scan is the other side of the question: given how many
//! candidate spans were offered a tag comparison, and given that a tag is an HMAC
//! output truncated to `w` bits, the number of confirmations an unrelated tree
//! should produce by chance is bounded by
//!
//! ```text
//! chance = probes × 2^-w
//! ```
//!
//! where `probes` counts only spans that reproduced a manifest address. It is a
//! union bound over the comparisons actually performed, so it is an upper limit on
//! coincidence rather than a claim about any particular copy, and the report prints
//! it as that. The level below then asks how many confirmations are left over once
//! the bound is subtracted, which is the only question arithmetic can answer here.
//!
//! The bound is not always small. A site's address is a digest of the code around
//! it with the site hidden, abstracted over local names and over every other
//! literal's value, which is what lets a renamed or reformatted copy still be
//! found — and what makes an ordinary one-line `var step = 4;` inside an ordinary
//! arithmetic function reproduce an address another project published. A scan of an
//! unrelated tree can therefore record hundreds of probes and a handful of
//! confirmations, all of it within what chance owes. That is why the bound decides
//! the *verdict* and not only the level: [`ReleaseTally::clears_chance`] is the
//! line between "this carries our release" and "this is a lead", and a scan that
//! cannot cross it says `INCONCLUSIVE` rather than accusing anybody (§27, §51).
//! Clearing it is necessary and not sufficient — the verdict also needs the level
//! to have reached `MODERATE`, so that a two-literal candidate cannot buy a finding
//! simply by being too small to set a wide bound. A verdict may say no more than
//! the ladder already said.
//!
//! ## What the ladder is
//!
//! The steps are protocol conventions, not measurements: they are chosen so that
//! one 4-bit fragment cannot on its own produce more than `WEAK`, and so that a
//! level above `WEAK` needs either several addresses or several independent files.
//! They are stated here as constants, listed in `docs/REPORTS.md`, and their
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
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
/// Confirmations the coincidence bound cannot account for, required at each step
/// above `WEAK`. `1.5` means "at least one whole event over the bound, and not by
/// rounding"; the higher steps are `3` and `6`.
pub const GUARANTEE_ABOVE_WEAK: f64 = 1.5;
pub const GUARANTEE_FOR_STRONG: f64 = 3.0;
pub const GUARANTEE_FOR_VERY_STRONG: f64 = 6.0;

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
    pub literals_tried: u64,
    pub windows_tried: u64,
    /// `"match"`, `"no-match"` or `"not-comparable"`.
    pub fingerprint: String,
    /// `probes × 2^-tag_bits`: the upper bound on coincidental confirmations.
    pub chance: f64,
    /// Confirmations above that bound.
    pub guarantee: f64,
    pub level: EvidenceLevel,
    /// The rules that produced `level`, in plain sentences with the numbers in them.
    pub reasons: Vec<String>,
}

impl ReleaseTally {
    /// Whether this release is strong enough to be reported as a finding.
    ///
    /// Two requirements, and the second is not a restatement of the first:
    ///
    /// * the count has to clear the coincidence bound the candidate's own probe
    ///   volume sets — `fragments > probes × 2^-w`, which is what `guarantee`
    ///   measures; and
    /// * the grade has to reach `MODERATE`, or the §16 fingerprint has to have
    ///   matched.
    ///
    /// The first rule alone leaves a hole worth naming, because a thin candidate
    /// makes the bound small: one 4-bit confirmation against two probes scores
    /// `guarantee ≈ 0.88` and passes, while the ladder is explicit that a single
    /// fragment is a lead to look at rather than proof of copying. A verdict is
    /// allowed to say only what its evidence level already says — which is the
    /// §27 requirement, and the reason `WEAK` and `None` are excluded here rather
    /// than only in the explanation.
    pub fn clears_chance(&self) -> bool {
        self.fingerprint == "match"
            || (self.guarantee > 0.0 && self.level >= EvidenceLevel::Moderate)
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
    let site_probes: Vec<u32> = release.sites.iter().map(|s| s.probes).collect();
    let probes = release.probes();
    let chance = chance_of_coincidence(&site_probes, release.tag_bits);
    let loose = union_bound_of_coincidence(probes, release.tag_bits);
    let fragments = release.confirmed();
    let guarantee = fragments as f64 - chance;
    let (level, mut reasons) = grade(
        fragments,
        files.len(),
        release.fingerprint.matched(),
        chance,
        guarantee,
    );
    reasons.push(format!(
        "coincidence bound: {probes} span(s) reached a {}-bit tag comparison at {} site(s), so an \
         unrelated tree holding those addresses and none of this project's codes is expected to \
         confirm at most {chance:.4} of them by chance ({loose:.4} if nothing is assumed about \
         spans sharing an address); {:.4} remain",
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
        literals_tried: release.literals_tried,
        windows_tried: release.windows_tried,
        fingerprint: release.fingerprint.as_str().to_string(),
        chance,
        guarantee,
        level,
        reasons,
    }
}

/// Expected coincidental confirmations for one release, computed where the width
/// is validated rather than trusted.
///
/// `site_probes` is how many candidate spans reached a tag comparison *at each
/// site*, so the sum is [`ReleaseTally::probes`]. A site contributes
/// `1 − (1 − 2^-w)^n`: the chance that at least one of its `n` spans carries this
/// project's `w`-bit code by luck. Summing the probes instead — the assumption-free
/// union bound `Σ n × 2^-w` — would say that four spans at one address can produce
/// four confirmations of the same site, and at a 4-bit tag over a self-similar
/// candidate it returns a bound larger than the number of sites, which is not a
/// statement anyone should print about evidence. What the tighter formula buys is
/// the assumption that spans sharing an address have independent tags, which is
/// true of unrelated source and false only of a tree that duplicates one
/// watermarked statement — where it errs by counting a second copy of real
/// evidence as a second chance to be fooled.
pub fn chance_of_coincidence(site_probes: &[u32], tag_bits: u8) -> f64 {
    let rate = match TagWidth::new(tag_bits) {
        Ok(width) => width.null_hit_probability(),
        // A width this build does not know cannot be graded, and must not be
        // graded generously: rate 1.0 means every site it probed is expected.
        Err(_) => 1.0,
    };
    site_probes
        .iter()
        .map(|&n| match n {
            0 => 0.0,
            _ => 1.0 - (1.0 - rate).powf(n as f64),
        })
        .sum()
}

/// The same expectation without the independence assumption: an upper bound, and
/// a loose one. Printed alongside the tight figure so the reader can see how much
/// of the verdict the assumption carries.
pub fn union_bound_of_coincidence(probes: u32, tag_bits: u8) -> f64 {
    let rate = match TagWidth::new(tag_bits) {
        Ok(width) => width.null_hit_probability(),
        Err(_) => 1.0,
    };
    probes as f64 * rate
}

/// The ladder, as a function of measured counts, so the same rules grade a scan
/// and a verification run.
fn grade(
    fragments: usize,
    files: usize,
    fingerprint_matched: bool,
    chance: f64,
    guarantee: f64,
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
    // The guarantee can only ever lower the level, never raise it: arithmetic about
    // coincidence is not a substitute for having the fragments.
    let allowed = if guarantee >= GUARANTEE_FOR_VERY_STRONG {
        EvidenceLevel::VeryStrong
    } else if guarantee >= GUARANTEE_FOR_STRONG {
        EvidenceLevel::Strong
    } else if guarantee >= GUARANTEE_ABOVE_WEAK {
        EvidenceLevel::Moderate
    } else {
        EvidenceLevel::Weak
    };
    let level = counted.min(allowed);
    if level < counted {
        reasons.push(format!(
            "{fragments} confirmation(s) against a coincidence bound of {:.4} expected by chance: \
             the bound cannot rule the extra ones out, so the level is capped at {level} whatever \
             the count would otherwise have earned (it reached {counted} on counts alone)",
            chance
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
            .then(
                (b.fingerprint == "match")
                    .cmp(&(a.fingerprint == "match")),
            )
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
            reasons.push(if t.guarantee <= 0.0 {
                format!(
                    "{} confirmation(s) against a bound of {:.4} an unrelated tree is expected to \
                     produce: the bound covers them, so this scan reports the candidate as \
                     INCONCLUSIVE rather than as carrying this release. Nothing here distinguishes \
                     it from an unrelated project, and a wider tag or a larger constellation would.",
                    t.fragments, t.chance
                )
            } else {
                format!(
                    "{} confirmation(s) clear the bound of {:.4} an unrelated tree is expected to \
                     produce, but {level} is the grade a verdict cannot be printed on: a lead this \
                     thin is reported as evidence to look at and as INCONCLUSIVE, not as this \
                     release being present.",
                    t.fragments, t.chance
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
        }
    }

    /// One release made of the given sites, at 4 bits.
    fn release(sites: Vec<SiteMatch>) -> ReleaseDetection {
        ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: 4,
            sites,
            fingerprint: FingerprintCheck::NotMatched,
            candidate_files: 3,
            literals_tried: 10,
            windows_tried: 10,
        }
    }

    /// How many spans stood at this site's address.
    fn probed(mut m: SiteMatch, n: u32) -> SiteMatch {
        m.probes = n;
        m
    }

    fn confirmed_at(file: &str) -> SiteMatch {
        site(SiteStatus::TagConfirmed, file, vec![RadiusKind::StatementId])
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
        // One span each at sixteen sites: the two formulas agree, at one expected hit.
        assert!((chance_of_coincidence(&[1; 16], 4) - 1.0).abs() < 1e-12);
        assert!((union_bound_of_coincidence(16, 4) - 1.0).abs() < 1e-12);
        // Sixteen spans at ONE site cannot confirm it sixteen times.
        assert!(
            (chance_of_coincidence(&[16], 4) - (1.0 - (15.0f64 / 16.0).powi(16))).abs() < 1e-12
        );
        assert!(
            (chance_of_coincidence(&[100], 8) - (1.0 - (255.0f64 / 256.0).powi(100))).abs()
                < 1e-12
        );
        let tight = chance_of_coincidence(&[16, 16, 16], 4);
        assert!((tight - 3.0 * (1.0 - (15.0f64 / 16.0).powi(16))).abs() < 1e-9);
        assert!(tight < union_bound_of_coincidence(48, 4));
        // A huge probe count cannot push the expectation past the sites it covers,
        // which is the failure a printed bound must never have.
        assert!(chance_of_coincidence(&[100_000; 24], 4) <= 24.0);
        // An unknown width is graded as if every probed site could coincide.
        assert_eq!(chance_of_coincidence(&[1, 1, 1], 9), 3.0);
        assert_eq!(union_bound_of_coincidence(3, 9), 3.0);
    }

    #[test]
    fn one_fragment_is_weak_even_though_the_ladder_would_not_say_so() {
        // 1 confirmation, 1 probe, 4 bits -> chance 0.0625, guarantee ~0.94 < 1.5.
        let (level, _) = grade(1, 1, false, 0.0625, 1.0 - 0.0625);
        assert_eq!(level, EvidenceLevel::Weak);
        let (eight, _) = grade(8, 4, false, 0.5, 7.5);
        assert_eq!(eight, EvidenceLevel::VeryStrong);
    }

    #[test]
    fn a_bound_that_explains_the_hits_caps_the_level_without_inventing_hits() {
        // 12 address-matched sites at 4 bits, 12 confirmations: chance 0.75 each is
        // not the shape here, so use a wide probe count that makes the bound bite.
        let (level, reasons) = grade(4, 1, false, 3.2, 0.8);
        assert_eq!(level, EvidenceLevel::Weak, "{reasons:?}");
        assert!(
            reasons.iter().any(|r| r.contains("coincidence bound")),
            "{reasons:?}"
        );
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
        let clean = detection(vec![release(vec![site(SiteStatus::Absent, "", vec![])])], false);
        let a = assess(&clean);
        assert_eq!(a.outcome, Outcome::NoProvenanceDetected);
        assert_eq!(a.level, EvidenceLevel::None);

        let unread = detection(vec![release(vec![site(SiteStatus::Absent, "", vec![])])], true);
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
        assert!(a.reasons.iter().any(|r| r.contains("not counted as evidence")));
    }

    #[test]
    fn a_spread_constellation_survives_the_bound_and_is_graded_by_the_counts() {
        let sites: Vec<SiteMatch> = (0..8)
            .map(|i| confirmed_at(match i {
                0..=2 => "src/a.js",
                3..=5 => "src/b.js",
                _ => "src/c.js",
            }))
            .collect();
        let a = assess(&detection(vec![release(sites)], false));
        assert_eq!(a.level, EvidenceLevel::VeryStrong, "{:?}", a.reasons);
        assert_eq!(a.outcome, Outcome::ProvenanceDetected);
        assert_eq!(a.releases[0].files, 3);
        assert_eq!(a.releases[0].bits, 32);
        // Eight confirmations over eight probes at 4 bits leaves 7.5 above the bound.
        assert!(a.releases[0].guarantee > 7.4, "{:?}", a.releases[0]);
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
        assert!(a.reasons.iter().any(|r| r.contains("capped")), "{:?}", a.reasons);
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
        sites.extend(
            (0..3)
                .map(|_| probed(site(SiteStatus::LocationOnly, "src/b.js", vec![]), 11)),
        );
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
        assert!(a.reasons.iter().any(|r| r.contains("not counted as evidence")));
    }

    #[test]
    fn a_lead_below_the_verdict_floor_is_reported_and_not_claimed_even_when_it_clears() {
        // The bound is not the only thing a verdict has to clear. Two spans at one
        // site's address expect 0.121 coincidences, so one confirmation leaves 0.879
        // of guarantee — the arithmetic is on its side and the ladder is not: one
        // fragment is WEAK, and WEAK is the level §23 defines as "a lead worth
        // manual review". A thin candidate must not be able to buy a verdict just
        // by being thin.
        let a = assess(&detection(vec![release(vec![probed(
            confirmed_at("src/a.js"),
            2,
        )])], false));
        assert_eq!(a.level, EvidenceLevel::Weak);
        assert!(a.releases[0].guarantee > 0.8, "{:?}", a.releases[0]);
        assert_eq!(a.outcome, Outcome::Inconclusive, "{:?}", a.reasons);
        assert!(
            a.reasons
                .iter()
                .any(|r| r.contains("clear the bound of") && r.contains("INCONCLUSIVE")),
            "the reason must name the rule that refused it: {:?}",
            a.reasons
        );

        // The floor itself: two fragments of one constellation over two probes clear
        // both rules, and the verdict follows.
        let b = assess(&detection(
            vec![release(vec![
                probed(confirmed_at("src/a.js"), 1),
                probed(confirmed_at("src/b.js"), 1),
            ])],
            false,
        ));
        assert_eq!(b.level, EvidenceLevel::Moderate, "{:?}", b.reasons);
        assert_eq!(b.outcome, Outcome::ProvenanceDetected, "{:?}", b.reasons);
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
