//! The seven evidence categories §22 asks for, and how each one is earned.
//!
//! A detection run answers a question about spans. An *evidence item* answers the
//! same question in the form a person can act on: what was seen, where it was seen,
//! what it was seen against, why it counts, and how much it counts for. §22's
//! prohibition is against printing `MATCH`; the corresponding obligation is that
//! every item here names its own basis, in terms a reviewer who has never read this
//! code can check.
//!
//! ```text
//! EXACT_SOURCE_MATCH        the candidate's canonical tree hashes to the
//!                           fingerprint this release published (§16)
//! WATERMARK_FRAGMENT_MATCH  a keyed site's address is present *and* the literal
//!                           there carries the code this project derives for it
//! PARTIAL_WATERMARK_MATCH   some but not every keyed site of a release is
//!                           accounted for — the constellation, not one star
//! CANONICAL_MATCH           the address was reproduced only through the
//!                           rename-tolerant keys: same canonical content,
//!                           different identifiers
//! STRUCTURAL_MATCH          the address is present and the code is not. Reported,
//!                           never counted as provenance (§51)
//! TOKEN_MATCH               a rendering-shaped token run — not a lone literal —
//!                           sits at the address and carries the code
//! NEGATIVE_CONTROL          nothing of this release is present, with the probe
//!                           counts that make the "nothing" auditable (§27)
//! ```
//!
//! ## Items are observations; the level is not built from them
//!
//! One site can legitimately produce three items: a fragment confirmed through the
//! abstracted keys at a multi-token span is the same *site* seen three ways. So
//! [`crate::level`] reads the detection's site list directly and never sums item
//! counts — otherwise a single statement copy-pasted into one file with two keys
//! and a rendering would look like three-quarters of a constellation.
//!
//! ## What never appears in an item
//!
//! No expected tag, no derived key, no root secret, and no raw location id beyond
//! the truncated handle already present in the private manifest: an expected tag in
//! a report is a copy of the watermark, and a report is the one artifact of a scan
//! that gets forwarded to other people. `basis` strings are built from counts,
//! paths, line numbers and the family name, which is what §29's leak sweep holds
//! this to.

use serde::{Deserialize, Serialize};
use swp_core::version::{SchemaVersion, SWP_PROTOCOL_NAME};
use swp_detection::{Detection, ReleaseDetection, SiteMatch, SiteStatus};

use crate::level::EvidenceLevel;

/// Where an observation was made, in somebody's coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    /// Project-relative path, forward slashes.
    pub file: String,
    /// One-based line, as the adapter counted it.
    pub line: u32,
    /// The matched text, truncated to the manifest's hint bound. Present for a
    /// candidate-side region, absent for a source-side one, because our own
    /// literal is in our own manifest and repeating it in a report helps nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    /// How many tokens the matched span covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u8>,
    /// Which of the release's four keyed radii reproduced this span.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub radii: Vec<String>,
}

/// One thing a scan observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    /// Stable handle for a citation: `EV-001`. Ordering is deterministic, so the
    /// same scan of the same tree produces the same ids.
    pub id: String,
    pub kind: EvidenceKind,
    pub project_id: String,
    pub release_id: String,
    /// Where it was found in the candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Region>,
    /// Where the corresponding site was in our protected release. Never a lookup
    /// key — provenance does not depend on file layout — but the line a reviewer
    /// opens first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_region: Option<Region>,
    /// Why this counts, in words, with the measured numbers in it.
    pub basis: String,
    /// The strength of *this item*, on the same ladder as the overall level, so a
    /// reader who stops at one line stops at an honest line.
    pub strength: EvidenceLevel,
    pub protocol: String,
    pub schema: u16,
}

impl EvidenceItem {
    fn new(
        kind: EvidenceKind,
        release: &ReleaseDetection,
        basis: String,
        strength: EvidenceLevel,
    ) -> Self {
        EvidenceItem {
            id: String::new(),
            kind,
            project_id: release.project_id.as_str().to_string(),
            release_id: release.release_id.as_str().to_string(),
            location: None,
            source_region: None,
            basis,
            strength,
            protocol: SWP_PROTOCOL_NAME.to_string(),
            schema: SchemaVersion::REPORT_V1.0,
        }
    }

    fn at(mut self, location: Region, source: Region) -> Self {
        self.location = Some(location);
        self.source_region = Some(source);
        self
    }
}

/// The category of an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    /// §16's whole-tree channel: byte-identical canonical source.
    ExactSourceMatch,
    /// A keyed site carrying its code.
    WatermarkFragmentMatch,
    /// A release partly present.
    PartialWatermarkMatch,
    /// Present as canonicalized content, absent as written text.
    CanonicalMatch,
    /// Address without code.
    StructuralMatch,
    /// A rendering rather than a literal.
    TokenMatch,
    /// An audited non-match.
    NegativeControl,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::ExactSourceMatch => "EXACT_SOURCE_MATCH",
            EvidenceKind::WatermarkFragmentMatch => "WATERMARK_FRAGMENT_MATCH",
            EvidenceKind::PartialWatermarkMatch => "PARTIAL_WATERMARK_MATCH",
            EvidenceKind::CanonicalMatch => "CANONICAL_MATCH",
            EvidenceKind::StructuralMatch => "STRUCTURAL_MATCH",
            EvidenceKind::TokenMatch => "TOKEN_MATCH",
            EvidenceKind::NegativeControl => "NEGATIVE_CONTROL",
        }
    }

    /// Whether this category states provenance rather than corroborates it.
    ///
    /// `STRUCTURAL_MATCH` and `NEGATIVE_CONTROL` are the two that do not: the first
    /// is what an innocent copy of unprotected code looks like, and the second is a
    /// statement about absence.
    pub fn asserts_provenance(self) -> bool {
        !matches!(
            self,
            EvidenceKind::StructuralMatch | EvidenceKind::NegativeControl
        )
    }

    /// Every category, so the tests can assert the table is exhaustive.
    pub const ALL: &'static [EvidenceKind] = &[
        EvidenceKind::ExactSourceMatch,
        EvidenceKind::WatermarkFragmentMatch,
        EvidenceKind::PartialWatermarkMatch,
        EvidenceKind::CanonicalMatch,
        EvidenceKind::StructuralMatch,
        EvidenceKind::TokenMatch,
        EvidenceKind::NegativeControl,
    ];
}

/// The items a scan produced, in a deterministic order: best release first, then
/// each release's aggregate items, then its per-site items by site index.
pub fn collect(detection: &Detection) -> Vec<EvidenceItem> {
    let mut out = Vec::new();
    for release in ordered(detection) {
        out.extend(release_items(release));
        for site in &release.sites {
            out.extend(site_items(release, site));
        }
    }
    for (n, item) in out.iter_mut().enumerate() {
        item.id = format!("EV-{n:03}");
    }
    out
}

/// Strongest release first, so a report's first page is about the copy rather than
/// about the nine other projects it was also checked against. Ties keep the index
/// order, which is newest-release-first from `swp-detection`.
fn ordered(detection: &Detection) -> Vec<&ReleaseDetection> {
    let mut order: Vec<usize> = (0..detection.releases.len()).collect();
    order.sort_by(|a, b| {
        let (x, y) = (&detection.releases[*b], &detection.releases[*a]);
        y.confirmed()
            .cmp(&x.confirmed())
            .then(y.confirmed_bits().cmp(&x.confirmed_bits()))
            .then(y.fingerprint.matched().cmp(&x.fingerprint.matched()))
    });
    order.into_iter().map(|i| &detection.releases[i]).collect()
}

fn release_items(release: &ReleaseDetection) -> Vec<EvidenceItem> {
    let mut out = Vec::new();
    let confirmed = release.confirmed();
    let total = release.total();

    if release.fingerprint.matched() {
        out.push(EvidenceItem::new(
            EvidenceKind::ExactSourceMatch,
            release,
            format!(
                "the canonicalized candidate tree hashes to the fingerprint this release \
                 published at level {} ({}/{} sites of it also carry their code)",
                release.fingerprint.as_str(),
                confirmed,
                total
            ),
            EvidenceLevel::VeryStrong,
        ));
    }

    if confirmed > 0 && confirmed < total {
        out.push(EvidenceItem::new(
            EvidenceKind::PartialWatermarkMatch,
            release,
            format!(
                "{confirmed} of {total} keyed sites are present: {} carry the code at their \
                 address, {} show the address without the code, {} have no matching span at all",
                confirmed,
                release.stripped(),
                release.absent()
            ),
            // The partial channel is about *how much* survived, so it borrows its
            // strength from coverage rather than asserting one of its own.
            crate::level::partial_level(confirmed, total),
        ));
    }

    if confirmed == 0 && release.stripped() == 0 {
        out.push(EvidenceItem::new(
            EvidenceKind::NegativeControl,
            release,
            format!(
                "no site of this release was reproduced: {} literal hypotheses and {} rendering \
                 hypotheses were keyed and looked up over {} candidate file(s), and {} span(s) \
                 reached a tag comparison",
                release.literals_tried,
                release.windows_tried,
                release.candidate_files,
                release.probes()
            ),
            EvidenceLevel::None,
        ));
    }
    out
}

fn site_items(release: &ReleaseDetection, site: &SiteMatch) -> Vec<EvidenceItem> {
    if site.status == SiteStatus::Absent {
        return Vec::new();
    }
    let radii: Vec<String> = site.slots.iter().map(|k| k.as_str().to_string()).collect();
    let found = Region {
        file: site.found_in.clone().unwrap_or_default(),
        line: site.found_line.unwrap_or(0),
        excerpt: site.found_text.clone(),
        tokens: Some(site.found_tokens),
        radii: radii.clone(),
    };
    let source = Region {
        file: site.manifest_file.clone(),
        line: site.manifest_line,
        excerpt: None,
        tokens: None,
        radii,
    };
    let width = format!("{}-bit", site.width);

    if site.status == SiteStatus::LocationOnly {
        return vec![EvidenceItem::new(
            EvidenceKind::StructuralMatch,
            release,
            format!(
                "the candidate reproduces this site's keyed address ({} of four radii) but the \
                 text there is not this project's code; a copy of the same source from before \
                 protection, or with the fragments stripped, looks identical to this",
                site.slots.len()
            ),
            EvidenceLevel::Weak,
        )
        .at(found, source)];
    }

    let mut out = Vec::new();
    let exact = site.status == SiteStatus::ExactRendering;
    out.push(
        EvidenceItem::new(
            EvidenceKind::WatermarkFragmentMatch,
            release,
            format!(
            "the {} literal at {}:{} decodes under the {} family to the {} code this project's \
             key derives for this address{}",
            site.class.as_str(),
            found.file,
            found.line,
            site.family.as_str(),
            width,
            if exact {
                ", and it is byte-for-byte the rendering the manifest recorded"
            } else {
                ""
            }
        ),
            // An exact rendering is a stronger statement than a decoding one: the first
            // says our bytes are sitting there, the second says a code is.
            if exact {
                EvidenceLevel::Strong
            } else if site.slots.len() > 1 {
                EvidenceLevel::Moderate
            } else {
                EvidenceLevel::Weak
            },
        )
        .at(found.clone(), source.clone()),
    );

    // The two channels below describe *how* a confirmed site was reached, and are
    // reported separately because each is a different thing to check by hand.
    if site.found_tokens > 1 {
        out.push(
            EvidenceItem::new(
                EvidenceKind::TokenMatch,
                release,
                format!(
                "the matched span is {} tokens wide, so it is a rendering rather than a source \
                 literal: our writer's expansion shape is present at this address",
                site.found_tokens
            ),
                EvidenceLevel::Moderate,
            )
            .at(found, source),
        );
    } else if site.refactored() {
        out.push(
            EvidenceItem::new(
                EvidenceKind::CanonicalMatch,
                release,
                format!(
                "the address was reproduced only through the rename-tolerant radii ({}), so the \
                 surrounding statement matches this release canonically while differing as text",
                site.slots.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
            ),
                EvidenceLevel::Moderate,
            )
            .at(found, source),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_core::LiteralClass;
    use swp_detection::{FingerprintCheck, InputKind, ReleaseDetection, SiteMatch, SLOT_COUNT};

    fn site(status: SiteStatus, tokens: u8) -> SiteMatch {
        SiteMatch {
            site: 0,
            manifest_file: "src/a.js".into(),
            manifest_line: 3,
            language: "javascript".into(),
            adapter: "ast".into(),
            class: LiteralClass::Integer,
            family: swp_core::FormFamily::Add,
            width: 4,
            primary: 0,
            locations: [swp_core::LocationId::default(); SLOT_COUNT],
            status,
            slots: vec![swp_core::RadiusKind::StatementId],
            found_in: Some("copy/a.js".into()),
            found_line: Some(11),
            found_text: Some("(995 + 5)".into()),
            found_tokens: tokens,
            probes: 1,
        }
    }

    fn detection(releases: Vec<ReleaseDetection>) -> Detection {
        Detection {
            described: "candidate".into(),
            kind: InputKind::Directory,
            releases,
            files_scanned: 3,
            bytes_scanned: 100,
            omissions: Vec::new(),
            notes: Vec::new(),
            partial: false,
        }
    }

    fn release(sites: Vec<SiteMatch>, fingerprint: FingerprintCheck) -> ReleaseDetection {
        ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: 4,
            sites,
            fingerprint,
            candidate_files: 3,
            literals_tried: 400,
            windows_tried: 90,
        }
    }

    #[test]
    fn every_kind_names_itself_and_declares_whether_it_proves_anything() {
        assert_eq!(
            EvidenceKind::ALL.len(),
            7,
            "seven evidence categories, and ALL must hold all of them"
        );
        for kind in EvidenceKind::ALL {
            assert!(kind.as_str().chars().next().unwrap().is_ascii_uppercase());
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(
                kind.as_str(),
                json.as_str().unwrap(),
                "serde and `as_str` must agree, or the JSON report and the text report \
                 will name the same observation twice under two spellings"
            );
        }
        assert!(!EvidenceKind::StructuralMatch.asserts_provenance());
        assert!(!EvidenceKind::NegativeControl.asserts_provenance());
        assert_eq!(
            EvidenceKind::ALL
                .iter()
                .filter(|k| k.asserts_provenance())
                .count(),
            5
        );
    }

    #[test]
    fn a_clean_scan_still_produces_an_auditable_negative_item() {
        let items = collect(&detection(vec![release(
            vec![site(SiteStatus::Absent, 0)],
            FingerprintCheck::NotMatched,
        )]));
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].kind, EvidenceKind::NegativeControl);
        assert!(items[0].basis.contains("400"), "{}", items[0].basis);
        assert_eq!(items[0].strength, EvidenceLevel::None);
    }

    #[test]
    fn an_address_without_a_code_is_structural_and_never_asserts_provenance() {
        let items = collect(&detection(vec![release(
            vec![site(SiteStatus::LocationOnly, 1)],
            FingerprintCheck::NotMatched,
        )]));
        let kinds: Vec<_> = items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [EvidenceKind::StructuralMatch], "{items:?}");
        assert!(!items[0].kind.asserts_provenance());
        assert!(items[0].basis.contains("looks identical to this"));
    }

    #[test]
    fn a_rendering_hit_reports_the_fragment_and_the_token_channel() {
        let items = collect(&detection(vec![release(
            vec![site(SiteStatus::TagConfirmed, 5)],
            FingerprintCheck::NotMatched,
        )]));
        let kinds: Vec<_> = items.iter().map(|i| i.kind).collect();
        assert!(
            kinds.contains(&EvidenceKind::WatermarkFragmentMatch),
            "{kinds:?}"
        );
        assert!(kinds.contains(&EvidenceKind::TokenMatch), "{kinds:?}");
        assert_eq!(items[0].location.as_ref().unwrap().tokens, Some(5));
    }

    #[test]
    fn ids_are_sequential_and_stable_for_the_same_detection() {
        let d = detection(vec![release(
            vec![site(SiteStatus::ExactRendering, 5)],
            FingerprintCheck::Matched,
        )]);
        let first = collect(&d);
        let second = collect(&d);
        assert_eq!(first, second);
        assert!(first
            .iter()
            .enumerate()
            .all(|(n, i)| i.id == format!("EV-{n:03}")));
        assert_eq!(first[0].kind, EvidenceKind::ExactSourceMatch);
    }
}
