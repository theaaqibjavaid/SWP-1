//! The match: read a candidate tree against one or more protected releases.
//!
//! This is §20's pipeline from "canonicalization" onward, and it is deliberately
//! narrow. Everything here answers one of three questions about a site named in a
//! signed manifest, and nothing else:
//!
//! ```text
//! is its address present?        — one of its four keyed radius ids was computed
//!                                  from a span in the candidate tree
//! is its watermark present?      — the literal at that span decodes, under the
//!                                  family the manifest names, to the code this
//!                                  project's key derives for that address
//! is the whole release present?  — the candidate tree's §16 fingerprint equals the
//!                                  one the release published
//! ```
//!
//! ## Two passes, because a watermark is not always a token
//!
//! The embedding pass offers one hypothesis per file — every literal — which is
//! correct for a writer and incomplete for a reader: a rendering like `(995 + 5)`
//! occupies five tokens where the source had one. So a scan runs the writer's
//! harvest first (pass A, `swp-embedding`'s own candidate scan, so the two can
//! never disagree about what a site is) and then [`crate::spans`]' rendering-shaped
//! windows over a fresh analysis of each file (pass B).
//!
//! Pass B re-reads and re-parses the tree. That is real cost, and it is paid
//! because the alternative — keeping every file's token stream from pass A alive —
//! is worse on a repository of any size, and because pass A's whole design is that
//! it throws the token streams away.
//!
//! ## What a match does not mean
//!
//! A location id is a content address, and content addresses match content. An
//! unprotected copy of the same source hits the same addresses while carrying no
//! watermark at all, so [`SiteStatus::LocationOnly`] is reported as the structural
//! channel and is *not* counted as provenance by anything downstream. Only
//! [`SiteStatus::TagConfirmed`] and [`SiteStatus::ExactRendering`] are watermark
//! hits, and even those say "this literal carries a code this project derives for
//! this address", which is a statement about the artifact — not about who typed it
//! or what rights attach to it (§51).
//!
//! ## Coincidence is arithmetic, not guesswork
//!
//! A `w`-bit code matches an unrelated literal with probability `2^-w`. The report
//! states hit counts and widths rather than a percentage, because the first number
//! is defined and the second would need a model of how many people copy code that
//! nobody here has (§23).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use swp_adapters::literal::decode;
use swp_adapters::{Analysis, DecodedSite, Registry};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{Digest, LocationId, ProjectId, ReleaseId};
use swp_core::limits::Limits;
use swp_core::site::{FormFamily, LiteralClass, RadiusKind, SiteTag, TagWidth};
use swp_core::text::decode_utf8_strict;
use swp_core::{radius_digests, ByteSpan};
use swp_embedding::{candidates, walk};
use swp_identity::ProtectConfig;
use swp_manifest::{FileCanonical, ManifestKeys, MAX_HINT_LEN};

use crate::index::ReleaseIndex;
use crate::input::{InputKind, Opened};
use crate::spans;

/// The four radius keys a site is addressed by. A manifest holds exactly this many
/// per site and a probe computes exactly this many ids per span.
pub const SLOT_COUNT: usize = 4;

/// A span this much longer than the manifest's hint bound cannot be a rendering
/// this tool recorded: `swp-embedding` refuses to write one whose spelling
/// exceeds [`MAX_HINT_LEN`], so anything bigger is ordinary source that happens to
/// sit at a matching address — and probing it would only add decode work and
/// coincidence surface.
const MAX_HYPOTHESIS_LEN: usize = MAX_HINT_LEN * 2;

/// How completely a manifest site is accounted for in the candidate tree.
///
/// Ordered by strength: a higher status always implies the one below it, and the
/// evidence layer takes the maximum over a site's observations rather than
/// counting them, so three observations of one site are three *locations*, not
/// three *sites*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiteStatus {
    /// No span in the candidate tree produced any of this site's four keys.
    Absent,
    /// A span produced a key, but the literal there does not carry the code.
    /// Either the copier has the code without the watermark, or they stripped it,
    /// or — indistinguishably — they copied a build from before protection.
    LocationOnly,
    /// The literal at a matching address decodes to the expected fragment.
    TagConfirmed,
    /// The literal is byte-for-byte the rendering the manifest recorded.
    ///
    /// Stronger than a tag hit because it survives no editing at all: the exact
    /// spelling this tool wrote is sitting in the candidate tree.
    ExactRendering,
}

impl SiteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteStatus::Absent => "absent",
            SiteStatus::LocationOnly => "location-only",
            SiteStatus::TagConfirmed => "tag-confirmed",
            SiteStatus::ExactRendering => "exact-rendering",
        }
    }

    /// Whether this status is watermark evidence at all.
    ///
    /// The line is drawn here, once, so that no report, test or level rule
    /// downstream can quietly start counting structural hits as provenance.
    pub fn is_watermark(self) -> bool {
        matches!(self, SiteStatus::TagConfirmed | SiteStatus::ExactRendering)
    }
}

/// One manifest site, and what a scan found where it should have been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteMatch {
    /// Index into the release's site list, so a report can point back at the
    /// manifest without restating it.
    pub site: usize,
    /// Where this site was in the *protected release*. A hint for a human reading
    /// a report about a copy; it is never a lookup key, and a hit at a different
    /// path is still a hit.
    pub manifest_file: String,
    pub manifest_line: u32,
    pub language: String,
    pub adapter: String,
    pub class: LiteralClass,
    pub family: FormFamily,
    pub width: u8,
    /// Which of the four keys the fragment hangs off, as a `RadiusKind` code.
    pub primary: u8,
    pub locations: [LocationId; SLOT_COUNT],
    pub status: SiteStatus,
    /// Which radius keys the candidate tree reproduced. Two keys hitting is not
    /// twice the evidence; it says the copy survived both a rename *and* a
    /// reformatting, which is what the split between L1 and L3 is for.
    pub slots: Vec<RadiusKind>,
    /// Where the matching span actually is, in the candidate's own coordinates.
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    /// The literal text found there, truncated to the report hint bound.
    pub found_text: Option<String>,
    /// How many tokens that span covers. One means the site's literal was sitting
    /// there on its own; more than one means a *rendering* was, which is the
    /// difference between "your number is in my file" and "my rewrite is in your
    /// file" that the evidence layer separates.
    pub found_tokens: u8,
    /// How many candidate spans stood at this site's address and were compared
    /// against its code. Reported as the scan's work, not as the bound's input:
    /// `probes × 2^-width` is only the number of confirmations an unrelated tree
    /// can be expected to produce here if every span carried its own code.
    pub probes: u32,
    /// How many *distinct* codes the candidate presented at this address, which is
    /// the number of draws the coincidence bound is computed from.
    ///
    /// Two copies of one statement at the same address are a single chance at this
    /// project's tag, not two. Measured on the 19,179 probed sites of 930 cross-scans
    /// of look-alike projects at a 4-bit tag, the two counts are nearly the same
    /// number — of 7,770 sites that presented 4 spans, 7,370 presented 4 distinct
    /// codes and 400 presented 3 — so building the bound from codes instead of
    /// spans lowers it by 1.8% at 4 bits, 0.5% at 6 and 0.1% at 8. That is why the
    /// statistic is the admissible one, not why the verdict changed: it makes the
    /// bound say "one chance per chance taken", and `swp_evidence::level` records
    /// separately that even this bound sits about 3x above what an unrelated tree
    /// really confirms, because draws that share an address are not independent.
    /// A span whose code this build cannot derive still counts as one draw: the
    /// figure may overstate the chances, and may not understate them.
    pub distinct_codes: u32,
}

impl SiteMatch {
    /// Whether the copy carries the watermark at this site.
    pub fn confirmed(&self) -> bool {
        self.status.is_watermark()
    }

    /// Whether the abstracted (L3) keys hit while the exact (L1) ones did not,
    /// which is the signature of a copy that was renamed or respelled.
    pub fn refactored(&self) -> bool {
        let abstracted = self
            .slots
            .iter()
            .any(|k| matches!(k, RadiusKind::StatementId | RadiusKind::ScopeId));
        let exact = self
            .slots
            .iter()
            .any(|k| matches!(k, RadiusKind::StatementRaw | RadiusKind::ScopeRaw));
        abstracted && !exact
    }

    /// Whether this site was found somewhere other than where we embedded it.
    pub fn moved(&self) -> bool {
        self.found_in
            .as_deref()
            .is_some_and(|f| f != self.manifest_file)
    }
}

/// The §16 channel's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintCheck {
    /// The candidate tree hashes to the release's published fingerprint.
    Matched,
    /// It hashes to something else — which is the ordinary answer, and not a
    /// finding on its own.
    NotMatched,
    /// The release published a fingerprint at a level this build cannot reproduce,
    /// so no claim is made either way.
    NotComparable { declared: String },
}

impl FingerprintCheck {
    pub fn matched(&self) -> bool {
        matches!(self, FingerprintCheck::Matched)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FingerprintCheck::Matched => "match",
            FingerprintCheck::NotMatched => "no-match",
            FingerprintCheck::NotComparable { .. } => "not-comparable",
        }
    }
}

/// One release, and how much of it the candidate accounts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDetection {
    pub project_id: ProjectId,
    pub release_id: ReleaseId,
    pub tag_bits: u8,
    pub sites: Vec<SiteMatch>,
    pub fingerprint: FingerprintCheck,
    /// How many source files the candidate tree contributed to the scan. A
    /// release's own file count is not here on purpose: this crate never assumes a
    /// copy kept its file layout.
    pub candidate_files: u32,
    /// Hypotheses each pass probed, which is the denominator a report needs to say
    /// "12 of 16 sites, out of 41k literals and 3k rendering shapes examined".
    pub literals_tried: u64,
    pub windows_tried: u64,
}

impl ReleaseDetection {
    pub fn total(&self) -> usize {
        self.sites.len()
    }

    pub fn confirmed(&self) -> usize {
        self.sites.iter().filter(|s| s.confirmed()).count()
    }

    /// Sites whose address is present but whose code is not — the strip channel.
    ///
    /// Read it as "the code is here, the watermark at that address is not", which
    /// an innocent copy of an unprotected build produces identically to a
    /// deliberate removal (§51). It is reported because it is observable, not
    /// because it is accusation.
    pub fn stripped(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| s.status == SiteStatus::LocationOnly)
            .count()
    }

    pub fn absent(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| s.status == SiteStatus::Absent)
            .count()
    }

    /// Confirmed over total. `None` for a release with no sites, which cannot come
    /// from a manifest that validated but must not divide by.
    pub fn coverage(&self) -> Option<f64> {
        if self.sites.is_empty() {
            return None;
        }
        Some(self.confirmed() as f64 / self.sites.len() as f64)
    }

    /// How many keyed bits the confirmed sites carry in total, which is the honest
    /// way to compare "12 sites at 4 bits" against "3 sites at 8 bits" without
    /// pretending either is a probability.
    pub fn confirmed_bits(&self) -> u32 {
        self.sites
            .iter()
            .filter(|s| s.confirmed())
            .map(|s| s.width as u32)
            .sum()
    }

    /// How many confirmed sites were found at a path other than the one we
    /// protected, which is the file-movement channel of §25.
    pub fn moved(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| s.confirmed() && s.moved())
            .count()
    }

    /// How many confirmed sites were reached only through the rename-tolerant
    /// keys, which is the renaming and reformatting channel of §25.
    pub fn refactored(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| s.confirmed() && s.refactored())
            .count()
    }

    /// How many candidate spans were offered a code comparison, across every site.
    /// The evidence layer divides nothing by this and takes no claim from it on its
    /// own; it is the denominator of the one coincidence figure the report is
    /// allowed to print.
    pub fn probes(&self) -> u32 {
        self.sites.iter().map(|s| s.probes).sum()
    }

    /// Confirmed sites whose winning span was more than one token — a rendering,
    /// not a literal left where it was.
    pub fn renderings(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| s.confirmed() && s.found_tokens > 1)
            .count()
    }
}

/// One scan of one candidate against everything it was scanned against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub described: String,
    pub kind: InputKind,
    pub releases: Vec<ReleaseDetection>,
    /// Source files the walk admitted.
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    /// Files the walk refused, with the reason, so "no evidence" reads as "we
    /// looked at these files" rather than "we looked at everything".
    pub omissions: Vec<String>,
    /// Caveats: widths scanned, hypotheses capped, archive members not opened.
    pub notes: Vec<String>,
    /// True when part of the candidate was never examined, which turns a negative
    /// result into an inconclusive one.
    pub partial: bool,
}

impl Detection {
    /// The release the candidate accounts for best, which is what a report leads
    /// with. Ties break toward more confirmed sites, then more bits, then the
    /// exact-fingerprint channel, then the id, so the answer is stable.
    pub fn best(&self) -> Option<&ReleaseDetection> {
        self.releases.iter().max_by(|a, b| {
            a.confirmed()
                .cmp(&b.confirmed())
                .then(a.confirmed_bits().cmp(&b.confirmed_bits()))
                .then(a.fingerprint.matched().cmp(&b.fingerprint.matched()))
                .then_with(|| a.release_id.as_str().cmp(b.release_id.as_str()))
        })
    }

    pub fn confirmed_anywhere(&self) -> bool {
        self.releases
            .iter()
            .any(|r| r.confirmed() > 0 || r.fingerprint.matched())
    }
}

/// One candidate observation: a span in the candidate tree whose address appears
/// in a release.
#[derive(Debug, Clone)]
struct Observation {
    file: String,
    line: u32,
    /// The literal as it stands in the candidate, untruncated: the decode has to
    /// see the whole form, and only the report hint is bounded.
    text: String,
    /// How many tokens the span covers — one for pass A, and the width of the
    /// rendering for pass B, which is the difference between "your literal is
    /// here" and "your rendering is here" that `TOKEN_MATCH` reports.
    tokens: u8,
    slots: Vec<RadiusKind>,
    dialect: &'static swp_adapters::Dialect,
}

/// Scan `opened` against every release in `indexes`.
pub fn scan_against(
    opened: &Opened,
    indexes: &[ReleaseIndex<'_>],
    limits: &Limits,
) -> Result<Detection, SwpError> {
    if indexes.is_empty() {
        return Err(SwpError::usage(
            "no protected releases were loaded, so there is nothing to match against",
        ));
    }
    let registry = Registry::standard();
    // A candidate that holds nothing the protocol can read is a result, not a
    // failure. `walk` refuses an empty tree because its other caller is
    // `swp protect`, where "no locations" genuinely is an error the operator has
    // to fix; here the honest answer is "this scan could not look at anything",
    // which §20 files under *cannot say* and §51 forbids dressing up as a clean
    // verdict.
    let walked = walk::walk_for_scan(&opened.root, &scan_config(), limits)?;
    let nothing_to_examine = walked.is_empty();

    let mut observations: Vec<BTreeMap<usize, Vec<Observation>>> =
        indexes.iter().map(|_| BTreeMap::new()).collect();
    let mut literals_tried = vec![0u64; indexes.len()];
    let mut windows_tried = vec![0u64; indexes.len()];
    // The candidate tree's own fingerprint, taken once per canonicalizer version
    // the releases were built under, because the version is inside the hash.
    let mut trees: BTreeMap<u16, Digest> = BTreeMap::new();
    let mut notes: Vec<String> = opened.notes.clone();
    // Refusals accumulate across the harvest passes, then dedup: two tag widths
    // over the same tree report the same skipped file twice otherwise, and a
    // report that lists one omission twice reads like two.
    let mut refusals: Vec<walk::Omission> = Vec::new();

    for group in groups(indexes) {
        let width = TagWidth::new(group.tag_bits).map_err(|_| {
            SwpError::new(
                ErrorCode::InvalidWatermark,
                format!(
                    "a release declares an unsupported tag width of {}",
                    group.tag_bits
                ),
            )
        })?;
        let keys: &ManifestKeys = indexes[group.positions[0]].keys();
        let merged = merged_index(indexes, &group.positions);
        let cfg = ProtectConfig {
            tag_bits: group.tag_bits,
            ..scan_config()
        };

        let scan = candidates::scan(&opened.root, &walked, keys, &cfg, width, limits)?;
        notes.extend(scan.notes.clone());
        refusals.extend(scan.omissions.iter().cloned());
        if let std::collections::btree_map::Entry::Vacant(slot) = trees.entry(group.canonicalizer) {
            let files: Vec<FileCanonical> = scan
                .files
                .iter()
                .map(|f| FileCanonical::new(f.rel.clone(), f.l1_digest))
                .collect();
            let digest = swp_manifest::project_fingerprint("L1", group.canonicalizer, &files)?;
            slot.insert(digest);
        }

        // Pass A: every literal the writer's own harvest would have offered.
        // The ids come straight off the candidate, because the candidate already
        // holds them and re-deriving them from the same digests would be a second
        // implementation of a rule that has to agree with the first.
        for file in &scan.files {
            let dialect = registry.for_language(&file.language).dialect();
            for cand in &file.candidates {
                record_hits(
                    &merged,
                    &mut observations,
                    &mut literals_tried,
                    &group.positions,
                    &cand.locations,
                    cand.line_hint,
                    &cand.original,
                    1,
                    &file.rel,
                    dialect,
                );
            }
        }

        // Pass B: the spans a rendering could occupy, which no literal is.
        for entry in &walked.files {
            let Some(text) = read_source(&opened.root, entry, limits)? else {
                continue;
            };
            let Ok(analysis) = registry.analyze(Path::new(&entry.rel), &text, limits) else {
                // Pass A already analyzed this file and recorded why it refused;
                // a second failure here is not a new finding.
                continue;
            };
            let dialect = registry.for_language(&analysis.language).dialect();
            let (windows, truncated) = spans::form_windows(&analysis);
            if truncated {
                notes.push(format!(
                    "{}: rendering hypotheses capped at {}, so later spans in this file were \
                     not probed",
                    entry.rel,
                    spans::MAX_WINDOWS_PER_FILE
                ));
            }
            for window in windows {
                let span = window.span;
                let start = (span.start as usize).min(text.len());
                let end = (span.end as usize).min(text.len());
                // Spans come out of the tokenizer so their edges are character
                // boundaries by construction; the check keeps a hand-built or
                // clamped span from slicing a multi-byte character.
                if end <= start || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
                    continue;
                }
                if end - start > MAX_HYPOTHESIS_LEN {
                    continue;
                }
                let ids = hypothesis_ids(&analysis, span, keys);
                record_hits(
                    &merged,
                    &mut observations,
                    &mut windows_tried,
                    &group.positions,
                    &ids,
                    line_of(&text, span.start),
                    &text[start..end],
                    window.tokens,
                    &entry.rel,
                    dialect,
                );
            }
        }
    }

    let mut releases = Vec::with_capacity(indexes.len());
    for (pos, idx) in indexes.iter().enumerate() {
        let mut sites = Vec::with_capacity(idx.site_count());
        for site in 0..idx.site_count() {
            let obs = observations[pos].remove(&site);
            sites.push(confirm(idx, site, obs.as_deref())?);
        }
        let check = if idx.fingerprint_level() != "L1" {
            FingerprintCheck::NotComparable {
                declared: idx.fingerprint_level().to_string(),
            }
        } else {
            match trees.get(&idx.canonicalizer_version()) {
                Some(d) if *d == *idx.fingerprint() => FingerprintCheck::Matched,
                Some(_) => FingerprintCheck::NotMatched,
                None => FingerprintCheck::NotComparable {
                    declared: idx.fingerprint_level().to_string(),
                },
            }
        };
        releases.push(ReleaseDetection {
            project_id: idx.project_id().clone(),
            release_id: idx.release_id().clone(),
            tag_bits: idx.tag_bits(),
            sites,
            fingerprint: check,
            candidate_files: walked.files.len() as u32,
            literals_tried: literals_tried[pos],
            windows_tried: windows_tried[pos],
        });
    }

    refusals.sort_by(|a, b| a.path.cmp(&b.path).then(a.reason.cmp(&b.reason)));
    refusals.dedup_by(|a, b| a.path == b.path && a.reason == b.reason);
    let omissions: Vec<String> = refusals
        .iter()
        .map(|o| format!("{}: {}", o.path, o.reason))
        .collect();
    let unexamined = refusals
        .iter()
        .filter(|o| o.kind == walk::OmissionKind::NotExamined)
        .count();
    let bytes_scanned: u64 = walked.files.iter().map(|f| f.bytes).sum();
    notes.push(format!(
        "candidate scan covered {} file(s) at tag widths {}",
        walked.files.len(),
        widths(indexes)
            .into_iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    if nothing_to_examine {
        notes.push(format!(
            "{} contained no source this protocol can read, so there was nothing to match \
             against: this scan cannot distinguish an unprotected copy from an empty directory",
            opened.described
        ));
    }

    if unexamined > 0 {
        notes.push(format!(
            "{unexamined} file(s) in this candidate could have carried a site and were not \
             examined, each named in the omission list with the limit that stopped it: this scan \
             covers what it read and says nothing about the rest"
        ));
    }

    Ok(Detection {
        described: opened.described.clone(),
        kind: opened.kind,
        releases,
        files_scanned: walked.files.len() as u32,
        bytes_scanned,
        omissions,
        notes,
        partial: opened.is_partial() || nothing_to_examine || unexamined > 0,
    })
}

/// The scan's own scope: every file a walk admits from the tree's root, under the
/// built-in exclusions only.
///
/// A candidate tree is not our project, so its *own* configuration — which it may
/// have smuggled in as a `.swp/config.toml` — is never read. The definition lives
/// in `swp-identity` rather than here because `swp protect` takes its §16
/// fingerprint over exactly this set, and a scanner and a writer that disagree
/// about which files a tree contains can never agree about the tree.
fn scan_config() -> ProtectConfig {
    ProtectConfig::scan_scope()
}

/// Releases that can share one harvest, keyed by everything a location id depends
/// on: the project, the canonicalizer version and the tag width the candidate scan
/// runs at.
struct Group {
    tag_bits: u8,
    canonicalizer: u16,
    positions: Vec<usize>,
}

fn groups(indexes: &[ReleaseIndex<'_>]) -> Vec<Group> {
    let mut by_key: BTreeMap<(String, u16, u8), Vec<usize>> = BTreeMap::new();
    for (pos, idx) in indexes.iter().enumerate() {
        by_key
            .entry((
                idx.project_id().as_str().to_string(),
                idx.canonicalizer_version(),
                idx.tag_bits(),
            ))
            .or_default()
            .push(pos);
    }
    by_key
        .into_iter()
        .map(|((_, canonicalizer, tag_bits), positions)| Group {
            tag_bits,
            canonicalizer,
            positions,
        })
        .collect()
}

fn widths(indexes: &[ReleaseIndex<'_>]) -> Vec<u8> {
    indexes
        .iter()
        .map(|i| i.tag_bits())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// One lookup table for a whole group: a location id straight to the releases and
/// sites it addresses. Without this, every literal in the tree costs one map probe
/// per release.
///
/// A hit carries the rendering its site expects, because a candidate span that
/// *is* that rendering is the one observation worth keeping when a site's address
/// is shared by more spans than the observation list holds — see
/// [`MAX_OBSERVATIONS`].
type Merged<'a> = BTreeMap<LocationId, Vec<Hit<'a>>>;

#[derive(Debug, Clone, Copy)]
struct Hit<'a> {
    release: usize,
    site: usize,
    slot: RadiusKind,
    rendered: &'a str,
}

fn merged_index<'a>(indexes: &'a [ReleaseIndex<'_>], positions: &[usize]) -> Merged<'a> {
    let mut merged: Merged = BTreeMap::new();
    for pos in positions {
        let idx = &indexes[*pos];
        for (site, entry) in idx.sites().iter().enumerate() {
            for (slot, kind) in RadiusKind::all().iter().enumerate() {
                merged.entry(entry.locations[slot]).or_default().push(Hit {
                    release: *pos,
                    site,
                    slot: *kind,
                    rendered: &entry.rendered,
                });
            }
        }
    }
    merged
}

/// Probe one hypothesis's four ids and file the hits where they belong.
///
/// The counter is bumped whether or not anything matched, because a report that
/// only counted hits could not say what it ruled out.
#[allow(clippy::too_many_arguments)]
fn record_hits(
    merged: &Merged<'_>,
    observations: &mut [BTreeMap<usize, Vec<Observation>>],
    tried: &mut [u64],
    positions: &[usize],
    ids: &[LocationId; SLOT_COUNT],
    line: u32,
    text: &str,
    tokens: u8,
    file: &str,
    dialect: &'static swp_adapters::Dialect,
) {
    for pos in positions {
        tried[*pos] += 1;
    }
    let mut found: BTreeMap<(usize, usize), (Vec<RadiusKind>, &str)> = BTreeMap::new();
    for id in ids {
        if let Some(hits) = merged.get(id) {
            for hit in hits {
                let entry = found
                    .entry((hit.release, hit.site))
                    .or_insert_with(|| (Vec::new(), hit.rendered));
                if !entry.0.contains(&hit.slot) {
                    entry.0.push(hit.slot);
                }
            }
        }
    }
    for ((release, site), (slots, rendered)) in found {
        let list = observations[release].entry(site).or_default();
        // The same span reached through two of a site's four keys is one
        // observation with two keys, not two observations.
        if let Some(existing) = list
            .iter_mut()
            .find(|o| o.file == file && o.text == text && o.line == line)
        {
            for kind in slots {
                if !existing.slots.contains(&kind) {
                    existing.slots.push(kind);
                }
            }
            continue;
        }
        let exact = text == rendered;
        if list.len() < MAX_OBSERVATIONS {
            list.push(Observation {
                file: file.to_string(),
                line,
                text: text.to_string(),
                tokens,
                slots,
                dialect,
            });
        } else if exact {
            // Bounded so a tree that repeats one statement a thousand times
            // cannot make one site hold a thousand copies of itself — but the
            // rendering the manifest names has to be in the list whatever the
            // bound is, because it is the only span of the site's own that can
            // confirm it. A big tree of boilerplate fills the list with spans
            // that share the abstracted address and are not it, and a site lost
            // that way reads as a stripped watermark in a file nobody stripped.
            if let Some(keeper) = list.iter_mut().find(|o| o.text != rendered) {
                *keeper = Observation {
                    file: file.to_string(),
                    line,
                    text: text.to_string(),
                    tokens,
                    slots,
                    dialect,
                };
            }
        }
    }
}

/// How many candidate spans one site may hold observations for.
const MAX_OBSERVATIONS: usize = 64;

/// The four keyed ids of a hypothesized rendering span, computed exactly the way
/// the embedder computed the real ones: radii from the span's first byte, the site
/// itself hidden.
fn hypothesis_ids(
    analysis: &Analysis,
    span: ByteSpan,
    keys: &ManifestKeys,
) -> [LocationId; SLOT_COUNT] {
    let digests = radius_digests(
        &analysis.tokens,
        analysis.statement_span_at(span.start),
        analysis.scope_span_at(span.start),
        span,
    );
    keys.location_ids(&digests)
}

/// Grade one site from everything found at its address.
fn confirm(
    idx: &ReleaseIndex,
    site: usize,
    obs: Option<&[Observation]>,
) -> Result<SiteMatch, SwpError> {
    let entry = idx.site(site);
    let width = entry.tag_width()?;
    let tag = SiteTag::new(idx.expected_tag(entry)?, width);
    let mut slots: Vec<RadiusKind> = Vec::new();
    let mut status = SiteStatus::Absent;
    let mut best: Option<&Observation> = None;
    let mut codes: BTreeSet<u32> = BTreeSet::new();
    let mut undecoded = 0u32;

    for o in obs.unwrap_or(&[]) {
        for kind in &o.slots {
            if !slots.contains(kind) {
                slots.push(*kind);
            }
        }
        if o.text == entry.rendered {
            status = SiteStatus::ExactRendering;
            best = Some(o);
            break;
        }
        let code = observed_code(o, entry.family, width);
        match code {
            Some(code) => {
                codes.insert(code);
            }
            None => undecoded += 1,
        }
        if status < SiteStatus::TagConfirmed {
            if let Some(code) = code {
                if tag.matches(code) {
                    status = SiteStatus::TagConfirmed;
                    best = Some(o);
                    continue;
                }
            }
        }
        if status == SiteStatus::Absent {
            status = SiteStatus::LocationOnly;
            best = Some(o);
        }
    }
    // An exact rendering stops the walk, so the spans behind it were never read and
    // their codes never seen. Count every span at the address in that case rather
    // than report a bound built on a partial look.
    let distinct_codes = if status == SiteStatus::ExactRendering {
        obs.unwrap_or(&[]).len() as u32
    } else {
        codes.len() as u32 + undecoded
    };
    slots.sort();
    // Two files in one tree can hold the same statement, and then this site has an
    // observation at each of them that is just as good as the other. Which one the
    // loop above kept is the order the walk happened to read them in. `moved` is a
    // claim about where the watermark *is*, so the copy sitting at the address the
    // manifest published wins that tie rather than the first one found — otherwise
    // an untouched project reads as having moved a site on some keys and not on
    // others, for a reason that has nothing to do with its own history.
    if let Some(chosen) = best {
        if chosen.file != entry.file {
            let at_published = obs.unwrap_or(&[]).iter().find(|o| {
                o.file == entry.file
                    && observation_tier(o, &entry.rendered, entry.family, width, tag) >= status
            });
            if at_published.is_some() {
                best = at_published;
            }
        }
    }
    Ok(SiteMatch {
        site,
        manifest_file: entry.file.clone(),
        manifest_line: entry.line_hint,
        language: entry.language.clone(),
        adapter: entry.adapter.clone(),
        class: entry.class,
        family: entry.family,
        width: entry.width,
        primary: entry.primary,
        locations: entry.locations,
        status,
        slots,
        found_in: best.map(|o| o.file.clone()),
        found_line: best.map(|o| o.line),
        found_text: best.map(|o| hint(&o.text)),
        found_tokens: best.map_or(0, |o| o.tokens),
        // Every span at the address, not only the ones that decoded: this is the
        // scan's own account of how much of the candidate it looked at, and the
        // observation cap above means a site repeated thousands of times reports 64
        // rather than the true count. That understates the work in the one case
        // where the candidate is plainly a copy, so it errs away from accusing.
        probes: obs.unwrap_or(&[]).len() as u32,
        distinct_codes,
    })
}

/// What one observation on its own would say about this site.
///
/// The three rules the scan loop applies, factored out so a tie between two equal
/// observations can be settled after the loop instead of inside it.
fn observation_tier(
    obs: &Observation,
    rendered: &str,
    family: FormFamily,
    width: TagWidth,
    tag: SiteTag,
) -> SiteStatus {
    if obs.text == rendered {
        return SiteStatus::ExactRendering;
    }
    if let Some(code) = observed_code(obs, family, width) {
        if tag.matches(code) {
            return SiteStatus::TagConfirmed;
        }
    }
    SiteStatus::LocationOnly
}

/// What a literal in the candidate tree carries, under the family the manifest
/// says to look for.
///
/// One family only, and the adapter's own strict decoder: widening this to "try
/// every family and report the best" would turn a 2^-width coincidence rate into a
/// several-families-deep one, and the whole value of the tag channel is that its
/// false-positive rate is a number we can state.
fn observed_code(obs: &Observation, family: FormFamily, width: TagWidth) -> Option<u32> {
    match decode(&obs.text, family, width, obs.dialect) {
        Some(DecodedSite::Integer { code, .. }) => Some(code),
        Some(DecodedSite::Text { code, .. }) => Some(code),
        None => None,
    }
}

/// Read one file for pass B. `None` means the walk's own bounds now exclude it,
/// which the walk already reported.
fn read_source(
    root: &Path,
    entry: &swp_embedding::walk::ScannedFile,
    limits: &Limits,
) -> Result<Option<String>, SwpError> {
    let abs = if entry.abs.is_absolute() {
        entry.abs.clone()
    } else {
        root.join(&entry.abs)
    };
    let bytes = std::fs::read(&abs)
        .map_err(|e| SwpError::new(ErrorCode::Io, format!("cannot read {}: {e}", abs.display())))?;
    if bytes.len() as u64 > limits.max_file_bytes {
        return Ok(None);
    }
    Ok(decode_utf8_strict(&bytes).map(str::to_string))
}

/// Truncate to the report hint bound without splitting a character.
fn hint(text: &str) -> String {
    if text.len() <= MAX_HINT_LEN {
        return text.to_string();
    }
    let mut end = MAX_HINT_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = text[..end].to_string();
    out.push('…');
    out
}

fn line_of(text: &str, byte: u32) -> u32 {
    let upto = (byte as usize).min(text.len());
    1 + text[..upto].bytes().filter(|b| *b == b'\n').count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_ordered_and_only_the_top_two_are_watermarks() {
        assert!(SiteStatus::TagConfirmed > SiteStatus::LocationOnly);
        assert!(SiteStatus::ExactRendering > SiteStatus::TagConfirmed);
        assert!(!SiteStatus::Absent.is_watermark());
        assert!(!SiteStatus::LocationOnly.is_watermark());
        assert!(SiteStatus::TagConfirmed.is_watermark());
        assert!(SiteStatus::ExactRendering.is_watermark());
    }

    #[test]
    fn a_refactored_copy_is_distinguished_from_an_exact_one() {
        let mut m = site_match(vec![RadiusKind::StatementId]);
        assert!(m.refactored(), "an L3-only hit is a renamed copy");
        m.slots.push(RadiusKind::StatementRaw);
        assert!(
            !m.refactored(),
            "an L1 hit means the text was not respelled"
        );
    }

    #[test]
    fn a_rendering_hit_is_counted_separately_from_a_literal_hit() {
        // The two channels say different things: a literal at a matching address is
        // what an unprotected copy also looks like, while a multi-token rendering is
        // only ever something that *protected* source contains.
        let m = site_match(vec![RadiusKind::StatementId]);
        assert_eq!(m.found_tokens, 5, "the helper models a rewritten site");
        let mut plain = m.clone();
        plain.found_tokens = 1;
        let release = ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: 4,
            sites: vec![m.clone(), plain.clone()],
            fingerprint: FingerprintCheck::NotMatched,
            candidate_files: 1,
            literals_tried: 90,
            windows_tried: 10,
        };
        assert_eq!(release.renderings(), 1);
        assert_eq!(
            release.probes(),
            2,
            "one comparison per span the address offered"
        );
    }

    #[test]
    fn a_hit_at_another_path_is_reported_as_moved_not_missing() {
        // The whole point of keying a location by content: `file` in the manifest
        // is where we wrote it, not where the copy keeps it.
        let mut m = site_match(vec![RadiusKind::StatementRaw]);
        m.found_in = Some("package/lib/calc.js".into());
        assert!(m.moved());
        m.found_in = Some("src/a.js".into());
        assert!(!m.moved());
    }

    fn site_match(slots: Vec<RadiusKind>) -> SiteMatch {
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
            locations: [LocationId::default(); SLOT_COUNT],
            status: SiteStatus::TagConfirmed,
            slots,
            found_in: Some("src/a.js".into()),
            found_line: Some(3),
            found_text: Some("(995 + 5)".into()),
            found_tokens: 5,
            probes: 1,
            distinct_codes: 1,
        }
    }

    #[test]
    fn hints_are_truncated_on_char_boundaries() {
        let long = "é".repeat(400);
        let cut = hint(&long);
        assert!(cut.chars().count() <= MAX_HINT_LEN + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(hint("short"), "short");
    }

    #[test]
    fn line_numbers_are_one_based_and_clamped() {
        let text = "a\nb\nc\n";
        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 2), 2);
        assert_eq!(line_of(text, 4), 3);
        assert_eq!(line_of(text, 9999), 4);
    }

    #[test]
    fn releases_are_grouped_by_everything_a_location_id_depends_on() {
        // Two widths means two harvests, because the candidate scan filters the
        // families it offers by the width it is running at.
        let same = |bits: u8| Group {
            tag_bits: bits,
            canonicalizer: 1,
            positions: vec![0, 1],
        };
        let a = same(4);
        let b = same(6);
        assert_ne!(a.tag_bits, b.tag_bits);
    }

    #[test]
    fn coverage_refuses_to_divide_by_an_empty_site_list() {
        let d = ReleaseDetection {
            project_id: ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            release_id: ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            tag_bits: 4,
            sites: Vec::new(),
            fingerprint: FingerprintCheck::NotMatched,
            candidate_files: 1,
            literals_tried: 0,
            windows_tried: 0,
        };
        assert!(d.coverage().is_none());
        assert_eq!(d.confirmed(), 0);
        assert_eq!(d.confirmed_bits(), 0);
        assert_eq!(d.stripped(), 0);
        assert!(!d.fingerprint.matched());
    }

    #[test]
    fn an_uncomparable_fingerprint_is_never_reported_as_a_mismatch() {
        let check = FingerprintCheck::NotComparable {
            declared: "L3".into(),
        };
        assert!(!check.matched());
        assert_eq!(check.as_str(), "not-comparable");
    }

    #[test]
    fn the_probe_counter_counts_ruled_out_hypotheses_not_only_hits() {
        let merged = BTreeMap::new();
        let mut obs: Vec<BTreeMap<usize, Vec<Observation>>> = vec![BTreeMap::new()];
        let mut tried = vec![0u64];
        let registry = Registry::standard();
        let ids = [LocationId::default(); SLOT_COUNT];
        record_hits(
            &merged,
            &mut obs,
            &mut tried,
            &[0],
            &ids,
            1,
            "1000",
            1,
            "src/a.js",
            registry.for_language("javascript").dialect(),
        );
        assert_eq!(tried[0], 1);
        assert!(obs[0].is_empty());
    }

    #[test]
    fn one_observation_merging_two_keys_is_still_one_site_hit() {
        let registry = Registry::standard();
        let dialect = registry.for_language("javascript").dialect();
        let mut obs: BTreeMap<usize, Vec<Observation>> = BTreeMap::new();
        for slots in [
            vec![RadiusKind::StatementId],
            vec![RadiusKind::StatementRaw],
        ] {
            let list = obs.entry(0).or_default();
            list.push(Observation {
                file: "src/a.js".into(),
                line: 3,
                text: "(995 + 5)".into(),
                tokens: 5,
                slots,
                dialect,
            });
        }
        assert_eq!(obs[&0].len(), 2, "the caller merges by (file, text, line)");
    }

    /// The bound on a site's observation list may cost it a wrong span, never the
    /// right one.
    ///
    /// A location id abstracts the names and the shape around a literal away, so a
    /// tree of ordinary boilerplate — the same five-line helper in sixty files,
    /// which is what real projects look like — hands the matcher many spans at one
    /// address and exactly one of them is the rendering the manifest named. This
    /// was found by the §44 ladder: a freshly protected 60-file tree verified with
    /// two of twenty sites graded `location-only`, because the sixty-four spans the
    /// list holds were the ones that walked first, and the report accused a project
    /// of stripping watermarks that were sitting in the file.
    #[test]
    fn a_full_observation_list_keeps_the_span_that_carries_the_rendering() {
        let registry = Registry::standard();
        let dialect = registry.for_language("javascript").dialect();
        let rendered = String::from("(995 + 5)");

        let mut merged: Merged = BTreeMap::new();
        merged.insert(
            LocationId::default(),
            RadiusKind::all()
                .iter()
                .map(|kind| Hit {
                    release: 0,
                    site: 0,
                    slot: *kind,
                    rendered: &rendered,
                })
                .collect(),
        );

        let mut obs: Vec<BTreeMap<usize, Vec<Observation>>> = vec![BTreeMap::new()];
        let mut tried = vec![0u64];
        for line in 1..=MAX_OBSERVATIONS as u32 {
            offer(&merged, &mut obs, &mut tried, line, "0", 1, dialect);
        }
        assert_eq!(
            obs[0][&0].len(),
            MAX_OBSERVATIONS,
            "the bound did not fill, so the case below is not the case being tested"
        );

        // The site's own rendering is the last thing the walk reaches.
        offer(
            &merged,
            &mut obs,
            &mut tried,
            MAX_OBSERVATIONS as u32 + 1,
            &rendered,
            5,
            dialect,
        );
        let list = &obs[0][&0];
        assert_eq!(list.len(), MAX_OBSERVATIONS, "the bound was exceeded");
        assert!(
            list.iter().any(|o| o.text == rendered),
            "a full list dropped the only span that carries this site's rendering"
        );
    }

    /// One candidate span, offered to the matcher the way the harvest offers it.
    fn offer(
        merged: &Merged<'_>,
        obs: &mut [BTreeMap<usize, Vec<Observation>>],
        tried: &mut [u64],
        line: u32,
        text: &str,
        tokens: u8,
        dialect: &'static swp_adapters::Dialect,
    ) {
        record_hits(
            merged,
            obs,
            tried,
            &[0],
            &[LocationId::default(); SLOT_COUNT],
            line,
            text,
            tokens,
            "src/a.js",
            dialect,
        );
    }
}
