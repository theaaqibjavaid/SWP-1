//! Pass two: choose the constellation.
//!
//! Selection is where the brief's "10–30 locations depending on size and
//! configuration" becomes an algorithm, and it has to satisfy four properties at
//! once:
//!
//! - **Deterministic.** The same tree and the same release id produce the same
//!   sites, byte for byte. Nothing here reads a clock or a random number.
//! - **Spread.** A constellation whose points sit in one file is one `rm` away
//!   from nothing, and a copy that took a quarter of the tree should carry a
//!   quarter of the sites. So candidates are taken round-by-round across files,
//!   with a per-file allowance that only relaxes once every file has had its turn.
//! - **Independent of what else exists.** A site's standing is its own footprint
//!   plus a keyed hash of its own identity, so protecting an extra directory
//!   cannot reshuffle the sites this run would have chosen in a directory it
//!   already had — it can only add competitors for the remaining slots.
//! - **Never forced.** §11 says skip rather than push through, and every refusal
//!   here is that kind: a radius already spoken for, an identity already taken, a
//!   ceiling reached. Each becomes a [`Skip`] with a reason a report can print.
//!
//! ## Why overlapping radii are refused rather than tolerated
//!
//! A location id digests the code *around* a site. Embed site B inside site A's
//! radius and A's recorded id describes a statement that no longer exists, so a
//! scanner recomputing it from the released source finds a different value and
//! reports A as removed. The run could not have known to blame itself. Two
//! candidates whose radii touch therefore compete for one slot.
//!
//! ## Who wins that competition
//!
//! The contest is decided by geometry first and by the key second: a file's
//! candidates are queued by how far their own edit reaches, and the keyed
//! priority breaks the ties geometry leaves. Both halves satisfy the properties
//! this pass needs — neither reads a clock, a filesystem order, or anything
//! outside the file — but only the keyed half is pseudorandom, and the blocking
//! geometry is not: two literals in one statement compete whatever the secret
//! is. Ordering by the key alone then amounts to a random walk over a fixed
//! interval problem, and it measured 8–15 sites of the same 24-site request on
//! the same three-file tree across projects, because a random order commits the
//! enclosing statement's radius early and every literal inside it is refused
//! after that. Shortest footprint first takes the narrow sites before their
//! enclosing scope is spoken for, which is both the larger constellation and a
//! number the next run reproduces.

use std::collections::BTreeSet;

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::LocationId;
use swp_core::limits::Limits;
use swp_core::{ByteSpan, RadiusKind};

use crate::candidates::{Candidate, KeyCounts, Scan};

/// Why a candidate literal did not become a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Another chosen site's radius contains this one's literal, or the reverse.
    OverlappingRadius,
    /// All four of this site's keys are already carried by another site, so no
    /// observation could tell the two apart.
    Indistinguishable,
    /// Every one of this site's four keys is already another site's primary
    /// identity, so its tag would collide with one already embedded.
    IdentityTaken,
    /// The requested number of sites is embedded.
    ConstellationFull,
    /// The manifest ceiling on locations is reached.
    LimitReached,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::OverlappingRadius => "overlapping-radius",
            SkipReason::Indistinguishable => "indistinguishable-site",
            SkipReason::IdentityTaken => "identity-already-taken",
            SkipReason::ConstellationFull => "constellation-full",
            SkipReason::LimitReached => "location-limit-reached",
        }
    }
}

/// One refused candidate, in the shape a report and a plan print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub file: String,
    pub line_hint: u32,
    pub span: ByteSpan,
    pub literal: String,
    pub reason: SkipReason,
    /// Which site or ceiling it lost to, when there is one to name.
    pub note: String,
}

/// One accepted site: which candidate it was, and which of its four keys carries
/// the fragment tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    /// Index into [`Scan::files`].
    pub file: usize,
    /// Index into that file's candidate list.
    pub candidate: usize,
    /// The key [`Candidate::locations`] slot the tag derives from: this site's
    /// most precisely-naming key that no other chosen site already carries, per
    /// [`Candidate::pick_primary`].
    pub primary: RadiusKind,
}

#[derive(Debug, Default)]
pub struct Selection {
    /// In (file, span) order, which is the order the apply pass wants.
    pub chosen: Vec<Chosen>,
    pub skipped: Vec<Skip>,
    /// What was asked for, after ceilings.
    pub target: usize,
}

impl Selection {
    pub fn len(&self) -> usize {
        self.chosen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chosen.is_empty()
    }

    pub fn chosen_at(&self, file: usize) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .chosen
            .iter()
            .filter(|c| c.file == file)
            .map(|c| c.candidate)
            .collect();
        out.sort();
        out
    }

    /// Every distinct reason the run has, for the summary line.
    pub fn skip_counts(&self) -> std::collections::BTreeMap<&'static str, u32> {
        let mut out = std::collections::BTreeMap::new();
        for s in &self.skipped {
            *out.entry(s.reason.as_str()).or_insert(0) += 1;
        }
        out
    }
}

/// Choose up to `target` sites from `scan`.
pub fn select(scan: &Scan, cfg_target: u32, limits: &Limits) -> Result<Selection, SwpError> {
    if scan.total_candidates() == 0 {
        return Err(SwpError::new(
            ErrorCode::NoSafeLocations,
            format!(
                "{} file{} were analyzed and none offered a literal that can carry a fragment; \
                 add source to [protect] targets, or lower tag_bits in .swp/config.toml so more \
                 literals qualify",
                scan.files.len(),
                if scan.files.len() == 1 { "" } else { "s" }
            ),
        ));
    }
    let target = (cfg_target as usize).min(limits.max_locations_per_manifest as usize);
    // A request trimmed by the ceiling is a different answer from one the tree
    // could not fill, and the report should name the right one.
    let capped = target < cfg_target as usize;

    // Per-file standing queues. Geometry first, key second: see the module header.
    let mut buckets: Vec<Vec<usize>> = Vec::with_capacity(scan.files.len());
    for file in &scan.files {
        let mut idx: Vec<usize> = (0..file.candidates.len()).collect();
        idx.sort_by_key(|i| standing(file, *i));
        buckets.push(idx);
    }
    // Files compete in the order of their best candidate, which is computed the
    // same way, so the round order does not come from the filesystem.
    let mut order: Vec<usize> = (0..scan.files.len()).collect();
    order.sort_by_key(|f| {
        let file = &scan.files[*f];
        if file.candidates.is_empty() {
            (u32::MAX, [0xffu8; 32])
        } else {
            standing(file, buckets[*f][0])
        }
    });
    let spread_files = scan.files_with_candidates().max(1);
    let counts = scan.key_counts();
    let mut sel = Selection {
        chosen: Vec::new(),
        skipped: Vec::new(),
        target,
    };
    let mut cursor = vec![0usize; scan.files.len()];
    let mut per_file = vec![0usize; scan.files.len()];
    let mut primaries: BTreeSet<LocationId> = BTreeSet::new();

    // Two passes: the first holds every file to its share so the constellation
    // spreads, the second returns to the files that still have candidates once
    // there is nowhere left to spread to. Splitting it this way is what lets a
    // three-file project still reach sixteen sites.
    for allow in share_ladder(target, spread_files) {
        if sel.chosen.len() >= target {
            break;
        }
        loop {
            let mut progressed = false;
            for f in &order {
                let f = *f;
                if sel.chosen.len() >= target || per_file[f] >= allow {
                    continue;
                }
                let queue = &buckets[f];
                while cursor[f] < queue.len() {
                    let ci = queue[cursor[f]];
                    cursor[f] += 1;
                    progressed = true;
                    let cand = &scan.files[f].candidates[ci];
                    match accept(scan, &sel, cand, &primaries, &counts, target, capped) {
                        Ok(primary) => {
                            primaries.insert(cand.locations[primary.code() as usize]);
                            sel.chosen.push(Chosen {
                                file: f,
                                candidate: ci,
                                primary,
                            });
                            per_file[f] += 1;
                            break;
                        }
                        Err((reason, note)) => sel.skipped.push(Skip {
                            file: scan.files[f].rel.clone(),
                            line_hint: cand.line_hint,
                            span: cand.span,
                            literal: cand.original.clone(),
                            reason,
                            note,
                        }),
                    }
                }
                if sel.chosen.len() >= target {
                    break;
                }
            }
            if !progressed {
                break;
            }
        }
    }

    // Everything the ladder never looked at is still owed an explanation: a
    // constellation that filled early leaves candidates unexamined, and silence
    // about them would read as "there were no others".
    for f in 0..scan.files.len() {
        let queue = &buckets[f];
        while cursor[f] < queue.len() {
            let cand = &scan.files[f].candidates[queue[cursor[f]]];
            sel.skipped.push(Skip {
                file: scan.files[f].rel.clone(),
                line_hint: cand.line_hint,
                span: cand.span,
                literal: cand.original.clone(),
                reason: if capped {
                    SkipReason::LimitReached
                } else {
                    SkipReason::ConstellationFull
                },
                note: if capped {
                    format!(
                        "{target} is the most a manifest may hold (requested {cfg_target}); \
                         raise max_locations_per_manifest or protect a smaller tree"
                    )
                } else {
                    format!("{target} sites is what was asked for")
                },
            });
            cursor[f] += 1;
        }
    }

    sel.chosen.sort_by(|a, b| {
        let ka = (
            a.file,
            scan.files[a.file].candidates[a.candidate].span.start,
        );
        let kb = (
            b.file,
            scan.files[b.file].candidates[b.candidate].span.start,
        );
        ka.cmp(&kb)
    });
    // A request the tree could not satisfy says so in one line, rather than
    // leaving the caller to subtract two numbers and guess.
    if sel.chosen.len() < target {
        shortfall(&mut sel, target);
    }
    Ok(sel)
}

/// One line per run, when the tree was smaller than the request.
fn shortfall(sel: &mut Selection, target: usize) {
    let placed = sel.chosen.len();
    let conflicts = sel
        .skipped
        .iter()
        .filter(|s| {
            matches!(
                s.reason,
                SkipReason::OverlappingRadius
                    | SkipReason::Indistinguishable
                    | SkipReason::IdentityTaken
            )
        })
        .count();
    sel.skipped.push(Skip {
        file: String::new(),
        line_hint: 0,
        span: ByteSpan::new(0, 0),
        literal: String::new(),
        reason: SkipReason::OverlappingRadius,
        note: format!(
            "{placed} of {target} requested sites placed: the tree offers no further site whose \
             radius and identity are both free ({conflicts} candidates lost that competition)"
        ),
    });
}

/// The per-file allowance to try, widest last: an even share first, then the
/// whole target so a small tree can still fill up.
fn share_ladder(target: usize, files: usize) -> Vec<usize> {
    let share = target.div_ceil(files.max(1)).max(1);
    let mut out = vec![share];
    if share < target {
        out.push(target);
    }
    out
}

/// A candidate's standing in its file's queue: the reach of its own edit first,
/// then its keyed priority. See the module header for why that order.
fn standing(file: &crate::candidates::FileScan, i: usize) -> (u32, [u8; 32]) {
    let cand = &file.candidates[i];
    (cand.blocks_until(), cand.priority)
}

/// Decide one candidate, or say why it cannot be used.
fn accept(
    scan: &Scan,
    sel: &Selection,
    cand: &Candidate,
    primaries: &BTreeSet<LocationId>,
    counts: &KeyCounts,
    target: usize,
    capped: bool,
) -> Result<RadiusKind, (SkipReason, String)> {
    if sel.chosen.len() >= target {
        return Err((
            if capped {
                SkipReason::LimitReached
            } else {
                SkipReason::ConstellationFull
            },
            String::new(),
        ));
    }
    for other in &sel.chosen {
        let oc = &scan.files[other.file].candidates[other.candidate];
        if other.file == cand.file && cand.radii_overlap(oc) {
            return Err((
                SkipReason::OverlappingRadius,
                format!("{}:{}", scan.files[other.file].rel, oc.line_hint),
            ));
        }
        if cand.indistinguishable_from(oc) {
            return Err((
                SkipReason::Indistinguishable,
                format!("{}:{}", scan.files[other.file].rel, oc.line_hint),
            ));
        }
    }
    match cand.pick_primary(primaries, counts) {
        Some(kind) => Ok(kind),
        None => Err((
            SkipReason::IdentityTaken,
            format!(
                "all four keys are already another site's primary, nearest of them {}",
                cand.locations[RadiusKind::StatementId.code() as usize].hex()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::site::TagWidth;
    use swp_identity::ProtectConfig;

    fn temp(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-select-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn keys() -> swp_manifest::ManifestKeys {
        use swp_core::id::{ProjectId, ReleaseId};
        use swp_core::version::CanonicalizerVersion;
        use swp_crypto::RootSecret;
        swp_manifest::ManifestKeys::derive(
            &RootSecret::from_bytes(&[11u8; 32]).unwrap(),
            &ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            &ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            CanonicalizerVersion::V1,
        )
    }

    fn scan_of(root: &std::path::Path) -> Scan {
        let cfg = ProtectConfig::default();
        let limits = Limits::default();
        let walked = crate::walk::walk(root, &cfg, &limits).unwrap();
        crate::candidates::scan(root, &walked, &keys(), &cfg, TagWidth::DEFAULT, &limits).unwrap()
    }

    /// A tree of `files` modules, each with `sites` literals in separate scopes.
    fn tree(label: &str, files: usize, sites: usize) -> std::path::PathBuf {
        let root = temp(label);
        for f in 0..files {
            let mut body = String::new();
            for s in 0..sites {
                body.push_str(&format!(
                    "function fn_{f}_{s}(base) {{\n  return base + {};\n}}\n",
                    1000 + f * 100 + s
                ));
            }
            write(&root, &format!("src/m{f}.js"), &body);
        }
        root
    }

    #[test]
    fn selection_is_deterministic_for_one_tree() {
        let root = tree("det", 4, 6);
        let scan = scan_of(&root);
        let a = select(&scan, 12, &Limits::default()).unwrap();
        let b = select(&scan, 12, &Limits::default()).unwrap();
        assert_eq!(a.chosen, b.chosen);
        assert_eq!(a.chosen.len(), 12);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_constellation_spreads_across_files_before_it_depthens_one() {
        let root = tree("spread", 5, 8);
        let scan = scan_of(&root);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        let per_file = sel.chosen.iter().fold(vec![0usize; 5], |mut acc, c| {
            acc[c.file] += 1;
            acc
        });
        assert!(
            per_file.iter().all(|n| *n >= 2),
            "every file should carry sites: {per_file:?}"
        );
        assert_eq!(sel.chosen.len(), 10);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_that_cannot_fill_its_share_does_not_waste_the_request() {
        // Three files hold nothing but module-level literals, so each can carry one
        // site; a fourth has functions. An even share would stop at 4 of 10, and
        // the wider second pass is what reaches the request.
        let root = temp("ladder");
        for f in 0..3 {
            write(
                &root,
                &format!("src/m{f}.js"),
                "export const A = 1000;
export const B = 2000;
",
            );
        }
        let mut many = String::new();
        for s in 0..9 {
            many.push_str(&format!(
                "function f{s}(v) {{
  return v + {};
}}
",
                3000 + s
            ));
        }
        write(&root, "src/busy.js", &many);
        let scan = scan_of(&root);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        assert_eq!(sel.chosen.len(), 10, "{:?}", sel.skipped);
        // Files are indexed in canonical path order, so `src/busy.js` is 0 and the
        // three module-level files follow. Each of those can hold exactly one site,
        // so the surplus has to go to the file with room: the ladder's second pass
        // is what stops a spread-first policy from stalling at four of ten.
        let per_file: Vec<usize> = (0..scan.files.len())
            .map(|f| sel.chosen_at(f).len())
            .collect();
        assert!(
            per_file[1..].iter().all(|n| *n <= 1),
            "one site per module-level file: {per_file:?}"
        );
        assert!(
            per_file[0] >= 7,
            "the file with room took what the others could not: {per_file:?}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn only_one_site_is_taken_per_radius_pair() {
        // One statement, two literals: whichever order the file offered them in,
        // the second must lose to the first because its radius is the same
        // statement, and a rewrite of one changes the other's address.
        let root = temp("oneper");
        write(
            &root,
            "src/a.js",
            "function f() {\n  return 100 + 200 + 300 + 400;\n}\nf(1);\n",
        );
        let scan = scan_of(&root);
        assert!(scan.files[0].usable() >= 4);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        assert_eq!(sel.chosen.len(), 1, "{:?}", sel.chosen);
        let overlaps: Vec<_> = sel
            .skipped
            .iter()
            .filter(|s| s.reason == SkipReason::OverlappingRadius)
            .collect();
        assert!(!overlaps.is_empty(), "{:?}", sel.skipped);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn siblings_in_one_scope_compete_too_because_they_share_its_key() {
        let root = temp("scope");
        write(
            &root,
            "src/a.js",
            "function f(a, b) {\n  const x = a + 100;\n  const y = b + 200;\n  return x * y;\n}\n",
        );
        let scan = scan_of(&root);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        let in_file = sel.chosen.iter().filter(|c| c.file == 0).count();
        assert_eq!(in_file, 1, "the function is one scope: {:?}", sel.chosen);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn module_level_sites_are_one_per_file_for_the_same_reason() {
        let root = temp("module");
        write(
            &root,
            "src/a.js",
            "export const A = 1000;\nexport const B = 2000;\nexport const C = 3000;\n",
        );
        let scan = scan_of(&root);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        assert_eq!(sel.chosen.len(), 1, "{:?}", sel.skipped);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn two_sites_with_identical_statements_still_get_distinct_identities() {
        let root = temp("twin");
        // Same statement text, different scopes: the statement keys collide, so one
        // of the two must be addressed by its scope key instead of sharing a
        // primary identity.
        write(
            &root,
            "src/a.js",
            "function one(v) {\n  return v + 100;\n}\nfunction two(v) {\n  return v + 200;\n}\n",
        );
        let scan = scan_of(&root);
        let sel = select(&scan, 10, &Limits::default()).unwrap();
        assert_eq!(sel.chosen.len(), 2, "{:?}", sel.skipped);
        let primaries: Vec<LocationId> = sel
            .chosen
            .iter()
            .map(|c| {
                let cand = &scan.files[c.file].candidates[c.candidate];
                cand.locations[c.primary.code() as usize]
            })
            .collect();
        let mut set = primaries.clone();
        set.sort();
        set.dedup();
        assert_eq!(set.len(), primaries.len(), "primaries must not repeat");
        assert!(
            sel.chosen
                .iter()
                .any(|c| c.primary != RadiusKind::StatementId),
            "one of them moved out to a wider key: {:?}",
            sel.chosen
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The number of sites a tree can hold is a property of the tree, not of the
    /// secret protecting it: geometry decides who blocks whom, and the key only
    /// picks which of two mutually-blocking candidates takes the slot. Before the
    /// footprint ordering this measured 8–15 of the same 24-site request across
    /// secrets, which is a constellation size no document can quote.
    #[test]
    fn capacity_does_not_depend_on_the_secret() {
        let root = tree("capacity", 4, 6);
        let limits = Limits::default();
        let cfg = ProtectConfig::default();
        let walked = crate::walk::walk(&root, &cfg, &limits).unwrap();
        let reach = |secret: u8| {
            let keys = swp_manifest::ManifestKeys::derive(
                &swp_crypto::RootSecret::from_bytes(&[secret; 32]).unwrap(),
                &swp_core::id::ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
                &swp_core::id::ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
                swp_core::version::CanonicalizerVersion::V1,
            );
            let s =
                crate::candidates::scan(&root, &walked, &keys, &cfg, TagWidth::DEFAULT, &limits)
                    .unwrap();
            let sel = select(&s, 8, &limits).unwrap();
            let mut footprint: Vec<(usize, u32)> = sel
                .chosen
                .iter()
                .map(|c| {
                    let cand = &s.files[c.file].candidates[c.candidate];
                    (c.file, cand.blocks_until())
                })
                .collect();
            footprint.sort();
            (sel.chosen.len(), footprint)
        };
        let (n1, f1) = reach(11);
        let (n2, f2) = reach(214);
        assert!(n1 > 1, "the fixture holds {n1} sites, which tests nothing");
        assert_eq!(n1, n2, "two secrets placed a different number of sites");
        assert_eq!(
            f1, f2,
            "two secrets filled a different set of slots, so the key decided geometry \
             rather than the tie inside it"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_unplaceable_request_reports_the_shortfall_once() {
        let root = tree("short", 1, 1);
        let scan = scan_of(&root);
        let sel = select(&scan, 20, &Limits::default()).unwrap();
        assert_eq!(sel.chosen.len(), 1);
        assert!(
            sel.skipped
                .iter()
                .any(|s| s.note.contains("1 of 20 requested")),
            "{:?}",
            sel.skipped
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_tree_with_no_sites_at_all_is_an_error_not_an_empty_release() {
        let root = temp("nosites");
        write(&root, "src/a.js", "function f(v) {\n  return v;\n}\n");
        let scan = scan_of(&root);
        let e = select(&scan, 10, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NoSafeLocations);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_ceiling_trimmed_request_says_which_limit_applied() {
        let root = tree("trimmed", 6, 6);
        let scan = scan_of(&root);
        let limits = Limits {
            max_locations_per_manifest: 4,
            ..Limits::default()
        };
        let sel = select(&scan, 30, &limits).unwrap();
        assert_eq!(sel.chosen.len(), 4);
        assert!(
            sel.skipped
                .iter()
                .any(|s| s.reason == SkipReason::LimitReached && s.note.contains("30")),
            "{:?}",
            sel.skipped
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_manifest_ceiling_caps_the_constellation() {
        let root = tree("ceiling", 6, 6);
        let scan = scan_of(&root);
        let limits = Limits {
            max_locations_per_manifest: 5,
            ..Limits::default()
        };
        let sel = select(&scan, 30, &limits).unwrap();
        assert_eq!(sel.chosen.len(), 5);
        assert_eq!(sel.target, 5, "the ceiling is what the run asked for");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn every_candidate_is_accounted_for_as_chosen_or_skipped() {
        let root = tree("account", 3, 5);
        let scan = scan_of(&root);
        let total = scan.total_candidates();
        let sel = select(&scan, 8, &Limits::default()).unwrap();
        assert_eq!(
            sel.chosen.len() + sel.skipped.len(),
            total,
            "no candidate may vanish: chosen {:?} skipped {:?}",
            sel.chosen.len(),
            sel.skipped.len()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn chosen_sites_are_listed_in_file_and_source_order() {
        let root = tree("order", 3, 4);
        let scan = scan_of(&root);
        let sel = select(&scan, 9, &Limits::default()).unwrap();
        let flat: Vec<(usize, u32)> = sel
            .chosen
            .iter()
            .map(|c| {
                (
                    c.file,
                    scan.files[c.file].candidates[c.candidate].span.start,
                )
            })
            .collect();
        let mut sorted = flat.clone();
        sorted.sort();
        assert_eq!(flat, sorted, "{flat:?}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_share_ladder_is_finite_and_monotonic() {
        assert_eq!(share_ladder(16, 4), vec![4, 16]);
        // Fewer sites asked for than files available: one per file first, and a
        // second pass that can only run if three files turned out to be empty.
        assert_eq!(share_ladder(3, 10), vec![1, 3]);
        assert_eq!(share_ladder(16, 1), vec![16]);
        assert!(share_ladder(0, 0).iter().all(|n| *n >= 1));
        for (target, files) in [(1, 1), (2, 8), (30, 2), (7, 7)] {
            let ladder = share_ladder(target, files);
            assert_eq!(
                ladder.last(),
                Some(&target.max(1)),
                "{target}/{files}: {ladder:?}"
            );
            assert!(
                ladder.windows(2).all(|w| w[0] < w[1]),
                "monotonic: {ladder:?}"
            );
        }
    }
}
