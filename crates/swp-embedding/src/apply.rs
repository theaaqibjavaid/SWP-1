//! Pass three: rewrite the chosen literals, and prove the file still means the
//! same thing before a single byte of it is kept.
//!
//! This pass is the reason the whole system is allowed to touch source. Selection
//! can only ever *ask* for a rewrite; nothing here is trusted to have produced one
//! safely until the adapter has re-parsed the result. So each file goes through
//! four checks, and any of them failing costs that file its sites and nothing
//! else — the run continues, the plan records what was dropped and why, and the
//! source that failed is never written.
//!
//! 1. **The site is still where it was.** Pass one threw its token streams away,
//!    so this pass re-analyzes and matches each chosen candidate by its literal's
//!    span *and* both radii. A file that changed between the two passes is a file
//!    whose recorded addresses no longer describe it.
//! 2. **The rendering says the code it was given, over the value it replaced.**
//!    [`swp_adapters::LanguageAdapter::validate`] decodes the new spelling and
//!    compares the literal value it means.
//! 3. **Nothing around it moved.** Same check, at L1, L2 and L3, over both radii.
//!    This is the one a lie would hide in: a rewrite that changed the canonical
//!    text of its own radius would leave the manifest holding a location id no
//!    scanner could ever recompute, and the site would read as removed by someone
//!    else rather than moved by us.
//! 4. **The recorded identity is the recomputed one.** The four keys are digested
//!    again from the protected text and compared to what pass one stored. Check 3
//!    already proved the adapter's side of this; what this one pins is *this
//!    crate's* slot layout, so a mixed-up index between the four radii fails here
//!    instead of in a detection run months later.
//!
//! ## Why nothing is written here
//!
//! [`apply`] returns protected text rather than saving it. A release record is
//! only meaningful with its manifest, and a manifest only with the sources it
//! describes, so the caller writes the `.swp/` records first and the sources last.
//! The opposite order would leave protected source with no record of where the
//! fragments went, which is unrecoverable; this order leaves at worst a record of
//! a release that `swp verify` reports as incomplete, which is the honest answer
//! about a run that was interrupted.

use std::collections::BTreeMap;
use std::path::Path;

use swp_adapters::{Analysis, Edit, Registry};
use swp_core::canon::{canonicalize, ByteSpan, CanonLevel};
use swp_core::error::SwpError;
use swp_core::id::{Digest, LocationId};
use swp_core::limits::Limits;
use swp_core::radius_digests;
use swp_core::site::{FormFamily, RadiusKind, TagWidth};
use swp_core::text::decode_utf8_strict;
use swp_manifest::{ManifestKeys, SiteEntry, MAX_HINT_LEN};

use crate::candidates::{line_of, line_starts, Candidate, FileScan, Scan};
use crate::select::{Chosen, Selection};

/// One file this run rewrote, in memory.
#[derive(Debug, Clone)]
pub struct Rewritten {
    pub rel: String,
    /// The protected text, whole. The caller writes it, last.
    pub text: String,
    /// L1 canonical digest of the protected text, which is this file's fingerprint
    /// input. [`Scan`]'s pre-write digest is kept for every file the run did not
    /// touch, so the release fingerprint covers the tree as released rather than
    /// as found.
    pub l1_digest: Digest,
    pub sites: u32,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// One site that was selected and then refused. It stays in the plan, because a
/// plan that lists only what succeeded would read as a smaller request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub file: String,
    pub line_hint: u32,
    pub literal: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Applied {
    /// Manifest entries, in (file, span) order.
    pub entries: Vec<SiteEntry>,
    pub files: Vec<Rewritten>,
    pub dropped: Vec<Dropped>,
    /// Sites the adapter proved end to end, which is every entry here plus none of
    /// the dropped ones — the two are never allowed to overlap.
    pub proved: u32,
}

impl Applied {
    pub fn sites(&self) -> usize {
        self.entries.len()
    }

    pub fn wrote(&self, rel: &str) -> bool {
        self.files.iter().any(|f| f.rel == rel)
    }

    /// The digest each unmodified file contributes to the release fingerprint.
    pub fn untouched_digests(&self, scan: &Scan) -> BTreeMap<String, Digest> {
        scan.files
            .iter()
            .filter(|f| !self.wrote(&f.rel))
            .map(|f| (f.rel.clone(), f.l1_digest))
            .collect()
    }

    /// Every file's fingerprint input, protected and untouched together.
    pub fn fingerprint_inputs(&self, scan: &Scan) -> BTreeMap<String, Digest> {
        let mut out = self.untouched_digests(scan);
        for file in &self.files {
            out.insert(file.rel.clone(), file.l1_digest);
        }
        out
    }
}

/// Rewrite every selected site that survives proof.
pub fn apply(
    root: &Path,
    scan: &Scan,
    selection: &Selection,
    keys: &ManifestKeys,
    width: TagWidth,
    limits: &Limits,
) -> Result<Applied, SwpError> {
    let registry = Registry::standard();
    let mut out = Applied::default();

    // Group by file, keeping the (file, span) order selection produced, so the
    // splice below only ever rewrites text that later sites have already passed.
    let mut by_file: BTreeMap<usize, Vec<&Chosen>> = BTreeMap::new();
    for chosen in &selection.chosen {
        by_file.entry(chosen.file).or_default().push(chosen);
    }

    for (file_index, chosen) in by_file {
        let file = &scan.files[file_index];
        if Path::new(&file.rel).is_absolute() {
            return Err(SwpError::internal(format!(
                "scan path {:?} is not project-relative",
                file.rel
            )));
        }
        let abs = root.join(&file.rel);
        let before = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(e) => {
                drop_sites(&mut out, file, &chosen, &format!("cannot re-read: {e}"));
                continue;
            }
        };
        let Some(before_text) = decode_utf8_strict(&before) else {
            drop_sites(
                &mut out,
                file,
                &chosen,
                "the file is no longer valid UTF-8 text",
            );
            continue;
        };
        let analysis = match registry.analyze(Path::new(&file.rel), before_text, limits) {
            Ok(a) => a,
            Err(e) => {
                drop_sites(
                    &mut out,
                    file,
                    &chosen,
                    &format!("re-analysis failed: {}", e.message()),
                );
                continue;
            }
        };
        let Some(adapter) = registry.for_path(Path::new(&file.rel)) else {
            drop_sites(
                &mut out,
                file,
                &chosen,
                "no language adapter for this file type",
            );
            continue;
        };
        let dialect = adapter.dialect();
        // The file must be the one pass one addressed. Comparing the L1 canonical
        // digest catches what a span match cannot: an edit that kept the literal's
        // offsets and its radii's offsets while changing the text inside them —
        // `v + 1000` rewritten to `v + 4242` is four characters for four — would
        // otherwise be embedded as though it still held `1000`, and the manifest
        // would record an original that is not in the file.
        if canonicalize(&analysis.tokens, CanonLevel::L1, None).digest() != file.l1_digest {
            drop_sites(
                &mut out,
                file,
                &chosen,
                "the file's canonical text changed after the scan; re-run protect",
            );
            continue;
        }

        let mut text = before_text.to_string();
        let mut delta: i64 = 0;
        let mut edits: Vec<Edit> = Vec::with_capacity(chosen.len());
        // The candidate each edit came from, and the grammar path of the site it
        // matched in this analysis, kept parallel to `edits` so the post-check can
        // compare identities without guessing which is which.
        let mut pairs: Vec<(usize, ByteSpan, String)> = Vec::with_capacity(chosen.len());

        for ch in &chosen {
            let cand = &file.candidates[ch.candidate];
            let Some((site_index, site)) = find_site(&analysis, cand) else {
                out.dropped.push(Dropped {
                    file: file.rel.clone(),
                    line_hint: cand.line_hint,
                    literal: cand.original.clone(),
                    reason: "the literal or one of its radii is no longer where the scan found it"
                        .to_string(),
                });
                continue;
            };
            let families = site.families(width, dialect);
            if families.is_empty() {
                out.dropped.push(Dropped {
                    file: file.rel.clone(),
                    line_hint: cand.line_hint,
                    literal: cand.original.clone(),
                    reason: format!(
                        "no equivalent form reaches a {}-bit code at this site",
                        width.bits()
                    ),
                });
                continue;
            }
            let code = keys.fragment_tag(&cand.locations[ch.primary.code() as usize], width);
            // Families are tried from a keyed start rather than always the first, so
            // a project's sites spread across every family the form engine has
            // instead of exhausting one before touching the next.
            let start = index_of(&cand.priority, families.len());
            let mut rendering: Option<(FormFamily, String)> = None;
            for offset in 0..families.len() {
                let family = families[(start + offset) % families.len()];
                let Ok(spelling) = adapter.render(&analysis, site_index, family, code, width)
                else {
                    continue;
                };
                if !carries_watermark(&spelling, &cand.original) {
                    // Either it did not change the literal at all, or it changed it
                    // into something a signed document cannot hold. The next family
                    // may still work, and §11 says try that rather than force this.
                    continue;
                }
                rendering = Some((family, spelling));
                break;
            }
            let Some((family, spelling)) = rendering else {
                out.dropped.push(Dropped {
                    file: file.rel.clone(),
                    line_hint: cand.line_hint,
                    literal: cand.original.clone(),
                    reason: format!(
                        "no family reachable here rendered code {code} as a distinct, \
                         recordable literal"
                    ),
                });
                continue;
            };

            let Some(range) = shifted(cand.span, delta) else {
                return Err(SwpError::internal(format!(
                    "site at {} in {} lies outside the text after earlier edits",
                    cand.span.start, file.rel
                )));
            };
            let rendered = ByteSpan::new(range.start as u32, (range.start + spelling.len()) as u32);
            text.replace_range(range, &spelling);
            delta += spelling.len() as i64 - cand.span.len() as i64;
            edits.push(
                Edit::new(site_index, cand.span, spelling.clone(), family, code, width)
                    .with_rendered(rendered),
            );
            pairs.push((ch.candidate, rendered, site.path.clone()));
        }

        if edits.is_empty() {
            // Nothing survived. The file is left exactly as it was found, which is
            // the only outcome its bytes can be trusted to have.
            continue;
        }

        // Checks 2 and 3, performed by the adapter against the text as it would be
        // written, before that text exists anywhere but here.
        let proof = match adapter.validate(before_text, &text, &edits) {
            Ok(p) => p,
            Err(e) => {
                drop_sites(
                    &mut out,
                    file,
                    &chosen,
                    &format!("the adapter refused the rewrite: {}", e.message()),
                );
                continue;
            }
        };
        if !proof.is_complete(edits.len() as u32, analysis.parse_errors) {
            drop_sites(
                &mut out,
                file,
                &chosen,
                &format!(
                    "the adapter proved {} of {} sites at {} of {} levels",
                    proof.sites_verified,
                    edits.len(),
                    proof.levels_stable,
                    swp_adapters::ALL_LEVELS
                ),
            );
            continue;
        }

        // Check 4: recompute each site's four keys from the protected text.
        let protected = match registry.analyze(Path::new(&file.rel), &text, limits) {
            Ok(a) => a,
            Err(e) => {
                drop_sites(
                    &mut out,
                    file,
                    &chosen,
                    &format!("the protected text does not analyze: {}", e.message()),
                );
                continue;
            }
        };
        let starts = line_starts(&text);
        let mut entries: Vec<SiteEntry> = Vec::with_capacity(edits.len());
        let mut refused: Option<String> = None;
        for (edit, (candidate_index, rendered, grammar_path)) in edits.iter().zip(&pairs) {
            let cand = &file.candidates[*candidate_index];
            let digests = radius_digests(
                &protected.tokens,
                protected.statement_span_at(rendered.start),
                protected.scope_span_at(rendered.start),
                *rendered,
            );
            let recomputed = keys.location_ids(&digests);
            if recomputed != cand.locations {
                refused = Some(explain_key_drift(cand, &recomputed));
                break;
            }
            let Some(ch) = chosen.iter().find(|c| c.candidate == *candidate_index) else {
                return Err(SwpError::internal("an edit lost its selection record"));
            };
            entries.push(SiteEntry {
                locations: cand.locations,
                primary: ch.primary.code(),
                file: file.rel.clone(),
                line_hint: line_of(&starts, rendered.start),
                language: file.language.clone(),
                adapter: file.adapter.to_string(),
                // The path as recorded for the site we planned, not as re-found in
                // the protected text: once `(1015 - 14)` is in place the parser
                // sees two number literals inside a parenthesized expression, and
                // neither is the site the manifest is describing.
                grammar_path: grammar_path.clone(),
                class: cand.class,
                family: edit.family,
                width: width.bits(),
                original: cand.original.clone(),
                rendered: edit.rendering.clone(),
            });
        }
        if let Some(why) = refused {
            drop_sites(&mut out, file, &chosen, &why);
            continue;
        }

        out.proved += proof.sites_verified;
        out.entries.extend(entries);
        out.files.push(Rewritten {
            sites: edits.len() as u32,
            bytes_before: before.len() as u64,
            bytes_after: text.len() as u64,
            l1_digest: canonicalize(&protected.tokens, CanonLevel::L1, None).digest(),
            rel: file.rel.clone(),
            text,
        });
    }

    Ok(out)
}

/// Whether a rendering is a watermark this system may record.
///
/// `original == rendered` would leave a site that carries no bits and proves
/// nothing; a rendering longer than the hint bound would make the whole signed
/// manifest invalid, which is a disproportionate way for one literal to fail; and
/// a control character cannot be described in a JSON document at all. All three
/// are refused per-site here, while the other families are still available.
fn carries_watermark(rendered: &str, original: &str) -> bool {
    rendered != original
        && rendered.len() <= MAX_HINT_LEN
        && !rendered.chars().any(|c| c.is_control())
}

/// A scan-time span, moved into the coordinates of the text being built.
///
/// Every accepted site's radius is disjoint from every other's, so an earlier edit
/// can only have changed the *offset* of a later site, never its length or its
/// surroundings; `delta` is the running sum of the length changes before it.
fn shifted(span: ByteSpan, delta: i64) -> Option<std::ops::Range<usize>> {
    let start = span.start as i64 + delta;
    let end = span.end as i64 + delta;
    if start < 0 || end < start {
        return None;
    }
    Some(start as usize..end as usize)
}

/// The site in a fresh analysis that a scan-time candidate described.
///
/// Matched on the literal's span *and* both radii: a re-analysis that puts the
/// same literal inside a different statement or scope describes a different
/// address, and embedding there would write a rendering whose recorded keys were
/// digested from other text.
fn find_site<'a>(
    analysis: &'a Analysis,
    cand: &Candidate,
) -> Option<(usize, &'a swp_adapters::CandidateSite)> {
    analysis.sites.iter().enumerate().find(|(_, s)| {
        s.span == cand.span && s.statement == cand.statement && s.scope == cand.scope
    })
}

/// A stable index into `n` choices, from a keyed 32-byte value.
///
/// The accumulator computes `priority mod n` over the whole hash rather than
/// masking off low bits, which would starve later families whenever `n` is not a
/// power of two. The leftover bias is below 2^-250 for any family count the form
/// engine has. Rejection sampling is not available: a fixed-length input either
/// lands in range or it does not, and a fallback that re-hashed would make the
/// choice depend on `n` in a way no future reader would think to re-derive.
fn index_of(priority: &[u8; 32], n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let modulus = n as u64;
    let mut acc: u64 = 0;
    for byte in priority {
        acc = (acc.wrapping_mul(256) + u64::from(*byte)) % modulus;
    }
    acc as usize
}

/// Which of the four keys drifted, for the drop note.
fn explain_key_drift(cand: &Candidate, recomputed: &[LocationId; 4]) -> String {
    let mut drifted: Vec<&str> = Vec::new();
    for (i, kind) in RadiusKind::all().iter().enumerate() {
        if recomputed[i] != cand.locations[i] {
            drifted.push(kind.as_str());
        }
    }
    format!(
        "the protected text no longer digests to this site's recorded identity ({})",
        drifted.join(", ")
    )
}

/// Refuse a whole file's rewrite under one reason.
///
/// Two different failures, two different scopes. A site that cannot be located at
/// all is skipped on its own — nothing about its neighbours was disproved, and
/// §11 asks for the smallest refusal available. A file whose *proof* fails is
/// given up entirely, because the proof compared each site's radii against a text
/// that already contained the other sites' renderings: if that comparison did not
/// hold, no site in the batch can claim its recorded identity, and a manifest
/// describing some of them would report the rest as removal by someone else.
fn drop_sites(out: &mut Applied, file: &FileScan, chosen: &[&Chosen], why: &str) {
    for ch in chosen {
        let cand = &file.candidates[ch.candidate];
        out.dropped.push(Dropped {
            file: file.rel.clone(),
            line_hint: cand.line_hint,
            literal: cand.original.clone(),
            reason: why.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_core::version::CanonicalizerVersion;
    use swp_crypto::RootSecret;
    use swp_identity::ProtectConfig;

    fn temp(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-apply-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn keys(release: &str) -> ManifestKeys {
        ManifestKeys::derive(
            &RootSecret::from_bytes(&[11u8; 32]).unwrap(),
            &ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            &ReleaseId::new(release).unwrap(),
            CanonicalizerVersion::V1,
        )
    }

    fn width() -> TagWidth {
        TagWidth::DEFAULT
    }

    /// Walk, scan and select, the way `protect` does.
    fn plan(root: &Path, k: &ManifestKeys, target: u32) -> (Scan, Selection) {
        let cfg = ProtectConfig::default();
        let limits = Limits::default();
        let walked = crate::walk::walk(root, &cfg, &limits).unwrap();
        let scan = crate::candidates::scan(root, &walked, k, &cfg, width(), &limits).unwrap();
        let sel = crate::select::select(&scan, target, &limits).unwrap();
        (scan, sel)
    }

    fn run(root: &Path, k: &ManifestKeys, target: u32) -> Applied {
        let (scan, sel) = plan(root, k, target);
        apply(root, &scan, &sel, k, width(), &Limits::default()).unwrap()
    }

    /// A module of `sites` functions, each with one distinct literal.
    fn module(label: &str, sites: usize) -> (std::path::PathBuf, String) {
        let root = temp(label);
        let mut body = String::new();
        for s in 0..sites {
            body.push_str(&format!(
                "function calc_{s}(base, scale) {{\n  return base * scale + {};\n}}\n",
                1000 + s
            ));
        }
        write(&root, "src/a.js", &body);
        let original = body.clone();
        (root, original)
    }

    #[test]
    fn an_applied_site_carries_its_code_over_its_own_value() {
        let (root, _) = module("proof", 6);
        let k = keys("rel-aaaaaaaaaaaa");
        let applied = run(&root, &k, 6);
        assert_eq!(applied.sites(), 6, "{:?}", applied.dropped);
        assert_eq!(applied.proved, 6);
        let registry = Registry::standard();
        let adapter = registry.for_path(Path::new("src/a.js")).unwrap();
        for entry in &applied.entries {
            assert_ne!(entry.original, entry.rendered);
            assert_eq!(entry.width, width().bits());
            let decoded = adapter
                .extract(&entry.rendered, entry.family, width())
                .expect("a rendering must decode as the family that made it");
            assert_eq!(
                decoded.canonical_value(),
                entry.original,
                "{} became {} and no longer means the same literal",
                entry.original,
                entry.rendered
            );
            let expected = k.fragment_tag(&entry.primary_id().unwrap(), width());
            assert_eq!(decoded.code(), expected, "the site carries the wrong tag");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_protected_text_is_returned_but_not_written() {
        let (root, original) = module("nowrite", 4);
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 4);
        assert_eq!(applied.sites(), 4, "{:?}", applied.dropped);
        assert_eq!(
            std::fs::read_to_string(root.join("src/a.js")).unwrap(),
            original,
            "pass three must not touch the tree"
        );
        assert_ne!(applied.files[0].text, original);
        assert!(applied.wrote("src/a.js"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn every_entry_is_addressable_again_in_the_protected_text() {
        let (root, _) = module("roundtrip", 5);
        let k = keys("rel-aaaaaaaaaaaa");
        let applied = run(&root, &k, 5);
        let registry = Registry::standard();
        let file = &applied.files[0];
        let analysis = registry
            .analyze(Path::new("src/a.js"), &file.text, &Limits::default())
            .unwrap();
        assert_eq!(applied.sites(), 5, "{:?}", applied.dropped);
        for entry in &applied.entries {
            // This is a scanner's whole job: find the literal, digest its radii,
            // derive its keys. Note that nothing here reads `file` or `line_hint`.
            let offset = file
                .text
                .find(&entry.rendered)
                .unwrap_or_else(|| panic!("{} is not in the protected text", entry.rendered))
                as u32;
            let span = ByteSpan::new(offset, offset + entry.rendered.len() as u32);
            let digests = radius_digests(
                &analysis.tokens,
                analysis.statement_span_at(span.start),
                analysis.scope_span_at(span.start),
                span,
            );
            assert_eq!(
                k.location_ids(&digests),
                entry.locations,
                "{} is not addressable in its own protected text",
                entry.rendered
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn no_two_sites_in_a_release_share_a_tag() {
        let (root, _) = module("primaries", 6);
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 6);
        let k = keys("rel-aaaaaaaaaaaa");
        let mut seen = std::collections::BTreeSet::new();
        for entry in &applied.entries {
            assert!(seen.insert(entry.primary_id().unwrap().hex()));
            let _ = k;
        }
        assert_eq!(seen.len(), applied.sites());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_changed_between_the_scan_and_the_write_loses_its_own_sites_only() {
        let root = temp("raced");
        write(
            &root,
            "src/a.js",
            "function one(v) {\n  return v + 1000;\n}\n",
        );
        write(
            &root,
            "src/b.js",
            "function two(v) {\n  return v + 2000;\n}\nfunction three(v) {\n  return v + 3000;\n}\n",
        );
        let k = keys("rel-aaaaaaaaaaaa");
        let (scan, sel) = plan(&root, &k, 3);
        assert_eq!(sel.chosen.len(), 3, "{:?}", sel.skipped);
        // The scan still describes `src/a.js` as it was; the file on disk has been
        // rewritten under it, so its address no longer means anything.
        write(
            &root,
            "src/a.js",
            "function one(v) {\n  return v + 4242;\n}\n",
        );
        let applied = apply(&root, &scan, &sel, &k, width(), &Limits::default()).unwrap();
        let dropped_a: Vec<&Dropped> = applied
            .dropped
            .iter()
            .filter(|d| d.file == "src/a.js")
            .collect();
        assert_eq!(dropped_a.len(), 1, "{:?}", applied.dropped);
        assert!(
            dropped_a[0].reason.contains("changed after the scan"),
            "{}",
            dropped_a[0].reason
        );
        // The other file was never in question.
        assert_eq!(
            applied
                .entries
                .iter()
                .filter(|e| e.file == "src/b.js")
                .count(),
            2,
            "{:?}",
            applied.entries
        );
        assert!(!applied.wrote("src/a.js"));
        assert!(
            !applied.entries.iter().any(|e| e.file == "src/a.js"),
            "a four-character edit that kept every offset must still be refused"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("src/a.js")).unwrap(),
            "function one(v) {\n  return v + 4242;\n}\n",
            "the raced file keeps whatever the other process wrote"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_rendering_that_changes_nothing_or_cannot_be_recorded_is_refused() {
        assert!(!carries_watermark("100", "100"));
        assert!(!carries_watermark(&"x".repeat(MAX_HINT_LEN + 1), "y"));
        assert!(!carries_watermark("a\nb", "c"));
        assert!(carries_watermark("(100 + 0)", "100"));
    }

    #[test]
    fn family_choice_is_keyed_spread_and_in_range() {
        let mut counts = [0u32; 4];
        for i in 0..400u16 {
            let mut priority = [0u8; 32];
            priority[31] = (i % 256) as u8;
            priority[30] = (i / 256) as u8;
            counts[index_of(&priority, 4)] += 1;
        }
        assert!(
            counts.iter().all(|c| *c > 60),
            "a family is being starved: {counts:?}"
        );
        assert_eq!(index_of(&[0u8; 32], 1), 0);
        assert_eq!(index_of(&[0u8; 32], 0), 0);
        for n in 1..8usize {
            assert!(index_of(&[0xffu8; 32], n) < n);
        }
    }

    #[test]
    fn a_site_that_cannot_be_located_is_skipped_without_touching_its_neighbours() {
        let (root, original) = module("stale", 3);
        let k = keys("rel-aaaaaaaaaaaa");
        let (mut scan, sel) = plan(&root, &k, 3);
        assert_eq!(sel.chosen.len(), 3, "{:?}", sel.skipped);
        // Claim, wrongly, that a candidate's enclosing scope is empty, so the
        // re-analysis cannot find a site at that address.
        let cand = &mut scan.files[0].candidates[0];
        cand.scope = ByteSpan::new(cand.span.end, cand.span.end);
        let first = scan.files[0].candidates[0].original.clone();
        let applied = apply(&root, &scan, &sel, &k, width(), &Limits::default()).unwrap();
        // §11's smallest refusal: the unlocatable site is skipped, and the two
        // whose addresses still describe them are embedded.
        assert_eq!(applied.sites(), 2, "{:?}", applied.entries);
        assert_eq!(applied.dropped.len(), 1, "{:?}", applied.dropped);
        assert_eq!(applied.dropped[0].literal, first);
        assert!(applied.dropped[0].reason.contains("no longer where"));
        let written = &applied.files[0].text;
        assert!(
            written.contains(&first),
            "the skipped site's literal must still read exactly as it did: {written}"
        );
        assert_eq!(applied.files[0].sites, 2);
        assert_eq!(
            std::fs::read_to_string(root.join("src/a.js")).unwrap(),
            original,
            "nothing is written by this pass"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fingerprint_inputs_cover_every_file_exactly_once() {
        let root = temp("fingerprint");
        write(
            &root,
            "src/a.js",
            "function one(v) {\n  return v + 1000;\n}\n",
        );
        write(
            &root,
            "src/b.js",
            "function two(v) {\n  return v * 2 + 2000;\n}\n",
        );
        write(
            &root,
            "src/c.ts",
            "const x: number = 3000;\nexport { x };\n",
        );
        let k = keys("rel-aaaaaaaaaaaa");
        let (scan, sel) = plan(&root, &k, 10);
        let applied = apply(&root, &scan, &sel, &k, width(), &Limits::default()).unwrap();
        let inputs = applied.fingerprint_inputs(&scan);
        assert_eq!(inputs.len(), scan.files.len(), "one entry per walked file");
        for file in &scan.files {
            let digest = inputs[&file.rel];
            if applied.wrote(&file.rel) {
                let rewritten = applied.files.iter().find(|f| f.rel == file.rel).unwrap();
                assert_eq!(digest, rewritten.l1_digest);
                assert_ne!(digest, file.l1_digest, "{} was rewritten", file.rel);
            } else {
                assert_eq!(digest, file.l1_digest);
            }
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn every_proved_site_is_recorded_and_no_record_is_unproved() {
        let (root, _) = module("levels", 5);
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 5);
        assert_eq!(applied.sites(), 5, "{:?}", applied.dropped);
        assert_eq!(applied.proved as usize, applied.sites());
        let written: u32 = applied.files.iter().map(|f| f.sites).sum();
        assert_eq!(written as usize, applied.sites());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_python_module_protects_the_same_way_as_a_javascript_one() {
        let root = temp("py");
        write(
            &root,
            "src/a.py",
            "def one(value):\n    return value + 1000\n\n\ndef two(value):\n    return value + 2000\n",
        );
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 2);
        assert_eq!(applied.sites(), 2, "{:?}", applied.dropped);
        assert_eq!(applied.entries[0].language, "python");
        assert_eq!(applied.entries[0].adapter, "ast");
        assert!(applied.files[0].text.contains("def one"));
        assert!(applied.files[0].text.contains("value"), "names kept");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn entries_name_the_adapter_mode_the_manifest_accepts() {
        let (root, _) = module("labels", 2);
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 2);
        let registry = Registry::standard();
        for entry in &applied.entries {
            assert!(matches!(entry.adapter.as_str(), "ast" | "lexical"));
            let kind = registry.for_language(&entry.language).capabilities().kind;
            assert_eq!(
                entry.adapter,
                crate::candidates::adapter_label(kind),
                "the entry claims a different analysis than the adapter does"
            );
            assert!(!entry.grammar_path.is_empty(), "inspect needs a path");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_site_recorded_in_a_release_is_a_site_the_manifest_will_accept() {
        let (root, _) = module("validate", 6);
        let applied = run(&root, &keys("rel-aaaaaaaaaaaa"), 6);
        let manifest = swp_manifest::PrivateManifest::build(
            ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            swp_identity::Timestamp::now_utc(),
            CanonicalizerVersion::V1.0,
            swp_core::id::Digest::default(),
            "L1",
            width().bits(),
            swp_core::version::GeneratorInfo::current(),
            applied.entries.clone(),
        );
        assert!(
            manifest.is_ok(),
            "pass three wrote entries a signed manifest cannot hold: {:?}",
            manifest.err().map(|e| e.message().to_string())
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
