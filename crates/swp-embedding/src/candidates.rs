//! Pass one: read each in-scope file once, and turn it into a list of addressable
//! sites — without keeping any of them in memory.
//!
//! The whole design of this pass is that it throws the token streams away. A
//! protection run over a real repository can hold hundreds of megabytes of
//! parsed source; what selection actually needs is one small record per candidate
//! literal, carrying its four keyed location ids and the families that can reach
//! every code at the requested width. Everything else can be recomputed in pass
//! three, for the handful of files that were chosen.
//!
//! ## What a candidate is
//!
//! A candidate is *addressable* before it is *usable*: the four location ids are
//! computed here, from the source exactly as it stands now, and the keyed tag the
//! site will carry is derived from them. That ordering matters — it is what lets
//! selection see collisions between sites that look different on screen and
//! reject them before anything is written, instead of discovering at verification
//! time that two entries in the manifest share an identity.
//!
//! ## Why the ids are computed here at all
//!
//! Because selection must be independent of file order and of what else is in the
//! tree. A priority derived from a keyed hash of the site's own identity has both
//! properties: adding a file elsewhere in the project cannot change which sites
//! this run picks, and re-running over an unchanged tree picks the same ones.

use std::collections::BTreeMap;
use std::path::Path;

use swp_adapters::{Analysis, Registry};
use swp_core::canon::{canonicalize, ByteSpan, CanonLevel};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{Digest, LocationId};
use swp_core::limits::Limits;
use swp_core::site::{FormFamily, LiteralClass, TagWidth};
use swp_core::text::decode_utf8_strict;
use swp_core::{radius_digests, RadiusKind};
use swp_identity::ProtectConfig;
use swp_manifest::{ManifestKeys, MAX_HINT_LEN};

use crate::walk::{Omission, OmissionKind, ScannedFile, Walk};

/// How a file's sites were found, spelled for the manifest and the report.
///
/// The mapping is explicit rather than `AdapterKind::as_str()` because the two
/// vocabularies genuinely differ: the adapter layer calls the fallback `"token"`,
/// while the manifest's `adapter` field is a closed set of `"ast" | "lexical"`
/// that a report reader is expected to recognize.
pub fn adapter_label(kind: swp_adapters::AdapterKind) -> &'static str {
    match kind {
        swp_adapters::AdapterKind::Ast => "ast",
        swp_adapters::AdapterKind::Lexical => "lexical",
    }
}

/// One literal that could carry a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Index into [`Scan::files`].
    pub file: usize,
    /// Index into that file's site list as the scan saw it. Pass three matches on
    /// [`Candidate::span`] rather than trusting this, because a re-analysis is a
    /// new analysis.
    pub site: usize,
    /// The literal itself.
    pub span: ByteSpan,
    /// The two radii, kept so the acceptance test in selection can ask whether one
    /// candidate's radius covers another's site.
    pub statement: ByteSpan,
    pub scope: ByteSpan,
    /// 1-based line at scan time. A hint for humans; nothing keyed reads it.
    pub line_hint: u32,
    pub class: LiteralClass,
    /// Families that reach every code at this run's width. Empty means the site
    /// was never a candidate at all, which is why selection does not re-check.
    pub families: Vec<FormFamily>,
    /// Keyed identity, indexed by [`swp_manifest::SLOTS`].
    pub locations: [LocationId; 4],
    /// Keyed, release-scoped ordering value. Smaller is chosen first among the
    /// candidates a file's geometry leaves tied; see [`crate::select`]'s header.
    pub priority: [u8; 32],
    /// The literal as written, already known to fit the manifest's hint bound.
    pub original: String,
}

impl Candidate {
    /// The key this site should carry its fragment tag under: the one that names
    /// it most precisely among the sites this scan saw, and — where several keys
    /// are equally precise — the one that survives the most rewriting. `None` when
    /// every key is already another accepted site's primary.
    ///
    /// Precision comes first because a tag is only evidence while it belongs to one
    /// site. The L3 statement key is the *most* refactor-tolerant of the four and
    /// also the weakest: `return total + 0;` canonicalizes to the same text under
    /// any names, so a repetitive module can hand twenty sites one id. Twenty
    /// sites sharing a tag means a scanner that finds that id cannot say which of
    /// the twenty it found, and the manifest's own evidence is worthless.
    ///
    /// The tie-break is [`swp_core::RadiusKind::all`] order, which runs from the
    /// rename-tolerant L3 keys to the byte-exact L1 ones, so two equally precise
    /// addresses prefer the one a rename is less likely to move.
    pub fn pick_primary(
        &self,
        taken: &std::collections::BTreeSet<LocationId>,
        counts: &KeyCounts,
    ) -> Option<RadiusKind> {
        RadiusKind::all()
            .iter()
            .copied()
            .filter(|k| !taken.contains(&self.locations[k.code() as usize]))
            .min_by_key(|k| {
                (
                    counts.twins(*k, &self.locations[k.code() as usize]),
                    k.code(),
                )
            })
    }

    /// Whether this candidate and another would leave the manifest with nothing to
    /// tell them apart.
    pub fn indistinguishable_from(&self, other: &Candidate) -> bool {
        self.locations == other.locations
    }

    /// Whether embedding at one site would sit inside the radius the other is
    /// addressed by.
    ///
    /// This is the reason two candidates can be rejected for being too close
    /// rather than for colliding. A location id is the digest of the code *around*
    /// a site; if site B's literal is inside site A's statement radius, then
    /// rewriting B changes A's radius text, so the id recorded for A describes a
    /// statement that no longer exists in the protected file. A scanner
    /// recomputing A's id from the released source would find a different value,
    /// and the site would read as "removed" when it is only "moved by our own
    /// edit". No amount of tagging fixes that, so it is prevented: one site per
    /// overlapping pair, and [`crate::select`] decides which by the order spelled
    /// out there — shortest footprint first, keyed priority breaking the ties.
    ///
    /// Keep it inside one file. Spans are byte offsets into separate documents, so
    /// comparing across files compares nothing.
    ///
    /// This is also the precondition [`swp_adapters::LanguageAdapter::validate`]
    /// needs when it compares a radius before and after: it hides one site on each
    /// side, which is only a fair test if no second site moved inside that radius.
    pub fn radii_overlap(&self, other: &Candidate) -> bool {
        covers(self.statement, other.span)
            || covers(self.scope, other.span)
            || covers(other.statement, self.span)
            || covers(other.scope, self.span)
    }

    /// How far into the file this candidate's own edit reaches: the end of the
    /// wider of its two radii.
    ///
    /// Selection walks a file's candidates in this order, because the geometry
    /// that makes two candidates compete is fixed by the tree while the key that
    /// breaks a tie is not — see [`Self::radii_overlap`].
    pub fn blocks_until(&self) -> u32 {
        self.statement.end.max(self.scope.end)
    }
}

fn covers(radius: ByteSpan, site: ByteSpan) -> bool {
    radius.contains(site.start) || radius.contains(site.end.saturating_sub(1))
}

/// One file that was read and analyzed.
#[derive(Debug, Clone)]
pub struct FileScan {
    pub rel: String,
    pub language: String,
    pub adapter: &'static str,
    /// L1 canonical digest of the file as it stood, which is the fingerprint
    /// input for every file this run does not modify.
    pub l1_digest: Digest,
    /// Literals that could carry a fragment.
    pub candidates: Vec<Candidate>,
    /// Literals examined and rejected, for the density figure in the report.
    pub refused: u32,
    pub parse_errors: u32,
    pub bytes: u64,
}

impl FileScan {
    pub fn usable(&self) -> usize {
        self.candidates.len()
    }
}

#[derive(Debug, Default)]
pub struct Scan {
    pub files: Vec<FileScan>,
    pub omissions: Vec<Omission>,
    pub bytes_read: u64,
    /// Per-language file counts, in the shape the release record wants.
    pub adapters: Vec<AdapterStat>,
    /// Selection-time notes that are not omissions: a file capped for having too
    /// many literals, say.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterStat {
    pub language: String,
    pub mode: &'static str,
    pub files: u32,
}

impl Scan {
    /// Files that could have carried evidence and did not get examined, whether
    /// the walk refused them or this pass did. A non-empty result is what makes a
    /// scan partial (§45).
    pub fn refused(&self) -> impl Iterator<Item = &Omission> + '_ {
        self.omissions
            .iter()
            .filter(|o| o.kind == OmissionKind::NotExamined)
    }

    pub fn total_candidates(&self) -> usize {
        self.files.iter().map(|f| f.candidates.len()).sum()
    }

    pub fn files_with_candidates(&self) -> usize {
        self.files.iter().filter(|f| !f.candidates.is_empty()).count()
    }

    /// How many of this scan's candidate sites share each radius key.
    pub fn key_counts(&self) -> KeyCounts {
        KeyCounts::of(self)
    }
}

/// A census of the four radius keys across one scan.
///
/// Selection reads it to decide which key carries a site's tag; see
/// [`Candidate::pick_primary`]. It counts candidates this scan offered, which is
/// the right universe: a key that is unique here is unique among the sites a
/// scanner could resolve this manifest's hits to, and other projects cannot
/// collide with any of them anyway, because every id is keyed by the project.
#[derive(Debug, Default, Clone)]
pub struct KeyCounts(BTreeMap<(u8, LocationId), u32>);

impl KeyCounts {
    pub fn of(scan: &Scan) -> Self {
        let mut out = KeyCounts::default();
        for file in &scan.files {
            for cand in &file.candidates {
                for kind in RadiusKind::all() {
                    let slot = kind.code();
                    *out
                        .0
                        .entry((slot, cand.locations[slot as usize]))
                        .or_insert(0) += 1;
                }
            }
        }
        out
    }

    /// How many candidate sites can be named by this key value. At least one:
    /// the site being asked about.
    pub fn twins(&self, kind: RadiusKind, id: &LocationId) -> u32 {
        self.0.get(&(kind.code(), *id)).copied().unwrap_or(1)
    }
}

/// Read and analyze every file the walk admitted.
pub fn scan(
    root: &Path,
    walked: &Walk,
    keys: &ManifestKeys,
    cfg: &ProtectConfig,
    width: TagWidth,
    limits: &Limits,
) -> Result<Scan, SwpError> {
    let registry = Registry::standard();
    let mut scan = Scan {
        omissions: walked.omissions.clone(),
        ..Scan::default()
    };
    let mut by_language: BTreeMap<(String, &'static str), u32> = BTreeMap::new();
    let mut budget = limits.max_total_bytes;

    for entry in &walked.files {
        let admitted = match admit(&registry, root, entry, limits, &mut budget)? {
            Admission::Skip(omission) => {
                scan.omissions.push(omission);
                continue;
            }
            Admission::Use(used) => used,
        };
        let Admitted {
            text,
            analysis,
            l1_digest,
            bytes,
        } = admitted;
        scan.bytes_read += bytes;
        let file_index = scan.files.len();
        let starts = line_starts(&text);
        let mut candidates = Vec::new();
        let mut capped = false;
        let mut strings_left_out = 0u32;
        let dialect = registry.for_language(&analysis.language).dialect();
        let usable = analysis.usable_sites(width, dialect);
        for (site_index, (site, families)) in usable.into_iter().enumerate() {
            if candidates.len() as u32 >= limits.max_sites_per_file {
                capped = true;
                break;
            }
            let original = site.source(&text).to_string();
            if original.len() > MAX_HINT_LEN {
                // A literal too long to record is a literal too long to describe
                // in a signed manifest, and truncating the record would make
                // `swp verify` compare against text that is not in the file.
                continue;
            }
            let class = if site.is_numeric() {
                LiteralClass::Integer
            } else {
                LiteralClass::String
            };
            if class == LiteralClass::String && !cfg.embed_strings {
                // The project asked for number-only watermarks, because a rewritten
                // string literal shows up in a diff and in a snapshot test. The
                // count is kept so the report can say what was left on the table.
                strings_left_out += 1;
                continue;
            }
            if !has_context(&analysis, site.statement, site.span)
                || !has_context(&analysis, site.scope, site.span)
            {
                // A radius holding nothing but the literal digests to the empty
                // canonical text, which every such site shares: two of the four
                // keys would identify nothing at all, and any copy of any other
                // site would hit them. There is no address here, so there is no
                // site.
                continue;
            }
            let digests = radius_digests(&analysis.tokens, site.statement, site.scope, site.span);
            let locations = keys.location_ids(&digests);
            candidates.push(Candidate {
                file: file_index,
                site: site_index,
                span: site.span,
                statement: site.statement,
                scope: site.scope,
                line_hint: line_of(&starts, site.span.start),
                class,
                families,
                locations,
                priority: keys.selection_priority(&locations),
                original,
            });
        }
        if strings_left_out > 0 {
            scan.notes.push(format!(
                "{}: {} string literals were not offered as sites because embed_strings is off",
                entry.rel, strings_left_out
            ));
        }
        if capped || analysis.truncated {
            // Half a file's literals is half an examination. The note is the
            // sentence for a human; the omission is the same fact in the field a
            // report consumer reads, and it is what makes the scan partial.
            scan.omissions.push(Omission {
                path: entry.rel.clone(),
                reason: if capped {
                    format!(
                        "more literals than max_sites_per_file ({}), so its site list is \
                         incomplete",
                        limits.max_sites_per_file
                    )
                } else {
                    format!(
                        "a syntax tree past this scanner's bounds (max_depth={}, \
                         max_nodes_per_tree={}), so its site list is incomplete",
                        limits.max_depth, limits.max_nodes_per_tree
                    )
                },
                kind: OmissionKind::NotExamined,
            });
            scan.notes.push(format!(
                "  limits in force: max_sites_per_file={}, max_nodes_per_tree={}, max_depth={}",
                limits.max_sites_per_file, limits.max_nodes_per_tree, limits.max_depth
            ));
        }
        *by_language
            .entry((analysis.language.clone(), adapter_label(analysis.capabilities.kind)))
            .or_insert(0) += 1;
        scan.files.push(FileScan {
            rel: entry.rel.clone(),
            language: analysis.language.clone(),
            adapter: adapter_label(analysis.capabilities.kind),
            l1_digest,
            candidates,
            refused: analysis.refusals.len() as u32,
            parse_errors: analysis.parse_errors,
            bytes,
        });
    }

    scan.adapters = by_language
        .into_iter()
        .map(|((language, mode), files)| AdapterStat { language, mode, files })
        .collect();
    Ok(scan)
}

/// One file that made it through reading and analysis.
struct Admitted {
    text: String,
    analysis: Analysis,
    /// The §16 fingerprint input: L1 canonical digest, as the file stands now.
    l1_digest: Digest,
    /// Raw bytes on disk, counted against [`Limits::max_total_bytes`].
    bytes: u64,
}

enum Admission {
    Use(Admitted),
    Skip(Omission),
}

/// Read one walked file and analyze it, or say why this pass cannot use it.
///
/// Every consumer of a file's L1 digest goes through here, including
/// [`tree_digests`]. That is the point: `swp protect` publishes a fingerprint of
/// the whole tree and a scanner recomputes one from a candidate copy, and if the
/// two read files under different rules the hashes simply never agree — the
/// exact-copy channel would stop firing on every project, quietly, with a report
/// that reads as "this copy was modified".
fn admit(
    registry: &Registry,
    root: &Path,
    entry: &ScannedFile,
    limits: &Limits,
    budget: &mut u64,
) -> Result<Admission, SwpError> {
    let abs = if entry.abs.is_absolute() {
        entry.abs.clone()
    } else {
        root.join(&entry.abs)
    };
    // Everything `admit` refuses here is a file the walk had already decided was
    // source, so every skip below is a hole in the examination rather than a
    // non-source file being ignored (§45).
    let skip = |reason: String| Admission::Skip(Omission {
        path: entry.rel.clone(),
        reason,
        kind: OmissionKind::NotExamined,
    });
    let bytes = match std::fs::read(&abs) {
        Ok(b) => b,
        Err(e) => return Ok(skip(format!("cannot read: {e}"))),
    };
    if bytes.len() as u64 > *budget {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "the targets exceed max_total_bytes ({} bytes); narrow [protect] targets",
                limits.max_total_bytes
            ),
        ));
    }
    *budget -= bytes.len() as u64;
    let Some(text) = decode_utf8_strict(&bytes) else {
        return Ok(skip("not valid UTF-8 text".to_string()));
    };
    if text.len() as u64 > limits.max_parse_bytes {
        return Ok(skip(format!(
            "{} bytes, above max_parse_bytes ({})",
            text.len(),
            limits.max_parse_bytes
        )));
    }
    let analysis = match registry.analyze(Path::new(&entry.rel), text, limits) {
        Ok(a) => a,
        Err(e) => return Ok(skip(format!("analysis failed: {}", e.message()))),
    };
    let l1_digest = canonicalize(&analysis.tokens, CanonLevel::L1, None).digest();
    Ok(Admission::Use(Admitted {
        text: text.to_string(),
        l1_digest,
        bytes: bytes.len() as u64,
        analysis,
    }))
}

/// Every file's §16 fingerprint input in a walked tree, without harvesting the
/// literals in it.
///
/// `swp protect` needs this for the part of a project its `[protect] targets`
/// exclude, because a release's fingerprint covers the tree as a scanner will
/// walk it — see [`swp_identity::ProtectConfig::scan_scope`]. Candidate hunting is
/// the expensive half of [`scan`], and none of it is wanted here.
pub fn tree_digests(
    root: &Path,
    walked: &Walk,
    limits: &Limits,
) -> Result<BTreeMap<String, Digest>, SwpError> {
    let registry = Registry::standard();
    let mut budget = limits.max_total_bytes;
    let mut out = BTreeMap::new();
    for entry in &walked.files {
        // A file this pass leaves out is a file the scanner's own pass over the
        // same tree leaves out too, because both call the same `admit`; the
        // omission is not recorded, since neither side can report it.
        if let Admission::Use(admitted) = admit(&registry, root, entry, limits, &mut budget)? {
            out.insert(entry.rel.clone(), admitted.l1_digest);
        }
    }
    Ok(out)
}

/// Whether a radius says anything beyond the literal in it.
fn has_context(analysis: &Analysis, radius: ByteSpan, site: ByteSpan) -> bool {
    analysis
        .tokens_in(radius)
        .iter()
        .any(|t| !site.contains(t.span.start))
}

/// Byte offsets that begin a line, for the `line_hint` report field.
pub(crate) fn line_starts(text: &str) -> Vec<u32> {
    let mut out = vec![0u32];
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            out.push((i + 1) as u32);
        }
    }
    out
}

pub(crate) fn line_of(starts: &[u32], byte: u32) -> u32 {
    // The number of line starts at or before `byte`, which is the 1-based line.
    starts.partition_point(|s| *s <= byte) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::{ProjectId, ReleaseId};
    use swp_core::version::CanonicalizerVersion;
    use swp_crypto::RootSecret;

    fn keys() -> ManifestKeys {
        ManifestKeys::derive(
            &RootSecret::from_bytes(&[7u8; 32]).unwrap(),
            &ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            &ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            CanonicalizerVersion::V1,
        )
    }

    fn temp(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-scan-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn scanned(root: &Path, cfg: &ProtectConfig, limits: &Limits) -> Scan {
        let walked = crate::walk::walk(root, cfg, limits).unwrap();
        scan(
            root,
            &walked,
            &keys(),
            cfg,
            TagWidth::DEFAULT,
            limits,
        )
        .unwrap()
    }

    fn cfg(t: &[&str]) -> ProtectConfig {
        ProtectConfig {
            targets: t.iter().map(|s| s.to_string()).collect(),
            ..ProtectConfig::default()
        }
    }

    #[test]
    fn a_small_javascript_file_yields_addressable_sites() {
        let root = temp("js");
        write(
            &root,
            "src/app.js",
            "function area(w, h) {\n  const pad = 4;\n  return w * h + pad + 100;\n}\nmodule.exports = { area, margin: 12 };",
        );
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert_eq!(s.files.len(), 1);
        assert_eq!(s.files[0].language, "javascript");
        assert_eq!(s.files[0].adapter, "ast");
        assert!(s.files[0].usable() >= 3, "{:?}", s.files[0]);
        for c in &s.files[0].candidates {
            assert!(c.locations.iter().all(|l| *l != LocationId::default()));
            assert!(c.families.iter().any(|f| f.applies_to_numbers()));
            assert!(c.line_hint >= 1 && c.line_hint <= 5, "line hint {}", c.line_hint);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn candidate_addresses_are_unique_across_a_corpus_of_short_files() {
        let root = temp("unique");
        // Two files, each with the *same* statement text. Their statement radii
        // canonicalize identically, which is exactly the case the wider scope key
        // and the raw keys exist to separate — and the case that selection must
        // notice rather than embed twice under one identity.
        write(&root, "src/a.js", "function f() {\n  return 100;\n}\nconsole.log(f(), 7);");
        write(&root, "src/b.js", "function f() {\n  return 100;\n}\nconsole.log(f(), 9);");
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        let mut all: Vec<LocationId> = s
            .files
            .iter()
            .flat_map(|f| f.candidates.iter().flat_map(|c| c.locations))
            .collect();
        let total = all.len();
        all.sort();
        all.dedup();
        assert!(
            all.len() >= total / 2,
            "addresses collapsed too far: {}/{} distinct",
            all.len(),
            total
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_document_that_is_one_literal_offers_no_address() {
        let root = temp("bare");
        write(&root, "src/bare.js", "42");
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert_eq!(s.files.len(), 1);
        assert!(
            s.files[0].candidates.is_empty(),
            "the radius would contain nothing but the watermark itself: {:?}",
            s.files[0].candidates
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn non_utf8_files_are_omitted_rather_than_corrupting_a_run() {
        let root = temp("binary");
        write(&root, "src/app.js", "const a = 100;\nconst b = 200;\n");
        let path = root.join("src/blob.js");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xffu8, 0xfe, 0x00, 0x80]).unwrap();
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert_eq!(s.files.len(), 1, "the valid file still scanned");
        assert!(s
            .omissions
            .iter()
            .any(|o| o.path == "src/blob.js" && o.reason.contains("UTF-8")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn line_hints_count_crlf_the_same_way() {
        let root = temp("crlf");
        write(&root, "src/w.js", "const a = 1;\r\n\r\nconst b = 222;\r\n");
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        let c = s
            .files
            .iter()
            .flat_map(|f| f.candidates.iter())
            .find(|c| c.original == "222")
            .expect("the literal is a site");
        assert_eq!(c.line_hint, 3);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn newline_style_does_not_change_a_location_id() {
        // The whole point of L1/L3 collapsing line breaks: a copy that was
        // converted to CRLF by an editor still has to be found.
        let a = temp("nl-a");
        let b = temp("nl-b");
        write(&a, "src/m.js", "function f(x) {\n  return x + 1000;\n}\n");
        write(&b, "src/m.js", "function f(x) {\r\n  return x + 1000;\r\n}\r\n");
        let sa = scanned(&a, &cfg(&["src"]), &Limits::default());
        let sb = scanned(&b, &cfg(&["src"]), &Limits::default());
        let find = |s: &Scan| -> Vec<LocationId> {
            s.files
                .iter()
                .flat_map(|f| f.candidates.iter())
                .filter(|c| c.original == "1000")
                .map(|c| c.locations[0])
                .collect()
        };
        assert_eq!(find(&sa).len(), 1);
        assert_eq!(find(&sb).len(), 1);
        assert_eq!(find(&sa), find(&sb));
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn overlong_literals_are_left_out_of_the_candidate_list() {
        let root = temp("long");
        let big = "x".repeat(MAX_HINT_LEN + 10);
        write(
            &root,
            "src/s.js",
            &format!("const small = 5;\nconst big = \"{big}\";\nconst other = 7;\n"),
        );
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert!(
            s.files
                .iter()
                .flat_map(|f| f.candidates.iter())
                .all(|c| c.original.len() <= MAX_HINT_LEN)
        );
        assert!(s
            .files
            .iter()
            .flat_map(|f| f.candidates.iter())
            .any(|c| c.original == "5"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn string_sites_are_left_out_when_the_project_asks_for_numbers_only() {
        let root = temp("strings");
        // Long enough to carry a 4-bit code: a string family needs one split point
        // or escape slot per reachable value, so a short literal is honestly not a
        // site at all — see `swp_adapters::string_family_supports`.
        let body = "const name = \"a string long enough to carry a tag\";\nconst limit = 4096;\n";
        write(&root, "src/a.js", body);
        let mut off = cfg(&["src"]);
        off.embed_strings = false;
        let s = scanned(&root, &off, &Limits::default());
        let originals: Vec<&str> = s.files[0]
            .candidates
            .iter()
            .map(|c| c.original.as_str())
            .collect();
        assert!(originals.contains(&"4096"), "{originals:?}");
        assert!(
            !originals.iter().any(|o| o.contains("long enough")),
            "a string site must not be offered: {originals:?}"
        );
        assert!(
            s.notes.iter().any(|n| n.contains("embed_strings")),
            "the run must say what it left out: {:?}",
            s.notes
        );
        // The same tree with strings on offers more sites, which is the point of
        // recording the setting per release.
        let on = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert!(on.files[0].usable() > s.files[0].usable());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn per_file_site_cap_is_reported_not_applied_silently() {
        let root = temp("cap");
        let mut body = String::new();
        for i in 0..40 {
            body.push_str(&format!("export const v{i} = {};\n", 1000 + i));
        }
        write(&root, "src/gen.js", &body);
        let limits = Limits { max_sites_per_file: 10, ..Limits::default() };
        let s = scanned(&root, &cfg(&["src"]), &limits);
        assert!(s.files[0].usable() <= 10);
        assert!(
            s.notes.iter().any(|n| n.contains("max_sites_per_file")),
            "{:?}",
            s.notes
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn total_byte_budget_stops_the_run_with_an_error() {
        let root = temp("budget");
        write(&root, "src/a.js", "const a = 100;\nconst b = 200;\n");
        write(&root, "src/b.js", "const c = 300;\nconst d = 400;\n");
        let limits = Limits { max_total_bytes: 32, ..Limits::default() };
        let walked = crate::walk::walk(&root, &cfg(&["src"]), &limits).unwrap();
        let e = scan(&root, &walked, &keys(), &cfg(&["src"]), TagWidth::DEFAULT, &limits).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn adapter_labels_are_the_manifest_vocabulary_not_the_adapter_one() {
        assert_eq!(adapter_label(swp_adapters::AdapterKind::Ast), "ast");
        assert_eq!(adapter_label(swp_adapters::AdapterKind::Lexical), "lexical");
        assert_eq!(swp_adapters::AdapterKind::Lexical.as_str(), "token");
    }

    #[test]
    fn overlapping_radii_are_detected_in_both_directions() {
        let a = candidate(
            ByteSpan::new(20, 23),
            ByteSpan::new(10, 40),
            ByteSpan::new(0, 100),
        );
        // B's literal sits inside A's statement, so embedding B rewrites the text
        // A's address is digested from.
        let b = candidate(
            ByteSpan::new(30, 33),
            ByteSpan::new(28, 36),
            ByteSpan::new(25, 40),
        );
        assert!(a.radii_overlap(&b), "b's site is inside a's statement");
        assert!(b.radii_overlap(&a), "the test must not depend on argument order");
        // C is in a statement of its own but the same scope, which is still a
        // conflict: A's scope key would be digested from text that B changed.
        let c = candidate(
            ByteSpan::new(60, 63),
            ByteSpan::new(55, 70),
            ByteSpan::new(0, 100),
        );
        assert!(a.radii_overlap(&c), "a shared scope is a shared address");
        // D has disjoint statement *and* scope, so neither rewrite can be seen in
        // the other's radius, which is what lets both be embedded at once.
        let d = candidate(
            ByteSpan::new(160, 163),
            ByteSpan::new(150, 170),
            ByteSpan::new(140, 190),
        );
        assert!(!a.radii_overlap(&d), "{d:?} is outside both of a's radii");
        assert!(!d.radii_overlap(&a));
    }

    fn candidate(
        span: ByteSpan,
        statement: ByteSpan,
        scope: ByteSpan,
    ) -> Candidate {
        Candidate {
            file: 0,
            site: 0,
            span,
            statement,
            scope,
            line_hint: 1,
            class: LiteralClass::Integer,
            families: vec![FormFamily::Add],
            locations: [LocationId::default(); 4],
            priority: [0u8; 32],
            original: "100".into(),
        }
    }

    #[test]
    fn primary_choice_takes_the_first_key_no_accepted_site_has_claimed() {
        let mut a = candidate(
            ByteSpan::new(20, 23),
            ByteSpan::new(10, 40),
            ByteSpan::new(0, 100),
        );
        for (i, id) in a.locations.iter_mut().enumerate() {
            *id = LocationId::from_bytes(&[i as u8 + 1; 16]).unwrap();
        }
        // With no census to consult every key is equally precise, so the slot
        // order decides and the most refactor-tolerant key wins.
        assert_eq!(
            a.pick_primary(&Default::default(), &KeyCounts::default()),
            Some(RadiusKind::StatementId)
        );
        let mut taken = std::collections::BTreeSet::new();
        taken.insert(a.locations[0]);
        // A second site in the same file whose statement radius canonicalizes the
        // same way — two `return <SITE>;` lines — must move out to the scope key
        // rather than share an identity.
        assert_eq!(
            a.pick_primary(&taken, &KeyCounts::default()),
            Some(RadiusKind::ScopeId)
        );
        taken.insert(a.locations[1]);
        taken.insert(a.locations[2]);
        assert_eq!(
            a.pick_primary(&taken, &KeyCounts::default()),
            Some(RadiusKind::ScopeRaw)
        );
        taken.insert(a.locations[3]);
        assert_eq!(
            a.pick_primary(&taken, &KeyCounts::default()),
            None,
            "every key is spoken for"
        );
    }

    /// The census is what keeps a repetitive module from giving twenty sites the
    /// same tag: a key several candidates share loses to a key only one has.
    #[test]
    fn a_tag_binds_to_the_key_that_names_the_site_best() {
        let shared = LocationId::from_bytes(&[9u8; 16]).unwrap();
        let mut cands = Vec::new();
        for i in 0..3u8 {
            let mut c = candidate(
                ByteSpan::new(20 + i as u32 * 10, 23 + i as u32 * 10),
                ByteSpan::new(10, 40),
                ByteSpan::new(0, 100),
            );
            c.locations = [
                shared,
                LocationId::from_bytes(&[i + 1; 16]).unwrap(),
                LocationId::from_bytes(&[i + 40; 16]).unwrap(),
                LocationId::from_bytes(&[i + 80; 16]).unwrap(),
            ];
            cands.push(c);
        }
        let counts = scan_of(cands.clone()).key_counts();
        assert_eq!(counts.twins(RadiusKind::StatementId, &shared), 3);
        assert_eq!(
            counts.twins(RadiusKind::ScopeId, &cands[0].locations[1]),
            1,
            "each site's own scope key"
        );
        for c in &cands {
            assert_eq!(
                c.pick_primary(&Default::default(), &counts),
                Some(RadiusKind::ScopeId),
                "three statements that canonicalize alike must not share a tag"
            );
        }
    }

    fn scan_of(candidates: Vec<Candidate>) -> Scan {
        Scan {
            files: vec![FileScan {
                rel: "src/a.js".into(),
                language: "javascript".into(),
                adapter: "ast",
                l1_digest: Digest::default(),
                candidates,
                refused: 0,
                parse_errors: 0,
                bytes: 100,
            }],
            ..Scan::default()
        }
    }

    #[test]
    fn two_sites_sharing_every_key_are_indistinguishable() {
        let a = candidate(
            ByteSpan::new(20, 23),
            ByteSpan::new(10, 40),
            ByteSpan::new(0, 100),
        );
        let b = candidate(
            ByteSpan::new(60, 63),
            ByteSpan::new(50, 70),
            ByteSpan::new(0, 100),
        );
        // Both default ids, i.e. the same canonical text at all four radii.
        assert!(a.indistinguishable_from(&b));
        let mut c = b.clone();
        c.locations[2] = LocationId::from_bytes(&[9u8; 16]).unwrap();
        assert!(!a.indistinguishable_from(&c), "one differing key is enough");
    }

    #[test]
    fn scan_records_per_language_adapter_modes() {
        let root = temp("stats");
        write(&root, "src/a.js", "const a = 100;\nconst b = 200;\n");
        write(&root, "src/b.py", "LIMIT = 500\nOTHER = 600\n");
        let s = scanned(&root, &cfg(&["src"]), &Limits::default());
        assert_eq!(s.adapters.len(), 2, "{:?}", s.adapters);
        for stat in &s.adapters {
            assert_eq!(stat.mode, "ast", "both languages have a parser here");
            assert_eq!(stat.files, 1);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
