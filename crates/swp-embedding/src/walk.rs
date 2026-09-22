//! The source walk: which files a protection run may look at, and which it must
//! never touch.
//!
//! This is the only place in the embedding crate that decides scope, so it is
//! also the only place a user's `targets`/`excludes` configuration is honored.
//! Four properties it exists to keep:
//!
//! 1. **Determinism.** The walk is sorted by canonical relative path before it
//!    returns, so two runs over an unchanged tree hand the same file list to the
//!    same selection order and therefore choose the same constellation. Without
//!    this, `swp protect` would be a dice roll on directory order.
//! 2. **No symlinks.** [`walkdir::WalkDir::follow_links`] is off, so a tree
//!    containing a link to `/` or to a dependency directory cannot make this run
//!    read the machine. A link is reported as an omission, not silently dropped.
//! 3. **Bounded work.** File count and per-file size come from [`Limits`], and
//!    exceeding one is an error rather than a truncation: a protection run that
//!    quietly covered half the tree would leave `swp verify` reporting "sites
//!    missing" about code it was never told to protect.
//! 4. **Parsed files only, unless told otherwise.** The walk admits a file when
//!    a real grammar covers its extension. The lexical fallback is not offered
//!    here, because on a language SWP-1 cannot re-parse, `validate` cannot prove
//!    the surrounding code unchanged, and an edit inside a `Makefile` recipe or a
//!    JSON value is exactly the behavioral regression §11 forbids.
//!
//! ## Glob syntax
//!
//! Deliberately tiny, because the whole vocabulary the default exclusions use is
//! `**/dir/**` and `**/*.ext`:
//!
//! - `**` matches zero or more path segments,
//! - `*` matches within one segment, `?` matches one character,
//! - comparison is case-insensitive, since a `Dist` directory means the same
//!   thing as `dist`, and an over-exclusion here loses coverage while an
//!   under-exclusion loses the whole run to `node_modules`.
//!
//! A pattern is matched against directories too (to prune them), which is why a
//! trailing `**` also excludes the named directory itself: `**` matches the empty
//! remainder.

use std::path::{Component, Path, PathBuf};

use swp_adapters::Registry;
use swp_core::error::{ErrorCode, SwpError};
use swp_core::limits::Limits;
use swp_core::text::canonical_relpath;
use swp_identity::ProtectConfig;
use walkdir::WalkDir;

/// One file the walk decided may be analyzed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedFile {
    /// Canonical project-relative path: forward slashes, NFC, no `.`/`..`. This
    /// is the string that reaches the manifest and the fingerprint, so it reads
    /// the same on every platform.
    pub rel: String,
    pub abs: PathBuf,
    /// Size from the walk's own stat, so an oversized file is reported without
    /// being read first.
    pub bytes: u64,
}

/// Why a file the walk looked at did not make it into the tree it returns.
///
/// The distinction is §45's. A `.png` is not source this protocol reads, and a
/// scan that skips it has still examined everything the candidate could answer
/// with. A 9 MiB `.js` is a different event: it could have held the watermark,
/// and nothing looked at it. Only the second kind leaves a result partial, and
/// the report needs the difference to be a fact rather than a phrase a reader
/// has to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmissionKind {
    /// Not source the protocol can read, and not something hiding copied source
    /// would plausibly be: no grammar for the extension, an empty file, a device.
    NotSource,
    /// Something that could have carried evidence and was not examined: a
    /// resource ceiling, an unreadable file, an archive the walk does not open,
    /// an analysis that refused to parse it.
    NotExamined,
}

/// Something the walk looked at and refused, with the reason a report shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omission {
    pub path: String,
    pub reason: String,
    pub kind: OmissionKind,
}

/// File names that are containers rather than trees.
///
/// `swp scan` opens one of these when the operator names it on the command line
/// (§20); finding one *inside* a tree it is walking is a different event, and
/// [`Limits::max_archive_depth`] says it is not opened there. It is still a
/// place copied source could be hiding, so the report has to say which half of
/// the candidate it did not look at. This is the extension half of
/// `swp-detection`'s content sniffing, which stays authoritative for a path
/// named outright; the list only decides how an unopened file is described.
fn container_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "zip"
            | "tar"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "7z"
            | "jar"
            | "war"
            | "whl"
            | "vsix"
            | "apk"
            | "epub"
            | "nupkg"
    )
}

#[derive(Debug, Default)]
pub struct Walk {
    pub files: Vec<ScannedFile>,
    pub omissions: Vec<Omission>,
    /// Directories pruned. Counted rather than listed: one real project prunes
    /// thousands of `node_modules` subdirectories, and the list would drown the
    /// report that is trying to explain the run.
    pub dirs_pruned: u32,
}

impl Walk {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The omissions that are holes in an examination rather than files that were
    /// never source: a limit that fired, a read that failed, an archive left
    /// closed. Non-empty means a scan over this tree cannot call itself complete
    /// (§45).
    pub fn refused(&self) -> impl Iterator<Item = &Omission> + '_ {
        self.omissions
            .iter()
            .filter(|o| o.kind == OmissionKind::NotExamined)
    }
}

/// Walk every configured target under `root`. An empty result is an error,
/// because the caller is `swp protect` and "there is nowhere to put a
/// watermark" is a failure the operator has to fix.
pub fn walk(root: &Path, cfg: &ProtectConfig, limits: &Limits) -> Result<Walk, SwpError> {
    let out = walk_tree(root, cfg, limits)?;
    if out.files.is_empty() {
        let unsupported = out
            .omissions
            .iter()
            .all(|o| o.reason.starts_with("no language adapter"));
        let hint = if unsupported {
            let languages = Registry::standard()
                .parsed_languages()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Nothing under [protect] targets has a language adapter, so this tree is not \
                 source to SWP-1 and nothing was written. This build parses {languages}; \
                 another language needs an adapter, which is the extension point the \
                 documentation describes. Point [protect] targets at the part of the tree \
                 that is one of them, if there is one."
            )
        } else {
            String::new()
        };
        let error = SwpError::new(
            ErrorCode::NoSafeLocations,
            format!(
                "nothing to protect under \"{}\": {} path{} refused ({}). Check [protect] \
                 targets and excludes in .swp/config.toml",
                swp_core::text::display_path(&root.display().to_string()),
                out.omissions.len(),
                if out.omissions.len() == 1 { "" } else { "s" },
                summarize_omissions(&out.omissions)
            ),
        );
        return Err(if hint.is_empty() {
            error
        } else {
            error.with_next(hint)
        });
    }
    Ok(out)
}

/// [`walk`] with an empty tree left as an answer rather than an error, because
/// the caller is `swp scan`: "this candidate holds nothing I can read" is a
/// result, and the omissions that prove it are the only evidence a reader has
/// that the scan looked at the tree rather than sailed past it.
pub fn walk_for_scan(root: &Path, cfg: &ProtectConfig, limits: &Limits) -> Result<Walk, SwpError> {
    walk_tree(root, cfg, limits)
}

fn walk_tree(root: &Path, cfg: &ProtectConfig, limits: &Limits) -> Result<Walk, SwpError> {
    if cfg.targets.is_empty() {
        return Err(SwpError::usage(
            "no protected targets: set [protect] targets in .swp/config.toml",
        ));
    }
    let registry = Registry::standard();
    let excludes = Excludes::build(cfg)?;
    // `swp scan ../suspect/copy` is the protocol's main use of this function, and
    // a caller-written `..` in that path would otherwise make every file on the
    // candidate look like it sits outside the walked root: `join_target` below
    // resolves `.` and `..` lexically, so the walk has to compare against the
    // same spelling it walks from.
    let root = normalize(root);
    let root = root.as_path();

    let mut out = Walk::default();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for target in &cfg.targets {
        let target_root = join_target(root, target)?;
        if target_root.is_file() {
            // A single named file is a legitimate target: a one-script project
            // should be protectable, and a user who lists `src/main.js` means
            // exactly that file.
            admit(
                root,
                &target_root,
                &excludes,
                &registry,
                limits,
                &mut out,
                &mut seen,
            );
            continue;
        }
        if !target_root.is_dir() {
            out.omissions.push(Omission {
                path: target.clone(),
                reason: "target does not exist".to_string(),
                kind: OmissionKind::NotExamined,
            });
            continue;
        }
        let mut found: Vec<(PathBuf, u64)> = Vec::new();
        for entry in WalkDir::new(&target_root)
            .follow_links(false)
            .sort_by_file_name()
            .max_depth(limits.max_depth.max(1) as usize)
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    // An unreadable directory (permissions, a path that vanished
                    // mid-walk) is reported and passed over: one locked directory
                    // must not stop a run over ten thousand.
                    let path = e
                        .path()
                        .and_then(|p| relpath(root, p))
                        .unwrap_or_else(|| "<unreadable path>".to_string());
                    out.omissions.push(Omission {
                        path,
                        reason: "unreadable".to_string(),
                        kind: OmissionKind::NotExamined,
                    });
                    continue;
                }
            };
            let file_type = entry.file_type();
            let path = entry.path();
            if path == target_root {
                continue;
            }
            let Some(rel) = relpath(root, path) else {
                out.omissions.push(Omission {
                    path: path.display().to_string(),
                    reason: relpath_failure(root, path).to_string(),
                    kind: OmissionKind::NotExamined,
                });
                continue;
            };
            if file_type.is_symlink() {
                // §21: a link is not followed, because where it points is the
                // candidate's business and reading the machine is not the
                // scanner's. That is a hole in the examination all the same —
                // copied source behind a link was not looked at — so the report
                // says so instead of counting it as a clean read.
                out.omissions.push(Omission {
                    path: rel,
                    reason: "symbolic link, never followed (§21)".to_string(),
                    kind: OmissionKind::NotExamined,
                });
                continue;
            }
            if file_type.is_dir() {
                // Pruned on the directory's own path, so the tree below it is
                // never opened rather than opened and then thrown away.
                if excludes.matches(&rel) || excludes.prunes(&rel) {
                    out.dirs_pruned += 1;
                    continue;
                }
                // `max_depth` stops the descent without telling us, so the stop
                // is detected here: a directory at the ceiling has children this
                // walk will never see.
                if entry.depth() as u64 >= limits.max_depth.max(1) as u64 {
                    out.omissions.push(Omission {
                        path: rel,
                        reason: format!(
                            "directory at max_depth ({}), so its contents were not walked",
                            limits.max_depth
                        ),
                        kind: OmissionKind::NotExamined,
                    });
                }
                continue;
            }
            if !file_type.is_file() {
                // Fifos, sockets and devices: opening one could block this run
                // forever, so it is refused before it is touched.
                out.omissions.push(Omission {
                    path: rel,
                    reason: "not a regular file".to_string(),
                    kind: OmissionKind::NotSource,
                });
                continue;
            }
            let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            found.push((path.to_path_buf(), bytes));
        }
        for (path, bytes) in found {
            admit_with(
                root, &path, bytes, &excludes, &registry, limits, &mut out, &mut seen,
            );
        }
    }
    out.files.sort_by(|a, b| a.rel.cmp(&b.rel));
    if out.files.len() as u64 > limits.max_files {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "the tree holds {} files, above max_files ({}); narrow the input path, or raise \
                 max_files in .swp/config.toml under [limits]",
                out.files.len(),
                limits.max_files
            ),
        ));
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn admit(
    root: &Path,
    abs: &Path,
    excludes: &Excludes,
    registry: &Registry,
    limits: &Limits,
    out: &mut Walk,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let bytes = std::fs::metadata(abs).map(|m| m.len()).unwrap_or(0);
    admit_with(root, abs, bytes, excludes, registry, limits, out, seen);
}

#[allow(clippy::too_many_arguments)]
fn admit_with(
    root: &Path,
    abs: &Path,
    bytes: u64,
    excludes: &Excludes,
    registry: &Registry,
    limits: &Limits,
    out: &mut Walk,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let Some(rel) = relpath(root, abs) else {
        out.omissions.push(Omission {
            path: abs.display().to_string(),
            reason: relpath_failure(root, abs).to_string(),
            kind: OmissionKind::NotExamined,
        });
        return;
    };
    if !seen.insert(rel.clone()) || excludes.matches(&rel) {
        return;
    }
    if bytes == 0 {
        out.omissions.push(Omission {
            path: rel,
            reason: "empty file".to_string(),
            kind: OmissionKind::NotSource,
        });
        return;
    }
    if bytes > limits.max_file_bytes {
        out.omissions.push(Omission {
            path: rel,
            reason: format!(
                "{} bytes, above max_file_bytes ({})",
                bytes, limits.max_file_bytes
            ),
            kind: OmissionKind::NotExamined,
        });
        return;
    }
    if container_extension(Path::new(&rel)) {
        // A container inside a tree is not opened: `max_archive_depth` bounds how
        // many levels the scanner takes apart, and the walk is already level one.
        // Naming it is the difference between "this tree holds no source" and
        // "this tree holds a source carrier the scan did not read".
        out.omissions.push(Omission {
            path: rel,
            reason: format!(
                "an archive; only the container named on the command line is opened \
                 (max_archive_depth={})",
                limits.max_archive_depth
            ),
            kind: OmissionKind::NotExamined,
        });
        return;
    }
    if registry.for_path(Path::new(&rel)).is_none() {
        out.omissions.push(Omission {
            path: rel,
            reason: "no language adapter for this file type".to_string(),
            kind: OmissionKind::NotSource,
        });
        return;
    }
    out.files.push(ScannedFile {
        rel,
        abs: abs.to_path_buf(),
        bytes,
    });
}

/// The first few omissions, so the error line names a cause instead of a count.
fn summarize_omissions(omissions: &[Omission]) -> String {
    let mut reasons: Vec<String> = Vec::new();
    for o in omissions {
        if !reasons.contains(&o.reason) {
            reasons.push(o.reason.clone());
        }
        if reasons.len() == 3 {
            break;
        }
    }
    if reasons.is_empty() {
        "no reasons".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Join a configured target onto the project root, refusing anything that would
/// leave the tree. A `..` in `config.toml` is either a mistake or an attacker's
/// edit of a candidate repository's config, and the answer is the same either way.
///
/// `"."` — which [`canonical_relpath`] reduces to the empty string — means the
/// root itself. `swp scan` relies on that: a candidate tree is walked whole, with
/// no project configuration to name its targets.
fn join_target(root: &Path, target: &str) -> Result<PathBuf, SwpError> {
    let rel = canonical_relpath(target);
    if rel.contains("..") {
        return Err(SwpError::usage(format!(
            "target {target:?} must name a path inside the project"
        )));
    }
    if rel.is_empty() {
        return Ok(normalize(root));
    }
    let cleaned = normalize(&root.join(rel.as_str()));
    let root_clean = normalize(root);
    if !cleaned.starts_with(&root_clean) {
        return Err(SwpError::new(
            ErrorCode::PathRejected,
            format!("target {target:?} resolves outside the project root"),
        ));
    }
    Ok(cleaned)
}

/// Lexical normalization for a path that may not exist: resolve `.` and `..`
/// without touching the filesystem, so the containment test is about the path
/// text rather than about which symlinks happen to exist right now.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn relpath(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let text = rel.to_str()?;
    let canon = canonical_relpath(text);
    (!canon.is_empty()).then_some(canon)
}

/// Why [`relpath`] produced nothing, in the words an operator can act on. The two
/// causes are different failures and a report that named the wrong one would send
/// someone hunting for an encoding problem in a path that simply is not inside
/// the tree being walked.
fn relpath_failure(root: &Path, path: &Path) -> &'static str {
    if path.strip_prefix(root).is_err() {
        "path is outside the walked root"
    } else {
        "path is not valid text"
    }
}

/// The merged exclusion set: the always-excluded trees plus the project's own.
#[derive(Debug, Default)]
pub struct Excludes {
    patterns: Vec<Pattern>,
}

/// The exclusion globs one run applies, in the order they take effect: the
/// always-excluded trees first, then the project's own additions.
///
/// The plan records this list rather than the parsed patterns, and the walk builds
/// its matcher from it, so the two can never disagree about what was excluded.
pub fn effective_excludes(cfg: &ProtectConfig) -> Vec<String> {
    swp_identity::DEFAULT_EXCLUDES
        .iter()
        .copied()
        .chain(cfg.excludes.iter().map(String::as_str))
        .map(String::from)
        .collect()
}

impl Excludes {
    pub fn build(cfg: &ProtectConfig) -> Result<Self, SwpError> {
        let mut out = Excludes::default();
        for glob in effective_excludes(cfg) {
            out.patterns.push(Pattern::parse(&glob)?);
        }
        Ok(out)
    }

    pub fn matches(&self, rel: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(rel))
    }

    /// Whether a directory can be pruned because every path beneath it is
    /// excluded anyway.
    ///
    /// `**/dist/**` already matches `dist` through [`Excludes::matches`], since
    /// the trailing `**` can match nothing. This covers the shape a user writes
    /// when they mean "everything below here" but spell it `dist/*`: matching the
    /// directory against that pattern would be wrong, so the test is whether a
    /// `**`-tailed pattern matches the directory plus one synthetic child.
    pub fn prunes(&self, rel: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| p.tail_is_any() && p.matches_with_child(rel))
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// One compiled glob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    segs: Vec<Seg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    /// `**`
    Any,
    /// A segment, possibly with wildcards inside it.
    Parts(Vec<Part>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// `*` within a segment.
    Star,
    /// `?`.
    One,
    Lit(char),
}

impl Pattern {
    pub fn parse(glob: &str) -> Result<Self, SwpError> {
        let text = canonical_relpath(glob);
        if text.is_empty() {
            return Err(SwpError::usage("exclude patterns must name a path"));
        }
        if text.split('/').any(|s| s == "..") {
            return Err(SwpError::usage(format!(
                "exclude pattern {glob:?} escapes the project"
            )));
        }
        let mut segs = Vec::new();
        for raw in text.split('/') {
            if raw == "**" {
                segs.push(Seg::Any);
                continue;
            }
            let mut parts = Vec::new();
            for c in raw.chars() {
                parts.push(match c {
                    '*' => Part::Star,
                    '?' => Part::One,
                    other => Part::Lit(other.to_ascii_lowercase()),
                });
            }
            segs.push(Seg::Parts(parts));
        }
        Ok(Pattern { segs })
    }

    /// Whether this pattern names the path `rel`.
    pub fn matches(&self, rel: &str) -> bool {
        match_segs(&self.segs, &segments(rel))
    }

    /// Whether it would match a path one level below `rel`.
    fn matches_with_child(&self, rel: &str) -> bool {
        let mut parts = segments(rel);
        parts.push(String::new());
        match_segs(&self.segs, &parts)
    }

    fn tail_is_any(&self) -> bool {
        matches!(self.segs.last(), Some(Seg::Any))
    }
}

fn segments(rel: &str) -> Vec<String> {
    canonical_relpath(rel)
        .split('/')
        .map(|s| s.to_string())
        .collect()
}

fn match_segs(pattern: &[Seg], path: &[String]) -> bool {
    match (pattern.first(), path.split_first()) {
        (None, _) => path.is_empty(),
        (Some(Seg::Any), _) => {
            // `**` may consume this segment and remain available for the next, or
            // match nothing here and move on. Trying both is what lets `**/x/**`
            // skip several directories, or none at all.
            if !path.is_empty() && match_segs(pattern, &path[1..]) {
                return true;
            }
            match_segs(&pattern[1..], path)
        }
        (Some(Seg::Parts(parts)), Some((head, rest))) => {
            match_seg(parts, head) && match_segs(&pattern[1..], rest)
        }
        (Some(Seg::Parts(_)), None) => false,
    }
}

fn match_seg(parts: &[Part], text: &str) -> bool {
    let chars: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    match_seg_at(parts, 0, &chars, 0)
}

fn match_seg_at(parts: &[Part], pi: usize, text: &[char], ti: usize) -> bool {
    match parts.get(pi) {
        None => ti == text.len(),
        Some(Part::Star) => {
            for probe in ti..=text.len() {
                if match_seg_at(parts, pi + 1, text, probe) {
                    return true;
                }
            }
            false
        }
        Some(Part::One) => ti < text.len() && match_seg_at(parts, pi + 1, text, ti + 1),
        Some(Part::Lit(c)) => {
            ti < text.len() && text[ti] == *c && match_seg_at(parts, pi + 1, text, ti + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(g: &str) -> Pattern {
        Pattern::parse(g).unwrap()
    }

    #[test]
    fn double_star_spans_directories_and_can_be_empty() {
        assert!(p("**/node_modules/**").matches("node_modules"));
        assert!(p("**/node_modules/**").matches("node_modules/react/index.js"));
        assert!(p("**/node_modules/**").matches("packages/node_modules"));
        assert!(!p("**/node_modules/**").matches("src/node_modules2/a.js"));
        assert!(!p("**/node_modules/**").matches("src/main.js"));
    }

    #[test]
    fn star_stays_inside_its_segment() {
        assert!(p("**/*.min.js").matches("a.min.js"));
        assert!(p("**/*.min.js").matches("web/dist/app.min.js"));
        assert!(
            !p("**/*.min.js").matches("web/app.min.map"),
            "* must not cross a directory boundary"
        );
        assert!(!p("**/*.min.js").matches("web/app.js"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        assert!(p("src/a?.js").matches("src/ab.js"));
        assert!(!p("src/a?.js").matches("src/a.js"));
        assert!(!p("src/a?.js").matches("src/abc.js"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(p("**/DIST/**").matches("web/dist/app.js"));
        assert!(p("**/build/**").matches("Web/Build/out.js"));
    }

    #[test]
    fn patterns_are_matched_against_canonical_paths() {
        // Both sides go through `canonical_relpath`, so a pattern written with
        // backslashes or a `./` prefix means the same thing as its plain form.
        assert_eq!(p("./**/dist/**").segs, p("**/dist/**").segs);
        assert!(p("**\\target\\**").matches("target/x"));
    }

    #[test]
    fn a_directory_matching_all_below_it_can_be_pruned() {
        let mut e = Excludes::default();
        e.patterns.push(p("dist/**"));
        assert!(e.prunes("dist"));
        // An anchored pattern is anchored: `dist/**` does not mean "any dist".
        assert!(!e.prunes("pkg/dist"));
        assert!(!e.prunes("src"));
        let mut rooted = Excludes::default();
        rooted.patterns.push(p("**/dist/**"));
        assert!(rooted.prunes("pkg/dist"));
        // `dist/*` names one level only, so pruning on it would drop files the
        // pattern does not match: the user said "files directly in dist".
        let mut e2 = Excludes::default();
        e2.patterns.push(p("dist/*"));
        assert!(!e2.prunes("dist"));
        assert!(e2.matches("dist/app.js"));
        assert!(!e2.matches("dist/deep/app.js"));
    }

    #[test]
    fn escaping_patterns_are_refused() {
        assert!(Pattern::parse("../outside/**").is_err());
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("src/../src/**").is_err());
    }

    #[test]
    fn default_excludes_cover_dependency_and_build_trees() {
        let cfg = ProtectConfig::default();
        let e = Excludes::build(&cfg).unwrap();
        for path in [
            "node_modules/x/index.js",
            "src/node_modules/x.js",
            ".swp/private/root.key",
            "dist/app.min.js",
            "web/app.min.js",
            "target/debug/build/out.js",
        ] {
            assert!(e.matches(path), "{path} should be excluded by default");
        }
        for path in ["src/main.js", "src/util/helpers.ts", "lib/app.py"] {
            assert!(!e.matches(path), "{path} must not be excluded");
        }
    }

    #[test]
    fn the_swp_directory_is_always_excluded() {
        // A run that walked `.swp/` would read back its own manifests as if they
        // were source, and could watermark a copy of an earlier release's
        // rendered literals.
        let cfg = ProtectConfig::default();
        let e = Excludes::build(&cfg).unwrap();
        assert!(e.matches(".swp/config.toml"));
        assert!(e.prunes(".swp"));
    }

    #[test]
    fn a_project_exclusion_adds_to_the_defaults_rather_than_replacing_them() {
        let cfg = ProtectConfig {
            excludes: vec!["src/generated/**".into()],
            ..ProtectConfig::default()
        };
        let e = Excludes::build(&cfg).unwrap();
        assert!(e.matches("src/generated/api.js"));
        assert!(
            e.matches("node_modules/x/y.js"),
            "defaults must still apply"
        );
    }

    #[test]
    fn targets_cannot_escape_the_project() {
        let root = Path::new("/tmp/swp-walk-test");
        assert!(join_target(root, "../etc").is_err());
        // A target that resolves back inside is still refused rather than
        // simplified: `config.toml` is project content, and the readable answer to
        // a path containing `..` is "write the path you mean".
        assert!(join_target(root, "src/../src").is_err());
        assert_eq!(
            join_target(root, "./src").unwrap(),
            PathBuf::from("/tmp/swp-walk-test/src")
        );
        // `.` is the one target that legitimately names no *sub*path: it means the
        // root, which is what `swp scan` asks for when it walks a candidate tree
        // that has no configuration of its own.
        assert_eq!(join_target(root, ".").unwrap(), root.to_path_buf());
        assert_eq!(join_target(root, "").unwrap(), root.to_path_buf());
    }

    #[test]
    fn only_parser_covered_extensions_are_walked() {
        let registry = Registry::standard();
        let covered = |rel: &str| registry.for_path(Path::new(rel)).is_some();
        assert!(covered("a/b.js"));
        assert!(covered("a/b.py"));
        assert!(covered("a/b.tsx"));
        assert!(
            !covered("a/b.rs"),
            "the lexical fallback must stay opt-in, not a side effect of the walk"
        );
        assert!(!covered("README"));
    }

    /// `swp scan ../suspect/copy` is the shape a real investigation takes, and a
    /// `..` in the caller's path used to make every file in the candidate look
    /// like it sat outside the walked root — so the scan examined nothing, called
    /// the result inconclusive, and looked like it had looked hard.
    #[test]
    fn a_root_written_with_a_parent_segment_walks_the_same_files() {
        let dir = temp("parent-segment");
        std::fs::create_dir_all(dir.join("here/src")).unwrap();
        std::fs::create_dir_all(dir.join("there/src")).unwrap();
        std::fs::write(dir.join("there/src/a.js"), "const x = 1;\n").unwrap();
        std::fs::write(dir.join("there/src/b.js"), "const y = 2;\n").unwrap();

        let cfg = ProtectConfig {
            targets: vec![".".to_string()],
            ..ProtectConfig::default()
        };
        let limits = Limits::default();
        let plain = walk_for_scan(&dir.join("there"), &cfg, &limits).unwrap();
        let roundabout =
            walk_for_scan(&dir.join("here").join("..").join("there"), &cfg, &limits).unwrap();
        let rels = |w: &Walk| {
            w.files
                .iter()
                .map(|f| f.rel.clone())
                .collect::<Vec<_>>()
                .join(",")
        };
        assert_eq!(plain.files.len(), 2, "{:?}", plain.omissions);
        assert_eq!(
            rels(&plain),
            rels(&roundabout),
            "the same tree spelled two ways yielded two different walks"
        );
        assert!(
            roundabout.omissions.is_empty(),
            "a spelling mistake in the walk is being reported as a candidate's problem: {:?}",
            roundabout.omissions
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn temp(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-walk-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn cfg(targets: &[&str]) -> ProtectConfig {
        ProtectConfig {
            targets: targets.iter().map(|t| t.to_string()).collect(),
            ..ProtectConfig::default()
        }
    }

    #[test]
    fn a_walk_is_sorted_and_deduplicated_across_overlapping_targets() {
        let root = temp("sort");
        touch(&root.join("src/b.js"), "const b = 1;\n");
        touch(&root.join("src/a.js"), "const a = 1;\n");
        touch(&root.join("src/sub/c.js"), "const c = 1;\n");
        touch(&root.join("tools/d.js"), "const d = 1;\n");
        let w = walk(
            &root,
            &cfg(&["src", "src/sub", "tools"]),
            &Limits::default(),
        )
        .unwrap();
        let rels: Vec<&str> = w.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["src/a.js", "src/b.js", "src/sub/c.js", "tools/d.js"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn excluded_directories_are_pruned_and_reported_as_such() {
        let root = temp("prune");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        touch(
            &root.join("src/node_modules/dep/index.js"),
            "const d = 1;\n",
        );
        touch(&root.join("src/dist/bundle.js"), "const b = 1;\n");
        let w = walk(&root, &cfg(&["src"]), &Limits::default()).unwrap();
        assert_eq!(w.files.len(), 1, "only app.js is in scope: {:?}", w.files);
        assert!(w.dirs_pruned >= 2, "both trees should have been pruned");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_named_single_file_target_works() {
        let root = temp("onefile");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        touch(&root.join("src/other.js"), "const b = 1;\n");
        let w = walk(&root, &cfg(&["src/app.js"]), &Limits::default()).unwrap();
        assert_eq!(
            w.files.iter().map(|f| f.rel.as_str()).collect::<Vec<_>>(),
            ["src/app.js"]
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_target_is_reported_rather_than_fatal_when_others_exist() {
        let root = temp("missing");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        let w = walk(&root, &cfg(&["src", "gone"]), &Limits::default()).unwrap();
        assert_eq!(w.files.len(), 1);
        assert!(w
            .omissions
            .iter()
            .any(|o| o.path == "gone" && o.reason.contains("does not exist")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn nothing_in_scope_is_an_error_that_names_a_cause() {
        let root = temp("allgone");
        touch(&root.join("src/data.json"), "{}");
        let e = walk(&root, &cfg(&["nope"]), &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NoSafeLocations);
        assert!(e.message().contains("does not exist"), "{}", e.message());
        let e2 = walk(&root, &cfg(&["src"]), &Limits::default()).unwrap_err();
        assert!(
            e2.message().contains("no language adapter"),
            "the empty-walk error should explain why: {}",
            e2.message()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oversized_files_are_omitted_without_being_read() {
        let root = temp("big");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        touch(&root.join("src/huge.js"), &"x".repeat(4096));
        let limits = Limits {
            max_file_bytes: 64,
            ..Limits::default()
        };
        let w = walk(&root, &cfg(&["src"]), &limits).unwrap();
        assert_eq!(w.files.len(), 1);
        assert!(w
            .omissions
            .iter()
            .any(|o| o.path == "src/huge.js" && o.reason.contains("max_file_bytes")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn too_many_files_stops_the_run_instead_of_protecting_a_subset() {
        let root = temp("count");
        for i in 0..5 {
            touch(&root.join(format!("src/f{i}.js")), "const a = 1;\n");
        }
        let limits = Limits {
            max_files: 3,
            ..Limits::default()
        };
        let e = walk(&root, &cfg(&["src"]), &limits).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded);
        assert!(e.message().contains("narrow"), "{}", e.message());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn empty_files_are_recorded_as_omissions() {
        let root = temp("empty");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        touch(&root.join("src/nothing.js"), "");
        let w = walk(&root, &cfg(&["src"]), &Limits::default()).unwrap();
        assert_eq!(
            w.files.iter().map(|f| f.rel.as_str()).collect::<Vec<_>>(),
            ["src/app.js"]
        );
        assert!(w
            .omissions
            .iter()
            .any(|o| o.path == "src/nothing.js" && o.reason == "empty file"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn symlinks_are_refused_not_followed() {
        let root = temp("link");
        touch(&root.join("src/app.js"), "const a = 1;\n");
        touch(&root.join("elsewhere/x.js"), "const x = 1;\n");
        let link = root.join("src/escape.js");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(root.join("elsewhere/x.js"), &link).is_ok();
        #[cfg(not(windows))]
        let made = std::os::unix::fs::symlink(root.join("elsewhere/x.js"), &link).is_ok();
        if !made {
            // A symlink on Windows needs a privilege a test runner may not have;
            // say so rather than passing a check that never ran.
            eprintln!("skipping: cannot create a symlink in this environment");
            std::fs::remove_dir_all(&root).unwrap();
            return;
        }
        let w = walk(&root, &cfg(&["src"]), &Limits::default()).unwrap();
        assert_eq!(w.files.len(), 1);
        assert!(w
            .omissions
            .iter()
            .any(|o| o.path == "src/escape.js" && o.reason.contains("symbolic link")));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
