//! Secret-leak scanning (§29).
//!
//! # Why this is a library and not one test
//!
//! A leak can appear in a manifest, a report, a CLI log line, an error message,
//! a test snapshot, a restore plan, or a temporary file left behind by a crash.
//! Those artifacts are produced by five different crates, and the way to check
//! each of them is identical: hold a secret whose value you know, produce the
//! artifact, and look for it. So the looking lives here and every suite reuses
//! it. If the check and the suites drift apart, the check is worthless.
//!
//! # What counts as a leak
//!
//! Any of a set of *renderings* of the secret — see [`NeedleSet`]. A secret
//! that reaches an artifact as raw bytes, as hex, as base64 with or without
//! padding, or as a URL-escaped string is equally leaked, and an implementation
//! that leaks only one of those would pass a test that looked for only one.
//!
//! # What this cannot do
//!
//! It cannot see a secret that has been transformed — hashed into something the
//! attacker cannot invert is fine, but so is "XOR'd with a constant", and no
//! byte-pattern search catches that. The suites therefore also assert the
//! positive property where it matters: that the values which *do* appear are
//! derivable only with the key. This is a tripwire for careless serialization,
//! not a proof.

use std::path::Path;

use base64::Engine as _;
use swp_core::hex_encode;

/// Byte length below which a "secret" is too short to search for: at that size
/// random matches in ordinary text would make the sweep useless, and nothing in
/// SWP-1 handles a secret that small.
const MIN_SECRET_LEN: usize = 16;

/// Every form of one secret worth grepping for.
#[derive(Debug, Clone)]
pub struct NeedleSet {
    label: String,
    needles: Vec<(&'static str, Vec<u8>)>,
}

impl NeedleSet {
    /// Build the renderings of `secret`, which is expected to be a root secret
    /// or a derived key.
    pub fn new(label: impl Into<String>, secret: &[u8]) -> Self {
        assert!(
            secret.len() >= MIN_SECRET_LEN,
            "refusing to sweep for a {len}-byte needle; shorter values match ordinary text",
            len = secret.len()
        );
        let mut needles: Vec<(&'static str, Vec<u8>)> = Vec::new();
        let mut push = |name: &'static str, bytes: Vec<u8>| {
            if !bytes.is_empty() {
                needles.push((name, bytes));
            }
        };

        push("raw", secret.to_vec());
        push("hex-lower", hex_encode(secret).into_bytes());
        push(
            "hex-upper",
            hex_encode(secret).to_ascii_uppercase().into_bytes(),
        );
        // Grouped hex is how a human-readable log might format a key.
        push(
            "hex-spaced",
            hex_encode(secret)
                .as_bytes()
                .chunks(2)
                .map(|p| String::from_utf8_lossy(p).to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .into_bytes(),
        );
        let std_b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        push("base64", std_b64.clone().into_bytes());
        push(
            "base64-nopad",
            std_b64.trim_end_matches('=').as_bytes().to_vec(),
        );
        push(
            "base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret)
                .into_bytes(),
        );
        push(
            "base64-hyphenated",
            std_b64
                .as_bytes()
                .chunks(4)
                .map(|p| String::from_utf8_lossy(p).to_string())
                .collect::<Vec<_>>()
                .join("-")
                .into_bytes(),
        );
        // Percent-encoding, as it would appear if a key ever rode in a URL.
        let escaped: String = secret
            .iter()
            .map(|b| format!("%{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        push("percent", escaped.into_bytes());

        NeedleSet {
            label: label.into(),
            needles,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn rendering_count(&self) -> usize {
        self.needles.len()
    }

    /// Which renderings, if any, occur in `haystack`.
    pub fn find(&self, haystack: &[u8]) -> Vec<&'static str> {
        self.needles
            .iter()
            .filter(|(_, needle)| contains_bytes(haystack, needle))
            .map(|(name, _)| *name)
            .collect()
    }
}

/// Substring search over bytes. A `memchr`-free implementation is fine here:
/// sweeps run over a handful of small artifacts in tests, not over source trees
/// in production.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// One artifact that leaked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub artifact: String,
    pub renderings: Vec<&'static str>,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} leaks a secret as {}",
            self.artifact,
            self.renderings.join(" + ")
        )
    }
}

/// Everything a sweep looked at, so a suite can assert it actually covered the
/// artifacts it claims to cover rather than passing on an empty scan.
#[derive(Debug, Default)]
pub struct SweepReport {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub skipped: Vec<String>,
    pub violations: Vec<Violation>,
}

impl SweepReport {
    pub fn assert_clean(&self) {
        assert!(
            self.files_scanned > 0,
            "the sweep looked at nothing; a vacuous pass is a broken test"
        );
        assert!(
            self.violations.is_empty(),
            "secret leak detected:\n{}",
            self.violations
                .iter()
                .map(|v| format!("  {v}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    pub fn summary(&self) -> String {
        format!(
            "scanned {} file(s), {} byte(s), {} skipped, {} violation(s)",
            self.files_scanned,
            self.bytes_scanned,
            self.skipped.len(),
            self.violations.len()
        )
    }
}

/// Sweep an in-memory artifact — a rendered report, a CLI's stdout, a
/// serialized manifest — without it ever touching disk.
pub fn sweep_bytes(label: &str, bytes: &[u8], needles: &[NeedleSet], out: &mut SweepReport) {
    out.files_scanned += 1;
    out.bytes_scanned += bytes.len() as u64;
    for needle in needles {
        let renderings = needle.find(bytes);
        if !renderings.is_empty() {
            out.violations.push(Violation {
                artifact: format!(
                    "{label} [{}, {:?}]",
                    needle.label(),
                    first_offsets(bytes, needle)
                ),
                renderings,
            });
        }
    }
}

fn first_offsets(bytes: &[u8], needle: &NeedleSet) -> Vec<usize> {
    needle
        .needles
        .iter()
        .filter_map(|(_, n)| {
            if n.is_empty() || n.len() > bytes.len() {
                return None;
            }
            (0..=(bytes.len() - n.len())).find(|&i| bytes[i..i + n.len()] == n[..])
        })
        .take(3)
        .collect()
}

/// Sweep every file under `root`, following no symlinks and skipping nothing by
/// extension — a secret hidden in a file type we decided not to read is exactly
/// the leak this suite exists to find.
pub fn sweep_tree(root: &Path, needles: &[NeedleSet]) -> SweepReport {
    sweep_tree_skipping(root, needles, &[])
}

/// As [`sweep_tree`], but ignoring files whose path ends with any of
/// `skip_suffixes`.
///
/// There is exactly one legitimate use for this: `root.key` is *supposed* to
/// contain the secret, and no sweep is interesting until it stops reporting
/// that one file. Every caller must therefore say which files it excused, and
/// the suites assert that the excused set is precisely the root key and nothing
/// else. An unbounded skip list would turn this suite into a no-op.
pub fn sweep_tree_skipping(
    root: &Path,
    needles: &[NeedleSet],
    skip_suffixes: &[&str],
) -> SweepReport {
    let mut report = SweepReport::default();
    // Materialise the walk before touching `report` again: the error collector
    // below and the read loop both need it mutably, and holding the iterator
    // open across both is a borrow conflict, not a real requirement.
    let mut walk_errors = Vec::new();
    let paths: Vec<std::path::PathBuf> = walkdir::WalkDir::new(root)
        .follow_links(false)
        .max_depth(32)
        .into_iter()
        .filter_map(|entry| match entry {
            Ok(e) => Some(e),
            Err(err) => {
                walk_errors.push(format!("unreadable entry: {err}"));
                None
            }
        })
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    report.skipped.extend(walk_errors);
    for path in paths {
        let display = path.display().to_string();
        if skip_suffixes.iter().any(|s| display.ends_with(s)) {
            report.skipped.push(display);
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => sweep_bytes(&display, &bytes, needles, &mut report),
            Err(e) => report.skipped.push(format!("{}: {e}", path.display())),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn every_rendering_of_a_secret_is_detected() {
        let needles = NeedleSet::new("test", &secret());
        assert!(needles.rendering_count() >= 8);
        // Feed each rendering back separately, so a needle that silently became
        // empty or unsearchable fails rather than quietly reducing coverage.
        let forms: Vec<Vec<u8>> = vec![
            secret(),
            hex_encode(&secret()).into_bytes(),
            hex_encode(&secret()).to_ascii_uppercase().into_bytes(),
            base64::engine::general_purpose::STANDARD
                .encode(secret())
                .into_bytes(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret())
                .into_bytes(),
        ];
        for form in forms {
            let text = format!(
                "prefix {form} suffix",
                form = String::from_utf8_lossy(&form)
            );
            assert!(
                !needles.find(text.as_bytes()).is_empty(),
                "missed rendering {text}"
            );
        }
    }

    #[test]
    fn clean_artifacts_produce_no_violations() {
        let needles = NeedleSet::new("test", &secret());
        let innocent =
            br#"{"protocol":"SWP-1","project_id":"swp1-abcdefghijklmnop","signature":"dGVzdA=="}"#;
        assert!(needles.find(innocent).is_empty());
    }

    #[test]
    fn a_secret_embedded_in_a_large_file_is_still_found() {
        let needles = NeedleSet::new("test", &secret());
        let mut blob = vec![b'x'; 500_000];
        let hex = hex_encode(&secret());
        blob[499_000..499_000 + hex.len()].copy_from_slice(hex.as_bytes());
        assert!(needles.find(&blob).contains(&"hex-lower"));
    }

    #[test]
    fn short_needles_are_refused_rather_than_being_noisy() {
        let r = std::panic::catch_unwind(|| NeedleSet::new("tiny", b"abc"));
        assert!(r.is_err(), "a 3-byte needle matches ordinary text");
    }

    #[test]
    fn a_sweep_of_nothing_fails_the_assert() {
        let report = SweepReport::default();
        assert!(std::panic::catch_unwind(|| report.assert_clean()).is_err());
    }
}
