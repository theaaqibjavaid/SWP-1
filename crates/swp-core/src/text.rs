//! Byte-level text utilities that make SWP-1 reproducible across operating
//! systems. Every value that goes into a hash passes through these functions,
//! so Windows/Linux/macOS trees holding the same code produce the same ids.

use unicode_normalization::UnicodeNormalization;

/// Canonical text is defined over NFC-normalized UTF-8 bytes. macOS hands out
/// NFD filenames and authors on different OSes type visually identical
/// identifiers with different codepoints; without this pin, the same code would
/// hash differently depending on who checked it out last.
///
/// NFC, deliberately not NFKD: compatibility folding merges genuinely distinct
/// program text (`ﬁ` with `fi`, fullwidth with ASCII), which would create false
/// matches.
pub fn nfc(s: &str) -> String {
    if unicode_normalization::is_nfc(s) {
        return s.to_string();
    }
    s.chars().nfc().collect()
}

pub fn is_nfc(s: &str) -> bool {
    unicode_normalization::is_nfc(s)
}

/// Normalize CRLF and lone CR to LF. Used for hashing inputs only; SWP-1 never
/// rewrites a file's existing line endings.
pub fn newlines_to_lf(bytes: &[u8]) -> Vec<u8> {
    if !bytes.contains(&b'\r') {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                out.push(b'\n');
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Strip a UTF-8 BOM if present.
pub fn strip_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        &bytes[3..]
    } else {
        bytes
    }
}

/// Decode UTF-8 strictly. Source that is not valid UTF-8 is skipped as
/// `MALFORMED_SOURCE` rather than being lossily converted, because a lossy
/// conversion is not reversible and would hash differently per platform.
pub fn decode_utf8_strict(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

/// The dominant line terminator of a file, so a rewrite can keep the file's own
/// convention instead of converting the whole file to LF.
pub fn detect_newline(text: &str) -> &'static str {
    let mut lf = 0usize;
    let mut crlf = 0usize;
    let b = text.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'\n' {
            if i > 0 && b[i - 1] == b'\r' {
                crlf += 1;
            } else {
                lf += 1;
            }
        }
    }
    if crlf > lf {
        "\r\n"
    } else {
        "\n"
    }
}

/// Relative, `/`-separated, NFC path used inside every hashed value and every
/// manifest. Absolute paths never appear in a manifest or report: they are not
/// reproducible and they leak the developer's directory layout.
pub fn canonical_relpath(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in replaced.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                parts.push("..");
            }
            s => parts.push(s),
        }
    }
    nfc(&parts.join("/"))
}

/// A path with its Windows verbatim prefix removed, for display only.
///
/// The store canonicalizes with `\\?\` so that a deep tree stays readable, which
/// is the right thing to hand the filesystem and the wrong thing to print at a
/// person: the prefix is an implementation detail of one platform, and `{:?}` on
/// such a path doubles every separator in it.
pub fn display_path(path: &str) -> &str {
    path.strip_prefix(r"\\?\UNC\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_and_lone_cr_become_lf() {
        assert_eq!(newlines_to_lf(b"a\r\nb\rc\nd"), b"a\nb\nc\nd".to_vec());
        assert_eq!(newlines_to_lf(b"plain"), b"plain".to_vec());
    }

    #[test]
    fn bom_is_stripped_only_at_the_front() {
        assert_eq!(strip_bom(&[0xef, 0xbb, 0xbf, b'x']), b"x");
        assert_eq!(strip_bom(b"x"), b"x");
    }

    #[test]
    fn newline_detection_prefers_dominant_style() {
        assert_eq!(detect_newline("a\r\nb\r\nc\n"), "\r\n");
        assert_eq!(detect_newline("a\nb\n"), "\n");
        assert_eq!(detect_newline("no newlines"), "\n");
    }

    #[test]
    fn relpaths_are_normalized() {
        assert_eq!(canonical_relpath("a\\b\\c"), "a/b/c");
        assert_eq!(canonical_relpath("./a//b/"), "a/b");
        assert_eq!(canonical_relpath("a/./b"), "a/b");
    }

    #[test]
    fn nfc_merges_a_decomposed_sequence() {
        // "e" + combining acute accent becomes U+00E9.
        assert_eq!(nfc("e\u{0301}"), "\u{00e9}");
        assert!(is_nfc(nfc("e\u{0301}").as_str()));
        // Distinct codepoints must NOT be folded together.
        assert_ne!(nfc("\u{fb01}"), "fi");
    }

    #[test]
    fn invalid_utf8_is_rejected_not_replaced() {
        assert!(decode_utf8_strict(&[0xff, 0xfe]).is_none());
    }
}
