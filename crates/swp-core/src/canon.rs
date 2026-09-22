//! Canonicalization: the three normalization levels defined by the protocol,
//! applied to an abstract token stream.
//!
//! This is the heart of "language-independent". An adapter's whole job with
//! respect to canonicalization is to hand over tokens that say *what the source
//! means* (`kind`, and optionally a normalized `value`); the rules below are
//! identical for every language and are the only thing that location ids and
//! fingerprints are computed from.
//!
//! - **L1 formatting-insensitive.** Whitespace between tokens collapses to one
//!   space, comments are dropped, and a line break survives as exactly one
//!   newline character. Token spellings are preserved otherwise. So re-indenting
//!   and re-wrapping a statement is invisible here, while splitting one line into
//!   two changes the text — the deliberate cost of a level that must not merge
//!   different programs. Used for the release fingerprint.
//! - **L2 identifier-insensitive.** L1 plus every identifier that the adapter
//!   reports as locally bound is renamed by first occurrence to `#lN`. Imports,
//!   globals, property keys and member names are preserved verbatim, because
//!   renaming those merges genuinely different programs and breaks cross-project
//!   matching.
//! - **L3 structural.** L2 plus literal value normalization and adapter-declared
//!   synonym classes, so `0x1F400`, `1_00_000` and `128000` all become
//!   `<n:128000>`. Used for the two name-abstracted location keys, which is the
//!   only reason a reflowed, renamed copy can still hit its site address.
//!   Deliberate losses are documented in docs/SWP-1-SPEC.md.

use sha2::{Digest as _, Sha256};

use crate::id::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonLevel {
    L1,
    L2,
    L3,
}

impl CanonLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            CanonLevel::L1 => "L1",
            CanonLevel::L2 => "L2",
            CanonLevel::L3 => "L3",
        }
    }

    pub fn includes_identifiers(self) -> bool {
        matches!(self, CanonLevel::L1)
    }

    pub fn includes_literals(self) -> bool {
        matches!(self, CanonLevel::L1 | CanonLevel::L2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokKind {
    /// An identifier-ish token: name, `identifier`, `NAME`, ...
    Ident,
    /// A reserved word of the language.
    Keyword,
    /// Numeric literal of any radix or separator style.
    Number,
    /// String/bytes literal.
    String,
    /// Template literal / f-string: not value-equal to a plain string.
    Template,
    /// Regular expression literal.
    Regex,
    /// Operator, e.g. `+`, `==`, `->`.
    Operator,
    /// Punctuation, e.g. `(`, `,`, `{`.
    Punct,
    /// A structural line break, emitted only where newlines carry grammar
    /// (Python). JS/TS adapters omit these; semicolons carry the structure.
    LineBreak,
    /// Kept for diagnostics; never reaches the canonicalizer output.
    Comment,
}

/// What an identifier token *is*, as decided by the adapter's scope analysis.
/// This is where a language's binding rules are encoded, once, so that the
/// normalization below stays language-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum IdentRole {
    /// Bound inside the region being canonicalized: local variable, parameter,
    /// locally declared function or class. Renamed at L2.
    #[default]
    Local,
    /// Resolved outside the region: global, imported name, standard-library
    /// name. Preserved at every level.
    Free,
    /// Property access target (`obj.member`) — not a binding in JS/TS.
    MemberName,
    /// Object/struct literal key — semantic data, not a binding.
    PropertyKey,
    /// Label or other syntactic name.
    Label,
}

impl IdentRole {
    /// Whether L2 renames a token with this role.
    pub fn renamed(self) -> bool {
        matches!(self, IdentRole::Local | IdentRole::Label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSpan {
    pub start: u32,
    pub end: u32,
}

impl ByteSpan {
    pub fn new(start: u32, end: u32) -> Self {
        ByteSpan { start, end }
    }
    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
    pub fn contains(&self, off: u32) -> bool {
        off >= self.start && off < self.end
    }
}

/// One token of the abstract stream an adapter produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokKind,
    /// Exact source spelling.
    pub text: String,
    /// Normalized meaning, when the adapter can produce one: the decimal value
    /// of a number, the decoded contents of a string, the source of a regex.
    /// L3 uses this instead of `text`, which is what makes the structural
    /// channel immune to the tag channel being constant-folded away.
    pub value: Option<String>,
    pub role: IdentRole,
    /// Adapter-declared equivalence class used at L3 only, e.g. `!=` and `!==`
    /// both mapping to `NEQ`. `None` means "no declared equivalence".
    pub synonym: Option<String>,
    pub span: ByteSpan,
}

impl Token {
    pub fn new(kind: TokKind, text: impl Into<String>, span: ByteSpan) -> Self {
        Token {
            kind,
            text: text.into(),
            value: None,
            role: IdentRole::default(),
            synonym: None,
            span,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    pub fn with_role(mut self, role: IdentRole) -> Self {
        self.role = role;
        self
    }

    pub fn with_synonym(mut self, syn: impl Into<String>) -> Self {
        self.synonym = Some(syn.into());
        self
    }
}

/// Result of canonicalization: the normalized bytes plus a digest, which is the
/// form actually stored in manifests and indexes.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalText {
    bytes: Vec<u8>,
    digest: Digest,
}

impl CanonicalText {
    pub fn new(bytes: Vec<u8>) -> Self {
        let digest = Digest(Sha256::digest(&bytes).into());
        CanonicalText { bytes, digest }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_str(&self) -> &str {
        // Canonical output is UTF-8 by construction.
        std::str::from_utf8(&self.bytes).unwrap_or("<non-utf8>")
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn hex(&self) -> String {
        self.digest.hex()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl std::fmt::Debug for CanonicalText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Canon({}b, {})", self.bytes.len(), self.digest.short())
    }
}

/// Escape a token value so it cannot be confused with canonical structure.
fn push_escaped(out: &mut Vec<u8>, prefix: &[u8], value: &str) {
    out.extend_from_slice(prefix);
    for c in value.chars() {
        match c {
            '\\' => out.extend_from_slice(b"\\\\"),
            '<' => out.extend_from_slice(b"\\<"),
            '>' => out.extend_from_slice(b"\\>"),
            ' ' => out.push(b'_'),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if c.is_control() => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    out.push(b'>');
}

/// Canonicalize a token stream.
///
/// `site` marks the byte span of the watermark site itself; its tokens are
/// replaced by a single `<SITE>` placeholder. This is load-bearing: a location
/// id is computed from the code *around* a site, so the site's own spelling
/// cannot be part of it — otherwise embedding a fragment would destroy the id
/// that identifies where the fragment lives.
pub fn canonicalize(tokens: &[Token], level: CanonLevel, site: Option<ByteSpan>) -> CanonicalText {
    let mut out: Vec<u8> = Vec::with_capacity(tokens.len() * 8);
    let mut seen: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut first = true;
    let mut pushed_site_placeholder = false;

    for t in tokens {
        if t.kind == TokKind::Comment {
            continue;
        }
        if let Some(s) = site {
            if s.contains(t.span.start) {
                if !pushed_site_placeholder {
                    if !first {
                        out.push(b' ');
                    }
                    out.extend_from_slice(b"<SITE>");
                    first = false;
                    pushed_site_placeholder = true;
                }
                continue;
            }
        }
        if !first {
            out.push(b' ');
        }
        first = false;
        match t.kind {
            TokKind::Ident if level != CanonLevel::L1 && t.role.renamed() => {
                let n = match seen.get(t.text.as_str()) {
                    Some(n) => *n,
                    None => {
                        let n = seen.len();
                        seen.insert(t.text.as_str(), n);
                        n
                    }
                };
                let label = format!("#l{n}");
                out.extend_from_slice(label.as_bytes());
            }
            TokKind::Number | TokKind::String | TokKind::Template | TokKind::Regex => {
                if level.includes_literals() {
                    out.extend_from_slice(t.text.as_bytes());
                } else {
                    let (tag, value) = match t.kind {
                        TokKind::Number => (b"<n:".as_slice(), t.value.as_deref()),
                        TokKind::String => (b"<s:".as_slice(), t.value.as_deref()),
                        TokKind::Template => (b"<t:".as_slice(), t.value.as_deref()),
                        _ => (b"<r:".as_slice(), t.value.as_deref()),
                    };
                    match value {
                        Some(v) => push_escaped(&mut out, tag, v),
                        // An adapter that cannot normalize a literal keeps its
                        // spelling; the loss is recorded in the spec.
                        None => out.extend_from_slice(t.text.as_bytes()),
                    }
                }
            }
            TokKind::Operator | TokKind::Keyword => match (level, &t.synonym) {
                (CanonLevel::L3, Some(s)) => out.extend_from_slice(s.as_bytes()),
                _ => out.extend_from_slice(t.text.as_bytes()),
            },
            TokKind::LineBreak => {
                if level == CanonLevel::L1 {
                    out.push(b'\n');
                } else {
                    out.extend_from_slice(b"\\n");
                }
            }
            TokKind::Punct => out.extend_from_slice(t.text.as_bytes()),
            TokKind::Ident => out.extend_from_slice(t.text.as_bytes()),
            TokKind::Comment => {}
        }
    }
    // Nothing extra is counted here: because a locally bound identifier is renamed
    // by first occurrence, two texts that differ in how many names they bind
    // already differ in the bytes, so a region renamed beyond its own count cannot
    // collide with one that merely changed formatting.
    CanonicalText::new(out)
}

/// Tokens whose span lies wholly inside `span`, as a subslice.
///
/// Relies on the guarantee that a stream is in source order and non-overlapping,
/// which every adapter establishes by walking a parser's leaves. This is the only
/// implementation of that selection: the radius keys of [`crate::radius`] and
/// `swp-adapters`' validation both go through it, so the text a location id is
/// digested from and the text an embedding proves unchanged are the same text.
pub fn tokens_within(tokens: &[Token], span: ByteSpan) -> &[Token] {
    let start = tokens.partition_point(|t| t.span.end <= span.start || t.span.start < span.start);
    let end = tokens.partition_point(|t| t.span.end <= span.end);
    &tokens[start.min(end)..end]
}

/// Render a canonical text for human display in `swp inspect` (truncated).
pub fn preview(text: &CanonicalText, max: usize) -> String {
    let s = text.as_str();
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…(+{}b)", &s[..end], s.len() - end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(v: &[(TokKind, &str)]) -> Vec<Token> {
        let mut off = 0u32;
        v.iter()
            .map(|(k, t)| {
                let span = ByteSpan::new(off, off + t.len() as u32);
                off += t.len() as u32 + 1;
                Token::new(*k, *t, span)
            })
            .collect()
    }

    #[test]
    fn l1_drops_comments_and_keeps_spellings() {
        let mut t = toks(&[
            (TokKind::Ident, "x"),
            (TokKind::Punct, "="),
            (TokKind::Number, "0x10"),
        ]);
        t.insert(
            0,
            Token::new(TokKind::Comment, "// hi", ByteSpan::new(0, 5)),
        );
        let c = canonicalize(&t, CanonLevel::L1, None);
        assert_eq!(c.as_str(), "x = 0x10");
    }

    #[test]
    fn l3_normalizes_literal_values() {
        let mut t = toks(&[(TokKind::Punct, "="), (TokKind::Number, "0x1F400")]);
        t[1] = t[1].clone().with_value("128000");
        let c = canonicalize(&t, CanonLevel::L3, None);
        assert_eq!(c.as_str(), "= <n:128000>");
        // Same value written differently canonicalizes identically.
        let mut u = toks(&[(TokKind::Punct, "="), (TokKind::Number, "1_28_000")]);
        u[1] = u[1].clone().with_value("128000");
        assert_eq!(canonicalize(&u, CanonLevel::L3, None), c);
        // And differently at L1/L2.
        assert_ne!(
            canonicalize(&t, CanonLevel::L2, None),
            canonicalize(&u, CanonLevel::L2, None)
        );
    }

    #[test]
    fn l2_renames_locals_in_first_occurrence_order_and_preserves_free_names() {
        let src = [
            (TokKind::Ident, "count"),
            (TokKind::Punct, "="),
            (TokKind::Number, "0"),
            (TokKind::Ident, "console"),
            (TokKind::Punct, "."),
            (TokKind::Ident, "log"),
            (TokKind::Punct, "("),
            (TokKind::Ident, "count"),
            (TokKind::Punct, ")"),
        ];
        let mut t = toks(&src);
        t[0].role = IdentRole::Local;
        t[3].role = IdentRole::Free;
        t[5].role = IdentRole::MemberName;
        t[7].role = IdentRole::Local;
        let c = canonicalize(&t, CanonLevel::L2, None);
        assert_eq!(c.as_str(), "#l0 = 0 console . log ( #l0 )");
        // Renaming the local does not change the canonical form...
        let mut r = t.clone();
        r[0].text = "n".into();
        r[7].text = "n".into();
        assert_eq!(canonicalize(&r, CanonLevel::L2, None), c);
        // ...but renaming a free name does, on purpose.
        let mut g = t.clone();
        g[3].text = "logger".into();
        assert_ne!(canonicalize(&g, CanonLevel::L2, None), c);
    }

    #[test]
    fn site_placeholder_makes_the_site_invisible_to_the_locator() {
        let t = toks(&[
            (TokKind::Ident, "x"),
            (TokKind::Punct, "="),
            (TokKind::Number, "1000"),
        ]);
        let site = Some(ByteSpan::new(t[2].span.start, t[2].span.end));
        let plain = canonicalize(&t, CanonLevel::L3, site);
        // `x` is a local binding, so L3 abstracts it too; the point is that the
        // site's own spelling is gone.
        assert_eq!(plain.as_str(), "#l0 = <SITE>");
        // After embedding, the same tokens carry a decomposition; the id is
        // unchanged because the site is replaced either way.
        let embedded = vec![
            Token::new(TokKind::Ident, "x", ByteSpan::new(0, 1)),
            Token::new(TokKind::Punct, "=", ByteSpan::new(2, 3)),
            Token::new(TokKind::Punct, "(", ByteSpan::new(4, 5)),
            Token::new(TokKind::Number, "996", ByteSpan::new(5, 8)),
            Token::new(TokKind::Operator, "+", ByteSpan::new(9, 10)),
            Token::new(TokKind::Number, "4", ByteSpan::new(11, 12)),
            Token::new(TokKind::Punct, ")", ByteSpan::new(12, 13)),
        ];
        let site_after = Some(ByteSpan::new(4, 13));
        let after = canonicalize(&embedded, CanonLevel::L3, site_after);
        assert_eq!(after.as_str(), "#l0 = <SITE>");
        assert_eq!(after, plain);
        // Without the placeholder the two would differ, which is the circular
        // reference the protocol must avoid.
        assert_ne!(
            canonicalize(&t, CanonLevel::L3, None),
            canonicalize(&embedded, CanonLevel::L3, None)
        );
    }

    #[test]
    fn escaped_values_cannot_forge_structure() {
        // A string whose *contents* look like canonical markup must not be able
        // to impersonate a number token: '<' and '>' and '\' are all escaped.
        let mut t = toks(&[(TokKind::String, "\"x\"")]);
        t[0] = t[0].clone().with_value("<n:5> <s:a");
        let c = canonicalize(&t, CanonLevel::L3, None);
        assert_eq!(c.as_str(), "<s:\\<n:5\\>_\\<s:a>");
        let mut u = toks(&[(TokKind::String, "\"y\"")]);
        u[0] = u[0].clone().with_value("<n:5> <s:a>");
        assert_ne!(canonicalize(&u, CanonLevel::L3, None), c);
    }

    #[test]
    fn synonyms_only_apply_at_l3() {
        let a = toks(&[(TokKind::Operator, "!=")]);
        let b = vec![Token::new(TokKind::Operator, "!=", ByteSpan::new(0, 2)).with_synonym("NEQ")];
        assert_eq!(
            canonicalize(&a, CanonLevel::L1, None),
            canonicalize(&b, CanonLevel::L1, None)
        );
        assert_eq!(canonicalize(&b, CanonLevel::L3, None).as_str(), "NEQ");
    }

    #[test]
    fn digests_are_stable_bytes() {
        let t = toks(&[(TokKind::Ident, "a"), (TokKind::Punct, ";")]);
        let c1 = canonicalize(&t, CanonLevel::L1, None);
        let c2 = canonicalize(&t, CanonLevel::L1, None);
        assert_eq!(c1.digest(), c2.digest());
        assert_eq!(c1.hex().len(), 64);
    }
}
