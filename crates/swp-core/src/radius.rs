//! The four radius keys of a watermark site: what identifies *where* it is.
//!
//! A site is never located by its own text — that is the text the watermark
//! rewrites, and rewriting it would change the address of the thing it
//! identifies. Instead each site is addressed by the code *around* it, at two
//! radii (the innermost enclosing statement, the enclosing function or module
//! block) and two levels of abstraction, giving four keys per site.
//!
//! | key | radius | level | survives |
//! |---|---|---|---|
//! | `statement+identifiers` | statement | L3 | renaming locals, respelling other literals, reformatting |
//! | `scope+identifiers` | scope | L3 | the above, plus the statement moving within its scope |
//! | `statement+names` | statement | L1 | reformatting only |
//! | `scope+names` | scope | L1 | reformatting only |
//!
//! The abstracted pair uses L3 rather than L2 deliberately. L2 abstracts names
//! but keeps every *other* literal's spelling, so a copier who writes `1_000`
//! where the project wrote `1000` would break all four keys at once. At L3 the
//! surrounding literals are normalized by value, so the site is still found, and
//! the two name-preserving keys remain what identifies a copy that was not
//! edited at all.
//!
//! This is the single definition of that computation. `swp-embedding` uses it to
//! write a manifest and `swp-detection` uses it to read one; if the two ever
//! disagreed, every site in every copy would look like a tamper, so neither is
//! allowed its own copy of these twelve lines. The cross-check that they still
//! agree with the adapter's own radius queries lives in
//! `crates/swp-adapters/tests/token_stream.rs`.

use crate::canon::{canonicalize, tokens_within, ByteSpan, CanonLevel, Token};
use crate::id::Digest;
use crate::site::RadiusKind;

/// The canonical level a radius key is computed at.
pub fn level_for(kind: RadiusKind) -> CanonLevel {
    match kind {
        RadiusKind::StatementId | RadiusKind::ScopeId => CanonLevel::L3,
        RadiusKind::StatementRaw | RadiusKind::ScopeRaw => CanonLevel::L1,
    }
}

/// The site's canonical digest at one radius, with the site hidden.
pub fn radius_digest(
    tokens: &[Token],
    kind: RadiusKind,
    statement: ByteSpan,
    scope: ByteSpan,
    site: ByteSpan,
) -> Digest {
    let radius = match kind {
        RadiusKind::StatementId | RadiusKind::StatementRaw => statement,
        RadiusKind::ScopeId | RadiusKind::ScopeRaw => scope,
    };
    canonicalize(
        tokens_within(tokens, radius),
        level_for(kind),
        Some(site),
    )
    .digest()
}

/// All four keys, indexed by [`RadiusKind::all`] — which is also the order a
/// manifest stores them in, so index `i` here and slot `i` there are the same
/// key by construction rather than by convention.
pub fn radius_digests(
    tokens: &[Token],
    statement: ByteSpan,
    scope: ByteSpan,
    site: ByteSpan,
) -> [Digest; 4] {
    let mut out = [Digest::default(); 4];
    for (i, kind) in RadiusKind::all().iter().enumerate() {
        out[i] = radius_digest(tokens, *kind, statement, scope, site);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::{IdentRole, TokKind};

    fn ident(text: &str, start: u32) -> Token {
        Token::new(
            TokKind::Ident,
            text,
            ByteSpan::new(start, start + text.len() as u32),
        )
        .with_role(IdentRole::Local)
    }

    fn punct(text: &str, start: u32) -> Token {
        Token::new(
            TokKind::Punct,
            text,
            ByteSpan::new(start, start + text.len() as u32),
        )
    }

    fn number(text: &str, value: &str, start: u32) -> Token {
        Token::new(
            TokKind::Number,
            text,
            ByteSpan::new(start, start + text.len() as u32),
        )
        .with_value(value)
    }

    /// `( const total = base + 1000 )`, with `1000` the site.
    fn stream() -> Vec<Token> {
        vec![
            punct("(", 0),
            ident("const", 2),
            ident("total", 8),
            punct("=", 14),
            ident("base", 16),
            punct("+", 21),
            number("1000", "1000", 23),
            punct(")", 28),
        ]
    }

    const SITE: ByteSpan = ByteSpan { start: 23, end: 27 };
    const STMT: ByteSpan = ByteSpan { start: 0, end: 29 };

    /// The property every other claim in this module rests on: rewriting the
    /// site does not move it.
    /// The whole point of hiding the site: a rewrite that replaces one token
    /// with a longer expression leaves the address untouched, because the
    /// rendering occupies the site span and everything else keeps its place.
    #[test]
    fn the_sites_own_spelling_does_not_change_its_address() {
        let before = radius_digests(&stream(), STMT, STMT, SITE);
        let rendered = vec![
            punct("(", 0),
            ident("const", 2),
            ident("total", 8),
            punct("=", 14),
            ident("base", 16),
            punct("+", 21),
            number("(900 + 100)", "1000", 23),
            punct(")", 35),
        ];
        let after = radius_digests(
            &rendered,
            ByteSpan { start: 0, end: 36 },
            ByteSpan { start: 0, end: 36 },
            ByteSpan { start: 23, end: 34 },
        );
        assert_eq!(before, after);
    }

    #[test]
    fn abstracted_keys_absorb_renames_and_respellings() {
        let mut other = stream();
        other[2] = ident("count", 8);
        other[6] = number("1_000", "1000", 23);
        for kind in [RadiusKind::StatementId, RadiusKind::ScopeId] {
            assert_eq!(
                radius_digest(&stream(), kind, STMT, STMT, SITE),
                radius_digest(&other, kind, STMT, STMT, SITE),
                "{kind:?} should not notice a local rename or a respelling"
            );
        }
        for kind in [RadiusKind::StatementRaw, RadiusKind::ScopeRaw] {
            assert_ne!(
                radius_digest(&stream(), kind, STMT, STMT, SITE),
                radius_digest(&other, kind, STMT, STMT, SITE),
                "{kind:?} should notice them: it is the exact-copy key"
            );
        }
    }

    #[test]
    fn two_different_radii_give_two_different_digests() {
        let narrow_scope = ByteSpan { start: 14, end: 29 };
        let d = radius_digests(&stream(), STMT, narrow_scope, SITE);
        assert_ne!(d[0], d[1]);
        assert_ne!(d[2], d[3]);
    }

    /// A module-level statement in a small file has the same span at both
    /// radii, and the lexical fallback says so by using the whole document for
    /// both. The digests are then equal by construction — the four *keys* stay
    /// distinct because `swp-manifest` mixes the radius into the id, which is
    /// the part of this design that a digest alone cannot carry.
    #[test]
    fn equal_radii_give_equal_digests_and_are_not_an_error() {
        let d = radius_digests(&stream(), STMT, STMT, SITE);
        assert_eq!(d[0], d[1], "statement and scope keys share one span");
        assert_eq!(d[2], d[3]);
        assert_ne!(d[0], d[2], "L1 and L3 of the same text differ");
    }

    #[test]
    fn hiding_the_site_keeps_everything_else() {
        let visible = canonicalize(&stream(), CanonLevel::L1, None).as_str().to_string();
        let hidden = canonicalize(&stream(), CanonLevel::L1, Some(SITE)).as_str().to_string();
        assert!(visible.contains("1000"), "{visible}");
        assert!(!hidden.contains("1000"), "{hidden}");
        assert!(hidden.contains("<SITE>"), "{hidden}");
    }

    #[test]
    fn levels_are_the_documented_ones() {
        assert_eq!(level_for(RadiusKind::StatementId), CanonLevel::L3);
        assert_eq!(level_for(RadiusKind::ScopeId), CanonLevel::L3);
        assert_eq!(level_for(RadiusKind::StatementRaw), CanonLevel::L1);
        assert_eq!(level_for(RadiusKind::ScopeRaw), CanonLevel::L1);
    }

    #[test]
    fn the_computation_is_deterministic() {
        assert_eq!(
            radius_digests(&stream(), STMT, STMT, SITE),
            radius_digests(&stream(), STMT, STMT, SITE)
        );
    }

    #[test]
    fn a_token_outside_the_radius_is_not_part_of_it() {
        let inner = ByteSpan { start: 14, end: 28 };
        let tokens = stream();
        let inside = tokens_within(&tokens, inner);
        assert_eq!(inside.len(), 4);
        assert_eq!(inside[0].text, "=");
        assert_eq!(inside[3].text, "1000");
    }
}
