//! Turning a literal's *source text* into a value the form engine can rewrite.
//!
//! This is the boundary where an adapter's knowledge of spelling stops and the
//! protocol's knowledge of value begins. It is also where most refusals happen:
//! a literal the adapter cannot interpret with certainty is not a watermark
//! site, and the reason is recorded rather than dropped, because "this project
//! produced no sites" has to be explainable in a report.
//!
//! # What is refused, and why
//!
//! | Spelling | Refused because |
//! |---|---|
//! | `1.5`, `1e9`, `.5` | floating point: `(0.03 + 0.02) != 0.05`, so no arithmetic form is value-preserving |
//! | `1_000` | the decoder would have to agree with the parser about separators |
//! | `0755` | a leading zero means octal in some languages and is a syntax error in others |
//! | `10n`, `0xffn` | BigInt arithmetic has different overflow semantics |
//! | `"a\tb"` | the source text and the decoded value differ, so a split point is not the same thing as a value boundary |
//! | `"a" + "b"` already | an already-decomposed literal is not the canonical spelling a site starts from |
//! | `f"…"`, `` `…` ``, `r"…"` | prefixes change evaluation or escaping |
//!
//! A refusal costs one site. Guessing costs the protocol's correctness.

use swp_core::site::TagWidth;

use crate::dialect::Dialect;
use crate::forms::StringForm;

/// Why a literal was not offered as a watermark site.
///
/// The `str` forms are what a report prints, so they are written to be read by
/// someone who did not write this code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// Not a literal at all (an identifier, a computed member expression).
    NotALiteral,
    /// Floating-point, exponent or hexadecimal-float spelling.
    FloatingPoint,
    /// Arbitrary-precision integer suffix (`10n`).
    BigInt,
    /// Digit separators (`1_000`).
    DigitSeparator,
    /// Leading-zero decimal, which is octal in some languages.
    AmbiguousRadix,
    /// The value is outside the range the protocol reasons about.
    OutOfRange,
    /// Not exactly representable in this language's number type.
    NotExactlyRepresentable,
    /// The literal contains an escape sequence.
    ContainsEscape,
    /// The literal spans lines or is a template/braced string.
    MultilineOrTemplate,
    /// A string prefix changes how the contents are read.
    StringPrefix,
    /// An empty literal has no split point and no escape to add.
    EmptyLiteral,
    /// No family at the requested width can carry every code for this value.
    NoEquivalentForm,
    /// The literal sits in a position where a rewrite would change behavior.
    UnsafeContext,
    /// The file exceeded a resource limit before this literal was reached.
    ResourceLimit,
}

impl RefusalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalKind::NotALiteral => "not-a-literal",
            RefusalKind::FloatingPoint => "floating-point",
            RefusalKind::BigInt => "big-integer",
            RefusalKind::DigitSeparator => "digit-separator",
            RefusalKind::AmbiguousRadix => "ambiguous-radix",
            RefusalKind::OutOfRange => "out-of-range",
            RefusalKind::NotExactlyRepresentable => "not-exactly-representable",
            RefusalKind::ContainsEscape => "contains-escape",
            RefusalKind::MultilineOrTemplate => "multiline-or-template",
            RefusalKind::StringPrefix => "string-prefix",
            RefusalKind::EmptyLiteral => "empty-literal",
            RefusalKind::NoEquivalentForm => "no-equivalent-form",
            RefusalKind::UnsafeContext => "unsafe-context",
            RefusalKind::ResourceLimit => "resource-limit",
        }
    }
}

/// The value of a candidate site, after the adapter has interpreted its spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteValue {
    Integer(i128),
    Text(OwnedString),
}

/// An owned [`StringForm`], so an analysis can outlive the source it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedString {
    pub inner: String,
    pub quote: char,
}

impl OwnedString {
    pub fn as_form(&self) -> StringForm<'_> {
        StringForm {
            inner: &self.inner,
            quote: self.quote,
        }
    }

    pub fn char_count(&self) -> usize {
        self.inner.chars().count()
    }
}

impl SiteValue {
    /// Which literal class this site rewrote, as the manifest records it.
    pub fn class(&self) -> swp_core::site::LiteralClass {
        match self {
            SiteValue::Integer(_) => swp_core::site::LiteralClass::Integer,
            SiteValue::Text(_) => swp_core::site::LiteralClass::String,
        }
    }
}

/// The outcome of interpreting one literal.
pub type Parsed = Result<SiteValue, RefusalKind>;

/// Interpret a numeric literal's source text.
///
/// `text` is the exact spelling in the file, without any leading unary operator:
/// in every language this crate supports, `-5` is an operator applied to `5`, and
/// the token the parser hands over is `5`.
pub fn parse_integer(text: &str, dialect: &Dialect) -> Parsed {
    let t = text.trim();
    if t.is_empty() {
        return Err(RefusalKind::NotALiteral);
    }
    if t.contains('_') || dialect.digit_separator.is_some_and(|s| t.contains(s)) {
        return Err(RefusalKind::DigitSeparator);
    }
    // A dot makes a float in every language and every radix.
    if t.contains('.') {
        return Err(RefusalKind::FloatingPoint);
    }
    if t.ends_with(['n', 'N']) {
        return Err(RefusalKind::BigInt);
    }
    if !t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Err(RefusalKind::NotALiteral);
    }
    let (radix, digits) = match t.as_bytes() {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', b'o' | b'O', rest @ ..] => (8, rest),
        [b'0', b'b' | b'B', rest @ ..] => (2, rest),
        [b'0', second, ..] if second.is_ascii_digit() => return Err(RefusalKind::AmbiguousRadix),
        other => (10, other),
    };
    if digits.is_empty() {
        return Err(RefusalKind::NotALiteral);
    }
    let digits = std::str::from_utf8(digits).map_err(|_| RefusalKind::NotALiteral)?;
    if radix == 10 && digits.contains(['e', 'E', 'f', 'F']) {
        // An exponent, or the `Infinity` and `float` spellings of another language.
        return Err(RefusalKind::FloatingPoint);
    }
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(RefusalKind::NotALiteral);
    }
    let value = i128::from_str_radix(digits, radix).map_err(|_| RefusalKind::OutOfRange)?;
    if value > dialect.max_exact_integer {
        return Err(RefusalKind::NotExactlyRepresentable);
    }
    Ok(SiteValue::Integer(value))
}

/// Interpret a string literal's source text.
///
/// The returned [`StringForm`] carries the *source* text between the quotes, not
/// the decoded value. That is deliberate: the families split and escape source
/// text, and the only case where the two are interchangeable is the one where the
/// text contains no escapes — which is what the refusals below establish.
pub fn parse_string(text: &str, dialect: &Dialect) -> Parsed {
    let t = text;
    let quote = match t.chars().next() {
        Some(c @ ('"' | '\'')) => c,
        // A backtick opens a template literal, which evaluates its contents.
        Some('`') => return Err(RefusalKind::MultilineOrTemplate),
        // `r"…"`, `b"…"`, `f"…"`: a prefix changes how the contents are read, and
        // an `f` prefix means the text between the quotes is not the value.
        Some(c) if c.is_ascii_alphabetic() => return Err(RefusalKind::StringPrefix),
        _ => return Err(RefusalKind::NotALiteral),
    };
    if !dialect.quote_chars.contains(&quote) {
        return Err(RefusalKind::MultilineOrTemplate);
    }
    let triple = String::from_iter([quote, quote, quote]);
    // Triple-quoted strings may span lines, and in JavaScript three in a row is
    // not a literal at all; either way the contents are not plain source text.
    if t.starts_with(&triple) {
        return Err(RefusalKind::MultilineOrTemplate);
    }
    let body = &t[quote.len_utf8()..];
    let Some(inner) = body.strip_suffix(quote) else {
        return Err(RefusalKind::MultilineOrTemplate);
    };
    if inner.is_empty() {
        return Err(RefusalKind::EmptyLiteral);
    }
    if inner.contains('\\') {
        return Err(RefusalKind::ContainsEscape);
    }
    if inner.contains(['\n', '\r']) {
        return Err(RefusalKind::MultilineOrTemplate);
    }
    // `"a"b"` ends at the second quote, so an inner delimiter means what we were
    // handed is not one literal.
    if inner.contains(quote) {
        return Err(RefusalKind::MultilineOrTemplate);
    }
    Ok(SiteValue::Text(OwnedString {
        inner: inner.to_string(),
        quote,
    }))
}

/// Interpret one literal token according to its kind.
pub fn parse_literal(text: &str, kind: swp_core::canon::TokKind, dialect: &Dialect) -> Parsed {
    match kind {
        swp_core::canon::TokKind::Number => parse_integer(text, dialect),
        swp_core::canon::TokKind::String => parse_string(text, dialect),
        swp_core::canon::TokKind::Template | swp_core::canon::TokKind::Regex => {
            Err(RefusalKind::MultilineOrTemplate)
        }
        _ => Err(RefusalKind::NotALiteral),
    }
}

/// The families a value can actually carry at this width.
///
/// Kept here so the AST layer and the fallback lexer ask the same question and
/// get the same answer, and so a site recorded in a manifest is one that was
/// checked to be embeddable before it was counted as available.
pub fn families_for(
    value: &SiteValue,
    width: TagWidth,
    dialect: &Dialect,
) -> Vec<swp_core::site::FormFamily> {
    match value {
        SiteValue::Integer(v) => crate::forms::available_number_families(*v, width, dialect),
        SiteValue::Text(text) => {
            let form = text.as_form();
            crate::forms::available_string_families(&form, width, dialect)
        }
    }
}

/// Does any family carry this value?
pub fn is_embeddable(value: &SiteValue, width: TagWidth, dialect: &Dialect) -> bool {
    !families_for(value, width, dialect).is_empty()
}

/// Render one code into one form for this value.
pub fn render(
    value: &SiteValue,
    family: swp_core::site::FormFamily,
    code: u32,
    width: TagWidth,
    dialect: &Dialect,
) -> Result<String, swp_core::error::SwpError> {
    match value {
        SiteValue::Integer(v) => crate::forms::render_number(*v, family, code, width, dialect),
        SiteValue::Text(text) => {
            crate::forms::render_string(&text.as_form(), family, code, width, dialect)
        }
    }
}

/// Decode a candidate spelling, given the family a manifest says to look for.
pub fn decode(
    text: &str,
    family: swp_core::site::FormFamily,
    width: TagWidth,
    dialect: &Dialect,
) -> Option<DecodedSite> {
    if family.applies_to_numbers() {
        return crate::forms::decode_number(text, family, width).map(|d| DecodedSite::Integer {
            value: d.value,
            code: d.code,
        });
    }
    crate::forms::decode_string(text, family, width, dialect).map(|d| DecodedSite::Text {
        inner: d.inner,
        code: d.code,
        quote: d.quote,
    })
}

/// A form found in a candidate file, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedSite {
    Integer {
        value: i128,
        code: u32,
    },
    Text {
        inner: String,
        code: u32,
        quote: char,
    },
}

impl DecodedSite {
    /// The literal's own value, as the canonicalizer would record it. Used to
    /// confirm that a decoded form and the manifest's original agree.
    pub fn canonical_value(&self) -> String {
        match self {
            DecodedSite::Integer { value, .. } => value.to_string(),
            DecodedSite::Text { inner, .. } => inner.clone(),
        }
    }

    pub fn code(&self) -> u32 {
        match self {
            DecodedSite::Integer { code, .. } | DecodedSite::Text { code, .. } => *code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(t: &str) -> i128 {
        match parse_integer(t, &Dialect::JS).unwrap() {
            SiteValue::Integer(v) => v,
            other => panic!("not an integer: {other:?}"),
        }
    }

    fn text(t: &str) -> OwnedString {
        match parse_string(t, &Dialect::PY).unwrap() {
            SiteValue::Text(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    #[test]
    fn every_radix_spelling_reaches_the_same_value() {
        assert_eq!(int("128000"), 128_000);
        assert_eq!(int("0X1F400"), 128_000);
        assert_eq!(int("0o372000"), 128_000);
        assert_eq!(int("0b11111010000000000"), 128_000);
        assert_eq!(int("0"), 0);
    }

    #[test]
    fn spellings_that_require_a_guess_are_refused() {
        for (src, want) in [
            ("1.5", RefusalKind::FloatingPoint),
            ("1e9", RefusalKind::FloatingPoint),
            (".5", RefusalKind::FloatingPoint),
            ("1_000", RefusalKind::DigitSeparator),
            ("0x1f_40", RefusalKind::DigitSeparator),
            ("10n", RefusalKind::BigInt),
            ("0755", RefusalKind::AmbiguousRadix),
            ("", RefusalKind::NotALiteral),
            ("0x", RefusalKind::NotALiteral),
            ("0b12", RefusalKind::NotALiteral),
            ("1.5e3", RefusalKind::FloatingPoint),
            // 2**127 - 1 has 39 digits, so this 40-digit literal does not fit the
            // protocol integer type at all, rather than merely exceeding a bound.
            (
                "9999999999999999999999999999999999999999",
                RefusalKind::OutOfRange,
            ),
        ] {
            assert_eq!(parse_integer(src, &Dialect::JS).err(), Some(want), "{src}");
        }
        // The exactness bound is a JavaScript fact, not a Python one.
        assert_eq!(
            parse_integer("9007199254740993", &Dialect::JS).err(),
            Some(RefusalKind::NotExactlyRepresentable)
        );
        assert_eq!(
            parse_integer("9007199254740993", &Dialect::PY).unwrap(),
            SiteValue::Integer(9007199254740993)
        );
    }

    #[test]
    fn string_parsing_returns_the_source_text() {
        let s = text("\"station-keeper\"");
        assert_eq!(s.inner, "station-keeper");
        assert_eq!(s.quote, '"');
        assert_eq!(text("'single'").quote, '\'');
        // The inner text keeps its spaces and punctuation untouched.
        assert_eq!(text("\"a, b; c\"").inner, "a, b; c");
    }

    #[test]
    fn strings_that_are_not_plain_literals_are_refused() {
        for (src, want) in [
            ("\"a\\tb\"", RefusalKind::ContainsEscape),
            ("\"\"\"triple\"\"\"", RefusalKind::MultilineOrTemplate),
            ("\"\"\"\"\"\"", RefusalKind::MultilineOrTemplate),
            ("\"unclosed", RefusalKind::MultilineOrTemplate),
            ("''", RefusalKind::EmptyLiteral),
            ("r\"raw\"", RefusalKind::StringPrefix),
            ("b\"bytes\"", RefusalKind::StringPrefix),
            ("f\"{x}\"", RefusalKind::StringPrefix),
            ("\"a\"b\"", RefusalKind::MultilineOrTemplate),
            ("`template`", RefusalKind::MultilineOrTemplate),
        ] {
            assert_eq!(parse_string(src, &Dialect::PY).err(), Some(want), "{src}");
        }
        // The other quote character is ordinary text, not a delimiter.
        assert_eq!(
            parse_string("'say \"hi\" now'", &Dialect::PY).unwrap(),
            SiteValue::Text(OwnedString {
                inner: "say \"hi\" now".to_string(),
                quote: '\''
            })
        );
        assert!(parse_string("\"say 'hi' now\"", &Dialect::PY).is_ok());
    }

    #[test]
    fn a_string_spanning_lines_is_refused_rather_than_split() {
        assert_eq!(
            parse_string("\"one\ntwo-three-four-five-six\"", &Dialect::PY).err(),
            Some(RefusalKind::MultilineOrTemplate)
        );
    }

    #[test]
    fn embeddability_agrees_with_the_form_engine() {
        let w = TagWidth::DEFAULT;
        assert!(is_embeddable(&SiteValue::Integer(1000), w, &Dialect::JS));
        // Every integer a dialect represents exactly has a form: `add` covers
        // values above the modulus and `sub` covers the rest, so a numeric site
        // is refused for how it is spelled — a float, a separator, a BigInt —
        // and never for a lack of renderings. `no-equivalent-form` in a report
        // is therefore about short strings, which is worth stating somewhere.
        for v in [
            0,
            1,
            3,
            16,
            17,
            1000,
            2_147_483_647,
            Dialect::JS.max_exact_integer,
        ] {
            assert!(
                is_embeddable(&SiteValue::Integer(v), w, &Dialect::JS),
                "{v}"
            );
        }
        assert!(is_embeddable(
            &SiteValue::Text(text("\"a really long literal value here\"")),
            w,
            &Dialect::PY
        ));
        assert!(!is_embeddable(
            &SiteValue::Text(text("\"short\"")),
            w,
            &Dialect::PY
        ));
        for f in families_for(&SiteValue::Integer(1000), w, &Dialect::JS) {
            assert!(f.applies_to_numbers());
        }
    }

    #[test]
    fn rendering_and_decoding_agree_through_this_layer_too() {
        let w = TagWidth::DEFAULT;
        let value = SiteValue::Integer(4096);
        for family in families_for(&value, w, &Dialect::JS) {
            let rendered = render(&value, family, 6, w, &Dialect::JS).unwrap();
            match decode(&rendered, family, w, &Dialect::JS).unwrap() {
                DecodedSite::Integer { value: v, code } => {
                    assert_eq!(v, 4096, "{family:?} rendered {rendered}");
                    assert_eq!(code, 6 & (w.modulus() as u32 - 1));
                }
                DecodedSite::Text { .. } => panic!("numeric family decoded a string"),
            }
        }
    }

    #[test]
    fn a_string_site_round_trips_through_this_layer() {
        let w = TagWidth::DEFAULT;
        let site = text("\"the-quick-brown-fox-jumps\"");
        let value = SiteValue::Text(site.clone());
        for family in families_for(&value, w, &Dialect::JS) {
            let rendered = render(&value, family, 3, w, &Dialect::JS).unwrap();
            let back = decode(&rendered, family, w, &Dialect::JS).unwrap();
            assert_eq!(back.canonical_value(), site.inner, "{family:?}");
            assert_eq!(back.code(), 3);
        }
    }
}
