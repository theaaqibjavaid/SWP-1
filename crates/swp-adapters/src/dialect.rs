//! The per-language facts the form engine needs.
//!
//! The form engine in [`crate::forms`] is shared by every language: it renders
//! and decodes watermark-bearing literal spellings. What differs between
//! languages is which spellings the parser accepts, and how far an integer may
//! grow before the language stops representing it exactly. Those differences are
//! data, not code, so they live here as a struct.
//!
//! A new adapter supplies a `Dialect` and gets every family the data supports —
//! which is the main reason adding a language later does not touch the protocol.

/// How one language renders literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dialect {
    pub name: &'static str,
    /// Largest integer the language represents exactly in ordinary arithmetic.
    /// Above it, an expression like `(a + b)` may not evaluate back to the
    /// original value, so no arithmetic family may be used. JavaScript numbers
    /// are IEEE-754 doubles; Python integers are unbounded.
    pub max_exact_integer: i128,
    /// Whether `<int>` `/` truncates toward negative infinity (Python) rather
    /// than producing a float. Affects nothing in v1 — every form here uses
    /// `+`, `-` and `*` only — but recorded because an adapter author reading
    /// this struct needs to know the field was considered.
    pub integer_division_truncates: bool,
    /// Whether two adjacent string literals concatenate without an operator.
    /// Python yes; JavaScript and TypeScript no.
    pub adjacent_strings: bool,
    /// Whether `\xHH` escapes are accepted inside an ordinary string literal.
    /// This is the whole of what the `str-escape` family needs from a language,
    /// so a dialect that sets it false simply never sees that family offered —
    /// on either side of the pipeline, which is the point: a family the scanner
    /// would not recognise is one the writer must not produce.
    pub hex_escapes: bool,
    /// Quote characters that begin a plain string literal.
    pub quote_chars: &'static [char],
    /// Character used for digit grouping, if any (`1_000`). A literal written
    /// with separators is left alone: the decoder would have to agree with the
    /// parser about it, and that is one ambiguity fewer worth having.
    pub digit_separator: Option<char>,
}

impl Dialect {
    /// ECMAScript: numbers are doubles, so exactness ends at 2^53 - 1.
    pub const JS: Dialect = Dialect {
        name: "javascript",
        max_exact_integer: (1i128 << 53) - 1,
        integer_division_truncates: false,
        adjacent_strings: false,
        hex_escapes: true,
        quote_chars: &['"', '\''],
        // Numeric separators are ES2021, so a modern JavaScript file really can
        // contain `1_000_000`. Refused either way; recorded because it is true.
        digit_separator: Some('_'),
    };

    /// TypeScript shares JavaScript's runtime, therefore its exactness bound.
    pub const TS: Dialect = Dialect {
        name: "typescript",
        ..Dialect::JS
    };

    /// Python integers are arbitrary precision; adjacent literals concatenate.
    pub const PY: Dialect = Dialect {
        name: "python",
        max_exact_integer: i128::MAX,
        integer_division_truncates: true,
        adjacent_strings: true,
        hex_escapes: true,
        quote_chars: &['"', '\''],
        digit_separator: Some('_'),
    };

    /// The assumptions the lexical fallback makes when it does not know what
    /// language it is reading.
    ///
    /// Every field takes the least-committal value available, because a fallback
    /// that guesses grants rewrites a real parser would refuse: the exactness
    /// bound is JavaScript's rather than an unbounded one, and adjacent-literal
    /// concatenation and digit separators are off. `hex_escapes` is the one field
    /// set to `true` rather than `false`, and deliberately so: the fallback
    /// offers no string sites of its own, so that flag can only ever widen what a
    /// scan *reads back* — and a scanner that refused to decode an escape it was
    /// shown would lose real evidence to a technicality.
    pub const GENERIC: Dialect = Dialect {
        name: "generic",
        max_exact_integer: (1i128 << 53) - 1,
        integer_division_truncates: false,
        adjacent_strings: false,
        hex_escapes: true,
        quote_chars: &['"', '\''],
        digit_separator: None,
    };

    pub fn supports_exact(&self, v: i128) -> bool {
        v >= 0 && v <= self.max_exact_integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_and_ts_agree_because_they_share_a_runtime() {
        assert_eq!(Dialect::JS.max_exact_integer, Dialect::TS.max_exact_integer);
        assert_eq!(Dialect::JS.adjacent_strings, Dialect::TS.adjacent_strings);
    }

    #[test]
    fn the_exactness_bound_is_the_javascript_integer_limit() {
        // 2^53 - 1, not 2^53: the first integer a double cannot represent is
        // 2^53 + 1, but 2^53 itself is the first even-only value, so the bound
        // every reference uses is 2^53 - 1.
        assert_eq!(Dialect::JS.max_exact_integer, 9_007_199_254_740_991);
        assert!(Dialect::JS.supports_exact(Dialect::JS.max_exact_integer));
        assert!(!Dialect::JS.supports_exact(Dialect::JS.max_exact_integer + 1));
        assert!(!Dialect::JS.supports_exact(-1));
        assert!(Dialect::PY.supports_exact(i128::MAX));
    }
}
