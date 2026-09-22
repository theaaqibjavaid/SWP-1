//! Equivalent-form rendering and decoding.
//!
//! A watermark site is one literal spelling replaced by another that the
//! language evaluates to the same value, where the *choice among the equivalent
//! spellings* carries `bits` pseudorandom bits. This module owns that
//! substitution; it knows nothing about JavaScript or Python beyond what a
//! [`Dialect`] says.
//!
//! # The contract every family here satisfies
//!
//! 1. **Value preserving** — decoding a rendered form returns the original
//!    value. Exhaustively tested, per family, per width, per code.
//! 2. **Non-canonical** — the rendering is never the spelling the source
//!    started with, so a site that was not watermarked cannot accidentally
//!    "carry" a code from this encoder.
//! 3. **Complete or absent** — [`number_family_supports`] answers "can this
//!    family carry *every* code at this width for *this* value?". A family that
//!    can only reach some codes is refused outright rather than biased into,
//!    because a site whose reachable code set is a proper subset of the modulus
//!    is a site whose expected tag may be unrepresentable, and the evidence
//!    ladder cannot count a hit that could not have been embedded.
//! 4. **Uniform under a keyed tag** — the extracted code is compared against a
//!    value derived from the project key, so the innocent hit probability is
//!    `2^-bits` regardless of how authors actually spell things. That is the
//!    whole statistical argument of the protocol and it lives in
//!    `docs/VALIDATION.md`; what lives here is the mechanism it relies on.
//!
//! # What is deliberately absent
//!
//! Floating-point literals. `(0.03 + 0.02)` is not `0.05` in IEEE-754, and a
//! watermark that occasionally changes a computed value by one unit in the last
//! place is not semantics-preserving. Floats are therefore never sites, and the
//! safety analyzer reports why rather than failing silently.
//!
//! # The string families
//!
//! All three operate on the *source text between the quotes* rather than on the
//! decoded value, and all three refuse a literal containing a backslash or a
//! line break. That restriction is what makes them safe: with no escapes in the
//! text, the decoded content and the source text are the same string, so a
//! rendering is value-preserving by construction and the decoder cannot disagree
//! with the language's parser about where a character ends.

use swp_core::error::{ErrorCode, SwpError};
use swp_core::site::{FormFamily, TagWidth};

use crate::dialect::Dialect;

/// A decoded form: what it evaluates to, and the code it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    pub value: i128,
    pub code: u32,
}

/// Number of distinct codes a site of this width can carry.
fn modulus(width: TagWidth) -> u32 {
    width.modulus() as u32
}

/// The second operand used by the `+` and `-` families for a given code.
///
/// `1..=modulus`, never `0`: `(v + 0)` is the identity form, and allowing it
/// would make the canonical spelling reachable, which breaks property 2.
fn operand_for(code: u32, width: TagWidth) -> i128 {
    (code % modulus(width) + 1) as i128
}

/// Numeric families, in the order site selection should prefer them.
///
/// Ordered by how ordinary the resulting code looks, because a reviewer reading
/// a diff should see arithmetic that could plausibly have been written by hand:
/// addition and subtraction of small numbers first, then factorisations, then
/// radix spelling, which is the most visible of the set.
pub const NUMBER_FAMILIES: [FormFamily; 4] = [
    FormFamily::Add,
    FormFamily::Sub,
    FormFamily::Mul,
    FormFamily::Radix,
];

/// Numeric families only — [`string_family_supports`] and its neighbours handle
/// the string ones.
pub fn is_numeric(family: FormFamily) -> bool {
    matches!(
        family,
        FormFamily::Add | FormFamily::Sub | FormFamily::Mul | FormFamily::Radix
    )
}

/// Can this family encode every code at `width` for this value?
pub fn number_family_supports(
    value: i128,
    family: FormFamily,
    width: TagWidth,
    dialect: &Dialect,
) -> bool {
    let m = modulus(width);
    if !is_numeric(family) {
        return false;
    }
    if !dialect.supports_exact(value) {
        return false;
    }
    match family {
        // `v - b` must stay positive for the largest operand, so v > m.
        FormFamily::Add => value > m as i128,
        // The largest operand a code can select is `m`, so `v + m` must stay exact.
        FormFamily::Sub => value + m as i128 <= dialect.max_exact_integer,
        FormFamily::Mul => every_residue_has_a_divisor(value, m),
        FormFamily::Radix => hex_letter_count(value) >= width.bits() as usize,
        _ => false,
    }
}

/// Families available for one value, widest supported width first.
pub fn available_number_families(
    value: i128,
    width: TagWidth,
    dialect: &Dialect,
) -> Vec<FormFamily> {
    NUMBER_FAMILIES
        .into_iter()
        .filter(|f| is_numeric(*f))
        .filter(|f| number_family_supports(value, *f, width, dialect))
        .collect()
}

fn hex_letter_count(value: i128) -> usize {
    format!("{value:x}")
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .count()
}

/// Whether each residue `1..=m` has some divisor of `value` congruent to it.
///
/// Bounded by construction: `m <= 256`, and the scan stops after `8 * m`
/// candidates. Real constants with enough factorisation to carry a code at all
/// have small divisors — the residue classes are dense among the first few
/// hundred integers — and a value whose only covering divisors are larger than
/// the bound loses one family rather than producing a wrong answer. The search
/// may only ever *under*-report, and `render_number` re-checks per code, so a
/// too-optimistic answer is impossible.
fn every_residue_has_a_divisor(value: i128, m: u32) -> bool {
    if value < 2 {
        return false;
    }
    let mut covered = vec![false; m as usize];
    let mut remaining = m;
    let limit = 8i128 * m as i128;
    let mut d = 2i128;
    while d <= value / 2 && d <= limit {
        if value % d == 0 {
            let other = value / d;
            // Both `d * (value/d)` and `(value/d) * d` are legal renderings, so
            // either factor may serve as the operand carrying the code.
            for candidate in [d, other] {
                if candidate < 2 || candidate > value / 2 {
                    continue;
                }
                let r = (candidate % m as i128) as usize;
                if !covered[r] {
                    covered[r] = true;
                    remaining -= 1;
                    if remaining == 0 {
                        return true;
                    }
                }
            }
        }
        d += 1;
    }
    remaining == 0
}

/// Render `value` as a form carrying `code`.
pub fn render_number(
    value: i128,
    family: FormFamily,
    code: u32,
    width: TagWidth,
    dialect: &Dialect,
) -> Result<String, SwpError> {
    if !is_numeric(family) {
        return Err(SwpError::new(
            ErrorCode::UnsafeEmbedding,
            format!("{} is not a numeric form family", family.as_str()),
        ));
    }
    if !number_family_supports(value, family, width, dialect) {
        return Err(SwpError::new(
            ErrorCode::UnsafeEmbedding,
            format!(
                "{} cannot carry a {}-bit code for {value}, so this site is not usable",
                family.as_str(),
                width.bits()
            ),
        ));
    }
    let b = operand_for(code, width);
    let out = match family {
        FormFamily::Add => format!("({} + {b})", value - b),
        FormFamily::Sub => format!("({} - {b})", value + b),
        FormFamily::Mul => {
            let m = modulus(width);
            let want = b.rem_euclid(m as i128);
            let operand = mul_operand(value, m, want)?;
            format!("({} * {operand})", value / operand)
        }
        FormFamily::Radix => render_radix(value, code, width),
        other => {
            return Err(SwpError::new(
                ErrorCode::UnsafeEmbedding,
                format!("{} is not a numeric form family", other.as_str()),
            ))
        }
    };
    // Property 2, checked rather than argued: a rendering that came out looking
    // like the plain decimal would carry no bits at all.
    if out == format!("{value}") {
        return Err(SwpError::new(
            ErrorCode::UnsafeEmbedding,
            "the rendered form is identical to the original literal",
        ));
    }
    Ok(out)
}

fn mul_operand(value: i128, m: u32, want: i128) -> Result<i128, SwpError> {
    let mut d = 2i128;
    // The same bound `every_residue_has_a_divisor` used to decide the family is
    // available, so a site that was accepted is always one that can be rendered.
    let limit = 8i128 * m as i128;
    while d <= value / 2 && d <= limit {
        if value % d == 0 && d.rem_euclid(m as i128) == want {
            return Ok(d);
        }
        if value % d == 0 {
            let other = value / d;
            if other >= 2 && other <= value / 2 && other.rem_euclid(m as i128) == want {
                return Ok(other);
            }
        }
        d += 1;
    }
    Err(SwpError::new(
        ErrorCode::UnsafeEmbedding,
        format!("no factorisation of {value} carries the requested code"),
    ))
}

/// Hex spelling whose letter case carries the code, most significant bit first.
fn render_radix(value: i128, code: u32, width: TagWidth) -> String {
    let digits = format!("{value:x}");
    let bits = width.bits() as usize;
    let letters: Vec<usize> = digits
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .collect();
    // The last `bits` letters carry the pattern; earlier ones stay canonical so
    // a reader sees a normal hex constant rather than a case anomaly at each
    // digit. `number_family_supports` guarantees enough letters exist.
    let chosen = &letters[letters.len() - bits..];
    let mut out = String::with_capacity(digits.len() + 2);
    out.push_str("0x");
    for (i, c) in digits.char_indices() {
        let set = match chosen.iter().position(|&p| p == i) {
            Some(j) => (code >> (bits - 1 - j)) & 1 == 1,
            None => false,
        };
        out.push(if set { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// Decode a rendered form. `None` means "this text is not a form of this
/// family", which is the ordinary answer for most source.
pub fn decode_number(text: &str, family: FormFamily, width: TagWidth) -> Option<Decoded> {
    match family {
        FormFamily::Add => decode_binary(text, '+').map(|(a, b)| Decoded {
            value: a + b,
            code: code_of(b, width),
        }),
        FormFamily::Sub => decode_binary(text, '-').map(|(a, b)| Decoded {
            value: a - b,
            code: code_of(b, width),
        }),
        FormFamily::Mul => decode_binary(text, '*').map(|(a, b)| Decoded {
            value: a * b,
            code: code_of(b, width),
        }),
        FormFamily::Radix => decode_radix(text, width),
        _ => None,
    }
}

/// Invert a renderer's `1..=modulus` operand into the code it was chosen for.
/// Used by both the numeric and the string families, which pick operands the
/// same way.
fn code_of(operand: i128, width: TagWidth) -> u32 {
    (operand - 1).rem_euclid(modulus(width) as i128) as u32
}

/// `(a OP b)` with optional surrounding whitespace, nothing else inside.
///
/// Deliberately strict. A looser parser would accept source nobody wrote, and
/// every extra accepted shape is another way an innocent expression can be
/// mistaken for a watermark.
fn decode_binary(text: &str, op: char) -> Option<(i128, i128)> {
    let inner = text.trim().strip_prefix('(')?.trim();
    let inner = inner.strip_suffix(')')?.trim();
    let (left, right) = inner.split_once(op)?;
    // An operator appearing twice means this is not the shape we rendered, and
    // splitting it anyway would produce a confident wrong answer.
    if right.contains(op) || left.contains(op) {
        return None;
    }
    let a: i128 = left.trim().parse().ok()?;
    let b: i128 = right.trim().parse().ok()?;
    if a < 0 || b < 0 {
        return None;
    }
    Some((a, b))
}

fn decode_radix(text: &str, width: TagWidth) -> Option<Decoded> {
    let trimmed = text.trim();
    let rest = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let value = i128::from_str_radix(&rest.to_ascii_lowercase(), 16).ok()?;
    let bits = width.bits() as usize;
    let letters: Vec<usize> = rest
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .collect();
    // Fewer letters than bits is not a form this encoder produced: refuse it,
    // rather than reporting a code from a partial pattern whose hit probability
    // is higher than the width claims.
    if letters.len() < bits {
        return None;
    }
    let chosen = &letters[letters.len() - bits..];
    let mut code = 0u32;
    for &pos in chosen {
        let is_upper = rest[pos..].chars().next()?.is_ascii_uppercase();
        code = (code << 1) | is_upper as u32;
    }
    Some(Decoded { value, code })
}

/// A string literal the form engine may rewrite: the source text between the
/// quotes, and the quote character that opened it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringForm<'a> {
    pub inner: &'a str,
    pub quote: char,
}

/// A decoded string form: content, the code it carries, and the quote style it
/// was written with, which the scanner needs to compare against the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedString {
    pub inner: String,
    pub code: u32,
    pub quote: char,
}

pub const STRING_FAMILIES: [FormFamily; 3] = [
    FormFamily::StringConcat,
    FormFamily::StringEscape,
    FormFamily::StringAdjacent,
];

/// The split index a code selects, `1..=modulus` so the unsplit literal is never
/// reachable.
fn split_for(code: u32, width: TagWidth) -> usize {
    (code % modulus(width) + 1) as usize
}

impl<'a> StringForm<'a> {
    /// Whether this literal is one the engine will touch at all.
    ///
    /// A backslash means the source text and the decoded value differ, and a
    /// line break means the literal spans lines — a template literal, a
    /// triple-quoted string, or a line continuation. Rewriting either on the
    /// assumption that text equals value is exactly the kind of subtle behavior
    /// change this protocol is not allowed to make, so both are refused here
    /// and reported by the safety analyzer.
    pub fn is_rewrite_safe(&self) -> bool {
        !self.inner.is_empty()
            && !self.inner.contains('\\')
            && !self.inner.contains('\n')
            && !self.inner.contains('\r')
            && !self.inner.contains(self.quote)
    }

    fn char_count(&self) -> usize {
        self.inner.chars().count()
    }
}

/// Can this string family encode every code at `width`?
pub fn string_family_supports(
    site: &StringForm,
    family: FormFamily,
    width: TagWidth,
    dialect: &Dialect,
) -> bool {
    if !STRING_FAMILIES.contains(&family) || !site.is_rewrite_safe() {
        return false;
    }
    let m = modulus(width) as usize;
    match family {
        // Split points are the capacity: a literal of `n` characters has `n - 1`
        // of them that leave both pieces non-empty, and the codes need `m`.
        FormFamily::StringConcat => site.char_count() > m,
        FormFamily::StringAdjacent => dialect.adjacent_strings && site.char_count() > m,
        FormFamily::StringEscape => {
            dialect.hex_escapes
                && site.char_count() >= m
                && site.inner.chars().take(m).all(|c| (c as u32) <= 0xff)
        }
        _ => false,
    }
}

/// Families available for one string, in preference order.
pub fn available_string_families(
    site: &StringForm,
    width: TagWidth,
    dialect: &Dialect,
) -> Vec<FormFamily> {
    STRING_FAMILIES
        .into_iter()
        .filter(|f| string_family_supports(site, *f, width, dialect))
        .collect()
}

pub fn render_string(
    site: &StringForm,
    family: FormFamily,
    code: u32,
    width: TagWidth,
    dialect: &Dialect,
) -> Result<String, SwpError> {
    if !string_family_supports(site, family, width, dialect) {
        return Err(SwpError::new(
            ErrorCode::UnsafeEmbedding,
            format!(
                "{} cannot carry a {}-bit code for {:?}, so this site is not usable",
                family.as_str(),
                width.bits(),
                site.inner
            ),
        ));
    }
    let q = site.quote;
    let out = match family {
        FormFamily::StringConcat | FormFamily::StringAdjacent => {
            let (left, right) = split_inner(site, split_for(code, width));
            let joiner = if family == FormFamily::StringConcat {
                " + "
            } else {
                " "
            };
            format!("({q}{left}{q}{joiner}{q}{right}{q})")
        }
        FormFamily::StringEscape => {
            let count = split_for(code, width);
            let mut escaped = String::new();
            for ch in site.inner.chars().take(count) {
                escaped.push_str(&format!("\\x{:02x}", ch as u32));
            }
            let tail: String = site.inner.chars().skip(count).collect();
            format!("{q}{escaped}{tail}{q}")
        }
        other => {
            return Err(SwpError::new(
                ErrorCode::UnsafeEmbedding,
                format!("{} is not a string form family", other.as_str()),
            ))
        }
    };
    if out == format!("{q}{}{q}", site.inner) {
        return Err(SwpError::new(
            ErrorCode::UnsafeEmbedding,
            "the rendered form is identical to the original literal",
        ));
    }
    Ok(out)
}

fn split_inner<'a>(site: &StringForm<'a>, at: usize) -> (&'a str, &'a str) {
    let byte = site
        .inner
        .char_indices()
        .nth(at)
        .map(|(i, _)| i)
        .unwrap_or(site.inner.len());
    site.inner.split_at(byte)
}

/// Recognise a rendered string form.
///
/// As strict as [`decode_number`] on purpose: every extra accepted shape is one
/// more way an innocent literal is mistaken for a watermark, and a form the
/// scanner cannot recognise is a form the encoder must not produce.
pub fn decode_string(
    text: &str,
    family: FormFamily,
    width: TagWidth,
    dialect: &Dialect,
) -> Option<DecodedString> {
    match family {
        FormFamily::StringConcat => decode_pieces(text, width, Joiner::Plus),
        FormFamily::StringAdjacent if dialect.adjacent_strings => {
            decode_pieces(text, width, Joiner::Space)
        }
        FormFamily::StringAdjacent => None,
        FormFamily::StringEscape if dialect.hex_escapes => decode_escaped(text, width),
        FormFamily::StringEscape => None,
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Joiner {
    Plus,
    Space,
}

/// Read one quoted literal from the front of `text`, returning its quote
/// character, its source text, and whatever follows the closing quote.
fn read_quoted(text: &str) -> Option<(char, &str, &str)> {
    let bytes = text.as_bytes();
    let quote = match *bytes.first()? {
        b'"' => '"',
        b'\'' => '\'',
        _ => return None,
    };
    // Only ASCII bytes are compared, so a multi-byte character is stepped over
    // one continuation byte at a time and every slice boundary stays on a char
    // boundary.
    for (i, b) in bytes.iter().enumerate().skip(1) {
        match b {
            b'\\' | b'\n' | b'\r' => return None,
            q if *q == quote as u8 => {
                let (inner, rest) = text.split_at(i);
                return Some((quote, &inner[quote.len_utf8()..], &rest[1..]));
            }
            _ => {}
        }
    }
    None
}

fn strip_outer_parens(text: &str) -> Option<&str> {
    let t = text.trim();
    let inner = t.strip_prefix('(')?.trim_end();
    Some(inner.strip_suffix(')')?.trim())
}

/// `("left" + "right")` or `"left" "right"`, both wrapped in the parentheses the
/// renderer emits.
fn decode_pieces(text: &str, width: TagWidth, joiner: Joiner) -> Option<DecodedString> {
    let body = strip_outer_parens(text)?;
    let (q1, left, rest) = read_quoted(body)?;
    let after = match joiner {
        Joiner::Plus => rest.trim_start().strip_prefix('+')?,
        // The renderer separates the two literals by exactly the joiner, so a
        // piece that runs straight into the next quote is not our shape.
        Joiner::Space if rest.starts_with(' ') || rest.starts_with('\t') => rest,
        Joiner::Space => return None,
    };
    let (q2, right, tail) = read_quoted(after.trim_start())?;
    if q1 != q2 || !tail.trim().is_empty() {
        return None;
    }
    // The renderer never writes an empty piece: a split index of 0 would carry
    // no bits and one past the end would be a literal the reader can delete.
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some(DecodedString {
        inner: format!("{left}{right}"),
        code: code_of(left.chars().count() as i128, width),
        quote: q1,
    })
}

/// Count the leading `\xHH` escapes; the count selects the code.
fn decode_escaped(text: &str, width: TagWidth) -> Option<DecodedString> {
    let trimmed = text.trim();
    let quote = trimmed.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        return None;
    }
    let body = trimmed.strip_prefix(quote)?.strip_suffix(quote)?;
    let mut inner = String::new();
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    let mut escapes = 0u32;
    let mut seen_plain = false;
    while i < chars.len() {
        if chars[i] == '\\' && i + 3 < chars.len() && chars[i + 1] == 'x' {
            if seen_plain {
                // The renderer escapes a prefix of the literal, so ordinary text
                // followed by an escape is not a form it produced.
                return None;
            }
            let hex: String = chars[i + 2..i + 4].iter().collect();
            let byte = u8::from_str_radix(&hex, 16).ok()?;
            inner.push(byte as char);
            i += 4;
            escapes += 1;
            continue;
        }
        if chars[i] == '\\' {
            return None;
        }
        seen_plain = true;
        inner.push(chars[i]);
        i += 1;
    }
    if escapes == 0 {
        return None;
    }
    Some(DecodedString {
        inner,
        code: code_of(escapes as i128, width),
        quote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seventeen_character_string_is_the_shortest_that_carries_four_bits() {
        // The concat family's capacity is its split points, and both pieces have
        // to be non-empty, so length and width are directly related: 16 bits of
        // code need split points 1..=16, and the 16th only exists in a literal of
        // 17 characters or more.
        let w4 = TagWidth::DEFAULT;
        let short = StringForm {
            inner: "1234567890123456",
            quote: '"',
        };
        let long = StringForm {
            inner: "12345678901234567",
            quote: '"',
        };
        assert!(!string_family_supports(
            &short,
            FormFamily::StringConcat,
            w4,
            &Dialect::JS
        ));
        assert!(string_family_supports(
            &long,
            FormFamily::StringConcat,
            w4,
            &Dialect::JS
        ));
    }

    #[test]
    fn string_forms_round_trip_exhaustively() {
        let samples = [
            "the-quick-brown-fox-jumps",
            "0123456789abcdef0123456789abcdef",
            "a really long user-facing error message about a missing file",
            // A `+` inside the text is the case a naive `split_once('+')` gets
            // wrong, and the wide characters make byte-vs-char indexing matter.
            "error: x + y is not a valid Ω ≈ 1.0 calibration for station-keepers",
        ];
        for dialect in [Dialect::JS, Dialect::PY] {
            for width in widths() {
                for inner in samples {
                    for &quote in dialect.quote_chars {
                        let site = StringForm { inner, quote };
                        for family in STRING_FAMILIES {
                            if !dialect.adjacent_strings && family == FormFamily::StringAdjacent {
                                continue;
                            }
                            let supported = string_family_supports(&site, family, width, &dialect);
                            let mut codes = Vec::new();
                            for code in 0..modulus(width) {
                                let Ok(rendered) =
                                    render_string(&site, family, code, width, &dialect)
                                else {
                                    continue;
                                };
                                assert!(supported, "rendered {family:?} for an unsupported site");
                                assert_ne!(
                                    rendered,
                                    format!("{quote}{inner}{quote}"),
                                    "canonical form leaked"
                                );
                                let back = decode_string(&rendered, family, width, &dialect)
                                    .unwrap_or_else(|| {
                                        panic!("cannot decode {rendered} ({family:?})")
                                    });
                                assert_eq!(back.inner, inner, "content changed");
                                assert_eq!(back.quote, quote, "quote style changed");
                                assert_eq!(back.code, code, "wrong code from {rendered}");
                                codes.push(code);
                            }
                            assert_eq!(
                                codes.len(),
                                if supported {
                                    modulus(width) as usize
                                } else {
                                    0
                                },
                                "{family:?} of {inner:?} at {} bits: {} of {} codes reachable",
                                width.bits(),
                                codes.len(),
                                modulus(width)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn strings_with_escapes_or_line_breaks_are_never_offered() {
        for family in STRING_FAMILIES {
            let backslash = StringForm {
                inner: r"line one\nline two and more characters here",
                quote: '"',
            };
            let newline = StringForm {
                inner: "line one\nline two and more characters here",
                quote: '"',
            };
            let empty = StringForm {
                inner: "",
                quote: '"',
            };
            for site in [&backslash, &newline, &empty] {
                assert!(
                    !string_family_supports(site, family, TagWidth::DEFAULT, &Dialect::PY),
                    "{family:?} was offered for an unsafe string literal"
                );
            }
        }
    }

    #[test]
    fn string_decoding_refuses_foreign_shapes() {
        let d = Dialect::JS;
        let w = TagWidth::DEFAULT;
        assert_eq!(
            decode_string("\"abcd\"", FormFamily::StringConcat, w, &d),
            None
        );
        assert_eq!(
            decode_string("(\"ab\" + \"cd\")", FormFamily::StringAdjacent, w, &d),
            None
        );
        assert_eq!(
            decode_string("(\"ab\" - \"cd\")", FormFamily::StringConcat, w, &d),
            None
        );
        // Three pieces is not the shape this encoder produces.
        assert_eq!(
            decode_string("(\"a\" + \"b\" + \"c\")", FormFamily::StringConcat, w, &d),
            None
        );
        // Neither is an empty piece, which carries no bits.
        assert_eq!(
            decode_string("(\"\" + \"abcd\")", FormFamily::StringConcat, w, &d),
            None
        );
        // Nor a closing quote that never opens a second literal.
        assert_eq!(
            decode_string("(\"abcd\")", FormFamily::StringConcat, w, &d),
            None
        );
        assert_eq!(
            decode_string("('a' + 'b')", FormFamily::StringConcat, w, &d)
                .map(|s| (s.inner, s.quote, s.code)),
            Some(("ab".to_string(), '\'', 0))
        );
        // A `+` that belongs to the text rather than to the operator is not
        // mistaken for the split: this decodes to the full literal, whose five
        // leading left-side characters carry code 4.
        assert_eq!(
            decode_string("(\"x + y\" + \"z\")", FormFamily::StringConcat, w, &d)
                .map(|s| (s.inner, s.code)),
            Some(("x + yz".to_string(), 4))
        );
        assert_eq!(
            decode_string("\"a\\nb\"", FormFamily::StringConcat, w, &d),
            None
        );
        // An escape family form whose escapes are not a prefix is foreign.
        assert_eq!(
            decode_string("\"ab\\x63d\"", FormFamily::StringEscape, w, &d),
            None
        );
    }

    #[test]
    fn adjacent_strings_are_python_only() {
        assert!(!string_family_supports(
            &StringForm {
                inner: "a very long piece of text",
                quote: '"'
            },
            FormFamily::StringAdjacent,
            TagWidth::DEFAULT,
            &Dialect::JS
        ));
        assert!(string_family_supports(
            &StringForm {
                inner: "a very long piece of text",
                quote: '"'
            },
            FormFamily::StringAdjacent,
            TagWidth::DEFAULT,
            &Dialect::PY
        ));
    }

    /// A dialect that has no `\xHH` escapes must not be offered the family, and
    /// must not decode it either — the writer and the reader are gated by the
    /// same one piece of data, so a language cannot end up with fragments its
    /// scanner was never willing to look for.
    #[test]
    fn a_dialect_without_hex_escapes_never_sees_the_escape_family() {
        let d = Dialect {
            name: "no-escapes",
            hex_escapes: false,
            ..Dialect::JS
        };
        let site = StringForm {
            inner: "a very long piece of text",
            quote: '"',
        };
        assert!(string_family_supports(
            &site,
            FormFamily::StringEscape,
            TagWidth::DEFAULT,
            &Dialect::JS
        ));
        assert!(!string_family_supports(
            &site,
            FormFamily::StringEscape,
            TagWidth::DEFAULT,
            &d
        ));
        let rendered = render_string(
            &site,
            FormFamily::StringEscape,
            3,
            TagWidth::DEFAULT,
            &Dialect::JS,
        )
        .expect("JavaScript does have \\xHH");
        assert_eq!(
            decode_string(&rendered, FormFamily::StringEscape, TagWidth::DEFAULT, &d),
            None
        );
        assert!(decode_string(
            &rendered,
            FormFamily::StringEscape,
            TagWidth::DEFAULT,
            &Dialect::JS
        )
        .is_some());
    }

    #[test]
    fn escaping_only_covers_characters_a_single_escape_can_name() {
        // Beyond U+00FF, `\xHH` cannot express the character at all, so the
        // family has to refuse the site rather than produce broken source.
        let wide = StringForm {
            inner: "\u{30c6}\u{30b9}\u{30c8}\u{30ab}\u{30e9}\u{30fc}\u{30c8}\u{30fb}\u{30c6}\u{30b9}\u{30c8}\u{30ab}\u{30e9}\u{30fc}\u{30c8}\u{30fb}\u{30c6}",
            quote: '"',
        };
        assert!(!string_family_supports(
            &wide,
            FormFamily::StringEscape,
            TagWidth::DEFAULT,
            &Dialect::PY
        ));
        assert!(string_family_supports(
            &wide,
            FormFamily::StringConcat,
            TagWidth::DEFAULT,
            &Dialect::PY
        ));
    }

    fn widths() -> Vec<TagWidth> {
        (TagWidth::MIN..=TagWidth::MAX)
            .filter_map(|b| TagWidth::new(b).ok())
            .collect()
    }

    /// Values chosen to cover the interesting cases: small, large, prime,
    /// highly composite, hex with many letters, and at the exactness boundary.
    fn probe_values() -> Vec<i128> {
        vec![
            1,
            2,
            17,
            51,
            100,
            128,
            240,
            255,
            360,
            1000,
            4096,
            65535,
            8080,
            2_147_483_647,
            0xdead_beef,
            0x0a1b_c3d4_e5f6_0a0b,
        ]
    }

    #[test]
    fn every_supported_family_round_trips_at_every_code() {
        for dialect in [Dialect::JS, Dialect::PY] {
            for width in widths() {
                for &value in &probe_values() {
                    for family in NUMBER_FAMILIES.iter().filter(|f| is_numeric(**f)) {
                        if !number_family_supports(value, *family, width, &dialect) {
                            continue;
                        }
                        for code in 0..modulus(width) {
                            let rendered = render_number(value, *family, code, width, &dialect)
                                .unwrap_or_else(|e| panic!("{family:?} {value} code {code}: {e}"));
                            assert_ne!(rendered, format!("{value}"), "canonical form leaked");
                            let back = decode_number(&rendered, *family, width)
                                .unwrap_or_else(|| panic!("cannot decode {rendered}"));
                            assert_eq!(back.value, value, "value changed in {rendered}");
                            assert_eq!(back.code, code, "wrong code from {rendered}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_rejected_family_is_rejected_for_every_code_not_just_some() {
        // Property 3: partial coverage is impossible by construction, because
        // support is decided before any code is chosen.
        for dialect in [Dialect::JS, Dialect::PY] {
            for width in widths() {
                for &value in &probe_values() {
                    for family in NUMBER_FAMILIES.iter().filter(|f| is_numeric(**f)) {
                        let supported = number_family_supports(value, *family, width, &dialect);
                        let reachable: u32 = (0..modulus(width))
                            .filter(|code| {
                                render_number(value, *family, *code, width, &dialect).is_ok()
                            })
                            .count() as u32;
                        assert_eq!(
                            reachable,
                            if supported { modulus(width) } else { 0 },
                            "{family:?} of {value} at {} bits claims supported={supported} \
                             but rendered {reachable}/{} codes",
                            width.bits(),
                            modulus(width)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn floats_and_huge_integers_are_never_sites() {
        // The exactness bound is a real constraint in JavaScript, not a formality.
        let huge = Dialect::JS.max_exact_integer + 1;
        for family in NUMBER_FAMILIES.iter().filter(|f| is_numeric(**f)) {
            assert!(!number_family_supports(
                huge,
                *family,
                TagWidth::DEFAULT,
                &Dialect::JS
            ));
            // Python's integers are unbounded, so the same value is fine there.
            assert!(
                number_family_supports(huge, *family, TagWidth::DEFAULT, &Dialect::PY)
                    || matches!(family, FormFamily::Mul | FormFamily::Radix),
                "python should accept {family:?} for a large integer"
            );
        }
        assert!(!number_family_supports(
            -255,
            FormFamily::Add,
            TagWidth::DEFAULT,
            &Dialect::PY
        ));
    }

    #[test]
    fn decoding_is_strict_about_shapes_it_did_not_render() {
        let w = TagWidth::DEFAULT;
        assert_eq!(decode_number("255", FormFamily::Add, w), None);
        assert_eq!(decode_number("(1 + 2 + 3)", FormFamily::Add, w), None);
        assert_eq!(decode_number("(1 - 2)", FormFamily::Add, w), None);
        assert_eq!(decode_number("(a + b)", FormFamily::Add, w), None);
        assert_eq!(
            decode_number("(1+2)", FormFamily::Add, w).map(|d| d.value),
            Some(3)
        );
        // A radix spelling too short to carry the width is not evidence.
        assert_eq!(decode_number("0xff", FormFamily::Radix, w), None);
        assert!(decode_number("0xdeadbeef", FormFamily::Radix, w).is_some());
    }

    #[test]
    fn mul_needs_a_divisor_in_every_residue_class() {
        let w4 = TagWidth::new(4).unwrap();
        // 240 = 2^4 * 3 * 5 has many divisors but none congruent to 1, 7, 9, 11
        // or 13 modulo 16, so it cannot carry an arbitrary 4-bit code.
        assert!(!number_family_supports(
            240,
            FormFamily::Mul,
            w4,
            &Dialect::PY
        ));
        // A number with divisors spread across all classes does. 720720 =
        // 2^4 * 3^2 * 5 * 7 * 11 * 13, and each residue mod 16 has a divisor in
        // it (16 for 0, 33 for 1, 4 for 4, 12 for 12, and so on).
        assert!(number_family_supports(
            720_720,
            FormFamily::Mul,
            w4,
            &Dialect::PY
        ));
        // 510510 has a single factor of two, so no divisor is 0, 4, 8 or 12
        // modulo 16 and four codes are unreachable: the family is refused.
        assert!(!number_family_supports(
            510_510,
            FormFamily::Mul,
            w4,
            &Dialect::PY
        ));
        // At two bits everything composite works.
        assert!(number_family_supports(
            240,
            FormFamily::Mul,
            TagWidth::new(2).unwrap(),
            &Dialect::PY
        ));
    }

    #[test]
    fn radix_needs_enough_letters() {
        let w4 = TagWidth::new(4).unwrap();
        assert!(!number_family_supports(
            0xff,
            FormFamily::Radix,
            w4,
            &Dialect::PY
        ));
        assert!(number_family_supports(
            0xabcd,
            FormFamily::Radix,
            w4,
            &Dialect::PY
        ));
        // 0b1010 across the four letters `abcd`, most significant bit first.
        assert_eq!(
            render_number(0xabcd, FormFamily::Radix, 0b1010, w4, &Dialect::PY).unwrap(),
            "0xAbCd"
        );
        assert_eq!(
            decode_number("0xAbCd", FormFamily::Radix, w4).unwrap(),
            Decoded {
                value: 0xabcd,
                code: 0b1010
            }
        );
    }

    #[test]
    fn an_unsupported_site_reports_why_rather_than_panicking() {
        let e = render_number(3, FormFamily::Add, 0, TagWidth::DEFAULT, &Dialect::JS).unwrap_err();
        assert_eq!(e.code(), ErrorCode::UnsafeEmbedding);
        assert!(e.render().contains("add"), "{}", e.render());
        let e2 = render_number(
            255,
            FormFamily::StringConcat,
            0,
            TagWidth::DEFAULT,
            &Dialect::JS,
        )
        .unwrap_err();
        assert!(
            e2.render().contains("not a numeric form"),
            "{}",
            e2.render()
        );
    }

    #[test]
    fn available_families_match_the_support_predicate() {
        for dialect in [Dialect::JS, Dialect::TS, Dialect::PY] {
            for &value in &probe_values() {
                let got = available_number_families(value, TagWidth::DEFAULT, &dialect);
                for family in NUMBER_FAMILIES {
                    assert_eq!(
                        got.contains(&family),
                        number_family_supports(value, family, TagWidth::DEFAULT, &dialect),
                        "{family:?} disagrees for {value}"
                    );
                }
                // The two arithmetic families are the ones that carry almost
                // every site, so their rule is asserted directly rather than
                // only through the predicate that implements it.
                let m = modulus(TagWidth::DEFAULT) as i128;
                assert_eq!(
                    got.contains(&FormFamily::Add),
                    value > m && dialect.supports_exact(value),
                    "add availability wrong for {value}"
                );
                assert_eq!(
                    got.contains(&FormFamily::Sub),
                    value + m <= dialect.max_exact_integer,
                    "sub availability wrong for {value}"
                );
            }
        }
    }
}
