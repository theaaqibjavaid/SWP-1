//! Language-agnostic watermark site vocabulary: what a location is, how wide a
//! tag is, and which equivalent-form family carried it.
//!
//! The protocol speaks in these terms; only `swp-adapters` knows how to turn
//! them into JavaScript or Python syntax.

use crate::error::{ErrorCode, SwpError};

/// Which slice of context identifies a site, and whether local names were
/// abstracted away.
///
/// Four keys are computed for every site and every one is stored in the private
/// manifest. A copy that was reformatted still matches the `*Id` keys; a copy
/// whose local names were rewritten still matches... both, because `*Id` keys
/// are name-insensitive; a copy where an ancestor function was extracted or
/// inlined can still match the statement-radius key. The detector counts a site
/// once however many of its four keys hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RadiusKind {
    /// Innermost enclosing statement/expression-statement, local names abstracted.
    StatementId,
    /// Innermost enclosing statement, local names preserved.
    StatementRaw,
    /// Enclosing function/class/module block, local names abstracted.
    ScopeId,
    /// Enclosing function/class/module block, local names preserved.
    ScopeRaw,
}

impl RadiusKind {
    /// Single byte used in the keyed derivation. Fixed forever: changing it
    /// changes every location id.
    pub fn code(self) -> u8 {
        match self {
            RadiusKind::StatementId => 0,
            RadiusKind::ScopeId => 1,
            RadiusKind::StatementRaw => 2,
            RadiusKind::ScopeRaw => 3,
        }
    }

    pub fn from_code(b: u8) -> Result<Self, SwpError> {
        Ok(match b {
            0 => RadiusKind::StatementId,
            1 => RadiusKind::ScopeId,
            2 => RadiusKind::StatementRaw,
            3 => RadiusKind::ScopeRaw,
            _ => {
                return Err(SwpError::invalid_manifest(format!(
                    "unknown radius kind code {b}"
                )))
            }
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RadiusKind::StatementId => "statement+identifiers",
            RadiusKind::StatementRaw => "statement+names",
            RadiusKind::ScopeId => "scope+identifiers",
            RadiusKind::ScopeRaw => "scope+names",
        }
    }

    /// Strongest first: the primary key of a site is its statement radius with
    /// names abstracted, because that is the one that survives the most
    /// ordinary refactoring while staying specific.
    pub fn all() -> [RadiusKind; 4] {
        [
            RadiusKind::StatementId,
            RadiusKind::ScopeId,
            RadiusKind::StatementRaw,
            RadiusKind::ScopeRaw,
        ]
    }
}

/// How many bits a site carries. Every site's tag is the low `width` bits of a
/// keyed HMAC, and an equivalent-form family must offer at least `2^width`
/// *distinct, non-canonical* renderings or the site is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(try_from = "u8")]
pub struct TagWidth(u8);

impl TagWidth {
    pub const MIN: u8 = 2;
    /// Eight bits per site is the protocol maximum: at that width almost no
    /// family has enough non-canonical renderings, and the added strength buys
    /// nothing a wider constellation does not already provide.
    pub const MAX: u8 = 8;
    pub const DEFAULT: TagWidth = TagWidth(4);

    pub fn new(bits: u8) -> Result<Self, SwpError> {
        if !(Self::MIN..=Self::MAX).contains(&bits) {
            return Err(SwpError::new(
                ErrorCode::Usage,
                format!(
                    "tag width must be between {} and {} bits, got {bits}",
                    Self::MIN,
                    Self::MAX
                ),
            ));
        }
        Ok(TagWidth(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether a raw bit count is usable, without constructing the value.
    pub fn is_supported(bits: u8) -> bool {
        (Self::MIN..=Self::MAX).contains(&bits)
    }

    pub fn modulus(self) -> u64 {
        1u64 << self.0
    }

    /// Upper bound on the probability that an innocent site in an unrelated
    /// project decodes to this site's expected tag, assuming the copier's
    /// choice of literal spelling is independent of the project key — which is
    /// exactly what the HMAC gives us. The full derivation is in
    /// docs/VALIDATION.md.
    pub fn null_hit_probability(self) -> f64 {
        // Exact power of two, so this is representable without rounding.
        (0.5f64).powi(self.0 as i32)
    }
}

impl std::convert::TryFrom<u8> for TagWidth {
    type Error = SwpError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        TagWidth::new(v)
    }
}

impl<'de> serde::Deserialize<'de> for TagWidth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u8::deserialize(d)?;
        TagWidth::new(v).map_err(serde::de::Error::custom)
    }
}

/// The value a watermark site encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SiteTag {
    pub value: u32,
    pub width: TagWidth,
}

impl SiteTag {
    pub fn new(value: u32, width: TagWidth) -> Self {
        SiteTag {
            value: value & ((1u32 << width.bits()) - 1),
            width,
        }
    }

    /// Does an observed form value agree with this tag?
    pub fn matches(&self, observed: u32) -> bool {
        self.value == (observed & ((1u32 << self.width.bits()) - 1))
    }
}

/// Which family of semantics-preserving renderings carried a site's bits.
/// Recorded in the manifest so a scan can dispatch to the right decoder, and so
/// `swp inspect` can explain what it embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(into = "&'static str")]
pub enum FormFamily {
    /// `(a + b)` where `a + b` equals the original value.
    Add,
    /// `(a - b)` where `a - b` equals the original value.
    Sub,
    /// `(a * b)` for a composite value with an exact factorization.
    Mul,
    /// A radix rendering whose digits carry the bits.
    Radix,
    /// `("abc" + "def")` where the split point carries the bits.
    StringConcat,
    /// Escaped code points whose low bits carry the tag.
    StringEscape,
    /// Adjacent literal concatenation `( "ab" "cd" )` (Python only).
    StringAdjacent,
}

impl FormFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            FormFamily::Add => "add",
            FormFamily::Sub => "sub",
            FormFamily::Mul => "mul",
            FormFamily::Radix => "radix",
            FormFamily::StringConcat => "str-concat",
            FormFamily::StringEscape => "str-escape",
            FormFamily::StringAdjacent => "str-adjacent",
        }
    }

    pub fn parse(s: &str) -> Result<Self, SwpError> {
        Ok(match s {
            "add" => FormFamily::Add,
            "sub" => FormFamily::Sub,
            "mul" => FormFamily::Mul,
            "radix" => FormFamily::Radix,
            "str-concat" => FormFamily::StringConcat,
            "str-escape" => FormFamily::StringEscape,
            "str-adjacent" => FormFamily::StringAdjacent,
            other => {
                return Err(SwpError::invalid_manifest(format!(
                    "unknown form family {other:?}"
                )))
            }
        })
    }

    /// Whether this family applies to a numeric or a string site.
    pub fn applies_to_numbers(self) -> bool {
        matches!(
            self,
            FormFamily::Add | FormFamily::Sub | FormFamily::Mul | FormFamily::Radix
        )
    }

    pub fn applies_to_strings(self) -> bool {
        matches!(
            self,
            FormFamily::StringConcat | FormFamily::StringEscape | FormFamily::StringAdjacent
        )
    }

    pub fn all() -> [FormFamily; 7] {
        [
            FormFamily::Add,
            FormFamily::Sub,
            FormFamily::Mul,
            FormFamily::Radix,
            FormFamily::StringConcat,
            FormFamily::StringEscape,
            FormFamily::StringAdjacent,
        ]
    }

    /// A family is only usable if it can render `2^bits` *distinct non-canonical*
    /// forms. This is a protocol-level sanity bound; the adapter proves the
    /// property per site by exhaustive round-trip tests.
    pub fn max_bits(self) -> u8 {
        match self {
            FormFamily::Add | FormFamily::Sub => 8,
            FormFamily::Mul => 6,
            FormFamily::Radix => 4,
            FormFamily::StringConcat => 6,
            FormFamily::StringEscape => 5,
            FormFamily::StringAdjacent => 5,
        }
    }
}

impl From<FormFamily> for &'static str {
    fn from(f: FormFamily) -> Self {
        f.as_str()
    }
}

impl<'de> serde::Deserialize<'de> for FormFamily {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        FormFamily::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The literal class a site rewrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiteralClass {
    Integer,
    String,
}

impl LiteralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            LiteralClass::Integer => "integer",
            LiteralClass::String => "string",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radius_codes_are_stable_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for k in RadiusKind::all() {
            assert!(seen.insert(k.code()), "duplicate radius code");
            assert_eq!(RadiusKind::from_code(k.code()).unwrap(), k);
        }
        assert_eq!(RadiusKind::StatementId.code(), 0);
        assert!(RadiusKind::from_code(9).is_err());
    }

    #[test]
    fn tag_width_bounds_are_enforced() {
        assert!(TagWidth::new(1).is_err());
        assert!(TagWidth::new(9).is_err());
        assert_eq!(TagWidth::new(4).unwrap().modulus(), 16);
        assert_eq!(
            TagWidth::new(8).unwrap().null_hit_probability(),
            1.0 / 256.0
        );
    }

    #[test]
    fn tags_mask_to_their_width() {
        let t = SiteTag::new(0xffff_0005, TagWidth::new(4).unwrap());
        assert_eq!(t.value, 5);
        assert!(t.matches(21)); // 21 & 0b1111 == 5
        assert!(!t.matches(6));
    }

    #[test]
    fn families_round_trip_through_their_protocol_names() {
        for f in FormFamily::all() {
            assert_eq!(FormFamily::parse(f.as_str()).unwrap(), f);
        }
        assert!(FormFamily::parse("quantum").is_err());
    }

    #[test]
    fn serde_round_trips_site_types() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct S {
            w: TagWidth,
            f: FormFamily,
            t: SiteTag,
        }
        let s = S {
            w: TagWidth::new(5).unwrap(),
            f: FormFamily::Mul,
            t: SiteTag::new(3, TagWidth::new(5).unwrap()),
        };
        let json = crate::cjson::encode(&s).unwrap();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"f":"mul","t":{"value":3,"width":5},"w":5}"#
        );
        let back: S = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, s);
        // A width outside the protocol is rejected on read, not clamped.
        assert!(
            serde_json::from_str::<S>(r#"{"w":99,"f":"mul","t":{"value":0,"width":4}}"#).is_err()
        );
    }
}
