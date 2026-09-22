//! The adapter interface, and the registry that chooses one.
//!
//! The brief names nine operations — identify, parse, canonicalize, analyze,
//! find candidate locations, embed, extract features, detect, validate. They are
//! here, grouped where the data makes them fall out: `analyze` is parse plus
//! canonicalization input plus candidate locations, because a language cannot
//! find safe literal sites without having parsed the file, and splitting those
//! into three calls would let a caller pair the results of two different parses.
//!
//! ## What the trait is for
//!
//! It is the seam that keeps the protocol language-independent. Everything above
//! this file — site selection, keyed tags, canonical text, evidence, reports —
//! consumes [`Analysis`], [`swp_core::canon::Token`] and [`FormFamily`] and never
//! inspects a spelling. Adding a language is implementing this trait plus a
//! [`crate::ts::Grammar`] table, not editing a `match`.
//!
//! ## Validation is not optional
//!
//! [`LanguageAdapter::validate`] re-parses the watermarked file and proves three
//! things about every embedded site: the code around it canonicalizes identically
//! before and after at L1, L2 and L3; the new spelling decodes back to the
//! original value; and the code it carries is the one requested. A transformation
//! that cannot pass that check is not a bug to be found later — it is a silent
//! behavior change, which is the one thing a watermark must never do.

use std::path::Path;

use swp_core::canon::{ByteSpan, CanonLevel, CanonicalText, Token};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::limits::Limits;
use swp_core::site::{FormFamily, TagWidth};

use crate::analyze::{Analysis, Capabilities};
use crate::generic::GenericAdapter;
use crate::js::{JAVASCRIPT, TYPESCRIPT};
use crate::literal::{self, DecodedSite};
use crate::py::PYTHON;
use crate::ts;

/// One embedding the protocol asked for, and where it ended up.
///
/// [`Edit::rendered`] is filled in by the caller that splices the text, because
/// only that pass knows how earlier edits shifted later offsets. The validator
/// needs it: without the post-embedding span there is no way to point the
/// canonicalizer at the site in the new file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// Index into the analysis' site list the value was taken from.
    pub site: usize,
    /// The literal as it was.
    pub original: ByteSpan,
    /// The equivalent spelling that replaces it.
    pub rendering: String,
    pub family: FormFamily,
    pub code: u32,
    pub width: TagWidth,
    /// Filled while applying: where the rendering landed.
    pub rendered: Option<ByteSpan>,
}

impl Edit {
    pub fn new(
        site: usize,
        original: ByteSpan,
        rendering: String,
        family: FormFamily,
        code: u32,
        width: TagWidth,
    ) -> Edit {
        Edit {
            site,
            original,
            rendering,
            family,
            code,
            width,
            rendered: None,
        }
    }

    /// The value this edit was supposed to preserve, as the report prints it.
    pub fn span(&self) -> ByteSpan {
        self.rendered.unwrap_or(self.original)
    }

    /// Record where the rendering landed, once the splicing pass knows.
    pub fn with_rendered(mut self, rendered: ByteSpan) -> Edit {
        self.rendered = Some(rendered);
        self
    }
}

/// Proof that an embedding did not change what the code means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// Sites whose rendering decoded back to the original value.
    pub sites_verified: u32,
    /// How many canonical levels were unchanged around every site: 3 means L1,
    /// L2 and L3 all held.
    pub levels_stable: u8,
    /// Parse errors in the watermarked file, which must not exceed the original's.
    pub parse_errors: u32,
}

impl Proof {
    /// Whether the proof is complete: every site checked, every level stable, and
    /// the file no less parseable than before.
    pub fn is_complete(&self, sites: u32, before_errors: u32) -> bool {
        self.sites_verified == sites
            && self.levels_stable == ALL_LEVELS
            && self.parse_errors <= before_errors
    }
}

/// [`CanonLevel`] count the protocol requires an embedding to preserve.
pub const ALL_LEVELS: u8 = 3;

/// A language SWP-1 can analyze.
pub trait LanguageAdapter: Send + Sync {
    /// Stable identifier, recorded in manifests and reports. Never renamed: it
    /// is part of what a release stores.
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> Capabilities;

    /// Whether this adapter is the one for this file.
    fn identifies(&self, path: &Path) -> bool {
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            return false;
        };
        self.extensions()
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    }

    /// File extensions claimed, lowercase, without the dot.
    fn extensions(&self) -> &'static [&'static str];

    /// Parse the file, classify every literal, and record the radii.
    fn analyze(&self, source: &str, limits: &Limits) -> Result<Analysis, SwpError>;

    /// Canonical text for an analysis at one level, with one site hidden.
    ///
    /// A default method, not a per-language one: if an adapter could choose its
    /// own canonicalization, two languages would drift apart and the location ids
    /// would stop meaning the same thing.
    fn canonicalize(
        &self,
        tokens: &[Token],
        level: CanonLevel,
        site: Option<ByteSpan>,
    ) -> CanonicalText {
        swp_core::canon::canonicalize(tokens, level, site)
    }

    /// The rendering for one code at one family, or the reason this site cannot
    /// carry it.
    fn render(
        &self,
        analysis: &Analysis,
        site: usize,
        family: FormFamily,
        code: u32,
        width: TagWidth,
    ) -> Result<String, SwpError> {
        let dialect = self.dialect();
        let Some(candidate) = analysis.sites.get(site) else {
            return Err(SwpError::new(
                ErrorCode::Internal,
                format!("site {site} is not in the analysis of {}", self.name()),
            ));
        };
        candidate.render(family, code, width, dialect)
    }

    /// What a spelling found in a candidate file means.
    ///
    /// The scanner calls this for every literal it can reach, with the family the
    /// manifest says to look for. A `None` answer is the ordinary case and is not
    /// a mismatch; a mismatch is a `Some` whose code disagrees.
    fn extract(&self, text: &str, family: FormFamily, width: TagWidth) -> Option<DecodedSite> {
        literal::decode(text, family, width, self.dialect())
    }

    /// The literal facts about this language's numbers and strings.
    fn dialect(&self) -> &'static crate::dialect::Dialect;

    /// Re-parse the watermarked file and check it against the original.
    ///
    /// This is the last line of defence, so it fails closed: any check that
    /// cannot be performed is an error, not a skipped site. The three checks are
    /// the three ways a "semantics-preserving" transformation can lie.
    fn validate(&self, before: &str, after: &str, edits: &[Edit]) -> Result<Proof, SwpError> {
        let limits = Limits::default();
        let original = self.analyze(before, &limits)?;
        let updated = self.analyze(after, &limits)?;
        if updated.parse_errors > original.parse_errors {
            return Err(SwpError::new(
                ErrorCode::UnsafeEmbedding,
                format!(
                    "{} parsed {} errors after embedding where it parsed {} before",
                    self.name(),
                    updated.parse_errors,
                    original.parse_errors
                ),
            ));
        }
        let mut proof = Proof {
            sites_verified: 0,
            levels_stable: ALL_LEVELS,
            parse_errors: updated.parse_errors,
        };
        for edit in edits {
            let Some(rendered) = edit.rendered else {
                return Err(SwpError::new(
                    ErrorCode::Internal,
                    "an edit reached validation without its rendered span".to_string(),
                ));
            };
            let Some(candidate) = original.sites.get(edit.site) else {
                return Err(SwpError::new(
                    ErrorCode::Internal,
                    format!(
                        "edit refers to site {} which the analysis did not produce",
                        edit.site
                    ),
                ));
            };
            let text = &after[rendered.start as usize..rendered.end as usize];

            // 1. The form says what it was asked to say.
            let Some(decoded) = self.extract(text, edit.family, edit.width) else {
                return Err(SwpError::new(
                    ErrorCode::InvalidWatermark,
                    format!(
                        "{} did not decode as a {} form after embedding",
                        shorten(text),
                        edit.family.as_str()
                    ),
                ));
            };
            if decoded.code() != edit.code {
                return Err(SwpError::new(
                    ErrorCode::InvalidWatermark,
                    format!(
                        "the rendered form {} carries code {} where {} was embedded",
                        shorten(text),
                        decoded.code(),
                        edit.code
                    ),
                ));
            }
            if decoded.canonical_value() != canonical_of(&candidate.value) {
                return Err(SwpError::new(
                    ErrorCode::UnsafeEmbedding,
                    format!(
                        "the rendering {} changed literal {} to {}",
                        shorten(text),
                        canonical_of(&candidate.value),
                        decoded.canonical_value()
                    ),
                ));
            }
            proof.sites_verified += 1;

            // 2. Nothing around it moved, at every level the location ids are
            // computed from. The site is hidden on both sides — it is precisely
            // what changed — and the comparison is made over the enclosing
            // radius, which is what a detector will recompute from a copy.
            for level in [CanonLevel::L1, CanonLevel::L2, CanonLevel::L3] {
                for (before_radius, after_radius, name) in [
                    (
                        candidate.statement,
                        updated.statement_span_at(rendered.start),
                        "statement",
                    ),
                    (
                        candidate.scope,
                        updated.scope_span_at(rendered.start),
                        "scope",
                    ),
                ] {
                    let a = self.canonicalize(
                        original.tokens_in(before_radius),
                        level,
                        Some(candidate.span),
                    );
                    let b =
                        self.canonicalize(updated.tokens_in(after_radius), level, Some(rendered));
                    if a != b {
                        // A moved radius is not a warning. The location id this
                        // site contributes is digested from exactly this text,
                        // so a difference here means the manifest would record an
                        // id the scanner can never find again.
                        return Err(SwpError::new(
                            ErrorCode::UnsafeEmbedding,
                            format!(
                                "embedding {} at {} changed its {} radius under {}: {} became {}",
                                edit.family.as_str(),
                                candidate.span.start,
                                name,
                                level.as_str(),
                                swp_core::canon::preview(&a, 96),
                                swp_core::canon::preview(&b, 96)
                            ),
                        ));
                    }
                }
            }
        }
        Ok(proof)
    }
}

fn canonical_of(value: &literal::SiteValue) -> String {
    match value {
        literal::SiteValue::Integer(v) => v.to_string(),
        literal::SiteValue::Text(s) => s.inner.clone(),
    }
}

fn shorten(text: &str) -> String {
    let count = text.chars().count();
    if count <= 40 {
        return text.to_string();
    }
    let kept: String = text.chars().take(40).collect();
    format!("{kept}…")
}

/// The adapters this build ships with.
///
/// Ordered by preference so the registry consults real parsers before the
/// fallback, and closed: a language not in this list has no parser here. The
/// walk refuses such a file outright rather than handing it to the fallback, so
/// `swp protect` and `swp scan` only ever deal with the languages above.
pub struct Registry {
    adapters: Vec<Box<dyn LanguageAdapter>>,
    fallback: GenericAdapter,
}

impl Registry {
    /// Every adapter compiled into this build.
    pub fn standard() -> Registry {
        Registry {
            adapters: vec![
                Box::new(AstAdapter::new("javascript", || &JAVASCRIPT)),
                Box::new(AstAdapter::new("typescript", || &TYPESCRIPT)),
                Box::new(AstAdapter::new("python", || &PYTHON)),
            ],
            fallback: GenericAdapter,
        }
    }

    /// The adapter for a path, if a parser covers it.
    pub fn for_path(&self, path: &Path) -> Option<&dyn LanguageAdapter> {
        self.adapters
            .iter()
            .find(|a| a.identifies(path))
            .map(|a| a.as_ref())
    }

    /// The adapter to use regardless of extension: the parser when one exists for
    /// the named language, the lexical fallback otherwise.
    ///
    /// There is no "no adapter" answer, which is why the return type carries no
    /// option: a caller that needs to know *how* the file was analyzed reads
    /// [`Capabilities::kind`] from the analysis rather than guessing from which
    /// branch it took.
    pub fn for_language(&self, language: &str) -> &dyn LanguageAdapter {
        self.adapters
            .iter()
            .find(|a| a.name() == language)
            .map(|a| a.as_ref())
            .unwrap_or(&self.fallback)
    }

    /// Analyze a file with a parser if one covers its extension, and with the
    /// lexical fallback otherwise. The returned analysis records which happened.
    pub fn analyze(
        &self,
        path: &Path,
        source: &str,
        limits: &Limits,
    ) -> Result<Analysis, SwpError> {
        self.for_path(path)
            .unwrap_or(&self.fallback)
            .analyze(source, limits)
    }

    /// Names of the languages with a real parser.
    pub fn parsed_languages(&self) -> Vec<&'static str> {
        self.adapters.iter().map(|a| a.name()).collect()
    }
}

/// The one [`LanguageAdapter`] implementation for every parsed language: all of
/// the behaviour is shared, and what differs is a [`ts::Grammar`] table.
///
/// The table is reached through a function rather than stored as a reference so
/// that a grammar can be a `static` item in its own module, next to the tables it
/// is built from, instead of a registry-wide allocation the caller has to keep
/// alive.
pub struct AstAdapter {
    name: &'static str,
    grammar: fn() -> &'static ts::Grammar,
}

impl AstAdapter {
    /// Constructed by [`Registry::standard`], which is where the language name and
    /// its grammar table are paired; a caller outside this crate gets adapters
    /// from the registry instead of naming grammars, which are `pub(crate)`.
    pub(crate) fn new(name: &'static str, grammar: fn() -> &'static ts::Grammar) -> AstAdapter {
        AstAdapter { name, grammar }
    }

    fn table(&self) -> &'static ts::Grammar {
        (self.grammar)()
    }
}

impl LanguageAdapter for AstAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::AST
    }

    fn extensions(&self) -> &'static [&'static str] {
        self.table().extensions
    }

    fn dialect(&self) -> &'static crate::dialect::Dialect {
        &self.table().dialect
    }

    fn analyze(&self, source: &str, limits: &Limits) -> Result<Analysis, SwpError> {
        ts::analyze(self.table(), source, limits)
    }
}
