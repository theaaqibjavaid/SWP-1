//! The analysis result an adapter returns, and the vocabulary of what it found.
//!
//! Everything the rest of SWP-1 needs from a language is here: the abstract
//! token stream, the literals that may carry a watermark and where they sit, and
//! — just as important — the literals that may *not*, with a reason. A report
//! that says "this project produced four sites" is only trustworthy if the same
//! run can also say why the other two hundred literals were skipped.
//!
//! ## Radius
//!
//! A site is located not by its own text but by the code around it, at two
//! radii: the innermost enclosing statement, and the enclosing function or
//! module block. Both are byte spans into the *original* source, which lets the
//! embedding splice a rendering in and lets the detector recompute the same span
//! from a candidate file without the site's own spelling. `swp_core::canon`
//! replaces the site span with a `<SITE>` placeholder while canonicalizing, so
//! the location id of a rewritten statement is the id of the original.

use swp_core::canon::{ByteSpan, Token};
use swp_core::site::{FormFamily, RadiusKind, TagWidth};

use crate::literal::{OwnedString, RefusalKind, SiteValue};

/// How the analysis was produced, which caps the strength of the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKind {
    /// A real parser: the token stream follows the grammar, and enclosing
    /// statements and scopes are syntactic facts.
    Ast,
    /// Lexical normalization: tokens come from a hand-written scanner, so
    /// radius is approximate and identifiers cannot be classified.
    Lexical,
}

impl AdapterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterKind::Ast => "ast",
            AdapterKind::Lexical => "token",
        }
    }

    /// Evidence strength this kind of analysis can support, per
    /// `docs/SWP-1-SPEC.md` §Language-agnostic fallback. A lexical match is
    /// never reported as if a parser had confirmed it.
    pub fn max_evidence(self) -> EvidenceStrength {
        match self {
            AdapterKind::Ast => EvidenceStrength::Ast,
            AdapterKind::Lexical => EvidenceStrength::Token,
        }
    }
}

/// What a claim of reuse is backed by. Kept deliberately coarse: these are the
/// four levels the specification names, and nothing in this workspace invents a
/// fifth or interpolates between two.
// Declared weakest first, so the derived `Ord` is the strength ranking a report
// sorts by. The ordering is coarse on purpose: `Ast` and `Exact` answer different
// questions — one asks "was this our watermark", the other "is this our text" —
// and a scale that could trade them off would be pretending to a precision the
// protocol does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceStrength {
    /// Similarity alone. Never reported as provenance.
    Weak,
    /// A structural match confirmed by the lexical fallback.
    Token,
    /// Text identical after canonicalization. Strong only for exact copies.
    Exact,
    /// A keyed watermark site confirmed inside parsed code.
    Ast,
}

impl EvidenceStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceStrength::Ast => "STRONG",
            EvidenceStrength::Exact => "STRONG (exact copy)",
            EvidenceStrength::Token => "MODERATE",
            EvidenceStrength::Weak => "WEAK",
        }
    }

    /// Whether this level may be described as evidence of provenance at all.
    /// `swp scan` uses this to decide what goes in the findings list and what
    /// goes in the "similar, not evidence" appendix.
    pub fn is_provenance(self) -> bool {
        matches!(self, EvidenceStrength::Ast | EvidenceStrength::Exact)
    }
}

/// What an adapter promises, so the embedding and the report can degrade
/// honestly instead of assuming every language supports everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub kind: AdapterKind,
    /// Whether local and free identifiers are distinguished, which is what makes
    /// the `*Id` radius keys name-insensitive. `false` means L2 canonicalizes
    /// exactly as L1 does.
    pub scopes: bool,
    /// Whether a literal's value is normalized independently of its spelling,
    /// which is what makes L3 meaningful.
    pub literal_values: bool,
    /// Whether the adapter can re-parse its own output, which is what makes
    /// [`crate::adapter::LanguageAdapter::validate`] more than a string compare.
    pub reparse: bool,
    /// Highest evidence this adapter's analyses can support.
    pub evidence: EvidenceStrength,
}

impl Capabilities {
    /// A parsed language with scope analysis.
    pub const AST: Capabilities = Capabilities {
        kind: AdapterKind::Ast,
        scopes: true,
        literal_values: true,
        reparse: true,
        evidence: EvidenceStrength::Ast,
    };

    /// The lexical fallback: honest about being weaker.
    pub const LEXICAL: Capabilities = Capabilities {
        kind: AdapterKind::Lexical,
        scopes: false,
        literal_values: true,
        reparse: false,
        evidence: EvidenceStrength::Token,
    };
}

/// One literal that may carry a watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSite {
    /// Where the literal is.
    pub span: ByteSpan,
    /// Its index in [`Analysis::tokens`], so the canonicalizer can be handed a
    /// slice without re-finding it.
    pub token: usize,
    /// What it means.
    pub value: SiteValue,
    /// The innermost enclosing statement, as a byte span that contains `span`.
    pub statement: ByteSpan,
    /// The enclosing function, class or module block. Module level sites use the
    /// whole file, which is a weaker key and is recorded as such rather than
    /// silently.
    pub scope: ByteSpan,
    /// Grammar path from the scope root down to the literal, e.g.
    /// `return;binary_expression;number`. Purely for the report: it lets
    /// `swp inspect` say *"inside the return statement of `describe`"* without
    /// the reader having to open the file.
    pub path: String,
}

impl CandidateSite {
    pub fn radius(&self, kind: RadiusKind) -> ByteSpan {
        match kind {
            RadiusKind::StatementId | RadiusKind::StatementRaw => self.statement,
            RadiusKind::ScopeId | RadiusKind::ScopeRaw => self.scope,
        }
    }

    pub fn is_numeric(&self) -> bool {
        matches!(self.value, SiteValue::Integer(_))
    }

    /// Families usable at this site for the requested width.
    pub fn families(&self, width: TagWidth, dialect: &crate::dialect::Dialect) -> Vec<FormFamily> {
        crate::literal::families_for(&self.value, width, dialect)
    }

    /// The rendering that carries `code`, or the reason it cannot.
    pub fn render(
        &self,
        family: FormFamily,
        code: u32,
        width: TagWidth,
        dialect: &crate::dialect::Dialect,
    ) -> Result<String, swp_core::error::SwpError> {
        crate::literal::render(&self.value, family, code, width, dialect)
    }

    /// Source text of the literal as it appears in the file.
    pub fn source<'a>(&self, text: &'a str) -> &'a str {
        &text[self.span.start as usize..self.span.end as usize]
    }
}

/// A literal that was examined and rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub span: ByteSpan,
    pub kind: RefusalKind,
    /// Human-readable detail: the spelling, or the enclosing construct.
    pub note: String,
}

/// Everything one file produced.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// `javascript`, `python`, `generic-javascript`, ...
    pub language: String,
    pub capabilities: Capabilities,
    pub tokens: Vec<Token>,
    pub sites: Vec<CandidateSite>,
    pub refusals: Vec<Refusal>,
    /// Count of parse errors reported by the grammar. A file with errors is
    /// still analyzed — half-written code is common in a copied tree — but the
    /// report says so, and its sites carry weaker evidence.
    pub parse_errors: u32,
    /// Nodes visited, for the resource report.
    pub nodes: u32,
    /// True when a limit stopped the walk early, so the caller knows the site
    /// list is incomplete rather than empty by nature.
    pub truncated: bool,
    /// The whole document, which is the radius of a site no statement encloses.
    pub file: ByteSpan,
    /// Every node the grammar calls a statement, in the order the walk saw them.
    ///
    /// Sites carry their own radius; this is what lets the validator find the
    /// *enclosing statement of a rendering*, which is not itself a site and so
    /// appears nowhere else in the analysis.
    pub statement_spans: Vec<ByteSpan>,
    /// Every node the grammar opens a binding scope at.
    pub scope_spans: Vec<ByteSpan>,
}

impl Analysis {
    fn empty(language: &str, capabilities: Capabilities) -> Analysis {
        Analysis {
            language: language.to_string(),
            capabilities,
            tokens: Vec::new(),
            sites: Vec::new(),
            refusals: Vec::new(),
            parse_errors: 0,
            nodes: 0,
            truncated: false,
            file: ByteSpan::new(0, 0),
            statement_spans: Vec::new(),
            scope_spans: Vec::new(),
        }
    }

    /// Sites that can carry `width`, in the order they appear in the file.
    ///
    /// This is the answer to the brief's `find_candidate_locations()`: a list of
    /// locations, each with the families that reach every code at that width.
    /// A site whose family set is empty is not a location at all — offering it
    /// would mean a manifest entry whose tag could not have been embedded.
    pub fn usable_sites(
        &self,
        width: TagWidth,
        dialect: &crate::dialect::Dialect,
    ) -> Vec<(&CandidateSite, Vec<FormFamily>)> {
        self.sites
            .iter()
            .filter_map(|s| {
                let families = s.families(width, dialect);
                (!families.is_empty()).then_some((s, families))
            })
            .collect()
    }

    pub fn site_at_offset(&self, byte: u32) -> Option<&CandidateSite> {
        self.sites.iter().find(|s| s.span.contains(byte))
    }

    /// Tokens whose span lies within `span`, as a subslice.
    ///
    /// Relies on the adapter's guarantee that tokens are in source order and
    /// non-overlapping, which every adapter in this crate establishes by walking
    /// a parser's leaves.
    pub fn tokens_in(&self, span: ByteSpan) -> &[Token] {
        swp_core::canon::tokens_within(&self.tokens, span)
    }

    /// The innermost recorded statement radius containing `byte`.
    ///
    /// Used by validation, where the thing being located is a rendering rather
    /// than a site, so no [`CandidateSite`] carries its enclosing span. A byte in
    /// whitespace between statements resolves to the document, which is the same
    /// answer [`CandidateSite::radius`] gives for a top-level literal.
    pub fn statement_span_at(&self, byte: u32) -> ByteSpan {
        enclosing(&self.statement_spans, byte, self.file)
    }

    pub fn scope_span_at(&self, byte: u32) -> ByteSpan {
        let statement = self.statement_span_at(byte);
        enclosing(&self.scope_spans, byte, statement)
    }

    /// How many distinct literals produced at least one site, for the report's
    /// density figure.
    pub fn site_density(&self) -> f64 {
        let literals = self.sites.len() + self.refusals.len();
        if literals == 0 {
            0.0
        } else {
            self.sites.len() as f64 / literals as f64
        }
    }
}

/// Builder used by the AST and lexical layers, so both produce identical shapes.
pub(crate) struct AnalysisBuilder {
    pub(crate) analysis: Analysis,
    pub(crate) max_sites: u32,
}

/// The tightest span in `spans` that contains `byte`, or `fallback`.
///
/// Linear rather than indexed: validation asks this once per embedded site and a
/// project embeds tens of them, while a binary search would need the walk to
/// emit spans in start order *and* tie-break nested spans by end order, which is
/// more machinery than the question is worth.
fn enclosing(spans: &[ByteSpan], byte: u32, fallback: ByteSpan) -> ByteSpan {
    let mut best: Option<ByteSpan> = None;
    for s in spans {
        if !s.contains(byte) {
            continue;
        }
        if best.is_none_or(|b| s.len() < b.len()) {
            best = Some(*s);
        }
    }
    best.unwrap_or(fallback)
}

impl AnalysisBuilder {
    pub(crate) fn new(
        language: &str,
        capabilities: Capabilities,
        limits: &swp_core::limits::Limits,
    ) -> AnalysisBuilder {
        AnalysisBuilder {
            analysis: Analysis::empty(language, capabilities),
            max_sites: limits.max_sites_per_file,
        }
    }

    pub(crate) fn push_token(&mut self, token: Token) {
        self.analysis.tokens.push(token);
    }

    pub(crate) fn set_file(&mut self, span: ByteSpan) {
        self.analysis.file = span;
    }

    pub(crate) fn push_statement(&mut self, span: ByteSpan) {
        self.analysis.statement_spans.push(span);
    }

    pub(crate) fn push_scope(&mut self, span: ByteSpan) {
        self.analysis.scope_spans.push(span);
    }

    pub(crate) fn push_site(
        &mut self,
        span: ByteSpan,
        value: SiteValue,
        statement: ByteSpan,
        scope: ByteSpan,
        path: String,
    ) -> bool {
        if self.analysis.sites.len() >= self.max_sites as usize {
            self.analysis.truncated = true;
            self.analysis.refusals.push(Refusal {
                span,
                kind: RefusalKind::ResourceLimit,
                note: format!("site limit of {} per file reached", self.max_sites),
            });
            return false;
        }
        let token = self
            .analysis
            .tokens
            .partition_point(|t| t.span.end <= span.start);
        self.analysis.sites.push(CandidateSite {
            span,
            token,
            value,
            statement,
            scope,
            path,
        });
        true
    }

    pub(crate) fn push_refusal(&mut self, span: ByteSpan, kind: RefusalKind, note: String) {
        if self.analysis.refusals.len() >= 256 {
            // Refusals are diagnostics, not protocol state; a hostile file with
            // millions of them must not grow the report.
            return;
        }
        self.analysis.refusals.push(Refusal { span, kind, note });
    }

    pub(crate) fn finish(self) -> Analysis {
        self.analysis
    }
}

/// The string a site would have to have been to be a text site: kept separate
/// from [`OwnedString`] so an adapter cannot accidentally rewrite a literal that
/// has already been rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalText(pub OwnedString);

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::canon::{ByteSpan, TokKind, Token};
    use swp_core::limits::Limits;
    use swp_core::site::LiteralClass;

    fn toks(v: &[(&str, u32)]) -> Vec<Token> {
        v.iter()
            .map(|(t, end)| Token::new(TokKind::Punct, *t, ByteSpan::new(*end, *end + 1)))
            .collect()
    }

    #[test]
    fn tokens_in_selects_the_span_exactly() {
        let mut b = AnalysisBuilder::new("test", Capabilities::AST, &Limits::default());
        for t in toks(&[("a", 0), ("b", 2), ("c", 4), ("d", 6)]) {
            b.push_token(t);
        }
        let a = b.finish();
        // A statement radius covering tokens `b` and `c`.
        let got = a.tokens_in(ByteSpan::new(1, 6));
        assert_eq!(
            got.iter().map(|t| t.text.as_str()).collect::<Vec<_>>(),
            ["b", "c"]
        );
        assert_eq!(a.tokens_in(ByteSpan::new(0, 7)).len(), 4);
        assert!(a.tokens_in(ByteSpan::new(8, 9)).is_empty());
        assert!(a.tokens_in(ByteSpan::new(5, 5)).is_empty());
    }

    #[test]
    fn site_token_index_points_at_the_literal() {
        let mut b = AnalysisBuilder::new("test", Capabilities::AST, &Limits::default());
        b.push_token(Token::new(TokKind::Ident, "x", ByteSpan::new(0, 1)));
        b.push_token(Token::new(TokKind::Punct, "=", ByteSpan::new(2, 3)));
        b.push_token(Token::new(TokKind::Number, "1000", ByteSpan::new(4, 8)));
        b.push_site(
            ByteSpan::new(4, 8),
            SiteValue::Integer(1000),
            ByteSpan::new(0, 8),
            ByteSpan::new(0, 8),
            "expression_statement;number".into(),
        );
        let a = b.finish();
        assert_eq!(a.tokens.len(), 3);
        let site = &a.sites[0];
        assert_eq!(site.token, 2);
        assert_eq!(a.tokens[site.token].kind, TokKind::Number);
        assert_eq!(site.source("x = 1000"), "1000");
        assert!(site.is_numeric());
        assert_eq!(a.site_at_offset(6).unwrap().token, 2);
        assert!(a.site_at_offset(1).is_none());
    }

    #[test]
    fn the_site_limit_is_enforced_and_said_so() {
        let limits = Limits {
            max_sites_per_file: 2,
            ..Limits::default()
        };
        let mut b = AnalysisBuilder::new("test", Capabilities::AST, &limits);
        for i in 0..5u32 {
            let span = ByteSpan::new(i, i + 1);
            b.push_site(span, SiteValue::Integer(1), span, span, String::new());
        }
        let a = b.finish();
        assert_eq!(a.sites.len(), 2);
        assert!(a.truncated);
        assert_eq!(a.refusals.len(), 3);
        assert_eq!(a.refusals[0].kind, RefusalKind::ResourceLimit);
    }

    #[test]
    fn refusal_reports_stay_bounded() {
        let mut b = AnalysisBuilder::new("test", Capabilities::AST, &Limits::default());
        for i in 0..2000u32 {
            b.push_refusal(
                ByteSpan::new(i, i + 1),
                RefusalKind::FloatingPoint,
                "1.5".into(),
            );
        }
        let a = b.finish();
        assert_eq!(a.refusals.len(), 256);
        assert!(!a.truncated, "a bounded diagnostic is not a truncated scan");
    }

    #[test]
    fn usable_sites_drops_what_cannot_carry_the_width() {
        let mut b = AnalysisBuilder::new("test", Capabilities::AST, &Limits::default());
        b.push_token(Token::new(TokKind::Number, "1", ByteSpan::new(0, 1)));
        b.push_site(
            ByteSpan::new(0, 1),
            SiteValue::Integer(1),
            ByteSpan::new(0, 1),
            ByteSpan::new(0, 1),
            String::new(),
        );
        b.push_site(
            ByteSpan::new(2, 9),
            SiteValue::Text(OwnedString {
                inner: "abcdefgh".into(),
                quote: '"',
            }),
            ByteSpan::new(0, 9),
            ByteSpan::new(0, 9),
            String::new(),
        );
        let a = b.finish();
        let w = TagWidth::DEFAULT;
        let usable = a.usable_sites(w, &crate::dialect::Dialect::JS);
        // The integer has forms; a two-character string has nowhere to split.
        assert_eq!(usable.len(), 1, "{usable:?}");
        assert!(usable[0].0.is_numeric());
        assert_eq!(usable[0].1.first().copied(), Some(FormFamily::Sub));
        // At two bits the same string has split points and the site is usable.
        assert_eq!(
            a.usable_sites(TagWidth::new(2).unwrap(), &crate::dialect::Dialect::JS)
                .len(),
            2
        );
    }

    #[test]
    fn evidence_levels_are_ordered_and_named() {
        assert!(EvidenceStrength::Ast > EvidenceStrength::Exact);
        assert!(EvidenceStrength::Exact > EvidenceStrength::Token);
        assert!(EvidenceStrength::Token > EvidenceStrength::Weak);
        assert!(EvidenceStrength::Ast.is_provenance());
        assert!(EvidenceStrength::Exact.is_provenance());
        assert!(!EvidenceStrength::Token.is_provenance());
        assert!(!EvidenceStrength::Weak.is_provenance());
        assert_eq!(AdapterKind::Ast.max_evidence(), EvidenceStrength::Ast);
        assert_eq!(AdapterKind::Lexical.max_evidence(), EvidenceStrength::Token);
        let lexical = Capabilities::LEXICAL;
        let ast = Capabilities::AST;
        assert!(!lexical.scopes);
        assert!(!lexical.reparse);
        assert!(ast.reparse);
        assert!(ast.scopes);
    }

    #[test]
    fn radius_kinds_map_to_the_two_spans() {
        let statement = ByteSpan::new(10, 20);
        let scope = ByteSpan::new(0, 100);
        let site = CandidateSite {
            span: ByteSpan::new(14, 18),
            token: 0,
            value: SiteValue::Integer(7),
            statement,
            scope,
            path: String::new(),
        };
        assert_eq!(site.radius(RadiusKind::StatementId), statement);
        assert_eq!(site.radius(RadiusKind::StatementRaw), statement);
        assert_eq!(site.radius(RadiusKind::ScopeId), scope);
        assert_eq!(site.radius(RadiusKind::ScopeRaw), scope);
        assert_eq!(site.value.class(), LiteralClass::Integer);
    }
}
