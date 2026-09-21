//! The lexical fallback: what SWP-1 does with a language it has no parser for.
//!
//! # Why this exists at all
//!
//! A project that mixes languages must still be protectable, and a scan that
//! silently ignores `main.cob` is worse than one that says it analyzed the file
//! with weaker tools. The fallback therefore exists so that "unsupported" is a
//! *graded* statement — "analyzed lexically, evidence capped at MODERATE" —
//! rather than a gap.
//!
//! # What it refuses, and why each refusal is load-bearing
//!
//! A scanner without a grammar cannot tell a value from a name. Concretely, it
//! cannot distinguish:
//!
//! | Looks like | Could really be | Consequence of rewriting it |
//! |---|---|---|
//! | `"mod"` | a module specifier, an import, a URL | the program loads something else, or fails to load |
//! | `"""text"""` at line start | a docstring | the module's `__doc__` changes, which is observable behavior |
//! | `100` after `:` | a JSON or YAML member | arithmetic is not valid syntax there at all |
//! | `1` before `:` | a `case` label, an object key, a `goto` label | the statement stops parsing |
//! | `1200 ms` | a duration literal with a separated unit, which is one token there | `(1199 + 1) ms` does not parse |
//! | `2` glued to `px`, `em`, `s` | a unit-suffixed literal | the token was never an integer |
//!
//! So the fallback offers **numeric literals in expression positions only**, and
//! refuses every text literal, with the reason recorded. That is a smaller
//! constellation than a parser would find, which is the honest price of not
//! having one; the size of that price is what `swp scan --languages` reports.
//!
//! # What it guarantees
//!
//! * Tokens are in source order, non-overlapping, and each token's text equals
//!   the source at its span — the same contract the AST walkers give, because
//!   [`crate::adapter::LanguageAdapter::validate`] relies on it.
//! * Line-initial tokens, comments and directives are skipped the same way for
//!   every file, so the same bytes always produce the same stream. Determinism
//!   matters more here than correctness of meaning: the fallback compares a
//!   project against a copy of itself, both scanned by this same lexer.
//! * Radius is a *line*, not a statement. A copy that re-wraps a long call
//!   argument list therefore loses its fallback location ids, and the report says
//!   `token`-level evidence rather than pretending otherwise.

use swp_core::canon::{ByteSpan, IdentRole, TokKind, Token};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::limits::Limits;

use crate::adapter::LanguageAdapter;
use crate::analyze::{Analysis, AnalysisBuilder, Capabilities};
use crate::dialect::Dialect;
use crate::literal::{self, RefusalKind, SiteValue};

/// The adapter used when no grammar covers the language.
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericAdapter;

impl GenericAdapter {
    pub fn new() -> GenericAdapter {
        GenericAdapter
    }
}

impl LanguageAdapter for GenericAdapter {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn capabilities(&self) -> Capabilities {
        // `scopes: false` is the whole difference the report has to show: with no
        // grammar there is no way to tell a local name from a global one, so L2
        // canonicalizes exactly as L1 does and the two name-insensitive radius
        // keys collapse into their name-preserving twins.
        Capabilities::LEXICAL
    }

    fn extensions(&self) -> &'static [&'static str] {
        // The fallback claims no extension on purpose: `Registry::for_path` must
        // never pick it silently for a file a parser could have handled.
        &[]
    }

    fn dialect(&self) -> &'static Dialect {
        &Dialect::GENERIC
    }

    fn analyze(&self, source: &str, limits: &Limits) -> Result<Analysis, SwpError> {
        if source.len() as u64 > limits.max_parse_bytes {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "a {} byte file exceeds the {} byte analysis limit",
                    source.len(),
                    limits.max_parse_bytes
                ),
            ));
        }
        let lexed = lex(source, limits.max_nodes_per_tree);
        let mut b = AnalysisBuilder::new("generic", Capabilities::LEXICAL, limits);
        let file = ByteSpan::new(0, source.len() as u32);
        b.set_file(file);
        for span in &lexed.lines {
            b.push_statement(*span);
        }
        // The fallback knows no blocks, so the file is the only scope: every
        // site's scope radius is the whole document, which is a weaker key than a
        // parsed language's, and is recorded as one rather than disguised.
        b.push_scope(file);
        for (token, _) in &lexed.tokens {
            b.push_token(token.clone());
        }
        for (index, (token, line)) in lexed.tokens.iter().enumerate() {
            if token.kind == TokKind::Number {
                classify_number(&mut b, &lexed, index, token, *line, source);
            } else if matches!(
                token.kind,
                TokKind::String | TokKind::Template | TokKind::Regex
            ) {
                b.push_refusal(
                    token.span,
                    RefusalKind::UnsafeContext,
                    "the lexical fallback never rewrites a text literal: without a grammar it \
                     cannot be told apart from a module specifier, a directive or a docstring"
                        .to_string(),
                );
            }
        }
        let mut analysis = b.finish();
        analysis.nodes = lexed.tokens.len() as u32;
        analysis.parse_errors = lexed.errors;
        analysis.truncated |= lexed.truncated;
        Ok(analysis)
    }
}

/// The position rule for the one site class the fallback offers.
fn classify_number(
    b: &mut AnalysisBuilder,
    lexed: &Lexed,
    index: usize,
    token: &Token,
    line: u32,
    source: &str,
) {
    let previous = index.checked_sub(1).map(|i| &lexed.tokens[i]);
    let next = lexed.tokens.get(index + 1);
    if let Some(reason) = number_position_hazard(previous, next, line, token, source) {
        b.push_refusal(token.span, RefusalKind::UnsafeContext, reason);
        return;
    }
    match literal::parse_integer(token.text.as_str(), &Dialect::GENERIC) {
        Ok(value) => {
            let statement = lexed
                .lines
                .get(line as usize)
                .copied()
                .unwrap_or(ByteSpan::new(0, source.len() as u32));
            let scope = ByteSpan::new(0, source.len() as u32);
            b.push_site(
                token.span,
                value,
                statement,
                scope,
                format!("lexical;line={}", line + 1),
            );
        }
        Err(kind) => b.push_refusal(token.span, kind, shorten(&token.text)),
    }
}

/// Why this number may not be an ordinary expression value, if it may not.
fn number_position_hazard(
    previous: Option<&Annotated>,
    next: Option<&Annotated>,
    line: u32,
    token: &Token,
    source: &str,
) -> Option<String> {
    let prev_token = previous.map(|p| &p.0);
    let next_token = next.map(|n| &n.0);
    if prev_token.is_some_and(|p| p.span.end == token.span.start)
        || next_token.is_some_and(|n| n.span.start == token.span.end)
    {
        // `10px`, `2em`, `r".."`, `1"`, `#".."`: whatever the neighbour is, the
        // two together are one thing the scanner did not understand.
        return Some("glued to an adjacent token, so it may be a unit suffix or a prefix".into());
    }
    if next_token.is_some_and(|n| n.text == ":") {
        return Some("a label or `case` position, where the grammar expects a name".into());
    }
    if prev_token.is_some_and(|p| p.text == ":") {
        // Data files put values exactly here, and `{"a": (1 + 1)}` is not data.
        return Some(
            "the value of a key:value pair, which may be JSON or YAML rather than code".into(),
        );
    }
    if prev_token.is_some_and(|p| p.text == ".") {
        return Some("a member name, which is not a value in any language".into());
    }
    if next.is_some_and(|(n, nline)| {
        // `1200 ms`, `5 ns`, `30 s`: a literal with a separated unit is one token
        // in the hardware and timing languages, and arithmetic is not valid in
        // front of a unit. A real parser settles this; a lexer has to assume the
        // worst and lose the site.
        *nline == line
            && n.kind == TokKind::Ident
            && source[token.span.end as usize..n.span.start as usize]
                .chars()
                .all(char::is_whitespace)
    }) {
        return Some(
            "followed on the same line by a bare word, which is a unit suffix in the languages \
             without a parser here"
                .into(),
        );
    }
    None
}

/// One token plus the line it sits on.
type Annotated = (Token, u32);

struct Lexed {
    tokens: Vec<Annotated>,
    /// Span of each line's content, with trailing whitespace removed. A line
    /// index is a `u32` counted from zero, so this is the statement radius table.
    lines: Vec<ByteSpan>,
    /// Unterminated strings and block comments: the fallback's only signal that
    /// the file did not scan cleanly.
    errors: u32,
    truncated: bool,
}

fn lex(source: &str, max_tokens: u32) -> Lexed {
    let mut l = Lexer {
        src: source,
        bytes: source.as_bytes(),
        i: 0,
        line: 0,
        line_start: 0,
        tokens: Vec::new(),
        lines: Vec::new(),
        max_tokens,
        errors: 0,
        truncated: false,
    };
    l.run();
    Lexed {
        tokens: l.tokens,
        lines: l.lines,
        errors: l.errors,
        truncated: l.truncated,
    }
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    i: usize,
    line: u32,
    line_start: usize,
    tokens: Vec<Annotated>,
    lines: Vec<ByteSpan>,
    max_tokens: u32,
    errors: u32,
    truncated: bool,
}

const OPERATOR_CHARS: &[u8] = b"+-*/%=<>!&|^~?:\\@";

impl<'a> Lexer<'a> {
    fn cur(&self) -> Option<char> {
        self.src[self.i..].chars().next()
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.src[self.i..].chars().nth(ahead)
    }

    fn at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// Advance one character, closing the line record when it is a newline.
    fn bump(&mut self) {
        let Some(c) = self.cur() else { return };
        self.i += c.len_utf8();
        if c == '\n' {
            self.close_line(self.i - 1);
            self.line += 1;
            self.line_start = self.i;
        }
    }

    fn close_line(&mut self, end: usize) {
        let mut stop = end;
        while stop > self.line_start && matches!(self.at(stop - 1), Some(b' ' | b'\t' | b'\r')) {
            stop -= 1;
        }
        self.lines
            .push(ByteSpan::new(self.line_start as u32, stop as u32));
    }

    fn run(&mut self) {
        while !self.truncated {
            let Some(c) = self.cur() else { break };
            match c {
                '\n' | ' ' | '\t' | '\r' => self.bump(),
                '#' => self.skip_line(),
                '/' if self.peek(1) == Some('/') => self.skip_line(),
                '/' if self.peek(1) == Some('*') => self.skip_block(),
                '"' | '\'' => self.quoted(c),
                '`' => self.backticked(),
                c if c.is_ascii_digit() => self.number(),
                c if is_word_start(c) => self.word(),
                c if is_operator(c) => self.operator(),
                _ => {
                    let start = self.i;
                    self.bump();
                    self.emit(TokKind::Punct, start);
                }
            }
        }
        // Close whatever line the scan stopped on, so `lines[tok.line]` is a
        // valid index even for a truncated file.
        self.close_line(self.i);
    }

    fn skip_line(&mut self) {
        while !matches!(self.cur(), None | Some('\n')) {
            self.bump();
        }
    }

    fn skip_block(&mut self) {
        self.bump();
        self.bump();
        loop {
            match self.cur() {
                None => {
                    self.errors += 1;
                    return;
                }
                Some('*') if self.peek(1) == Some('/') => {
                    self.bump();
                    self.bump();
                    return;
                }
                _ => self.bump(),
            }
        }
    }

    fn quoted(&mut self, quote: char) {
        let start = self.i;
        let q = quote as u8;
        let triple = self.at(self.i + 1) == Some(q) && self.at(self.i + 2) == Some(q);
        if triple {
            // A triple-quoted literal may span lines. The lexer must still find
            // its end, or every following line's radius would be wrong.
            self.bump();
            self.bump();
            self.bump();
            loop {
                match self.cur() {
                    None => {
                        self.errors += 1;
                        break;
                    }
                    Some('\\') => {
                        self.bump();
                        self.bump();
                    }
                    Some(c) if c == quote => {
                        if self.at(self.i + 1) == Some(q) && self.at(self.i + 2) == Some(q) {
                            self.bump();
                            self.bump();
                            self.bump();
                            break;
                        }
                        self.bump();
                    }
                    _ => self.bump(),
                }
            }
        } else {
            self.bump();
            loop {
                match self.cur() {
                    None | Some('\n') => {
                        // An unterminated string ends the line scan and is
                        // counted, so `swp status` can show a broken file.
                        self.errors += 1;
                        break;
                    }
                    Some('\\') => {
                        self.bump();
                        if !matches!(self.cur(), None | Some('\n')) {
                            self.bump();
                        }
                    }
                    Some(c) if c == quote => {
                        self.bump();
                        break;
                    }
                    _ => self.bump(),
                }
            }
        }
        self.emit(TokKind::String, start);
    }

    fn backticked(&mut self) {
        let start = self.i;
        self.bump();
        loop {
            match self.cur() {
                None => {
                    self.errors += 1;
                    break;
                }
                Some('\\') => {
                    self.bump();
                    self.bump();
                }
                Some('`') => {
                    self.bump();
                    break;
                }
                _ => self.bump(),
            }
        }
        self.emit(TokKind::Template, start);
    }

    fn number(&mut self) {
        let start = self.i;
        while let Some(c) = self.cur() {
            // A sign belongs to the literal only directly after an exponent:
            // `1e-9` is one token, `1 - 9` is three.
            let signed_exponent = matches!(c, '+' | '-') && self.prev_is_exponent(start);
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || signed_exponent {
                self.bump();
            } else {
                break;
            }
        }
        self.emit(TokKind::Number, start);
    }

    fn prev_is_exponent(&self, start: usize) -> bool {
        match self.at(self.i.wrapping_sub(1)) {
            Some(b'e') | Some(b'E') => self.i - 1 > start,
            _ => false,
        }
    }

    fn word(&mut self) {
        let start = self.i;
        while let Some(c) = self.cur() {
            if c.is_alphanumeric() || c == '_' || c == '$' {
                self.bump();
            } else {
                break;
            }
        }
        self.emit(TokKind::Ident, start);
    }

    fn operator(&mut self) {
        let start = self.i;
        while self.cur().is_some_and(is_operator) {
            self.bump();
        }
        self.emit(TokKind::Operator, start);
    }

    fn emit(&mut self, kind: TokKind, start: usize) {
        if self.tokens.len() as u32 >= self.max_tokens {
            self.truncated = true;
            return;
        }
        let end = self.i;
        if end == start {
            return;
        }
        let text = &self.src[start..end];
        let mut token = Token::new(kind, text, ByteSpan::new(start as u32, end as u32));
        match kind {
            TokKind::Ident => token.role = IdentRole::Free,
            TokKind::Number => {
                // The value of record is the unbounded one, exactly as the AST
                // walkers record it: what `0x1F400` *means* does not depend on
                // which language asked. Whether the file may be rewritten is a
                // separate question, answered by `Dialect::GENERIC`.
                if let Ok(SiteValue::Integer(v)) = literal::parse_integer(text, &Dialect::PY) {
                    token.value = Some(v.to_string());
                }
            }
            TokKind::String => {
                if let Ok(SiteValue::Text(s)) = literal::parse_string(text, &Dialect::PY) {
                    token.value = Some(s.inner);
                }
            }
            _ => {}
        }
        self.tokens.push((token, self.line));
    }
}

fn is_word_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == '$'
}

fn is_operator(c: char) -> bool {
    c.is_ascii() && OPERATOR_CHARS.contains(&(c as u8))
}

fn shorten(text: &str) -> String {
    const MAX: usize = 32;
    let count = text.chars().count();
    if count <= MAX {
        return text.to_string();
    }
    let kept: String = text.chars().take(MAX).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Edit;
    use swp_core::canon::CanonLevel;
    use swp_core::site::{FormFamily, TagWidth};

    fn analyze(source: &str) -> Analysis {
        GenericAdapter
            .analyze(source, &Limits::default())
            .expect("the fallback cannot fail on a size-capped file")
    }

    fn assert_tokens_match_source(source: &str, analysis: &Analysis) {
        let mut previous_end = 0u32;
        for t in &analysis.tokens {
            assert_eq!(
                t.text.as_str(),
                &source[t.span.start as usize..t.span.end as usize],
                "token text must equal the source at its span"
            );
            assert!(t.span.start >= previous_end, "tokens must not overlap");
            assert!(!t.span.is_empty());
            previous_end = t.span.end;
        }
    }

    #[test]
    fn a_script_the_parser_does_not_know_still_produces_numeric_sites() {
        let source = "set_timeout handler 1200 ms\nretry after 30\n";
        let a = analyze(source);
        assert_eq!(a.language, "generic");
        assert_eq!(a.capabilities, Capabilities::LEXICAL);
        assert_eq!(a.tokens.len(), 7);
        assert_tokens_match_source(source, &a);
        // `1200 ms` is a duration literal in the languages without a parser here,
        // so only `30` — the last thing on its line — is a value.
        let sites: Vec<_> = a.sites.iter().map(|s| s.source(source)).collect();
        assert_eq!(sites, ["30"]);
        assert_eq!(a.refusals.len(), 1);
        assert_eq!(a.refusals[0].kind, RefusalKind::UnsafeContext);
        assert!(a.refusals[0].note.contains("unit"), "{:?}", a.refusals[0]);
    }

    #[test]
    fn the_radius_of_a_fallback_site_is_its_line_and_its_file() {
        let source = "total = 4000 + 2\n";
        let a = analyze(source);
        let site = &a.sites[0];
        assert_eq!(
            &source[site.statement.start as usize..site.statement.end as usize],
            "total = 4000 + 2"
        );
        assert_eq!(site.scope, ByteSpan::new(0, source.len() as u32));
        assert_eq!(site.path, "lexical;line=1");
        // The same lookup the validator uses finds the line from a byte inside it.
        assert_eq!(a.statement_span_at(site.span.start), site.statement);
    }

    #[test]
    fn data_files_are_refused_rather_than_corrupted() {
        let json = "{\"timeout\": 5000, \"retries\": 3}\n";
        let a = analyze(json);
        assert!(a.sites.is_empty(), "{:?}", a.sites);
        assert!(a
            .refusals
            .iter()
            .all(|r| r.kind == RefusalKind::UnsafeContext));
        assert_eq!(a.tokens.len(), 9);
    }

    #[test]
    fn text_literals_are_never_sites() {
        let source = "require \"https://example.com/a\"\nuse 'os'\n";
        let a = analyze(source);
        assert!(a.sites.is_empty());
        assert_eq!(a.refusals.len(), 2);
        assert_eq!(a.refusals[0].kind, RefusalKind::UnsafeContext);
        // The URL inside the quotes is one string, not a comment: `//` only
        // starts a comment outside a literal.
        assert_eq!(a.tokens.len(), 4, "{:?}", a.tokens);
    }

    #[test]
    fn comments_and_directives_produce_nothing() {
        let source = "# a comment with 42 in it\nx = 7 // trailing 99\n/* block 8 */ y = 11\n";
        let a = analyze(source);
        let values: Vec<_> = a
            .sites
            .iter()
            .map(|s| match s.value {
                SiteValue::Integer(v) => v,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(values, [7, 11]);
    }

    #[test]
    fn a_broken_string_does_not_steal_the_next_line_radius() {
        let source = "msg = \"a\nb\"\ntotal = 5000\n";
        let a = analyze(source);
        // Two, because the scan that does not find a closing quote on the first
        // line then finds none on the second either. The count is the point: a
        // file the fallback could not scan cleanly must not look clean.
        assert_eq!(a.parse_errors, 2);
        let site = &a.sites[0];
        assert_eq!(site.source(source), "5000");
        assert_eq!(
            &source[site.statement.start as usize..site.statement.end as usize],
            "total = 5000"
        );
    }

    #[test]
    fn an_empty_file_analyzes_as_empty() {
        let a = analyze("");
        assert!(a.tokens.is_empty());
        assert!(a.sites.is_empty());
        assert_eq!(a.parse_errors, 0);
        assert!(!a.truncated);
    }

    #[test]
    fn the_fallback_collapses_l1_and_l2_because_it_sees_no_bindings() {
        let source = "count = 4000\nshow count\n";
        let a = analyze(source);
        // With no grammar there is no answer to "is this name bound here?", so no
        // token is renamed and L2 is L1. That equivalence is what
        // `Capabilities::scopes` promises; the test exists to catch the day the
        // canonicalizer makes the two levels differ without an adapter saying so.
        assert_eq!(
            GenericAdapter.canonicalize(&a.tokens, CanonLevel::L1, None),
            GenericAdapter.canonicalize(&a.tokens, CanonLevel::L2, None)
        );
        // And the cost: a renamed copy of the same program is a different
        // canonical text, where the AST adapter would abstract the name away.
        let b = analyze("n = 4000\nshow n\n");
        assert_ne!(
            GenericAdapter.canonicalize(&a.tokens, CanonLevel::L2, None),
            GenericAdapter.canonicalize(&b.tokens, CanonLevel::L2, None)
        );
    }

    #[test]
    fn literal_values_still_normalize_at_l3() {
        let a = analyze("x = 0x1F400\n");
        let text = GenericAdapter.canonicalize(&a.tokens, CanonLevel::L3, None);
        assert_eq!(text.as_str(), "x = <n:128000>");
        // And the site is offered, because the fallback reads the radix fine.
        assert_eq!(a.sites.len(), 1);
        assert_eq!(a.sites[0].value, SiteValue::Integer(128000));
    }

    #[test]
    fn the_site_limit_truncates_and_says_so() {
        let limits = Limits {
            max_sites_per_file: 3,
            ..Limits::default()
        };
        let source = "a = 1000\nb = 2000\nc = 3000\nd = 4000\n";
        let a = GenericAdapter.analyze(source, &limits).unwrap();
        assert_eq!(a.sites.len(), 3);
        assert!(a.truncated);
    }

    #[test]
    fn a_watermarked_line_survives_the_fallbacks_own_validation() {
        let source = "retries = 3000\nother = 1\n";
        let before = analyze(source);
        let site = &before.sites[0];
        let width = TagWidth::new(4).unwrap();
        let rendering = site
            .render(FormFamily::Add, 4, width, &Dialect::GENERIC)
            .expect("a decomposition of 3000");
        let start = source.find("3000").expect("the literal is in the source") as u32;
        let original = ByteSpan::new(start, start + "3000".len() as u32);
        let rendered = ByteSpan::new(start, start + rendering.len() as u32);
        let after = format!(
            "{}{rendering}{}",
            &source[..original.start as usize],
            &source[original.end as usize..]
        );
        assert_eq!(after, format!("retries = {rendering}\nother = 1\n"));
        let edit =
            Edit::new(0, original, rendering, FormFamily::Add, 4, width).with_rendered(rendered);
        let proof = GenericAdapter.validate(source, &after, &[edit]).unwrap();
        assert!(proof.is_complete(1, 0), "{proof:?}");
        // And the fallback's scanner reads the tag back out of the new file.
        let text = &after[rendered.start as usize..rendered.end as usize];
        let decoded = GenericAdapter
            .extract(text, FormFamily::Add, width)
            .expect("the form must decode");
        assert_eq!(decoded.code(), 4);
        assert_eq!(decoded.canonical_value(), "3000");
    }

    #[test]
    fn a_rendering_that_breaks_the_line_fails_validation() {
        let source = "retries = 3000\n";
        let before = analyze(source);
        let width = TagWidth::new(4).unwrap();
        let rendering = before.sites[0]
            .render(FormFamily::Add, 4, width, &Dialect::GENERIC)
            .unwrap();
        // Deliberately wrong: the span claims the rendering is where `3000` was,
        // but the file kept the original text, so nothing decodes.
        let edit = Edit::new(
            0,
            ByteSpan::new(10, 14),
            rendering,
            FormFamily::Add,
            4,
            width,
        )
        .with_rendered(ByteSpan::new(10, 14));
        let error = GenericAdapter
            .validate(source, source, &[edit])
            .expect_err("an unchanged file cannot prove an embedding");
        assert_eq!(error.code(), ErrorCode::InvalidWatermark);
    }

    #[test]
    fn hostile_input_stops_at_the_token_cap() {
        let source = format!("x = {};\n", "1 ".repeat(200_000).trim());
        let limits = Limits {
            max_nodes_per_tree: 100,
            ..Limits::default()
        };
        let a = GenericAdapter.analyze(&source, &limits).unwrap();
        assert_eq!(a.tokens.len(), 100);
        assert!(a.truncated);
        assert!(a.sites.len() <= 100);
    }
}
