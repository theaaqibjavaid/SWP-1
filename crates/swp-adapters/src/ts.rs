//! The shared tree-sitter walk.
//!
//! One walker turns a syntax tree into the abstract stream `swp-core` consumes.
//! A language supplies a [`Grammar`]: which node kinds are keywords, which are
//! statements, which construct a binding scope, which nodes are literal leaves,
//! and how to decide what an identifier *is*. That split is the whole reason
//! adding a language later is a table plus two small functions rather than a new
//! code path.
//!
//! # What the walk guarantees
//!
//! * Tokens are emitted in source order, do not overlap, and each token's `text`
//!   equals the source at its span. The canonicalizer slices by radius on that
//!   assumption, and `tests/token_stream.rs` checks it on the fixture projects.
//! * A literal is one atomic token, never its internals. A JavaScript `string`
//!   node contains `string_fragment` children and a Python one contains
//!   `string_start`/`string_content`/`string_end`; descending into either would
//!   put parts of one literal into the stream twice.
//! * Comments produce no tokens. L1 canonicalization is defined as
//!   comment-insensitive, so dropping them here makes every level behave the same
//!   in every adapter instead of depending on how a grammar exposes them.
//! * Radius spans come from the grammar, not from indentation or line numbers, so
//!   a reformatted copy of a function yields the same statement span for the same
//!   code.

use std::collections::BTreeSet;

use swp_core::canon::{ByteSpan, IdentRole, TokKind, Token};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::limits::Limits;
use tree_sitter::{Language, Node, TreeCursor};

use crate::analyze::{Analysis, AnalysisBuilder, Capabilities};
use crate::dialect::Dialect;
use crate::literal::{self, RefusalKind, SiteValue};
use crate::safety;

/// Everything a language has to say about its own syntax.
pub(crate) struct Grammar {
    pub name: &'static str,
    pub dialect: Dialect,
    pub extensions: &'static [&'static str],
    pub language: fn() -> Language,
    /// Node kinds that produce no token at all: comments and interpreter
    /// directives, which L1 is defined to ignore.
    pub skipped: &'static [&'static str],
    /// Reserved words, emitted as [`TokKind::Keyword`] rather than operators.
    pub keywords: &'static [&'static str],
    /// Node kinds that are statements: the innermost enclosing one is a site's
    /// statement radius.
    pub is_statement: fn(kind: &str) -> bool,
    /// Node kinds that open a binding scope: the innermost enclosing one is a
    /// site's scope radius.
    pub is_scope: fn(kind: &str) -> bool,
    /// Node kinds that must be emitted whole.
    pub is_atomic: fn(kind: &str) -> bool,
    /// Whether a node kind is a definition name (`function foo`), which is a
    /// binding the rest of the file refers to by that same spelling.
    pub is_definition: fn(kind: &str, field: Option<&str>) -> bool,
    /// How to classify an identifier leaf.
    pub role_of: fn(&IdentQuery) -> IdentRole,
    /// Collect the names this file binds locally.
    ///
    /// `depth` is the remaining recursion budget, which the caller seeds from
    /// [`Limits::max_depth`]. This pass descends the whole tree, so without a
    /// budget a candidate file holding one 5,000-term expression — which is
    /// ordinary minified output, and trivially hostile — overflows the stack and
    /// kills the scanner instead of reporting a limit. The main walk is bounded the
    /// same way; a file too deep to walk is also too deep to name-bind, so the
    /// two guards disagreeing would only lose information, never gain a false one.
    pub scan_bindings: fn(Node, &str, &mut Names, u32),
    /// Operators spelled more than one way, mapped to their L3 class, so that
    /// `!=` and `!==` canonicalize identically.
    pub synonyms: &'static [(&'static str, &'static str)],
    /// Whether a newline token carries grammar (Python) or is whitespace (JS).
    pub line_breaks: bool,
}

/// The node-kind tables are lists in reading order, not sets: a language's table
/// should look like the grammar's own documentation. Membership is a linear scan
/// over a few dozen names, once per node, which is cheaper than the hash of a
/// `HashSet` built per file.
pub(crate) fn in_list(list: &[&str], kind: &str) -> bool {
    list.contains(&kind)
}

/// The names a file binds, as decided by [`Grammar::scan_bindings`].
#[derive(Default)]
pub(crate) struct Names(BTreeSet<String>);

impl Names {
    pub(crate) fn add(&mut self, name: &str) {
        if !name.is_empty() && self.0.len() < 65_536 {
            self.0.insert(name.to_string());
        }
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.0.contains(name)
    }
}

/// What a role callback may look at: enough to apply a language's binding rules,
/// and nothing else, so an adapter author cannot reach back into the tree and
/// create a dependency the scanner would not reproduce.
pub(crate) struct IdentQuery<'a> {
    pub text: &'a str,
    /// The identifier's own node kind, e.g. `property_identifier`.
    pub kind: &'a str,
    pub parent_kind: &'a str,
    /// Which grammar field this node fills in its parent, if any.
    pub field: Option<&'a str>,
    /// Whether the identifier is the name being declared by a definition.
    pub is_definition: bool,
    /// How many scopes enclose this name: `0` is module level.
    pub depth: usize,
    pub names: &'a Names,
}

fn span_of(node: Node) -> ByteSpan {
    ByteSpan::new(node.start_byte() as u32, node.end_byte() as u32)
}

/// The node kinds that hold a call's arguments, one per grammar.
const ARGUMENT_LISTS: &[&str] = &["arguments", "argument_list"];

fn is_literal_kind(kind: TokKind) -> bool {
    matches!(kind, TokKind::Number | TokKind::String)
}

/// The kind an atomic node's text is recorded as.
fn atomic_kind(kind: &str) -> TokKind {
    match kind {
        "number" | "integer" | "float" => TokKind::Number,
        "string" => TokKind::String,
        "template_string" | "fstring" | "interpolation" => TokKind::Template,
        "regex" => TokKind::Regex,
        _ => TokKind::String,
    }
}

struct Walk<'g, 'a> {
    g: &'g Grammar,
    b: &'a mut AnalysisBuilder,
    source: &'a str,
    limits: &'a Limits,
    names: &'a Names,
    file: ByteSpan,
    statements: Vec<ByteSpan>,
    scopes: Vec<ByteSpan>,
    path: Vec<&'a str>,
    nodes: u32,
    errors: u32,
    stopped: bool,
}

impl<'g, 'a> Walk<'g, 'a> {
    fn visit(&mut self, node: Node<'a>) {
        if self.stopped {
            return;
        }
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes_per_tree
            || self.path.len() > self.limits.max_depth as usize
        {
            self.b.analysis.truncated = true;
            self.stopped = true;
            return;
        }
        let kind = node.kind();
        let span = span_of(node);
        if node.is_error() || node.is_missing() {
            self.errors += 1;
        }
        if self.g.skipped.contains(&kind) {
            return;
        }
        self.path.push(kind);
        let statement = (self.g.is_statement)(kind);
        let scope = (self.g.is_scope)(kind);
        if statement {
            self.statements.push(span);
            self.b.push_statement(span);
        }
        if scope {
            self.scopes.push(span);
            self.b.push_scope(span);
        }

        if (self.g.is_atomic)(kind) {
            self.emit_atomic(node);
        } else if node.child_count() == 0 {
            self.emit_leaf(node);
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                self.visit(child);
            }
        }

        if statement {
            self.statements.pop();
        }
        if scope {
            self.scopes.pop();
        }
        self.path.pop();
    }

    /// An atomic node contributes exactly one token: all of its source text.
    fn emit_atomic(&mut self, node: Node<'a>) {
        let kind = atomic_kind(node.kind());
        let span = span_of(node);
        let text = &self.source[span.start as usize..span.end as usize];
        let mut token = Token::new(kind, text, span);
        if let Some(v) = normalized_value(text, kind) {
            token.value = Some(v);
        }
        self.b.push_token(token);
        if !is_literal_kind(kind) {
            // A template string or a regex is not a plain literal: the reason
            // goes in the report so `swp status` can explain a thin constellation.
            let reason = match kind {
                TokKind::Template => RefusalKind::MultilineOrTemplate,
                _ => RefusalKind::NotALiteral,
            };
            self.b.push_refusal(span, reason, shorten(text));
            return;
        }
        if let Some(note) = self.position_hazard(node, kind) {
            self.b.push_refusal(span, RefusalKind::UnsafeContext, note);
            return;
        }
        match literal::parse_literal(text, kind, &self.g.dialect) {
            Ok(value) => {
                let (statement, scope, path) = self.context();
                self.b.push_site(span, value, statement, scope, path);
            }
            Err(reason) => self.b.push_refusal(span, reason, shorten(text)),
        }
    }

    /// Why the grammar says this literal is not a value, if it does.
    ///
    /// The ancestor path is taken from the walk rather than re-read from the tree
    /// because the walk is what defines it: a site's radius, its scope depth and
    /// its position are all facts about this one traversal, and asking the tree
    /// again would let the two disagree.
    fn position_hazard(&self, node: Node<'a>, kind: TokKind) -> Option<String> {
        let parent = node.parent();
        let (parent_kind, field, index) = match parent {
            Some(p) => {
                let index = position_in(p, node);
                (p.kind(), p.field_name_for_child(index as u32), index)
            }
            None => ("", None, 0),
        };
        let ctx = safety::SiteContext {
            path: &self.path,
            parent_kind,
            field,
            index,
            literal: kind,
            callee_kind: self.callee_kind(node),
            callee_text: self.callee_text(node),
        };
        safety::why_unsafe(&ctx).map(|note| {
            let breadcrumb = ctx.path.last().copied().unwrap_or("");
            format!("{note} (inside `{breadcrumb}`)")
        })
    }

    /// The callee of the call this literal is an argument of, as a node kind.
    ///
    /// A dynamic `import("./lazy")` is a call, so the grammar never marks its
    /// specifier as a source the way `import_statement` does; the callee's kind is
    /// what says "this argument names a module".
    fn callee_kind(&self, node: Node<'a>) -> &'static str {
        match self.callee(node) {
            Some(callee) => callee.kind(),
            None => "",
        }
    }

    fn callee_text(&self, node: Node<'a>) -> &'a str {
        match self.callee(node) {
            Some(callee) => {
                let span = span_of(callee);
                &self.source[span.start as usize..span.end as usize]
            }
            None => "",
        }
    }

    fn callee(&self, node: Node<'a>) -> Option<Node<'a>> {
        let list = node.parent()?;
        if !in_list(ARGUMENT_LISTS, list.kind()) {
            return None;
        }
        list.parent()?.child_by_field_name("function")
    }

    fn emit_leaf(&mut self, node: Node<'a>) {
        let kind = node.kind();
        let span = span_of(node);
        let text = &self.source[span.start as usize..span.end as usize];
        let class = classify(self.g, kind, text);
        let mut token = Token::new(class, text, span);
        match class {
            TokKind::Ident => {
                let parent = node.parent();
                let field = parent.and_then(|p| {
                    let index = position_in(p, node);
                    p.field_name_for_child(index as u32)
                });
                let parent_kind = parent.map(|p| p.kind()).unwrap_or("");
                token.role = (self.g.role_of)(&IdentQuery {
                    text,
                    kind,
                    parent_kind,
                    is_definition: (self.g.is_definition)(parent_kind, field),
                    depth: self.scopes.len().saturating_sub(1),
                    field,
                    names: self.names,
                });
            }
            TokKind::Operator => {
                if let Some((_, syn)) = self.g.synonyms.iter().find(|(sp, _)| *sp == kind) {
                    token.synonym = Some((*syn).to_string());
                }
            }
            _ => {}
        }
        self.b.push_token(token);
    }

    /// The radii and breadcrumb for the node being emitted. A literal outside
    /// any statement — a top-level expression in a script — takes the file for
    /// both, which is a weaker key, and the report says so rather than pretending.
    fn context(&self) -> (ByteSpan, ByteSpan, String) {
        let statement = self.statements.last().copied().unwrap_or(self.file);
        let scope = self.scopes.last().copied().unwrap_or(statement);
        let start = self.path.len().saturating_sub(5);
        (statement, scope, self.path[start..].join(";"))
    }
}

fn position_in(parent: Node, child: Node) -> usize {
    let mut cursor: TreeCursor = parent.walk();
    for (i, c) in parent.children(&mut cursor).enumerate() {
        if c.id() == child.id() {
            return i;
        }
    }
    usize::MAX
}

/// Parse and analyze one file with a grammar.
pub(crate) fn analyze(g: &Grammar, source: &str, limits: &Limits) -> Result<Analysis, SwpError> {
    if source.len() as u64 > limits.max_parse_bytes {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "a {} byte file exceeds the {} byte parse limit",
                source.len(),
                limits.max_parse_bytes
            ),
        ));
    }
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&(g.language)()).map_err(|e| {
        SwpError::new(
            ErrorCode::UnsupportedLanguage,
            format!("{} grammar unavailable: {e}", g.name),
        )
    })?;
    let Some(tree) = parser.parse(source, None) else {
        return Err(SwpError::new(
            ErrorCode::ParserFailure,
            format!("{} parser stopped on a {} byte file", g.name, source.len()),
        ));
    };
    let root = tree.root_node();
    let file = span_of(root);

    let mut names = Names::default();
    (g.scan_bindings)(root, source, &mut names, limits.max_depth);

    let mut b = AnalysisBuilder::new(g.name, Capabilities::AST, limits);
    b.set_file(file);
    let (nodes, errors) = {
        let mut walk = Walk {
            g,
            b: &mut b,
            source,
            limits,
            names: &names,
            file,
            statements: Vec::new(),
            scopes: Vec::new(),
            path: Vec::new(),
            nodes: 0,
            errors: 0,
            stopped: false,
        };
        walk.visit(root);
        (walk.nodes, walk.errors)
    };
    let mut analysis = b.finish();
    analysis.nodes = nodes;
    analysis.parse_errors = errors;
    Ok(analysis)
}

fn classify(g: &Grammar, kind: &str, text: &str) -> TokKind {
    if kind == "\n" || kind == "line_break" {
        return if g.line_breaks {
            TokKind::LineBreak
        } else {
            TokKind::Punct
        };
    }
    if kind == "identifier" || kind.ends_with("identifier") {
        return TokKind::Ident;
    }
    if g.keywords.contains(&kind) {
        return TokKind::Keyword;
    }
    // Anonymous word nodes (`if`, `function`) are keywords by table; a node whose
    // whole text is operator characters is an operator; everything structural —
    // brackets, commas, semicolons — is punctuation.
    if !text.is_empty() && text.chars().all(|c| "!%&*+-/<=>^|~?:".contains(c)) {
        return TokKind::Operator;
    }
    TokKind::Punct
}

/// The value the canonicalizer uses at L3, so a rewritten literal does not move
/// the shape of the code around it.
///
/// Python's unbounded integers are used as the interpretation of record even in
/// JavaScript files: the *canonical value* of `0x1F400` is 128000 whatever the
/// runtime would do with it. A float, a separator or an over-long literal has no
/// value here, and L3 keeps its spelling, which is the honest degradation.
fn normalized_value(text: &str, kind: TokKind) -> Option<String> {
    match kind {
        TokKind::Number => match literal::parse_integer(text, &Dialect::PY) {
            Ok(SiteValue::Integer(v)) => Some(v.to_string()),
            _ => None,
        },
        TokKind::String => match literal::parse_string(text, &Dialect::PY) {
            Ok(SiteValue::Text(s)) => Some(s.inner),
            _ => None,
        },
        _ => None,
    }
}

fn shorten(text: &str) -> String {
    const MAX: usize = 48;
    let count = text.chars().count();
    if count <= MAX {
        return text.to_string();
    }
    let kept: String = text.chars().take(MAX).collect();
    format!("{kept}…(+{} chars)", count - MAX)
}
