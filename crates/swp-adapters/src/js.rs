//! JavaScript and TypeScript.
//!
//! Both languages share one grammar family, so they share this table; the
//! TypeScript additions are kinds the ECMAScript grammar never produces, and they
//! are added rather than forked because a `.ts` file is a `.js` file with types.

use tree_sitter::Language;

use crate::dialect::Dialect;
use crate::ts::{in_list, Grammar, IdentQuery, Names};

/// Node kinds that carry no source structure for canonicalization purposes:
/// comments and interpreter directives. Dropping them here, rather than emitting
/// and filtering, is what makes L1 comment-insensitive for every level.
pub(crate) const SKIPPED: &[&str] = &["comment", "hash_bang_line"];

const JS_STATEMENTS: &[&str] = &[
    "expression_statement",
    "lexical_declaration",
    "variable_declaration",
    "return_statement",
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "throw_statement",
    "break_statement",
    "continue_statement",
    "labeled_statement",
    "with_statement",
    "empty_statement",
    "import_statement",
    "export_statement",
    "function_declaration",
    "generator_function_declaration",
    "class_declaration",
];

const JS_SCOPES: &[&str] = &[
    "program",
    "function_declaration",
    "generator_function_declaration",
    "function",
    "generator_function",
    "arrow_function",
    "method_definition",
    "class_body",
];

const JS_ATOMIC: &[&str] = &[
    "number",
    "string",
    "template_string",
    "regex",
    "escape_sequence",
];

const JS_KEYWORDS: &[&str] = &[
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "return",
    "throw",
    "try",
    "catch",
    "finally",
    "function",
    "class",
    "extends",
    "new",
    "delete",
    "typeof",
    "instanceof",
    "in",
    "of",
    "void",
    "this",
    "super",
    "async",
    "await",
    "yield",
    "static",
    "get",
    "set",
    "import",
    "export",
    "from",
    "as",
    "with",
    "var",
    "let",
    "const",
    "true",
    "false",
    "null",
    "undefined",
    "NaN",
    "public",
    "private",
    "protected",
    "readonly",
    "abstract",
    "interface",
    "type",
    "enum",
    "implements",
    "declare",
    "namespace",
    "module",
    "keyof",
    "infer",
    "satisfies",
    "any",
    "string_type",
    "number_type",
    "boolean_type",
    "never",
    "unknown",
];

/// `("a" && "b")` and `"a" and "b"` are not the same claim, so the equivalence
/// classes here stay inside one language's operator set, and there are only two
/// places in JavaScript where the grammar really offers a choice: loose and
/// strict equality. Referring to them as one class at L3 is what lets a scanner
/// match a copy that tightened `==` to `===`.
const JS_SYNONYMS: &[(&str, &str)] = &[("==", "EQ"), ("===", "EQ"), ("!=", "NEQ"), ("!==", "NEQ")];

fn js_statement(kind: &str) -> bool {
    in_list(JS_STATEMENTS, kind)
}

fn js_scope(kind: &str) -> bool {
    in_list(JS_SCOPES, kind)
}

fn js_atomic(kind: &str) -> bool {
    in_list(JS_ATOMIC, kind)
}

fn js_definition(kind: &str, field: Option<&str>) -> bool {
    field == Some("name")
        && matches!(
            kind,
            "function_declaration"
                | "generator_function_declaration"
                | "function"
                | "generator_function"
                | "class_declaration"
                | "class"
                | "method_definition"
        )
}

/// The one question L2 asks about a name: was it introduced here, or does it
/// come from somewhere the reader cannot see?
///
/// JavaScript's rules make most of the answer mechanical — a member name and an
/// object-literal key are not bindings at all. What needs judgement is a
/// definition: a module-level `function describe()` is the file's API and other
/// files call it by that spelling, so renaming it would make a canonical form
/// that no reader could recognize, while a function defined inside another
/// function is as local as a variable. That distinction is `depth`, which is the
/// number of enclosing scopes, so a name declared at the top of a module is
/// preserved and the same name declared inside a function is not.
pub(crate) fn js_role(q: &IdentQuery) -> swp_core::canon::IdentRole {
    use swp_core::canon::IdentRole;
    match q.kind {
        // `obj.member` and `#private` are property slots, not bindings.
        "property_identifier" | "shorthand_property_identifier" | "private_property_identifier" => {
            if q.parent_kind == "object_literal" || q.parent_kind == "pair" {
                IdentRole::PropertyKey
            } else {
                IdentRole::MemberName
            }
        }
        "identifier" if q.parent_kind == "pair" && q.field == Some("key") => IdentRole::PropertyKey,
        "identifier" if q.parent_kind == "method_definition" => IdentRole::MemberName,
        "type_identifier" => IdentRole::Free,
        "identifier" if q.parent_kind == "labeled_statement" => IdentRole::Label,
        "identifier" if q.parent_kind == "statement_block" => IdentRole::Label,
        _ => {
            if q.is_definition {
                // A definition's name: part of the module's surface at depth 0.
                return if q.depth == 0 {
                    IdentRole::Free
                } else {
                    IdentRole::Local
                };
            }
            if q.names.contains(q.text) {
                IdentRole::Local
            } else {
                // An import, a global, or a name from another module. Preserved
                // at every level, which is also what makes a cross-project copy
                // of `require("express")` still recognizable as one.
                IdentRole::Free
            }
        }
    }
}

/// Collect the names this file introduces.
///
/// Deliberately file-wide rather than block-scoped: what L2 needs is a
/// deterministic answer that the scanner computes the same way from a copy, not
/// a reimplementation of the temporal dead zone. A name that is *both* a local
/// here and a global there resolves to Local in both files, which is the
/// conservative direction — it renames, so it cannot create a false match, only
/// miss one that a name-sensitive key would have caught.
///
/// `depth` is the stack budget from [`crate::ts::Grammar::scan_bindings`]; the
/// descent covers the whole file, so it is bounded rather than trusting that no
/// source on someone's disk nests deeper than the machine can recurse.
fn js_bindings(node: tree_sitter::Node, source: &str, names: &mut Names, depth: u32) {
    if depth == 0 {
        return;
    }
    let kind = node.kind();
    if matches!(
        kind,
        "variable_declarator" | "assignment_expression" | "augmented_assignment_expression"
    ) {
        if let Some(target) = node.child_by_field_name("name").or_else(|| {
            if kind == "variable_declarator" {
                None
            } else {
                node.child(0)
            }
        }) {
            collect_pattern_names(target, source, names, depth);
        }
    }
    if matches!(
        kind,
        "formal_parameters"
            | "required_parameter"
            | "optional_parameter"
            | "catch_clause"
            | "arrow_function"
            | "function"
            | "function_expression"
            | "generator_function"
    ) {
        if kind == "formal_parameters" || kind == "catch_clause" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_pattern_names(child, source, names, depth);
            }
        } else if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.named_children(&mut cursor) {
                collect_pattern_names(child, source, names, depth);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        js_bindings(child, source, names, depth - 1);
    }
}

/// Every identifier a binding target introduces, minus the values behind `=`.
fn collect_pattern_names(node: tree_sitter::Node, source: &str, names: &mut Names, depth: u32) {
    if depth == 0 {
        return;
    }
    match node.kind() {
        "identifier" | "shorthand_property_identifier" => {
            names.add(&node_source(node, source));
        }
        // `{ a: local }` binds `local`, not `a`.
        "object_assignment_pattern" => {
            if let Some(right) = node.child_by_field_name("right") {
                collect_pattern_names(right, source, names, depth);
            }
        }
        "assignment_pattern" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_pattern_names(left, source, names, depth);
            }
        }
        "object_pattern" | "array_pattern" | "rest_pattern" | "assignment_expression" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_pattern_names(child, source, names, depth - 1);
            }
        }
        _ => {}
    }
}

fn node_source(node: tree_sitter::Node, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

pub(crate) static JAVASCRIPT: Grammar = Grammar {
    name: "javascript",
    dialect: Dialect::JS,
    extensions: &["js", "mjs", "cjs", "jsx"],
    language: || Language::from(tree_sitter_javascript::LANGUAGE),
    skipped: SKIPPED,
    keywords: JS_KEYWORDS,
    is_statement: js_statement,
    is_scope: js_scope,
    is_atomic: js_atomic,
    is_definition: js_definition,
    role_of: js_role,
    scan_bindings: js_bindings,
    synonyms: JS_SYNONYMS,
    line_breaks: false,
};

pub(crate) static TYPESCRIPT: Grammar = Grammar {
    name: "typescript",
    dialect: Dialect::TS,
    extensions: &["ts", "mts", "cts", "tsx"],
    language: || Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
    skipped: SKIPPED,
    keywords: JS_KEYWORDS,
    is_statement: js_statement,
    is_scope: js_scope,
    is_atomic: js_atomic,
    is_definition: js_definition,
    role_of: js_role,
    scan_bindings: js_bindings,
    synonyms: JS_SYNONYMS,
    line_breaks: false,
};
