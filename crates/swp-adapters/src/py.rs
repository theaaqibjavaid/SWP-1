//! Python.
//!
//! Three things make this grammar different enough from JavaScript to deserve
//! its own table rather than a few conditionals: newlines are tokens, an
//! assignment creates a binding without any declaration keyword, and adjacent
//! string literals concatenate without an operator.

use swp_core::canon::IdentRole;
use tree_sitter::{Language, Node};

use crate::dialect::Dialect;
use crate::js::SKIPPED;
use crate::ts::{in_list, Grammar, IdentQuery, Names};

const PY_STATEMENTS: &[&str] = &[
    "expression_statement",
    "assignment",
    "augmented_assignment",
    "annotated_assignment",
    "for_statement",
    "while_statement",
    "if_statement",
    "elif_clause",
    "else_clause",
    "try_statement",
    "except_clause",
    "finally_clause",
    "with_statement",
    "return_statement",
    "yield_statement",
    "import_statement",
    "import_from_statement",
    "future_import_statement",
    "global_statement",
    "nonlocal_statement",
    "assert_statement",
    "raise_statement",
    "delete_statement",
    "print_statement",
    "exec_statement",
    "break_statement",
    "continue_statement",
    "pass_statement",
    "function_definition",
    "class_definition",
    "decorated_definition",
    "match_statement",
];

const PY_SCOPES: &[&str] = &[
    "module",
    "function_definition",
    "class_definition",
    "lambda",
];

const PY_ATOMIC: &[&str] = &[
    "integer",
    "float",
    "string",
    "escape_interpolation",
    "interpolation",
];

const PY_KEYWORDS: &[&str] = &[
    "def", "class", "if", "elif", "else", "for", "while", "try", "except", "finally", "with", "as",
    "lambda", "return", "yield", "yield", "import", "from", "pass", "break", "continue", "global",
    "nonlocal", "assert", "del", "raise", "in", "is", "not", "and", "or", "async", "await",
    "match", "case", "print", "exec", "true", "false", "none",
];

/// Python has one genuine spelling pair — the two ways to write an inequality
/// between comparisons — and nothing else in the grammar offers a choice.
const PY_SYNONYMS: &[(&str, &str)] = &[("not", "NOT"), ("!", "NOT")];

fn py_statement(kind: &str) -> bool {
    in_list(PY_STATEMENTS, kind)
}

fn py_scope(kind: &str) -> bool {
    in_list(PY_SCOPES, kind)
}

fn py_atomic(kind: &str) -> bool {
    in_list(PY_ATOMIC, kind)
}

fn py_definition(kind: &str, field: Option<&str>) -> bool {
    field == Some("name") && matches!(kind, "function_definition" | "class_definition")
}

/// Python resolves a name to a local if the function binds it anywhere, so the
/// file-wide set from [`py_bindings`] answers the question the same way the
/// interpreter's symbol table does for the common cases.
///
/// `self` is the one exception worth naming: it is a parameter, so the general
/// rule would rename it, and renaming the receiver of every method in a file
/// makes a canonical form that no Python reader would recognize as a method. It
/// stays a free name.
pub(crate) fn py_role(q: &IdentQuery) -> IdentRole {
    if q.parent_kind == "attribute" && q.field == Some("attribute") {
        return IdentRole::MemberName;
    }
    if q.parent_kind == "keyword_argument" && q.field == Some("name") {
        return IdentRole::PropertyKey;
    }
    if matches!(q.parent_kind, "function_definition" | "class_definition")
        && q.field == Some("name")
    {
        return IdentRole::Free;
    }
    if q.text == "self" || q.text == "cls" {
        return IdentRole::Free;
    }
    if q.is_definition {
        return if q.depth == 0 {
            IdentRole::Free
        } else {
            IdentRole::Local
        };
    }
    if q.names.contains(q.text) {
        IdentRole::Local
    } else {
        IdentRole::Free
    }
}

/// `depth` is the stack budget from [`crate::ts::Grammar::scan_bindings`]: this
/// descent covers the whole file, so it is bounded rather than assuming a
/// candidate's source nests shallowly.
fn py_bindings(node: Node, source: &str, names: &mut Names, depth: u32) {
    if depth == 0 {
        return;
    }
    let kind = node.kind();
    if matches!(
        kind,
        "assignment" | "annotated_assignment" | "augmented_assignment"
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            collect_targets(left, source, names, depth);
        }
    }
    if matches!(kind, "for_statement") {
        if let Some(left) = node.child_by_field_name("left") {
            collect_targets(left, source, names, depth);
        }
    }
    if matches!(kind, "parameters") {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_targets(child, source, names, depth - 1);
        }
    }
    if matches!(kind, "as_pattern" | "with_clause" | "aliased_import") {
        if let Some(alias) = node.child_by_field_name("alias").or_else(|| node.child(0)) {
            collect_targets(alias, source, names, depth);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        py_bindings(child, source, names, depth - 1);
    }
}

/// The names a binding target introduces.
fn collect_targets(node: Node, source: &str, names: &mut Names, depth: u32) {
    if depth == 0 {
        return;
    }
    match node.kind() {
        "identifier" => names.add(&source[node.start_byte()..node.end_byte()]),
        "parameter" | "typed_parameter" | "typed_default_parameter" | "default_parameter" => {
            if let Some(name) = node.child_by_field_name("name") {
                collect_targets(name, source, names, depth);
            } else {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    collect_targets(child, source, names, depth - 1);
                }
            }
        }
        "list_pattern" | "tuple_pattern" | "dictionary_pattern" | "set_pattern"
        | "list_comprehension" | "pattern_list" | "list" | "tuple" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_targets(child, source, names, depth - 1);
            }
        }
        "keyword_argument" | "pair" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_targets(value, source, names, depth);
            }
        }
        _ => {}
    }
}

pub(crate) static PYTHON: Grammar = Grammar {
    name: "python",
    dialect: Dialect::PY,
    extensions: &["py", "pyi"],
    language: || Language::from(tree_sitter_python::LANGUAGE),
    skipped: SKIPPED,
    keywords: PY_KEYWORDS,
    is_statement: py_statement,
    is_scope: py_scope,
    is_atomic: py_atomic,
    is_definition: py_definition,
    role_of: py_role,
    scan_bindings: py_bindings,
    synonyms: PY_SYNONYMS,
    line_breaks: true,
};
