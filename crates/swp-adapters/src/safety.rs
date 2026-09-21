//! Which literal positions a rewrite may not touch.
//!
//! The form engine guarantees that a rendering *equals* the literal it replaces.
//! Equality is not the whole contract: a literal also has to be in a position
//! where an expression is allowed and where evaluating to the same value leaves
//! the program's meaning alone. A parser is what makes that question answerable,
//! which is why the checks live with the AST layer and not in the fallback — the
//! fallback has to refuse most positions outright instead.
//!
//! Every rule below is keyed on grammar node kinds and field names rather than on
//! language identity, so one table serves JavaScript, TypeScript and Python: a
//! node kind that only one grammar produces simply never appears in another's
//! walk. The one exception is a loader that a grammar spells as an ordinary
//! identifier (`require`), which has no shape to key on and so is matched by name.
//! Each rule costs at least one candidate site, and the refusals are reported by
//! name so the price of safety is visible in `swp status`.

use swp_core::canon::TokKind;

/// Where the literal being considered sits.
pub(crate) struct SiteContext<'a> {
    /// Node kinds from the document root down to and including the literal, in
    /// that order.
    pub path: &'a [&'a str],
    /// Kind of the literal's parent node, `""` if it has none.
    pub parent_kind: &'a str,
    /// Grammar field the literal fills in that parent, if any.
    pub field: Option<&'a str>,
    /// The literal's index among its parent's children.
    pub index: usize,
    pub literal: TokKind,
    /// Kind of the callee when the literal sits in a call's argument list, `""`
    /// otherwise. A dynamic `import()` is a call whose callee is the `import`
    /// keyword node, which is the only way to tell it apart from an ordinary
    /// call that happens to be named `import`.
    pub callee_kind: &'static str,
    /// Text of that callee, for the loaders a grammar spells as identifiers.
    pub callee_text: &'a str,
}

/// Why this position must not be rewritten, in the words a report prints.
pub(crate) fn why_unsafe(ctx: &SiteContext) -> Option<&'static str> {
    if ctx.path.iter().any(|k| k.contains("jsx_")) && ctx.parent_kind == "jsx_attribute" {
        return Some(
            "a JSX attribute, where the grammar accepts a quoted string or a braced expression \
             but not a parenthesized one",
        );
    }
    if ctx.field == Some("key") && ctx.parent_kind == "pair" {
        // `{ key: 1 }` and `{"a": 1}` put a literal in the key slot, where
        // parentheses are not valid syntax; Python dicts use the same node kind
        // for the same reason.
        return Some("an object or dict key, which is a name written as a literal, not a value");
    }
    if ctx.field == Some("source")
        || ctx
            .path
            .iter()
            .any(|k| k.starts_with("import_") || k.ends_with("import_statement"))
        || ctx.callee_kind == "import"
        || matches!(ctx.callee_text, "require" | "__import__")
    {
        return Some(
            "a module specifier, which names a module for the loader and for build tooling \
             rather than holding a value",
        );
    }
    if ctx
        .path
        .iter()
        .any(|k| *k == "type_annotation" || k.ends_with("_type") || k.ends_with("_qualifier"))
    {
        return Some("a type position, where a literal type is syntax and an expression is not");
    }
    if ctx.path.iter().any(|k| k.contains("pattern")) {
        return Some(
            "a match/case pattern, where the literal is a test and a parenthesized expression \
             would be a capture",
        );
    }
    if ctx.literal == TokKind::String
        && ctx.index == 0
        && matches!(ctx.parent_kind, "expression_statement" | "statement")
    {
        return Some(
            "a statement consisting of one string, which is a docstring or directive and so has \
             meaning beyond its value",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{why_unsafe, SiteContext};
    use crate::analyze::Analysis;
    use crate::literal::RefusalKind;
    use crate::ts::Grammar;
    use crate::{js, py};
    use swp_core::limits::Limits;

    fn with(grammar: &'static Grammar, source: &str) -> Analysis {
        crate::ts::analyze(grammar, source, &Limits::default()).expect("parse")
    }

    fn javascript(source: &str) -> Analysis {
        with(&js::JAVASCRIPT, source)
    }

    fn typescript(source: &str) -> Analysis {
        with(&js::TYPESCRIPT, source)
    }

    fn python(source: &str) -> Analysis {
        with(&py::PYTHON, source)
    }

    /// The spellings that became sites, in source order.
    fn sites<'a>(analysis: &Analysis, source: &'a str) -> Vec<&'a str> {
        analysis.sites.iter().map(|s| s.source(source)).collect()
    }

    /// The predicate reads node kinds, so a hand-built context shows the rule
    /// itself, without a grammar in the way.
    #[test]
    fn a_plain_expression_value_is_always_safe() {
        let value = SiteContext {
            path: &[
                "module",
                "function_definition",
                "return_statement",
                "integer",
            ],
            parent_kind: "return_statement",
            field: Some("argument"),
            index: 1,
            literal: swp_core::canon::TokKind::Number,
            callee_kind: "",
            callee_text: "",
        };
        assert_eq!(why_unsafe(&value), None);
        // The same number one step away from a value position is not.
        let key = SiteContext {
            path: &["module", "expression_statement", "pair", "integer"],
            parent_kind: "pair",
            field: Some("key"),
            ..value
        };
        assert!(why_unsafe(&key).is_some());
        let specifier = SiteContext {
            path: &["program", "import_statement", "string"],
            parent_kind: "import_statement",
            field: Some("source"),
            index: 2,
            literal: swp_core::canon::TokKind::String,
            ..value
        };
        assert!(why_unsafe(&specifier).is_some());
    }

    fn refused<'a>(analysis: &'a Analysis, source: &'a str) -> Vec<(&'a str, &'a str)> {
        analysis
            .refusals
            .iter()
            .filter(|r| r.kind == RefusalKind::UnsafeContext)
            .map(|r| {
                (
                    &source[r.span.start as usize..r.span.end as usize],
                    r.note.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn an_object_key_is_refused_and_its_value_is_not() {
        let source = "const config = { timeout: 30000, \"retries\": 4, 7: 'lucky' };\n";
        let a = javascript(source);
        // The `key` field is a name spelled as a literal in every grammar, and
        // parentheses are not valid there; the `value` field is an expression.
        assert_eq!(sites(&a, source), ["30000", "4", "'lucky'"]);
        let notes = refused(&a, source);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert_eq!(notes[0].0, "\"retries\"");
        assert_eq!(notes[1].0, "7");
        for (_, note) in &notes {
            assert!(note.contains("key"), "{note}");
        }
    }

    #[test]
    fn a_dict_key_is_refused_the_same_way_in_python() {
        let source = "config = {\"timeout\": 30000, \"retries\": 4}\n";
        let a = python(source);
        assert_eq!(sites(&a, source), ["30000", "4"]);
        let notes = refused(&a, source);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert_eq!(notes[0].0, "\"timeout\"");
        assert_eq!(notes[1].0, "\"retries\"");
    }

    #[test]
    fn a_module_specifier_is_refused_because_it_names_a_file() {
        let source = "import express from \"express\";\nimport(\"./lazy\");\nexport * from \"./re-export\";\nconst local = \"a value\";\n";
        let a = javascript(source);
        assert_eq!(sites(&a, source), ["\"a value\""]);
        let refused: Vec<_> = refused(&a, source).into_iter().map(|(t, _)| t).collect();
        assert_eq!(
            refused,
            ["\"express\"", "\"./lazy\"", "\"./re-export\""],
            "every specifier must be refused by name"
        );
    }

    #[test]
    fn a_require_call_is_refused_because_build_tooling_resolves_it() {
        // `require` is an ordinary identifier to the grammar, so only its name
        // says that the string inside it is a module rather than a value. A
        // bundler that cannot read the specifier stops putting the module in the
        // bundle, which is a broken build, not a preserved meaning.
        let source = "const fs = require(\"node:fs\");\nconst helper = load(\"./helper\");\n";
        let a = javascript(source);
        assert_eq!(sites(&a, source), ["\"./helper\""]);
        assert_eq!(refused(&a, source).len(), 1);
    }

    #[test]
    fn a_docstring_or_directive_is_not_a_value() {
        let source =
            "\"use strict\";\nfunction read() {\n  \"a bare statement\";\n  return 12;\n}\n";
        let a = javascript(source);
        assert_eq!(sites(&a, source), ["12"]);
        let notes = refused(&a, source);
        assert_eq!(notes.len(), 2, "{notes:?}");
        for (text, note) in &notes {
            assert!(note.contains("docstring or directive"), "{text}: {note}");
        }
        assert_eq!(notes[0].0, "\"use strict\"");
        assert_eq!(notes[1].0, "\"a bare statement\"");
    }

    #[test]
    fn a_python_docstring_keeps_its_module_documentation_intact() {
        let source = "def helper():\n    \"\"\"Explain the helper.\"\"\"\n    return 2500\n";
        let a = python(source);
        assert_eq!(sites(&a, source), ["2500"]);
        assert!(sites(&a, source).iter().all(|s| !s.contains('\"')));
    }

    #[test]
    fn a_match_pattern_is_a_test_not_an_expression() {
        let source = "def classify(code):\n    match code:\n        case 404:\n            return 1004\n        case _:\n            return 1005\n";
        let a = python(source);
        let values = sites(&a, source);
        assert!(values.contains(&"1004"), "{values:?}");
        assert!(!values.contains(&"404"), "{values:?}");
    }

    #[test]
    fn a_type_position_is_syntax_rather_than_a_value() {
        let source = "const flag: true = true;\nconst size: 12 = 12;\n";
        let a = typescript(source);
        assert_eq!(sites(&a, source), ["12"]);
    }

    #[test]
    fn a_jsx_attribute_is_refused_but_a_braced_expression_is_not() {
        let source = "const view = <Panel title=\"Dashboard\" rows={3000} label={\"x\"} />;\n";
        let a = javascript(source);
        assert_eq!(sites(&a, source), ["3000", "\"x\""]);
        let notes = refused(&a, source);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(notes[0].0, "\"Dashboard\"");
    }

    #[test]
    fn an_ordinary_value_in_a_realistic_file_stays_available() {
        // The mirror image of the rules above: none of this is a key, a pattern,
        // a specifier, a type or a directive, so a scan must find all of it.
        let source = "function describe(kind, value) {\n  const limit = 120000;\n  if (value > limit) {\n    console.log(kind + \" is over the limit of \" + limit);\n    return 2;\n  }\n  return 1 + 1;\n}\n";
        let a = javascript(source);
        assert_eq!(a.parse_errors, 0);
        let values = sites(&a, source);
        for expected in ["120000", "\" is over the limit of \"", "2", "1", "1"] {
            assert!(
                values.contains(&expected),
                "{expected} missing from {values:?}"
            );
        }
    }
}
