//! §45: a candidate project is untrusted, so its shape is an attack surface.
//!
//! These tests feed the adapters inputs chosen to be pathological — one enormous
//! expression, deep nesting, a long single line — and require the same answer of
//! each: the analysis finishes, it says what it could not see, and it does not
//! abort the process. A crash is the worst possible outcome for a scanner, because
//! it is indistinguishable from a refusal to scan at all.

use std::path::Path;

use swp_adapters::{Analysis, Registry};
use swp_core::limits::Limits;

fn analyze(rel: &str, source: &str, limits: &Limits) -> Analysis {
    Registry::standard()
        .analyze(Path::new(rel), source, limits)
        .expect("a hostile file is a truncated analysis, not an error")
}

/// A left-nested operator chain: each term adds one level to the tree, so N terms
/// mean a recursion N deep in every whole-tree pass.
fn chain(terms: usize) -> String {
    let mut out = String::from("const x = 0");
    for i in 0..terms {
        out.push_str(&format!(" + ({i} + {i})"));
    }
    out.push_str(";\n");
    out
}

#[test]
fn a_five_thousand_term_expression_is_truncated_rather_than_fatal() {
    // This is the shape of minified or generated JavaScript, and also the shape of
    // a file written to stop a scanner from ever reporting on it.
    let source = chain(5_000);
    let analysis = analyze("hostile.js", &source, &Limits::default());
    assert!(
        analysis.truncated,
        "a tree past the depth limit must say so, not silently return the prefix it walked"
    );
    // Some tokens came out, which is what makes the answer partial rather than
    // empty — the report distinguishes the two.
    assert!(!analysis.tokens.is_empty());
}

#[test]
fn a_deeply_nested_python_pattern_survives_its_own_binding_scan() {
    let source = format!(
        "def f():\n    x = {}\n",
        "[ ".repeat(5_000) + "1" + &" ]".repeat(5_000)
    );
    let analysis = analyze("hostile.py", &source, &Limits::default());
    assert!(analysis.truncated || !analysis.tokens.is_empty());
}

#[test]
fn one_unbounded_line_does_not_defeat_the_fallback_lexer() {
    let source = format!("x = {}\n", "1+".repeat(200_000));
    let analysis = analyze("hostile.unknownext", &source, &Limits::default());
    assert!(
        analysis.truncated || analysis.tokens.len() > 1,
        "the lexical path has no recursion to overflow, so it should just work"
    );
}

#[test]
fn a_lower_depth_limit_lowers_what_is_walked_and_says_so() {
    // A chain that is deep but well inside the default limit, so the two runs
    // differ only by the configured number.
    let source = chain(100);
    let tight = Limits {
        max_depth: 8,
        ..Limits::default()
    };
    let loose = analyze("a.js", &source, &Limits::default());
    let limited = analyze("a.js", &source, &tight);
    assert!(limited.truncated);
    assert!(
        limited.tokens.len() < loose.tokens.len(),
        "the limit has to actually stop the walk, not just flag it afterwards"
    );
}
