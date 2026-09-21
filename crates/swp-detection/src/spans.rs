//! Finding the *shape* a watermark can hide in.
//!
//! Pass one of a scan (`swp-embedding`'s candidate harvest, reused here) offers
//! one hypothesis per file: every literal token is a possible site. That is the
//! right hypothesis list for a *writer* — a writer only ever rewrites a literal —
//! and the wrong one for a *reader*, because the writer's output is not always a
//! literal any more:
//!
//! ```text
//! return base * 1000;              the source as written   — one Number token
//! return base * (995 + 5);         the source as shipped   — five tokens, no literal *at the site*
//! ```
//!
//! A protected copy therefore has no token at the site whose span is the site.
//! The keyed location ids are computed with the site *hidden* and replaced by
//! `<SITE>` (`swp-core::radius`), so the detector needs the span of the whole
//! rendering — `( 995 + 5 )` — to reproduce them. This module enumerates the
//! spans that a rendering could occupy.
//!
//! ## The rule, and why it is token-kind-only
//!
//! A candidate window is a balanced, whitespace-tolerant run of *form material*:
//!
//! - it contains at least two tokens, and at least one literal,
//! - every token in it is a literal, an operator, or punctuation,
//! - it begins at a literal or an opening bracket and ends at a literal or a
//!   closing bracket, and brackets are balanced inside it, never going negative.
//!
//! A lone literal is therefore not a window — with one exception, spelled out at
//! [`form_windows`]: the scan pass refuses a string containing a backslash, so the
//! escape family's own output would otherwise be hypothesized by neither pass.
//!
//! Nothing in that list names a language, an operator character, or a family. That
//! is deliberate: the adapter layer already decided which token is a literal and
//! which is punctuation, so this rule stays correct for a grammar that is added
//! later, and a new rendering family needs no change here as long as it is spelled
//! out of material the source already has.
//!
//! It is also *only* a hypothesis generator. Every window it produces is keyed into
//! a location id and looked up in a signed manifest; a window that matches nothing
//! is dropped. So being generous here costs a little time and cannot produce a
//! false hit, which is why the rule is "plausible shape" rather than "the exact
//! bytes `render_number` emits". The strictness that keeps false positives down
//! lives where it belongs — in [`swp_adapters::forms::decode_number`], which
//! refuses any text that is not precisely one rendering family's shape.
//!
//! ## Bounds
//!
//! [`MAX_FORM_TOKENS`] caps a window's length, [`MAX_WINDOWS_PER_FILE`] caps how
//! many hypotheses one file may contribute. The first is a protocol fact — the
//! widest rendering this version emits is five tokens — and the second is work
//! conservation: a 4 MiB file of densely packed arithmetic could otherwise produce
//! millions of digests to look up. A file that hits the second bound is reported
//! as scanned-with-a-caveat rather than skipped.

use std::collections::BTreeSet;

use swp_adapters::Analysis;
use swp_core::canon::{ByteSpan, TokKind, Token};

/// Longest token run a rendering can be.
///
/// The widest form this version of the protocol emits is `( a + b )` — five
/// tokens, including both brackets — so six admits one token of slack for a
/// spelling the adapter produced rather than the one this tool wrote. Anything
/// longer is not a watermark, and a generous bound here costs a hash and a lookup
/// per extra window, which is why the slack is one token rather than ten.
pub const MAX_FORM_TOKENS: usize = 6;

/// Hypothesis ceiling per file, which is what keeps a pathological arithmetic
/// expression from dominating a scan.
pub const MAX_WINDOWS_PER_FILE: usize = 20_000;

/// One span worth asking the manifest about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Window {
    pub span: ByteSpan,
    /// How many tokens it covers, for the report's "what did you try" figure.
    pub tokens: u8,
}

/// Every span in `analysis` that a rendered literal could occupy.
///
/// Single-token windows are excluded, with one exception below: a lone literal is
/// already offered as a candidate by the scan pass, and returning it here would
/// mean hashing it twice.
pub fn form_windows(analysis: &Analysis) -> (Vec<Window>, bool) {
    let tokens = &analysis.tokens;
    let mut out: BTreeSet<Window> = BTreeSet::new();
    let mut truncated = false;

    // The exception: the scan pass *refuses* a string literal that contains a
    // backslash, because a writer must not re-escape one — and so a literal the
    // escape family wrote is offered by nobody but this function. Without these,
    // every `str-escape` site would be written, signed, and then reported absent.
    // The predicate is the renderer's own spelling (`\xHH`, one or more, as a
    // prefix), not a general "has any escape", because that keeps the extra
    // hashing to the shape this tool can actually have produced.
    for token in tokens {
        if !is_escape_prefix(token) {
            continue;
        }
        if out.len() >= MAX_WINDOWS_PER_FILE {
            truncated = true;
            break;
        }
        out.insert(Window {
            span: token.span,
            tokens: 1,
        });
    }

    let mut start = 0usize;
    while start < tokens.len() {
        if truncated {
            break;
        }
        if !is_material(tokens[start].kind) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < tokens.len() && is_material(tokens[end].kind) {
            end += 1;
        }
        // `end` is now the first token outside the run.
        'run: for a in start..end {
            if !is_head(&tokens[a]) {
                continue;
            }
            let mut depth: i32 = 0;
            let limit = end.min(a + MAX_FORM_TOKENS);
            for b in a..limit {
                depth += bracket_delta(&tokens[b]);
                if depth < 0 {
                    break;
                }
                if b == a || depth != 0 || !is_tail(&tokens[b]) {
                    continue;
                }
                let window = Window {
                    span: ByteSpan::new(tokens[a].span.start, tokens[b].span.end),
                    tokens: (b - a + 1) as u8,
                };
                if out.len() >= MAX_WINDOWS_PER_FILE {
                    // Stopping, not skipping: continuing would re-test the bound
                    // for every remaining span in the file and add nothing.
                    truncated = true;
                    break 'run;
                }
                out.insert(window);
            }
        }
        start = end + 1;
    }
    (out.into_iter().collect(), truncated)
}

/// A token a rendering could be spelled out of.
fn is_material(kind: TokKind) -> bool {
    matches!(kind, TokKind::Number | TokKind::String | TokKind::Operator | TokKind::Punct)
}

fn is_literal(kind: TokKind) -> bool {
    matches!(kind, TokKind::Number | TokKind::String)
}

const OPENERS: [&str; 3] = ["(", "[", "{"];
const CLOSERS: [&str; 3] = [")", "]", "}"];

fn is_opener(token: &Token) -> bool {
    token.kind == TokKind::Punct && OPENERS.contains(&token.text.as_str())
}

fn is_closer(token: &Token) -> bool {
    token.kind == TokKind::Punct && CLOSERS.contains(&token.text.as_str())
}

/// Where a window may begin: a literal, or a bracket it must then close.
fn is_head(token: &Token) -> bool {
    is_literal(token.kind) || is_opener(token)
}

/// Does this token read as `"<prefix of \xHH escapes>…`, the shape
/// [`swp_adapters::forms`] writes for the string-escape family?
///
/// The two quote characters and the `\x` spelling come from the renderer, not from
/// a grammar, so this stays correct for a language added later. `\n` and `é` are
/// not it: a literal that begins any other way is not a rendering this tool can
/// have written, and `decode_string` would refuse it a token later anyway.
fn is_escape_prefix(token: &Token) -> bool {
    if token.kind != TokKind::String {
        return false;
    }
    let text = token.text.as_str();
    let Some(body) = text
        .strip_prefix('"')
        .or_else(|| text.strip_prefix('\''))
    else {
        return false;
    };
    body.starts_with("\\x")
}

fn is_tail(token: &Token) -> bool {
    is_literal(token.kind) || is_closer(token)
}

fn bracket_delta(token: &Token) -> i32 {
    if is_opener(token) {
        1
    } else if is_closer(token) {
        -1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_adapters::Registry;
    use swp_core::limits::Limits;

    fn windows_of(rel: &str, text: &str) -> Vec<String> {
        let registry = Registry::standard();
        let analysis = registry
            .analyze(std::path::Path::new(rel), text, &Limits::default())
            .unwrap();
        form_windows(&analysis)
            .0
            .into_iter()
            .map(|w| {
                let s = w.span.start as usize;
                let e = w.span.end as usize;
                text[s..e].to_string()
            })
            .collect()
    }

    #[test]
    fn an_addition_rendering_is_found_inside_bigger_arithmetic() {
        // The exact shape of a protected line: the rendering sits mid-expression,
        // preceded by an operator and followed by a semicolon, both of which the
        // maximal material run would include.
        let text = "function calc(base) {\n  return base * (995 + 5);\n}\n";
        let found = windows_of("a.js", text);
        assert!(found.contains(&"(995 + 5)".to_string()), "{found:?}");
        assert!(found.contains(&"995 + 5".to_string()), "the unparenthesised spelling is a plausible re-rendering of the same site");
        assert!(
            !found.iter().any(|w| w.starts_with('*') || w.ends_with(';')),
            "a window may not begin at an operator or end at punctuation: {found:?}"
        );
    }

    #[test]
    fn string_concatenation_and_adjacency_shapes_are_both_found() {
        let js = "const label = (\"hello\" + \"world\");\n";
        let found = windows_of("a.js", js);
        assert!(found.contains(&"(\"hello\" + \"world\")".to_string()), "{found:?}");
        assert!(found.contains(&"\"hello\" + \"world\"".to_string()), "{found:?}");

        let py = "label = (\"hello\" \"world\")\n";
        let found = windows_of("a.py", py);
        assert!(found.contains(&"(\"hello\" \"world\")".to_string()), "{found:?}");
        assert!(found.contains(&"\"hello\" \"world\"".to_string()), "{found:?}");
    }

    #[test]
    fn a_lone_literal_produces_no_window() {
        // That literal is already a candidate site in pass one; repeating it here
        // would double the hashing for every literal in the tree.
        let found = windows_of("a.js", "const x = 1000;\nconst s = \"plain\";\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_escaped_string_is_a_window_even_though_it_is_one_token() {
        // The shape `str-escape` actually writes. The scan pass refuses it (a
        // backslash means source text and decoded value differ), so if this
        // function skipped it as a lone literal, a protected site would be
        // unwritable-in-theory-but-signed-and-then-reported-absent. That is a
        // real defect this test exists to keep fixed.
        let text = "const s = \"\\x68\\x65llo\";\n";
        let found = windows_of("a.js", text);
        assert_eq!(found, vec!["\"\\x68\\x65llo\"".to_string()], "{found:?}");
    }

    #[test]
    fn only_the_renderers_own_escape_spelling_gets_that_treatment() {
        // `\n` is an escape a person writes, not one this tool emits, and a plain
        // backslash mid-text is not a prefix at all. Offering them would mean
        // hashing every escaped string in every file to prove nothing.
        for (text, why) in [
            ("const s = \"a\\nb\";\n", "short escape first"),
            ("const s = \"a\\x62\";\n", "escape not a prefix"),
            ("const s = '\\x68ello';\n", "single quote is fine, so expect a window"),
        ] {
            let found = windows_of("a.js", text);
            let starts_with_escape = found
                .iter()
                .any(|w| w.starts_with("\"\\x") || w.starts_with("'\\x"));
            if why.contains("so expect a window") {
                assert!(starts_with_escape, "{text} → {found:?}");
            } else {
                assert!(
                    found.is_empty(),
                    "{text} ({why}) should offer nothing and offered {found:?}"
                );
            }
        }
    }

    #[test]
    fn the_escape_exception_is_not_language_specific() {
        // The renderer emits this shape in every dialect that has a string type,
        // and the predicate above reads the token's own text, so a Python file is
        // covered by the same twelve lines as a JavaScript one.
        let found = windows_of("a.py", "label = \"\\x68\\x65llo\"\n");
        assert_eq!(found, vec!["\"\\x68\\x65llo\"".to_string()], "{found:?}");
    }

    #[test]
    fn unbalanced_and_identifier_bearing_runs_are_not_offered() {
        let found = windows_of("a.js", "const x = a[0] + b[1];\n");
        assert!(
            !found.iter().any(|w| w.contains("a[0]")),
            "identifiers break the run, so this is not a rendering shape: {found:?}"
        );
        for w in &found {
            let opens = w.matches('(').count();
            let closes = w.matches(')').count();
            assert_eq!(opens, closes, "offered window {w:?} is unbalanced");
        }
    }

    #[test]
    fn a_group_nested_inside_another_is_offered_even_though_the_outer_one_is_not() {
        // `(1000 + 5)` is the rendering; the extra parentheses around it are the
        // copier's own code. The inner span is what has to be found, and the outer
        // one is deliberately absent: at twelve tokens it is past
        // [`MAX_FORM_TOKENS`], and no form this protocol emits is that wide, so
        // offering it would buy hashing cost and a wider coincidence surface.
        let text = "const v = ((1000 + 5) * (2 + 3));\n";
        let found = windows_of("a.js", text);
        assert!(found.iter().any(|w| w == "(1000 + 5)"), "{found:?}");
        assert!(found.iter().any(|w| w == "(2 + 3)"), "{found:?}");
        assert!(
            !found.iter().any(|w| w == "((1000 + 5) * (2 + 3))"),
            "{found:?}"
        );
    }

    #[test]
    fn the_window_bound_is_a_caveat_rather_than_a_silent_truncation() {
        // A generated file, which is the shape that produces a huge hypothesis
        // count without nesting past the depth limit: each line is shallow, and
        // each paren tower contributes more windows than sites.
        let mut text = String::new();
        for i in 0..11_000 {
            text.push_str(&format!("const v{i} = (({i}));\n"));
        }
        let registry = Registry::standard();
        // Raised, not default: the per-file site ceiling would truncate the
        // analysis first, and then this would be a test of a different limit.
        let limits = Limits {
            max_sites_per_file: 20_000,
            ..Limits::default()
        };
        let analysis = registry
            .analyze(std::path::Path::new("a.js"), &text, &limits)
            .unwrap();
        assert!(
            !analysis.truncated,
            "the file has to be one the adapters fully walked, or this proves nothing"
        );
        let (found, truncated) = form_windows(&analysis);
        assert_eq!(found.len(), MAX_WINDOWS_PER_FILE, "{:?}", found.len());
        assert!(truncated, "a capped hypothesis list must report the cap");
    }

    #[test]
    fn windows_are_ordered_and_deduplicated() {
        let text = "const a = (1 + 2);\nconst b = (1 + 2);\n";
        let registry = Registry::standard();
        let analysis = registry
            .analyze(std::path::Path::new("a.js"), text, &Limits::default())
            .unwrap();
        let (found, _) = form_windows(&analysis);
        assert!(found.windows(2).all(|w| w[0] < w[1]), "{found:?}");
        // Two identical spellings at different offsets are different spans, and
        // must both be offered — one of them may be the site.
        assert_eq!(found.len(), 4, "{found:?}");
    }
}
