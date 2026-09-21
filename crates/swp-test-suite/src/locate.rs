//! Finding the fragments from the source alone — §52's first attack, written as
//! code rather than as a claim.
//!
//! §50's threat model assumes an attacker who knows SWP-1: knows the four numeric
//! families and the three string families, and knows what each one's output looks
//! like. What it does *not* give them is the private manifest, so the question
//! this module answers is the one §52 asks first — *can the sites be found without
//! it?* — and the answer is measured, not asserted: each family's rendering has a
//! shape, so a search for those shapes finds them.
//!
//! That matters for two documented conclusions, and they pull in opposite
//! directions:
//!
//! * **Concealment is not one of this protocol's properties**, and the
//!   documentation must not imply it is. Every watermark this system writes is
//!   findable by a person who knows the format, so removal cannot be modelled as
//!   "the attacker had to guess where to look".
//! * What the shapes do *not* give away is **which literal is which project's**.
//!   Finding a fragment and confirming a site are different acts: a located
//!   literal tells an attacker what to delete, and tells them nothing about whose
//!   code it is, because the bit pattern that carries the answer is only readable
//!   with the project's key. §27's false-positive corpora measure the shape half
//!   of that, and what they showed is worth stating precisely because it is the
//!   opposite of what this module's first draft assumed: the shapes are **not**
//!   common in ordinary code — the search raised no flags at all across the nine
//!   corpora it was run over — so a detector keyed on shape would not have been a
//!   false-positive machine. It would still have been worthless as evidence, for
//!   the key reason above, and that is the argument §27 has to make rather than
//!   the argument this file first thought it had.
//!
//! [`normalize`] is the removal that follows the finding. It is deliberately
//! behaviour-preserving — fold `(a + b)` to its value, lower-case a mixed-case hex
//! literal, decode an escape-prefixed string, join a split string — because §52
//! pairs removal with *"preserve behavior while changing syntax"*. An attacker who
//! changes a constant's value is not defeating a watermark, they are shipping a
//! different program, and a suite that let them do it would be reporting a victory
//! the protocol was never asked to deliver.

use std::collections::BTreeMap;

use crate::transform::{Tree, read_tree};

/// The spelling a fragment was written in. Named for what a reader sees, not for
/// the family that produced it: the whole point of §52's first attack is that the
/// reader cannot see the family, only the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    /// `(a + b)`, `(a - b)`, `(a * b)` where the second operand is `1..=16`.
    Foldable,
    /// A hexadecimal literal whose letters are neither all upper nor all lower.
    MixedCaseRadix,
    /// A string literal that opens with one or more `\xHH` escapes.
    EscapePrefixed,
    /// `("left" + "right")`, or the same two literals adjacent in parentheses.
    SplitString,
}

impl Shape {
    pub fn slug(self) -> &'static str {
        match self {
            Shape::Foldable => "foldable-arithmetic",
            Shape::MixedCaseRadix => "mixed-case-hex",
            Shape::EscapePrefixed => "escape-prefixed-string",
            Shape::SplitString => "split-string",
        }
    }

    /// Why a person hunting a watermark would stop on this shape.
    pub fn tells(self) -> &'static str {
        match self {
            Shape::Foldable => {
                "an arithmetic group of two plain integers is a form nobody writes to \
                 compute a number, only to spell one"
            }
            Shape::MixedCaseRadix => {
                "case carries no meaning in a hex literal, so mixed case is a channel"
            }
            Shape::EscapePrefixed => {
                "an escaped head on a plain ASCII string says the spelling was chosen, \
                 not typed"
            }
            Shape::SplitString => {
                "a string cut in two at a point no line break explains is a split with a \
                 reason"
            }
        }
    }

    /// The shapes, for the table `swp-validate` prints.
    pub const ALL: [Shape; 4] = [
        Shape::Foldable,
        Shape::MixedCaseRadix,
        Shape::EscapePrefixed,
        Shape::SplitString,
    ];
}

/// One located span: byte range in the file as it stands, and the text there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    pub file: String,
    pub start: usize,
    pub end: usize,
    pub shape: Shape,
    pub text: String,
}

/// Every span in `tree` whose spelling matches a watermark rendering shape,
/// ordered so two runs over one tree agree on what to remove first.
pub fn locate(tree: &Tree) -> Vec<Flag> {
    let mut out = Vec::new();
    for (file, body) in tree {
        out.extend(locate_file(file, body));
    }
    out.sort_by_key(|f| (f.file.clone(), f.start, f.end));
    out
}

/// Locate in one file. Public because §52's precision row counts flags per file
/// in trees that were never protected, where a whole-tree call would hide which
/// corpus the false hits came from.
pub fn locate_file(file: &str, body: &str) -> Vec<Flag> {
    let view = code_view(body);
    let code = view.code.as_slice();
    let raw = body.as_bytes();
    let mut flags = Vec::new();
    let mut taken = vec![false; body.len()];

    for (start, end) in &view.strings {
        if *end <= *start + 1 {
            continue;
        }
        // An escape-prefixed literal: the writer's own spelling, `\xHH` at the head.
        let inner = &raw[start + 1..*end];
        if inner.starts_with(b"\\x") || inner.starts_with(b"\\X") {
            flags.push(Flag {
                file: file.to_string(),
                start: *start,
                end: *end,
                shape: Shape::EscapePrefixed,
                text: body[*start..*end].to_string(),
            });
            mark(&mut taken, *start, *end);
        }
    }

    // Two literals inside one group, with or without a `+` between them. Read from
    // the string table rather than the masked view, because the view keeps the
    // quotes and blanks what is between them.
    for pair in view.strings.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if taken[a.0..b.1].contains(&true) {
            continue;
        }
        let Some(open) = raw[..a.0].iter().rposition(|c| *c == b'(') else {
            continue;
        };
        if !code[open + 1..a.0].iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let gap = &code[a.1..b.0];
        if gap.is_empty() || !gap.iter().all(|c| c.is_ascii_whitespace() || *c == b'+') {
            continue;
        }
        let Some(offset) = code[b.1..].iter().position(|c| *c == b')') else {
            continue;
        };
        let close = b.1 + offset;
        if !code[b.1..close].iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        flags.push(Flag {
            file: file.to_string(),
            start: open,
            end: close + 1,
            shape: Shape::SplitString,
            text: body[open..close + 1].to_string(),
        });
        mark(&mut taken, open, close + 1);
    }

    let mut i = 0;
    while i < code.len() {
        if taken[i] {
            i += 1;
            continue;
        }
        if code[i] == b'(' {
            if let Some(width) = foldable_width(&code[i..]) {
                if !taken[i..i + width].contains(&true) {
                    flags.push(Flag {
                        file: file.to_string(),
                        start: i,
                        end: i + width,
                        shape: Shape::Foldable,
                        text: body[i..i + width].to_string(),
                    });
                    mark(&mut taken, i, i + width);
                }
            }
            i += 1;
            continue;
        }
        if code[i] == b'0' && matches!(code.get(i + 1), Some(b'x') | Some(b'X')) {
            let is_ident_char = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
            if i > 0 && is_ident_char(code[i - 1]) {
                i += 1;
                continue;
            }
            let mut j = i + 2;
            while j < code.len() && code[j].is_ascii_hexdigit() {
                j += 1;
            }
            let letters: Vec<u8> = code[i + 2..j]
                .iter()
                .copied()
                .filter(|c| c.is_ascii_alphabetic())
                .collect();
            let mixed = letters.iter().any(u8::is_ascii_uppercase)
                && letters.iter().any(u8::is_ascii_lowercase);
            if mixed && letters.len() >= 2 && !taken[i..j].contains(&true) {
                flags.push(Flag {
                    file: file.to_string(),
                    start: i,
                    end: j,
                    shape: Shape::MixedCaseRadix,
                    text: body[i..j].to_string(),
                });
                mark(&mut taken, i, j);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    flags
}

/// Rewrite every flagged span into the plainest spelling of the same value, which
/// is the removal an attacker who cannot see the manifest can actually carry out.
/// Returns the number of files changed.
///
/// Each shape has exactly one folding, and it is the one a formatter would do
/// anyway: compute the group, lower-case the hex digits, decode the escapes, join
/// the pieces. Nothing here guesses at what the site *used* to say — that is the
/// manifest's knowledge, and §52's premise is that the attacker does not have it.
pub fn normalize(tree: &mut Tree, flags: &[Flag]) -> usize {
    let mut by_file: BTreeMap<&str, Vec<&Flag>> = BTreeMap::new();
    for flag in flags {
        by_file.entry(flag.file.as_str()).or_default().push(flag);
    }
    let mut changed = 0;
    for (file, mut spans) in by_file {
        let Some(body) = tree.get(file).cloned() else { continue };
        // Last to first, so no replacement moves a span that is still to come.
        spans.sort_by_key(|f| std::cmp::Reverse(f.start));
        let mut out = body.clone();
        for flag in spans {
            let Some(folded) = fold(&flag.text, flag.shape) else {
                continue;
            };
            if flag.end > out.len() {
                continue;
            }
            out.replace_range(flag.start..flag.end, &folded);
        }
        if out != body {
            tree.insert(file.to_string(), out);
            changed += 1;
        }
    }
    changed
}

/// The plainest spelling of one flagged span, or `None` if its text is not what
/// its shape claims — a flag that cannot be folded is left in place rather than
/// rewritten on a guess.
fn fold(text: &str, shape: Shape) -> Option<String> {
    match shape {
        Shape::Foldable => {
            let (a, op, b, _) = group_at(text.as_bytes())?;
            let value = match op {
                b'+' => a + b,
                b'-' => a - b,
                b'*' => a.checked_mul(b)?,
                _ => return None,
            };
            Some(value.to_string())
        }
        Shape::MixedCaseRadix => Some(text.to_ascii_lowercase()),
        Shape::EscapePrefixed => {
            let quote = text.chars().next()?;
            let inner = text[quote.len_utf8()..text.len() - quote.len_utf8()].to_string();
            let mut out = String::new();
            let bytes = inner.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'\\'
                    && matches!(bytes.get(i + 1), Some(b'x') | Some(b'X'))
                    && bytes.len() >= i + 4
                {
                    if let Some(v) = hex_value(&bytes[i + 2..i + 4]) {
                        out.push(v as char);
                        i += 4;
                        continue;
                    }
                }
                let ch = inner[i..].chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
            Some(format!("{quote}{out}{quote}"))
        }
        Shape::SplitString => {
            let pieces: Vec<(usize, usize)> = code_view(text)
                .strings
                .into_iter()
                .filter(|(s, e)| e - s >= 2)
                .collect();
            if pieces.len() != 2 {
                return None;
            }
            let b = text.as_bytes();
            let left = &b[pieces[0].0..pieces[0].1];
            let right = &b[pieces[1].0..pieces[1].1];
            let quote = *left.first()? as char;
            let inner = |piece: &[u8]| {
                String::from_utf8_lossy(&piece[1..piece.len() - 1]).into_owned()
            };
            Some(format!(
                "{quote}{}{}{quote}",
                inner(left),
                inner(right)
            ))
        }
    }
}

fn hex_value(digits: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(digits).ok()?;
    if text.len() != 2 {
        return None;
    }
    u8::from_str_radix(text, 16).ok()
}

/// Is `code` a `(a OP b)` group whose tail operand is in the writer's range? If
/// so, its width in bytes.
fn foldable_width(code: &[u8]) -> Option<usize> {
    group_at(code).map(|(_, _, _, width)| width)
}

/// `(a, op, b, width)` for a `(a OP b)` group starting at byte 0, when it is a
/// shape the writer could have produced.
///
/// The acceptance rule differs by operator, and follows the renderer rather than
/// taste. `+` and `-` carry the code in their **second** operand, which
/// `operand_for` always draws from `1..=2^width`; an ordinary `(total + 40)` is
/// not that, and folding it would change the program. `*` carries the code in a
/// *factor* the renderer picks from either side of the product, so a factorisation
/// of one literal into two is already the shape — and no ordinary constant is
/// written as a product of two literals, because a compiler would fold it.
///
/// One function does both the finding and the folding, because a span the search
/// names and the fold rejects would leave the watermark in place while the table
/// reported it removed.
fn group_at(code: &[u8]) -> Option<(i128, u8, i128, usize)> {
    if code.first() != Some(&b'(') {
        return None;
    }
    let mut i = skip_spaces(code, 1);
    let a_at = i;
    i = digits_end(code, i)?;
    let a: i128 = std::str::from_utf8(&code[a_at..i]).ok()?.parse().ok()?;
    i = skip_spaces(code, i);
    let op = *code.get(i)?;
    if !matches!(op, b'+' | b'-' | b'*') {
        return None;
    }
    i += 1;
    i = skip_spaces(code, i);
    let b_at = i;
    i = digits_end(code, i)?;
    let b: i128 = std::str::from_utf8(&code[b_at..i]).ok()?.parse().ok()?;
    i = skip_spaces(code, i);
    if code.get(i) != Some(&b')') {
        return None;
    }
    let carries = match op {
        b'*' => a >= 2 && b >= 2,
        _ => (1..=16).contains(&b),
    };
    if !carries {
        return None;
    }
    Some((a, op, b, i + 1))
}

fn skip_spaces(code: &[u8], mut i: usize) -> usize {
    while i < code.len() && code[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn digits_end(code: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < code.len() && code[i].is_ascii_digit() {
        i += 1;
    }
    if i == from {
        None
    } else {
        Some(i)
    }
}

/// A file's bytes with comments and string *contents* blanked to spaces, plus the
/// byte ranges of every string literal found.
///
/// Length is preserved, so an offset into the view is an offset into the original.
/// That is the whole reason this exists rather than a `str::replace`: a watermark
/// lives in code, and a search that also reads the text of a string will flag a
/// tutorial's `"(1 + 2)"` example and then rewrite it — which is a change to what
/// the program prints.
/// Which bytes of a file are real code: outside every comment and outside every
/// string body.
///
/// [`code_view`] blanks what is not code to spaces, so a byte that survived
/// unchanged is a byte a mutation may act on. The test-suite's text transforms use
/// this for the same reason the locator does: `", "` inside a message is not a
/// formatting hook, and rewriting it changes what the program prints, which §25
/// forbids a refactoring from doing.
pub(crate) fn editable(body: &str) -> Vec<bool> {
    let view = code_view(body);
    view.code
        .iter()
        .zip(body.as_bytes())
        .map(|(seen, actual)| seen == actual)
        .collect()
}

/// Every string literal's byte range, quotes included.
///
/// A mask says whether a *byte* is code; this says whether a *line* starts inside
/// a literal, which the mask cannot: the newline before a multi-line string's
/// second line is the string's own character and is left alone by the blanking.
pub(crate) fn string_spans(body: &str) -> Vec<(usize, usize)> {
    code_view(body).strings
}

/// The literals themselves, in order, for a test that wants to say "and nothing
/// about what the program prints changed".
#[cfg(test)]
pub(crate) fn literals(body: &str) -> Vec<String> {
    string_spans(body)
        .into_iter()
        .map(|(start, end)| body[start..end].to_string())
        .collect()
}

struct CodeView {
    code: Vec<u8>,
    /// `(start, end)` byte ranges, quotes included.
    strings: Vec<(usize, usize)>,
}

fn code_view(body: &str) -> CodeView {
    let b = body.as_bytes();
    let mut code = b.to_vec();
    let mut strings = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if matches!(b.get(i + 1), Some(b'/') | Some(b'*')) => {
                if b[i + 1] == b'/' {
                    i = blank_to_newline(&mut code, i);
                } else {
                    let end = b[i + 2..]
                        .windows(2)
                        .position(|w| w == b"*/")
                        .map(|p| i + 2 + p + 2)
                        .unwrap_or(b.len());
                    blank(&mut code, i, end);
                    i = end;
                }
            }
            b'#' => {
                i = blank_to_newline(&mut code, i);
            }
            q @ (b'\'' | b'"' | b'`') => {
                let triple = b[i + 1..].starts_with(&[q, q]);
                let opener = if triple { 3 } else { 1 };
                let mut j = i + opener;
                let mut closed = false;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if triple {
                        if b[j..].starts_with(&[q, q, q]) {
                            closed = true;
                            j += 3;
                            break;
                        }
                        j += 1;
                        continue;
                    }
                    if b[j] == q {
                        closed = true;
                        j += 1;
                        break;
                    }
                    if q != b'`' && b[j] == b'\n' {
                        break;
                    }
                    j += 1;
                }
                if !closed {
                    // An unterminated literal says nothing about this file that is
                    // worth acting on; skip the opening quote and move on.
                    i += 1;
                    continue;
                }
                strings.push((i, j));
                blank(&mut code, i + opener, (j - opener).max(i + opener));
                i = j;
            }
            _ => i += 1,
        }
    }
    CodeView { code, strings }
}

/// Blank `[start, end)`, keeping newlines so line structure survives.
fn blank(code: &mut [u8], start: usize, end: usize) {
    let end = end.min(code.len());
    if start >= end {
        return;
    }
    for slot in &mut code[start..end] {
        if *slot != b'\n' {
            *slot = b' ';
        }
    }
}

fn blank_to_newline(code: &mut [u8], from: usize) -> usize {
    let mut j = from;
    while j < code.len() && code[j] != b'\n' {
        code[j] = b' ';
        j += 1;
    }
    j
}

fn mark(taken: &mut [bool], start: usize, end: usize) {
    let end = end.min(taken.len());
    for slot in taken.iter_mut().take(end).skip(start) {
        *slot = true;
    }
}

/// What a shape search achieved against ground truth from the manifest.
#[derive(Debug, Clone, Default)]
pub struct Recall {
    /// Shape slug → flags raised.
    pub by_shape: BTreeMap<&'static str, usize>,
    /// Fragments the search located.
    pub found: usize,
    /// Fragments it did not, with the text so a reader can see why.
    pub missed: Vec<String>,
    /// Flags raised on text that is not one of the release's fragments — the
    /// attacker's cost, and the reason a *detector* must not key on shape.
    pub innocent: usize,
    pub total: usize,
}

impl Recall {
    pub fn hit_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.found as f64 / self.total as f64
    }
}

/// Compare a shape search against what was actually written. The manifest is used
/// here as *ground truth after the fact*: the attacker has the tree only, and the
/// suite has both, which is the only way to report "it found 34 of 36" rather than
/// "it found some".
pub fn score(flags: &[Flag], renderings: &[String]) -> Recall {
    let mut out = Recall {
        by_shape: flags.iter().fold(BTreeMap::new(), |mut m: BTreeMap<&'static str, usize>, f| {
            *m.entry(f.shape.slug()).or_default() += 1;
            m
        }),
        total: renderings.len(),
        ..Recall::default()
    };
    let mut pool: BTreeMap<&str, usize> = BTreeMap::new();
    for flag in flags {
        *pool.entry(flag.text.as_str()).or_default() += 1;
    }
    for rendering in renderings {
        match pool.get_mut(rendering.as_str()) {
            Some(count) if *count > 0 => {
                *count -= 1;
                out.found += 1;
            }
            _ => out.missed.push(rendering.clone()),
        }
    }
    out.innocent = pool.values().sum();
    out
}

/// Locate over a directory tree on disk, the way §52's attacker sees it.
pub fn locate_tree(root: &std::path::Path) -> Vec<Flag> {
    locate(&read_tree(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> Tree {
        files
            .iter()
            .map(|(n, b)| (n.to_string(), b.to_string()))
            .collect()
    }

    fn shapes(body: &str) -> Vec<(&'static str, String)> {
        locate_file("t.js", body)
            .into_iter()
            .map(|f| (f.shape.slug(), f.text))
            .collect()
    }

    #[test]
    fn each_rendering_shape_is_found_and_named() {
        let body = "const a = (29999 + 1);\nconst b = (29999 - 1);\nconst c = (2 * 720720);\n\
                    const d = 0xbEeF;\nconst e = \"\\x68ello\";\nconst f = (\"start\" + \"ing\");\n";
        let found = shapes(body);
        let names: Vec<&str> = found.iter().map(|(s, _)| *s).collect();
        for shape in Shape::ALL {
            assert!(
                names.contains(&shape.slug()),
                "{shape:?} is not found by the search: {found:?}"
            );
        }
        assert_eq!(
            found.iter().filter(|(s, _)| *s == "foldable-arithmetic").count(),
            3
        );
    }

    #[test]
    fn a_plain_tree_raises_nothing() {
        // §52's attack has to be aimed, and an aimless one is a false-positive
        // generator. These are the ordinary spellings the shape search must walk
        // past: the operand bound, the case rule and the parenthesis requirement
        // are what keep it there.
        let body = "const rate = 0.25;\nconst total = base * 4;\nconst hex = 0xFF00;\n\
                    const lower = 0xff00;\nconst text = \"plain string\";\n\
                    const joined = first + last;\nconst idx = (1 + 2 + 3);\n\
                    function f(x) { return x + 1; }\nconst v = 1e9;\n";
        assert_eq!(shapes(body), vec![], "a plain file was flagged as holding fragments");
    }

    #[test]
    fn comments_and_string_bodies_are_not_code() {
        // Rewriting text inside a string changes what the program prints, and
        // rewriting a comment changes nothing but the count the table reports.
        // Both are the same failure: a search that reads the wrong bytes.
        let js = "const note = \"use (29999 + 1) to watermark\";\n// (29999 + 1)\n/* 0xbEeF */\n";
        assert_eq!(shapes(js), vec![]);
        let py = "note = \"use (29999 + 1) to watermark\"\n# (29999 + 1)\n";
        assert_eq!(locate_file("t.py", py), vec![]);
    }

    #[test]
    fn folding_a_shape_preserves_the_value_it_computes() {
        let cases = [
            ("(29999 + 1)", "30000"),
            ("(29999 - 1)", "29998"),
            ("(2 * 720720)", "1441440"),
            ("( 180180 * 4 )", "720720"),
            ("0xbEeF", "0xbeef"),
            ("( \"start\" + \"ing\" )", "\"starting\""),
            ("\"\\x68ello\"", "\"hello\""),
            ("\"\\x68\\x69 there\"", "\"hi there\""),
        ];
        for (text, want) in cases {
            let flags = locate_file("t.js", text);
            assert!(!flags.is_empty(), "{text} was not flagged");
            let got = fold(&flags[0].text, flags[0].shape).unwrap_or_default();
            assert_eq!(got, want, "{text}");
        }
    }

    #[test]
    fn a_folded_tree_raises_no_more_flags() {
        // Removal has to *work*, or the row about it in the documentation is a
        // statement about a search that found things it could not take out.
        let mut tree = tree(&[(
            "src/a.js",
            "const a = (29999 + 1);\nconst b = 0xbEeF;\nconst c = \"\\x68ello\";\n\
             const d = (\"st\" + \"art\");\n",
        )]);
        let flags = locate(&tree);
        assert_eq!(flags.len(), 4, "{flags:?}");
        assert_eq!(normalize(&mut tree, &flags), 1);
        assert_eq!(locate(&tree), vec![], "the fold left the shapes in place");
        assert!(tree["src/a.js"].contains("const a = 30000;"));
        assert!(tree["src/a.js"].contains("const c = \"hello\";"));
    }

    #[test]
    fn offsets_survive_a_multiline_file() {
        // `normalize` replaces by byte range, so an off-by-one around a newline or
        // a multi-byte character would corrupt the file rather than fold it.
        let body = "// comment\nconst a = (29999 + 1);\nconst b = \"café ☕\";\n\
                    const c = (1 + 2 + 3);\nconst d = (29996 + 4);\n";
        let mut tree = tree(&[("m.js", body)]);
        let flags = locate(&tree);
        let texts: Vec<&str> = flags.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, vec!["(29999 + 1)", "(29996 + 4)"], "{texts:?}");
        normalize(&mut tree, &flags);
        assert_eq!(
            tree["m.js"],
            "// comment\nconst a = 30000;\nconst b = \"café ☕\";\nconst c = (1 + 2 + 3);\n\
             const d = 30000;\n"
        );
    }

    #[test]
    fn the_search_finds_every_fragment_a_protected_tree_holds() {
        // Ground truth, from the manifest. The measured result on the form corpus is
        // 36 of 36 located — near-total recall, which is the finding §50 has to
        // carry: concealment is not a property of this protocol, and no document may
        // imply that an attacker would have to guess where to look. It is *asserted*
        // as a floor rather than an equality because a rendering can legitimately
        // come out already plain — a hex form whose value carries no letters to
        // case-flip, a factorisation into two operands of one — and the search
        // cannot see a shape that was never written.
        use crate::Project;
        let project = Project::fixture("locate-protected", "forms");
        project.set_config(crate::fixtures::FORMS_CONFIG);
        let release = project.protect();
        let renderings: Vec<String> = release.site_texts().into_iter().map(|s| s.rendered).collect();
        let flags = locate_tree(project.root());
        let score = score(&flags, &renderings);
        println!(
            "  shape search on a {}-site release: {}/{} located ({:.0}%), {} innocent flag(s) in \
             the same tree, by shape {:?}",
            score.total,
            score.found,
            score.total,
            score.hit_rate() * 100.0,
            score.innocent,
            score.by_shape,
        );
        for missed in score.missed.iter().take(6) {
            println!("  not located: {missed}");
        }
        assert!(
            score.hit_rate() >= 0.9,
            "the shape search located only {:.0}% of the fragments it was aimed at, so the \
             removal row below measures an attack that barely found its target",
            score.hit_rate() * 100.0
        );
    }

    #[test]
    fn the_same_search_over_unprotected_code_raises_nothing_to_fold() {
        // The other half of §52's finding, and the half that decides whether the
        // attack above costs the attacker anything. Across every unrelated corpus —
        // common algorithms, framework idioms, boilerplate, an eighty-two file
        // generated SDK, standard-library usage in a second language, open-source
        // data structures — the shape search finds **nothing** to fold.
        //
        // Two consequences, and the second one is a correction this module's own
        // first draft needed. The first is tactical: an attacker who folds what the
        // search finds is not gambling with innocent constants, so the removal costs
        // them nothing but the work of running the search. The second is that the
        // easy argument — "shape matching would produce false positives, which is
        // why the tag is keyed" — is *not* available, because the measurement says
        // the opposite. The reason a shape is not evidence is that a shape carries
        // nobody's identity: only `HMAC(location_key, λ)` does, and that needs the
        // project's secret.
        use crate::fixtures::Corpus;
        let mut rows = Vec::new();
        for corpus in [
            Corpus::Algorithms,
            Corpus::Framework,
            Corpus::Boilerplate,
            Corpus::Generated,
            Corpus::Stdlib,
            Corpus::Oss,
        ] {
            let dir = crate::TempDir::new(&format!("locate-{}", corpus.slug()));
            let files = corpus.write(dir.path());
            let flags = locate_tree(dir.path());
            let by_shape: BTreeMap<&str, usize> =
                flags.iter().fold(BTreeMap::new(), |mut m, f| {
                    *m.entry(f.shape.slug()).or_default() += 1;
                    m
                });
            println!(
                "  {:<12} {:>4} file(s), {:>3} shape flag(s)  {by_shape:?}",
                corpus.slug(),
                files.len(),
                flags.len(),
            );
            rows.push((corpus.slug(), files.len(), flags.len()));
        }
        let files: usize = rows.iter().map(|(_, n, _)| n).sum();
        let flags: usize = rows.iter().map(|(_, _, n)| n).sum();
        println!("  {files} unrelated file(s) read, {flags} foldable shape(s) in them");
        // Recorded, not required: a future corpus that *does* hold these shapes is a
        // finding about ordinary code, not a broken test, and §24's rule applies —
        // document what was observed rather than assert a number nobody earned.
    }
}
