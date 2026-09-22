//! The mutations §25 and §26 ask for, as data rather than as ad-hoc edits.
//!
//! One list, three users: the detection matrix measures each transform once,
//! §43's property tests compose them in random order, and `swp-validate` prints
//! the table the documentation quotes. If each did its own string surgery, three
//! documents would quote three measurements of three different attacks.
//!
//! Every transform here preserves the program's meaning, because §25 is about
//! *refactoring*: an edit that changes what the code computes is not something a
//! detector is asked to survive, it is a different program. That is also why
//! `constant_rewrite` spells a number in another base instead of changing it,
//! and why `dead_code_removal` only deletes functions nothing calls.
//!
//! A transform reports how many files it changed, and the suites assert that
//! number is not zero. A "measurement" showing that detection survived a
//! mutation that mutated nothing is the most easy-to-write false result in this
//! file, so the harness refuses to produce one.

use std::collections::BTreeMap;
use std::path::Path;

/// A candidate's sources, in memory: path → text. Sorted by path, so a
/// transform that walks the tree in order does the same thing twice.
pub type Tree = BTreeMap<String, String>;

/// Read a directory's sources, skipping `.swp/` — a candidate that carried its
/// own store would be a second project, and §21's question would not be asked.
pub fn read_tree(root: &Path) -> Tree {
    list_sources(root)
        .into_iter()
        .filter_map(|rel| {
            let body = std::fs::read_to_string(root.join(&rel)).ok()?;
            Some((rel, body))
        })
        .collect()
}

/// Write a tree out, replacing what is there — which includes **deleting** what
/// is not. A candidate whose file moved must not still hold the file where it
/// was: a rename that left the original on disk would measure a copy, and every
/// §25 row built on one would overstate how tolerant the detector is. `.swp/` is
/// untouched, because it is not part of the tree by definition.
pub fn write_tree(root: &Path, tree: &Tree) {
    for rel in list_sources(root) {
        if !tree.contains_key(&rel) {
            let _ = std::fs::remove_file(root.join(&rel));
        }
    }
    for (rel, body) in tree {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body.as_bytes()).unwrap();
    }
}

/// Every file path under `root`, relative, `.swp/` skipped.
fn list_sources(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().map(|n| n == ".swp").unwrap_or(false) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

/// The attacks, named exactly as the brief names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    /// §25: local variables. The most common edit in real maintenance.
    VariableRename,
    /// §25: function names, including every call site.
    FunctionRename,
    /// §25: class names.
    ClassRename,
    /// §25: indentation, blank lines, semicolon-free style — no token removed.
    Reformat,
    /// §25: every comment line.
    CommentRemoval,
    /// §25: a module moves to another directory, contents untouched.
    FileMovement,
    /// §25: a statement becomes its own function, called from where it was.
    FunctionExtraction,
    /// §25: a small helper's body written out at its call site.
    FunctionInlining,
    /// §25: equivalent expressions in a different shape.
    ExpressionRewrite,
    /// §25: the same values in another notation (`231` → `0xe7`).
    ConstantRewrite,
    /// §25: the module's exports re-stated, an import added.
    ImportChange,
    /// §25: delete code nothing references.
    DeadCodeRemoval,
    /// §25: same statements and functions, different order.
    CodeReorder,
    /// §26: find the fragments as a person hunting a watermark would — a
    /// rendered site's text, deleted from the source where it appears.
    ArtifactRemoval,
    /// §26: rewrite the arithmetic around a site without deleting it.
    SiteRewrite,
    /// §26: normalize every numeric literal to one canonical form.
    ConstantNormalization,
    /// §26: rebuild a copied module by keeping its structure and dropping its
    /// hand-written bodies.
    ModuleRebuild,
}

impl Transform {
    /// §25's thirteen, then §26's four, in the order the brief lists them.
    pub const REFACTORING: [Transform; 13] = [
        Transform::VariableRename,
        Transform::FunctionRename,
        Transform::ClassRename,
        Transform::Reformat,
        Transform::CommentRemoval,
        Transform::FileMovement,
        Transform::FunctionExtraction,
        Transform::FunctionInlining,
        Transform::ExpressionRewrite,
        Transform::ConstantRewrite,
        Transform::ImportChange,
        Transform::DeadCodeRemoval,
        Transform::CodeReorder,
    ];

    /// §26's removal attempts, in increasing effort.
    pub const ADVERSARIAL: [Transform; 4] = [
        Transform::ArtifactRemoval,
        Transform::SiteRewrite,
        Transform::ConstantNormalization,
        Transform::ModuleRebuild,
    ];

    pub const ALL: [Transform; 17] = {
        let mut out: [Transform; 17] = [Transform::VariableRename; 17];
        let mut i = 0;
        while i < 13 {
            out[i] = Self::REFACTORING[i];
            i += 1;
        }
        let mut j = 0;
        while j < 4 {
            out[13 + j] = Self::ADVERSARIAL[j];
            j += 1;
        }
        out
    };

    /// The name a documented number can be traced back to.
    pub fn slug(self) -> &'static str {
        match self {
            Transform::VariableRename => "variable_rename",
            Transform::FunctionRename => "function_rename",
            Transform::ClassRename => "class_rename",
            Transform::Reformat => "formatting",
            Transform::CommentRemoval => "comment_removal",
            Transform::FileMovement => "file_movement",
            Transform::FunctionExtraction => "function_extraction",
            Transform::FunctionInlining => "function_inlining",
            Transform::ExpressionRewrite => "expression_rewrite",
            Transform::ConstantRewrite => "constant_rewrite",
            Transform::ImportChange => "import_changes",
            Transform::DeadCodeRemoval => "dead_code_removal",
            Transform::CodeReorder => "code_reordering",
            Transform::ArtifactRemoval => "artifact_removal",
            Transform::SiteRewrite => "site_rewrite",
            Transform::ConstantNormalization => "constant_normalization",
            Transform::ModuleRebuild => "module_rebuild",
        }
    }

    /// What the transform does, for the table `swp-validate` prints.
    pub fn describes(self) -> &'static str {
        match self {
            Transform::VariableRename => "local variables renamed at every use",
            Transform::FunctionRename => "free functions renamed, calls with them",
            Transform::ClassRename => "classes renamed",
            Transform::Reformat => "indentation, blank lines and spacing changed",
            Transform::CommentRemoval => "comment lines deleted",
            Transform::FileMovement => "one module moved to another directory",
            Transform::FunctionExtraction => "a return expression lifted into a new function",
            Transform::FunctionInlining => "a helper's body written into its caller",
            Transform::ExpressionRewrite => "equivalent arithmetic written differently",
            Transform::ConstantRewrite => "integers re-spelled in hexadecimal",
            Transform::ImportChange => "exports restated and an unused import added",
            Transform::DeadCodeRemoval => "an unreferenced class deleted",
            Transform::CodeReorder => "functions and statements reordered",
            Transform::ArtifactRemoval => "every fragment literal found and deleted",
            Transform::SiteRewrite => "the arithmetic around a fragment rewritten",
            Transform::ConstantNormalization => "all numeric literals normalized to decimal",
            Transform::ModuleRebuild => "bodies replaced with stubs, shape kept",
        }
    }

    /// Apply the transform in place, returning how many files it changed.
    pub fn apply(self, tree: &mut Tree, sites: &[SiteText]) -> usize {
        let mut changed = 0;
        match self {
            Transform::VariableRename => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = body
                        .replace("amount", "principal")
                        .replace("weeks", "periods")
                        .replace("this.seed", "this.offset")
                        .replace("(seed)", "(offset)");
                    changed += usize::from(*body != before);
                }
            }
            Transform::FunctionRename => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = body.replace("duty_", "charge_");
                    changed += usize::from(*body != before);
                }
            }
            Transform::ClassRename => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = body.replace("Bucket_", "Bin_");
                    changed += usize::from(*body != before);
                }
            }
            Transform::Reformat => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = reflow(body);
                    changed += usize::from(*body != before);
                }
            }
            Transform::CommentRemoval => {
                for body in tree.values_mut() {
                    let kept: Vec<&str> = body
                        .lines()
                        .filter(|l| !l.trim_start().starts_with("//"))
                        .collect();
                    let joined = kept.join("\n") + "\n";
                    if joined != *body {
                        *body = joined;
                        changed += 1;
                    }
                }
            }
            Transform::FileMovement => {
                // One module, moved. A watermark tied to a path would fail here,
                // and §10 says it must not be.
                if let Some((rel, body)) = tree
                    .iter()
                    .find(|(rel, _)| rel.starts_with("src/"))
                    .map(|(rel, body)| (rel.clone(), body.clone()))
                {
                    tree.remove(&rel);
                    tree.insert(format!("lib/{}", rel.trim_start_matches("src/")), body);
                    changed = 1;
                }
            }
            Transform::FunctionExtraction => {
                // The rounded total becomes its own function, and every module
                // grows one declaration: the code computes the same numbers in a
                // shape a copy of the original would not have.
                const ROUND: &str = "function round2(value) {\n  return Math.round(value * 100) \
                                     / 100;\n}\n\n";
                for body in tree.values_mut() {
                    let before = body.clone();
                    if !body.contains("return Math.round(sum * 100) / 100;") {
                        continue;
                    }
                    *body =
                        body.replace("return Math.round(sum * 100) / 100;", "return round2(sum);");
                    if !body.contains("function round2(") {
                        body.push_str(ROUND);
                    }
                    changed += usize::from(*body != before);
                }
            }
            Transform::FunctionInlining => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = body.replace(
                        "sum += this.scale(row.amount, row.rate);",
                        "const step = row.amount * row.rate * 0.25;\n      sum += step + \
                         this.seed;",
                    );
                    changed += usize::from(*body != before);
                }
            }
            Transform::ExpressionRewrite => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = body
                        .replace("value * rate * 0.25", "(value * rate) / 4")
                        .replace("Math.round(sum * 100) / 100", "Number(sum.toFixed(2))")
                        .replace("let sum = 0;", "let sum = 0.00;");
                    changed += usize::from(*body != before);
                }
            }
            Transform::ConstantRewrite => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = hex_rewrite(body);
                    changed += usize::from(*body != before);
                }
            }
            Transform::ImportChange => {
                // Same exports, different module idiom, plus an import the file
                // does not use: the shape of a module's interface changes and
                // nothing about its behaviour does.
                for body in tree.values_mut() {
                    let before = body.clone();
                    let mut kept: Vec<&str> = Vec::new();
                    let mut exported = String::new();
                    for line in body.lines() {
                        if let Some(rest) = line.strip_prefix("module.exports = ") {
                            exported = rest
                                .trim_end_matches(';')
                                .trim_start_matches('{')
                                .trim_end_matches('}')
                                .trim()
                                .to_string();
                            continue;
                        }
                        kept.push(line);
                    }
                    if exported.is_empty() {
                        continue;
                    }
                    kept.retain(|l| !l.trim().is_empty());
                    *body = format!(
                        "{}\nconst path = require('node:path');\nvoid path;\nexports.RATES = {{ \
                         {exported} }};\n",
                        kept.join("\n")
                    );
                    changed += usize::from(*body != before);
                }
            }
            Transform::DeadCodeRemoval => {
                // The generator's classes are never instantiated, which is what
                // makes deleting them dead-code removal rather than a rewrite.
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = drop_class(body);
                    changed += usize::from(*body != before);
                }
            }
            Transform::CodeReorder => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    let mut blocks: Vec<String> = body
                        .split("\n\n")
                        .map(str::to_string)
                        .filter(|b| !b.trim().is_empty())
                        .collect();
                    blocks.reverse();
                    let mut out = blocks.join("\n\n");
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                    *body = out;
                    changed += usize::from(*body != before);
                }
            }
            Transform::ArtifactRemoval => {
                // The attack a person who knows SWP-1 exists starts with: take
                // each rendered fragment the manifest names and cut it out.
                for body in tree.values_mut() {
                    let before = body.clone();
                    for site in sites {
                        if body.contains(&site.rendered) {
                            *body = body.replace(&site.rendered, &site.original);
                        }
                    }
                    changed += usize::from(*body != before);
                }
            }
            Transform::SiteRewrite => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    for site in sites {
                        if body.contains(&site.rendered) {
                            *body = body.replace(&site.rendered, &equivalent_of(&site.rendered));
                        }
                    }
                    changed += usize::from(*body != before);
                }
            }
            Transform::ConstantNormalization => {
                for body in tree.values_mut() {
                    let before = body.clone();
                    *body = normalize_numbers(body);
                    changed += usize::from(*body != before);
                }
            }
            Transform::ModuleRebuild => {
                for (rel, body) in tree.iter_mut() {
                    if !rel.ends_with(".js") {
                        continue;
                    }
                    let before = body.clone();
                    *body = rebuild(body);
                    changed += usize::from(*body != before);
                }
            }
        }
        changed
    }
}

/// A site as an attacker who has read the source but not the manifest would
/// describe it: the text that sits there now, and the value it means.
#[derive(Debug, Clone)]
pub struct SiteText {
    pub file: String,
    pub rendered: String,
    pub original: String,
}

impl SiteText {
    /// From one `sites[]` element of a private manifest.
    pub fn from_manifest(site: &serde_json::Value) -> Option<Self> {
        Some(SiteText {
            file: site["file"].as_str()?.to_string(),
            rendered: site["rendered"].as_str()?.to_string(),
            original: site["original"].as_str()?.to_string(),
        })
    }
}

/// `255` → `0xff` for integers large enough to be worth it. Same value, other
/// notation: a detector that keyed on the decimal spelling is measuring the
/// printer, not the program.
fn hex_rewrite(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut run = String::new();
    // The character before the digit run in hand. Digits never move it, so when a
    // run ends it is exactly the character the run was glued to — which is what
    // says whether that run was a number at all.
    let mut prev = Some(' ');
    for ch in body.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() {
            run.push(ch);
            continue;
        }
        let raw = std::mem::take(&mut run);
        let glued = |c: char| c.is_alphanumeric() || c == '_' || c == '.';
        let standalone = !glued(prev.unwrap_or(' ')) && !glued(ch);
        if standalone && raw.len() >= 3 && raw.parse::<u64>().is_ok_and(|v| v >= 100) {
            out.push_str(&format!("0x{:x}", raw.parse::<u64>().unwrap()));
        } else {
            out.push_str(&raw);
        }
        out.push(ch);
        prev = Some(ch);
    }
    out
}

/// §26's "normalize constants": put every numeric literal in one spelling.
///
/// Hex becomes decimal, and a float loses a leading zero and trailing zeros, so
/// `0.25` and `.250` both become `.25`. Neither changes a value — which is the
/// point. An attacker normalizes because a detector that keys on *text* breaks
/// when the same constant is written two ways, and a detector that keys on the
/// constant does not care.
fn normalize_numbers(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // A run is digits and points, plus the `x` of a `0x` prefix: taking `x`
        // only there is what keeps `max` and `exit` out of the number scanner.
        let starts_number = chars[i].is_ascii_digit();
        if !starts_number {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        let hex = chars[i] == '0' && matches!(chars.get(i + 1), Some('x') | Some('X'));
        i += 1;
        if hex {
            i += 1;
        }
        while i < chars.len() && (chars[i].is_ascii_hexdigit() || (chars[i] == '.' && !hex)) {
            i += 1;
        }
        let run: String = chars[start..i].iter().collect();
        // `.` on either side means it is not one token, and a lone run of hex
        // letters is an identifier's tail, not a number: leave both alone.
        let is_hex = run.starts_with("0x") || run.starts_with("0X");
        let numeric = is_hex || run.parse::<f64>().is_ok();
        if !numeric || run.starts_with('.') || run.ends_with('.') {
            out.push_str(&run);
            continue;
        }
        if is_hex {
            let digits: String = run.chars().skip(2).collect();
            match u64::from_str_radix(&digits, 16) {
                Ok(v) => out.push_str(&v.to_string()),
                Err(_) => out.push_str(&run),
            }
            continue;
        }
        out.push_str(&canonical_decimal(&run));
    }
    out
}

/// The one spelling of one decimal value: no leading zero before the point, no
/// trailing zeros after it, and integers written bare.
fn canonical_decimal(run: &str) -> String {
    if !run.contains('.') {
        return run
            .parse::<u64>()
            .map(|v| v.to_string())
            .unwrap_or_else(|_| run.to_string());
    }
    let (whole, frac) = run.split_once('.').expect("checked by the caller");
    let frac = frac.trim_end_matches('0');
    let whole = whole.trim_start_matches('0');
    if frac.is_empty() {
        return if whole.is_empty() {
            "0".into()
        } else {
            whole.into()
        };
    }
    if whole.is_empty() {
        format!(".{frac}")
    } else {
        format!("{whole}.{frac}")
    }
}

/// Delete a class declaration: the lines from `class` to its closing brace.
fn drop_class(body: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    let mut depth = 0i32;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if !skipping && trimmed.starts_with("class ") && trimmed.ends_with('{') {
            skipping = true;
            depth = 1;
            continue;
        }
        if skipping {
            depth += trimmed.matches('{').count() as i32;
            depth -= trimmed.matches('}').count() as i32;
            if depth <= 0 {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Keep a module's *structure* and replace every statement with a stub: the
/// declarations, blocks and exports of the file survive, the code in it does not.
///
/// Two things make this more than a per-line rewrite, and both were found by
/// testing rather than by reading. The first is that a statement is not a line:
/// `PIPE_BODY`'s method chain and `TABLE_BODY`'s multi-line object literal each
/// span three lines whose middles are not statements, so stubbing line by line
/// leaves a file no grammar accepts — `module_rebuild` produced exactly two
/// syntax errors on `src/mod4.js` before this function learned to group lines
/// into units by bracket depth. A measurement of an unparseable candidate is a
/// measurement of the lexical fallback (§21), not of the attack.
///
/// The second is that the earlier version kept every `const` and `return` line
/// verbatim, which kept the literals the fragments live in: the survival number
/// it produced described an attack that had not been carried out. So a `const`
/// keeps its name and loses its value, and a `return` keeps itself and loses its
/// expression. That makes this the most destructive of §26's four attempts,
/// which is where the brief places it.
///
/// Nothing here is executed, so a stub that would break the program at run time
/// is still a fair attack — §11's no-regression rule binds the writer, not the
/// attacker.
fn rebuild(body: &str) -> String {
    let mut out = String::new();
    let mut unit: Vec<&str> = Vec::new();
    let mut depth = 0i32;
    let mut base = 0i32;
    for line in body.lines() {
        let trimmed = line.trim();
        if unit.is_empty() {
            if trimmed.is_empty() {
                out.push('\n');
                continue;
            }
            if starts_comment(trimmed) {
                out.push_str(line);
                out.push('\n');
                continue;
            }
        }
        let (delta, last, before_last) = outside_strings(line);
        depth += delta;
        unit.push(line);
        let header = last == Some('{') && depth == base + 1 && before_last != Some('=');
        let closed = depth <= base && matches!(last, Some(';') | Some('}') | Some(':'));
        if header || closed {
            emit(&mut out, &unit);
            unit.clear();
            base = depth;
        }
    }
    if !unit.is_empty() {
        emit(&mut out, &unit);
    }
    out
}

/// A comment line, in either dialect the suites carry.
fn starts_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('#')
}

/// The bracket balance a line contributes, and the last two non-space characters
/// of it, all counted outside string literals.
///
/// Outside strings is the whole point: `label_0` builds the message
/// `' kg (' + … + ' lb)'`, and counting that stray parenthesis would leave every
/// following line looking like the inside of a group.
fn outside_strings(line: &str) -> (i32, Option<char>, Option<char>) {
    let mut delta = 0i32;
    let mut quote: Option<char> = None;
    let mut last: Option<char> = None;
    let mut before_last: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(open) = quote {
            if ch == '\\' {
                chars.next();
            } else if ch == open {
                quote = None;
                before_last = last;
                last = Some(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '{' | '(' | '[' => {
                delta += 1;
                before_last = last;
                last = Some(ch);
            }
            '}' | ')' | ']' => {
                delta -= 1;
                before_last = last;
                last = Some(ch);
            }
            c if !c.is_whitespace() => {
                before_last = last;
                last = Some(c);
            }
            _ => {}
        }
    }
    (delta, last, before_last)
}

/// Write one grouped unit: a block header, a label, an export or a comment goes
/// out as it came in, and anything that computes something goes out as a stub.
fn emit(out: &mut String, unit: &[&str]) {
    let head = unit[0].trim();
    let joined = unit.join("\n");
    let interface = head.ends_with('{')
        || head.starts_with('}')
        || (unit.len() == 1 && head.ends_with(':'))
        || head.starts_with("module.exports")
        || head.starts_with("exports.")
        || head.starts_with("import ")
        || head.starts_with("export ")
        || head.starts_with("'use strict'")
        || head.starts_with("\"use strict\"");
    if interface {
        out.push_str(&joined);
        out.push('\n');
        return;
    }
    let indent = &unit[0][..unit[0].len() - head.len()];
    let stub = match declaration(head) {
        // The declaration is structure, its value is code. A destructuring head
        // has no single name to keep, so it takes the plain stub.
        Some((keyword, name)) if !name.is_empty() => {
            format!("{indent}{keyword}{name} = void 0;")
        }
        _ if head.starts_with("return") => format!("{indent}return void 0;"),
        _ => format!("{indent}void 0;"),
    };
    out.push_str(&stub);
    out.push('\n');
}

/// The keyword and bound name of a `const`/`let`/`var` head, if it is one.
fn declaration(head: &str) -> Option<(&'static str, &str)> {
    for keyword in ["const ", "let ", "var "] {
        if let Some(rest) = head.strip_prefix(keyword) {
            let name = rest
                .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .next()
                .unwrap_or_default();
            return Some((keyword, name));
        }
    }
    None
}

/// An attacker rewriting a fragment rather than deleting it keeps the value and
/// changes the text — which is the same trick as `constant_rewrite`, aimed at one
/// site instead of the file.
/// §25's formatting change: every code line's indentation doubles, and an
/// argument list breaks across lines.
///
/// Both edits stay in code. A whole-file `replace(", ", ",\n  ")` — which is what
/// this did first, and what the hand-written fixtures caught — splits a
/// single-quoted string across two lines, which is a syntax error, and reflows a
/// triple-quoted one, which is a changed message. §25's premise is that these
/// forms preserve meaning, so the mask from [`crate::locate`] decides which bytes
/// a formatter is allowed to see.
fn reflow(body: &str) -> String {
    let broken = split_lists(body);
    let spans = crate::locate::string_spans(&broken);
    let mut out = String::with_capacity(broken.len() + 32);
    let mut line_start = 0usize;
    for line in broken.split_inclusive('\n') {
        let text = line.trim_end_matches(['\n', '\r']);
        let indent = text.len() - text.trim_start().len();
        // A line that opens inside a literal — the second line of a template
        // string, or the line holding its closing quote — keeps its text exactly:
        // its leading spaces, and the ones before its closing quote, are the
        // string's own characters.
        let opens_in_literal = spans
            .iter()
            .any(|(from, to)| line_start + indent >= *from && line_start + indent < *to);
        if opens_in_literal {
            out.push_str(text);
        } else {
            out.push_str(&" ".repeat(indent * 2));
            out.push_str(text.trim_start());
        }
        out.push('\n');
        line_start += line.len();
    }
    out.push('\n');
    out
}

/// `", "` becomes `",\n  "` wherever it separates arguments rather than sitting
/// inside a literal or a comment.
fn split_lists(body: &str) -> String {
    let mask = crate::locate::editable(body);
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len() + 16);
    let mut cut = 0usize;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b',' && bytes[i + 1] == b' ' && mask[i] && mask[i + 1] {
            out.push_str(&body[cut..i]);
            out.push_str(",\n  ");
            i += 2;
            cut = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&body[cut..]);
    out
}

fn equivalent_of(rendered: &str) -> String {
    let mut out = String::with_capacity(rendered.len());
    let mut run = String::new();
    for ch in rendered.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() {
            run.push(ch);
            continue;
        }
        let raw = std::mem::take(&mut run);
        match raw.parse::<u64>() {
            Ok(v) if v >= 16 => out.push_str(&format!("0x{:x}", v)),
            _ => out.push_str(&raw),
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::synthetic_project;
    use crate::project::Project;
    use crate::tmp::TempDir;

    fn tree() -> Tree {
        let dir = TempDir::new("transform-seed");
        synthetic_project(dir.path(), 9);
        read_tree(dir.path())
    }

    /// §25's premise, tested where it is weakest: a formatter may move code
    /// around, and may not touch what the program prints.
    ///
    /// The fixtures the measurement suites copy are hand-written and full of
    /// strings with commas in them — a message, a `console.log` argument list, a
    /// template spanning lines — and a whole-file reflow used to split those
    /// literals in two. That produced a "candidate" that no parser accepts, which
    /// every number beside it would have described as resilience.
    #[test]
    fn reflow_reindent_and_rewrap_code_but_never_a_literal() {
        let dir = TempDir::new("transform-reflow");
        crate::fixtures::javascript_project(dir.path());
        crate::fixtures::python_project(dir.path());
        let mut files = 0usize;
        for (rel, body) in read_tree(dir.path()) {
            let Some(source) = body.strip_suffix('\n').map(|s| s.to_string()) else {
                continue;
            };
            let after = reflow(&source);
            assert_ne!(after, source, "reflow did nothing to {rel}");
            assert_eq!(
                crate::locate::literals(&source),
                crate::locate::literals(&after),
                "reflow changed a string literal in {rel}"
            );
            // The whole of what a formatting change is allowed to be: whitespace.
            // Anything else in this file would be an edit to the program.
            let tight =
                |text: &str| -> String { text.chars().filter(|c| !c.is_whitespace()).collect() };
            assert_eq!(
                tight(&source),
                tight(&after),
                "reflow changed something besides the layout of {rel}"
            );
            files += 1;
        }
        assert!(files >= 4, "only {files} file(s) were checked");
    }

    #[test]
    fn every_refactoring_changes_the_tree() {
        // The assertion the measurement suites depend on: a transform that
        // matched nothing would report "detection survived `class_rename`" about
        // a tree nobody renamed anything in.
        //
        // The two §26 attacks that aim at a site are tested separately, below,
        // because on an unprotected tree they have nothing to aim at — which is
        // itself worth stating out loud.
        let base = tree();
        assert!(base.len() >= 8, "the seed tree is too small to transform");
        for t in Transform::ALL {
            if matches!(t, Transform::ArtifactRemoval | Transform::SiteRewrite) {
                // Nothing to attack. These two act on a tree that already holds a
                // fragment; on clean source they change no bytes, and saying so
                // here is what stops a later table from reporting "detection
                // survived" about an attack that ran into nothing.
                let mut untouched = base.clone();
                assert_eq!(
                    t.apply(&mut untouched, &[]),
                    0,
                    "{} changed a tree that holds nothing it acts on",
                    t.slug()
                );
                continue;
            }
            let mut copy = base.clone();
            let changed = t.apply(&mut copy, &[]);
            assert!(changed > 0, "{} changed no file at all", t.slug());
            assert!(
                copy.values().all(|b| !b.trim().is_empty()),
                "{} emptied a source file, which measures deletion, not refactoring",
                t.slug()
            );
        }
    }

    /// §26's premise, tested rather than assumed: an attacker who knows SWP-1
    /// exists can find the rendered fragments in the source, and can rewrite one
    /// without deleting it. If these two found nothing, every "the watermark was
    /// not removed" number in the validation report would be an artifact of the
    /// attack not having been carried out.
    #[test]
    fn the_two_site_attacks_find_real_fragments_in_a_real_tree() {
        let project = Project::synthetic("transform-attacks", 9);
        let release = project.protect();
        let sites: Vec<SiteText> = release
            .sites
            .iter()
            .filter_map(SiteText::from_manifest)
            .filter(|s| s.rendered != s.original)
            .collect();
        assert!(
            !sites.is_empty(),
            "a protected tree offered no fragment an attacker could locate"
        );
        let tree = read_tree(project.root());
        for t in [Transform::ArtifactRemoval, Transform::SiteRewrite] {
            let mut copy = tree.clone();
            let changed = t.apply(&mut copy, &sites);
            assert!(
                changed > 0,
                "{} looked for the rendered fragments and found none",
                t.slug()
            );
        }
        // Removing an artifact restores what the source said before it was
        // protected: that is the attack succeeding, not failing.
        let mut copy = tree.clone();
        Transform::ArtifactRemoval.apply(&mut copy, &sites);
        let removed = sites
            .iter()
            .filter(|s| copy.get(&s.file).is_some_and(|b| !b.contains(&s.rendered)))
            .count();
        assert!(
            removed * 2 >= sites.len(),
            "artifact removal reached only {removed} of {} sites",
            sites.len()
        );
    }

    #[test]
    fn a_refactored_tree_is_still_a_tree_of_the_same_programs() {
        // Structure, not syntax: file count, and every file still declaring its
        // functions. A transform that deleted half a module would make a later
        // "detection failed" result a statement about the transform.
        let base = tree();
        let functions = |tree: &Tree| -> usize {
            tree.values()
                .map(|b| b.matches("function ").count() + b.matches("class ").count())
                .sum()
        };
        for t in Transform::REFACTORING {
            let mut copy = base.clone();
            t.apply(&mut copy, &[]);
            assert_eq!(
                copy.len(),
                base.len(),
                "{} added or removed a file",
                t.slug()
            );
            for (rel, body) in &copy {
                assert!(
                    body.contains("function ") || body.contains("const RATES"),
                    "{rel} lost every declaration it had under {}",
                    t.slug()
                );
            }
            if t != Transform::DeadCodeRemoval && t != Transform::CommentRemoval {
                assert!(
                    functions(&copy) >= functions(&base),
                    "{} lost declarations: {} vs {} in the untouched tree",
                    t.slug(),
                    functions(&copy),
                    functions(&base)
                );
            }
        }
    }

    /// A mutation the suites call an attack has to leave a program behind, or the
    /// measurement is about the scanner meeting broken source instead of about a
    /// watermark surviving an edit.
    ///
    /// This is why `module_rebuild` keeps every line that opens or closes a block
    /// rather than a list of keywords: a stub that unbalances a brace turns a
    /// "17 of 24 sites found" row into a statement about the lexical fallback on
    /// a file no grammar accepts. The two site attacks are skipped because they
    /// act on a *protected* tree, and this one has nothing of theirs to remove.
    #[test]
    fn every_mutation_leaves_a_tree_the_grammar_accepts() {
        let registry = swp_adapters::Registry::standard();
        let limits = swp_core::limits::Limits::default();
        let base = tree();
        for t in Transform::ALL {
            if matches!(t, Transform::ArtifactRemoval | Transform::SiteRewrite) {
                continue;
            }
            let mut copy = base.clone();
            t.apply(&mut copy, &[]);
            for (rel, body) in &copy {
                let analysis = registry
                    .analyze(Path::new(rel), body, &limits)
                    .unwrap_or_else(|e| panic!("{} made {rel} unanalyzable: {e}", t.slug()));
                assert_eq!(
                    analysis.parse_errors,
                    0,
                    "{} left {} syntax error(s) in {rel}, so any detection number after it is a \
                     measurement of a fallback parser on broken code",
                    t.slug(),
                    analysis.parse_errors
                );
            }
        }
    }

    /// The attack has to actually attack.
    ///
    /// `module_rebuild`'s predecessor kept every `const` and `return` line as it
    /// found them, which kept the literals the fragments live in, and the number
    /// it printed described a rebuild nobody had carried out. A rebuild keeps
    /// declarations and block shape; what it loses is the code, and in this
    /// protocol the code *is* the literals — so the test is how many of them
    /// survive, not whether the file still looks like a file.
    #[test]
    fn a_rebuilt_module_loses_its_literals_and_keeps_its_shape() {
        let base = tree();
        let mut copy = base.clone();
        let changed = Transform::ModuleRebuild.apply(&mut copy, &[]);
        assert_eq!(changed, base.len(), "a module was left out of the rebuild");
        let before = numeric_values(&base);
        let after = numeric_values(&unstubbed(&copy));
        println!(
            "  module_rebuild left {} of {} free-standing numeric literals",
            after.len(),
            before.len()
        );
        assert!(
            after.len() * 2 <= before.len(),
            "a rebuild left {} of {} literals in place, so a survival number after it is a \
             measurement of a file that was never rebuilt",
            after.len(),
            before.len()
        );
        for (rel, body) in &copy {
            assert!(
                body.contains("function ") || body.contains("class "),
                "{rel} lost every declaration it had, which is deletion rather than rebuild"
            );
            assert!(body.contains("void 0;"), "{rel} lost no statement at all");
            assert!(
                body.contains("module.exports") || body.contains("exports."),
                "{rel} lost the interface the module publishes"
            );
        }
    }

    #[test]
    fn the_two_attack_lists_are_disjoint_and_together_everything() {
        assert_eq!(Transform::ALL.len(), 17);
        assert_eq!(
            Transform::REFACTORING.len() + Transform::ADVERSARIAL.len(),
            17
        );
        let mut slugs: Vec<&str> = Transform::ALL.iter().map(|t| t.slug()).collect();
        let unique = slugs.len();
        slugs.sort();
        slugs.dedup();
        assert_eq!(slugs.len(), unique, "two transforms share a name");
        for t in Transform::ALL {
            assert!(!t.describes().is_empty());
        }
        for t in Transform::ADVERSARIAL {
            assert!(
                !Transform::REFACTORING.contains(&t),
                "{} is in both lists",
                t.slug()
            );
        }
    }

    #[test]
    fn the_number_attacks_change_notation_and_not_value() {
        // §26's cheapest removal attempt is respelling. If either direction
        // changed a number's value the rest of the measurement would be about
        // broken code rather than about the watermark — so this compares the
        // numbers themselves, not a digit sum that a mangled literal can hide:
        // `0.249` respelled to `0.0xf9` keeps the digit count in the same ball
        // park and stops parsing as a number entirely.
        let before = numeric_values(&tree());
        let mut copy = tree();
        Transform::ConstantRewrite.apply(&mut copy, &[]);
        let hexed: Vec<String> = copy
            .values()
            .flat_map(|b| b.split_whitespace())
            .filter(|t| t.starts_with("0x"))
            .map(str::to_string)
            .collect();
        assert!(!hexed.is_empty(), "nothing was re-spelled in hex");
        let respelled = numeric_values(&copy);
        assert_eq!(
            before,
            respelled,
            "hex changed a value: {:?} vs {:?}",
            before.iter().take(8).collect::<Vec<_>>(),
            respelled.iter().take(8).collect::<Vec<_>>(),
        );
        Transform::ConstantNormalization.apply(&mut copy, &[]);
        let left: Vec<String> = copy
            .values()
            .flat_map(|b| b.split_whitespace())
            .filter(|t| t.contains("0x") || t.contains("0X"))
            .map(str::to_string)
            .collect();
        assert!(
            left.is_empty(),
            "normalization left hexadecimal behind: {left:?}"
        );
        assert_eq!(
            before,
            numeric_values(&copy),
            "normalizing the spelling did not put the values back"
        );
    }

    /// A rebuilt tree with its stubs removed, so counting literals counts the
    /// ones the rebuild preserved rather than the `0` in every `void 0;`.
    fn unstubbed(tree: &Tree) -> Tree {
        tree.iter()
            .map(|(rel, body)| (rel.clone(), body.replace("void 0;", "")))
            .collect()
    }

    /// Every free-standing numeric literal in a tree, as the value it denotes, in
    /// source order. A literal is free-standing when neither neighbour is part of
    /// an identifier or of the other half of a decimal, which is the same rule
    /// `hex_rewrite` uses — deliberately, because the point of the test is that
    /// one rule's respelling is the other rule's number, and two different
    /// definitions of "number" would let each be wrong about the other.
    fn numeric_values(tree: &Tree) -> Vec<String> {
        let mut out = Vec::new();
        for body in tree.values() {
            let chars: Vec<char> = body.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let free = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
                let starts = free
                    && (chars[i].is_ascii_digit()
                        || (chars[i] == '.'
                            && matches!(chars.get(i + 1), Some(d) if d.is_ascii_digit())));
                if !starts {
                    i += 1;
                    continue;
                }
                let start = i;
                let hex = chars[i] == '0' && matches!(chars.get(i + 1), Some('x') | Some('X'));
                i += if hex { 2 } else { 1 };
                while i < chars.len() && (chars[i].is_ascii_hexdigit() || (chars[i] == '.' && !hex))
                {
                    i += 1;
                }
                let run: String = chars[start..i].iter().collect();
                let run = run.trim_end_matches('.');
                let value = if let Some(digits) =
                    run.strip_prefix("0x").or_else(|| run.strip_prefix("0X"))
                {
                    u64::from_str_radix(digits, 16)
                        .ok()
                        .map(|v| format!("{v}.0"))
                } else {
                    run.parse::<f64>().ok().map(|v| format!("{v:?}"))
                };
                if let Some(v) = value {
                    out.push(v);
                }
            }
        }
        out
    }
}
