//! The foreign-binding boundary, enforced against the source it claims to describe.
//!
//! [docs/BINDING_SURFACE.json]( names five categories of `swp-sdk` API: what a
//! future Python or Node binding may wrap (`binding_facing`), what is public in Rust
//! on purpose and stays there (`rust_only`), what would hand a caller keyed or
//! private material (`forbidden`), what is meant to cross and cannot yet (`pending`),
//! and what must not become public at all (`sealed`). This suite is the difference
//! between that file being a contract and being a note: it reads the crate's sources
//! and fails when the two disagree, in either direction.
//!
//! Three properties the checks are built to have:
//!
//! * **Completeness.** Every `pub` item declared in `crates/swp-sdk/src` is
//!   classified, so growing the façade is a decision rather than a drift: a new
//!   `pub fn` that returns a keyed handle fails here, not in a reviewer's diff.
//! * **Containment.** A binding-facing type's public fields, and a binding-facing
//!   function's parameters and return, may name only other binding-facing types or
//!   the primitives and std containers the manifest lists. This is what catches a
//!   leak a plain name gives nothing away about: `ProtectOutcome` is an unremarkable
//!   word, and `protection.plan.sites[].locations` is `[LocationId; 4]`.
//! * **Independence.** `NEVER_BINDING_FACING` below repeats the privileged names in
//!   Rust. Editing the JSON cannot admit one of them, because the manifest and this
//!   gate would both have to say a name is safe — and for these names they cannot.
//! * **Cleanliness of the boundary itself.** The JSON is read by a binding that holds
//!   no key and so has nothing to compare against, and `u8` is an allowed inline name:
//!   hence the byte-shape ban on binding-facing fields and the key-shaped-text sweep of
//!   the file. Neither is a name check, so neither can be talked past by renaming.
//!
//! Nothing here opens a project, reads a store or touches a key: the suite reads
//! files and compiles, so it is deterministic, offline and identical on any machine.
//! A binding reuses the boundary by reading the same JSON, which is why the file
//! states its categories in data rather than in prose.

// The two pins below are the boundary stated as types rather than as text. They fail
// to compile if the API they describe stops existing, which is the point of pinning.

/// The leak this freeze records instead of repairing: the result of a public
/// `protect` reaches the keyed site identities of a private plan document. If `Plan`
/// ever stops carrying them this stops compiling, and the pin is deleted in the
/// change that removed the field.
const _: fn(&swp_sdk::ProtectOutcome) -> &[swp_core::id::LocationId; 4] =
    |outcome| &outcome.protection.plan.sites[0].locations;

/// The door that makes `Store` a Rust-only export: it unseals the root secret. Named
/// here so the manifest cannot quietly keep excluding an access that has closed.
const _: fn(
    &swp_identity::Store,
) -> Result<swp_crypto::secret::RootSecret, swp_core::error::SwpError> = |store| store.load_root();

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Where the boundary is written down. A binding reads this file; this suite reads
/// the source the file describes.
const MANIFEST: &str = "docs/BINDING_SURFACE.json";
const SDK_DIR: &str = "crates/swp-sdk/src";
const LIB_RS: &str = "crates/swp-sdk/src/lib.rs";

/// The five categories, and only these: a sixth is a new idea about the boundary and
/// has to be argued in Rust as well as in JSON.
const CATEGORIES: [&str; 5] = [
    "binding_facing",
    "rust_only",
    "forbidden",
    "pending",
    "sealed",
];

/// Privileged by name, listed here independently of the manifest. A binding-facing
/// entry naming any of these fails the gate however the JSON is edited.
const NEVER_BINDING_FACING: [&str; 33] = [
    "Store",
    "open_store",
    "load_root",
    "root_key_exists",
    "root_key_path",
    "private_dir",
    "read_private_manifest",
    "private_manifest_ids",
    "write_private_manifest",
    "plans_dir",
    "plan_path",
    "read_plan",
    "write_plan",
    "secret",
    "load_releases",
    "indexes",
    "loaded",
    "relabel",
    "build",
    "private_manifest",
    "as_slice",
    "fragment_tag",
    "expected_tag",
    "RootSecret",
    "SecretBytes",
    "ManifestKeys",
    "ReleaseIndex",
    "CandidateRelease",
    "LocationId",
    "Protection",
    "Plan",
    "PlannedSite",
    "SkippedSite",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    protocol: String,
    #[serde(rename = "crate")]
    crate_name: String,
    generated: bool,
    purpose: String,
    enforced_by: String,
    enforcement_source: String,
    notes: Vec<String>,
    inline_types: Vec<String>,
    modules: Vec<String>,
    surface: Vec<Group>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    category: String,
    meaning: String,
    items: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    kind: String,
    declared_in: String,
    #[serde(default)]
    reexported: bool,
    reason: String,
    #[serde(default)]
    blocked_by: Option<String>,
    #[serde(default)]
    must_be: Option<String>,
}

/// One `pub` declaration found in the crate's sources.
#[derive(Debug)]
struct Declaration {
    file: String,
    line: usize,
    kind: String,
    name: String,
    /// The `impl` target for a method; `None` for a free item.
    owner: Option<String>,
}

#[derive(Debug, Default)]
struct Scan {
    declarations: Vec<Declaration>,
    reexports: Vec<String>,
    modules: Vec<String>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: cannot read the source: {e}", path.display()))
}

fn load() -> Manifest {
    let text = read_repo(MANIFEST);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{MANIFEST}: {e}"))
}

/// Every entry with the category it sits in.
fn entries(manifest: &Manifest) -> Vec<(&'static str, &Entry)> {
    let mut out: Vec<(&'static str, &Entry)> = Vec::new();
    for group in &manifest.surface {
        let category: &'static str = match group.category.as_str() {
            "binding_facing" => "binding_facing",
            "rust_only" => "rust_only",
            "forbidden" => "forbidden",
            "pending" => "pending",
            "sealed" => "sealed",
            other => panic!("{MANIFEST}: unknown category {other:?}"),
        };
        for item in &group.items {
            out.push((category, item));
        }
    }
    out
}

fn name_of(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

fn source_files(dir: &str) -> Vec<String> {
    let absolute = repo_root().join(dir);
    let mut found: Vec<String> = std::fs::read_dir(&absolute)
        .unwrap_or_else(|e| panic!("{}: {e}", absolute.display()))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|e| e == "rs"))
        .filter_map(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| format!("{dir}/{n}"))
        })
        .collect();
    found.sort();
    found
}

/// The identifier a declaration keyword is followed by.
fn ident_after(text: &str, keyword: &str) -> Option<String> {
    let rest = text.strip_prefix(keyword)?.strip_prefix(' ')?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// The type an `impl` header is for, or `None` for a trait implementation, whose
/// methods are reached through the trait rather than by name.
fn impl_target(line: &str) -> Option<String> {
    let body = line.trim_end_matches('{').trim();
    let body = body.strip_prefix("impl")?;
    if body.contains(" for ") {
        return None;
    }
    ident_after(body, "")
}

/// The `pub` declarations, re-exported names and module statements of one source
/// file. Test modules are skipped: they are this crate's own business, not its
/// surface.
fn scan_file(relative: &str) -> Scan {
    let text = read_repo(relative);
    let mut scan = Scan::default();
    let mut in_test_module = false;
    let mut owner: Option<String> = None;
    let mut open_use: Option<String> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if let Some(statement) = open_use.take() {
            let mut joined = statement;
            joined.push(' ');
            joined.push_str(line);
            if closed_use(&joined) {
                scan.reexports.extend(use_names(&joined));
            } else {
                open_use = Some(joined);
            }
            continue;
        }
        if in_test_module {
            if line == "}" {
                in_test_module = false;
            }
            continue;
        }
        if line.starts_with("mod ") && line.ends_with('{') {
            in_test_module = true;
            continue;
        }
        if line.starts_with("impl") {
            owner = impl_target(line);
            continue;
        }
        if line == "}" {
            owner = None;
            continue;
        }
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("use ") {
            if closed_use(rest) {
                scan.reexports.extend(use_names(rest));
            } else {
                open_use = Some(rest.to_string());
            }
            continue;
        }
        if let Some(name) = ident_after(rest, "mod") {
            scan.modules.push(name);
            continue;
        }
        for keyword in ["struct", "enum", "trait", "type", "fn", "const", "static"] {
            if let Some(name) = ident_after(rest, keyword) {
                scan.declarations.push(Declaration {
                    file: relative.to_string(),
                    line: index + 1,
                    kind: keyword.to_string(),
                    name,
                    owner: owner.clone(),
                });
                break;
            }
        }
    }
    assert!(
        open_use.is_none(),
        "{relative}: a `pub use` whose braces never closed"
    );
    scan
}

fn closed_use(statement: &str) -> bool {
    statement.contains(';') && count(statement, '{') == count(statement, '}')
}

fn count(text: &str, needle: char) -> usize {
    text.chars().filter(|c| *c == needle).count()
}

/// The names a `pub use` brings in, in either form this crate uses.
fn use_names(statement: &str) -> Vec<String> {
    let body = statement
        .trim()
        .trim_end_matches(';')
        .trim_end()
        .to_string();
    if let Some(open) = body.find('{') {
        let close = body.rfind('}').unwrap_or(body.len());
        return split_top(&body[open + 1..close])
            .into_iter()
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .map(|part| name_of(&part).to_string())
            .collect();
    }
    vec![name_of(&body).to_string()]
}

/// A type declaration's header and body lines, up to its closing brace.
fn declaration_lines(file: &str, keyword: &str, name: &str) -> Vec<String> {
    let text = read_repo(file);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let prefix = format!("pub {keyword} {name}");
    let header = lines
        .iter()
        .position(|line| {
            line.starts_with(&prefix)
                && line[prefix.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '-'))
        })
        .unwrap_or_else(|| panic!("{file}: no `{prefix}` to classify"));
    let mut body = vec![lines[header].to_string()];
    if lines[header].ends_with(';') {
        // A tuple struct, a unit struct or a type alias: the header is the whole body.
        return body;
    }
    for line in &lines[header + 1..] {
        if *line == "}" {
            return body;
        }
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        body.push(line.to_string());
    }
    panic!("{file}: {} {name} has no closing brace", keyword);
}

/// The public type expressions a declaration exposes: the fields marked `pub`, and
/// every enum variant's payload.
fn public_members(file: &str, kind: &str, name: &str) -> Vec<String> {
    let lines = declaration_lines(file, kind, name);
    let mut members = Vec::new();
    match kind {
        "struct" => {
            let header = &lines[0];
            let after = header
                .split_once(name)
                .map(|(_, rest)| rest.trim_start().to_string())
                .unwrap_or_default();
            if after.starts_with('(') {
                for part in split_top(&between(header, '(', ')')) {
                    if let Some(rest) = part.trim().strip_prefix("pub ") {
                        members.push(rest.trim().trim_end_matches(',').to_string());
                    }
                }
                return members;
            }
            let mut held: Option<String> = None;
            for line in &lines[1..] {
                if let Some(mut buffer) = held.take() {
                    buffer.push(' ');
                    buffer.push_str(line);
                    if balanced(&buffer) {
                        members.push(buffer);
                    } else {
                        held = Some(buffer);
                    }
                    continue;
                }
                let Some(rest) = line.strip_prefix("pub ") else {
                    continue;
                };
                let Some(colon) = rest.find(':') else {
                    continue;
                };
                let ty = rest[colon + 1..].trim().trim_end_matches(',').to_string();
                if balanced(&ty) {
                    members.push(ty);
                } else {
                    held = Some(ty);
                }
            }
        }
        "enum" => {
            for line in &lines[1..] {
                let variant = line.trim_end_matches(',').trim();
                if variant.is_empty() {
                    continue;
                }
                if let Some(open) = variant.find('{') {
                    let close = variant.rfind('}').unwrap_or(variant.len());
                    for part in split_top(&variant[open + 1..close]) {
                        if let Some(colon) = part.find(':') {
                            members.push(part[colon + 1..].trim().to_string());
                        }
                    }
                } else if variant.contains('(') {
                    for part in split_top(&between(variant, '(', ')')) {
                        members.push(part.trim().to_string());
                    }
                }
            }
        }
        other => panic!("no member model for a {other}"),
    }
    members
}

/// The text between the first `open` and its matching `close`.
fn between(text: &str, open: char, close: char) -> String {
    let mut depth = 0usize;
    let mut started = false;
    let mut out = String::new();
    for c in text.chars() {
        if c == open {
            depth += 1;
            started = true;
            if depth == 1 {
                continue;
            }
        }
        if c == close {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        if started {
            out.push(c);
        }
    }
    out
}

/// Split on commas that are not inside brackets, braces or angle brackets.
fn split_top(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

fn balanced(text: &str) -> bool {
    let mut depth = 0i32;
    for c in text.chars() {
        match c {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    depth <= 0
}

/// Drop whitespace and lifetimes, then peel the wrappers that carry no name.
fn normalize(ty: &str) -> String {
    let mut out = String::new();
    let mut chars = ty.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '\'' {
            while chars
                .peek()
                .is_some_and(|n| n.is_alphanumeric() || *n == '_')
            {
                chars.next();
            }
            continue;
        }
        out.push(c);
    }
    loop {
        let peeled: Option<String> = ["&", "*const", "*mut", "mut"]
            .iter()
            .find_map(|prefix| out.strip_prefix(prefix))
            .map(str::to_string);
        match peeled {
            Some(next) => out = next,
            None => break,
        }
    }
    out
}

/// Every named type in a type expression, with containers descended into.
fn type_names(ty: &str) -> Vec<String> {
    let mut found = Vec::new();
    collect(normalize(ty).as_str(), &mut found);
    found
}

fn collect(text: &str, out: &mut Vec<String>) {
    if text.is_empty() {
        return;
    }
    if let Some(inner) = text.strip_prefix('[') {
        let element = inner.trim_end_matches(']').split(';').next().unwrap_or("");
        collect(normalize(element).as_str(), out);
        return;
    }
    if let Some(inner) = text.strip_prefix('(') {
        for part in split_top(inner.trim_end_matches(')')) {
            collect(normalize(&part).as_str(), out);
        }
        return;
    }
    if text.ends_with('>') {
        if let Some(open) = text.find('<') {
            let base = normalize(&text[..open]);
            if !base.is_empty() && base != "_" {
                out.push(base);
            }
            for part in split_top(&text[open + 1..text.len() - 1]) {
                collect(normalize(&part).as_str(), out);
            }
            return;
        }
    }
    let name = name_of(text).to_string();
    if !name.is_empty() && name != "_" {
        out.push(name);
    }
}

/// The parameter and return types of one public function, as written.
fn signature_types(file: &str, name: &str) -> Vec<String> {
    let text = read_repo(file);
    let lines: Vec<String> = text.lines().map(|line| line.trim().to_string()).collect();
    let header = lines
        .iter()
        .position(|line| {
            let Some(rest) = line.strip_prefix("pub ") else {
                return false;
            };
            ident_after(rest, "fn").is_some_and(|found| found == name)
        })
        .unwrap_or_else(|| panic!("{file}: no `pub fn {name}` to classify"));
    let mut signature = String::new();
    for line in &lines[header..] {
        signature.push_str(line);
        signature.push(' ');
        if line.contains('{') || line.ends_with(';') {
            break;
        }
    }
    let mut types = Vec::new();
    for part in split_top(&between(&signature, '(', ')')) {
        let part = part.trim();
        if part.is_empty() || part.ends_with("self") {
            continue;
        }
        if let Some(colon) = part.find(':') {
            types.push(part[colon + 1..].trim().to_string());
        }
    }
    if let Some(arrow) = signature.find("->") {
        let tail = signature[arrow + 2..]
            .trim()
            .trim_end_matches('{')
            .trim_end()
            .to_string();
        types.push(tail);
    }
    types
}

/// The visibility a named item is declared with.
fn visibility(file: &str, name: &str) -> (String, usize) {
    let text = read_repo(file);
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        for (marker, found) in [
            ("pub fn", "pub"),
            ("pub(crate) fn", "pub(crate)"),
            ("pub(super) fn", "pub(super)"),
            ("fn", "private"),
            ("pub struct", "pub"),
            ("pub(crate) struct", "pub(crate)"),
        ] {
            let head = format!("{marker} {name}");
            if let Some(at) = line.find(&head) {
                if !line[..at].is_empty() {
                    continue;
                }
                let follows = line[at + head.len()..].chars().next();
                if matches!(follows, Some('(') | Some('<') | Some(' ') | None) {
                    return (found.to_string(), index + 1);
                }
            }
        }
    }
    panic!("{file}: no declaration named {name}");
}

/// Whether one file really declares the item an entry points at.
fn declares(file: &str, kind: &str, name: &str) -> bool {
    let text = read_repo(file);
    match kind {
        "struct" | "enum" | "trait" | "type" => {
            let prefix = format!("pub {kind} {name}");
            text.lines().map(str::trim).any(|line| {
                line.starts_with(&prefix)
                    && line[prefix.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            })
        }
        "fn" => text.lines().map(str::trim).any(|line| {
            let head = format!("fn {name}");
            let Some(at) = line.find(&head) else {
                return false;
            };
            matches!(
                line[at + head.len()..].chars().next(),
                Some('(') | Some('<') | Some(' ') | None
            )
        }),
        "const" | "static" => text.contains(&format!("{kind} {name}")),
        _ => false,
    }
}

/// The facts an entry asserts about itself, independent of its category.
fn problems_of(category: &str, entry: &Entry, manifest: &Manifest) -> Vec<String> {
    let mut problems = Vec::new();
    if !repo_root().join(&entry.declared_in).is_file() {
        problems.push(format!(
            "{category}: {} files itself under {}, which does not exist",
            entry.path, entry.declared_in
        ));
    } else if !declares(&entry.declared_in, &entry.kind, name_of(&entry.path)) {
        problems.push(format!(
            "{category}: {} is a {} filed under {}, which declares no such {}",
            entry.path, entry.kind, entry.declared_in, entry.kind
        ));
    }
    if entry.reason.trim().len() < 20 {
        problems.push(format!(
            "{category}: {} states no reason worth reading: {:?}",
            entry.path, entry.reason
        ));
    }
    if category == "pending" {
        let blocker = entry
            .blocked_by
            .as_ref()
            .unwrap_or_else(|| panic!("pending: {} does not name what blocks it", entry.path));
        let known = entries(manifest)
            .iter()
            .any(|(_, other)| name_of(&other.path) == name_of(blocker));
        assert!(
            known,
            "pending: {blocker} blocks {} and is not in the manifest",
            entry.path
        );
    }
    problems
}

#[test]
fn the_manifest_is_the_contract_a_binding_reads() {
    let manifest = load();
    assert_eq!(manifest.schema, "swp-binding-surface-v1");
    assert_eq!(manifest.protocol, "SWP-1");
    assert_eq!(manifest.crate_name, "swp-sdk");
    assert!(
        !manifest.generated,
        "{MANIFEST} is written by hand; a generated boundary would enforce nothing"
    );
    assert!(manifest.purpose.len() > 40, "{MANIFEST} states no purpose");
    assert!(
        manifest.enforced_by.contains("binding_surface"),
        "{MANIFEST} does not name the gate that enforces it"
    );
    assert_eq!(
        manifest.enforcement_source,
        "crates/swp-test-suite/tests/binding/surface.rs"
    );
    assert!(
        manifest.notes.len() >= 4,
        "{MANIFEST} barely explains itself"
    );
    let listed: BTreeSet<&str> = manifest
        .surface
        .iter()
        .map(|g| g.category.as_str())
        .collect();
    for expected in CATEGORIES {
        assert!(
            listed.contains(expected),
            "{MANIFEST} has no {expected} group"
        );
    }
    for group in &manifest.surface {
        assert!(
            !group.items.is_empty(),
            "{} is an empty group",
            group.category
        );
        assert!(
            group.meaning.len() > 20,
            "{} says what it means",
            group.category
        );
    }

    // One classification per item, and no two type entries sharing a name, so that a
    // type appearing in a field resolves to exactly one entry.
    let mut seen = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut problems = Vec::new();
    for (category, entry) in entries(&manifest) {
        assert!(
            seen.insert((entry.declared_in.clone(), name_of(&entry.path).to_string())),
            "{MANIFEST}: {} is classified twice",
            entry.path
        );
        if matches!(entry.kind.as_str(), "struct" | "enum") {
            assert!(
                types.insert(name_of(&entry.path).to_string()),
                "{MANIFEST}: two entries are named {}, so a field of that type would be ambiguous",
                name_of(&entry.path)
            );
        }
        problems.extend(problems_of(category, entry, &manifest));
    }
    assert!(
        problems.is_empty(),
        "{MANIFEST} does not describe the tree:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_public_item_in_the_facade_is_classified() {
    let manifest = load();
    let mut unclassified: Vec<String> = Vec::new();
    for file in source_files(SDK_DIR) {
        for declaration in scan_file(&file).declarations {
            let classified = entries(&manifest).iter().any(|(_, entry)| {
                entry.declared_in == declaration.file && name_of(&entry.path) == declaration.name
            });
            if classified {
                continue;
            }
            let path = match &declaration.owner {
                Some(owner) => format!("swp_sdk::{owner}::{}", declaration.name),
                None if file == LIB_RS => format!("swp_sdk::{}", declaration.name),
                None => format!(
                    "swp_sdk::{}::{}",
                    Path::new(&file)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .expect("a file stem"),
                    declaration.name
                ),
            };
            unclassified.push(format!(
                "{}:{}: `pub {} {path}` is not in {MANIFEST}",
                declaration.file, declaration.line, declaration.kind,
            ));
        }
    }
    assert!(
        unclassified.is_empty(),
        "the façade grew past its boundary:\n{}",
        unclassified.join("\n")
    );
}

#[test]
fn the_reexports_and_modules_are_the_manifests() {
    let manifest = load();
    let scan = scan_file(LIB_RS);
    assert_eq!(
        scan.modules, manifest.modules,
        "{LIB_RS} and {MANIFEST} disagree about the modules the façade opens"
    );
    let reexported: BTreeSet<String> = scan.reexports.into_iter().collect();
    let marked: BTreeSet<String> = entries(&manifest)
        .iter()
        .filter(|(_, entry)| entry.reexported)
        .map(|(_, entry)| name_of(&entry.path).to_string())
        .collect();
    assert_eq!(
        reexported, marked,
        "{LIB_RS} re-exports a different set of names than {MANIFEST} marks `reexported`"
    );
    let text = read_repo(LIB_RS);
    for forbidden_source in ["swp_crypto", "swp_manifest", "swp_detection"] {
        assert!(
            !text.contains(&format!("pub use {forbidden_source}::")),
            "{LIB_RS} re-exports from {forbidden_source}, which would make a key, a keyed document or a \
             keyed index nameable from the façade"
        );
    }
}

/// The sealed half of the boundary: an accessor that returns keyed material or a
/// store handle is not public today, and this fails if one becomes public.
#[test]
fn keyed_accessors_are_still_sealed() {
    let manifest = load();
    let mut checked = 0usize;
    for (category, entry) in entries(&manifest) {
        if category != "sealed" {
            continue;
        }
        checked += 1;
        let must_be = entry
            .must_be
            .as_deref()
            .unwrap_or_else(|| panic!("sealed: {} states no visibility to keep", entry.path));
        let (found, line) = visibility(&entry.declared_in, name_of(&entry.path));
        assert_eq!(
            found, must_be,
            "{}:{}: being {must_be} is what keeps {} out of a binding; it is now `{found}`",
            entry.declared_in, line, entry.path
        );
    }
    assert!(checked >= 9, "{MANIFEST} seals only {checked} accessors");
}

#[test]
fn a_binding_facing_type_reaches_only_binding_facing_types() {
    let manifest = load();
    let allowed: BTreeSet<String> = entries(&manifest)
        .iter()
        .filter(|(category, entry)| {
            *category == "binding_facing" && matches!(entry.kind.as_str(), "struct" | "enum")
        })
        .map(|(_, entry)| name_of(&entry.path).to_string())
        .collect();
    let inline: BTreeSet<String> = manifest.inline_types.iter().cloned().collect();
    let mut leaks: Vec<String> = Vec::new();
    for (category, entry) in entries(&manifest) {
        if category != "binding_facing" || !matches!(entry.kind.as_str(), "struct" | "enum") {
            continue;
        }
        for member in public_members(&entry.declared_in, &entry.kind, name_of(&entry.path)) {
            for token in type_names(&member) {
                if inline.contains(&token) || allowed.contains(&token) {
                    continue;
                }
                let here = entries(&manifest)
                    .iter()
                    .find(|(_, other)| name_of(&other.path) == token)
                    .map(|(other, item)| format!("{other}, at {}", item.path))
                    .unwrap_or_else(|| "classified nowhere".to_string());
                leaks.push(format!(
                    "{} reaches {token}, which is {here}: {member}",
                    entry.path
                ));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "something on the binding-facing side reaches off it:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_binding_facing_call_signs_only_binding_facing_types() {
    let manifest = load();
    let allowed: BTreeSet<String> = entries(&manifest)
        .iter()
        .filter(|(category, _)| *category == "binding_facing")
        .map(|(_, entry)| name_of(&entry.path).to_string())
        .collect();
    let inline: BTreeSet<String> = manifest.inline_types.iter().cloned().collect();
    let mut leaks: Vec<String> = Vec::new();
    for (category, entry) in entries(&manifest) {
        if category != "binding_facing" || entry.kind != "fn" {
            continue;
        }
        for ty in signature_types(&entry.declared_in, name_of(&entry.path)) {
            for token in type_names(&ty) {
                if inline.contains(&token) || allowed.contains(&token) {
                    continue;
                }
                leaks.push(format!(
                    "{} takes or returns {token}, which is not binding-facing: {ty}",
                    entry.path
                ));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "a binding-facing call crosses the boundary in its signature:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn nothing_privileged_is_listed_as_binding_facing() {
    let manifest = load();
    let mut violations: Vec<String> = Vec::new();
    for (category, entry) in entries(&manifest) {
        if category == "binding_facing" && NEVER_BINDING_FACING.contains(&name_of(&entry.path)) {
            violations.push(format!(
                "{} is {}, which this gate will not let into the boundary",
                entry.path,
                name_of(&entry.path)
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "the JSON and this gate disagree about what is privileged:\n{}",
        violations.join("\n")
    );
    // The list is only worth having while it names things that still exist.
    for name in NEVER_BINDING_FACING {
        assert!(
            entries(&manifest)
                .iter()
                .any(|(_, entry)| name_of(&entry.path) == name),
            "NEVER_BINDING_FACING names {name}, which the manifest has lost: retire the entry with the API"
        );
    }
}

#[test]
fn the_keyed_half_of_a_protect_result_stays_out_of_the_boundary() {
    let manifest = load();
    let category_of = |name: &str| -> String {
        entries(&manifest)
            .iter()
            .find(|(_, entry)| name_of(&entry.path) == name)
            .map(|(category, _)| (*category).to_string())
            .unwrap_or_else(|| panic!("{MANIFEST} has no entry named {name}"))
    };
    for keyed in ["LocationId", "PlannedSite", "Plan", "Protection"] {
        assert_eq!(category_of(keyed), "forbidden", "{keyed} is keyed material");
    }
    assert_eq!(category_of("ProtectOutcome"), "pending");
    assert_eq!(category_of("open_store"), "rust_only");
    assert_eq!(category_of("Store"), "rust_only");
    // The pin above is a claim about this build, not a story: the field it reads is
    // the one `Store::write_plan` puts under `.swp/private/plans/`.
    let plan = read_repo("crates/swp-embedding/src/plan.rs");
    assert!(
        plan.contains("pub locations: [LocationId; 4]"),
        "the pinned keyed field has moved: change the boundary and the pin together"
    );
}

#[test]
fn the_operations_a_binding_may_be_built_on_are_all_named() {
    let manifest = load();
    let calls: BTreeSet<String> = entries(&manifest)
        .iter()
        .filter(|(category, entry)| *category == "binding_facing" && entry.kind == "fn")
        .map(|(_, entry)| name_of(&entry.path).to_string())
        .collect();
    for expected in [
        "open",
        "discover",
        "init",
        "verify",
        "scan",
        "reports",
        "read_report",
        "identity",
        "config",
        "stored_config",
        "warnings",
        "limits",
        "releases",
        "one_release",
        "release_history",
        "release",
        "project_root",
        "capabilities",
        "banner",
        "report_stem",
        "suggest_sites",
        "new",
    ] {
        assert!(
            calls.contains(expected),
            "{MANIFEST} no longer offers {expected} to a binding"
        );
    }
    assert!(
        !calls.contains("protect"),
        "protect is `pending`: a manifest that moved it into the boundary would have to answer \
         for the plan field first"
    );
}

/// Type names that mean "this field is keyed material", checked against the field's
/// own type expression rather than the entry's prose.
const KEYED_FIELD_TYPES: [&str; 8] = [
    "LocationId",
    "SecretBytes",
    "RootSecret",
    "ManifestKeys",
    "SiteTag",
    "Plan",
    "PlannedSite",
    "Protection",
];

/// A byte blob is how a key or a keyed id looks once it has been unwrapped from its
/// newtype, and `u8` is an allowed inline name, so containment alone would let
/// `pub sites: Vec<u8>` through. Only one binding-facing type carries bytes at all:
/// the public SHA-256 of already-published material.
const BYTE_SHAPES: [&str; 4] = ["[u8;", "&[u8]", "Vec<u8>", "[u8]"];
const BYTE_CARRIERS: [&str; 1] = ["Digest"];

#[test]
fn a_binding_facing_field_is_never_keyed_material() {
    let manifest = load();
    let mut leaks: Vec<String> = Vec::new();
    let mut read = 0usize;
    for (category, entry) in entries(&manifest) {
        if category != "binding_facing" || !matches!(entry.kind.as_str(), "struct" | "enum") {
            continue;
        }
        let name = name_of(&entry.path);
        for member in public_members(&entry.declared_in, &entry.kind, name) {
            read += 1;
            for token in type_names(&member) {
                if KEYED_FIELD_TYPES.contains(&token.as_str()) {
                    leaks.push(format!(
                        "{} exposes a field of keyed type {token}: {member}",
                        entry.path
                    ));
                }
            }
            if !BYTE_CARRIERS.contains(&name)
                && BYTE_SHAPES.iter().any(|shape| member.contains(shape))
            {
                leaks.push(format!(
                    "{} exposes a raw byte field, which is how a key looks once its newtype is \
                     gone: {member}",
                    entry.path
                ));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "the boundary has a keyed value in it:\n{}",
        leaks.join("\n")
    );
    assert!(
        read > 60,
        "this check only read {read} public field(s) of the binding-facing types, which means it \
         is not looking at the boundary at all"
    );
}

/// Runs of hex or base64 long enough to be a key or a keyed id: 32 hex characters is
/// one `LocationId`, 64 hex or 44 base64 is one root secret.
fn secret_shaped_runs(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut run = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        if run.len() >= 32 {
            found.push(format!("{} hex characters", run.len()));
        }
        run.clear();
    }
    let mut b64 = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            b64.push(c);
            continue;
        }
        // An underscore, a colon or a hyphen breaks both this run and a real key,
        // which is base64 of raw bytes and contains neither.
        if b64.len() >= 44 {
            found.push(format!("{} base64 characters", b64.len()));
        }
        b64.clear();
    }
    found
}

/// Long runs of hex or base64 in the boundary file would be a key or a keyed id
/// written down next to the thing that forbids them. `secret_leak` sweeps the
/// artifacts a *run* produces; nothing else sweeps this file, which is hand-written
/// and read by a binding that has no key to compare against.
#[test]
fn the_manifest_file_carries_no_secret_shaped_text() {
    // The detector is shown to detect, or its silence on the real file means nothing.
    let hex = "0123456789abcdef".repeat(4);
    let b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    assert_eq!(
        secret_shaped_runs(&format!("\"a\": \"{hex}\",\n\"b\": \"{b64}\"\n")).len(),
        3,
        "the detector missed a key-shaped run"
    );
    assert!(
        secret_shaped_runs("\"path\": \"swp_identity::Store::read_private_manifest\"").is_empty()
    );

    let text = read_repo(MANIFEST);
    let found = secret_shaped_runs(&text);
    assert!(
        found.is_empty(),
        "{MANIFEST} contains text shaped like key material: {}",
        found.join(", ")
    );
}
