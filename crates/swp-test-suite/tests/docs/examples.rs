//! Every `console` block in the documentation is a transcript this build
//! still produces.
//!
//! The rule the section states is that a documented command must have been run,
//! and a documentation example that no longer works must fail the build. That is
//! only achievable if the quoted lines are machine-checkable, so the examples
//! carry a small convention, written out in `examples/javascript/README.md` and
//! repeated here because it is what makes the check possible:
//!
//! * a ` ```console ` block is verbatim tool output, produced by
//!   `scripts/capture-docs.sh` and re-produced here;
//! * the block's first line is `$ swp <args>`, and the lines under it are checked
//!   against the transcript of *that* command, so output cannot be quoted under a
//!   command that never printed it;
//! * `…` stands for whatever this project's secret influences — an id, a digest,
//!   a byte total, a keyed literal — and matches either the rest of a word or a
//!   whole run of words on its own;
//! * a block is matched as an ordered subsequence, so eliding a section of a
//!   transcript is allowed and inventing a line is not;
//! * whitespace is insignificant, because the product aligns columns and a
//!   document should be quoting a result rather than a layout;
//! * a line with no `…` is therefore asserting an exact number: which default
//!   `tag_bits` has, how many sites this tree can hold, what a scan of a copy of
//!   it says. Those are the lines this suite exists to catch going stale.
//!
//! Nothing here compares a transcript against a stored snapshot. The four trees
//! are protected from scratch under a fresh root secret on every run, which is
//! what "validated against the real implementation" asks for, and the only
//! thing a block may quote is what the fresh run printed.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use swp_test_suite::TempDir;

/// The four example trees, in the order `scripts/capture-docs.sh` protects
/// them in: `javascript` scans a *protected* TypeScript tree, so TypeScript has
/// to have run before it.
const EXAMPLES: [&str; 4] = ["typescript", "python", "javascript", "generic"];

/// `…`, the one character a documented line may use to stand for what the key
/// decides.
const ELISION: char = '\u{2026}';
const ELISION_STR: &str = "\u{2026}";

/// Where the documentation lives. The suite reads the shipped sources rather than
/// copies of them, which is the only way a stale sentence in the repository is the
/// thing that fails.
fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

/// The repository root, which every page below is relative to.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every page the documentation test checks, and the example project its
/// unlabelled `console` blocks quote. This list *is* the page index: adding a page
/// here is how it becomes checked, and deleting a page without deleting its entry
/// fails the run.
const PAGES: [(&str, &str); 9] = [
    ("README.md", "javascript"),
    ("docs/GETTING-STARTED.md", "javascript"),
    ("docs/USER-GUIDE.md", "javascript"),
    ("docs/CLI.md", "javascript"),
    ("docs/TROUBLESHOOTING.md", "javascript"),
    ("docs/SECURITY.md", "javascript"),
    ("docs/SWP-1-SPEC.md", "javascript"),
    ("docs/DEVELOPER-GUIDE.md", "javascript"),
    ("docs/VALIDATION.md", "javascript"),
];

/// One command's transcript, in the shape the documentation echoes it.
struct Shot {
    /// `$ swp protect --sites 12` — the line a reader would type, with the build
    /// artifact's own path left out because it is not part of the example.
    header: String,
    lines: Vec<String>,
    code: i32,
}

impl Shot {
    /// The transcript below its header line, which is what a block's body matches.
    fn body(&self) -> &[String] {
        &self.lines[1..]
    }
}

/// A writer two commands' streams share, so that a `warning:` line lands where the
/// product printed it rather than after everything the command also wrote. The
/// documentation quotes an interleaved transcript because that is what a terminal
/// shows, and because the alternative is a document that silently reorders its own
/// evidence.
#[derive(Clone)]
struct Tee(Rc<RefCell<Vec<u8>>>);

impl Write for Tee {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run one command in `cwd` and render it the way the capture script does.
fn shoot(argv: &[&str], cwd: &Path) -> Shot {
    let owned: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
    let shared = Rc::new(RefCell::new(Vec::new()));
    let (mut out, mut err) = (Tee(Rc::clone(&shared)), Tee(Rc::clone(&shared)));
    let code = swp_cli::run_in(&owned, cwd, &mut out, &mut err);

    let text = String::from_utf8_lossy(&shared.borrow()).into_owned();
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| line.trim_end().to_string())
        .collect();
    while lines.last().map(String::is_empty).unwrap_or(false) {
        lines.pop();
    }
    lines.insert(0, format!("$ swp {}", owned.join(" ")));
    // `scan`, `verify` and `report` print their own exit code as their last line, so
    // that a script can read it from a log. Every other command does not, and the
    // transcript records what happened for all of them the same way.
    let tail = lines.last().cloned().unwrap_or_default();
    if !tail.starts_with(&format!("exit {code}")) {
        lines.push(format!("exit {code}"));
    }
    Shot {
        header: lines[0].clone(),
        lines,
        code,
    }
}

/// Protect one example from a clean copy of it, and return every transcript the
/// documentation may quote, keyed by the line a reader would type.
///
/// The layout is the capture script's: `<work>/<example>` beside `<work>/plain`,
/// because what `swp scan ../plain` is evidence *of* depends on what `../plain`
/// holds — the Python sources exactly as they were written, in a tree this project
/// never touched.
fn capture(work: &Path, example: &str) -> BTreeMap<String, Shot> {
    let dir = work.join(example);
    copy_tree(&examples_dir().join(example), &dir);
    let plain = work.join("plain");
    copy_files(
        &examples_dir().join("python").join("src"),
        &plain.join("src"),
    );
    let _ = std::fs::copy(
        examples_dir().join("python").join("pyproject.toml"),
        plain.join("pyproject.toml"),
    );

    let mut shots: BTreeMap<String, Shot> = BTreeMap::new();
    record(&mut shots, shoot(&["init"], &dir));
    record(&mut shots, shoot(&["generate"], &dir));
    // A dry run before the real one, because it writes nothing and its transcript
    // is the one the documentation shows: what protect would do to a clean tree.
    record(&mut shots, shoot(&["protect", "--dry-run"], &dir));
    record(&mut shots, shoot(&["protect", "--sites", "12"], &dir));
    record(&mut shots, shoot(&["verify"], &dir));
    // The JSON view of the same command, before the copy exists: `verify` reads the
    // tree it is standing in, so a transcript of it is only quotable against the
    // tree the documentation describes, and every page quotes the clean one.
    record(&mut shots, shoot(&["verify", "--format", "json"], &dir));

    let copy_src = dir.join("copy").join("src");
    copy_files(&dir.join("src"), &copy_src);
    record(&mut shots, shoot(&["scan", "./copy"], &dir));
    record(&mut shots, shoot(&["scan", "../plain"], &dir));
    // The same untouched tree, asked the other question: `verify` there is the
    // failure a reader hits when they run the command before `swp init`, and the
    // answer has to be quotable rather than described.
    record(&mut shots, shoot(&["verify", "-p", "../plain"], &dir));
    if example == "javascript" {
        // A second, unrelated protected tree, so that a page can show what a near
        // miss looks like rather than describe it. Its own `init` and `protect`
        // transcripts are deliberately not recorded: the shot map is keyed by the
        // line a reader types, and a second `swp init` there would replace the
        // JavaScript run every other block on these pages is quoting.
        let foreign = work.join("typescript-foreign");
        copy_tree(&examples_dir().join("typescript"), &foreign);
        let _ = shoot(&["init"], &foreign);
        let _ = shoot(&["protect", "--sites", "12"], &foreign);
        record(&mut shots, shoot(&["scan", "../typescript-foreign"], &dir));
    }
    record(&mut shots, shoot(&["inspect", "releases"], &dir));

    // The store-side views need the release this run published, which is a fresh id
    // every time: read it off the filesystem rather than pasting one in.
    let release = staged(&dir, ".swp/public/releases");
    if let Some(release) = &release {
        for view in ["release", "plan", "fragments", "manifest"] {
            record(
                &mut shots,
                shoot(&["inspect", view, "--release", release], &dir),
            );
        }
        record(
            &mut shots,
            shoot(&["verify", "--release", release, "--save"], &dir),
        );
        record(&mut shots, shoot(&["report"], &dir));
        if let Some(stem) = staged(&dir, ".swp/private/reports") {
            record(&mut shots, shoot(&["report", &stem], &dir));
        }
    }

    // The interface pages, run last so that nothing here can disturb the numbers
    // the sequence above printed: every one of these is read-only or fails early.
    for argv in [
        &["--version"][..],
        &["help"][..],
        &["help", "protect"][..],
        &["help", "scan"][..],
        &["inspect", "store"][..],
        &["inspect", "identity"][..],
        &["inspect", "config"][..],
    ] {
        record(&mut shots, shoot(argv, &dir));
    }
    for argv in [
        &["scan", "./copy", "--format", "json"][..],
        &["scan", "./nowhere"][..],
        &["scan", "--formt", "json", "./copy"][..],
    ] {
        record(&mut shots, shoot(argv, &dir));
    }

    // Five experiments last, because each leaves the tree in a state none of the
    // pages above quote: a limit small enough to stop a scan halfway, one protected
    // file emptied, a committed release record edited, no root secret at all, and
    // finally no config to open the store with. Every one passes `-p .`, naming the
    // store it is standing in, which keeps these transcripts distinguishable from
    // the clean runs earlier in this function — a documented line is looked up by
    // what a reader would type, and `swp verify` had already spoken for itself.
    let config = dir.join(".swp").join("config.toml");
    if let Ok(text) = std::fs::read_to_string(&config) {
        let shrunk = shrink_max_file_bytes(&text, 900);
        if std::fs::write(&config, shrunk).is_ok() {
            record(&mut shots, shoot(&["scan", "./copy", "-p", "."], &dir));
            let _ = std::fs::write(&config, &text);
        }
    }
    // The scanned copy goes before the emptied file: verify reads the whole project
    // tree, so with `copy/` still around every site it has lost from `src/` it still
    // finds in the copy, reports as moved, and calls the tree intact. The transcript
    // below is meant to show a watermark that is really gone.
    let _ = std::fs::remove_dir_all(dir.join("copy"));
    if emptied_source_file(&dir) {
        record(&mut shots, shoot(&["verify", "-p", "."], &dir));
    }
    if let Some((path, original)) = tamper_release_record(&dir) {
        record(&mut shots, shoot(&["inspect", "releases", "-p", "."], &dir));
        let _ = std::fs::write(&path, original);
    }
    let secret = dir.join(".swp").join("private").join("root.key");
    if std::fs::remove_file(&secret).is_ok() {
        record(&mut shots, shoot(&["generate", "-p", "."], &dir));
    }
    if std::fs::remove_file(&config).is_ok() {
        record(&mut shots, shoot(&["inspect", "store", "-p", "."], &dir));
    }
    shots
}

/// Flip one character of the newest release record's fingerprint, and hand back the
/// file and its original bytes.
///
/// One character of one hex field is what an edit looks like: valid JSON, parseable
/// in every shape, and no longer the document this project signed. The record is the
/// committed half of the store, so it is the artifact an attacker who can only push
/// to the repository can reach.
fn tamper_release_record(dir: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let releases = dir.join(".swp").join("public").join("releases");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&releases)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    let path = names.pop()?;
    let original = std::fs::read(&path).ok()?;
    let at = std::str::from_utf8(&original)
        .ok()?
        .find(FINGERPRINT_FIELD)?
        + FINGERPRINT_FIELD.len();
    let mut bytes = original.clone();
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    std::fs::write(&path, &bytes).ok()?;
    Some((path, original))
}

const FINGERPRINT_FIELD: &str = "\"fingerprint\": \"";

/// Empty the last file under `src/`, and report whether anything was.
///
/// The last rather than the first, because the examples put their most-referenced
/// module first and a document should be able to name a file its own transcript
/// has not just quoted. An empty file parses in every dialect, which a comment
/// written in the wrong one would not.
fn emptied_source_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir.join("src")) else {
        return false;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    match files.pop() {
        Some(last) => std::fs::write(&last, "").is_ok(),
        None => false,
    }
}

/// The config text with `max_file_bytes` set to `bytes`, wherever the key sits.
///
/// Written against the setting rather than the line it currently occupies because
/// the default is a documented number that a future release may raise, and a
/// replacement that silently stopped matching would make the experiment above
/// quote an ordinary scan while claiming to show a truncated one.
fn shrink_max_file_bytes(text: &str, bytes: u64) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("max_file_bytes") {
                format!("max_file_bytes = {bytes}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn record(shots: &mut BTreeMap<String, Shot>, shot: Shot) {
    shots.insert(shot.header.clone(), shot);
}

/// The first `*.json` under `rel`, by name, without the extension — the same rule
/// the capture script's `ls | head -n 1 | sed` applies.
fn staged(dir: &Path, rel: &str) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join(rel))
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".json").map(str::to_string)
        })
        .collect();
    names.sort();
    names.into_iter().next()
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("copy root");
    for entry in std::fs::read_dir(from).expect("read example tree") {
        let entry = entry.expect("directory entry");
        let name = entry.file_name();
        // A shipped example must never carry a store. If one did, this suite would
        // be quoting somebody's root key, so it is skipped rather than copied.
        if name == ".swp" {
            continue;
        }
        let target = to.join(name);
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

fn copy_files(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("copy root");
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.path().is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name())).expect("copy file");
        }
    }
}

// -------------------------------------------------------------------------------------
// The matcher
// -------------------------------------------------------------------------------------

/// Match one documented line against one transcript line.
///
/// Whitespace runs collapse on both sides, because the product aligns columns to
/// whatever the widest value in them is, and a document that reproduced that
/// padding would be documenting a layout rather than a result. `…` matches either
/// the rest of a word or a whole run of words, which between them cover every kind
/// of volatile value the examples quote.
fn line_matches(pattern: &str, line: &str) -> bool {
    fn go(pattern: &[&str], line: &[&str]) -> bool {
        match (pattern.first(), line.first()) {
            (None, _) => true,
            (_, None) => false,
            (Some(word), _) if *word == ELISION_STR => {
                (1..=line.len()).any(|skip| go(&pattern[1..], &line[skip..]))
            }
            (Some(head), Some(word)) => token_matches(head, word) && go(&pattern[1..], &line[1..]),
        }
    }
    go(
        &pattern.split_whitespace().collect::<Vec<_>>(),
        &line.split_whitespace().collect::<Vec<_>>(),
    )
}

/// `…` inside a word: the pieces either side of it have to appear in that word, in
/// order, with the first flush against its start and the last against its end.
fn token_matches(pattern: &str, word: &str) -> bool {
    if !pattern.contains(ELISION) {
        return pattern == word;
    }
    let pieces: Vec<&str> = pattern.split(ELISION).collect();
    let mut at = 0usize;
    for (index, piece) in pieces.iter().enumerate() {
        if piece.is_empty() {
            continue;
        }
        if index == 0 && !word.starts_with(piece) {
            return false;
        }
        if index + 1 == pieces.len() && !word.ends_with(piece) {
            return false;
        }
        match word[at..].find(piece) {
            Some(offset) => at += offset + piece.len(),
            None => return false,
        }
    }
    true
}

/// A documented block: which example it quotes, where it starts, and its segments
/// — one per command it shows.
struct Block {
    example: String,
    started_at: usize,
    segments: Vec<Segment>,
}

struct Segment {
    header: String,
    body: Vec<String>,
}

/// Every ` ```console ` block in one document.
///
/// A block may name the example it belongs to in the fence (` ```console:python `);
/// one that does not belongs to the document's own example, which for an example
/// README is the directory it sits in, and for everything else is JavaScript — the
/// language `docs/GETTING-STARTED.md` walks through.
fn blocks_of(path: &Path, default_example: &str) -> Vec<Block> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: cannot read the documentation: {e}", path.display()));
    let mut found: Vec<Block> = Vec::new();
    let mut open: Option<(String, usize, Vec<String>)> = None;
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim_end();
        let fence = trimmed.strip_prefix("```console");
        match (&mut open, fence) {
            (None, Some(rest)) => {
                let example = match rest.strip_prefix(':') {
                    Some(named) => named.trim().to_string(),
                    None => default_example.to_string(),
                };
                open = Some((example, number + 1, Vec::new()));
            }
            (Some(_), Some(_)) => panic!(
                "{}:{}: a console block opened inside one that is still open",
                path.display(),
                number + 1
            ),
            (Some(_), None) if trimmed == "```" => {
                let (example, started_at, body) = open.take().expect("an open block");
                found.push(Block {
                    example,
                    started_at,
                    segments: segments_of(body, path, started_at),
                });
            }
            (slot @ Some(_), _) => slot
                .as_mut()
                .expect("an open block")
                .2
                .push(trimmed.to_string()),
            (None, None) => {}
        }
    }
    assert!(
        open.is_none(),
        "{}: a console block is never closed",
        path.display()
    );
    found
}

/// Split a block at every `$ swp …` line, so that a block showing two commands has
/// both checked against their own transcripts.
///
/// The blank line between two commands in one block belongs to neither of them, so
/// a segment's trailing empty lines are dropped rather than quoted at the end of a
/// transcript that stopped at its exit code.
fn segments_of(body: Vec<String>, path: &Path, started_at: usize) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();
    for line in body {
        if let Some(args) = line.strip_prefix("$ swp ") {
            segments.push(Segment {
                header: format!("$ swp {args}"),
                body: Vec::new(),
            });
            continue;
        }
        if line.starts_with("$ ") {
            panic!(
                "{}:{}: this block quotes `{line}`, a command the capture sequence does not run, \
                 so nothing would validate its output",
                path.display(),
                started_at
            );
        }
        segments
            .last_mut()
            .unwrap_or_else(|| {
                panic!(
                    "{}:{}: output quoted before the command that printed it",
                    path.display(),
                    started_at
                )
            })
            .body
            .push(line);
    }
    for segment in &mut segments {
        while segment.body.last().map(String::is_empty).unwrap_or(false) {
            segment.body.pop();
        }
    }
    segments
}

/// Check one block against the transcripts a fresh run of its example produced,
/// pushing every line that no longer matches rather than stopping at the first: a
/// page that has drifted usually has several lines wrong, and one report is
/// easier to fix than a rebuild per line.
fn check(block: &Block, shots: &BTreeMap<String, Shot>, path: &Path, failures: &mut Vec<String>) {
    for segment in &block.segments {
        let matched: Vec<&Shot> = shots
            .values()
            .filter(|shot| header_matches(&segment.header, &shot.header))
            .collect();
        if matched.len() != 1 {
            failures.push(format!(
                "{}:{}: `{}` is not exactly one of the commands this run printed ({} match; it \
                 printed: {})",
                path.display(),
                block.started_at,
                segment.header,
                matched.len(),
                shots
                    .values()
                    .map(|shot| shot.header.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        let shot = matched[0];
        // A block that ends on `exit N` is claiming the command's exit code, which
        // is a different kind of claim from the text around it: `exit 0` would match
        // the words of `exit 0 — a listing is not a finding`, and a page that says a
        // failing command succeeded deserves the sharper message rather than a
        // "never printed" one. So that line is compared to the code, not to the text.
        let quoted_exit = segment
            .body
            .last()
            .and_then(|line| line.strip_prefix("exit "))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|number| number.parse::<i32>().ok());
        let body = if quoted_exit.is_some() {
            &segment.body[..segment.body.len() - 1]
        } else {
            &segment.body[..]
        };
        if let Some(claimed) = quoted_exit {
            if claimed != shot.code {
                failures.push(format!(
                    "{}:{}: the block says `{}` exits {claimed}; it exited {}",
                    path.display(),
                    block.started_at,
                    segment.header,
                    shot.code
                ));
                continue;
            }
        }
        let mut cursor = 0usize;
        for pattern in body {
            let found = shot.body()[cursor..]
                .iter()
                .position(|line| line_matches(pattern, line));
            let Some(offset) = found else {
                failures.push(format!(
                    "{}:{}: `{}` never printed `{}` after everything above it. What it printed \
                     next:\n{}",
                    path.display(),
                    block.started_at,
                    segment.header,
                    pattern,
                    preview(&shot.body()[cursor.min(shot.body().len())..])
                ));
                cursor = usize::MAX;
                break;
            };
            cursor += offset + 1;
        }
        if cursor == usize::MAX {
            continue;
        }
    }
}

/// The command a block quotes and the command that ran are the same command: same
/// words, in the same order, with `…` allowed to stand for an argument this
/// project's key decided.
fn header_matches(pattern: &str, header: &str) -> bool {
    let pattern: Vec<&str> = pattern.split_whitespace().collect();
    let header: Vec<&str> = header.split_whitespace().collect();
    if pattern.len() > header.len() {
        return false;
    }
    pattern
        .iter()
        .zip(header.iter())
        .all(|(p, h)| *p == ELISION_STR || token_matches(p, h))
        && (pattern.len() == header.len() || pattern.last() == Some(&ELISION_STR))
}

fn preview(lines: &[String]) -> String {
    if lines.is_empty() {
        return "    (nothing: the command printed no more lines)".to_string();
    }
    lines
        .iter()
        .take(12)
        .map(|line| format!("    | {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_documented_transcript_is_one_this_build_still_produces() {
    let root = TempDir::new("docs").sensitive();
    let work = root.child("work");
    std::fs::create_dir_all(&work).expect("work root");

    let mut failures: Vec<String> = Vec::new();
    let mut transcripts: BTreeMap<String, BTreeMap<String, Shot>> = BTreeMap::new();
    let mut blocks_checked = 0usize;

    // The four example READMEs, then the documentation pages. Both are checked by
    // the same rule because both quote the same tool: a transcript in `docs/CLI.md`
    // can go stale exactly the way one in `examples/python/README.md` can.
    let mut pages: Vec<(PathBuf, String, bool)> = EXAMPLES
        .iter()
        .map(|example| {
            (
                examples_dir().join(example).join("README.md"),
                (*example).to_string(),
                true,
            )
        })
        .collect();
    pages.extend(
        PAGES
            .iter()
            .map(|(relative, example)| (repo_root().join(relative), (*example).to_string(), false)),
    );

    for (path, default_example, is_example) in pages {
        if !path.exists() {
            failures.push(format!(
                "{}: a page listed in PAGES is missing from the tree",
                path.display()
            ));
            continue;
        }
        let blocks = blocks_of(&path, &default_example);
        if is_example {
            assert!(
                !blocks.is_empty(),
                "{}: not one console block. Either the page stopped quoting real output, or its \
                 fences are spelled something this suite does not read.",
                path.display()
            );
        }
        for block in &blocks {
            if !transcripts.contains_key(&block.example) {
                let shots = capture(&work, &block.example);
                transcripts.insert(block.example.clone(), shots);
            }
            let shots = &transcripts[&block.example];
            blocks_checked += 1;
            check(block, shots, &path, &mut failures);
        }
    }

    assert!(
        failures.is_empty(),
        "{} documented line(s) no longer match what `swp` prints:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(
        blocks_checked >= 40,
        "only {blocks_checked} documented block(s) were checked, across the four example pages \
         and the {} documentation pages listed in PAGES. Every one of them is asked to quote \
         output this build actually printed, so a low count here reads as pages that lost their \
         transcripts rather than as a shorter manual.",
        PAGES.len()
    );
}

/// The other half of the documentation contract. The test above proves that a
/// quoted *output* is one this build printed; it cannot see a command the pages
/// mention in prose without quoting it, and that is where an interface change
/// leaves a body: a page that tells the reader to run `swp scan --languages` is
/// wrong whether or not it shows the error.
///
/// So every backticked command in every page is handed to the real parser. What
/// this proves is that the verb exists, that the option exists, and that the
/// option belongs to that verb. What it does not prove is that the command
/// succeeds on a given tree — `swp verify` in an unprotected project is a correct
/// thing to document and a failing thing to run — which is why the transcript test
/// above still carries the weight for anything with output quoted under it.
///
/// Placeholders are the honest exception: `swp scan <candidate>` is a template, not
/// a command line, and `swp help <command>` is how `swp help` itself writes it. A
/// snippet with a `<…>` argument is skipped; one with a `…` is the transcript form
/// of elision and is checked with the elided word treated as any other value.
#[test]
fn every_command_the_pages_name_is_one_the_parser_accepts() {
    let mut checked = 0usize;
    let mut rejected: Vec<String> = Vec::new();

    let mut sources: Vec<PathBuf> = PAGES
        .iter()
        .map(|(relative, _)| repo_root().join(relative))
        .collect();
    for example in EXAMPLES {
        sources.push(examples_dir().join(example).join("README.md"));
    }

    for path in sources {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // a missing page is the other test's failure, with a better message.
        };
        for (snippet, refused) in snippets(&text) {
            if refused {
                continue;
            }
            let Some(words) = command_words(&snippet) else {
                continue;
            };
            checked += 1;
            if let Err(problem) = swp_cli::args::parse(&words) {
                rejected.push(format!(
                    "{}: `{snippet}` — {}",
                    path.display(),
                    problem.message()
                ));
            }
        }
    }

    assert!(
        checked >= 40,
        "only {checked} documented command(s) were parsed. Either the pages stopped naming \
         commands in backticks, or the extraction above stopped finding them."
    );
    assert!(
        rejected.is_empty(),
        "{} documented command(s) are not commands this build has:\n{}",
        rejected.len(),
        rejected.join("\n")
    );
}

/// The commands a document names, each with whether the document itself shows that
/// command being refused: every single-line backtick span, and every line of a
/// fenced block that starts by typing `swp`.
///
/// The second half matters because a shell transcript is usually fenced as `bash`,
/// and a `swp` line in one is as much a claim about the interface as one in prose.
///
/// A typed line whose transcript answers `error [USAGE]` is refused. Such a block
/// exists to show the refusal — CLI.md types a mistyped flag on purpose — so the
/// words on its line are deliberately not a command this build has, and checking
/// them would fail the one thing the page is demonstrating. The transcript test
/// above still verifies that the refusal is the one this build prints.
fn snippets(text: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("$ swp ") {
            found.push((trimmed.to_string(), refused_below(&lines[index..])));
        } else if trimmed.starts_with("swp ") {
            found.push((trimmed.to_string(), false));
        }
        let mut rest = *line;
        while let Some(start) = rest.find('`') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('`') else { break };
            let inner = &after[..end];
            if !inner.is_empty() && !inner.contains('\n') {
                found.push((inner.to_string(), false));
            }
            rest = &after[end + 1..];
        }
    }
    found
}

/// Whether the lines under a typed command open with the parser's own refusal.
/// Only the first few count: a transcript block is short, and a longer window
/// would let a refusal several commands down the page excuse the command above it.
fn refused_below(block: &[&str]) -> bool {
    block
        .iter()
        .skip(1)
        .take(4)
        .any(|line| line.starts_with("error [USAGE]"))
}

/// The argv a snippet asks for, or `None` when it is prose rather than a command.
///
/// A trailing period or comma is how a sentence ends, not part of an argument, so
/// it is removed once before giving up.
fn command_words(snippet: &str) -> Option<Vec<String>> {
    let text = snippet.trim();
    let body = text
        .strip_prefix("$ swp ")
        .or_else(|| text.strip_prefix("swp "))?
        .trim();
    if body.is_empty() || body.contains('<') || body.contains('`') {
        return None;
    }
    let mut words: Vec<String> = body.split_whitespace().map(str::to_string).collect();
    // A line that begins with the word `swp` is just as often the banner this tool
    // prints — `swp SWP-1 · swp 1.0.0 · …` — as it is a command someone typed, so
    // the second word has to be a verb before anything is parsed.
    const VERBS: [&str; 11] = [
        "init",
        "generate",
        "protect",
        "verify",
        "scan",
        "inspect",
        "report",
        "help",
        "--help",
        "-h",
        "--version",
    ];
    if !words.first().is_some_and(|w| VERBS.contains(&w.as_str())) {
        return None;
    }
    if let Some(last) = words.last_mut() {
        let trimmed = last.trim_end_matches(['.', ',', ';', ':', '?', '!']);
        if !trimmed.is_empty() {
            *last = trimmed.to_string();
        }
    }
    // `swp init — once per project` is a sentence with a command in front of it.
    if let Some(at) = words.iter().position(|w| w == "—" || w == "·") {
        words.truncate(at);
    }
    (!words.is_empty()).then_some(words)
}

/// A check that cannot fail is not a check, and the rule above is worth nothing if the
/// matcher above is generous enough to wave anything through. So the two rules it
/// rests on — `…` stands for what the key decides, and everything else has to be a
/// line the product really printed — are tested against transcripts written here
/// rather than against the documentation.
#[test]
fn elision_stands_for_what_the_key_decides_and_nothing_else() {
    assert!(line_matches(
        "protected swp1-… — release rel-…",
        "protected swp1-us4t6us3djqbch25 — release rel-egmaltb2mxjpa"
    ));
    assert!(line_matches(
        "  src/money.js — 5 site(s), 1497 → … bytes",
        "  src/money.js — 5 site(s), 1497 → 1556 bytes"
    ));
    // A whole run of words: the report's own path, and a digest with its level.
    assert!(line_matches(
        "  fingerprint … (L1)",
        "  fingerprint 711a46937748a4eacc79d4e5dd0707c9cb25cba01c181739957fb35d2cc5ba2f (L1)"
    ));
    assert!(line_matches("  …", "  anything at all here"));

    // The same line with a number invented is the thing this suite exists to catch.
    assert!(!line_matches(
        "  sites       12/12 embedded, 21 refused",
        "  sites       10/12 embedded, 21 refused"
    ));
    assert!(!line_matches(
        "  src/money.js — 5 site(s), 1497 → … bytes",
        "  src/money.js — 4 site(s), 1497 → 1556 bytes"
    ));
    // `…` stands for characters inside a word, not for a word that is absent.
    assert!(!line_matches(
        "protected swp1-…",
        "nothing protected here at all"
    ));
    // Padding is free; a different word is not.
    assert!(line_matches("sites    4 bits", "sites       4 bits"));
    assert!(!line_matches("sites    4 bits", "sites    5 bits"));
}

#[test]
fn a_block_is_checked_against_the_command_that_printed_it() {
    let printed = |args: &[&str], body: &[&str], code: i32| {
        let header = format!("$ swp {}", args.join(" "));
        Shot {
            lines: std::iter::once(header.clone())
                .chain(body.iter().map(|line| (*line).to_string()))
                .collect(),
            code,
            header,
        }
    };
    let mut shots: BTreeMap<String, Shot> = BTreeMap::new();
    for shot in [
        printed(
            &["protect", "--sites", "12"],
            &["  sites       10/12 embedded", "exit 0"],
            0,
        ),
        printed(
            &["verify"],
            &["  verdict     INTACT — 10/10 site(s)", "exit 0"],
            0,
        ),
        printed(
            &["scan", "./copy"],
            &["result    PROVENANCE_DETECTED", "exit 1"],
            1,
        ),
    ] {
        shots.insert(shot.header.clone(), shot);
    }

    // A command line quoting `verify` must not be answered from `verify --save`:
    // same prefix, different transcript.
    assert!(header_matches("$ swp verify", "$ swp verify"));
    assert!(!header_matches(
        "$ swp verify",
        "$ swp verify --release rel-abc --save"
    ));
    assert!(header_matches("$ swp report …", "$ swp report rep-7dqk3x"));
    assert!(!header_matches("$ swp scan ./copy", "$ swp scan ../plain"));

    // A block whose last line is a claim about the exit code fails on the number,
    // not on the text around it — `exit 0` would otherwise match the prefix of
    // `exit 0 — a listing is not a finding`.
    let quoted = |text: &str| Block {
        example: "javascript".to_string(),
        started_at: 1,
        segments: segments_of(
            text.lines().map(str::to_string).collect::<Vec<_>>(),
            Path::new("test.md"),
            1,
        ),
    };
    let mut failures: Vec<String> = Vec::new();
    check(
        &quoted("$ swp scan ./copy\nresult    PROVENANCE_DETECTED\nexit 0"),
        &shots,
        Path::new("test.md"),
        &mut failures,
    );
    assert_eq!(
        failures.len(),
        1,
        "a wrong exit code must be caught: {failures:?}"
    );
    assert!(
        failures[0].contains("exits 0") && failures[0].contains("it exited 1"),
        "{}",
        failures[0]
    );

    failures.clear();
    check(
        &quoted("$ swp verify\n  verdict     ABSENT — nothing here\nexit 0"),
        &shots,
        Path::new("test.md"),
        &mut failures,
    );
    assert_eq!(
        failures.len(),
        1,
        "an invented line must be caught: {failures:?}"
    );

    failures.clear();
    check(
        &quoted("$ swp protect\n  sites       10/12 embedded\nexit 0"),
        &shots,
        Path::new("test.md"),
        &mut failures,
    );
    assert_eq!(
        failures.len(),
        1,
        "a command nobody ran must not pass: {failures:?}"
    );
}
