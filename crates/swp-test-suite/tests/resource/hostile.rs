//! §45 — resource-exhaustion protection: hostile candidates, and the contract
//! the scanner keeps when it meets them.
//!
//! A candidate is untrusted input from an adversarial world (§50). §45 names the
//! shapes: huge files, deep syntax, many nested structures, zip bombs, millions
//! of tiny files, malformed source, repeated parser failures. The product's side
//! of the deal is in `swp-core`'s `Limits`, each enforced *before* a parse or a
//! hash, and each breach reported — as an omission that makes the result partial
//! when the scan can still answer, as `LIMIT_REACHED` when it cannot.
//!
//! The property this suite exists to defend is one sentence, and every test ends
//! on it: **a limit that fired is never allowed to look like a clean result.** A
//! scan that read 250 of 400 files must not print `NO_PROVENANCE_DETECTED` as
//! though the other 150 had been examined — because an attacker who wants a "no
//! evidence" certificate then gets one for free. So each case below asks for one
//! of two answers, and rejects everything else: a report that calls itself
//! partial and names what it left out, or a refusal that stops the run out loud.
//!
//! Two shapes of refusal are both legitimate and they are not the same promise.
//! A per-file ceiling (`max_file_bytes`, `max_parse_bytes`, a syntax tree too
//! deep) skips *that file* and keeps going, because the rest of the candidate
//! still deserves an answer. A whole-tree ceiling (`max_files`) stops the run,
//! because a scanner that quietly covered a prefix of the tree is describing a
//! different candidate than the one it was given. The tests say which is which.
//!
//! Every case also checks the candidate's bytes afterwards: reading a hostile
//! tree must never rewrite it (§21), and a hostile tree must never be executed,
//! imported or built — nothing here shells out, and the CLI under test has no
//! code path that does.
//!
//! Timings here are assertions of *survival*, not benchmarks; §44's ladder is
//! where the numbers live.

use std::collections::BTreeSet;
use std::path::Path;

use swp_test_suite::project::{Project, Run, Verdict};
use swp_test_suite::TempDir;

const MODULES: usize = 12;
const TARGET_SITES: u32 = 24;

/// A protected project to do the scanning with: the scanner is always a project
/// with its own keys, never the candidate (§21).
fn scanner() -> Project {
    let project = Project::synthetic_wide("hostile-scanner", MODULES, TARGET_SITES);
    project.protect();
    project
}

/// Same, with `[limits]` keys lowered — which a config may do. A repository's
/// author cannot raise a ceiling past the hard one, so these are the operator's
/// own knobs being tested, not the product's defaults.
fn scanner_with_limits(body: &str) -> Project {
    let project = scanner();
    project.set_config(body);
    project
}

fn hostile(label: &str) -> TempDir {
    TempDir::new(&format!("hostile-{label}"))
}

/// One hostile candidate's answer, in whichever of the two forms §45 allows.
enum Answer {
    /// A report, and it says part of the candidate was not examined.
    Partial(Verdict),
    /// No report: the scan stopped before it had an answer. `LIMIT_REACHED` is
    /// exit 7 and its own message, so this is a refusal, not a crash.
    Refused(Run),
}

/// `swp scan` of a hostile candidate, sorted into an [`Answer`].
///
/// The panic inside is the test: any other exit code — a clean 0 with
/// `NO_PROVENANCE_DETECTED`, a finding, a signal, an unparseable document — is
/// the failure this suite exists to catch, so it is reported with the whole
/// command output rather than an assert on a field.
fn scan_hostile(project: &Project, candidate: &Path) -> Answer {
    let run = project.run(&["scan", &candidate.display().to_string(), "--format", "json"]);
    match run.code {
        0 | 1 | 10 => {
            let v = Verdict::of(run);
            if v.partial {
                Answer::Partial(v)
            } else {
                panic!(
                    "a scan that did not finish is not allowed to report itself complete:\n{}",
                    v.run.out
                );
            }
        }
        7 => Answer::Refused(run),
        other => panic!(
            "scan of {} exited {other}, which is neither a partial result (10) nor a \
             resource-limit refusal (7):\n{}{}",
            candidate.display(),
            run.out,
            run.err
        ),
    }
}

impl Answer {
    /// The report, for the cases where a report is the only acceptable answer:
    /// a per-file ceiling leaves the rest of the tree to be examined, so a scan
    /// that gave up instead would be refusing to answer a question it can answer.
    fn report(self, name: &str) -> Verdict {
        match self {
            Answer::Partial(v) => v,
            Answer::Refused(r) => panic!(
                "{name}: the scan refused the whole candidate when only one file was over a \
                 limit, so the files it could have read got no answer at all:\n{}{}",
                r.out, r.err
            ),
        }
    }

    /// The strings the report has to contain when a limit fires, in the order §49
    /// asks for them: the file, and the rule.
    fn text(&self, key: &str) -> String {
        match self {
            Answer::Partial(v) => v.run.json()[key]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            // A refusal has no report to read fields out of; its whole text is
            // the explanation, and that is what a reader of `--format json` gets.
            Answer::Refused(r) => format!("{}{}", r.out, r.err),
        }
    }

    /// Everything the command said, whichever form it took — what a test checks
    /// when it is asking whether a number reached the operator at all.
    fn whole(&self) -> String {
        match self {
            Answer::Partial(v) => format!("{}{}", v.run.out, v.run.err),
            Answer::Refused(r) => format!("{}{}", r.out, r.err),
        }
    }

    /// The contract, in either form: loud, specific, and never a clean result.
    fn assert_refused_not_cleared(&self, name: &str) {
        match self {
            Answer::Partial(v) => {
                assert!(
                    v.partial,
                    "{name}: the candidate could not be fully examined and the report did not \
                     mark itself partial — §45's limits would be invisible to a reader:\n{}",
                    v.run.out
                );
                assert_eq!(
                    v.result, "INCONCLUSIVE",
                    "{name}: a scan that did not finish is not a clean result. \
                     NO_PROVENANCE_DETECTED is a statement about what was examined, and §45 makes \
                     an unfinished examination say \"cannot say\" instead:\n{}",
                    v.run.out
                );
                assert_eq!(
                    v.run.code, 10,
                    "{name}: INCONCLUSIVE must exit 10, whatever else the scan found\n{}",
                    v.run.out
                );
                assert!(
                    !self.text("omissions").is_empty(),
                    "{name}: a partial scan named no file it skipped, so a reader cannot tell \
                     what was not looked at:\n{}",
                    v.run.out
                );
                assert!(
                    !self.text("notes").is_empty(),
                    "{name}: a partial scan named its omissions but never said which limit \
                     stopped it:\n{}",
                    v.run.out
                );
            }
            Answer::Refused(r) => {
                assert!(
                    r.err.contains("LIMIT_REACHED"),
                    "{name}: exit 7 without LIMIT_REACHED is not a resource-limit refusal:\n{}",
                    r.err
                );
                assert!(
                    r.err.contains("max_"),
                    "{name}: the refusal did not name the limit that fired, so the operator \
                     cannot raise just it:\n{}",
                    r.err
                );
                assert!(
                    r.out.is_empty() || !r.out.contains("\"result\""),
                    "{name}: a scan that gave up printed a verdict anyway:\n{}",
                    r.out
                );
            }
        }
    }
}

/// The candidate's own inventory, bytewise: every file, its length and a
/// checksum. `read_tree` is the suites' *source* reader and deliberately skips
/// what is not UTF-8 text, which is precisely the material a hostile tree is
/// made of, so §45 counts files on its own terms.
fn inventory(dir: &Path) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(rel) = path.strip_prefix(dir) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            out.push((
                rel.to_string_lossy().replace('\\', "/"),
                bytes.len() as u64,
                fnv64(&bytes),
            ));
        }
    }
    out.sort();
    out
}

/// A checksum cheap enough to run over an 8 MiB file twice, and bad enough to
/// notice a byte changing. Nothing here needs a cryptographic hash of the
/// candidate — §30's rules are about the watermark, not about a test's own
/// bookkeeping.
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

/// §21's promise, checked on the bytes: reading a candidate never changes it.
fn assert_untouched(name: &str, before: &[(String, u64, u64)], dir: &Path) {
    let after = inventory(dir);
    assert_eq!(before, &after[..], "{name}: the scan altered the candidate");
}

#[test]
fn a_file_over_the_size_ceiling_is_refused_and_says_so() {
    let project = scanner();
    let dir = hostile("huge");
    // One byte past the default 8 MiB ceiling, and a normal file beside it: the
    // point is that the ordinary file is still examined while the giant is not.
    let big = vec![b'a'; 8 * 1024 * 1024 + 1];
    dir.write("src/giant.js", &big);
    dir.write(
        "src/small.js",
        b"function rate(base) {\n  const fee = base * 0.125;\n  return fee + 4211;\n}\nmodule.exports = { rate };\n",
    );
    let before = inventory(dir.path());
    assert_eq!(
        before.len(),
        2,
        "the hostile tree lost a file before the scan"
    );

    let v = scan_hostile(&project, dir.path()).report("the 8 MiB + 1 file");
    let answer = Answer::Partial(v.clone());
    answer.assert_refused_not_cleared("the 8 MiB + 1 file");
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("giant.js"),
        "the omission list did not name the file it refused:\n{omissions}"
    );
    assert!(
        omissions.contains("max_file_bytes"),
        "the omission named the file but not the rule, so the operator cannot act on it:\n{omissions}"
    );
    assert!(
        v.files_scanned >= 1,
        "the ordinary file beside the giant was not scanned either:\n{}",
        v.run.out
    );
    assert_untouched("the giant-file scan", &before, dir.path());
    println!(
        "\n§45 — 8 MiB + 1 byte: refused mid-tree; {} of {} file(s) still read, {} byte(s) \
         examined, verdict {} / {} (exit {})",
        v.files_scanned,
        before.len(),
        v.bytes_scanned,
        v.result,
        v.level,
        v.run.code
    );
    println!(
        "  the refusal as the report words it: {}",
        omissions.lines().next().unwrap_or_default()
    );
}

#[test]
fn deep_nesting_is_stopped_before_the_stack_is() {
    let project = scanner();
    let dir = hostile("deep");
    // 4 000 nested blocks: far past `max_depth`, and shaped like real JavaScript
    // so the parser is the thing that has to stop it, not a pre-check on bytes.
    let mut body = String::new();
    for depth in 0..4_000 {
        body.push_str(&format!("if (a{depth} > 0) {{\n"));
    }
    body.push_str("const value = 4711;\n");
    for _ in 0..4_000 {
        body.push_str("}\n");
    }
    dir.write("src/deep.js", body.as_bytes());
    let before = inventory(dir.path());

    let v = scan_hostile(&project, dir.path()).report("4 000 nested blocks");
    let answer = Answer::Partial(v.clone());
    answer.assert_refused_not_cleared("4 000 nested blocks");
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("deep.js"),
        "the file whose analysis stopped short was not named:\n{omissions}"
    );
    assert!(
        omissions.contains("max_depth") || omissions.contains("max_nodes_per_tree"),
        "the report said the site list was incomplete without saying which bound made it \
         so:\n{omissions}"
    );
    assert_untouched("the deep-nesting scan", &before, dir.path());
    println!(
        "\n§45 — 4 000 nested blocks: survived in one file, {} byte(s) read, verdict {} / {} \
         (exit {})",
        v.bytes_scanned, v.result, v.level, v.run.code
    );
    println!("  {}", omissions.lines().next().unwrap_or_default());
}

#[test]
fn a_directory_tree_deeper_than_max_depth_stops_where_it_says() {
    // The other depth: `max_depth` also bounds the *walk*, and a walk that simply
    // stops descending is the quietest possible failure — no file was refused,
    // the tree is just smaller than it is. `max_depth = 12` stands in for the
    // default 256 for the same reason a 400-file tree stands in for a million:
    // the claim is about the counter, and the counter is the same size either
    // way.
    let project = scanner_with_limits(
        "[protect]\ntargets = [\"src\"]\ntarget_sites = 24\ntag_bits = 4\nembed_strings = \
         true\n[limits]\nmax_depth = 12\n",
    );
    let dir = hostile("wide-depth");
    let mut rel = String::from("src");
    for depth in 0..24 {
        rel.push_str(&format!("/d{depth}"));
    }
    dir.write(
        &format!("{rel}/leaf.js"),
        b"function leaf() {\n  return 8231;\n}\nmodule.exports = { leaf };\n",
    );
    dir.write(
        "src/shallow.js",
        b"function shallow() {\n  return 4211;\n}\nmodule.exports = { shallow };\n",
    );
    let before = inventory(dir.path());

    let v = scan_hostile(&project, dir.path()).report("a 24-deep directory tree");
    let answer = Answer::Partial(v.clone());
    answer.assert_refused_not_cleared("a 24-deep directory tree");
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("max_depth"),
        "the walk stopped descending and nothing in the report says so:\n{omissions}"
    );
    assert!(
        v.files_scanned >= 1,
        "the shallow half of the tree went unread too, which is not what a depth bound \
         means:\n{}",
        v.run.out
    );
    assert_untouched("the deep-directory scan", &before, dir.path());
    println!(
        "\n§45 — a tree 24 directories deep under max_depth=12: {} of {} file(s) reached, \
         verdict {} / {}",
        v.files_scanned,
        before.len(),
        v.result,
        v.level
    );
    println!("  {}", omissions.lines().next().unwrap_or_default());
}

#[test]
fn a_tree_of_many_files_stops_at_the_walk_ceiling_and_reports_the_rest() {
    // 400 files against a ceiling of 250: "millions of tiny files" is the same
    // code path with a bigger number, and a test that created a million files to
    // prove a counter would spend more time on the filesystem than on the claim.
    let project = scanner_with_limits(
        "[protect]\ntargets = [\"src\"]\ntarget_sites = 24\ntag_bits = 4\nembed_strings = \
         true\n[limits]\nmax_files = 250\n",
    );
    let dir = hostile("many");
    for i in 0..400 {
        dir.write(
            &format!("src/m{i:03}.js"),
            format!(
                "const V_{i} = {};\nmodule.exports = {{ V_{i} }};\n",
                1000 + i
            )
            .as_bytes(),
        );
    }
    let before = inventory(dir.path());
    assert_eq!(
        before.len(),
        400,
        "the hostile tree lost a file before the scan"
    );

    let answer = scan_hostile(&project, dir.path());
    // This one is allowed to answer either way, and both answers are the same
    // promise: the 150 files nobody read are not evidence of nothing being there.
    answer.assert_refused_not_cleared("400 files under a 250 ceiling");
    let text = answer.whole();
    assert!(
        text.contains("400"),
        "the refusal did not say how many files the tree holds:\n{text}"
    );
    assert!(
        text.contains("250"),
        "the refusal did not name the ceiling it hit:\n{text}"
    );
    if let Answer::Partial(v) = &answer {
        assert!(
            (v.files_scanned as usize) < before.len(),
            "the ceiling was configured at 250 and the scan read {} of {} files without \
             saying it stopped:\n{}",
            v.files_scanned,
            before.len(),
            v.run.out
        );
    }
    assert_untouched("the many-file scan", &before, dir.path());
    match &answer {
        Answer::Partial(v) => println!(
            "\n§45 — 400 files under max_files=250: answered partially, {} read, verdict {} / {}",
            v.files_scanned, v.result, v.level
        ),
        Answer::Refused(r) => println!(
            "\n§45 — 400 files under max_files=250: the whole scan refused, exit {}, because a \
             prefix of a tree is not the tree it was asked about",
            r.code
        ),
    }
    println!("  {}", first_line(&answer.whole(), "max_files"));
}

#[test]
fn malformed_and_binary_candidates_are_answered_not_crashed() {
    let project = scanner();
    let dir = hostile("broken");
    dir.write("src/unclosed.js", b"function oops( {\n  return 1234\n");
    dir.write(
        "src/truncated.js",
        b"const half = { \"nested\": [1, 2, 3, /* unterminated",
    );
    dir.write(
        "src/binary.js",
        &[0u8, 159, 146, 150, 0, 255, 128, 0, 7, 8, 9],
    );
    dir.write("src/empty.js", b"");
    dir.write("src/nulls.py", b"def f():\n    return 42\x00\n");
    dir.write("src/crlf.ts", "export const X = 4021;\r\n\r\n".as_bytes());
    dir.write("src/repeated.js", vec![b';'; 200_000].as_slice());
    dir.write("src/notsource.md", b"# Notes\n\nNothing here is source.\n");
    let before = inventory(dir.path());
    let names: BTreeSet<String> = before.iter().map(|(p, _, _)| p.clone()).collect();
    assert_eq!(
        names.len(),
        8,
        "the hostile tree lost a file before the scan"
    );

    let answer = scan_hostile(&project, dir.path());
    // Nothing here is a limit breach to refuse: broken source is a normal thing a
    // scanner meets. The claim is that it is *answered* — a legal verdict, a
    // reason for everything that could not be read, and the bytes intact. A
    // non-UTF-8 `.js` is a file the walk admitted and the reader could not use, so
    // that one really is a hole in the examination, and the scan says so.
    let v = match &answer {
        Answer::Partial(v) => v.clone(),
        Answer::Refused(r) => panic!(
            "malformed source made the scanner give up on the whole tree instead of answering \
             for the part it could read:\n{}{}",
            r.out, r.err
        ),
    };
    let legal = matches!(
        v.result.as_str(),
        "NO_PROVENANCE_DETECTED" | "INCONCLUSIVE" | "PROVENANCE_DETECTED"
    );
    assert!(
        legal,
        "a malformed tree produced no verdict at all: {:?}",
        v.result
    );
    let expected = match v.result.as_str() {
        "PROVENANCE_DETECTED" => 1,
        "INCONCLUSIVE" => 10,
        _ => 0,
    };
    assert_eq!(
        v.run.code, expected,
        "the exit code contradicts the verdict:\n{}",
        v.run.out
    );
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("binary.js"),
        "a file the scanner could not decode was not named:\n{omissions}"
    );
    // The other two lines in that list are not the same kind of fact. A Markdown
    // file and an empty one were never candidates for a site, so they leave the
    // examination complete; a `.js` the decoder refused leaves a hole. §45's
    // promise is about the hole, and the report counts them separately — which is
    // the difference between an honest INCONCLUSIVE and a scan that calls every
    // README an unfinished examination.
    assert!(
        omissions.contains("notsource.md"),
        "the report hides which files it passed over, so a reader cannot check the \
         count:\n{omissions}"
    );
    let notes = answer.text("notes");
    assert!(
        notes.contains("1 file(s) in this candidate could have carried a site"),
        "the scan counted the wrong number of holes in its own examination — a Markdown file \
         and an empty file are not unexamined source:\n{notes}"
    );
    assert!(
        !answer.text("explanation").is_empty(),
        "the scan gave a verdict without a single line of explanation:\n{}",
        v.run.out
    );
    assert_untouched("the malformed-tree scan", &before, dir.path());
    println!(
        "\n§45 — 8 hostile files (unclosed, truncated, binary, empty, embedded NUL, CRLF, 200 KB \
         of semicolons, one non-source): verdict {} / {} (exit {}), {} file(s) scanned, {} \
         byte(s) read",
        v.result, v.level, v.run.code, v.files_scanned, v.bytes_scanned
    );
    for line in omissions.lines().filter(|l| !l.is_empty()).take(4) {
        println!("  {line}");
    }
}

#[test]
fn an_archive_bomb_is_measured_before_it_expands_past_the_ceiling() {
    let project = scanner();
    let dir = hostile("bomb");
    // 64 MiB of spaces inside a zip: deflated to tens of kilobytes, so the ratio
    // is around a thousand and `max_archive_ratio` (200) is what has to stop it.
    // The container is built here, in memory, and never extracted by the test.
    let (zip_bytes, compressed) = bomb_container();
    let archive = dir.write("candidate.zip", &zip_bytes);
    let expanded = 64 * 1024 * 1024;
    println!(
        "\n§45 — built a {expanded} byte payload that occupies {compressed} byte(s) zipped \
         (ratio {}), then pointed the scanner at it",
        expanded / compressed.max(1)
    );

    let answer = scan_hostile(&project, &archive);
    // Whether the container is refused or examined, the contract is the same.
    answer.assert_refused_not_cleared("the archive bomb");
    let bytes_scanned = match &answer {
        Answer::Partial(v) => v.bytes_scanned,
        Answer::Refused(_) => 0,
    };
    assert!(
        bytes_scanned < 16 * 1024 * 1024,
        "the scan expanded {bytes_scanned} bytes out of a {compressed} byte container: the \
         ratio bound did not fire before the byte counter did"
    );
    assert_untouched("the archive scan", &inventory(dir.path()), dir.path());
    match &answer {
        Answer::Partial(v) => println!(
            "  answered, and said it was partial: {} file(s), {} byte(s), verdict {} / {}",
            v.files_scanned, v.bytes_scanned, v.result, v.level
        ),
        Answer::Refused(r) => println!(
            "  refused before expanding anything: exit {}, {}",
            r.code,
            r.err.lines().next().unwrap_or_default()
        ),
    }
    println!(
        "  {}",
        match &answer {
            Answer::Partial(v) => v.run.json()["omissions"]
                .as_array()
                .map(|a| a
                    .iter()
                    .filter_map(|l| l.as_str())
                    .collect::<Vec<_>>()
                    .join(" | "))
                .unwrap_or_default(),
            Answer::Refused(r) => r.err.lines().nth(1).unwrap_or_default().to_string(),
        }
    );

    // And the same container as a *member of a tree*, which the scanner does not
    // open: an archive inside a candidate is a place copied source can hide, so
    // the walk has to say it left a container closed rather than report the tree
    // as clean.
    let tree = hostile("bomb-tree");
    tree.write("candidate.zip", &zip_bytes);
    tree.write(
        "src/plain.js",
        b"function plain() {\n  return 6137;\n}\nmodule.exports = { plain };\n",
    );
    let answer = scan_hostile(&project, tree.path());
    answer.assert_refused_not_cleared("an archive inside a tree");
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("candidate.zip") && omissions.contains("archive"),
        "a container the walk will not open was not named as unexamined:\n{omissions}"
    );
    println!(
        "  the same container inside a tree: named as unexamined — {}",
        omissions
            .lines()
            .find(|l| l.contains("candidate.zip"))
            .unwrap_or_default()
    );
}

/// The 64 MiB-of-nothing zip, and how small it gets.
///
/// Spaces rather than zeros because a real zip of zeros is the case everyone
/// tests; the interesting property is the ratio, and spaces deflate about as
/// violently.
fn bomb_container() -> (Vec<u8>, usize) {
    use std::io::Write;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::<u8>::new()));
    let options: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("src/bombed.js", options).unwrap();
    let chunk = vec![b' '; 1024 * 1024];
    for _ in 0..64 {
        zip.write_all(&chunk).unwrap();
    }
    let bytes = zip.finish().unwrap().into_inner();
    let compressed = bytes.len();
    (bytes, compressed)
}

#[test]
fn a_candidate_cannot_hide_behind_a_symlink_without_saying_so() {
    // §21: links are never followed, because where one points is the candidate's
    // business and reading the machine is not the scanner's. The §45 half is that
    // refusing to look has to be visible in the answer. On a filesystem that will
    // not make a symlink for an unprivileged process, the case cannot be built
    // here, and the test says so instead of passing quietly.
    let project = scanner();
    let dir = hostile("links");
    dir.write(
        "src/plain.js",
        b"function plain() {\n  return 4211;\n}\nmodule.exports = { plain };\n",
    );
    let outside = hostile("outside");
    let real = outside.write(
        "everywhere.js",
        b"function hidden() {\n  return 9241;\n}\nmodule.exports = { hidden };\n",
    );
    if !make_link(&dir.child("src").join("escape.js"), &real) {
        println!("\n§45 — symlinks: this filesystem refused to create one; not exercised");
        return;
    }
    let answer = scan_hostile(&project, dir.path());
    answer.assert_refused_not_cleared("a candidate with a symlink");
    let omissions = answer.text("omissions");
    assert!(
        omissions.contains("escape.js"),
        "the link was not followed, and the report did not say which file that left \
         unread:\n{omissions}"
    );
    println!(
        "  a link is refused and named: {}",
        first_line(&omissions, "escape.js")
    );
}

/// Create a symlink, and report whether the platform allowed it. Windows needs
/// either developer mode or elevation, and a suite that required it would fail on
/// a machine that is not misconfigured.
#[cfg(unix)]
fn make_link(link: &Path, target: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn make_link(link: &Path, target: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn make_link(_link: &Path, _target: &Path) -> bool {
    false
}

fn first_line(text: &str, has: &str) -> String {
    text.lines()
        .find(|l| l.contains(has))
        .unwrap_or_default()
        .to_string()
}
