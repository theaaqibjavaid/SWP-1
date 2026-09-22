//! The text of `swp help`, and the exit-code table a script author reads first.
//!
//! Help is a specification of the interface, so it lives in one file rather than
//! in seven call sites: the option list each command prints is generated from
//! [`crate::args::Command::flags`], which means a flag can be added to a command
//! in exactly one place and appears in its help automatically. A test asserts
//! that every declared flag is reachable from the help text, which is what keeps
//! the two from drifting apart.

use swp_core::error::{ErrorCode, SwpError};
use swp_core::version::SWP_PROTOCOL_NAME;

use crate::args::{Command, Flag, Parsed};
use crate::output::{Format, Sink};

/// The version banner: what a report's `generator` field says, and what
/// `swp --version` prints.
pub fn banner() -> String {
    format!(
        "{SWP_PROTOCOL_NAME} · swp {} · report schema {}",
        crate::VERSION,
        swp_evidence::REPORT_SCHEMA
    )
}

/// Print `swp --version` / `swp help --version`.
pub fn version(sink: &mut Sink<'_>) -> Result<(), SwpError> {
    let protocol = serde_json::json!({
        "protocol": SWP_PROTOCOL_NAME,
        "swp_version": crate::VERSION,
        "report_schema": swp_evidence::REPORT_SCHEMA,
        "canonicalizer_version": swp_core::version::CanonicalizerVersion::V1.0,
    });
    if sink.json() {
        return sink.result(&protocol, &[]);
    }
    sink.result(&protocol, &[format!("swp {}", banner())])
}

/// `swp help` with no argument: the overview.
pub fn overview(sink: &mut Sink<'_>) -> Result<(), SwpError> {
    if sink.json() {
        // A JSON-mode help request gets the interface as data, because that is
        // the only honest machine-readable answer, and it is generated from the
        // same tables the parser uses.
        let commands: Vec<serde_json::Value> = Command::ALL
            .iter()
            .map(|c| {
                serde_json::json!({
                    "command": c.name(),
                    "summary": c.blurb(),
                    "options": c.flags().iter().map(option_shape).collect::<Vec<_>>(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "protocol": SWP_PROTOCOL_NAME,
            "version": crate::VERSION,
            "commands": commands,
            // Objects, not pairs: a tuple array serializes as `[0, "text"]`, which
            // a reader has to already know the shape of to use.
            "exit_codes": exit_codes()
                .iter()
                .map(|(code, meaning)| serde_json::json!({ "code": code, "meaning": meaning }))
                .collect::<Vec<_>>(),
        });
        return sink.result(&doc, &[]);
    }
    let mut lines = Vec::new();
    lines.push(format!("swp {}", banner()));
    lines.push(String::new());
    lines.push("Usage: swp <command> [options]".to_string());
    lines.push(String::new());
    lines.push("Commands".to_string());
    for c in Command::ALL {
        lines.push(format!("  {:<10} {}", c.name(), c.blurb()));
    }
    lines.push(format!("  {:<10} {}", "help", Command::Help.blurb()));
    lines.push(format!(
        "  {:<10} {}",
        "--version",
        Command::Version.blurb()
    ));
    lines.push(String::new());
    lines.push("The normal sequence in a project you own:".to_string());
    lines.push("  swp init                 once; creates .swp/ and the project secret".to_string());
    lines.push("  swp generate             see the constellation, change nothing".to_string());
    lines.push("  swp protect              embed it and record a release".to_string());
    lines.push(
        "  swp verify               confirm this tree still carries that release".to_string(),
    );
    lines.push("  swp scan ./copy          look at somebody else's tree".to_string());
    lines.push(String::new());
    lines.push("Every command takes --help. Machine-readable output is --format json.".to_string());
    lines.push(String::new());
    lines.push("Exit codes".to_string());
    for (code, meaning) in exit_codes() {
        lines.push(format!("  {:>3}  {}", code, meaning));
    }
    lines.push(String::new());
    lines.push("Run `swp help <command>` for a command's options.".to_string());
    // Text mode never serializes the value, and JSON mode returned above.
    sink.result(&serde_json::Value::Null, &lines)
}

/// `swp help protect`, and the same text `swp protect --help` prints.
pub fn command(cmd: Command, sink: &mut Sink<'_>) -> Result<(), SwpError> {
    let mut lines = Vec::new();
    lines.push(format!("swp {} — {}", cmd.name(), cmd.blurb()));
    lines.push(String::new());
    lines.push(format!("Usage: {}", usage(cmd)));
    lines.push(String::new());
    lines.push("Options".to_string());
    for f in cmd.flags() {
        lines.push(format!("  {:<24} {}", render_flag(*f), f.summary()));
    }
    lines.push(format!("  {:<24} {}", "-h, --help", "this text"));
    if let Some(extra) = detail(cmd) {
        lines.push(String::new());
        lines.push("Notes".to_string());
        for line in extra {
            lines.push(format!("  {line}"));
        }
    }
    lines.push(String::new());
    lines.push("Exit codes".to_string());
    for (code, meaning) in command_exit_codes(cmd) {
        lines.push(format!("  {:>3}  {}", code, meaning));
    }
    let doc = serde_json::json!({
        "command": cmd.name(),
        "usage": usage(cmd),
        "options": cmd.flags().iter().map(option_shape).collect::<Vec<_>>(),
        // The same three sections the page has, so a script reading the JSON is
        // not handed a shorter contract than a person reading the terminal.
        "notes": detail(cmd).unwrap_or_default(),
        "exit_codes": command_exit_codes(cmd)
            .iter()
            .map(|(code, meaning)| serde_json::json!({ "code": code, "meaning": meaning }))
            .collect::<Vec<_>>(),
    });
    sink.result(&doc, &lines)
}

fn option_shape(f: &Flag) -> serde_json::Value {
    serde_json::json!({
        "option": f.long(),
        "short": f.short(),
        "value": f.takes_value(),
        "summary": f.summary(),
    })
}

/// One line of the option column, short alias included.
fn render_flag(f: Flag) -> String {
    let head = match f.short() {
        Some(s) => format!("{s}, {}", f.long()),
        None => format!("    {}", f.long()),
    };
    if f.takes_value() {
        format!("{head} <{}>", metavar(f))
    } else {
        head
    }
}

fn metavar(f: Flag) -> &'static str {
    match f {
        Flag::Format => "text|json",
        Flag::Output => "path",
        Flag::Release => "id",
        Flag::Revision => "label",
        Flag::Project => "path",
        Flag::Target => "path",
        Flag::Sites | Flag::Bits | Flag::Limit => "n",
        Flag::Name => "label",
        _ => "",
    }
}

pub fn usage(cmd: Command) -> String {
    let positional = match cmd {
        Command::Scan => "<candidate>",
        Command::Inspect => "[view]",
        Command::Report => "[name]",
        _ => "",
    };
    if positional.is_empty() {
        format!("swp {}", cmd.name())
    } else {
        format!("swp {} {}", cmd.name(), positional)
    }
}

/// The lines under "Notes", or `None` for the commands that only print.
///
/// The static lines per command cannot name `swp inspect`'s views without
/// duplicating them, so that one line is built from the parser's own list.
fn detail(cmd: Command) -> Option<Vec<String>> {
    let base: &'static [&'static str] = match cmd {
        Command::Init => &[
            "init creates .swp/ and a 256-bit project secret from the operating system's",
            "random source. It never replaces an existing secret: the secret is what every",
            "past release's fragments are keyed under, and a second one would make the",
            "first project's copies unverifiable.",
            "It then measures the tree and writes a suggested [protect] target_sites into",
            ".swp/config.toml. The suggestion is a starting point, not a limit.",
        ],
        Command::Generate => &[
            "generate runs the whole protection pipeline — walk, harvest, select, prove each",
            "rewrite in memory — and saves the result as a private plan. It modifies no",
            "source file and writes no release record, so nothing it produced is verifiable",
            "later. `swp protect --release <same id>` applies exactly this plan.",
        ],
        Command::Protect => &[
            "protect writes .swp/private/manifests/<id>.json, .swp/private/plans/<id>.json",
            "and .swp/public/releases/<id>.json before it touches one source file, so an",
            "interrupted run leaves a tree `swp verify` can describe honestly.",
            "Every rewrite is re-parsed after it is rendered and refused unless it is",
            "provably equivalent, so a location that cannot carry a fragment safely is",
            "skipped rather than forced.",
            "--dry-run decides and reports, and writes nothing at all.",
        ],
        Command::Verify => &[
            "verify scans this project's own tree against one of its releases. Exit 0 means",
            "every site of that release is still present and still carries its code; it does",
            "not mean the tree is unchanged, only that the watermark is intact.",
            "Without --release the newest release is the one checked, because that is the",
            "tree a protect run left behind.",
        ],
        Command::Scan => &[
            "scan reads a candidate and never runs it: no build, no install, no import, no",
            "interpreter. Archives are opened in a private temporary directory, path-traversal",
            "and symlink entries are refused, and the extracted tree is deleted on exit.",
            "A candidate's own .swp/ directory is ignored: the project doing the scanning",
            "supplies the keys, never the tree being judged.",
            "--save keeps the report with the project being scanned, not with the candidate.",
        ],
        Command::Inspect => &[
            "inspect reads the local store only. It cannot report anything about a candidate;",
            "that is `swp scan`.",
        ],
        Command::Report => &[
            "A saved report is a JSON document under .swp/private/reports/. `swp report`",
            "lists them, `swp report <name>` re-renders one from the document that was",
            "written at the time — so the grading a report received is preserved even after",
            "the ladder's rules change, because the stored level is printed, not recomputed.",
            "<name> is the stem, the file name, or the store-relative path; all three mean",
            "the same entry. --release filters the listing to the reports that name it.",
            "This command exits 0 whatever a listed report concluded: reading an old finding",
            "is not a new one.",
        ],
        Command::Help | Command::Version => &[],
    };
    let mut out: Vec<String> = base.iter().map(|line| line.to_string()).collect();
    if cmd == Command::Inspect {
        out.push(format!(
            "The views are {}. store is the default.",
            crate::inspect::view_names().join(", ")
        ));
        out.push(format!(
            "The {} views print your own copy of the watermark, and say so on stderr. That is \
             why they are not the default.",
            crate::inspect::private_view_names().join(", ")
        ));
    }
    (!out.is_empty()).then_some(out)
}

/// The stable exit-code contract, in the order a reader wants it.
pub fn exit_codes() -> Vec<(i32, &'static str)> {
    vec![
        (
            0,
            "success; for scan, no watermark evidence found in a fully examined candidate",
        ),
        (
            1,
            "scan: watermark evidence found; the candidate carries one of your releases",
        ),
        (2, ErrorCode::Usage.as_str()),
        (3, ErrorCode::SecretUnavailable.as_str()),
        (4, ErrorCode::NotProtected.as_str()),
        (5, ErrorCode::ReleaseMismatch.as_str()),
        (6, ErrorCode::ProtocolVersionUnsupported.as_str()),
        (7, ErrorCode::LimitExceeded.as_str()),
        (
            10,
            "INCONCLUSIVE / INSUFFICIENT_EVIDENCE — part of the candidate was not examined",
        ),
        (14, ErrorCode::Io.as_str()),
        (15, ErrorCode::NoSafeLocations.as_str()),
        (70, ErrorCode::Internal.as_str()),
    ]
}

/// The codes one command can exit with, in the order its author cares about.
///
/// A command's success codes are its own — `swp scan` exiting 1 did not fail —
/// while the failure codes come from the shared table, because an error means
/// the same thing in every command.
fn command_exit_codes(cmd: Command) -> Vec<(i32, &'static str)> {
    let mut out: Vec<(i32, &'static str)> = match cmd {
        Command::Scan => vec![
            (0, "no watermark evidence found in a candidate that was fully examined"),
            (1, "watermark evidence found: the candidate carries one of your releases"),
            (10, "inconclusive: nothing was confirmed and part of the candidate was not examined"),
        ],
        Command::Verify => vec![
            (0, "every site of the release is present and still carries its code"),
            (5, "the release does not match this tree: sites are absent or stripped"),
            (10, "inconclusive: this tree was not fully read, so the release could not be checked everywhere"),
        ],
        Command::Protect | Command::Generate => vec![
            (0, "the constellation was decided, proved in memory, and recorded"),
            (15, "no location passed the safety preconditions; nothing was modified"),
        ],
        Command::Init => vec![(0, "the project's store exists, or already existed")],
        Command::Inspect | Command::Report => {
            vec![(0, "the store was read and printed")]
        }
        Command::Help | Command::Version => vec![(0, "the text was printed")],
    };
    // The shared codes mean the same thing everywhere, except where the command
    // above already gave that number its own reading — `swp verify` exits 5 for a
    // tree that no longer matches, and printing a second line for 5 that calls it
    // a bad manifest would leave the reader to guess.
    let shared = [
        (2, ErrorCode::Usage.as_str()),
        (3, ErrorCode::SecretUnavailable.as_str()),
        (4, ErrorCode::NotProtected.as_str()),
        (5, ErrorCode::InvalidManifest.as_str()),
        (6, ErrorCode::ProtocolVersionUnsupported.as_str()),
        (7, ErrorCode::LimitExceeded.as_str()),
        (14, ErrorCode::Io.as_str()),
        (70, ErrorCode::Internal.as_str()),
    ];
    let extra: Vec<(i32, &'static str)> = shared
        .into_iter()
        .filter(|(code, _)| !out.iter().any(|(listed, _)| listed == code))
        .collect();
    out.extend(extra);
    out
}

/// Print help for the whole tool, or for one command named in the positional.
///
/// A verb that is not a command is normally caught by the parser; this path is
/// `swp help <word>`, where the reader asked to be told about something, so the
/// same near-miss hint is offered from the same source.
pub fn print(parsed: &Parsed, sink: &mut Sink<'_>) -> Result<(), SwpError> {
    match parsed.positional.first().map(|s| s.as_str()) {
        None => overview(sink),
        Some(w) if w == "help" || w == "--help" => overview(sink),
        Some(w) => match Command::ALL.iter().find(|c| c.name() == w) {
            Some(c) => command(*c, sink),
            None => Err(SwpError::usage(match Command::nearest(w) {
                Some(c) => format!(
                    "there is no command {w:?}. Did you mean `swp {}`?",
                    c.name()
                ),
                None => format!(
                    "there is no command {w:?}. Run `swp help` for the {} commands.",
                    Command::ALL.len()
                ),
            })),
        },
    }
}

/// Where a command's words go when `--output` names a file: stdout stays the
/// document's home unless the operator asks for it elsewhere.
pub fn write_document(path: &str, text: &str) -> Result<(), SwpError> {
    std::fs::write(path, text).map_err(|e| SwpError::io(format!("cannot write {path:?}: {e}")))
}

/// The format a `--format` value asked for, shared by the commands that write a
/// document to a file rather than to stdout.
pub fn format_of(parsed: &Parsed) -> Result<Format, SwpError> {
    Ok(if parsed.json()? {
        Format::Json
    } else {
        Format::Text
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::args::parse;

    /// Drive the real entry point, the way a person typing `--help` would.
    fn say(argv: &[&str]) -> (i32, String, String) {
        let line: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = crate::run_in(&line, Path::new("."), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).expect("help printed invalid UTF-8"),
            String::from_utf8(err).expect("help wrote invalid UTF-8"),
        )
    }

    /// The "Options" block alone: a flag named in a Notes sentence is prose about
    /// another command, not a promise this one keeps.
    fn options(text: &str) -> String {
        let start = text
            .find("Options\n")
            .expect("a help page with no Options section");
        let rest = &text[start + "Options\n".len()..];
        let end = rest
            .find("\nNotes")
            .or_else(|| rest.find("\nExit codes"))
            .expect("an Options section that never ends");
        rest[..end].to_string()
    }

    #[test]
    fn every_command_answers_its_own_help_flag_with_its_own_page() {
        for cmd in Command::ALL {
            let (code, text, err) = say(&[cmd.name(), "--help"]);
            assert_eq!(code, 0, "{} --help failed: {err}", cmd.name());
            assert!(
                text.starts_with(&format!("swp {} — {}", cmd.name(), cmd.blurb())),
                "{} help does not name itself:\n{text}",
                cmd.name()
            );
            assert!(
                text.contains(&format!("Usage: {}", usage(*cmd))),
                "{} help contradicts usage():\n{text}",
                cmd.name()
            );
            let opts = options(&text);
            for f in cmd.flags() {
                assert!(
                    opts.contains(f.long()),
                    "{} accepts {} but its help omits it",
                    cmd.name(),
                    f.long()
                );
                if let Some(short) = f.short() {
                    assert!(opts.contains(short), "{} help omits {}", cmd.name(), short);
                }
                assert!(
                    opts.contains(f.summary()),
                    "{} help lost the description of {}",
                    cmd.name(),
                    f.long()
                );
            }
            assert!(
                opts.contains("-h, --help"),
                "{} help has no --help line",
                cmd.name()
            );
            // The same page from the other direction, because §32 asks for both.
            let (alias_code, alias_text, _) = say(&["help", cmd.name()]);
            assert_eq!(alias_code, 0);
            assert_eq!(alias_text, text, "`help x` and `x --help` disagree");
        }
    }

    #[test]
    fn the_help_page_offers_no_option_the_command_would_reject() {
        for cmd in Command::ALL {
            let opts = options(&say(&[cmd.name(), "--help"]).1);
            for f in crate::args::ALL_FLAGS {
                if cmd.flags().contains(&f) {
                    continue;
                }
                assert!(
                    !opts.contains(f.long()),
                    "{}'s help offers {}, which it refuses",
                    cmd.name(),
                    f.long()
                );
                // …and the parser really does refuse it.
                let (code, _, err) = say(&[cmd.name(), f.long(), "x"]);
                assert_eq!(
                    code,
                    ErrorCode::Usage.exit_code(),
                    "{} accepted {}",
                    cmd.name(),
                    f.long()
                );
                assert!(err.contains(f.long()), "{err}");
            }
        }
    }

    #[test]
    fn the_overview_lists_every_command_and_the_whole_exit_table() {
        let (code, text, _) = say(&["help"]);
        assert_eq!(code, 0);
        for cmd in Command::ALL {
            assert!(
                text.contains(cmd.name()),
                "the overview lost {}",
                cmd.name()
            );
            assert!(
                text.contains(cmd.blurb()),
                "the overview lost {}'s summary",
                cmd.name()
            );
        }
        for (n, meaning) in exit_codes() {
            assert!(
                text.contains(&format!("{n:>3}  {meaning}")),
                "the overview does not print exit {n}"
            );
        }
        assert!(
            text.contains("--help") && text.contains("--format json"),
            "the overview must tell a reader how to learn more:\n{text}"
        );
    }

    #[test]
    fn help_in_json_mode_is_the_interface_as_data() {
        let (code, text, err) = say(&["help", "--format", "json"]);
        assert_eq!(code, 0, "{err}");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("help wrote invalid json");
        let commands = doc["commands"].as_array().unwrap();
        assert_eq!(commands.len(), Command::ALL.len());
        for entry in commands {
            let name = entry["command"].as_str().unwrap();
            let declared = Command::ALL.iter().find(|c| c.name() == name).unwrap();
            let options = entry["options"].as_array().unwrap();
            assert_eq!(options.len(), declared.flags().len(), "{name}'s options");
            for f in declared.flags() {
                assert!(
                    options.iter().any(|o| o["option"] == f.long()),
                    "{name} does not document {}",
                    f.long()
                );
            }
        }
        assert_eq!(doc["protocol"], swp_core::SWP_PROTOCOL_NAME);
        let codes = doc["exit_codes"].as_array().unwrap();
        assert_eq!(codes.len(), exit_codes().len());
        assert!(
            codes
                .iter()
                .any(|e| e["code"] == 1 && e["meaning"].is_string()),
            "the table is not self-describing: {codes:?}"
        );
        // A command page carries the same three sections the text page has.
        let (code, text, err) = say(&["help", "scan", "--format", "json"]);
        assert_eq!(code, 0, "{err}");
        let one: serde_json::Value = serde_json::from_str(&text).expect("page is not json");
        assert_eq!(one["command"], "scan");
        assert_eq!(one["usage"], usage(Command::Scan));
        assert!(
            !one["notes"].as_array().unwrap().is_empty(),
            "the notes vanished from the json page"
        );
        assert!(
            one["exit_codes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["code"] == 1),
            "a script cannot see that scan exits 1 on a finding"
        );
    }

    #[test]
    fn a_pages_exit_code_table_never_prints_one_number_two_ways() {
        for cmd in Command::ALL {
            let codes = command_exit_codes(*cmd);
            let mut seen: Vec<i32> = codes.iter().map(|(n, _)| *n).collect();
            let count = seen.len();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), count, "{} lists an exit code twice", cmd.name());
            assert_eq!(
                seen.first().copied(),
                Some(0),
                "{} has no success code",
                cmd.name()
            );
            for expected in [2, ErrorCode::Io.exit_code(), 70] {
                assert!(
                    seen.contains(&expected),
                    "{}'s table omits {expected}",
                    cmd.name()
                );
            }
            let (_, text, _) = say(&[cmd.name(), "--help"]);
            for (n, meaning) in &codes {
                assert!(
                    text.contains(&format!("{n:>3}  {meaning}")),
                    "{}'s page omits exit {n}",
                    cmd.name()
                );
            }
        }
    }

    #[test]
    fn inspect_help_names_the_views_its_parser_accepts() {
        let names = crate::inspect::view_names();
        assert_eq!(names.len(), 8, "inspect grew or lost a view");
        let (_, text, _) = say(&["inspect", "--help"]);
        for name in &names {
            assert!(
                text.contains(name),
                "inspect's help omits the {name:?} view"
            );
        }
        // The parser's own refusal lists them too, so a reader who guesses wrong
        // is told the alternatives without leaving the terminal.
        let parsed = parse(&["inspect".into(), "not-a-view".into()]).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut sink = Sink::new(Format::Text, false, &mut out, &mut err);
        let e = crate::inspect::run(&parsed, Path::new("."), &mut sink).unwrap_err();
        for name in &names {
            assert!(
                e.message().contains(name),
                "the refusal omits {name:?}: {e}"
            );
        }
        assert_eq!(e.code(), ErrorCode::Usage);
    }

    #[test]
    fn a_command_that_does_not_exist_is_named_and_the_alternatives_are_offered() {
        let (code, _, err) = say(&["protec"]);
        assert_eq!(code, ErrorCode::Usage.exit_code(), "{err}");
        assert!(
            err.contains("protect"),
            "a near-miss should point at it: {err}"
        );
        assert!(err.contains("swp help"), "{err}");
    }
}
