//! The command line, parsed by hand.
//!
//! There is no argument-parsing dependency in this build. That is a constraint
//! the project accepted rather than a preference: SWP-1 is offline-first (§34)
//! and proprietary, and a tool that cannot fetch a crate must not need one. The
//! parser below is forty lines of matching rather than a library, and it is
//! strict in the two ways that matter for a provenance tool —
//!
//! * an unrecognized option is an error, never ignored. `--formt json` printing
//!   human text where machine text was asked for is the kind of failure that
//!   gets baked into a script;
//! * every option is declared once, in [`Flag`], with whether it takes a value
//!   and which commands accept it, so `swp scan --release` and `swp verify
//!   --release` cannot grow different meanings.

use std::collections::BTreeMap;

use swp_core::error::SwpError;

/// Every option SWP-1 accepts, anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flag {
    /// `--format text|json`
    Format,
    /// `--output <path>`
    Output,
    /// `--save`
    Save,
    /// `--release <id>`
    Release,
    /// `--latest`
    Latest,
    /// `--revision <text>`
    Revision,
    /// `--project <path>`
    Project,
    /// `--target <path>`, repeatable
    Target,
    /// `--sites <n>`
    Sites,
    /// `--bits <n>`
    Bits,
    /// `--name <label>`
    Name,
    /// `--limit <n>`
    Limit,
    /// `--force`
    Force,
    /// `--dry-run`
    DryRun,
    /// `--full`
    Full,
    /// `--quiet`
    Quiet,
    /// `--verbose`
    Verbose,
}

impl Flag {
    /// The long form, which is also the key in [`Parsed`].
    pub fn long(self) -> &'static str {
        match self {
            Flag::Format => "--format",
            Flag::Output => "--output",
            Flag::Save => "--save",
            Flag::Release => "--release",
            Flag::Latest => "--latest",
            Flag::Revision => "--revision",
            Flag::Project => "--project",
            Flag::Target => "--target",
            Flag::Sites => "--sites",
            Flag::Bits => "--bits",
            Flag::Name => "--name",
            Flag::Limit => "--limit",
            Flag::Force => "--force",
            Flag::DryRun => "--dry-run",
            Flag::Full => "--full",
            Flag::Quiet => "--quiet",
            Flag::Verbose => "--verbose",
        }
    }

    /// The short alias, where one exists.
    pub fn short(self) -> Option<&'static str> {
        match self {
            Flag::Output => Some("-o"),
            Flag::Project => Some("-p"),
            Flag::Quiet => Some("-q"),
            Flag::Verbose => Some("-v"),
            Flag::Force => Some("-f"),
            _ => None,
        }
    }

    pub fn takes_value(self) -> bool {
        matches!(
            self,
            Flag::Format
                | Flag::Output
                | Flag::Release
                | Flag::Revision
                | Flag::Project
                | Flag::Target
                | Flag::Sites
                | Flag::Bits
                | Flag::Name
                | Flag::Limit
        )
    }

    /// One line of the help text.
    pub fn summary(self) -> &'static str {
        match self {
            Flag::Format => "output format: text (default) or json",
            Flag::Output => "write the machine-readable document here instead of stdout",
            Flag::Save => "also save the report under .swp/private/reports/",
            Flag::Release => "release id: the one to act on, or to list reports for",
            Flag::Latest => "act on the newest release only",
            Flag::Revision => "record this source revision label in the release record",
            Flag::Project => "the protected project to work on (default: search upward)",
            Flag::Target => "override [protect] targets for this run (repeatable)",
            Flag::Sites => "override [protect] target_sites for this run",
            Flag::Bits => "override [protect] tag_bits (2-8) for this run",
            Flag::Name => "the project's display label (init only)",
            Flag::Limit => "rows the text lists before counting the rest; json is never cut",
            Flag::Force => "redo work the tool would otherwise skip",
            Flag::DryRun => "decide and report, change nothing",
            Flag::Full => "list every item, not the first page of them",
            Flag::Quiet => "print only the result line",
            Flag::Verbose => "explain what is being looked at while it is looked at",
        }
    }

    fn find(spec: &str) -> Option<Self> {
        ALL_FLAGS
            .iter()
            .find(|f| f.long() == spec || f.short() == Some(spec))
            .copied()
    }
}

/// Every option, in the order the help lists them. Declared once so the parser,
/// the help and the tests cannot each keep a private copy that falls behind.
pub const ALL_FLAGS: [Flag; 17] = [
    Flag::Format,
    Flag::Output,
    Flag::Save,
    Flag::Release,
    Flag::Latest,
    Flag::Revision,
    Flag::Project,
    Flag::Target,
    Flag::Sites,
    Flag::Bits,
    Flag::Name,
    Flag::Limit,
    Flag::Force,
    Flag::DryRun,
    Flag::Full,
    Flag::Quiet,
    Flag::Verbose,
];

/// The seven commands, plus the two that print and leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Init,
    Generate,
    Protect,
    Verify,
    Scan,
    Inspect,
    Report,
    Help,
    Version,
}

impl Command {
    pub const ALL: &'static [Command] = &[
        Command::Init,
        Command::Generate,
        Command::Protect,
        Command::Verify,
        Command::Scan,
        Command::Inspect,
        Command::Report,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Command::Init => "init",
            Command::Generate => "generate",
            Command::Protect => "protect",
            Command::Verify => "verify",
            Command::Scan => "scan",
            Command::Inspect => "inspect",
            Command::Report => "report",
            Command::Help => "help",
            Command::Version => "--version",
        }
    }

    /// The one-line description the overview lists.
    pub fn blurb(self) -> &'static str {
        match self {
            Command::Init => "create the project's identity and private store",
            Command::Generate => "plan a constellation and write nothing into the source",
            Command::Protect => "embed the watermark and record the release",
            Command::Verify => "check this tree against one of its own releases",
            Command::Scan => "scan a candidate copy for evidence of your releases",
            Command::Inspect => "show what the store holds: identity, releases, fragments",
            Command::Report => "list and re-render saved reports",
            Command::Help => "this text",
            Command::Version => "the protocol and build versions",
        }
    }

    /// Options this command accepts, in the order the help lists them.
    pub fn flags(self) -> &'static [Flag] {
        match self {
            Command::Init => &[
                Flag::Name,
                Flag::Project,
                Flag::Format,
                Flag::Force,
                Flag::Quiet,
            ],
            Command::Generate => &[
                Flag::Project,
                Flag::Target,
                Flag::Sites,
                Flag::Bits,
                Flag::Release,
                Flag::Format,
                Flag::Quiet,
                Flag::Verbose,
            ],
            Command::Protect => &[
                Flag::Project,
                Flag::Target,
                Flag::Sites,
                Flag::Bits,
                Flag::Release,
                Flag::Revision,
                Flag::DryRun,
                Flag::Format,
                Flag::Quiet,
                Flag::Verbose,
            ],
            Command::Verify => &[
                Flag::Project,
                Flag::Release,
                Flag::Latest,
                Flag::Format,
                Flag::Save,
                Flag::Output,
                Flag::Full,
                Flag::Limit,
                Flag::Quiet,
                Flag::Verbose,
            ],
            Command::Scan => &[
                Flag::Release,
                Flag::Latest,
                Flag::Project,
                Flag::Format,
                Flag::Save,
                Flag::Output,
                Flag::Full,
                Flag::Limit,
                Flag::Quiet,
                Flag::Verbose,
            ],
            Command::Inspect => &[
                Flag::Project,
                Flag::Release,
                Flag::Format,
                Flag::Full,
                Flag::Limit,
            ],
            Command::Report => &[
                Flag::Project,
                Flag::Release,
                Flag::Format,
                Flag::Full,
                Flag::Output,
                Flag::Limit,
            ],
            Command::Help | Command::Version => &[Flag::Format],
        }
    }

    /// Whether the command needs the project's private root secret.
    pub fn needs_secret(self) -> bool {
        matches!(
            self,
            Command::Generate | Command::Protect | Command::Verify | Command::Scan
        )
    }

    /// The command a reader most plausibly meant: the closest name within two
    /// edits, which covers a dropped, doubled or swapped letter without ever
    /// offering something unrelated. `None` when nothing is that close, or when
    /// the word is too short to guess from — `swp s` should be answered with the
    /// list, not with one arbitrary command picked out of it.
    pub fn nearest(typed: &str) -> Option<Command> {
        let typed = typed.to_ascii_lowercase();
        if typed.chars().count() < 3 {
            return None;
        }
        let mut best: Option<(usize, Command)> = None;
        for c in Command::ALL {
            let d = edit_distance(&typed, c.name());
            if d <= 2 && best.is_none_or(|(bd, _)| d < bd) {
                best = Some((d, *c));
            }
        }
        best.map(|(_, c)| c)
    }
}

/// The same idea for options, so `swp scan --formt json x` is answered with
/// `--format` rather than with a list.
fn nearest_flag(spec: &str) -> Option<Flag> {
    let typed = spec.to_ascii_lowercase();
    if typed.chars().count() < 4 {
        return None;
    }
    let mut best: Option<(usize, Flag)> = None;
    for f in ALL_FLAGS {
        let d = edit_distance(&typed, f.long());
        if d <= 2 && best.is_none_or(|(bd, _)| d < bd) {
            best = Some((d, f));
        }
    }
    best.map(|(_, f)| f)
}

/// Levenshtein distance over chars. These are short words, so the quadratic form
/// is cheaper than a cleverer one and cannot be made to lag on hostile input
/// beyond its own length.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                prev[j + 1]
                    .saturating_add(1)
                    .min(cur[j].saturating_add(1))
                    .min(prev[j] + usize::from(ca != *cb)),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

/// A parsed command line: which command, its positional words, and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub command: Command,
    pub positional: Vec<String>,
    /// One entry per occurrence, so `--target a --target b` keeps both.
    values: BTreeMap<Flag, Vec<String>>,
}

impl Parsed {
    pub fn value(&self, flag: Flag) -> Option<&str> {
        self.values.get(&flag)?.last().map(|s| s.as_str())
    }

    pub fn many(&self, flag: Flag) -> Vec<String> {
        self.values.get(&flag).cloned().unwrap_or_default()
    }

    pub fn has(&self, flag: Flag) -> bool {
        self.values.contains_key(&flag)
    }

    /// A valued option parsed as a number, with the option named in the error.
    pub fn number(&self, flag: Flag) -> Result<Option<u32>, SwpError> {
        let Some(raw) = self.value(flag) else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        let n = trimmed.parse::<u32>().map_err(|_| {
            SwpError::usage(format!(
                "{} expects a whole number, found {raw:?}",
                flag.long()
            ))
        })?;
        Ok(Some(n))
    }

    /// Whether `--format json` was asked for. Anything else is a usage error: a
    /// report format that does not exist must not silently fall back to text.
    pub fn json(&self) -> Result<bool, SwpError> {
        match self.value(Flag::Format) {
            None | Some("text") => Ok(false),
            Some("json") => Ok(true),
            Some(other) => Err(SwpError::usage(format!(
                "--format expects text or json, found {other:?}"
            ))),
        }
    }

    pub fn quiet(&self) -> bool {
        self.has(Flag::Quiet)
    }

    pub fn verbose(&self) -> bool {
        self.has(Flag::Verbose)
    }
}

/// Parse `argv` without the program name.
///
/// Errors carry [`ErrorCode::Usage`], whose exit code is 2, so a script can tell
/// "you asked for something SWP-1 does not do" from "SWP-1 ran and found
/// nothing".
pub fn parse(argv: &[String]) -> Result<Parsed, SwpError> {
    let Some(word) = argv.first() else {
        return Ok(Parsed {
            command: Command::Help,
            positional: Vec::new(),
            values: BTreeMap::new(),
        });
    };
    let command = match word.as_str() {
        "-h" | "--help" | "help" => Command::Help,
        "-V" | "--version" | "version" => Command::Version,
        other => Command::ALL
            .iter()
            .find(|c| c.name() == other)
            .copied()
            .ok_or_else(|| {
                // A mistyped verb is the one error on the line the reader cannot
                // see themselves, so the near miss is named rather than left to be
                // guessed again.
                SwpError::usage(match Command::nearest(other) {
                    Some(c) => format!(
                        "unknown command {other:?}. Did you mean `swp {}`? `swp help` lists the \
                         {} commands.",
                        c.name(),
                        Command::ALL.len()
                    ),
                    None => format!(
                        "unknown command {other:?}. Run `swp help` for the {} commands.",
                        Command::ALL.len()
                    ),
                })
            })?,
    };
    let mut parsed = Parsed {
        command,
        positional: Vec::new(),
        values: BTreeMap::new(),
    };
    let mut rest = argv[1..].iter().peekable();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            parsed.positional.extend(rest.cloned());
            break;
        }
        if arg == "-h" || arg == "--help" {
            // `swp scan --help` is a request for help, not an option to store.
            return Ok(Parsed {
                command: Command::Help,
                positional: vec![command.name().to_string()],
                values: BTreeMap::new(),
            });
        }
        if !arg.starts_with('-') {
            parsed.positional.push(arg.clone());
            continue;
        }
        // `--format=json` is accepted alongside `--format json`, because both
        // appear in the muscle memory of people who type command lines.
        let (spec, inline) = match arg.split_once('=') {
            Some((a, b)) => (a, Some(b.to_string())),
            None => (arg.as_str(), None),
        };
        let Some(flag) = Flag::find(spec) else {
            // Only suggest an option this command actually takes: pointing at
            // `--name` from `swp scan` would send the reader to a second failure.
            let hint = match nearest_flag(spec).filter(|f| command.flags().contains(f)) {
                Some(f) => format!("Did you mean {}?", f.long()),
                None => format!("Run `swp help {}` for what it does.", command.name()),
            };
            return Err(SwpError::usage(format!(
                "{} does not accept {spec:?}. {hint}",
                command.name()
            )));
        };
        if !command.flags().contains(&flag) {
            return Err(SwpError::usage(format!(
                "{spec:?} is not an option of `swp {}`. It accepts: {}.",
                command.name(),
                command
                    .flags()
                    .iter()
                    .map(|f| f.long())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let value = if flag.takes_value() {
            match inline.or_else(|| rest.next().cloned()) {
                Some(v) => v,
                None => {
                    return Err(SwpError::usage(format!(
                        "{} needs a value",
                        flag.long()
                    )))
                }
            }
        } else {
            if let Some(v) = inline {
                return Err(SwpError::usage(format!(
                    "{} is a flag and takes no value; remove ={v}",
                    flag.long()
                )));
            }
            String::new()
        };
        parsed.values.entry(flag).or_default().push(value);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::error::ErrorCode;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn commands_options_and_positionals_separate_cleanly() {
        let p = parse(&argv(&[
            "scan",
            "./candidate",
            "--format",
            "json",
            "--save",
            "-o",
            "out.json",
        ]))
        .unwrap();
        assert_eq!(p.command, Command::Scan);
        assert_eq!(p.positional, vec!["./candidate".to_string()]);
        assert_eq!(p.value(Flag::Format), Some("json"));
        assert!(p.has(Flag::Save));
        assert_eq!(p.value(Flag::Output), Some("out.json"));
        assert!(p.json().unwrap());
    }

    #[test]
    fn an_equals_form_and_a_repeated_option_both_work() {
        let p = parse(&argv(&[
            "protect",
            "--format=json",
            "--target",
            "src",
            "--target",
            "lib",
        ]))
        .unwrap();
        assert!(p.json().unwrap());
        assert_eq!(p.many(Flag::Target), vec!["src", "lib"]);
        // A repeated valued option is the *last* one for a single-valued flag.
        assert_eq!(p.value(Flag::Target), Some("lib"));
    }

    #[test]
    fn an_unknown_command_or_option_is_a_usage_error_that_names_the_command() {
        let e = parse(&argv(&["scan", "./x", "--formt", "json"])).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Usage);
        assert!(e.message().contains("scan"), "{e}");
        let e = parse(&argv(&["protecte"])).unwrap_err();
        assert!(e.message().contains("unknown command"), "{e}");
        // `-o` is `scan`'s, not `protect`'s: accepted by the parser, refused as a
        // wrong-command option rather than ignored.
        let e = parse(&argv(&["protect", "-o", "x"])).unwrap_err();
        assert!(e.message().contains("not an option"), "{e}");
    }

    #[test]
    fn help_reachable_three_ways_and_a_bare_call_is_help() {
        assert_eq!(parse(&argv(&[])).unwrap().command, Command::Help);
        assert_eq!(parse(&argv(&["--help"])).unwrap().command, Command::Help);
        let p = parse(&argv(&["scan", "--help"])).unwrap();
        assert_eq!(p.command, Command::Help);
        assert_eq!(p.positional, vec!["scan"]);
        let p = parse(&argv(&["help", "protect"])).unwrap();
        assert_eq!(p.positional, vec!["protect"]);
    }

    #[test]
    fn a_format_that_does_not_exist_is_refused_rather_than_defaulted() {
        let p = parse(&argv(&["scan", "./x", "--format", "yaml"])).unwrap();
        assert_eq!(p.json().unwrap_err().code(), ErrorCode::Usage);
        let p = parse(&argv(&["scan", "./x", "--sites", "eight"])).unwrap_err();
        assert!(p.message().contains("--sites"), "{p}");
    }

    #[test]
    fn a_trailing_double_dash_leaves_the_rest_alone() {
        let p = parse(&argv(&["scan", "--", "--weird-name", "-x"])).unwrap();
        assert_eq!(p.positional, vec!["--weird-name", "-x"]);
    }

    #[test]
    fn every_flag_is_declared_exactly_once_and_documented() {
        let all = ALL_FLAGS;
        let mut longs: Vec<&str> = all.iter().map(|f| f.long()).collect();
        let mut shorts: Vec<&str> = all.iter().filter_map(|f| f.short()).collect();
        assert_eq!(longs.len(), all.len());
        longs.sort();
        longs.dedup();
        assert_eq!(longs.len(), all.len(), "two flags share a long name");
        shorts.sort();
        shorts.dedup();
        assert_eq!(shorts.len(), all.iter().filter(|f| f.short().is_some()).count());
        for f in all {
            assert!(!f.summary().is_empty());
            assert!(
                f.long().starts_with("--") && f.long().len() > 2,
                "{:?} is not a long option",
                f.long()
            );
        }
        // Anything the parser knows is offered by at least one command, so a flag
        // cannot be added to the grammar and left unreachable.
        for f in &all {
            assert!(
                Command::ALL.iter().any(|c| c.flags().contains(f)),
                "{:?} is declared but no command takes it",
                f
            );
        }
        for c in Command::ALL {
            for f in c.flags() {
                assert!(all.contains(f), "{} lists an undeclared flag", c.name());
            }
            assert!(
                c.flags().windows(2).all(|w| w[0] != w[1]),
                "{} lists a flag twice",
                c.name()
            );
        }
        assert_eq!(Command::ALL.len(), 7, "§32 lists seven commands");
    }

    #[test]
    fn a_mistyped_verb_or_option_names_the_one_that_was_meant() {
        // The distance function first: a suggestion built on a wrong one is worse
        // than none, because it sends the reader to the command they did not mean.
        assert_eq!(edit_distance("protect", "protect"), 0);
        assert_eq!(edit_distance("", "scan"), 4);
        assert_eq!(edit_distance("scan", ""), 4);
        assert_eq!(edit_distance("protec", "protect"), 1);
        assert_eq!(edit_distance("reprot", "report"), 2);
        assert_eq!(Command::nearest("protec"), Some(Command::Protect));
        assert_eq!(Command::nearest("SCAN"), Some(Command::Scan));
        assert_eq!(Command::nearest("in"), None, "too short to guess from");
        assert_eq!(Command::nearest("definitely-not-a-command"), None);
        let e = parse(&argv(&["protec"])).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Usage);
        assert!(e.message().contains("protect"), "{e}");
        // An option that exists but not here is still refused, with no hint that
        // would send the reader to a second failure.
        let e = parse(&argv(&["scan", "./x", "--name", "y"])).unwrap_err();
        assert!(e.message().contains("--name"), "{e}");
        assert!(!e.message().contains("Did you mean"), "{e}");
        let e = parse(&argv(&["scan", "./x", "--formt", "json"])).unwrap_err();
        assert!(e.message().contains("--format"), "{e}");
    }
}
