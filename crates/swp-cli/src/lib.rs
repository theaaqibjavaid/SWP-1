//! SWP-1's command line: seven verbs over one protocol.
//!
//! §32 asks for `init`, `generate`, `protect`, `verify`, `scan`, `inspect` and
//! `report`, each with `--help` and useful exit codes, and §33 asks each to speak
//! machine. This crate is the only place in the workspace that talks to a person,
//! so the rules it keeps are about what a person can be trusted to have said:
//!
//! * **The command line is parsed, not guessed.** An unknown option is an error
//!   naming the command that rejected it ([`args`]), and `--format yaml` fails
//!   rather than quietly printing text. A provenance tool that invents a default
//!   when it misreads an instruction is a tool that produces a report nobody
//!   asked for.
//! * **One document on stdout, everything else on stderr.** Progress, warnings
//!   and errors never mix into the JSON a script is piping. `--quiet` removes
//!   progress; it does not remove warnings, because a refusal is not progress.
//! * **The exit code is part of the result, not an afterthought.** `swp scan`
//!   exits 1 when it *found* something, 0 when the candidate is clean, and 10
//!   when it cannot say — the three answers a caller can branch on, with the
//!   numbers taken from the same table every error uses.
//! * **Nothing here runs a candidate.** No process is spawned anywhere in this
//!   crate or in anything it calls (§21). There is no shell-out to `git` either:
//!   a revision label the operator typed (`--revision`) is recorded as exactly
//!   that, and the default is content-only.
//!
//! ## Where the security-relevant decisions are, for a reviewer
//!
//! | decision | file |
//! |---|---|
//! | which project's keys are used, and that a candidate cannot supply them | [`ctx::Ctx::open`] |
//! | when the root secret is read, and that it is never printed | [`ctx::Ctx::secret`] |
//! | what `init` creates, and that a second run cannot rotate the secret | [`init`] |
//! | what may be committed, backed up, and never shared | the four lists in [`init`], from `swp-manifest`'s table |
//! | which tree a command may write to | [`protect`], which delegates the writes to `swp-embedding` |
//! | what a report claims and what it refuses to | `swp-evidence`, rendered verbatim here |

use std::io::Write;
use std::path::Path;

use swp_core::error::{ErrorCode, SwpError};

pub mod args;
pub mod ctx;
pub mod help;
pub mod init;
pub mod inspect;
pub mod output;
pub mod protect;
pub mod report;
pub mod scan;
pub mod verify;

#[cfg(test)]
mod scratch;

/// The version `swp --version` prints and every artifact records as its
/// generator. One source, so a report and the binary that wrote it agree.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run `swp` with `argv` after the program name, writing to the given streams.
///
/// Returns the process exit code rather than a `Result`, because the failure has
/// already been reported by the time this returns — printing then exiting is the
/// whole job, and a `Result` would invite a caller to print it a second time.
pub fn run(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match std::env::current_dir() {
        Ok(cwd) => run_in(argv, &cwd, out, err),
        Err(e) => {
            let error = SwpError::new(
                ErrorCode::Io,
                format!("the working directory cannot be read: {e}"),
            );
            let mut sink = output::Sink::new(output::Format::Text, false, out, err);
            output::print_error(&mut sink, &error)
        }
    }
}

/// As [`run`], with the working directory named: the commands that locate a
/// project by walking up from it take it as an argument, which is what lets a
/// test drive them without moving the process.
pub fn run_in(argv: &[String], cwd: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match args::parse(argv) {
        Ok(p) => p,
        Err(e) => {
            // The line was not understood, so the format it asked for is not
            // either: the error is text, and the exit code is what a script
            // should branch on.
            let mut sink = output::Sink::new(output::Format::Text, false, out, err);
            return output::print_error(&mut sink, &e);
        }
    };
    let format = match help::format_of(&parsed) {
        Ok(f) => f,
        Err(e) => {
            let mut sink = output::Sink::new(output::Format::Text, false, out, err);
            return output::print_error(&mut sink, &e);
        }
    };
    let mut sink = output::Sink::new(format, parsed.quiet(), out, err);
    let outcome = dispatch(&parsed, cwd, &mut sink);
    match outcome {
        Ok(code) => code,
        Err(e) => output::print_error(&mut sink, &e),
    }
}

fn dispatch(
    parsed: &args::Parsed,
    cwd: &Path,
    sink: &mut output::Sink<'_>,
) -> Result<i32, SwpError> {
    match parsed.command {
        args::Command::Help => {
            help::print(parsed, sink)?;
            Ok(0)
        }
        args::Command::Version => {
            help::version(sink)?;
            Ok(0)
        }
        args::Command::Init => init::run(parsed, cwd, sink),
        args::Command::Generate => protect::run(parsed, cwd, sink, swp_embedding::Mode::Plan),
        args::Command::Protect => protect::run(parsed, cwd, sink, mode_of(parsed)),
        args::Command::Verify => verify::run(parsed, cwd, sink),
        args::Command::Scan => scan::run(parsed, cwd, sink),
        args::Command::Inspect => inspect::run(parsed, cwd, sink),
        args::Command::Report => report::run(parsed, cwd, sink),
    }
}

fn mode_of(parsed: &args::Parsed) -> swp_embedding::Mode {
    if parsed.has(args::Flag::DryRun) {
        swp_embedding::Mode::DryRun
    } else {
        swp_embedding::Mode::Release
    }
}
