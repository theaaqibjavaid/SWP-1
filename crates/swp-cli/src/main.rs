//! The `swp` binary: read argv, hand it to the library, exit with what it says.
//!
//! Deliberately four lines of logic. Everything a reviewer of a provenance tool
//! needs to check — which paths are read, whose keys are trusted, what may be
//! written, what a report is allowed to claim — is in `swp-cli`'s library, which
//! the integration tests drive directly through [`swp_cli::run_in`] rather than
//! through a process, because a test that has to spawn `swp` to check its exit
//! code cannot run in a sandbox where spawning is what the tool promises not to
//! do (§21).

use std::io::{self, Write};

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = io::LineWriter::new(stdout.lock());
    let mut err = stderr.lock();
    let code = swp_cli::run(&argv, &mut out, &mut err);
    // A broken pipe is how `swp scan . | head` ends, and it is not a failure of
    // the scan; everything else about flushing is.
    let _ = out.flush();
    let _ = err.flush();
    std::process::ExitCode::from(clamp(code))
}

/// A process exit status is one byte. The tool's own codes all fit; anything
/// larger is a bug and is reported as the generic failure code rather than
/// silently truncated to the wrong meaning (`258` would become `2`).
fn clamp(code: i32) -> u8 {
    if !(0..=255).contains(&code) {
        70
    } else {
        code as u8
    }
}
