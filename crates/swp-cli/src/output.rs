//! Output: two renderings of one result, and one way for an error to be shown.
//!
//! §33 asks every major operation for machine-readable output, and a tool that
//! grows a `--format json` branch per command always ends up with the two
//! branches disagreeing. So each command here builds one serializable value and
//! one list of text lines from the *same* computed facts, and [`Sink`] picks
//! which to write. The JSON is the only thing that is guaranteed stable; the text
//! is allowed to change wording between releases, and says so.
//!
//! Errors go to stderr in both modes, always with the actionable next step the
//! error table carries. A JSON-mode caller who needs a machine-readable failure
//! reads the exit code, which is the stable half of that contract.

use std::io::Write;

use serde::Serialize;
use swp_core::error::{ErrorCode, SwpError};

/// What `--format` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

/// Where a command's words go.
///
/// `stdout` carries exactly one document — the report, the release summary, the
/// listing — so `swp scan x --format json | jq .` works without a preamble
/// filter. Progress and warnings go to stderr and are suppressed by `--quiet`,
/// which is the only way a verbose scan stays machine-parseable.
pub struct Sink<'a> {
    pub format: Format,
    pub quiet: bool,
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl<'a> Sink<'a> {
    pub fn new(
        format: Format,
        quiet: bool,
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
    ) -> Self {
        Sink {
            format,
            quiet,
            out,
            err,
        }
    }

    pub fn json(&self) -> bool {
        self.format == Format::Json
    }

    /// Print the result: the value as JSON, or the lines as text.
    ///
    /// Both are built by the caller from the same facts; nothing here reformats
    /// one into the other, because a text rendering that is JSON with the
    /// punctuation stripped is the worst of both.
    pub fn result<T: Serialize>(&mut self, value: &T, lines: &[String]) -> Result<(), SwpError> {
        match self.format {
            Format::Json => {
                let text = serde_json::to_string_pretty(value)
                    .map_err(|e| SwpError::internal(format!("result is not serializable: {e}")))?;
                self.write(text + "\n")
            }
            Format::Text => {
                for line in lines {
                    self.write(line.clone() + "\n")?;
                }
                Ok(())
            }
        }
    }

    /// A progress or diagnostic line, never part of the document.
    pub fn note(&mut self, text: &str) {
        if self.quiet {
            return;
        }
        let _ = writeln!(self.err, "{text}");
    }

    /// A line that must survive `--quiet`: something was refused, not merely
    /// observed.
    pub fn warn(&mut self, text: &str) {
        let _ = writeln!(self.err, "warning: {text}");
    }

    fn write(&mut self, text: String) -> Result<(), SwpError> {
        self.out
            .write_all(text.as_bytes())
            .map_err(|e| SwpError::io(format!("cannot write the result: {e}")))
    }
}

/// How many rows a text rendering lists before counting the rest. A terminal
/// report that scrolls a finding off the page is a finding nobody sees, so the
/// window is narrow by default and `--full`/`--limit` widen it.
pub const TEXT_ROWS: usize = 24;

/// The window `--full` and `--limit <n>` asked for, in rows.
pub fn window(full: bool, limit: Option<u32>) -> usize {
    if full {
        usize::MAX
    } else {
        limit.map_or(TEXT_ROWS, |n| n as usize)
    }
}

/// The part of a table the text rendering prints, and how many rows it left out.
/// Only ever the text: a JSON document missing rows is not an auditable document.
pub fn head<T>(rows: &[T], limit: usize) -> (&[T], usize) {
    if rows.len() <= limit {
        (rows, 0)
    } else {
        (&rows[..limit], rows.len() - limit)
    }
}

/// A string shortened to fit a table column, on character boundaries.
///
/// Slicing bytes is not an option here: a candidate path, a project label or a
/// revision string is whatever the operator typed, and cutting one mid-UTF-8
/// sequence panics in the middle of a report about someone else's source tree.
pub fn clip(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    let mut out: String = chars[..width.saturating_sub(1)].iter().collect();
    out.push('…');
    out
}

/// Deliver one document: to `--output` when it names a file, otherwise to stdout.
///
/// The file always holds the JSON, whatever `--format` said, because that is what
/// the option promises — "the machine-readable document" — and a caller who
/// names a file and asks for text can pipe. stdout stays empty in that case, so
/// `swp scan x -o r.json > out` writes nothing confusing to `out`; the one line
/// saying where the document went is a note, and `--quiet` silences it.
pub fn deliver<T: Serialize>(
    sink: &mut Sink<'_>,
    value: &T,
    lines: &[String],
    output: Option<&str>,
) -> Result<(), SwpError> {
    let Some(path) = output.filter(|p| !p.trim().is_empty()) else {
        return sink.result(value, lines);
    };
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| SwpError::internal(format!("result is not serializable: {e}")))?;
    crate::help::write_document(path, &(text + "\n"))?;
    sink.note(&format!(
        "wrote the JSON document to {path}; {} line(s) of text were not printed",
        lines.len()
    ));
    Ok(())
}

/// Write one failure to stderr. Returns the process exit code.
///
/// The three lines are the three things a reader needs in order: what happened,
/// what to do about it, and where it happened. `render` keeps them in the order
/// the error table intends rather than letting each call site improvise.
pub fn print_error(sink: &mut Sink<'_>, error: &SwpError) -> i32 {
    let code = error.code();
    let _ = writeln!(sink.err, "error [{}]: {}", code.as_str(), error.message());
    if let Some(path) = error.path() {
        let _ = writeln!(sink.err, "  at: {path}");
    }
    let _ = writeln!(sink.err, "  next: {}", code.next_step());
    code.exit_code()
}

/// The exit code for a usage failure raised while printing was itself failing.
pub fn fallback_exit(code: ErrorCode) -> i32 {
    code.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink<'a>(
        format: Format,
        quiet: bool,
        out: &'a mut Vec<u8>,
        err: &'a mut Vec<u8>,
    ) -> Sink<'a> {
        Sink::new(format, quiet, out, err)
    }

    #[derive(serde::Serialize)]
    struct Value {
        schema: &'static str,
        sites: u32,
    }

    #[test]
    fn json_mode_writes_one_document_and_no_text_lines() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let lines = vec!["sites 3".to_string(), "human prose".to_string()];
        sink(Format::Json, false, &mut out, &mut err)
            .result(&Value { schema: "x", sites: 3 }, &lines)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("human prose"), "{text}");
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["sites"], 3);
        assert!(text.ends_with('\n'), "a document ends with a newline");
    }

    #[test]
    fn text_mode_writes_the_lines_verbatim_and_no_json() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        sink(Format::Text, false, &mut out, &mut err)
            .result(
                &Value { schema: "x", sites: 3 },
                &["sites 3".to_string()],
            )
            .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "sites 3\n");
    }

    #[test]
    fn notes_respect_quiet_and_warnings_do_not() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut s = sink(Format::Text, true, &mut out, &mut err);
        s.note("scanning 900 files");
        s.warn("a limit was reached");
        assert_eq!(String::from_utf8(out).unwrap(), "");
        let text = String::from_utf8(err).unwrap();
        assert!(!text.contains("scanning"), "{text}");
        assert!(text.contains("warning: a limit"), "{text}");
    }

    #[test]
    fn an_error_prints_code_next_step_and_its_exit_code() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut s = sink(Format::Json, false, &mut out, &mut err);
        let e = SwpError::new(ErrorCode::NotProtected, "no .swp here").with_path("./x");
        assert_eq!(print_error(&mut s, &e), ErrorCode::NotProtected.exit_code());
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains("NOT_PROTECTED"), "{text}");
        assert!(text.contains("next: Run `swp init`"), "{text}");
        assert!(text.contains("at: ./x"), "{text}");
        assert!(out.is_empty(), "a failure writes no document");
    }

    #[test]
    fn full_prints_every_row_and_a_limit_sizes_the_window() {
        assert_eq!(window(true, Some(3)), usize::MAX);
        assert_eq!(window(false, Some(3)), 3);
        assert_eq!(window(false, None), TEXT_ROWS);
        let rows = [1u32, 2, 3, 4, 5];
        assert_eq!(head(&rows, 3), (&rows[..3], 2));
        assert_eq!(head(&rows, usize::MAX), (&rows[..], 0));
        assert_eq!(head(&rows, 5), (&rows[..], 0), "an exact fit hides nothing");
    }

    #[test]
    fn clipping_a_column_never_splits_a_character() {
        assert_eq!(clip("src/a.js", 12), "src/a.js");
        assert_eq!(clip("src/a.js", 10), "src/a.js");
        assert_eq!(clip("src/a.js", 8), "src/a.js");
        assert_eq!(clip("src/a.js", 7), "src/a.…");
        // The multi-byte case is the one that panics if the cut is by bytes.
        let naive = "src/naïve/module/index.js";
        let clipped = clip(naive, 12);
        assert_eq!(clipped.chars().count(), 12, "{clipped:?}");
        assert!(clipped.ends_with('…'), "{clipped:?}");
        assert_eq!(clip("é", 1), "é");
    }

    #[test]
    fn output_sends_the_json_to_a_file_and_leaves_stdout_empty() {
        let dir = std::env::temp_dir().join(format!("swp-cli-output-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("doc.json");
        let at = path.display().to_string();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut s = sink(Format::Text, false, &mut out, &mut err);
        deliver(
            &mut s,
            &Value {
                schema: "x",
                sites: 7,
            },
            &["text rendering".to_string()],
            Some(&at),
        )
        .unwrap();
        assert!(out.is_empty(), "the document went to the file, not to stdout");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("\"sites\": 7"), "{written}");
        assert!(!written.contains("text rendering"), "{written}");
        assert!(
            String::from_utf8(err).unwrap().contains("wrote the JSON document"),
            "the operator is told where it went"
        );
        // No `--output` is the ordinary case: stdout gets the chosen rendering.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut s = sink(Format::Text, false, &mut out, &mut err);
        deliver(
            &mut s,
            &Value {
                schema: "x",
                sites: 7,
            },
            &["text rendering".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "text rendering\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
