//! The saved reports: what a scan or a verification concluded, read back.
//!
//! §19 asks for evidence to be kept *per release* rather than recomputed against
//! whatever the ladder believes today, and `save` is where that evidence lands:
//! one JSON document per run under `.swp/private/reports/`. This module is the
//! read side of that store, and the one promise it keeps is that it never
//! re-grades — [`Session::read_report`] returns the stored document parsed, so a
//! finding made before the ladder changed still reads the way it read on the day
//! it was made. The `generator` field in it says which build wrote that, which is
//! the only way the distinction survives.
//!
//! Reading a report needs no secret, no tree walk and no write. It is the
//! operation with the fewest edges in this crate, and it is here rather than left
//! to [`Store`](swp_identity::Store) because a caller should not have to know that
//! the name `scan --save` printed, the file name, and the store-relative path are
//! three spellings of one entry — or have to build a path into a private
//! directory to get at it.
use swp_core::error::{ErrorCode, SwpError};
use swp_evidence::Report;

use crate::session::Session;

/// One saved report, and where it came from.
#[derive(Debug, Clone)]
pub struct StoredReport {
    /// The document as it was graded. Re-serializing it yields the stored bytes
    /// unchanged, because the report *is* this type rather than a re-reading of a
    /// `serde_json::Value` — key order is part of what makes an export diffable
    /// against its original.
    pub report: Report,
    /// The stem [`Session::read_report`] accepts for this document.
    pub name: String,
    /// Store-relative and forward-slashed.
    pub path: String,
}

impl Session {
    /// Every saved report this store holds, newest first (the stems are timestamped).
    ///
    /// The names are what [`Session::read_report`] takes. A file in the directory
    /// that is not a readable report is still listed here, because this is a
    /// listing of the directory, not of the parseable documents in it —
    /// [`Session::read_report`] is where it would fail, and the caller is the only
    /// party who can do anything about it.
    pub fn reports(&self) -> Result<Vec<String>, SwpError> {
        self.store().report_names()
    }

    /// Read one saved report, by any of the three names it has.
    ///
    /// `--save` prints a stem, a listing prints a store-relative path, and a
    /// shell completion offers the file name. All three mean the same entry, so
    /// all three are accepted, and [`Store::report_path`](swp_identity::Store::report_path)
    /// is what refuses a name that would leave the reports directory — the path is
    /// never built from the caller's string here.
    pub fn read_report(&self, name: &str) -> Result<StoredReport, SwpError> {
        let stem = report_stem(name);
        let path = self.store().report_path(&stem)?;
        if !path.is_file() {
            let saved = self.store().report_names()?.len();
            return Err(SwpError::new(
                ErrorCode::Usage,
                format!(
                    "there is no saved report {stem:?} in this project ({saved} report(s) are \
                     stored). `swp report` lists them; a report is written by \
                     `swp scan <candidate> --save` or `swp verify --save`."
                ),
            )
            .with_path(self.relabel(&path)));
        }
        let bytes = self.store().read_report(&stem)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            SwpError::invalid_manifest(format!(
                "the saved report {stem:?} is not UTF-8, so it is not a report this tool wrote"
            ))
        })?;
        let report = Report::from_json(&text)?;
        let at = self.relabel(&path);
        Ok(StoredReport {
            report,
            name: stem,
            path: at,
        })
    }
}

/// The name a report is stored under, from however it was spelled.
pub fn report_stem(what: &str) -> String {
    let trimmed = what.trim();
    let last = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_string();
    match last.strip_suffix(".json") {
        Some(stripped) if !stripped.is_empty() => stripped.to_string(),
        _ => last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_spellings_of_one_entry_normalize_to_its_stem() {
        assert_eq!(
            report_stem("scan-2026-09-20T10-00-00Z"),
            "scan-2026-09-20T10-00-00Z"
        );
        assert_eq!(
            report_stem("scan-2026-09-20T10-00-00Z.json"),
            "scan-2026-09-20T10-00-00Z"
        );
        assert_eq!(report_stem(".swp/private/reports/scan-x.json"), "scan-x");
        assert_eq!(report_stem(r"\.swp\private\reports\scan-x.json"), "scan-x");
        // A name that is only the extension is not a name, and whitespace a shell
        // left behind is not part of it.
        assert_eq!(report_stem(".json"), ".json");
        assert_eq!(report_stem("  scan-x  "), "scan-x");
        // A traversal is stripped to its last segment, so what reaches the store's
        // own containment check is a bare entry name — never a path out of the
        // reports directory.
        assert_eq!(
            report_stem("../manifests/rel-aaaaaaaaaaaaaaaa"),
            "rel-aaaaaaaaaaaaaaaa"
        );
    }
}
