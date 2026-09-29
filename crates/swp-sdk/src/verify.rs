//! Is this tree still the tree that was protected?
//!
//! [`Session::verify`] is a scan of the project's **own** root against **one** of
//! its own releases, which is the narrowest possible claim and the most useful
//! one: the release's manifest says which keyed locations it used and what each
//! one must carry, and the scan recomputes both from the root secret. Nothing is
//! looked up by path, so the answer survives the project's own refactoring; what
//! does not survive it is deleting a watermarked literal, which is exactly what
//! the operation is for.
//!
//! Verification is *not* a scan with a convenient path. [`Session::scan`] asks
//! "does this artifact carry my provenance?" and grades an unknown tree against
//! every release; this asks "is my tree still whole?" and answers per site, with
//! a verdict rather than an evidence level. [`VerifyDocument`] and its
//! `SWP-1-verify-v1` schema belong to `swp-evidence`, which is where a scan's
//! meaning is decided — this module only runs the scan and fills the document in.

use swp_core::error::SwpError;
use swp_core::id::ReleaseId;
use swp_evidence::{grade, Verification, VerifyDocument};
use swp_identity::Timestamp;

use crate::session::{ReleaseSelection, Session};

/// What a verification takes.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// The release to check against. `None` is the newest, because "is the tree I
    /// am standing in still the tree I protected?" is a question about the last
    /// protection run.
    pub release: Option<ReleaseId>,
    /// Keep a `SWP-1-report-v2` copy of the underlying scan under
    /// `.swp/private/reports/`. The verification document itself is returned,
    /// never written: reading it back is `swp report`'s job, and its numbers
    /// belong to the moment they were measured.
    pub save: bool,
    /// How many per-site rows the caller intends to render.
    ///
    /// The document always carries every row; this only fills in
    /// [`VerifyDocument::omitted_rows`], which is the record that a text
    /// rendering left some out. `None` — or a number at least as large as the
    /// release — says nothing was omitted.
    pub rows: Option<usize>,
}

/// A verification's answer.
#[derive(Debug)]
pub struct VerifyOutcome {
    /// `INTACT`, `INCOMPLETE` or `INCONCLUSIVE`, the per-site rows, the counts
    /// behind them, and the exit code that a shell would have got — as data.
    ///
    /// [`VerifyDocument::exit_code`] is that code: `0` intact, `5` a site is not
    /// carrying its code, `10` this run could not have said either way.
    pub document: VerifyDocument,
    /// Where `save` wrote the report, when it did.
    pub report_saved: Option<String>,
}

impl Session {
    /// Grade this project's own tree against one of its releases.
    ///
    /// The release's manifest is authenticated against the project's public
    /// verify key before a single site of it is trusted, exactly as in
    /// [`Session::scan`] — and here it matters more, because a manifest is the
    /// list of expected values: an edited one would report an intact tree as
    /// tampered with, or a stripped one as clean (§31).
    ///
    /// A `Verdict::Inconclusive` is not a weak `Incomplete`. It says part of the
    /// tree was never read, so this run could not have seen a missing site; the
    /// document names what was omitted, and the exit code differs.
    pub fn verify(&self, options: &VerifyOptions) -> Result<VerifyOutcome, SwpError> {
        // A named release is checked against the store's listing before it is
        // loaded, so `--release <id>` for a release that was never published is the
        // "this project has no release …" refusal rather than the interrupted-run
        // one further down: the two need different answers from the operator, and
        // the CLI has always given the first.
        let release = match &options.release {
            Some(id) => self.one_release(&ReleaseSelection::Ids(vec![id.clone()]))?,
            None => self.one_release(&ReleaseSelection::All)?,
        };
        let limits = self.limits();
        let releases = self.load_releases(std::slice::from_ref(&release))?;
        let indexes = self.indexes(&releases)?;
        let root = self.project_root().to_path_buf();
        let opened = swp_detection::input::open(&root, &limits)?;
        let detection = swp_detection::scan_against(&opened, &indexes, &limits)?;
        let found = detection
            .releases
            .first()
            .ok_or_else(|| SwpError::internal("a scan of one release returned none"))?;
        let report_saved = if options.save {
            let at = Timestamp::now_utc();
            let report = swp_evidence::Report::build(
                &detection,
                "verify",
                &at.to_rfc3339(),
                &crate::banner(),
            );
            let stem = format!("verify-{}", at.filename_stem());
            Some(
                self.store()
                    .save_report(&stem, report.to_json().as_bytes())?,
            )
        } else {
            None
        };
        let expected = indexes[0].fingerprint().to_string();
        let document = grade(&Verification {
            detection: &detection,
            found,
            project_id: &self.identity().project_id,
            display_name: &self.identity().display_name,
            tree: &opened.described,
            record: &releases[0].record,
            fingerprint_expected: &expected,
            omitted_rows: options
                .rows
                .map_or(0, |n| found.sites.len().saturating_sub(n)),
            report_saved: report_saved.clone(),
        });
        Ok(VerifyOutcome {
            document,
            report_saved,
        })
    }
}
