//! A verification's answer: the `SWP-1-verify-v1` document, with its own words.
//!
//! The document is `swp-evidence`'s. It is built by `grade()` inside
//! `Session::verify`, from the detection run and the release's authenticated
//! manifest, and this module holds that value: every getter below reads a field
//! off it, and `toJson()` serializes it. Nothing here decides a verdict, counts
//! a site, compares a probability, or maps a result to an exit code — the
//! document already carries all four, because the same numbers have to be
//! readable by whoever receives the file later.
//!
//! Holding the Rust document rather than copying its fields is deliberate: a
//! copy could go stale against the schema, and `toJson()` on a copy would be
//! the binding's own document with a familiar name.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{SiteRow as SdkSiteRow, VerifyDocument, VerifyOutcome as SdkVerifyOutcome};

use crate::error::Failure;

/// A verification's answer: the document, and where a saved copy went.
#[napi(js_name = "VerifyOutcome")]
pub struct VerifyOutcome {
    document: VerifyDocument,
    report_saved: Option<String>,
}

/// One site of the release, and whether it is still there.
///
/// `SiteRow` is not `Clone`, so these rows are copied out when the outcome is
/// built. `confirmed` is not this binding's judgement: it is `SiteRow::confirmed`,
/// which asks the one place the protocol draws the watermark/not-watermark line.
#[napi(object, js_name = "SiteRow")]
#[derive(Clone)]
pub struct SiteRow {
    /// Index into the release's site list, matching `swp inspect manifest`.
    pub site: f64,
    /// Where this site was when the release was made. A hint for a human, never
    /// a lookup key — a site that moved is still the same site.
    pub file: String,
    pub line_hint: u32,
    pub language: String,
    pub adapter: String,
    /// `'integer'` or `'string'`.
    #[napi(js_name = "class")]
    pub class_: String,
    pub family: String,
    pub width: u8,
    /// `'absent'`, `'location-only'`, `'tag-confirmed'` or `'exact-rendering'`.
    pub status: String,
    /// Whether this row is watermark evidence, as `swp-evidence` grades it.
    pub confirmed: bool,
    /// Which of the four keyed radii the tree reproduced.
    pub slots: Vec<String>,
    /// Where the site was actually found, when that differs from `file`.
    pub found_in: Option<String>,
    pub found_line: Option<u32>,
    pub refactored: bool,
    pub moved: bool,
}

#[napi]
impl VerifyOutcome {
    /// `SWP-1-verify-v1`.
    #[napi(getter)]
    pub fn schema(&self) -> String {
        self.document.schema.to_string()
    }

    /// The protocol this document speaks: `SWP-1`.
    #[napi(getter)]
    pub fn protocol(&self) -> String {
        self.document.protocol.to_string()
    }

    #[napi(getter)]
    pub fn project_id(&self) -> String {
        self.document.project_id.clone()
    }

    #[napi(getter)]
    pub fn display_name(&self) -> String {
        self.document.display_name.clone()
    }

    /// How the tree being verified was described by the code that opened it.
    #[napi(getter)]
    pub fn tree(&self) -> String {
        self.document.tree.clone()
    }

    #[napi(getter)]
    pub fn release_id(&self) -> String {
        self.document.release_id.clone()
    }

    /// RFC 3339, UTC, as the release record recorded it.
    #[napi(getter)]
    pub fn release_created_at(&self) -> String {
        self.document.release_created_at.clone()
    }

    /// The label the release recorded, or `null` when it recorded content only.
    /// Display metadata: an attacker can write anything here and the detector
    /// reads nothing from it.
    #[napi(getter)]
    pub fn revision(&self) -> Option<String> {
        self.document.revision.clone()
    }

    /// Whether the release's manifest authenticated against the identity in
    /// `.swp/public/identity.json` — the precondition for every claim below.
    #[napi(getter)]
    pub fn manifest_authenticated(&self) -> bool {
        self.document.manifest_authenticated
    }

    #[napi(getter)]
    pub fn sites_expected(&self) -> f64 {
        self.document.sites_expected as f64
    }

    #[napi(getter)]
    pub fn sites_confirmed(&self) -> f64 {
        self.document.sites_confirmed as f64
    }

    #[napi(getter)]
    pub fn sites_exact(&self) -> f64 {
        self.document.sites_exact as f64
    }

    #[napi(getter)]
    pub fn sites_stripped(&self) -> f64 {
        self.document.sites_stripped as f64
    }

    #[napi(getter)]
    pub fn sites_absent(&self) -> f64 {
        self.document.sites_absent as f64
    }

    #[napi(getter)]
    pub fn sites_moved(&self) -> f64 {
        self.document.sites_moved as f64
    }

    #[napi(getter)]
    pub fn sites_refactored(&self) -> f64 {
        self.document.sites_refactored as f64
    }

    #[napi(getter)]
    pub fn tag_bits(&self) -> u8 {
        self.document.tag_bits
    }

    /// Keyed bits the confirmed sites carry.
    #[napi(getter)]
    pub fn confirmed_bits(&self) -> u32 {
        self.document.confirmed_bits
    }

    #[napi(getter)]
    pub fn files_scanned(&self) -> u32 {
        self.document.files_scanned
    }

    #[napi(getter)]
    pub fn bytes_scanned(&self) -> f64 {
        self.document.bytes_scanned as f64
    }

    /// `'match'`, `'no-match'` or `'not-comparable'`: did the tree hash to the
    /// §16 fingerprint this release published?
    #[napi(getter)]
    pub fn fingerprint(&self) -> String {
        self.document.fingerprint.clone()
    }

    /// The fingerprint this release published, hex.
    #[napi(getter)]
    pub fn fingerprint_expected(&self) -> String {
        self.document.fingerprint_expected.clone()
    }

    /// `INTACT`, `INCOMPLETE` or `INCONCLUSIVE` — the document's own word.
    #[napi(getter)]
    pub fn verdict(&self) -> String {
        self.document.verdict.as_str().to_string()
    }

    /// True when some of the tree was never read, which is what separates
    /// `INCOMPLETE` from `INCONCLUSIVE`.
    #[napi(getter)]
    pub fn partial(&self) -> bool {
        self.document.partial
    }

    /// Every site of the release, in the order the document records them.
    #[napi(getter)]
    pub fn sites(&self) -> Vec<SiteRow> {
        self.document.sites.iter().map(project_row).collect()
    }

    /// Rows the text rendering left out, counted rather than hidden.
    #[napi(getter)]
    pub fn omitted_rows(&self) -> f64 {
        self.document.omitted_rows as f64
    }

    #[napi(getter)]
    pub fn omissions(&self) -> Vec<String> {
        self.document.omissions.clone()
    }

    #[napi(getter)]
    pub fn notes(&self) -> Vec<String> {
        self.document.notes.clone()
    }

    /// Where `save` wrote the underlying `SWP-1-report-v2` copy, when it did.
    #[napi(getter)]
    pub fn report_saved(&self) -> Option<String> {
        self.report_saved.clone()
    }

    /// The §51 boundary, carried inside the document so a forwarded copy cannot
    /// lose it.
    #[napi(getter)]
    pub fn limitations(&self) -> Vec<String> {
        self.document.limitations.clone()
    }

    /// What the tool would suggest next, as sentences in the document.
    #[napi(getter)]
    pub fn next(&self) -> Vec<String> {
        self.document.next.clone()
    }

    /// The code a shell would have got, as data: `0` intact, `5` a site is not
    /// carrying its code, `10` this run could not have said either way.
    #[napi(getter)]
    pub fn exit_code(&self) -> i32 {
        self.document.exit_code
    }

    /// The document as its schema defines it — the same bytes `swp verify
    /// --format json` prints, because this is the same value `swp-evidence`
    /// graded.
    #[napi]
    pub fn to_json(&self, env: &Env) -> Result<String> {
        serde_json::to_string_pretty(&self.document)
            .map(|text| text + "\n")
            .map_err(|e| {
                Failure::from(swp_sdk::SwpError::internal(format!(
                    "document is not serializable: {e}"
                )))
                .into_napi_error(env)
            })
    }

    /// The release, the verdict and the confirmation count — the line a log
    /// carries, while `toJson()` is the document.
    #[napi(js_name = "toString")]
    pub fn to_string_(&self) -> String {
        format!(
            "VerifyOutcome(releaseId='{}', verdict='{}', sitesConfirmed={}/{})",
            self.document.release_id,
            self.document.verdict.as_str(),
            self.document.sites_confirmed,
            self.document.sites_expected,
        )
    }
}

fn project_row(row: &SdkSiteRow) -> SiteRow {
    SiteRow {
        site: row.site as f64,
        file: row.file.clone(),
        line_hint: row.line_hint,
        language: row.language.clone(),
        adapter: row.adapter.clone(),
        class_: row.class.to_string(),
        family: row.family.to_string(),
        width: row.width,
        status: row.status.to_string(),
        confirmed: row.confirmed(),
        slots: row.slots.iter().map(|s| s.to_string()).collect(),
        found_in: row.found_in.clone(),
        found_line: row.found_line,
        refactored: row.refactored,
        moved: row.moved,
    }
}

impl VerifyOutcome {
    pub(crate) fn from_outcome(inner: SdkVerifyOutcome) -> Self {
        VerifyOutcome {
            document: inner.document,
            report_saved: inner.report_saved,
        }
    }
}
