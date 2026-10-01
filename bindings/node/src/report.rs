//! The `SWP-1-report-v2` document, and the saved copies of it.
//!
//! `swp-evidence` owns this document: it grades a detection run, states the
//! evidence level with the numbers that produced it, and carries the §51
//! boundary inside the file so a forwarded report cannot lose it. This module
//! holds that value and reads it. Specifically, it does *not*:
//!
//! * grade evidence, sum confirmations, or compare a probability against a floor;
//! * decide whether a finding is a finding — `result` and `exitCode` are the
//!   document's own;
//! * render text of its own — `toText()` calls `swp-evidence`'s renderer, the
//!   one the CLI prints, so a Node program and a terminal show the same
//!   sentences;
//! * invent an object shape of the document. `toJson()` is the serialization the
//!   schema defines, and `fromJson()` is the reader that refuses a document it
//!   was not written under.
//!
//! Holding the Rust document rather than a copy is what makes the last two
//! true. `result` and `evidenceLevel` come out as the strings a stored report
//! uses (`Outcome::as_str`, `EvidenceLevel::as_str`). `swp-sdk` does not
//! re-export those two Rust enum names — `docs/SDK_API.md` §12 records that as
//! a known gap, not a bug to fix from a binding — and a JavaScript caller needs
//! the words, not the Rust type identity.
//!
//! The same gap shapes how the blocks below are written. `Report` is nameable
//! because `swp-sdk` re-exports it; the types of its `run`, `candidate`,
//! `releases` and `evidence` fields are not, because it does not re-export
//! those. They are still reachable — a field read on an inferred closure
//! argument needs no type name — which is why each projection is written where
//! its argument's type is already known instead of as a free function.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use swp_sdk::{Report, StoredReport};

use crate::error::{guarded, Failure};

/// The whole document, as `swp-evidence` graded it.
#[napi(js_name = "Report")]
#[derive(Clone)]
pub struct JsReport {
    pub(crate) inner: Report,
}

/// One saved report, and where it came from.
#[napi(js_name = "StoredReport")]
#[derive(Clone)]
pub struct JsStoredReport {
    pub(crate) report: JsReport,
    pub(crate) name: String,
    pub(crate) path: String,
}

/// The `run` block: who made this document, and when.
#[napi(object, js_name = "Run")]
#[derive(Clone)]
pub struct JsRun {
    /// `scan`, `verify`, or `report`: the command whose output this is.
    pub command: String,
    /// RFC 3339 UTC, supplied by the caller because this crate takes no clock.
    pub created_at: String,
    /// The build that wrote the document, so an old report can be re-read with
    /// the rules that produced it in hand.
    pub generator: String,
}

/// The `candidate` block: what was looked at, and how completely.
#[napi(object, js_name = "Candidate")]
#[derive(Clone)]
pub struct JsCandidate {
    /// How the input was described on the command line, or where it was staged.
    pub described: String,
    /// `'file'`, `'directory'`, `'zip'`, `'tar'`, `'tar.gz'`, …
    pub kind: String,
    pub files_scanned: u32,
    pub bytes_scanned: f64,
    /// True when something in the candidate was not examined.
    pub partial: bool,
}

/// One release's tally: the strongest match first.
#[napi(object, js_name = "ReleaseTally")]
#[derive(Clone)]
pub struct JsReleaseTally {
    pub project_id: String,
    pub release_id: String,
    /// Keyed sites this release holds.
    pub sites: f64,
    /// Sites whose literal carries this project's code.
    pub fragments: f64,
    /// Sites present as an address without a code.
    pub stripped: f64,
    /// Sites with no matching span.
    pub absent: f64,
    /// Confirmations that are byte-for-byte the recorded rendering.
    pub exact_renderings: f64,
    /// Confirmations reached only through the rename-tolerant radii.
    pub canonical_only: f64,
    /// Confirmations found in a file other than the one we protected.
    pub moved: f64,
    /// Confirmations found as a multi-token rendering.
    pub renderings: f64,
    /// Distinct candidate files holding a confirmation.
    pub files: f64,
    /// Keyed bits carried by the confirmed sites.
    pub bits: u32,
    pub tag_bits: u8,
    /// Spans that reached a tag comparison.
    pub probes: u32,
    /// Distinct keyed codes the candidate presented, summed over sites: the
    /// draws `chance` is computed from.
    pub draws: u32,
    pub literals_tried: f64,
    pub windows_tried: f64,
    /// `'match'`, `'no-match'` or `'not-comparable'`.
    pub fingerprint: String,
    /// `Σ_s [1 − (1 − 2^-tag_bits)^d_s]` over the sites' distinct-code counts:
    /// the upper bound on coincidental confirmations. Printed beside the
    /// verdict, always as the document's own number.
    pub chance: f64,
    /// Confirmations above that bound — the size of the excess. The verdict is
    /// decided by `coincidenceProbability`, not by this.
    pub guarantee: f64,
    /// The probability that an unrelated tree holding these addresses and none
    /// of this project's codes produces `fragments` confirmations or more: the
    /// upper tail of `Poisson(chance)`.
    pub coincidence_probability: f64,
    /// `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
    pub level: String,
    /// The rules that produced `level`, in plain sentences with the numbers in
    /// them.
    pub reasons: Vec<String>,
}

/// One thing a scan observed.
#[napi(object, js_name = "EvidenceItem")]
#[derive(Clone)]
pub struct JsEvidenceItem {
    /// Stable handle for a citation: `EV-001`. Ordering is deterministic.
    pub id: String,
    /// `EXACT_SOURCE_MATCH`, `WATERMARK_FRAGMENT_MATCH`,
    /// `PARTIAL_WATERMARK_MATCH`, `CANONICAL_MATCH`, `STRUCTURAL_MATCH`,
    /// `TOKEN_MATCH`, `NEGATIVE_CONTROL`.
    pub kind: String,
    pub project_id: String,
    pub release_id: String,
    /// Where it was found in the candidate.
    pub location: Option<JsRegion>,
    /// Where the corresponding site was in our protected release. Never a
    /// lookup key, but the line a reviewer opens first.
    pub source_region: Option<JsRegion>,
    /// Why this counts, in words, with the measured numbers in it.
    pub basis: String,
    /// The strength of *this item*, on the same ladder as the overall level.
    pub strength: String,
    pub protocol: String,
    pub schema: u16,
}

/// Where an observation was: a file, a line, and what was seen there.
#[napi(object, js_name = "Region")]
#[derive(Clone)]
pub struct JsRegion {
    /// Project-relative path, forward slashes.
    pub file: String,
    /// One-based line, as the adapter counted it.
    pub line: u32,
    /// The matched text, truncated to the report hint bound. Absent for a
    /// source-side region.
    pub excerpt: Option<String>,
    /// How many tokens the matched span covers.
    pub tokens: Option<u8>,
    /// Which of the release's four keyed radii reproduced this span.
    pub radii: Vec<String>,
}

#[napi]
impl JsReport {
    /// `SWP-1-report-v2`.
    #[napi(getter)]
    pub fn schema(&self) -> String {
        self.inner.schema.clone()
    }

    /// The protocol this build speaks: `SWP-1`.
    #[napi(getter)]
    pub fn protocol(&self) -> String {
        self.inner.protocol.clone()
    }

    #[napi(getter)]
    pub fn run(&self) -> JsRun {
        let inner = &self.inner.run;
        JsRun {
            command: inner.command.clone(),
            created_at: inner.created_at.clone(),
            generator: inner.generator.clone(),
        }
    }

    #[napi(getter)]
    pub fn candidate(&self) -> JsCandidate {
        let inner = &self.inner.candidate;
        JsCandidate {
            described: inner.described.clone(),
            kind: inner.kind.clone(),
            files_scanned: inner.files_scanned,
            bytes_scanned: inner.bytes_scanned as f64,
            partial: inner.partial,
        }
    }

    /// `PROVENANCE_DETECTED`, `NO_PROVENANCE_DETECTED`, `INCONCLUSIVE`.
    #[napi(getter)]
    pub fn result(&self) -> String {
        self.inner.result.as_str().to_string()
    }

    /// The §23 level: `NONE`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
    #[napi(getter)]
    pub fn evidence_level(&self) -> String {
        self.inner.evidence_level.as_str().to_string()
    }

    /// Why that level, one sentence per rule that fired, with the measured
    /// numbers.
    #[napi(getter)]
    pub fn explanation(&self) -> Vec<String> {
        self.inner.explanation.clone()
    }

    /// One entry per release the candidate was scanned against, strongest first.
    #[napi(getter)]
    pub fn releases(&self) -> Vec<JsReleaseTally> {
        self.inner
            .releases
            .iter()
            .map(|tally| JsReleaseTally {
                project_id: tally.project_id.clone(),
                release_id: tally.release_id.clone(),
                sites: tally.sites as f64,
                fragments: tally.fragments as f64,
                stripped: tally.stripped as f64,
                absent: tally.absent as f64,
                exact_renderings: tally.exact_renderings as f64,
                canonical_only: tally.canonical_only as f64,
                moved: tally.moved as f64,
                renderings: tally.renderings as f64,
                files: tally.files as f64,
                bits: tally.bits,
                tag_bits: tally.tag_bits,
                probes: tally.probes,
                draws: tally.draws,
                literals_tried: tally.literals_tried as f64,
                windows_tried: tally.windows_tried as f64,
                fingerprint: tally.fingerprint.clone(),
                chance: tally.chance,
                guarantee: tally.guarantee,
                coincidence_probability: tally.coincidence_probability,
                level: tally.level.as_str().to_string(),
                reasons: tally.reasons.clone(),
            })
            .collect()
    }

    #[napi(getter)]
    pub fn evidence(&self) -> Vec<JsEvidenceItem> {
        self.inner
            .evidence
            .iter()
            .map(|item| JsEvidenceItem {
                id: item.id.clone(),
                kind: item.kind.as_str().to_string(),
                project_id: item.project_id.clone(),
                release_id: item.release_id.clone(),
                location: item.location.as_ref().map(|r| JsRegion {
                    file: r.file.clone(),
                    line: r.line,
                    excerpt: r.excerpt.clone(),
                    tokens: r.tokens,
                    radii: r.radii.clone(),
                }),
                source_region: item.source_region.as_ref().map(|r| JsRegion {
                    file: r.file.clone(),
                    line: r.line,
                    excerpt: r.excerpt.clone(),
                    tokens: r.tokens,
                    radii: r.radii.clone(),
                }),
                basis: item.basis.clone(),
                strength: item.strength.as_str().to_string(),
                protocol: item.protocol.clone(),
                schema: item.schema,
            })
            .collect()
    }

    /// Files the walk refused, with the reason.
    #[napi(getter)]
    pub fn omissions(&self) -> Vec<String> {
        self.inner.omissions.clone()
    }

    /// Caveats: hypothesis caps, widths probed, containers not opened.
    #[napi(getter)]
    pub fn notes(&self) -> Vec<String> {
        self.inner.notes.clone()
    }

    /// The §51 boundary, carried inside the document rather than left to a
    /// README.
    #[napi(getter)]
    pub fn limitations(&self) -> Vec<String> {
        self.inner.limitations.clone()
    }

    /// What `swp scan` exits with: `0` nothing confirmed, `1` something was,
    /// `10` the scan could not have said either way.
    #[napi]
    pub fn exit_code(&self) -> i32 {
        self.inner.exit_code()
    }

    /// Machine-readable form, pretty-printed with a trailing newline,
    /// byte-for-byte the document a saved report holds.
    #[napi]
    pub fn to_json(&self) -> String {
        self.inner.to_json()
    }

    /// The human-facing rendering, the same text `swp scan` prints. `full`
    /// prints every evidence item; without it the list is windowed and the
    /// remainder counted.
    #[napi]
    pub fn to_text(&self, full: Option<bool>) -> String {
        self.inner.to_text(full.unwrap_or(false))
    }

    /// As `toText()`, with the evidence window sized by the caller — which is
    /// what `swp scan --limit <n>` asks for. Only the text is ever windowed.
    #[napi]
    pub fn to_text_items(&self, items: u32) -> String {
        self.inner.to_text_items(items as usize)
    }

    /// Read a stored report back, refusing anything that is not this schema.
    ///
    /// A document from another schema is not damage: it is a record of
    /// arithmetic this build does not apply, and the refusal says so rather than
    /// re-grading it under rules it was not written under.
    #[napi(factory)]
    pub fn from_json(env: &Env, text: String) -> Result<JsReport> {
        let report = guarded(env, || Report::from_json(&text).map_err(Failure::from))?;
        Ok(JsReport::from(report))
    }

    /// The verdict line, and nothing else: this object's whole account is the
    /// document, and a `toString` that tried to list twelve fields would be a
    /// second copy of it in a log.
    #[napi(js_name = "toString")]
    pub fn to_string_(&self) -> String {
        format!(
            "Report(schema='{}', result='{}', evidenceLevel='{}')",
            self.inner.schema,
            self.inner.result.as_str(),
            self.inner.evidence_level.as_str(),
        )
    }
}

#[napi]
impl JsStoredReport {
    /// The document as it was graded. Re-serializing it yields the stored bytes
    /// unchanged, because the report *is* this type.
    #[napi(getter)]
    pub fn report(&self) -> JsReport {
        self.report.clone()
    }

    /// The name `readReport` takes for this document.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Store-relative and forward-slashed.
    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    #[napi(js_name = "toString")]
    pub fn to_string_(&self) -> String {
        format!(
            "StoredReport(name='{}', result='{}', evidenceLevel='{}')",
            self.name,
            self.report.inner.result.as_str(),
            self.report.inner.evidence_level.as_str(),
        )
    }
}

impl From<Report> for JsReport {
    fn from(inner: Report) -> Self {
        JsReport { inner }
    }
}

impl JsStoredReport {
    pub(crate) fn from_stored(inner: StoredReport) -> Self {
        JsStoredReport {
            report: JsReport::from(inner.report),
            name: inner.name,
            path: inner.path,
        }
    }
}
