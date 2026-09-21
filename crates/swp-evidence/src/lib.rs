//! SWP-1 evidence: what a scan observed, how strong that is, and what to print.
//!
//! This crate sits between [`swp_detection`] and the CLI, and it exists because the
//! two questions asked there are different. Detection answers "is this keyed address
//! present, and does the literal there carry the code?" — a mechanical question with
//! a mechanical answer. A person reading a scan result is asking something else: *how
//! much of this project is in that tree, how sure can I be, and why do you say so?*
//! §22 forbids answering the second question with the word `MATCH`, and this crate is
//! the answer: seven typed evidence categories, five deterministic levels, and a
//! versioned report that carries the rule that fired alongside the numbers it fired
//! on.
//!
//! ## The two channels, kept apart all the way to the page
//!
//! ```text
//! detection               evidence                report
//! SiteStatus::Absent   -> (nothing)            -> counted in `sites - fragments`
//! SiteStatus::LocationOnly -> STRUCTURAL_MATCH -> tally.stripped, never graded
//! SiteStatus::TagConfirmed -> WATERMARK_FRAGMENT_MATCH,
//!                              + TOKEN_MATCH / CANONICAL_MATCH as channels
//! SiteStatus::ExactRendering -> the above, stated as the recorded rendering
//! FingerprintCheck::Matched -> EXACT_SOURCE_MATCH -> VERY_STRONG
//! ```
//!
//! The structural channel is the one that must not leak into a level. A location id
//! is a content address computed from canonicalized source, so an unprotected copy of
//! the same statement reproduces it exactly while carrying no watermark at all — which
//! is a fact about the copy, not an accusation about the copier. [`item::EvidenceKind::asserts_provenance`]
//! is where that line is written down, and the ladder in [`level`] reads sites, not
//! items, so one statement observed through three channels cannot count as three
//! statements.
//!
//! ## Why there is no percentage anywhere in this crate
//!
//! §23 allows a probabilistic claim only with a validated model, and there isn't one
//! for "how likely is it that a stranger wrote this". What *is* defensible is the
//! coincidence bound over the comparisons the scan actually performed: each site an
//! unrelated tree reproduced the address for confirms by chance with probability
//! `1 − (1 − 2^-width)^spans`, and those per-site probabilities sum to the bound
//! ([`level::chance_of_coincidence`]). `width` is the tag width the release recorded
//! and `spans` counts the candidate spans that reached its tag comparison. The
//! assumption-free version, `spans × 2^-width` ([`level::union_bound_of_coincidence`]),
//! is printed next to it. Both numbers go in the report, and so does the sentence
//! explaining that they bound chance and say nothing about intent.
//!
//! ## Secrets
//!
//! Nothing in this crate can hold key material: it consumes [`Detection`], whose
//! `SiteMatch` values carry paths, line numbers, widths, families and truncated text
//! hints and no tags or keys, and it emits strings built from those. The leak sweep in
//! `swp-test-suite` asserts the resulting JSON and text contain no root secret, no
//! derived key, and no expected tag for the artifacts a real protection run produced
//! (§29).

pub mod item;
pub mod level;
pub mod report;

pub use item::{collect, EvidenceItem, EvidenceKind, Region};
pub use level::{
    assess, chance_of_coincidence, partial_level, union_bound_of_coincidence, Assessment,
    EvidenceLevel, Outcome, ReleaseTally,
    MODERATE_MIN_FRAGMENTS, STRONG_MIN_FRAGMENTS, STRONG_SOLO_MIN_FRAGMENTS, VERY_STRONG_MIN_FILES,
    VERY_STRONG_MIN_FRAGMENTS,
};
pub use report::{kind_counts, Candidate, Report, Run, REPORT_SCHEMA, TEXT_EVIDENCE_ITEMS};
