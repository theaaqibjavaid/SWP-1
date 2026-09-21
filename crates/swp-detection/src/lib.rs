//! SWP-1 detection: read a candidate tree and say what of it is accounted for.
//!
//! This crate is the other half of the protocol. [`swp_embedding`] writes a
//! manifest that says which keyed locations a release used and what literal each
//! one carries; detection answers the only question a provenance tool can
//! actually answer about a tree it does not own: *how much of that manifest is
//! present here?*
//!
//! ## The §20 pipeline, and where each step lives
//!
//! ```text
//! input            input::open          — file | directory | archive | package
//! project detection input (same)        — the walk decides what is source
//! language detection swp-adapters       — extension and grammar
//! canonicalization  swp-core::canon     — the L1/L3 levels behind every digest
//! exact matching    find::Detection     — the release fingerprint
//! structural matching find::SiteMatch    — which of the four radius keys hit
//! watermark detection find::confirm      — does the literal carry its code
//! evidence aggregation swp-evidence     — this crate's output is its input
//! report             swp-cli             — rendered from the evidence
//! ```
//!
//! ## Why nothing here reads a file name
//!
//! A location id is an HMAC over the canonical text *around* a literal, keyed by
//! the project, and it deliberately excludes the path (`swp-manifest` rule 3). So
//! a copy that was moved, renamed, or put inside a directory prefix still matches,
//! and a report that keyed on paths would be a claim about file layout rather than
//! about provenance. The manifest's `file` and `line_hint` fields appear in the
//! output only as "where this site was in *our* release", never as a lookup key —
//! and there is a test that renames a whole tree to prove the finding is unchanged.
//!
//! ## Why a tag, and not a location, is the evidence
//!
//! The four keys are content addresses, and content addresses match content: an
//! unprotected copy of the same source hits the same location ids while carrying
//! no watermark at all. So a location hit on its own is reported as the *structural*
//! channel, which is corroborating and explicitly not proof, and only
//! [`find::SiteMatch::confirmed`] — "this literal decodes, under the family the
//! manifest names, to the code this project's key derives for this location" —
//! counts as a watermark hit. The distinction is the reason §23's levels are
//! deterministic rather than a probability: the coincidence rate of a 4-bit code
//! is known exactly (2^-4 per candidate the address admits), while "how likely is
//! it that a stranger wrote this statement" is not a quantity anyone here has a
//! defensible model for.
//!
//! ## What detection must never do
//!
//! It never executes, builds, installs or imports a candidate (§21) — no process is
//! spawned anywhere in this crate, and `input` refuses to even follow a symlink out
//! of an archive. It never asks the candidate's own `.swp` directory anything: a
//! copy may contain another project's artifacts, and treating attacker content as
//! configuration would let the scanned tree decide how it is judged.
//!
//! It never stores or prints the root secret, a derived key, or an expected tag.
//! Expected tags are recomputed per site by [`find`] and dropped as soon as a
//! comparison is made, because a report that quoted them would be a copy of the
//! watermark (§29 has the tests that hold that line).

pub mod find;
pub mod index;
pub mod input;
pub mod spans;

pub use find::{
    scan_against, Detection, FingerprintCheck, ReleaseDetection, SiteMatch, SiteStatus,
    SLOT_COUNT,
};
pub use index::{build_indexes, CandidateRelease, LocationHit, ReleaseIndex};
pub use input::{open, InputKind, Opened};
pub use spans::{form_windows, Window, MAX_FORM_TOKENS, MAX_WINDOWS_PER_FILE};
