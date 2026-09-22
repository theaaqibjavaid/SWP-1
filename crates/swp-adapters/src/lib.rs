//! SWP-1 language adapters.
//!
//! This is the only crate in the workspace that knows what source code looks
//! like. Everything above it — site selection, canonicalization, evidence,
//! reporting — speaks the abstract vocabulary in `swp-core`: tokens with kinds
//! and roles, spans, literal values, and named equivalent-form families. That
//! boundary is what makes the protocol language-independent rather than
//! JavaScript-with-a-plug-in.
//!
//! # Three rules this crate exists to enforce
//!
//! 1. **Nothing outside an adapter parses source.** If `swp-embedding` ever
//!    matches on a token spelling like `"function"`, the design has failed. A
//!    new language is added by implementing the trait, not by editing the core.
//! 2. **A transformation is only offered if it round-trips.** Every form family
//!    here is exhaustively tested — every width, every code, every reachable
//!    value shape — and a family that cannot carry *all* the codes at a site's
//!    width is refused for that site rather than used for the subset it happens
//!    to reach. A partially reachable site would be a site whose expected tag
//!    might be unembeddable, and the evidence model cannot count such a hit.
//! 3. **Unsupported means unsupported.** Where no AST adapter exists, the
//!    lexical fallback says so, in the release record and in the report, rather
//!    than reporting the same confidence as a semantic analysis would.
//!
//! A formatter, linter or compiler is never invoked by this crate, or by any
//! part of SWP-1: source is parsed by a library in-process, and the difference
//! between that and running a project's build tooling is the difference between
//! reading a file and executing it.

pub mod adapter;
pub mod analyze;
pub mod dialect;
pub mod forms;
pub mod generic;
pub mod literal;

mod js;
mod py;
mod safety;
mod ts;

pub use adapter::{AstAdapter, Edit, LanguageAdapter, Proof, Registry, ALL_LEVELS};
pub use analyze::{
    AdapterKind, Analysis, CandidateSite, Capabilities, EvidenceStrength, OriginalText, Refusal,
};
pub use dialect::Dialect;
pub use forms::{
    available_number_families, available_string_families, decode_number, decode_string,
    number_family_supports, render_number, render_string, string_family_supports, Decoded,
    DecodedString, StringForm, NUMBER_FAMILIES, STRING_FAMILIES,
};
pub use generic::GenericAdapter;
pub use literal::{DecodedSite, OwnedString, RefusalKind, SiteValue};
