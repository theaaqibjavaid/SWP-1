//! SWP-1 embedding: turning a project's source into a protected release.
//!
//! Five passes, in this order, each in its own module — because each one is
//! allowed to know less than the run needs, and that is what makes the whole thing
//! auditable.
//!
//! ```text
//! walk::walk         which files exist, and which the walk refused
//! candidates::scan   which literals could carry a fragment, and their four keys
//! select::select     which of those this release uses, in keyed order
//! apply::apply       rewrite them, and prove each rewrite before keeping it
//! protect::protect   the records that describe the result, and the write order
//! ```
//!
//! Four rules hold the passes apart:
//!
//! 1. **Nothing is embedded until it is proved.** [`apply`] re-analyzes each
//!    chosen file, decodes the new literal back to the value it must still mean,
//!    re-canonicalizes both radii, and recomputes the four location ids. A site
//!    that fails any of those is dropped and recorded as dropped. §11's "skip, do
//!    not force" is enforced there, not promised here.
//! 2. **No filesystem write before the last pass.** The four earlier passes read
//!    and return values; only [`protect`] touches disk, and it writes the `.swp/`
//!    records before the sources they describe, so an interrupted run leaves an
//!    honest `swp verify` result rather than unrecoverable source.
//! 3. **Selection is keyed, not ordered by the tree.** Each candidate's priority
//!    is a keyed hash of its own location ids, so adding a file elsewhere in the
//!    project cannot change which sites this run picks, and two runs over an
//!    unchanged tree pick the same ones. The number of sites is the project's
//!    [`swp_identity::ProtectConfig::target_sites`] capped by the resource limits,
//!    never a constant.
//! 4. **A plan holds no secrets and no tags.** [`Plan`] records where sites went
//!    and why others were refused, so the intent of a run survives a crash and can
//!    be reviewed before it is applied; it deliberately cannot be used to
//!    recompute a watermark, and neither can [`Protection`].

pub mod apply;
pub mod candidates;
pub mod plan;
pub mod protect;
pub mod select;
pub mod walk;

pub use plan::Plan;
pub use protect::{protect, FileChange, Mode, Protection, Request, FINGERPRINT_LEVEL};
pub use select::Selection;
pub use walk::Walk;
