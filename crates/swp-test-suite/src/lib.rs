//! Shared harness for the SWP-1 integration suites.
//!
//! The heart of it is [`sweep`]: a search for every way a 32-byte secret can
//! end up looking in a file. It is here, and reused by every later suite,
//! because "we checked for leaks" is only worth anything if the check is one
//! well-reviewed routine rather than a different ad-hoc `grep` per test.

pub mod fixtures;
pub mod locate;
pub mod project;
pub mod sweep;
pub mod tmp;
pub mod transform;

pub use locate::{locate, locate_file, normalize, Flag, Recall, Shape};
pub use project::{Candidate, Project, Release, Run, Verdict};
pub use sweep::{sweep_bytes, sweep_tree, NeedleSet, SweepReport};
pub use tmp::TempDir;
pub use transform::{read_tree, write_tree, SiteText, Transform, Tree};
