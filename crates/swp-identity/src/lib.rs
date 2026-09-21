//! SWP-1 identity: who a protected project is, which releases of it exist, and
//! where the tool keeps that information on disk.
//!
//! Three rules shape this crate:
//!
//! 1. **The project id is derived, not chosen.** It is a keyed truncation of the
//!    root secret, so it is stable for the life of the secret, unpredictable to
//!    anyone holding only the source, and different per project. It is public:
//!    it appears in signed manifests and scan reports. Knowing it buys an
//!    attacker nothing, because every fragment tag sits behind a derivation the
//!    id alone cannot reach.
//! 2. **Public and private are separated by path, not by discipline.**
//!    Everything under `.swp/public/` is safe to commit and is signed.
//!    Everything under `.swp/private/` holds keyed site data, is created with
//!    verified tightened permissions, and is gitignored. The split is enforced
//!    by the accessor that produces each path, and a test asserts the two trees
//!    are disjoint siblings.
//! 3. **Nothing here can print a secret.** Key material enters as a borrowed
//!    `RootSecret`, is compared through `same_as`, and is dropped. There is no
//!    code path in this crate that turns a secret into a string.

pub mod config;
pub mod project;
pub mod release;
pub mod store;
pub mod timestamp;

pub use config::{
    ProtectConfig, SwpConfig, DEFAULT_EXCLUDES, DEFAULT_TARGET_SITES, MAX_TARGET_SITES,
    MIN_TARGET_SITES,
};
pub use project::ProjectIdentity;
pub use release::{new_release_id, AdapterUse, ReleaseRecord, SourceRevision, WatermarkParams};
pub use store::{Store, StoreInit};
pub use timestamp::Timestamp;

/// Directory names inside a protected project.
pub const SWP_DIR: &str = ".swp";
pub const PUBLIC_DIR: &str = "public";
pub const PRIVATE_DIR: &str = "private";
pub const RELEASES_DIR: &str = "releases";
pub const MANIFESTS_DIR: &str = "manifests";
pub const PLANS_DIR: &str = "plans";
pub const REPORTS_DIR: &str = "reports";
pub const IDENTITY_FILE: &str = "identity.json";
pub const ROOT_KEY_FILE: &str = "root.key";
pub const CONFIG_FILE: &str = "config.toml";

/// Lines written into the project's `.gitignore` so a private store cannot be
/// committed by accident.
pub const GITIGNORE_MARKER: &str = "# SWP-1 private provenance data (never commit)";
pub const GITIGNORE_ENTRY: &str = ".swp/private/";
