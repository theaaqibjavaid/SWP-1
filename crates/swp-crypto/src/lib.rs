//! SWP-1 cryptography. Standard primitives only — HMAC-SHA-256, SHA-256,
//! Ed25519, and the operating system CSPRNG. Nothing here invents a primitive,
//! and nothing here encrypts a watermark: an HMAC is the right tool because the
//! detector needs a pseudorandom value it can recompute, not a secret it can
//! decrypt.
//!
//! Key material is confined to this crate. `RootSecret` and `DerivedKey`
//! redact themselves in `Debug`, implement no `Display`, derive no
//! `Serialize`, and zeroize on drop.

pub mod derive;
pub mod identity;
pub mod random;
pub mod seal;
pub mod secret;
pub mod sign;

pub use derive::{derive_key, hmac_keyed, truncate_bits, Domain, PROTOCOL_LABEL};
pub use identity::project_id_from_root;
pub use random::{random_array, random_vec};
pub use seal::{harden_permissions, plain_requested, PermissionOutcome, Scheme, SealedSecret};
pub use secret::{DerivedKey, PublicKeys, RootSecret, SecretBytes};
pub use sign::{ManifestSigningKey, VerifyingKey};

/// Length of the root secret in bytes (256 bits).
pub const ROOT_SECRET_LEN: usize = 32;
