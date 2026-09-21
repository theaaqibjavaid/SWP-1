//! SWP-1 core: the language-independent protocol foundation.
//!
//! Nothing in this crate knows about any programming language's syntax. Language
//! knowledge lives exclusively in `swp-adapters`, which feeds this crate an
//! abstract token stream and receives canonical text and site identities back.

pub mod canon;
pub mod cjson;
pub mod error;
pub mod id;
pub mod limits;
pub mod radius;
pub mod site;
pub mod text;
pub mod version;

pub use canon::{ByteSpan, CanonLevel, CanonicalText, IdentRole, TokKind, Token};
pub use error::{ErrorCode, SwpError, SwpResult};
pub use id::{base32_lower, hex_decode, hex_encode, Digest, LocationId, ProjectId, ReleaseId};
pub use limits::Limits;
pub use radius::{level_for, radius_digest, radius_digests};
pub use site::{FormFamily, LiteralClass, RadiusKind, SiteTag, TagWidth};
pub use text::{canonical_relpath, detect_newline, newlines_to_lf, nfc, strip_bom};
pub use version::{
    CanonicalizerVersion, GeneratorInfo, ProtocolVersion, SchemaVersion, SWP_PROTOCOL_NAME,
};
