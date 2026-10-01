//! `swp badge` — a trust anchor badge for a project.
//!
//! A badge is a small signed document that lets a project assert "I am really
//! project X" without revealing the root secret. It carries:
//!
//! * the project's public identity (project id, verify key, display name)
//! * an **anchor key** — derived from the root secret via the Evidence domain
//!   with a "badge" field, so it is provably a function of the secret but not
//!   the secret itself. Anyone who computes the anchor key from a candidate
//!   root secret can check that they hold the right one.
//! * a count of releases and the newest release id
//! * an Ed25519 signature over the whole document, from the project's
//!   manifest signing key
//!
//! The badge is written to `.swp/public/badge.json` and is safe to commit:
//! it carries no private manifest data, no site locations, no literal text.
//! The anchor key is public and is the one thing an external party can use
//! to assert "I know the root secret" without actually revealing it.
//!
//! `swp badge` (no subcommand) generates and writes the badge.
//! `swp badge show` prints the badge document.

use std::path::Path;

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::version::{GeneratorInfo, SWP_PROTOCOL_NAME};
use swp_crypto::{derive::derive_key, Domain};
use swp_identity::ProjectIdentity;
use swp_identity::SWP_DIR;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

/// The field name under which the anchor key is derived, for domain separation.
const ANCHOR_FIELD: &str = "badge";

/// The schema version for the badge document.
pub const BADGE_SCHEMA: &str = "SWP-1-badge-v1";

/// The trust anchor badge document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BadgeDocument {
    pub schema: String,
    pub protocol: String,
    /// The project's identity, embedded verbatim.
    pub project: ProjectIdentity,
    /// The anchor key: derived from the root secret via the Evidence domain
    /// with the "badge" field. Public, non-secret, and a function of the
    /// root secret. Anyone who holds the root secret can recompute it;
    /// anyone who does not, cannot.
    pub anchor_key: String,
    /// How many releases the project has.
    pub release_count: u32,
    /// The newest release id, or `null` if none.
    pub newest_release: Option<String>,
    /// When the badge was generated.
    pub generated_at: String,
    /// The build that generated it.
    pub generator: GeneratorInfo,
    /// Ed25519 signature over the canonical JSON of this document with
    /// `signature` removed.
    pub signature: String,
}

impl BadgeDocument {
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s = serde_json::to_string_pretty(self).expect("badge doc is serializable");
        s.push('\n');
        s.into_bytes()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("badge document is not valid UTF-8"))?;
        let doc: BadgeDocument = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("badge document: {e}")))?;
        if doc.schema != BADGE_SCHEMA {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "badge document declares schema {:?}, this build supports {BADGE_SCHEMA:?}",
                    doc.schema
                ),
            ));
        }
        if doc.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("badge document declares protocol {:?}", doc.protocol),
            ));
        }
        Ok(doc)
    }
}

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    match parsed.positional.first().map(|s| s.as_str()) {
        Some("show") => show(parsed, cwd, sink),
        Some(other) => Err(SwpError::usage(format!(
            "badge: unknown subcommand {other:?}. Use `swp badge` or `swp badge show`."
        ))),
        None => generate(parsed, cwd, sink),
    }
}

fn generate(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }

    let root = project.store.load_root()?;
    let identity = project.identity();
    let project_id_str = identity.project_id.as_str();

    // Derive the anchor key: an Evidence-domain key over the "badge" field,
    // then a second HMAC keyed under that Evidence key over the project id.
    // This keeps the anchor key in a different domain from the site keys,
    // so it cannot be confused with a location id or a tag.
    let evidence_key = derive_key(&root, Domain::Evidence, &[project_id_str.as_bytes()]);
    let anchor_bytes = swp_crypto::derive::hmac_keyed(
        &evidence_key,
        Domain::Evidence,
        &[ANCHOR_FIELD.as_bytes(), project_id_str.as_bytes()],
    )?;
    let anchor_b32 = swp_core::id::base32_lower(&anchor_bytes);

    let releases = project.session.release_history()?;
    let newest = releases.last().map(|r| r.release_id.as_str().to_string());

    let at = swp_identity::Timestamp::now_utc();
    let doc_unsigned = BadgeDocument {
        schema: BADGE_SCHEMA.to_string(),
        protocol: SWP_PROTOCOL_NAME.to_string(),
        project: identity.clone(),
        anchor_key: anchor_b32,
        release_count: releases.len() as u32,
        newest_release: newest,
        generated_at: at.to_rfc3339(),
        generator: GeneratorInfo::current(),
        signature: String::new(),
    };

    let signing_key = project.signing_key()?;
    let sig = swp_manifest::sig::sign_json_document(&doc_unsigned, &signing_key)?;
    let mut doc = doc_unsigned;
    doc.signature = sig;

    let out_path = project
        .root()
        .join(SWP_DIR)
        .join("public")
        .join("badge.json");
    std::fs::write(&out_path, doc.to_json_bytes())
        .map_err(|e| SwpError::io(format!("cannot write badge: {e}")))?;

    if parsed.verbose() {
        sink.note(&format!("badge written to {}", out_path.display()));
    }

    let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
    let lines = vec![text];
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

fn show(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    let path = project
        .root()
        .join(SWP_DIR)
        .join("public")
        .join("badge.json");
    if !path.is_file() {
        return Err(SwpError::new(
            ErrorCode::NotProtected,
            "no badge.json in this project. Run `swp badge` first to generate it.",
        ));
    }
    let bytes =
        std::fs::read(&path).map_err(|e| SwpError::io(format!("cannot read badge: {e}")))?;
    let doc = BadgeDocument::from_json_bytes(&bytes)?;

    let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
    let lines = vec![text];
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn badge_generation_writes_a_valid_document() {
        let dir = Scratch::protected("badge", "generate");
        let r = dir.run(&["badge"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let path = dir.root.join(".swp/public/badge.json");
        assert!(
            path.is_file(),
            "badge.json was not written: {}",
            path.display()
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        let doc = BadgeDocument::from_json_bytes(on_disk.as_bytes()).unwrap();
        assert_eq!(doc.schema, BADGE_SCHEMA);
        assert_eq!(doc.protocol, "SWP-1");
        assert_eq!(doc.project.project_id.to_string(), dir.project_id());
        assert_eq!(doc.release_count, 1);
        assert!(doc.newest_release.is_some());
        assert!(!doc.anchor_key.is_empty());
        assert!(!doc.signature.is_empty());
    }

    #[test]
    fn badge_show_reads_the_generated_file() {
        let dir = Scratch::protected("badge", "show");
        let r = dir.run(&["badge"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let r2 = dir.run(&["badge", "show", "--format", "json"]);
        assert_eq!(r2.code, 0, "{}{}", r2.out, r2.err);
        let doc = r2.json();
        assert_eq!(doc["schema"], BADGE_SCHEMA);
        assert_eq!(doc["project"]["project_id"], dir.project_id());
    }

    #[test]
    fn badge_show_fails_when_no_badge_exists() {
        let dir = Scratch::protected("badge", "no-badge");
        let r = dir.run(&["badge", "show"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("Run `swp badge`"), "{}", r.err);
    }

    #[test]
    fn badge_anchor_key_is_deterministic_across_runs() {
        let dir = Scratch::protected("badge", "deterministic");
        let r1 = dir.run(&["badge"]);
        assert_eq!(r1.code, 0, "{}", r1.err);
        let doc1: BadgeDocument = {
            let bytes = std::fs::read(dir.root.join(".swp/public/badge.json")).unwrap();
            BadgeDocument::from_json_bytes(&bytes).unwrap()
        };
        assert!(!doc1.anchor_key.is_empty());
        let r2 = dir.run(&["badge"]);
        assert_eq!(r2.code, 0, "{}", r2.err);
        let doc2: BadgeDocument = {
            let bytes = std::fs::read(dir.root.join(".swp/public/badge.json")).unwrap();
            BadgeDocument::from_json_bytes(&bytes).unwrap()
        };
        assert_eq!(
            doc1.anchor_key, doc2.anchor_key,
            "the anchor key must be a pure function of the root secret and project id"
        );
    }

    #[test]
    fn badge_without_a_project_fails_cleanly() {
        let dir = Scratch::new("badge", "noproject");
        let r = dir.run(&["badge"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("swp init"), "{}", r.err);
    }

    #[test]
    fn badge_release_count_matches_the_store() {
        let dir = Scratch::protected("badge", "count");
        let store = dir.store();
        let n = store.releases().unwrap().len();
        let r = dir.run(&["badge"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let doc: BadgeDocument = {
            let bytes = std::fs::read(dir.root.join(".swp/public/badge.json")).unwrap();
            BadgeDocument::from_json_bytes(&bytes).unwrap()
        };
        assert_eq!(
            doc.release_count, n as u32,
            "release_count must match the store"
        );
    }
}
