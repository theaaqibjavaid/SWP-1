//! `swp badge` — one signed page about the project.
//!
//! The badge is a small JSON document a project owner writes when they want to
//! point someone at the basics without handing over the store: which project
//! this is, how many releases it has, and what the newest one is. It is signed
//! with the project's own manifest key, so the page cannot be edited after
//! publication.
//!
//! ## What it is not
//!
//! It is not a trust anchor. An earlier draft of this command put an "anchor
//! key" in the file — a value derived from the root secret, offered as proof
//! that the bearer knew that secret. That is exactly the thing §18 keeps out of
//! a committable document: a key-derived value published under `.swp/public/`
//! gives a holder of the file a target to mount an offline search against, and
//! it cannot be taken back once it is in history. The field is gone, and with
//! it the only use of the `Evidence` derivation domain, which is reserved
//! again.
//!
//! SPEC 16 defines no way for one project to vouch for another, so the badge
//! creates no cross-project channel either. It is a publisher's own document:
//! it authenticates its own contents, and `swp badge show` compares those
//! contents against the identity in the store it was read from.
//!
//! `swp badge` (no subcommand) regenerates and writes the badge.
//! `swp badge show` reads it back, authenticates it, and prints it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::version::{GeneratorInfo, SWP_PROTOCOL_NAME};
use swp_crypto::VerifyingKey;
use swp_identity::ProjectIdentity;

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

/// The schema version for the badge document.
pub const BADGE_SCHEMA: &str = "SWP-1-badge-v1";

/// The trust badge document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BadgeDocument {
    pub schema: String,
    pub protocol: String,
    /// The project's public identity, embedded verbatim.
    pub project: ProjectIdentity,
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

    /// Read, validate and authenticate a badge document from JSON bytes.
    ///
    /// Authentication is part of reading, not an optional extra: a document whose
    /// release count or newest release id was edited after signing must fail here
    /// rather than reach a reader that prints it.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("badge document is not valid UTF-8"))?;
        let doc: BadgeDocument = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("badge document: {e}")))?;
        doc.validate()?;
        doc.verify_signature()?;
        Ok(doc)
    }

    pub fn validate(&self) -> Result<(), SwpError> {
        if self.schema != BADGE_SCHEMA {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "badge document declares schema {:?}, this build supports {BADGE_SCHEMA:?}",
                    self.schema
                ),
            ));
        }
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("badge document declares protocol {:?}", self.protocol),
            ));
        }
        self.project.validate()?;
        Ok(())
    }

    /// Check this document's signature against the verify key the embedded
    /// identity publishes.
    ///
    /// What that establishes, stated exactly: these are the bytes some holder of
    /// a manifest signing key chose to sign. It does not say whose key — the
    /// document names the key's owner itself, and a signature cannot corroborate
    /// a claim its own signed bytes are the only source of. `show` settles that
    /// by comparing the embedded identity with the store the file came out of.
    pub fn verify_signature(&self) -> Result<(), SwpError> {
        if self.signature.is_empty() {
            return Err(SwpError::invalid_manifest(
                "badge document is unsigned: no publisher's key attests to the claims in it",
            ));
        }
        let key = VerifyingKey::from_public_keys(&self.project.verification)?;
        swp_manifest::sig::verify_json_document(self, &self.signature, &key)
            .map_err(|e| SwpError::new(e.code(), format!("badge document: {}", e.message())))
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

    let identity = project.identity().clone();
    let releases = project.session.release_history()?;
    let newest = releases.last().map(|r| r.release_id.as_str().to_string());

    let at = swp_identity::Timestamp::now_utc();
    let doc_unsigned = BadgeDocument {
        schema: BADGE_SCHEMA.to_string(),
        protocol: SWP_PROTOCOL_NAME.to_string(),
        project: identity,
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

    project.store.write_badge(&doc.to_json_bytes())?;

    if parsed.verbose() {
        sink.note(&format!(
            "badge written to {}",
            project.store.badge_path().display()
        ));
    }

    let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
    let lines = vec![text];
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

fn show(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let path = project.store.badge_path();
    if !path.is_file() {
        return Err(SwpError::new(
            ErrorCode::NotProtected,
            "no badge.json in this project. Run `swp badge` first to generate it.",
        )
        .with_next(
            "The project is protected and has no badge yet, which is a missing file rather \
             than an unprotected tree. Run `swp badge`; it signs `.swp/public/badge.json` \
             from this store's identity, so it needs the root secret.",
        ));
    }
    let bytes =
        std::fs::read(&path).map_err(|e| SwpError::io(format!("cannot read badge: {e}")))?;
    let doc = BadgeDocument::from_json_bytes(&bytes)?;

    // The signature says a manifest key signed these bytes; the store says which
    // project that key belongs to. Without this comparison a badge copied out of
    // another project would print here as if it described this one.
    let identity = project.identity();
    if identity.project_id != doc.project.project_id {
        return Err(SwpError::invalid_manifest(format!(
            "this badge is for project {}, but the project here is {} — it was written by \
             someone else, so nothing in it describes this tree",
            doc.project.project_id, identity.project_id
        ))
        .with_next(
            "The badge is signed and intact; it simply is not yours. `swp badge` writes one \
             from this store's identity and release count.",
        ));
    }
    if identity.verification != doc.project.verification {
        return Err(SwpError::invalid_manifest(format!(
            "badge for {} carries a verify key that is not this project's own",
            doc.project.project_id
        ))
        .with_next(
            "The badge claims this project's identity and was signed against a different key, \
             so either the badge or `.swp/public/identity.json` was replaced since it was \
             written. Compare both against version control before regenerating either; \
             `swp badge` would overwrite the evidence.",
        ));
    }
    if parsed.verbose() {
        sink.note(&format!(
            "badge for {} authenticated and matched to this project's identity",
            doc.project.project_id
        ));
    }

    let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
    let lines = vec![text];
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    fn written(dir: &Scratch) -> BadgeDocument {
        let bytes = std::fs::read(dir.store().badge_path()).unwrap();
        BadgeDocument::from_json_bytes(&bytes).unwrap()
    }

    #[test]
    fn badge_generation_writes_a_valid_document() {
        let dir = Scratch::protected("badge", "generate");
        let r = dir.run(&["badge"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let path = dir.store().badge_path();
        assert!(
            path.is_file(),
            "badge.json was not written: {}",
            path.display()
        );
        let doc = written(&dir);
        assert_eq!(doc.schema, BADGE_SCHEMA);
        assert_eq!(doc.protocol, "SWP-1");
        assert_eq!(doc.project.project_id.to_string(), dir.project_id());
        assert_eq!(doc.release_count, 1);
        assert!(doc.newest_release.is_some());
        assert!(!doc.signature.is_empty());
    }

    #[test]
    fn a_badge_holds_only_the_fields_the_format_declares() {
        // The document used to carry an "anchor_key" derived from the root
        // secret. A committable public file must not hold key-derived material,
        // so the field list is asserted here rather than left to the struct:
        // re-adding any such field fails this test.
        let dir = Scratch::protected("badge", "fields");
        assert_eq!(dir.run(&["badge"]).code, 0);
        let text = std::fs::read_to_string(dir.store().badge_path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut keys: Vec<String> = value
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.to_string())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "generated_at",
                "generator",
                "newest_release",
                "project",
                "protocol",
                "release_count",
                "schema",
                "signature",
            ]
        );
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
    fn badge_show_reads_a_store_whose_root_key_is_absent() {
        // The badge is the public half of the store summarised, so an auditor with
        // a copied `public/` directory must be able to read it. `swp badge` needed
        // the key to sign; `swp badge show` needs the key in `identity.json`, which
        // is not a secret.
        let dir = Scratch::protected("badge", "show-no-key");
        assert_eq!(dir.run(&["badge"]).code, 0, "badge generation failed");
        std::fs::remove_file(dir.store().root_key_path()).unwrap();
        let r = dir.run(&["badge", "show", "--format", "json"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert_eq!(r.json()["schema"], BADGE_SCHEMA);
    }

    #[test]
    fn badge_show_fails_when_no_badge_exists() {
        let dir = Scratch::protected("badge", "no-badge");
        let r = dir.run(&["badge", "show"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("Run `swp badge`"), "{}", r.err);
        // The store here is protected and what is missing is one file in it. The
        // code's default advice sends the reader back to `swp init`, which would
        // refuse a store that already exists.
        assert!(
            !r.err.contains("swp init"),
            "the advice tells a protected project to initialise itself: {}",
            r.err
        );
    }

    #[test]
    fn an_unsigned_badge_is_refused() {
        let dir = Scratch::protected("badge", "unsigned");
        assert_eq!(dir.run(&["badge"]).code, 0);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.store().badge_path()).unwrap())
                .unwrap();
        value["signature"] = serde_json::Value::String(String::new());
        std::fs::write(
            dir.store().badge_path(),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
        let r = dir.run(&["badge", "show"]);
        assert_eq!(
            r.code,
            ErrorCode::InvalidManifest.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        assert!(r.err.contains("unsigned"), "{}", r.err);
    }

    #[test]
    fn an_edited_claim_in_a_signed_badge_is_refused() {
        let dir = Scratch::protected("badge", "edited");
        assert_eq!(dir.run(&["badge"]).code, 0);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.store().badge_path()).unwrap())
                .unwrap();
        value["release_count"] = serde_json::json!(99);
        std::fs::write(
            dir.store().badge_path(),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
        let r = dir.run(&["badge", "show"]);
        assert_eq!(
            r.code,
            ErrorCode::InvalidManifest.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        assert!(r.err.contains("does not verify"), "{}", r.err);
    }

    #[test]
    fn a_badge_copied_from_another_project_is_refused_here() {
        // A whole-document copy carries a valid signature, so the signature check
        // alone cannot catch it. The identity comparison is the check that does.
        let owner = Scratch::protected("badge", "copy-owner");
        let other = Scratch::protected_variant("badge", "copy-other", 1);
        assert_eq!(owner.run(&["badge"]).code, 0);
        let bytes = std::fs::read(owner.store().badge_path()).unwrap();
        std::fs::write(other.store().badge_path(), &bytes).unwrap();
        let r = other.run(&["badge", "show"]);
        assert_eq!(
            r.code,
            ErrorCode::InvalidManifest.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        assert!(r.err.contains("written by someone else"), "{}", r.err);
        assert!(r.err.contains(&other.project_id().to_string()), "{}", r.err);
        assert!(
            r.err.contains("next: The badge is signed and intact")
                && r.err.contains("`swp badge` writes one"),
            "the advice names this badge's own move: {}",
            r.err
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
        let n = dir.store().releases().unwrap().len();
        assert_eq!(dir.run(&["badge"]).code, 0);
        let doc = written(&dir);
        assert_eq!(
            doc.release_count, n as u32,
            "release_count must match the store"
        );
    }

    #[test]
    fn the_badge_is_listed_in_the_store_inventory() {
        // `swp inspect store` is the artifact list SECURITY.md points at, so a
        // file the tool writes has to appear in it once it exists.
        let dir = Scratch::protected("badge", "inventory");
        let before = dir.store().inventory().unwrap();
        assert!(!before.iter().any(|(p, _)| p.ends_with("badge.json")));
        assert_eq!(dir.run(&["badge"]).code, 0);
        let after = dir.store().inventory().unwrap();
        assert!(
            after
                .iter()
                .any(|(p, public)| p.ends_with("badge.json") && *public),
            "badge.json missing from the inventory: {after:?}"
        );
    }
}
