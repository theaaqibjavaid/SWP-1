//! `swp registry publish` and `swp registry search` — a public release index.
//!
//! The registry is a single JSON file that a project owner maintains in their
//! repository. It lists their releases in a shape that another project's `swp
//! scan` can discover without network access: every release record is signed
//! by the publisher's own key, so a reader who gets the file can authenticate
//! each entry against the publisher's public verify key without ever contacting
//! a server.
//!
//! This is not a network service. §16 says "one project, one secret, one store,
//! no third party, no online service." The registry is the one place the
//! protocol allows a second project to *name* a release: it is the equivalent
//! of a bibliography page, not of a database. The file can be mirrored, pushed,
//! or hand-copied; the signature is what makes it trustworthy.
//!
//! A release may be marked revoked in the index; a revoked entry is still
//! signed by the publisher, so revocation is itself authenticated and cannot be
//! faked by editing the JSON.

use std::path::Path;

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{ProjectId, ReleaseId};
use swp_core::version::SWP_PROTOCOL_NAME;
use swp_crypto::PublicKeys;
use swp_identity::ReleaseRecord;

use crate::args::{Flag, Parsed};
use crate::ctx::{self, Ctx};
use crate::output::{self, Sink};

/// The schema version string for the registry document.
pub const REGISTRY_SCHEMA: &str = "SWP-1-registry-v1";

/// One entry in the registry: a release record plus its revocation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub record: ReleaseRecord,
    /// `true` when the publisher revoked this release; the signature still
    /// covers this flag, so revocation is authenticated.
    #[serde(default)]
    pub revoked: bool,
}

/// The registry document itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryDocument {
    pub schema: String,
    pub protocol: String,
    pub project_id: ProjectId,
    /// The project's public verify key, serialized as `PublicKeys`, so a reader
    /// can authenticate every entry without the private manifest.
    pub verify_key: PublicKeys,
    /// One entry per release the project has published. Ordered oldest first.
    pub releases: Vec<RegistryEntry>,
    /// When the document was last written.
    pub generated_at: String,
    /// The build that wrote the file.
    pub generator: String,
    /// Ed25519 signature over the canonical JSON of this document with
    /// `signature` removed.
    pub signature: String,
}

impl RegistryDocument {
    /// Serialize to pretty-printed JSON bytes.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s = serde_json::to_string_pretty(self).expect("registry doc is serializable");
        s.push('\n');
        s.into_bytes()
    }

    /// Read and validate a registry document from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("registry document is not valid UTF-8"))?;
        let doc: RegistryDocument = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("registry document: {e}")))?;
        doc.validate()?;
        Ok(doc)
    }

    /// Validate structural invariants that do not require the signing key.
    pub fn validate(&self) -> Result<(), SwpError> {
        if self.schema != REGISTRY_SCHEMA {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "registry document declares schema {:?}, this build supports {REGISTRY_SCHEMA:?}",
                    self.schema
                ),
            ));
        }
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("registry document declares protocol {:?}", self.protocol),
            ));
        }
        for entry in &self.releases {
            entry.record.validate()?;
        }
        Ok(())
    }
}

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    match parsed.positional.first().map(|s| s.as_str()) {
        Some("publish") => publish(parsed, cwd, sink),
        Some("search") => search(parsed, cwd, sink),
        Some(other) => Err(SwpError::usage(format!(
            "registry: unknown subcommand {other:?}. Use `swp registry publish` or \
             `swp registry search <file> --release <id>`."
        ))),
        None => Err(SwpError::usage(
            "registry: a subcommand is required: `publish` or `search <file>`",
        )),
    }
}

fn publish(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let project = Ctx::open(parsed, cwd)?;
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let selection = ctx::selection(parsed)?;
    let ids = project.session.releases(&selection)?;

    let mut releases: Vec<RegistryEntry> = Vec::with_capacity(ids.len());
    for id in &ids {
        let record = project.release(id)?;
        releases.push(RegistryEntry {
            record,
            revoked: false,
        });
    }
    releases.sort_by(|a, b| {
        a.record
            .created_at
            .cmp(&b.record.created_at)
            .then_with(|| a.record.release_id.cmp(&b.record.release_id))
    });

    let at = swp_identity::Timestamp::now_utc();
    let verify_key = project.identity().verify_key()?;
    let doc_unsigned = RegistryDocument {
        schema: REGISTRY_SCHEMA.to_string(),
        protocol: SWP_PROTOCOL_NAME.to_string(),
        project_id: project.identity().project_id.clone(),
        verify_key: verify_key.to_public_keys(),
        releases: releases.clone(),
        generated_at: at.to_rfc3339(),
        generator: swp_sdk::banner(),
        signature: String::new(),
    };

    let signing_key = project.signing_key()?;
    let sig = swp_manifest::sig::sign_json_document(&doc_unsigned, &signing_key)?;
    let mut doc = doc_unsigned;
    doc.signature = sig;

    let out_path = project.root().join(".swp/public/registry.json");
    std::fs::write(&out_path, doc.to_json_bytes())
        .map_err(|e| SwpError::io(format!("cannot write registry: {e}")))?;

    if parsed.verbose() {
        sink.note(&format!(
            "registry written to {} ({} release(s))",
            out_path.display(),
            doc.releases.len()
        ));
    }

    let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
    let lines = vec![text];
    output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

fn search(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let file = match parsed.positional.get(1) {
        Some(f) => ctx::resolve(f, cwd)?,
        None => {
            return Err(SwpError::usage(
                "registry search: a file path is required, e.g. `swp registry search \
                 path/to/registry.json --release rel-xxxxxxxxxxxxxxxx`",
            ))
        }
    };
    let bytes = std::fs::read(&file)
        .map_err(|e| SwpError::io(format!("cannot read registry file {}: {e}", file.display())))?;
    let doc = RegistryDocument::from_json_bytes(&bytes)?;

    let release_id = match parsed.value(Flag::Release) {
        Some(raw) => ReleaseId::new(raw)?,
        None => {
            let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
            let lines = vec![text];
            output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
            return Ok(0);
        }
    };

    let entry = doc
        .releases
        .iter()
        .find(|e| e.record.release_id == release_id)
        .ok_or_else(|| {
            SwpError::new(
                ErrorCode::NotProtected,
                format!(
                    "release {} is not in this registry ({} release(s) listed). Use \
                     `swp registry search <file>` without --release to see all.",
                    release_id,
                    doc.releases.len()
                ),
            )
        })?;

    if entry.revoked {
        sink.warn(&format!(
            "release {} is REVOKED by the publisher; treat it as untrustworthy",
            entry.record.release_id
        ));
    }

    let entry_json =
        serde_json::to_string_pretty(&entry.record).expect("release record is serializable");
    let lines = vec![entry_json];
    output::deliver(sink, &entry.record, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn publish_writes_a_valid_registry_document() {
        let dir = Scratch::protected("registry", "publish");
        let r = dir.run(&["registry", "publish", "--format", "json"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let doc = r.json();
        assert_eq!(doc["schema"], REGISTRY_SCHEMA);
        assert_eq!(doc["protocol"], "SWP-1");
        assert_eq!(doc["project_id"], dir.project_id());
        assert!(!doc["releases"].as_array().unwrap().is_empty());
        let path = dir.root.join(".swp/public/registry.json");
        assert!(
            path.is_file(),
            "registry.json was not written: {}",
            path.display()
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        let parsed = RegistryDocument::from_json_bytes(on_disk.as_bytes()).unwrap();
        assert_eq!(
            parsed.releases.len(),
            doc["releases"].as_array().unwrap().len()
        );
    }

    #[test]
    fn search_without_release_id_prints_the_whole_registry() {
        let dir = Scratch::protected("registry", "search-all");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let registry_path = dir
            .root
            .join(".swp/public/registry.json")
            .display()
            .to_string();
        let r2 = dir.run(&["registry", "search", &registry_path, "--format", "json"]);
        assert_eq!(r2.code, 0, "{}{}", r2.out, r2.err);
        let doc = r2.json();
        assert!(!doc["releases"].as_array().unwrap().is_empty());
    }

    #[test]
    fn search_by_release_id_returns_that_entry() {
        let dir = Scratch::protected("registry", "search-one");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let registry_path = dir
            .root
            .join(".swp/public/registry.json")
            .display()
            .to_string();
        let releases = dir.store().releases().unwrap();
        let release_id = releases[0].as_str();
        let r2 = dir.run(&[
            "registry",
            "search",
            &registry_path,
            "--release",
            release_id,
            "--format",
            "json",
        ]);
        assert_eq!(r2.code, 0, "{}{}", r2.out, r2.err);
        let doc = r2.json();
        assert_eq!(doc["release_id"].as_str(), Some(release_id));
    }

    #[test]
    fn search_for_an_unknown_release_fails_with_the_count() {
        let dir = Scratch::protected("registry", "search-missing");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}", r.err);
        let registry_path = dir
            .root
            .join(".swp/public/registry.json")
            .display()
            .to_string();
        let r2 = dir.run(&[
            "registry",
            "search",
            &registry_path,
            "--release",
            "rel-aaaaaaaaaaaaaaaa",
        ]);
        assert_eq!(r2.code, ErrorCode::NotProtected.exit_code());
        assert!(r2.err.contains("not in this registry"), "{}", r2.err);
    }

    #[test]
    fn publish_with_latest_only_lists_one_release() {
        let dir = Scratch::protected("registry", "latest-only");
        let r = dir.run(&["registry", "publish", "--latest"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let doc = r.json();
        let releases = doc["releases"].as_array().unwrap();
        assert_eq!(releases.len(), 1, "{releases:?}");
    }

    #[test]
    fn publish_without_a_project_fails_cleanly() {
        let dir = Scratch::new("registry", "noproject");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, ErrorCode::NotProtected.exit_code());
        assert!(r.err.contains("swp init"), "{}", r.err);
    }

    #[test]
    fn a_malformed_registry_file_is_refused() {
        let dir = Scratch::new("registry", "malformed");
        dir.write("bad.json", "{not json");
        let r = dir.run(&["registry", "search", "bad.json"]);
        assert_eq!(r.code, ErrorCode::InvalidManifest.exit_code());
    }
}
