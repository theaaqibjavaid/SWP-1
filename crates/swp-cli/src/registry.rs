//! `swp registry publish` and `swp registry search` — a signed index of one
//! project's own releases.
//!
//! The registry is a single JSON file a project owner maintains in their
//! repository. It collects the release records the store already publishes, one
//! per file under `.swp/public/releases/`, into a document signed by the
//! project's own key, so a reader who has the file has every record and one
//! signature to check instead of one of each per release.
//!
//! ## What it is not
//!
//! SPEC 16 lists key sharing, delegation and a registry among the things this
//! protocol does not define: one project, one secret, one store, no third party,
//! no online service, and no way for one project to verify another's fragments.
//! A file in a repository cannot repeal that, and this module does not pretend
//! it does. The index is a publisher's convenience — a bibliography page, not a
//! database — and it can be mirrored, pushed or hand-copied because nothing in
//! the protocol reads it. `swp scan` never consults one: a finding is what the
//! keyed sites say, and no index can add to it.
//!
//! ## What a reader does get
//!
//! Self-authentication, and only that. [`RegistryDocument::verify_signatures`]
//! checks the document and every record inside it against the verify key the
//! document itself carries, so the file cannot be edited without its author's
//! private key. It cannot prove that key belongs to the project id the file
//! names: the id and the key are both derived from a root secret that is not in
//! the file, and no public relation between them exists. The one real pin is a
//! local project to compare against, which is what `search` does when it can —
//! and what it says out loud when it cannot.

use std::path::Path;

use serde::{Deserialize, Serialize};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ProjectId;
use swp_core::version::SWP_PROTOCOL_NAME;
use swp_crypto::{PublicKeys, VerifyingKey};
use swp_identity::ReleaseRecord;
use swp_sdk::ReleaseSelection;

use crate::args::{Flag, Parsed};
use crate::ctx::{self, Ctx};
use crate::output::{self, Sink};

/// The schema version string for the registry document.
pub const REGISTRY_SCHEMA: &str = "SWP-1-registry-v1";

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
    /// One record per release the project has published, oldest first. Each
    /// carries the signature the store published it with.
    pub releases: Vec<ReleaseRecord>,
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

    /// Read, validate and authenticate a registry document from JSON bytes.
    ///
    /// The signature check is part of reading, not an optional extra: a document
    /// whose claims were edited after it was signed must fail here rather than
    /// reach a reader that prints it.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("registry document is not valid UTF-8"))?;
        let doc: RegistryDocument = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("registry document: {e}")))?;
        doc.validate()?;
        doc.verify_signatures()?;
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
            entry.validate()?;
            // One document, one project. Without this a signed index of project A
            // could carry B's records — and the signature over the whole document
            // would then be A's attestation of claims A never made.
            if entry.project_id != self.project_id {
                return Err(SwpError::invalid_manifest(format!(
                    "registry lists release {} as project {}, but the document itself is \
                     project {}",
                    entry.release_id, entry.project_id, self.project_id
                )));
            }
        }
        Ok(())
    }

    /// Check this document's signature and every record inside it against the
    /// verify key the document carries.
    ///
    /// Say precisely what that establishes, because it is less than it sounds:
    /// the bytes are the bytes their author signed, and every claim in them —
    /// including which project id and which verify key — is that author's. It
    /// does not tie the carried key to the claimed project id, since both come
    /// from a root secret that is not in the file. `search` compares the pair
    /// against a local project's identity when one exists, and says so when one
    /// does not.
    pub fn verify_signatures(&self) -> Result<(), SwpError> {
        if self.signature.is_empty() {
            return Err(SwpError::invalid_manifest(
                "registry document is unsigned: no publisher's key attests to the claims in it",
            ));
        }
        let key = VerifyingKey::from_public_keys(&self.verify_key)?;
        swp_manifest::sig::verify_json_document(self, &self.signature, &key)
            .map_err(|e| SwpError::new(e.code(), format!("registry document: {}", e.message())))?;
        for entry in &self.releases {
            swp_manifest::sig::verify_release_record(entry, &key).map_err(|e| {
                SwpError::new(e.code(), format!("registry document: {}", e.message()))
            })?;
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

    let mut releases: Vec<ReleaseRecord> = Vec::with_capacity(ids.len());
    for id in &ids {
        releases.push(project.release(id)?);
    }
    releases.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.release_id.cmp(&b.release_id))
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

    project.store.write_registry(&doc.to_json_bytes())?;

    if parsed.verbose() {
        sink.note(&format!(
            "registry written to {} ({} release(s))",
            project.store.registry_path().display(),
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
    pin(parsed, cwd, &doc, sink)?;

    // The index is a list of releases, so the two flags that name one mean here
    // what they mean for every other verb — read through the same door, because
    // a command that accepts `--latest` and ignores it answers a different
    // question than the one was asked.
    let record = match ctx::selection(parsed)? {
        ReleaseSelection::All => {
            let text = String::from_utf8_lossy(&doc.to_json_bytes()).to_string();
            let lines = vec![text];
            output::deliver(sink, &doc, &lines, parsed.value(Flag::Output))?;
            return Ok(0);
        }
        ReleaseSelection::Latest => doc.releases.last().ok_or_else(|| {
            SwpError::new(
                ErrorCode::ReleaseMismatch,
                "this registry lists no releases, so it has no newest one",
            )
        })?,
        ReleaseSelection::Ids(ids) => {
            let Some(wanted) = ids.first() else {
                return Err(SwpError::usage(
                    "registry search: --release names the release to look up",
                ));
            };
            doc.releases
                .iter()
                .find(|r| &r.release_id == wanted)
                .ok_or_else(|| {
                    SwpError::new(
                        ErrorCode::ReleaseMismatch,
                        format!(
                            "release {} is not in this registry ({} release(s) listed). Use \
                             `swp registry search <file>` without --release to see all.",
                            wanted,
                            doc.releases.len()
                        ),
                    )
                })?
        }
    };

    let record_json = serde_json::to_string_pretty(record).expect("release record is serializable");
    let lines = vec![record_json];
    output::deliver(sink, record, &lines, parsed.value(Flag::Output))?;
    Ok(0)
}

/// Compare the index against a project this command was pointed at.
///
/// A signature checked under the key the signed document itself names proves
/// only that the bytes are what their author wrote. Tying that author to a
/// project id takes a second source, and the only one this command can reach
/// without a network is the project standing here: its identity document carries
/// the same pair from the inside, so a mismatch is caught and a match is the
/// strongest statement a reader here can make.
///
/// With no project to compare against the run still succeeds — reading an index
/// on its own terms is a legitimate thing to do — but it says which of the two
/// readings happened, because the weaker one must not be mistaken for the
/// stronger.
fn pin(
    parsed: &Parsed,
    cwd: &Path,
    doc: &RegistryDocument,
    sink: &mut Sink<'_>,
) -> Result<(), SwpError> {
    let project = match Ctx::open(parsed, cwd) {
        Ok(project) => project,
        Err(e) if e.code() == ErrorCode::NotProtected => {
            sink.warn(&format!(
                "no SWP-1 project here, so {} is authenticated against the verify key it \
                 carries and nothing else: the file vouches for its own claim about which \
                 project that key belongs to. Run this inside the project, or pass \
                 --project <dir>, to check the claim against that project's identity.",
                doc.project_id
            ));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    for warning in project.warnings() {
        sink.warn(warning);
    }
    let identity = project.identity();
    if identity.project_id != doc.project_id {
        return Err(SwpError::invalid_manifest(format!(
            "this index is for project {}, but the project here is {} — the two are different \
             keys' claims, so nothing in the index says anything about this tree",
            doc.project_id, identity.project_id
        )));
    }
    if identity.verification != doc.verify_key {
        return Err(SwpError::invalid_manifest(format!(
            "index for {} carries a verify key that is not this project's own ({})",
            doc.project_id, identity.project_id
        )));
    }
    if parsed.verbose() {
        sink.note(&format!(
            "index for {} checked against this project's identity: the key it signed itself \
             with is the key in .swp/public/identity.json",
            doc.project_id
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::{Run, Scratch};

    /// The index `publish` wrote, read back through the store's own path so a
    /// test cannot drift from where the command actually puts it.
    fn published(dir: &Scratch) -> serde_json::Value {
        let text = std::fs::read_to_string(dir.store().registry_path()).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// Search an index the test wrote into the scratch tree.
    fn search(dir: &Scratch, name: &str, doc: &serde_json::Value) -> Run {
        dir.write(name, &doc.to_string());
        dir.run(&["registry", "search", name, "--format", "json"])
    }

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
        assert_ne!(
            doc["signature"].as_str().unwrap(),
            "",
            "a published index that carries no signature authenticates nothing"
        );
        let path = dir.store().registry_path();
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
        let registry_path = dir.store().registry_path().display().to_string();
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
        let registry_path = dir.store().registry_path().display().to_string();
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
        let registry_path = dir.store().registry_path().display().to_string();
        let r2 = dir.run(&[
            "registry",
            "search",
            &registry_path,
            "--release",
            "rel-aaaaaaaaaaaaaaaa",
        ]);
        assert_eq!(r2.code, ErrorCode::ReleaseMismatch.exit_code());
        assert!(r2.err.contains("not in this registry"), "{}", r2.err);
    }

    #[test]
    fn search_latest_asks_the_index_for_its_newest_release() {
        let dir = Scratch::protected("registry", "search-latest");
        assert_eq!(dir.run(&["registry", "publish"]).code, 0);
        let registry_path = dir.store().registry_path().display().to_string();
        let newest = dir
            .store()
            .releases()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .to_string();
        let r = dir.run(&[
            "registry",
            "search",
            &registry_path,
            "--latest",
            "--format",
            "json",
        ]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        // A record, not the index: the flag selected a release instead of being
        // read, discarded, and the whole document printed anyway.
        let doc = r.json();
        assert_eq!(doc["release_id"].as_str(), Some(newest.as_str()), "{doc:#}");
        assert_ne!(doc["schema"], REGISTRY_SCHEMA, "{doc:#}");
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

    // --- what a reader is owed for the claims in the file --------------------

    #[test]
    fn an_unsigned_registry_is_refused() {
        let dir = Scratch::protected("registry", "unsigned");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let mut doc = published(&dir);
        doc["signature"] = serde_json::Value::String(String::new());
        let r = search(&dir, "unsigned.json", &doc);
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
    fn an_edited_claim_in_a_signed_registry_is_refused() {
        let dir = Scratch::protected("registry", "edited");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let mut doc = published(&dir);
        // A field the structural checks accept and only the signature covers.
        doc["releases"][0]["fingerprint_level"] = serde_json::Value::String("L2".to_string());
        let r = search(&dir, "edited.json", &doc);
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
    fn a_record_from_another_project_is_refused_before_the_signature() {
        let dir = Scratch::protected("registry", "foreign-id");
        let r = dir.run(&["registry", "publish"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        let mut doc = published(&dir);
        doc["project_id"] = serde_json::Value::String("swp1-abcdefghijklmnop".to_string());
        let r = search(&dir, "foreign-id.json", &doc);
        assert_eq!(
            r.code,
            ErrorCode::InvalidManifest.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        assert!(
            r.err
                .contains("but the document itself is project swp1-abcdefghijklmnop"),
            "the refusal names both the entry's project and the document's: {}",
            r.err
        );
    }

    #[test]
    fn an_index_for_another_project_is_refused_here() {
        let author = Scratch::protected("registry", "pin-author");
        let reader = Scratch::protected_variant("registry", "pin-reader", 1);
        assert_eq!(author.run(&["registry", "publish"]).code, 0);
        assert_ne!(author.project_id(), reader.project_id());
        let doc = published(&author);
        let r = search(&reader, "foreign.json", &doc);
        assert_eq!(
            r.code,
            ErrorCode::InvalidManifest.exit_code(),
            "{}{}",
            r.out,
            r.err
        );
        assert!(
            r.err.contains("this index is for project") && r.err.contains(&reader.project_id()),
            "the refusal says which project the index is for and which one is here: {}",
            r.err
        );
    }

    #[test]
    fn an_index_read_without_a_project_says_what_it_could_not_check() {
        let author = Scratch::protected("registry", "unpinned-author");
        let nowhere = Scratch::new("registry", "unpinned-here");
        assert_eq!(author.run(&["registry", "publish"]).code, 0);
        let doc = published(&author);
        let r = search(&nowhere, "index.json", &doc);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert!(
            r.err.contains("verify key it carries") && r.err.contains("--project"),
            "the run says which of the two readings it performed: {}",
            r.err
        );
    }
}
