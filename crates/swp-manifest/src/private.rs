//! The private manifest: what was embedded, where, and under which identity.
//!
//! How this maps onto the §18 example, which lists `location_id` and
//! `fragment_id` per entry:
//!
//! ```text
//! §18 "location_id"  →  SiteEntry::locations, four of them, one per radius key
//! §18 "fragment_id"  →  not stored. It is the value the site must carry, and it
//!                        is HMAC-derived from the primary location id on demand
//!                        (rule 1 of the crate note): storing it would copy the
//!                        watermark into the file that explains the watermark.
//! ```
//!
//! Four keys per site rather than one, because a copy does not survive
//! refactoring in only one way. `statement+identifiers` is the workhorse — it
//! ignores formatting *and* local renaming — but a copy whose enclosing function
//! was extracted into another file still matches a scope key, and one where the
//! literal itself was rewritten in place matches only the raw-name keys. A
//! location counts once however many of its keys hit, so the detector unions
//! them instead of voting between them.
//!
//! The `file`, `line_hint`, `language` and `grammar_path` fields are for humans.
//! §20's detection pipeline never reads them: a candidate is matched by keyed
//! location identity alone, which is why moving or renaming a file does not
//! break provenance. They are, however, project content, which is why the whole
//! document sits under `.swp/private/` and is gitignored.

use serde::{Deserialize, Serialize};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{Digest, LocationId, ProjectId, ReleaseId};
use swp_core::site::{FormFamily, LiteralClass, RadiusKind, TagWidth};
use swp_core::{canonical_relpath, Limits};
use swp_core::{GeneratorInfo, SchemaVersion, SWP_PROTOCOL_NAME};
use swp_crypto::{ManifestSigningKey, VerifyingKey};
use swp_identity::Timestamp;

use crate::fingerprint::sha256;
use crate::keys::SLOTS;
use crate::sig;

/// Bound on every stored string. The manifest holds source fragments and paths;
/// unbounded strings in a signed document are a memory problem before they are a
/// security one, and no legitimate literal or path is anywhere near this long.
pub const MAX_HINT_LEN: usize = 240;

/// One watermarked site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteEntry {
    /// Keyed identities of this site, indexed by [`SLOTS`]:
    /// `[statement+identifiers, scope+identifiers, statement+names, scope+names]`.
    pub locations: [LocationId; 4],
    /// Which of the four the fragment tag is derived from, as a `RadiusKind`
    /// code. Chosen at embed time as the key that names this site most precisely
    /// among the sites this run could see — two sites that canonicalize to the
    /// same statement text (two `return <SITE>;` lines, say) must not be given one
    /// tag, and a wider radius usually separates them — with the rename-tolerant
    /// keys preferred when two keys are equally precise.
    pub primary: u8,
    /// Canonical project-relative path, forward slashes. A report hint only.
    pub file: String,
    /// 1-based line at embed time. A report hint only, and expected to go stale.
    pub line_hint: u32,
    pub language: String,
    /// `"ast"` or `"lexical"`: how much the tool actually understood here.
    pub adapter: String,
    /// Grammar path from the enclosing scope to the literal, for `swp inspect`.
    pub grammar_path: String,
    /// What kind of literal carried the tag.
    pub class: LiteralClass,
    /// Which equivalent-form family carried it.
    pub family: FormFamily,
    /// Bits carried, which must equal the manifest's `tag_bits`.
    pub width: u8,
    /// The literal as written before the rewrite.
    pub original: String,
    /// The literal as written after it. `swp verify` looks for this text.
    pub rendered: String,
}

/// A numeric family cannot carry a string site, or the manifest would describe
/// a rewrite the form engine has no rendering for.
fn family_matches_class(family: FormFamily, class: LiteralClass) -> bool {
    match class {
        LiteralClass::Integer => family.applies_to_numbers(),
        LiteralClass::String => family.applies_to_strings(),
    }
}

impl SiteEntry {
    pub fn primary_kind(&self) -> Result<RadiusKind, SwpError> {
        RadiusKind::from_code(self.primary)
    }

    /// The id the tag is derived from.
    pub fn primary_id(&self) -> Result<LocationId, SwpError> {
        let kind = self.primary_kind()?;
        let index = SLOTS
            .iter()
            .position(|k| *k == kind)
            .ok_or_else(|| SwpError::invalid_manifest("primary radius has no manifest slot"))?;
        Ok(self.locations[index])
    }

    pub fn tag_width(&self) -> Result<TagWidth, SwpError> {
        TagWidth::new(self.width)
    }

    /// Recompute what this site must carry. Never stored, always derived (§8).
    pub fn expected_tag(&self, keys: &crate::ManifestKeys) -> Result<u32, SwpError> {
        Ok(keys.fragment_tag(&self.primary_id()?, self.tag_width()?))
    }

    /// The family must match the literal class it rewrote, or the manifest
    /// describes an embedding the form engine cannot produce.
    pub fn validate(&self) -> Result<(), SwpError> {
        for (i, id) in self.locations.iter().enumerate() {
            if *id == LocationId::default() {
                return Err(SwpError::invalid_manifest(format!(
                    "site {} in {:?} has an all-zero location id at slot {i}",
                    self.line_hint, self.file
                )));
            }
        }
        // Equal slots are legal, not a collision: a module-level statement in a
        // short file has the same span at both radii, and the lexical fallback
        // uses the whole document for both. The four *keys* remain distinct
        // because the radius is mixed into the id, but the underlying canonical
        // text can be identical, and that must not reject a real site.
        // Two sites that share all four, however, are indistinguishable, and
        // `PrivateManifest::validate` refuses those.
        let primary = self.primary_kind()?;
        let index = SLOTS
            .iter()
            .position(|k| *k == primary)
            .ok_or_else(|| SwpError::invalid_manifest("primary radius has no manifest slot"))?;
        if self.locations[index] == LocationId::default() {
            return Err(SwpError::invalid_manifest(
                "the primary location id is all zero",
            ));
        }
        for (field, value) in [
            ("file", &self.file),
            ("language", &self.language),
            ("adapter", &self.adapter),
            ("grammar_path", &self.grammar_path),
            ("original", &self.original),
            ("rendered", &self.rendered),
        ] {
            if value.len() > MAX_HINT_LEN || value.chars().any(|c| c.is_control()) {
                return Err(SwpError::invalid_manifest(format!(
                    "site hint {field} is too long or holds a control character"
                )));
            }
        }
        if self.file.is_empty() || self.file != canonical_relpath(&self.file) {
            return Err(SwpError::invalid_manifest(format!(
                "site file {:?} is not a canonical relative path",
                self.file
            )));
        }
        if !matches!(self.adapter.as_str(), "ast" | "lexical") {
            return Err(SwpError::invalid_manifest(format!(
                "unknown adapter kind {:?}",
                self.adapter
            )));
        }
        if self.line_hint == 0 {
            return Err(SwpError::invalid_manifest(
                "line hints are 1-based; 0 means it was never filled in",
            ));
        }
        let width = self.tag_width()?;
        if !family_matches_class(self.family, self.class) {
            return Err(SwpError::invalid_manifest(format!(
                "family {:?} cannot carry a {:?} site",
                self.family, self.class
            )));
        }
        if self.family.max_bits() < width.bits() {
            return Err(SwpError::invalid_manifest(format!(
                "family {:?} cannot carry {} bits",
                self.family,
                width.bits()
            )));
        }
        if self.original == self.rendered {
            // The rewrite would have carried no bits, so the site proves nothing
            // and would be counted as a hit by a scan that never saw a change.
            return Err(SwpError::invalid_manifest(
                "a site whose rendering equals its original text carries no watermark",
            ));
        }
        Ok(())
    }
}

/// A signed record of every site one release embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateManifest {
    pub protocol: String,
    pub schema: u16,
    pub project_id: ProjectId,
    pub release_id: ReleaseId,
    pub created_at: Timestamp,
    /// Must equal the project identity's value, and is mixed into every location
    /// id: a canonicalizer change renames sites rather than mis-reporting them.
    pub canonicalizer_version: u16,
    /// §16, over the whole protected tree.
    pub fingerprint: Digest,
    /// The level the fingerprint was taken at, so it can never be compared
    /// against one taken at another.
    pub fingerprint_level: String,
    pub tag_bits: u8,
    pub generator: GeneratorInfo,
    /// Every site, in embed order.
    pub sites: Vec<SiteEntry>,
    /// Ed25519 over the canonical JSON of this document with the field removed.
    pub signature: String,
}

impl PrivateManifest {
    /// Build and validate a manifest, so an invalid one never reaches disk.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        project_id: ProjectId,
        release_id: ReleaseId,
        created_at: Timestamp,
        canonicalizer_version: u16,
        fingerprint: Digest,
        fingerprint_level: &str,
        tag_bits: u8,
        generator: GeneratorInfo,
        sites: Vec<SiteEntry>,
    ) -> Result<Self, SwpError> {
        let m = PrivateManifest {
            protocol: SWP_PROTOCOL_NAME.to_string(),
            schema: SchemaVersion::MANIFEST_V1.0,
            project_id,
            release_id,
            created_at,
            canonicalizer_version,
            fingerprint,
            fingerprint_level: fingerprint_level.to_string(),
            tag_bits,
            generator,
            sites,
            signature: String::new(),
        };
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), SwpError> {
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("manifest declares protocol {:?}", self.protocol),
            ));
        }
        if self.schema != SchemaVersion::MANIFEST_V1.0 {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("manifest schema {} is not supported", self.schema),
            ));
        }
        if !TagWidth::is_supported(self.tag_bits) {
            return Err(SwpError::invalid_manifest(format!(
                "tag width {} is out of range",
                self.tag_bits
            )));
        }
        if !crate::fingerprint::LEVELS.contains(&self.fingerprint_level.as_str()) {
            return Err(SwpError::invalid_manifest(format!(
                "unknown fingerprint canonicalization level {:?}",
                self.fingerprint_level
            )));
        }
        if self.sites.is_empty() {
            // A manifest with no sites is not a record of a protected release;
            // accepting it would let `verify` pass on an unprotected tree.
            return Err(SwpError::new(
                ErrorCode::NoSafeLocations,
                "this release embedded no watermark sites, so it is not protected",
            ));
        }
        // Bounded before anything is walked: deserializing a huge `sites` array
        // has already cost memory, so the ceiling here is a tripwire against a
        // corrupt or hand-edited file, not the primary defence.
        let ceiling = u64::from(Limits::ceiling().max_locations_per_manifest);
        if self.sites.len() as u64 > ceiling {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "manifest lists {} sites, over the ceiling of {ceiling}",
                    self.sites.len()
                ),
            ));
        }
        let mut primaries = std::collections::BTreeMap::new();
        let mut shapes = std::collections::BTreeMap::new();
        for (i, site) in self.sites.iter().enumerate() {
            site.validate()?;
            if site.width != self.tag_bits {
                return Err(SwpError::invalid_manifest(format!(
                    "site {i} carries {} bits in a {}-bit release",
                    site.width, self.tag_bits
                )));
            }
            let primary = site.primary_id()?;
            if let Some(prev) = primaries.insert(primary, i) {
                return Err(SwpError::new(
                    ErrorCode::Internal,
                    format!(
                        "sites {prev} and {i} collide on primary location id {} — \
                         selection must refuse a colliding site, not record it",
                        primary.hex()
                    ),
                ));
            }
            if let Some(prev) = shapes.insert(site.locations, i) {
                // Sharing one weak key is normal and the tag resolves it. Sharing
                // all four means no observation could ever tell the sites apart,
                // so the pair carries no more information than one site would.
                return Err(SwpError::new(
                    ErrorCode::Internal,
                    format!("sites {prev} and {i} are indistinguishable on all four radius keys"),
                ));
            }
        }
        // Sites may share a *secondary* key — two `const X = <SITE>;` lines in
        // one module have the same statement text — and that is fine: the tag
        // check resolves the ambiguity at 2^-width per extra candidate.
        Ok(())
    }

    pub fn sign(&mut self, key: &ManifestSigningKey) -> Result<(), SwpError> {
        self.signature = sig::sign_json_document(self, key)?;
        Ok(())
    }

    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), SwpError> {
        if self.signature.is_empty() {
            return Err(SwpError::invalid_manifest("manifest is unsigned"));
        }
        sig::verify_json_document(self, &self.signature, key)
    }

    /// Pretty JSON for disk. The *signed* bytes are canonical JSON with the
    /// signature field removed, so reformatting this file never breaks it.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s =
            serde_json::to_string_pretty(self).expect("manifest is serializable by shape");
        s.push('\n');
        s.into_bytes()
    }

    /// The only way to read a manifest back. Authenticates rather than merely
    /// parsing: a silently edited manifest is worse than a missing one, because
    /// every site it no longer describes would report as tampering.
    pub fn load(bytes: &[u8], key: &VerifyingKey) -> Result<Self, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("manifest is not valid UTF-8"))?;
        let m: PrivateManifest = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("manifest: {e}")))?;
        m.validate()?;
        m.verify_signature(key)?;
        Ok(m)
    }

    /// What the release record binds: SHA-256 of the exact bytes written to
    /// `.swp/private/manifests/<release>.json`, so a restored backup can be
    /// confirmed to be the manifest this release shipped with.
    pub fn content_digest(&self) -> Digest {
        sha256(&self.to_json_bytes())
    }

    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    /// Expected tag for every site, in order. Used by `swp verify` and by the
    /// detector's per-site confirmation.
    pub fn expected_tags(&self, keys: &crate::ManifestKeys) -> Result<Vec<u32>, SwpError> {
        if keys.project_id() != &self.project_id {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                "these keys belong to a different project than this manifest",
            ));
        }
        self.sites
            .iter()
            .map(|s| s.expected_tag(keys))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Any site whose four keys include this id, as manifest positions. More than
    /// one is normal and is resolved by the tag, not by guessing.
    pub fn sites_for(&self, id: &LocationId) -> Vec<usize> {
        self.sites
            .iter()
            .enumerate()
            .filter(|(_, s)| s.locations.contains(id))
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::Digest;
    use swp_crypto::RootSecret;
    use crate::keys::ManifestKeys;

    fn keys() -> ManifestKeys {
        ManifestKeys::derive(
            &RootSecret::from_bytes(&[0x55u8; 32]).unwrap(),
            &project(),
            &release(),
            swp_core::CanonicalizerVersion::V1,
        )
    }

    fn project() -> ProjectId {
        ProjectId::new("swp1-abcdefghijklmnop").unwrap()
    }

    fn release() -> ReleaseId {
        ReleaseId::new("rel-aaaaaaaa").unwrap()
    }

    fn signing_key() -> ManifestSigningKey {
        ManifestSigningKey::from_root(
            &RootSecret::from_bytes(&[0x55u8; 32]).unwrap(),
            project().as_str(),
        )
        .unwrap()
    }

    /// A site built the way `swp-embedding` builds one: real ids from real keys.
    fn site(k: &ManifestKeys, digest_byte: u8, line: u32) -> SiteEntry {
        let mut canonicals = [
            Digest([digest_byte; 32]),
            Digest([digest_byte ^ 0x01; 32]),
            Digest([digest_byte ^ 0x02; 32]),
            Digest([digest_byte ^ 0x03; 32]),
        ];
        if digest_byte & 0x80 != 0 {
            // Deliberately reuse another site's statement-radius text — the two
            // `return <SITE>;` case — so the primary ids collide. The wider
            // radii stay distinct, which is what makes the pair legal except
            // that both chose the colliding key as primary.
            canonicals = [
                Digest([digest_byte & 0x7f; 32]),
                Digest([digest_byte; 32]),
                Digest([digest_byte ^ 0x10; 32]),
                Digest([digest_byte ^ 0x20; 32]),
            ];
        }
        let locations = k.location_ids(&canonicals);
        SiteEntry {
            locations,
            primary: RadiusKind::StatementId.code(),
            file: "src/app.js".to_string(),
            line_hint: line,
            language: "javascript".to_string(),
            adapter: "ast".to_string(),
            grammar_path: "return;binary_expression;number".to_string(),
            class: LiteralClass::Integer,
            family: FormFamily::Add,
            width: 4,
            original: "30000".to_string(),
            rendered: "(29999 + 1)".to_string(),
        }
    }

    fn manifest(k: &ManifestKeys, sites: Vec<SiteEntry>) -> PrivateManifest {
        PrivateManifest::build(
            k.project_id().clone(),
            k.release_id().clone(),
            Timestamp::from_unix(1_700_000_000),
            1,
            Digest([7u8; 32]),
            "L1",
            4,
            GeneratorInfo::current(),
            sites,
        )
        .unwrap()
    }

    #[test]
    fn a_signed_manifest_survives_the_disk_round_trip() {
        let k = keys();
        let mut m = manifest(&k, vec![site(&k, 1, 10), site(&k, 2, 20)]);
        m.sign(&signing_key()).unwrap();
        let bytes = m.to_json_bytes();
        let back = PrivateManifest::load(&bytes, &signing_key().verifying_key()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.site_count(), 2);
    }

    #[test]
    fn an_unsigned_or_forged_manifest_is_refused() {
        let k = keys();
        let m = manifest(&k, vec![site(&k, 1, 10)]);
        assert!(PrivateManifest::load(&m.to_json_bytes(), &signing_key().verifying_key())
            .unwrap_err()
            .message()
            .contains("unsigned"));

        let mut signed = m.clone();
        signed.sign(&signing_key()).unwrap();
        let mut bytes = String::from_utf8(signed.to_json_bytes()).unwrap();
        bytes = bytes.replace("\"line_hint\": 10", "\"line_hint\": 11");
        let e = PrivateManifest::load(bytes.as_bytes(), &signing_key().verifying_key()).unwrap_err();
        assert!(e.message().contains("signature"), "{e:?}");

        let other = ManifestSigningKey::from_root(
            &RootSecret::from_bytes(&[0x56u8; 32]).unwrap(),
            project().as_str(),
        )
        .unwrap();
        assert!(signed.verify_signature(&other.verifying_key()).is_err());
    }

    /// Formatting is not a signature change: the signed bytes are canonical, so
    /// an editor that re-indents the manifest does not destroy it.
    #[test]
    fn reformatting_does_not_break_the_signature() {
        let k = keys();
        let mut m = manifest(&k, vec![site(&k, 1, 10)]);
        m.sign(&signing_key()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&m.to_json_bytes()).unwrap();
        let compact = value.to_string();
        let back: PrivateManifest = serde_json::from_str(&compact).unwrap();
        assert!(back.verify_signature(&signing_key().verifying_key()).is_ok());
    }

    #[test]
    fn structural_validation_runs_before_authentication() {
        let k = keys();
        let mut m = manifest(&k, vec![site(&k, 1, 10)]);
        m.sign(&signing_key()).unwrap();
        // A well-formed but protocol-lying document must fail as a version
        // problem, not merely as a signature problem.
        m.protocol = "SWP-2".to_string();
        let e = PrivateManifest::load(&m.to_json_bytes(), &signing_key().verifying_key())
            .unwrap_err();
        assert!(e.code() == ErrorCode::ProtocolVersionUnsupported, "{e:?}");
    }

    #[test]
    fn an_empty_manifest_is_not_a_protected_release() {
        let e = PrivateManifest::build(
            project(),
            release(),
            Timestamp::from_unix(1),
            1,
            Digest([0u8; 32]),
            "L1",
            4,
            GeneratorInfo::current(),
            vec![],
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::NoSafeLocations);
    }

    #[test]
    fn two_sites_sharing_a_primary_identity_are_refused() {
        let k = keys();
        let e = manifest_build_err(vec![site(&k, 1, 10), site(&k, 0x81, 20)]);
        assert!(e.message().contains("collide"), "{e:?}");
    }

    fn manifest_build_err(sites: Vec<SiteEntry>) -> SwpError {
        PrivateManifest::build(
            project(),
            release(),
            Timestamp::from_unix(1),
            1,
            Digest([0u8; 32]),
            "L1",
            4,
            GeneratorInfo::current(),
            sites,
        )
        .unwrap_err()
    }

    #[test]
    fn a_site_must_be_a_real_rewrite_with_a_matching_family() {
        let k = keys();
        let mut unchanged = site(&k, 1, 10);
        unchanged.rendered = unchanged.original.clone();
        assert!(unchanged.validate().unwrap_err().message().contains("no watermark"));

        let mut mismatched = site(&k, 2, 10);
        mismatched.family = FormFamily::StringConcat;
        assert!(mismatched
            .validate()
            .unwrap_err()
            .message()
            .contains("cannot carry"));

        let mut too_wide = site(&k, 3, 10);
        too_wide.family = FormFamily::Radix;
        too_wide.width = 8;
        assert!(too_wide
            .validate()
            .unwrap_err()
            .message()
            .contains("cannot carry 8 bits"));

        let mut bad_path = site(&k, 4, 10);
        bad_path.file = "src\\sub\\app.js".to_string();
        assert!(bad_path.validate().unwrap_err().message().contains("canonical"));

        let mut leaked = site(&k, 5, 10);
        leaked.grammar_path = "a\0b".to_string();
        assert!(leaked.validate().unwrap_err().message().contains("control"));

        let mut zero_line = site(&k, 6, 10);
        zero_line.line_hint = 0;
        assert!(zero_line.validate().unwrap_err().message().contains("1-based"));
    }

    #[test]
    fn a_site_that_collides_internally_is_refused() {
        let k = keys();
        let mut s = site(&k, 1, 10);
        // Equal radii (a single-statement module) share a digest, so two slots
        // are equal and the site is still valid.
        s.locations[1] = s.locations[0];
        s.validate().unwrap();
        // An unset slot is not.
        s.locations[2] = LocationId::default();
        assert!(s.validate().unwrap_err().message().contains("all-zero"));
    }

    #[test]
    fn width_must_match_the_release() {
        let k = keys();
        let mut s = site(&k, 1, 10);
        s.width = 6;
        let e = manifest_build_err(vec![s]);
        assert!(e.message().contains("bits in a 4-bit release"), "{e:?}");
    }

    #[test]
    fn tags_are_recomputed_never_stored() {
        let k = keys();
        let m = manifest(&k, vec![site(&k, 1, 10), site(&k, 2, 20)]);
        let tags = m.expected_tags(&k).unwrap();
        assert_eq!(tags.len(), 2);
        for t in &tags {
            assert!(*t < 16);
        }
        let text = String::from_utf8(m.to_json_bytes()).unwrap();
        assert!(!text.contains("\"tag\""), "{text}");
        assert!(!text.contains("\"code\""));
        assert!(!text.contains("\"expected\""));
        // Keys from another project must not be usable by accident.
        let other = ManifestKeys::derive(
            &RootSecret::from_bytes(&[0x99u8; 32]).unwrap(),
            &ProjectId::new("swp1-bbbbbbbbbbbbbbbb").unwrap(),
            &release(),
            swp_core::CanonicalizerVersion::V1,
        );
        assert!(m.expected_tags(&other).is_err());
    }

    #[test]
    fn a_lookup_finds_every_site_sharing_a_weak_key() {
        let k = keys();
        // Two `return <SITE>;` statements in one project: the same statement
        // radius canonicalizes to the same text, so the two sites share that key
        // and differ only on their wider ones.
        let mut a = site(&k, 1, 10);
        a.primary = RadiusKind::ScopeId.code();
        let mut b = site(&k, 2, 20);
        b.locations[0] = a.locations[0];
        let m = manifest(&k, vec![a.clone(), b.clone()]);
        let hits = m.sites_for(&a.locations[0]);
        assert_eq!(hits, vec![0, 1]);
        assert_eq!(m.sites_for(&b.locations[1]), vec![1]);
        assert!(m.sites_for(&LocationId([0u8; 16])).is_empty());
    }

    #[test]
    fn the_manifest_digest_binds_the_exact_bytes() {
        let k = keys();
        let m = manifest(&k, vec![site(&k, 1, 10)]);
        assert_eq!(m.content_digest(), sha256(&m.to_json_bytes()));
        let mut other = m.clone();
        other.sites[0].line_hint = 99;
        assert_ne!(m.content_digest(), other.content_digest());
    }

    #[test]
    fn the_document_round_trips_through_json_strictly() {
        let k = keys();
        let mut m = manifest(&k, vec![site(&k, 1, 10)]);
        m.sign(&signing_key()).unwrap();
        let mut text = String::from_utf8(m.to_json_bytes()).unwrap();
        text = text.replace("\"signature\":", "\"sig\":");
        assert!(serde_json::from_str::<PrivateManifest>(&text).is_err());
    }
}
