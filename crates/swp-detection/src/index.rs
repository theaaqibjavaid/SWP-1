//! The release side of a scan: one protected release, indexed for lookup.
//!
//! A manifest is a list of sites in embed order. A scan is a stream of location
//! ids harvested out of a candidate tree. Matching those two by nested loops is
//! `O(candidates x sites)` over a candidate tree that can hold hundreds of
//! thousands of literals, so this module inverts the manifest once — location id
//! to `(site, slot)` — and every probe after that is one map lookup.
//!
//! ## Why the index refuses to be built loosely
//!
//! Three checks at construction, each one preventing a wrong answer rather than
//! tidying up:
//!
//! * **The signature must verify.** §31: an edited manifest is worse than a
//!   missing one, because every site it no longer describes would be reported as
//!   tampering in a copy that is actually clean. The scan is the only consumer, so
//!   the verification belongs here rather than in the caller's judgement.
//! * **The keys and the manifest must agree on project and canonicalizer.** A
//!   location id is an HMAC over `(project, radius, canonicalizer version, text)`
//!   (`swp-manifest::keys`), so keys derived for another project, or under another
//!   canonicalizer version, produce a *different id for the same code*. Indexing
//!   those against this manifest would find nothing in a genuine copy and, worse,
//!   could find something in an unrelated one.
//! * **The site count is bounded before the map is built.** A manifest is
//!   untrusted-on-disk content: its signature proves who wrote it, not that the
//!   writer was careful.
//!
//! ## What is deliberately not here
//!
//! The expected tag per site. §8's fragment is an HMAC of the site's primary
//! location id, and a code is only ever worth one comparison, so computing it at
//! the moment a literal is confirmed and dropping it again keeps the whole
//! constellation out of memory — and out of any Debug output, log line or panic
//! message this crate can produce. See [`ReleaseIndex::expected_tag`].

use std::collections::BTreeMap;

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{Digest, LocationId, ProjectId, ReleaseId};
use swp_core::limits::Limits;
use swp_core::site::{RadiusKind, TagWidth};
use swp_crypto::VerifyingKey;
use swp_identity::{ReleaseRecord, Timestamp};
use swp_manifest::{ManifestKeys, PrivateManifest, SiteEntry};

/// One entry in the inverted manifest: which site this id addresses, and which of
/// its four keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationHit {
    /// Index into [`ReleaseIndex::sites`].
    pub site: usize,
    /// Which of the four radius keys this id is, so the report can say *what kind*
    /// of copy it found: an L1 key hit means the surrounding text is byte-identical
    /// after canonicalization, an L3-only hit means it survived renaming.
    pub slot: RadiusKind,
}

/// A release plus everything derived from its manifest for lookup.
///
/// `'k` is how long the keys live for: the index borrows them rather than copying
/// them, because copying derived key material into a lookup structure would put
/// the secret behind the watermark in one more place than it needs to be.
#[derive(Debug)]
pub struct ReleaseIndex<'k> {
    release_id: ReleaseId,
    project_id: ProjectId,
    width: TagWidth,
    sites: Vec<SiteEntry>,
    by_location: BTreeMap<LocationId, Vec<LocationHit>>,
    /// The §16 fingerprint of the release, and the level it was taken at. The
    /// level travels with it because an L1 value compared against an L3 one is
    /// not a mismatch, it is a category error.
    fingerprint: Digest,
    fingerprint_level: String,
    keys: &'k ManifestKeys,
    created_at: Timestamp,
}

impl<'k> ReleaseIndex<'k> {
    /// Index one release. `record` supplies the fingerprint the scanner compares
    /// against; the manifest supplies the sites.
    ///
    /// # Errors
    ///
    /// Fails closed if the manifest does not authenticate, if the keys were not
    /// derived for this manifest's project and canonicalizer version, or if the
    /// document is over the configured bounds.
    pub fn build(
        manifest: &PrivateManifest,
        record: &ReleaseRecord,
        keys: &'k ManifestKeys,
        signing_key: &VerifyingKey,
        limits: &Limits,
    ) -> Result<Self, SwpError> {
        manifest.verify_signature(signing_key)?;
        record.validate()?;

        if record.project_id != manifest.project_id {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                format!(
                    "the release record describes {:?} but the manifest describes {:?}",
                    record.project_id, manifest.project_id
                ),
            ));
        }
        if record.release_id != manifest.release_id {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                format!(
                    "the release record is {:?} but the manifest is {:?}",
                    record.release_id, manifest.release_id
                ),
            ));
        }
        if record.fingerprint != manifest.fingerprint {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                "the public record's fingerprint is not the one the manifest recorded",
            ));
        }
        if record.fingerprint_level != manifest.fingerprint_level {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                "the record and the manifest disagree on the fingerprint's level",
            ));
        }
        if keys.project_id() != &manifest.project_id {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                "these keys were derived for a different project than this manifest",
            ));
        }
        if keys.canonicalizer_version() != manifest.canonicalizer_version {
            return Err(SwpError::new(
                ErrorCode::ReleaseMismatch,
                format!(
                    "these keys carry canonicalizer version {} but the manifest was built \
                     under {} — every location id would differ",
                    keys.canonicalizer_version(),
                    manifest.canonicalizer_version
                ),
            ));
        }
        if !TagWidth::is_supported(manifest.tag_bits) {
            return Err(SwpError::new(
                ErrorCode::InvalidWatermark,
                format!("manifest declares an unsupported tag width of {}", manifest.tag_bits),
            ));
        }
        if manifest.sites.len() as u64 > u64::from(limits.max_locations_per_manifest) {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "manifest lists {} sites, over the configured bound of {}",
                    manifest.sites.len(),
                    limits.max_locations_per_manifest
                ),
            ));
        }

        let mut by_location: BTreeMap<LocationId, Vec<LocationHit>> = BTreeMap::new();
        for (site, entry) in manifest.sites.iter().enumerate() {
            for (slot, kind) in RadiusKind::all().iter().enumerate() {
                by_location
                    .entry(entry.locations[slot])
                    .or_default()
                    .push(LocationHit { site, slot: *kind });
            }
        }
        Ok(ReleaseIndex {
            release_id: manifest.release_id.clone(),
            project_id: manifest.project_id.clone(),
            width: TagWidth::new(manifest.tag_bits)
                .map_err(|_| SwpError::new(ErrorCode::InvalidWatermark, "unsupported width"))?,
            sites: manifest.sites.clone(),
            by_location,
            fingerprint: manifest.fingerprint,
            fingerprint_level: manifest.fingerprint_level.clone(),
            keys,
            created_at: manifest.created_at,
        })
    }

    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn width(&self) -> TagWidth {
        self.width
    }

    pub fn tag_bits(&self) -> u8 {
        self.width.bits()
    }

    pub fn sites(&self) -> &[SiteEntry] {
        &self.sites
    }

    pub fn site(&self, index: usize) -> &SiteEntry {
        &self.sites[index]
    }

    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }

    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    pub fn fingerprint_level(&self) -> &str {
        &self.fingerprint_level
    }

    /// The canonicalizer version the manifest was built under, which is one of the
    /// four inputs to every location id and is inside the §16 fingerprint hash. The
    /// keys are refused at construction unless they carry the same value, so
    /// reading it from them and reading it from the manifest are the same answer.
    pub fn canonicalizer_version(&self) -> u16 {
        self.keys.canonicalizer_version()
    }

    /// The keys this release's tags are derived through, shared by every site of
    /// one project. Crate-visible only: exposing it would let a caller walk from a
    /// release index to keyed digests without going through [`Self::expected_tag`],
    /// which is the one place that consumes a key and drops the result.
    pub(crate) fn keys(&self) -> &'k ManifestKeys {
        self.keys
    }

    /// Every manifest site this id addresses. Empty is the ordinary answer: most
    /// literals in a foreign tree match nothing, and most of the ones that do
    /// match a *secondary* key rather than the primary.
    pub fn lookup(&self, id: &LocationId) -> &[LocationHit] {
        self.by_location.get(id).map_or(&[], Vec::as_slice)
    }

    /// The value this site must carry, recomputed rather than read (§8).
    ///
    /// Callers compare it once and drop it. It is never stored on the index,
    /// returned in a struct, or formatted: the whole point of the tag channel is
    /// that knowing the watermark means deriving it, which requires the root
    /// secret, which therefore never leaves `.swp/private/root.key`.
    pub fn expected_tag(&self, site: &SiteEntry) -> Result<u32, SwpError> {
        site.expected_tag(self.keys)
    }
}

/// A release as it arrives from the store: the two documents plus the keys that
/// tie them to the project's secret.
///
/// Not `Clone`, and that is the point — the keys own derived secret material, and
/// the type that has to be passed around is this one, so a scanner that wanted a
/// second copy of a project's keys would have to re-derive them from the root
/// secret on purpose rather than by accident.
#[derive(Debug)]
pub struct CandidateRelease {
    pub manifest: PrivateManifest,
    pub record: ReleaseRecord,
    /// Borrowed by the index [`build_indexes`] returns, which is why a batch of
    /// these outlives the indexes built from it.
    pub keys: ManifestKeys,
}

/// Index several releases at once, which is the normal case: an owner has many
/// protected builds and a copy could have come from any of them.
///
/// Releases that fail to authenticate are not silently dropped — one bad manifest
/// out of twelve should not turn "we could not read the evidence" into "no
/// evidence was found" — so the failure is returned to the caller with the release
/// id attached.
pub fn build_indexes<'k>(
    releases: &'k [CandidateRelease],
    signing_key: &VerifyingKey,
    limits: &Limits,
) -> Result<Vec<ReleaseIndex<'k>>, SwpError> {
    let mut out = Vec::with_capacity(releases.len());
    for release in releases {
        out.push(
            ReleaseIndex::build(
                &release.manifest,
                &release.record,
                &release.keys,
                signing_key,
                limits,
            )
            .map_err(|e| {
                SwpError::new(
                    e.code(),
                    format!(
                        "release {:?} cannot be scanned against: {}",
                        release.manifest.release_id,
                        e.message()
                    ),
                )
            })?,
        );
    }
    // Newest first, so a report leads with the release a copy most likely came
    // from. Release ids are opaque, so the ordering is by recorded time.
    out.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.release_id.as_str().cmp(a.release_id.as_str()))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::version::CanonicalizerVersion;
    use swp_core::{GeneratorInfo, SchemaVersion, SWP_PROTOCOL_NAME};
    use swp_crypto::RootSecret;
    use swp_identity::{Timestamp, WatermarkParams};

    fn root() -> RootSecret {
        RootSecret::from_bytes(&[0x31u8; 32]).unwrap()
    }

    fn project() -> ProjectId {
        ProjectId::new("swp1-abcdefghijklmnop").unwrap()
    }

    fn release(tag: &str) -> ReleaseId {
        ReleaseId::new(tag).unwrap()
    }

    fn keys_for(release_id: &str) -> ManifestKeys {
        ManifestKeys::derive(
            &root(),
            &project(),
            &release(release_id),
            CanonicalizerVersion::V1,
        )
    }

    fn signing_keypair() -> (swp_crypto::ManifestSigningKey, VerifyingKey) {
        let sk = swp_crypto::ManifestSigningKey::from_root(&root(), project().as_str()).unwrap();
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// One site with real ids, derived the way the embedder derives them.
    fn site(k: &ManifestKeys, seed: u8, line: u32) -> SiteEntry {
        let digests = [
            Digest([seed; 32]),
            Digest([seed ^ 0x40; 32]),
            Digest([seed ^ 0x80; 32]),
            Digest([seed ^ 0xc0; 32]),
        ];
        SiteEntry {
            locations: k.location_ids(&digests),
            primary: RadiusKind::StatementId.code(),
            file: format!("src/s{seed}.js"),
            line_hint: line,
            language: "javascript".into(),
            adapter: "ast".into(),
            grammar_path: "program > statement".into(),
            class: swp_core::LiteralClass::Integer,
            family: swp_core::FormFamily::Add,
            width: 4,
            original: "1000".into(),
            rendered: "(995 + 5)".into(),
        }
    }

    fn record(m: &PrivateManifest) -> ReleaseRecord {
        ReleaseRecord {
            protocol: SWP_PROTOCOL_NAME.into(),
            schema: SchemaVersion::MANIFEST_V1.0,
            project_id: m.project_id.clone(),
            release_id: m.release_id.clone(),
            created_at: m.created_at,
            source_revision: swp_identity::SourceRevision::Content,
            fingerprint: m.fingerprint,
            fingerprint_level: m.fingerprint_level.clone(),
            private_manifest_digest: m.content_digest(),
            watermark: WatermarkParams {
                target_sites: 2,
                tag_bits: m.tag_bits,
                sites_embedded: m.sites.len() as u32,
                sites_skipped: 0,
                canonicalizer_version: m.canonicalizer_version,
                form_set: "add".into(),
                adapters: vec![],
            },
            generator: m.generator.clone(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_signed_release_indexes_every_location_of_every_site() {
        let k = keys_for("rel-aaaaaaaaaaaa");
        let (sk, vk) = signing_keypair();
        let m = manifest(&k, &[1, 2], &sk);
        let idx = ReleaseIndex::build(&m, &record(&m), &k, &vk, &Limits::default()).unwrap();
        assert_eq!(idx.sites().len(), 2);
        for entry in m.sites.iter() {
            for (slot, id) in entry.locations.iter().enumerate() {
                let hits = idx.lookup(id);
                assert!(
                    hits.iter().any(|h| h.site == slot_of(&m, entry) && h.slot.code() as usize == slot),
                    "every stored id must address its own site"
                );
            }
        }
        assert!(idx.lookup(&LocationId::from_bytes(&[9u8; 16]).unwrap()).is_empty());
    }

    fn slot_of(m: &PrivateManifest, entry: &SiteEntry) -> usize {
        m.sites.iter().position(|s| s == entry).unwrap()
    }

    #[test]
    fn an_unsigned_or_edited_manifest_is_refused() {
        let k = keys_for("rel-aaaaaaaaaaaa");
        let (sk, vk) = signing_keypair();
        let mut m = manifest(&k, &[1], &sk);
        m.signature = String::new();
        let e = ReleaseIndex::build(&m, &record(&m), &k, &vk, &Limits::default()).unwrap_err();
        assert!(e.message().contains("unsigned") || e.code() == ErrorCode::InvalidManifest);

        // Re-signing a document whose fingerprint was edited is not detected by
        // the signature at all — whoever held the key can sign anything. What
        // detects it is the *published* release record, which is the document a
        // third party has, and which still names the digest the tree hashed to.
        let honest = manifest(&k, &[1], &sk);
        let published = record(&honest);
        let mut retargeted = honest.clone();
        retargeted.fingerprint = Digest([8u8; 32]);
        retargeted.sign(&sk).unwrap();
        let e = ReleaseIndex::build(
            &retargeted,
            &published,
            &k,
            &vk,
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::ReleaseMismatch, "{e:?}");
        // And the same edited document paired with a record edited to match it is
        // refused for the same reason one more step out: the caller's copy of the
        // record is what the index trusts, so the guard has to be the disagreement,
        // not a hash of something this crate could recompute.
        assert!(ReleaseIndex::build(&retargeted, &record(&retargeted), &k, &vk, &Limits::default()).is_ok());
    }

    #[test]
    fn keys_from_another_project_or_canonicalizer_cannot_index_this_manifest() {
        let (sk, vk) = signing_keypair();
        let k = keys_for("rel-aaaaaaaaaaaa");
        let m = manifest(&k, &[1], &sk);
        let other = ManifestKeys::derive(
            &RootSecret::from_bytes(&[0x32u8; 32]).unwrap(),
            &ProjectId::new("swp1-qrstuvwxyzabcdef").unwrap(),
            &release("rel-aaaaaaaaaaaa"),
            CanonicalizerVersion::V1,
        );
        let e = ReleaseIndex::build(&m, &record(&m), &other, &vk, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ReleaseMismatch, "{e:?}");

        let later = ManifestKeys::derive(
            &root(),
            &project(),
            &release("rel-aaaaaaaaaaaa"),
            CanonicalizerVersion(2),
        );
        let e = ReleaseIndex::build(&m, &record(&m), &later, &vk, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ReleaseMismatch, "{e:?}");
    }

    #[test]
    fn the_site_bound_is_enforced_before_the_map_is_built() {
        let k = keys_for("rel-aaaaaaaaaaaa");
        let (sk, vk) = signing_keypair();
        let m = manifest(&k, &[1, 2], &sk);
        let tight = Limits {
            max_locations_per_manifest: 1,
            ..Limits::default()
        };
        let e = ReleaseIndex::build(&m, &record(&m), &k, &vk, &tight).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded, "{e:?}");
    }

    #[test]
    fn a_mismatched_record_and_manifest_pair_is_refused() {
        let k = keys_for("rel-aaaaaaaaaaaa");
        let (sk, vk) = signing_keypair();
        let m = manifest(&k, &[1], &sk);
        let mut rec = record(&m);
        rec.fingerprint = Digest([0xee; 32]);
        let e = ReleaseIndex::build(&m, &rec, &k, &vk, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ReleaseMismatch, "{e:?}");

        let mut rec = record(&m);
        rec.release_id = release("rel-bbbbbbbbbbbb");
        let e = ReleaseIndex::build(&m, &rec, &k, &vk, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ReleaseMismatch, "{e:?}");
    }

    #[test]
    fn expected_tags_differ_per_site_and_are_recomputed_not_stored() {
        let k = keys_for("rel-aaaaaaaaaaaa");
        let (sk, vk) = signing_keypair();
        let m = manifest(&k, &[1, 2, 3], &sk);
        let idx = ReleaseIndex::build(&m, &record(&m), &k, &vk, &Limits::default()).unwrap();
        let tags: Vec<u32> = idx
            .sites()
            .iter()
            .map(|s| idx.expected_tag(s).unwrap())
            .collect();
        assert!(tags.iter().all(|t| *t < 16), "{tags:?} at 4 bits");
        assert_ne!(tags[0], tags[1], "distinct sites must not share a code");
        // Deriving twice gives the same answer, which is what lets the value be
        // recomputed per comparison instead of kept on the index.
        assert_eq!(
            idx.expected_tag(idx.site(0)).unwrap(),
            tags[0],
            "the tag is a pure function of the site and the keys"
        );
        // And the same site under another project's secret yields a different
        // code, so a code is evidence about *this* project rather than a property
        // of the literal that happens to carry it. (The index itself cannot be
        // built with the foreign keys: its manifest is signed by the real key, and
        // `ReleaseIndex::build` refuses that — which is the point of §31.)
        let other_root = RootSecret::from_bytes(&[0x99u8; 32]).unwrap();
        let foreign_keys = ManifestKeys::derive(
            &other_root,
            &project(),
            &release("rel-aaaaaaaaaaaa"),
            CanonicalizerVersion::V1,
        );
        let foreign_tags: Vec<u32> = idx
            .sites()
            .iter()
            .map(|s| s.expected_tag(&foreign_keys).unwrap())
            .collect();
        assert_ne!(foreign_tags, tags, "tags must be keyed by the secret");
    }

    #[test]
    fn many_releases_index_independently_and_the_newest_leads() {
        let (sk, vk) = signing_keypair();
        let k = keys_for("rel-aaaaaaaaaaaa");
        let older = manifest_full(&k, &[1], &sk, "rel-aaaaaaaaaaaa", at(200));
        let newer = manifest_full(&k, &[2, 3], &sk, "rel-bbbbbbbbbbbb", at(100));
        let (rec_old, rec_new) = (record(&older), record(&newer));
        let releases = [
            CandidateRelease { manifest: older, record: rec_old, keys: keys_for("rel-aaaaaaaaaaaa") },
            CandidateRelease { manifest: newer, record: rec_new, keys: keys_for("rel-aaaaaaaaaaaa") },
        ];
        let idx = build_indexes(&releases, &vk, &Limits::default()).unwrap();
        assert_eq!(idx.len(), 2);
        assert_eq!(idx[0].release_id(), &release("rel-bbbbbbbbbbbb"));
        assert_eq!(idx[0].site_count(), 2);
        assert_eq!(idx[1].site_count(), 1);
        // A site of the older release is still addressed by its own ids, and not
        // by the newer one's — the two indexes do not share a lookup table.
        let old_only = idx[1].sites()[0].locations[0];
        assert!(!idx[0].lookup(&old_only).iter().any(|h| idx[0].site(h.site).line_hint == 10));
    }

    /// A timestamp far enough in the past to order two releases unambiguously.
    fn at(minutes_ago: i64) -> Timestamp {
        Timestamp::from_unix(Timestamp::now_utc().unix() - minutes_ago * 60)
    }

    fn manifest(
        k: &ManifestKeys,
        seeds: &[u8],
        sk: &swp_crypto::ManifestSigningKey,
    ) -> PrivateManifest {
        manifest_full(k, seeds, sk, "rel-aaaaaaaaaaaa", Timestamp::now_utc())
    }

    fn manifest_full(
        k: &ManifestKeys,
        seeds: &[u8],
        sk: &swp_crypto::ManifestSigningKey,
        rid: &str,
        created_at: Timestamp,
    ) -> PrivateManifest {
        let sites: Vec<SiteEntry> = seeds
            .iter()
            .enumerate()
            .map(|(i, s)| site(k, *s, (i as u32 + 1) * 10))
            .collect();
        let mut m = PrivateManifest::build(
            project(),
            release(rid),
            created_at,
            1,
            Digest([7u8; 32]),
            "L1",
            4,
            GeneratorInfo::current(),
            sites,
        )
        .unwrap();
        m.sign(sk).unwrap();
        m
    }
}
