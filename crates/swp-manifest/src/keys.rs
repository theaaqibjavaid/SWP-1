//! Key derivation for manifests: which site is this, what must it carry, and
//! which sites a release picks.
//!
//! Three keys, three purposes, never mixed — `hmac_keyed` in `swp-crypto`
//! refuses a key whose domain does not match the derivation it is used in, so a
//! mix-up is a loud internal error rather than a quiet wrong answer:
//!
//! | key | domain | inputs | answers |
//! |---|---|---|---|
//! | site key | `project` | project id, canonicalizer version | "which site is this?" |
//! | tag key | `location` | project id | "what value must this site carry?" |
//! | selection key | `selection` | project id, release id, canonicalizer version | "which sites does this release use?" |
//!
//! The canonicalizer version is an input to two of the three, for the reason
//! [`ManifestKeys::derive`] gives: a canonicalizer change is meant to rename
//! every site. The tag key takes no version because its message already carries
//! a location id, and that id is a keyed digest of text canonicalized under one
//! version — the version reaches the tag through it rather than beside it.
//!
//! The asymmetry is deliberate. Location ids and fragment tags are keyed by the
//! *project* only, so re-protecting a project keeps every unchanged site's
//! watermark intact and each release adds coverage instead of rotating it.
//! Selection is keyed by the release too, because which sites a release happens
//! to use is release-specific information and a second release should reach a
//! different, still reproducible, constellation.

use swp_core::id::{Digest, LocationId, ProjectId, ReleaseId};
use swp_core::site::{RadiusKind, TagWidth};
use swp_core::CanonicalizerVersion;
use swp_crypto::{derive_key, hmac_keyed, truncate_bits, DerivedKey, Domain, RootSecret};

/// The radius kinds in manifest order. Spelled out rather than taken from
/// [`RadiusKind::all`] because a manifest's slot layout is a wire format: a test
/// asserts this stays equal to `all()`, but the order it *documents* is the one
/// that must not drift.
pub const SLOTS: [RadiusKind; 4] = [
    RadiusKind::StatementId,
    RadiusKind::ScopeId,
    RadiusKind::StatementRaw,
    RadiusKind::ScopeRaw,
];

/// Everything a manifest needs from the root secret, held for one project and
/// one release.
///
/// `Debug` is implemented by hand and names no key bytes: the values that appear
/// in reports are the ids and tags, never the keys that produce them.
pub struct ManifestKeys {
    project_id: ProjectId,
    release_id: ReleaseId,
    canonicalizer: u16,
    site_key: DerivedKey,
    tag_key: DerivedKey,
    selection_key: DerivedKey,
}

impl std::fmt::Debug for ManifestKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestKeys")
            .field("project_id", &self.project_id)
            .field("release_id", &self.release_id)
            .field("canonicalizer", &self.canonicalizer)
            .finish_non_exhaustive()
    }
}

impl ManifestKeys {
    /// Derive the three keys. `canonicalizer` must be the version recorded in
    /// the project identity, because it is mixed into every location id: a
    /// canonicalizer change renames every site on purpose, so that a manifest
    /// built under the old rules reports "cannot verify" instead of
    /// accidentally reporting "no evidence".
    pub fn derive(
        root: &RootSecret,
        project_id: &ProjectId,
        release_id: &ReleaseId,
        canonicalizer: CanonicalizerVersion,
    ) -> Self {
        let pid = project_id.as_str().as_bytes();
        let rid = release_id.as_str().as_bytes();
        let ver = canonicalizer.0.to_be_bytes();
        ManifestKeys {
            project_id: project_id.clone(),
            release_id: release_id.clone(),
            canonicalizer: canonicalizer.0,
            site_key: derive_key(root, Domain::Project, &[pid, &ver]),
            tag_key: derive_key(root, Domain::Location, &[pid]),
            selection_key: derive_key(root, Domain::Selection, &[pid, rid, &ver]),
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    pub fn canonicalizer_version(&self) -> u16 {
        self.canonicalizer
    }

    /// The keyed identity of one site at one radius.
    ///
    /// `canonical` is the SHA-256 of the site's canonical text at the radius's
    /// level, with the site itself replaced by `<SITE>` — so it is the shape of
    /// the surrounding statement or scope that identifies the site, not the
    /// literal in it, and not the file it lives in.
    pub fn location_id(&self, radius: RadiusKind, canonical: &Digest) -> LocationId {
        let mac = hmac_keyed(
            &self.site_key,
            Domain::Project,
            &[
                self.project_id.as_str().as_bytes(),
                &[radius.code()],
                self.canonicalizer.to_be_bytes().as_slice(),
                canonical.as_bytes(),
            ],
        )
        .expect("site key is a project-domain key");
        // 128 bits: the birthday bound is 2^64 sites, far past any repository,
        // and a collision would have to be *inside one project* to matter.
        LocationId::from_bytes(&mac[..16]).expect("HMAC output is 32 bytes")
    }

    /// All four keys for one site, in [`SLOTS`] order. Every site stores all
    /// four because a copy that was renamed, reformatted, or had its enclosing
    /// function inlined matches a different subset of them.
    pub fn location_ids(&self, canonical: &[Digest; 4]) -> [LocationId; 4] {
        let mut out = [LocationId::default(); 4];
        for (i, kind) in SLOTS.iter().enumerate() {
            out[i] = self.location_id(*kind, &canonical[i]);
        }
        out
    }

    /// The value a site must carry: `width` bits taken off a keyed MAC over its
    /// primary location id, by [`truncate_bits`]. This is the §8
    /// `F = HMAC(project_key, location)`, with a truncation wide enough to be a
    /// fragment and narrow enough that a literal can hold it.
    ///
    /// The width is inside the MAC input, so a project that later raises its
    /// tag width gets an *independent* value per site rather than a wider view
    /// of the same one — and an old copy carrying the old rendering is reported
    /// as not matching the new manifest, which is true, instead of accidentally
    /// half-matching it. Every manifest states its own width per site, so a
    /// scanner never has to guess which of the two it is looking at.
    pub fn fragment_tag(&self, primary: &LocationId, width: TagWidth) -> u32 {
        let mac = hmac_keyed(
            &self.tag_key,
            Domain::Location,
            &[
                self.project_id.as_str().as_bytes(),
                primary.as_bytes(),
                &[width.bits()],
            ],
        )
        .expect("tag key is a location-domain key");
        truncate_bits(&mac, width.bits())
    }

    /// A deterministic pseudo-random priority for each candidate site, used to
    /// pick the release's constellation. Sorting by this rather than by path
    /// order means the chosen sites are spread through the project instead of
    /// clustering at the front of the file list, and that the same project under
    /// the same release id always yields the same constellation.
    ///
    /// It is keyed over the site's *whole* identity, all four radius keys at once,
    /// rather than over one of them. A repetitive codebase can give a dozen
    /// statements the same L3 statement key — `return sum + 0;` rewritten under any
    /// name is the same canonical statement — and a priority derived from that key
    /// alone would rank all twelve identically, which degenerates to file order and
    /// makes the selection stop being release-scoped.
    ///
    /// It is keyed by the release, so a second `swp protect` reaches a different
    /// set. It is not secret: knowing a site's priority tells an attacker which
    /// sites were used, which the manifest already says, and not what they carry.
    pub fn selection_priority(&self, locations: &[LocationId; 4]) -> [u8; 32] {
        let mut identity = [0u8; 64];
        for (i, id) in locations.iter().enumerate() {
            identity[i * 16..(i + 1) * 16].copy_from_slice(id.as_bytes());
        }
        hmac_keyed(
            &self.selection_key,
            Domain::Selection,
            &[
                self.project_id.as_str().as_bytes(),
                self.release_id.as_str().as_bytes(),
                &identity,
            ],
        )
        .expect("selection key is a selection-domain key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::id::hex_encode;
    use swp_core::CanonicalizerVersion;
    use swp_crypto::derive::constant_time_eq;

    fn root() -> RootSecret {
        RootSecret::from_bytes(&[0x44u8; 32]).unwrap()
    }

    fn project() -> ProjectId {
        ProjectId::new("swp1-abcdefghijklmnop").unwrap()
    }

    fn release(n: u8) -> ReleaseId {
        ReleaseId::new(format!("rel-{}", base32(n))).unwrap()
    }

    fn base32(n: u8) -> String {
        swp_core::base32_lower(&[n, n, n, n, n, n, n, n])
    }

    fn keys() -> ManifestKeys {
        ManifestKeys::derive(&root(), &project(), &release(1), CanonicalizerVersion::V1)
    }

    fn digest(b: u8) -> Digest {
        Digest([b; 32])
    }

    #[test]
    fn derivation_is_reproducible() {
        let a = keys().location_id(RadiusKind::StatementId, &digest(1));
        let b = ManifestKeys::derive(&root(), &project(), &release(1), CanonicalizerVersion::V1)
            .location_id(RadiusKind::StatementId, &digest(1));
        assert_eq!(a, b);
    }

    /// The property the whole release story rests on: a site keeps its identity
    /// and its value across releases of the same project, so protecting twice
    /// never rotates a watermark an existing copy still carries.
    #[test]
    fn location_ids_and_tags_are_release_independent() {
        for id in [digest(2), digest(3)] {
            let a = keys().location_id(RadiusKind::ScopeId, &id);
            let b =
                ManifestKeys::derive(&root(), &project(), &release(9), CanonicalizerVersion::V1)
                    .location_id(RadiusKind::ScopeId, &id);
            assert_eq!(a, b);
            let w = TagWidth::DEFAULT;
            assert_eq!(
                keys().fragment_tag(&a, w),
                ManifestKeys::derive(&root(), &project(), &release(9), CanonicalizerVersion::V1,)
                    .fragment_tag(&b, w)
            );
        }
    }

    #[test]
    fn radius_kind_is_part_of_the_identity() {
        let d = digest(4);
        let k = keys();
        let mut seen = std::collections::BTreeSet::new();
        for r in SLOTS {
            assert!(
                seen.insert(k.location_id(r, &d).hex()),
                "two radii agreed on the same id"
            );
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn site_content_is_part_of_the_identity() {
        let k = keys();
        assert_ne!(
            k.location_id(RadiusKind::StatementId, &digest(1)),
            k.location_id(RadiusKind::StatementId, &digest(2))
        );
    }

    /// Changing the canonicalizer version must rename every site: it is the
    /// difference between "these digests mean something different now" and a
    /// silent mismatch against an old manifest.
    #[test]
    fn canonicalizer_version_is_part_of_the_identity() {
        let v1 = keys();
        let v2 = ManifestKeys::derive(&root(), &project(), &release(1), CanonicalizerVersion(2));
        assert_ne!(
            v1.location_id(RadiusKind::StatementId, &digest(5)),
            v2.location_id(RadiusKind::StatementId, &digest(5))
        );
    }

    #[test]
    fn different_projects_do_not_share_ids_or_tags() {
        let other = ProjectId::new("swp1-bbbbbbbbbbbbbbbb").unwrap();
        let k = ManifestKeys::derive(&root(), &other, &release(1), CanonicalizerVersion::V1);
        let own = keys();
        let d = digest(6);
        assert_ne!(
            own.location_id(RadiusKind::StatementId, &d),
            k.location_id(RadiusKind::StatementId, &d)
        );
        let id = own.location_id(RadiusKind::StatementId, &d);
        let w = TagWidth::DEFAULT;
        assert_ne!(own.fragment_tag(&id, w), k.fragment_tag(&id, w));
    }

    #[test]
    fn a_different_root_secret_gives_a_different_watermark() {
        let k = ManifestKeys::derive(
            &RootSecret::from_bytes(&[0x45u8; 32]).unwrap(),
            &project(),
            &release(1),
            CanonicalizerVersion::V1,
        );
        let d = digest(7);
        assert_ne!(
            keys().location_id(RadiusKind::StatementId, &d),
            k.location_id(RadiusKind::StatementId, &d)
        );
    }

    #[test]
    fn tags_fit_their_width_and_are_independent_per_width() {
        let id = keys().location_id(RadiusKind::StatementId, &digest(8));
        let mut independent = false;
        for bits in 2..=8u8 {
            let w = TagWidth::new(bits).unwrap();
            let tag = keys().fragment_tag(&id, w);
            assert!(tag < (1u32 << bits), "{bits}-bit tag {tag} overflowed");
            // Width is inside the MAC input, so widths are independent values:
            // a 4-bit tag must not be predictable from an 8-bit one.
            for other in 2..=8u8 {
                if other == bits {
                    continue;
                }
                let o = keys().fragment_tag(&id, TagWidth::new(other).unwrap());
                if o != tag {
                    independent = true;
                }
            }
        }
        assert!(
            independent,
            "every width produced the same value, so the width is not in the derivation"
        );
    }

    /// The four keys of one site, from four different radius digests.
    fn site_ids(k: &ManifestKeys, seed: u8) -> [LocationId; 4] {
        let mut digests = [digest(0); 4];
        for (i, d) in digests.iter_mut().enumerate() {
            *d = digest(seed.wrapping_add(i as u8));
        }
        k.location_ids(&digests)
    }

    #[test]
    fn selection_priorities_are_distinct_and_stable() {
        let k = keys();
        let mut set = std::collections::BTreeSet::new();
        for i in 0..64u8 {
            let ids = site_ids(&k, i);
            let p = k.selection_priority(&ids);
            assert!(set.insert(hex_encode(&p)));
            assert!(constant_time_eq(&p, &k.selection_priority(&ids)));
        }
        assert_eq!(set.len(), 64);
        let release2 =
            ManifestKeys::derive(&root(), &project(), &release(2), CanonicalizerVersion::V1);
        let ids = site_ids(&k, 0);
        assert_ne!(
            k.selection_priority(&ids),
            release2.selection_priority(&ids),
            "keyed by the release as well: a second protect picks a different set"
        );
    }

    /// The reason the priority reads all four keys instead of the primary one. A
    /// repetitive codebase hands dozens of statements the same L3 canonical text,
    /// and a priority from that key alone would rank them identically — the
    /// selection would fall back to file order and stop being release-scoped.
    #[test]
    fn sites_that_share_one_radius_key_still_rank_apart() {
        let k = keys();
        let mut twin = site_ids(&k, 0);
        let shared = twin[RadiusKind::StatementId.code() as usize];
        for id in twin.iter_mut() {
            *id = shared;
        }
        assert_eq!(
            twin.iter().collect::<std::collections::BTreeSet<_>>().len(),
            1,
            "the twin is the same site at every radius"
        );
        twin[RadiusKind::ScopeRaw.code() as usize] =
            k.location_id(RadiusKind::ScopeRaw, &digest(200));
        assert_ne!(
            k.selection_priority(&site_ids(&k, 0)),
            k.selection_priority(&twin)
        );
    }

    #[test]
    fn debug_never_prints_key_material() {
        let rendered = format!("{:?}", keys());
        for field in ["project_id", "release_id"] {
            assert!(rendered.contains(field));
        }
        assert!(!rendered.contains("Key("), "{rendered}");
        // The check-value handle is the only rendering of key material that is
        // safe to print, and it is not a path back to a key; the Debug impl here
        // must print neither it nor anything derived from the bytes.
        assert!(!rendered.contains(&root().fingerprint()), "{rendered}");
    }
    /// A pinned vector, computed once with an independent Python
    /// `hmac`/`hashlib` implementation of the encoding in `swp-crypto`, so it
    /// pins the construction rather than this code's reading of it. If it ever
    /// fails, every manifest an earlier build wrote is unverifiable — which is
    /// exactly why it is pinned.
    #[test]
    fn pinned_site_identity_vector() {
        let k = keys();
        let id = k.location_id(RadiusKind::StatementId, &digest(0xab));
        assert_eq!(id.hex(), "2c6c0f36efde2eef56dac84be63f7224");
        let tag = k.fragment_tag(&id, TagWidth::DEFAULT);
        assert_eq!(tag, 15);
    }

    /// A module-level site in a short file canonicalizes the same at both
    /// radii. The radius code in the derivation is what keeps its four keys
    /// distinct, so a manifest's slot layout can never be ambiguous.
    #[test]
    fn equal_canonical_text_at_two_radii_gives_two_different_ids() {
        let k = keys();
        let d = digest(0x5a);
        let mut seen = std::collections::BTreeSet::new();
        for r in SLOTS {
            assert!(seen.insert(k.location_id(r, &d).hex()));
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn manifest_slots_are_the_protocol_radii_in_order() {
        assert_eq!(SLOTS, RadiusKind::all());
        let codes: Vec<u8> = SLOTS.iter().map(|k| k.code()).collect();
        assert_eq!(codes, vec![0, 1, 2, 3]);
    }
}
