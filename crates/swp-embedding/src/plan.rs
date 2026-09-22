//! The plan: what this run intended, written before any of it happened.
//!
//! The brief asks for the operator to be able to answer "what did the tool
//! decide?" after the fact, and the manifest cannot answer it — the manifest is
//! the record of what was *embedded*, and between the two sit every site
//! selection refused and every rewrite the adapter would not prove. Those
//! refusals are the interesting part of a protection run: they are why a release
//! has fourteen sites when the config asked for twenty.
//!
//! So the plan is the intent document, and it is deliberately weaker than the
//! manifest in one specific way: **it holds no literal text and no tag.** The
//! §18 vocabulary appears only in the manifest, which is signed for exactly that
//! reason. A plan that also carried renderings would be a second document claiming
//! to describe the release, and the two would drift the moment one was edited by
//! hand. What the plan can say and the manifest cannot is what was *not* done, and
//! why.
//!
//! It is unsigned, and stays under `.swp/private/`. It is an operator log, not
//! evidence: signing it would imply a claim about the release that only the
//! manifest is in a position to make.

use serde::{Deserialize, Serialize};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::{LocationId, ProjectId, ReleaseId};
use swp_core::site::{FormFamily, LiteralClass, RadiusKind};
use swp_core::{canonical_relpath, GeneratorInfo, Limits, SchemaVersion, SWP_PROTOCOL_NAME};
use swp_identity::{ProtectConfig, Timestamp};

use crate::apply::Applied;
use crate::candidates::Scan;
use crate::select::Selection;

/// One site the run meant to embed, and everything known about it that is not its
/// content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSite {
    /// Canonical project-relative path.
    pub file: String,
    /// 1-based line in the *protected* text, which is where a reader will look.
    /// A hint only; nothing keyed reads it.
    pub line_hint: u32,
    pub language: String,
    /// `"ast"` or `"lexical"`.
    pub adapter: String,
    /// `integer` or `string`.
    pub class: String,
    /// The equivalent-form family that carried the tag.
    pub family: String,
    pub width: u8,
    /// `RadiusKind` code of the key the tag derived from.
    pub primary: u8,
    /// The site's four keyed identities, in manifest slot order. Present so a
    /// reader can confirm a plan and a manifest agree; the manifest is the one
    /// that is signed.
    pub locations: [LocationId; 4],
}

/// One candidate the run did not use, and the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedSite {
    pub file: String,
    pub line_hint: u32,
    /// A stable token for tooling: `overlapping-radius`, `constellation-full`,
    /// `changed-after-scan` and so on.
    pub reason: String,
    /// The sentence a report prints.
    pub detail: String,
}

/// What one `swp protect` decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub protocol: String,
    pub schema: u16,
    pub project_id: ProjectId,
    pub release_id: ReleaseId,
    pub created_at: Timestamp,
    pub canonicalizer_version: u16,
    pub generator: GeneratorInfo,
    /// The scope this run read, as configured, so a plan explains a release even
    /// after the config has been edited.
    pub targets: Vec<String>,
    pub excludes: Vec<String>,
    pub tag_bits: u8,
    pub embed_strings: bool,
    /// What was asked for, before ceilings.
    pub requested_sites: u32,
    /// What the ceilings allowed.
    pub target_sites: u32,
    pub sites: Vec<PlannedSite>,
    pub skipped: Vec<SkippedSite>,
    /// Everything the walk and the scan reported but did not act on: files
    /// omitted, per-file caps, resource limits in force.
    pub notes: Vec<String>,
}

impl Plan {
    /// Assemble the intent of one run from the three passes that produced it.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        project_id: ProjectId,
        release_id: ReleaseId,
        created_at: Timestamp,
        canonicalizer_version: u16,
        generator: GeneratorInfo,
        cfg: &ProtectConfig,
        requested_sites: u32,
        scan: &Scan,
        selection: &Selection,
        applied: &Applied,
    ) -> Result<Plan, SwpError> {
        let excludes: Vec<String> = crate::walk::effective_excludes(cfg);
        let mut sites: Vec<PlannedSite> = Vec::with_capacity(applied.entries.len());
        for entry in &applied.entries {
            sites.push(PlannedSite {
                file: entry.file.clone(),
                line_hint: entry.line_hint,
                language: entry.language.clone(),
                adapter: entry.adapter.clone(),
                class: class_label(entry.class).to_string(),
                family: family_label(entry.family).to_string(),
                width: entry.width,
                primary: entry.primary,
                locations: entry.locations,
            });
        }
        let mut skipped: Vec<SkippedSite> = Vec::new();
        for drop in &applied.dropped {
            skipped.push(SkippedSite {
                file: drop.file.clone(),
                line_hint: drop.line_hint,
                reason: "refused-by-validation".to_string(),
                detail: drop.reason.clone(),
            });
        }
        for skip in &selection.skipped {
            // The shortfall line is the one record in the selection that names no
            // candidate, and a plan that dropped it would read as a request the
            // tree happened to satisfy.
            if skip.file.is_empty() {
                continue;
            }
            skipped.push(SkippedSite {
                file: skip.file.clone(),
                line_hint: skip.line_hint,
                reason: skip.reason.as_str().to_string(),
                detail: skip.note.clone(),
            });
        }
        let mut notes: Vec<String> = scan.notes.clone();
        for omission in &scan.omissions {
            notes.push(format!("{}: {}", omission.path, omission.reason));
        }
        if let Some(shortfall) = selection
            .skipped
            .iter()
            .find(|s| s.file.is_empty() && !s.note.is_empty())
        {
            notes.push(shortfall.note.clone());
        }
        let plan = Plan {
            protocol: SWP_PROTOCOL_NAME.to_string(),
            schema: SchemaVersion::PLAN_V1.0,
            project_id,
            release_id,
            created_at,
            canonicalizer_version,
            generator,
            targets: cfg.targets.clone(),
            excludes,
            tag_bits: cfg.tag_bits,
            embed_strings: cfg.embed_strings,
            requested_sites,
            target_sites: selection.target as u32,
            sites,
            skipped,
            notes,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), SwpError> {
        if self.protocol != SWP_PROTOCOL_NAME {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("plan declares protocol {:?}", self.protocol),
            ));
        }
        if self.schema != SchemaVersion::PLAN_V1.0 {
            return Err(SwpError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!("plan schema {} is not supported", self.schema),
            ));
        }
        let ceiling = u64::from(Limits::ceiling().max_locations_per_manifest);
        if self.sites.len() as u64 > ceiling || self.skipped.len() as u64 > ceiling {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                "plan lists more sites than a manifest may hold".to_string(),
            ));
        }
        if self.sites.is_empty() && self.skipped.is_empty() {
            // Nothing planned and nothing refused is not a decision anybody should
            // be able to write down; it means a pass produced no report at all.
            return Err(SwpError::new(
                ErrorCode::Internal,
                "plan records neither a site nor a refusal".to_string(),
            ));
        }
        for site in &self.sites {
            if site.file != canonical_relpath(&site.file) {
                return Err(SwpError::invalid_manifest(format!(
                    "planned file {:?} is not a canonical relative path",
                    site.file
                )));
            }
            if site.line_hint == 0 || site.width < 2 || site.width > 8 {
                return Err(SwpError::invalid_manifest(
                    "planned site has a zero line hint or an unsupported tag width".to_string(),
                ));
            }
            RadiusKind::from_code(site.primary).map_err(|e| {
                SwpError::invalid_manifest(format!("planned site: {}", e.message()))
            })?;
            if !matches!(site.adapter.as_str(), "ast" | "lexical") {
                return Err(SwpError::invalid_manifest(format!(
                    "planned site names unknown adapter {:?}",
                    site.adapter
                )));
            }
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut s = serde_json::to_string_pretty(self).expect("plan is serializable by shape");
        s.push('\n');
        s.into_bytes()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Plan, SwpError> {
        let text = swp_core::text::decode_utf8_strict(bytes)
            .ok_or_else(|| SwpError::invalid_manifest("plan is not valid UTF-8"))?;
        let plan: Plan = serde_json::from_str(text)
            .map_err(|e| SwpError::invalid_manifest(format!("plan: {e}")))?;
        plan.validate()?;
        Ok(plan)
    }

    /// Every file this run planned to touch, in path order.
    pub fn touched_files(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = self.sites.iter().map(|s| s.file.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }
}

fn class_label(class: LiteralClass) -> &'static str {
    match class {
        LiteralClass::Integer => "integer",
        LiteralClass::String => "string",
    }
}

fn family_label(family: FormFamily) -> &'static str {
    family.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::select::SkipReason;
    use swp_core::limits::Limits;
    use swp_core::version::CanonicalizerVersion;
    use swp_core::GeneratorInfo;
    use swp_crypto::RootSecret;
    use swp_identity::ProtectConfig;

    fn temp(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-plan-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    fn keys(release: &str) -> swp_manifest::ManifestKeys {
        swp_manifest::ManifestKeys::derive(
            &RootSecret::from_bytes(&[11u8; 32]).unwrap(),
            &ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            &ReleaseId::new(release).unwrap(),
            CanonicalizerVersion::V1,
        )
    }

    /// Scan, select and apply over a small module, then build the plan for it.
    ///
    /// The module holds six addressable sites and the markdown file holds no site
    /// at all — it is a file the run saw and could not use — so a run over this
    /// tree has something to place and something to explain.
    fn built(label: &str, target: u32) -> (Plan, Scan, Selection, Applied) {
        let root = temp(label);
        let mut body = String::new();
        for s in 0..6 {
            body.push_str(&format!(
                "function calc_{s}(base, scale) {{\n  return base * scale + {};\n}}\n",
                1000 + s
            ));
        }
        std::fs::write(root.join("src/a.js"), &body).unwrap();
        std::fs::write(root.join("src/readme.md"), "# Notes\n").unwrap();
        let cfg = ProtectConfig::default();
        let limits = Limits::default();
        let k = keys("rel-aaaaaaaaaaaa");
        let walked = crate::walk::walk(&root, &cfg, &limits).unwrap();
        let scan = crate::candidates::scan(
            &root,
            &walked,
            &k,
            &cfg,
            swp_core::TagWidth::DEFAULT,
            &limits,
        )
        .unwrap();
        let selection = crate::select::select(&scan, target, &limits).unwrap();
        let applied = crate::apply::apply(
            &root,
            &scan,
            &selection,
            &k,
            swp_core::TagWidth::DEFAULT,
            &limits,
        )
        .unwrap();
        let plan = Plan::build(
            ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            Timestamp::now_utc(),
            CanonicalizerVersion::V1.0,
            GeneratorInfo::current(),
            &cfg,
            target,
            &scan,
            &selection,
            &applied,
        )
        .unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        (plan, scan, selection, applied)
    }

    #[test]
    fn a_plan_round_trips_through_the_bytes_the_store_writes() {
        let (plan, _, _, _) = built("roundtrip", 6);
        let bytes = plan.to_json_bytes();
        let back = Plan::from_json_bytes(&bytes).unwrap();
        assert_eq!(back, plan);
    }

    /// The line this crate exists to hold: a plan describes where and why, and
    /// never what. A rendering in a plan would be an unsigned second opinion about
    /// a signed document.
    #[test]
    fn a_plan_names_no_literal_text_and_no_tag() {
        let (plan, _, _, applied) = built("no-content", 6);
        let json = String::from_utf8(plan.to_json_bytes()).unwrap();
        for field in ["rendered", "original", "tag", "code", "fragment", "value"] {
            assert!(
                !json.contains(&format!("\"{field}\"")),
                "the plan carries a {field} field"
            );
        }
        assert_eq!(applied.sites(), plan.sites.len());
        for entry in &applied.entries {
            assert!(
                !json.contains(&entry.rendered),
                "the plan repeats a rendering"
            );
        }
    }

    #[test]
    fn every_site_and_every_refusal_the_run_made_appears_in_the_plan() {
        let (plan, scan, selection, applied) = built("account", 3);
        assert_eq!(plan.sites.len(), applied.sites());
        let refused = selection
            .skipped
            .iter()
            .filter(|s| !s.file.is_empty())
            .count()
            + applied.dropped.len();
        assert_eq!(plan.skipped.len(), refused);
        assert_eq!(plan.target_sites, 3);
        assert_eq!(plan.requested_sites, 3);
        // A file no adapter claims is a note, not a skip: no candidate was ever
        // offered for it, so there is no site to explain the refusal of.
        assert!(
            plan.notes.iter().any(|n| n.contains("readme.md")),
            "{:?}",
            plan.notes
        );
        assert_eq!(plan.sites[0].width, swp_core::TagWidth::DEFAULT.bits());
        assert_eq!(scan.files.len(), 1, "{:?}", scan.files);
    }

    #[test]
    fn a_shortfall_reaches_the_plan_as_one_note_about_the_request() {
        // Nine sites requested from a tree that holds six, and the plan has to say
        // so — a plan that only listed six would read as a satisfied request.
        let (plan, _, _, _) = built("short", 9);
        assert_eq!(plan.sites.len(), 6);
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("6 of 9 requested sites placed")),
            "{:?}",
            plan.notes
        );
    }

    #[test]
    fn a_plan_records_the_scope_it_read_not_just_the_files_it_touched() {
        let (plan, _, _, _) = built("scope", 4);
        assert_eq!(plan.targets, vec!["src".to_string()]);
        assert!(plan.excludes.iter().any(|e| e.contains("node_modules")));
        assert!(plan.excludes.iter().any(|e| e.contains(".swp")));
        assert_eq!(plan.tag_bits, 4);
        assert!(plan.embed_strings);
        assert_eq!(plan.canonicalizer_version, CanonicalizerVersion::V1.0);
        assert_eq!(plan.generator.generator, "swp-cli");
        assert!(!plan.generator.swp_version.is_empty());
        assert_eq!(plan.protocol, SWP_PROTOCOL_NAME);
        assert_eq!(plan.schema, SchemaVersion::PLAN_V1.0);
    }

    #[test]
    fn touched_files_are_the_planned_rewrites_without_repetition() {
        let root = temp("touched");
        for f in ["a", "b", "c"] {
            std::fs::write(
                root.join(format!("src/{f}.js")),
                "function one(v) {\n  return v + 1000;\n}\nfunction two(v) {\n  return v + 2000;\n}\n",
            )
            .unwrap();
        }
        let cfg = ProtectConfig::default();
        let limits = Limits::default();
        let k = keys("rel-aaaaaaaaaaaa");
        let walked = crate::walk::walk(&root, &cfg, &limits).unwrap();
        let scan = crate::candidates::scan(
            &root,
            &walked,
            &k,
            &cfg,
            swp_core::TagWidth::DEFAULT,
            &limits,
        )
        .unwrap();
        let selection = crate::select::select(&scan, 6, &limits).unwrap();
        let applied = crate::apply::apply(
            &root,
            &scan,
            &selection,
            &k,
            swp_core::TagWidth::DEFAULT,
            &limits,
        )
        .unwrap();
        let plan = Plan::build(
            ProjectId::new("swp1-abcdefghijklmnop").unwrap(),
            ReleaseId::new("rel-aaaaaaaaaaaa").unwrap(),
            Timestamp::now_utc(),
            CanonicalizerVersion::V1.0,
            GeneratorInfo::current(),
            &cfg,
            6,
            &scan,
            &selection,
            &applied,
        )
        .unwrap();
        let touched = plan.touched_files();
        assert_eq!(touched.len(), applied.files.len());
        assert!(touched.windows(2).all(|w| w[0] <= w[1]), "{touched:?}");
        assert!(touched.iter().all(|f| f.starts_with("src/")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_emptied_plan_is_refused_rather_than_written() {
        let (mut plan, _, _, _) = built("empty", 6);
        plan.sites.clear();
        plan.skipped.clear();
        let e = plan.validate().unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        // One refusal is enough to make the same document a record of a decision:
        // "we planned nothing, and here is the candidate we could not use".
        plan.skipped.push(SkippedSite {
            file: "src/a.js".into(),
            line_hint: 2,
            reason: SkipReason::ConstellationFull.as_str().to_string(),
            detail: "the request was filled elsewhere".to_string(),
        });
        plan.validate().unwrap();
    }

    #[test]
    fn a_plan_that_names_a_field_it_should_not_have_does_not_load() {
        let (plan, _, _, _) = built("unknown", 6);
        let json = String::from_utf8(plan.to_json_bytes()).unwrap();
        let tampered = json.replace("\"schema\":", "\"rendered\": \"x\", \"schema\":");
        let e = Plan::from_json_bytes(tampered.as_bytes()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidManifest, "{e:?}");
    }

    #[test]
    fn planned_locations_agree_with_the_manifest_entries_they_describe() {
        let (plan, _, _, applied) = built("agree", 6);
        for (planned, entry) in plan.sites.iter().zip(&applied.entries) {
            assert_eq!(planned.locations, entry.locations);
            assert_eq!(planned.primary, entry.primary);
            assert_eq!(planned.file, entry.file);
            assert_eq!(planned.line_hint, entry.line_hint);
            assert_eq!(planned.family, entry.family.as_str());
            assert_eq!(planned.class, class_label(entry.class));
        }
    }

    #[test]
    fn a_digest_never_appears_in_a_plan_json() {
        // The plan holds location ids, which are keyed; it must not hold the
        // release fingerprint or the manifest digest, which belong to the record.
        let (plan, _, _, _) = built("digest", 6);
        let json = String::from_utf8(plan.to_json_bytes()).unwrap();
        for field in ["fingerprint", "signature", "private_manifest_digest"] {
            assert!(!json.contains(field), "plan carries a {field} field");
        }
    }
}
