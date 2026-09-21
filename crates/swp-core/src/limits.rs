/// Resource ceilings that keep the scanner safe against hostile input.
///
/// A candidate project is untrusted. Every limit below is enforced before any
/// parse or hash happens, and exceeding one produces `LIMIT_REACHED` — a
/// partial result — never a false `NO_MATCH`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Largest file we will read at all. Larger files are skipped and reported.
    pub max_file_bytes: u64,
    /// Largest file we will hand to an AST parser.
    pub max_parse_bytes: u64,
    /// Largest tree we will keep.
    pub max_nodes_per_tree: u32,
    /// Deepest nesting we will canonicalize.
    pub max_depth: u32,
    /// Wall-clock budget for parsing a single document, in milliseconds.
    pub max_parse_millis: u64,
    /// Largest source tree we will walk.
    pub max_files: u64,
    /// Cumulative bytes read across one operation.
    pub max_total_bytes: u64,
    /// Candidate sites considered per file.
    pub max_sites_per_file: u32,
    pub max_archive_entries: u64,
    pub max_archive_member_bytes: u64,
    pub max_archive_expanded_bytes: u64,
    /// Refuse archives whose expanded/compressed ratio exceeds this.
    pub max_archive_ratio: u64,
    /// How many archive levels the scanner will open. 1 (the default) is "the
    /// container named on the command line and no further": an archive found
    /// inside one is reported as a note, not followed. 0 refuses containers
    /// outright, which is the setting for a scanner that only ever walks trees.
    pub max_archive_depth: u32,
    /// Total location ids a single manifest may hold.
    pub max_locations_per_manifest: u32,
    /// Bound on the region-digest working set; beyond it counting degrades and
    /// the report says so.
    pub max_digest_set_entries: u64,
    /// Shingles kept per structural region.
    pub max_shingles_per_region: u32,
    /// Largest report we will render to stdout before truncating lists.
    pub max_rendered_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_bytes: 8 * 1024 * 1024,
            max_parse_bytes: 4 * 1024 * 1024,
            max_nodes_per_tree: 2_000_000,
            max_depth: 256,
            max_parse_millis: 2_000,
            max_files: 200_000,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_sites_per_file: 4_000,
            max_archive_entries: 10_000,
            max_archive_member_bytes: 64 * 1024 * 1024,
            max_archive_expanded_bytes: 2 * 1024 * 1024 * 1024,
            max_archive_ratio: 200,
            max_archive_depth: 1,
            max_locations_per_manifest: 4_096,
            max_digest_set_entries: 4_000_000,
            max_shingles_per_region: 32_768,
            max_rendered_items: 400,
        }
    }
}

impl Limits {
    /// Absolute ceiling. Configuration may lower a limit but never raise it
    /// above this: the point of the limits is that they cannot be argued away
    /// by a hostile repository's author.
    pub fn ceiling() -> Self {
        Limits {
            max_file_bytes: 64 * 1024 * 1024,
            max_parse_bytes: 32 * 1024 * 1024,
            max_nodes_per_tree: 8_000_000,
            max_depth: 512,
            max_parse_millis: 20_000,
            max_files: 1_000_000,
            max_total_bytes: 64 * 1024 * 1024 * 1024,
            max_sites_per_file: 20_000,
            max_archive_entries: 100_000,
            max_archive_member_bytes: 256 * 1024 * 1024,
            max_archive_expanded_bytes: 16 * 1024 * 1024 * 1024,
            max_archive_ratio: 1000,
            max_archive_depth: 2,
            max_locations_per_manifest: 16_384,
            max_digest_set_entries: 16_000_000,
            max_shingles_per_region: 262_144,
            max_rendered_items: 10_000,
        }
    }

    /// Clamp `self` down to the ceiling, returning the violations found so the
    /// caller can warn about them instead of silently accepting a request for
    /// unsafe limits.
    pub fn clamped_to_ceiling(mut self) -> (Self, Vec<String>) {
        let c = Limits::ceiling();
        let mut v = Vec::new();
        macro_rules! clamp {
            ($field:ident, $name:expr) => {
                if self.$field > c.$field {
                    v.push(format!(
                        "{}: requested {} exceeds hard ceiling {}, using {}",
                        $name, self.$field, c.$field, c.$field
                    ));
                    self.$field = c.$field;
                }
            };
        }
        clamp!(max_file_bytes, "max_file_bytes");
        clamp!(max_parse_bytes, "max_parse_bytes");
        clamp!(max_nodes_per_tree, "max_nodes_per_tree");
        clamp!(max_depth, "max_depth");
        clamp!(max_parse_millis, "max_parse_millis");
        clamp!(max_files, "max_files");
        clamp!(max_total_bytes, "max_total_bytes");
        clamp!(max_sites_per_file, "max_sites_per_file");
        clamp!(max_archive_entries, "max_archive_entries");
        clamp!(max_archive_member_bytes, "max_archive_member_bytes");
        clamp!(max_archive_expanded_bytes, "max_archive_expanded_bytes");
        clamp!(max_archive_ratio, "max_archive_ratio");
        clamp!(max_archive_depth, "max_archive_depth");
        clamp!(max_locations_per_manifest, "max_locations_per_manifest");
        clamp!(max_digest_set_entries, "max_digest_set_entries");
        clamp!(max_shingles_per_region, "max_shingles_per_region");
        clamp!(max_rendered_items, "max_rendered_items");
        (self, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_inside_the_ceiling() {
        let d = Limits::default();
        let (clamped, violations) = d.clone().clamped_to_ceiling();
        assert!(
            violations.is_empty(),
            "defaults violated ceilings: {violations:?}"
        );
        assert_eq!(clamped, d);
    }

    #[test]
    fn oversized_requests_are_clamped_and_reported() {
        let l = Limits {
            max_file_bytes: u64::MAX,
            ..Default::default()
        };
        let (clamped, violations) = l.clamped_to_ceiling();
        assert_eq!(clamped.max_file_bytes, Limits::ceiling().max_file_bytes);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("max_file_bytes"));
    }
}
