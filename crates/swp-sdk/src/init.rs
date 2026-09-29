//! Become a project with a provenance identity, or re-open one that already is.
//!
//! Two things happen here and both are close to irreversible, which is why this
//! module is longer than the operation looks. A 256-bit secret is drawn from the
//! operating system's random source and sealed to this user, and the project's
//! identity is *derived* from it — so the secret is not a credential that can be
//! rotated, it is the root of every location id this project will ever publish.
//! [`Store::init`] refuses to replace one and nothing here asks it to.
//!
//! The second thing is measurement. §9 forbids a hard-coded site count, and
//! `.swp/config.toml` is where the number lives, so initializing walks the tree
//! once the way a scanner would and writes a starting figure that
//! [`suggest_sites`] documents. It is a suggestion in the strongest sense
//! available: returned to the caller, then written into a file the operator owns,
//! then compared against what the first protection run actually managed to embed.
//!
//! ## What this module does not do
//!
//! It never *accepts* a secret. A caller that has a key in hand from somewhere
//! else is a caller whose key would have to cross an FFI boundary into
//! garbage-collected memory this project cannot zeroize, so the only way a store
//! gets a root secret is the operating system's random source, here.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use swp_adapters::Registry;
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ProjectId;
use swp_crypto::SealedSecret;
use swp_embedding::walk;
use swp_identity::{ProtectConfig, Store, SwpConfig, MAX_TARGET_SITES, MIN_TARGET_SITES};

use crate::session::{Overrides, Session};

/// What the tree holds, measured the way a scan would measure it.
#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    /// Files with a parser-covered extension.
    pub files: u32,
    pub bytes: u64,
    pub languages: BTreeMap<String, u32>,
    /// Source files per top-level directory, which is what `[protect] targets`
    /// is chosen from.
    pub tops: BTreeMap<String, u32>,
    pub skipped: u32,
}

/// The `[protect]` section this run left behind.
#[derive(Debug, Clone, Serialize)]
pub struct Settings {
    pub targets: Vec<String>,
    pub target_sites: u32,
    pub tag_bits: u8,
    pub embed_strings: bool,
    /// Whether this run wrote the config, or left the operator's alone.
    pub written: bool,
    /// What the measurement suggested, whether or not it was applied.
    pub suggestion: u32,
}

/// What initializing a project takes: the display label, and the settings to
/// write if this run is the one that writes them.
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    /// The project's human name. A short single-line label; `None` keeps the
    /// directory's name or the label already on disk.
    pub name: Option<String>,
    /// Rename a project that already has a label. Without it a conflicting
    /// `name` is a usage error, because reports written before the rename keep
    /// the old label and the two would disagree.
    pub force: bool,
}

/// What a store now holds, in the form an application can act on.
///
/// The three fields a caller cannot derive from anywhere else are
/// [`InitResult::secret_scheme`], [`InitResult::permissions_verified`] and
/// [`InitResult::permissions_detail`]: on Windows `SWP_SECRET_PLAIN=1` skips
/// DPAPI, and `std::fs::set_permissions` reports success while changing nothing,
/// so this build reads the access list back and parses it. An embedded process
/// inherits its host's environment, and an application that never saw these three
/// could write an unsealed key and be told nothing.
#[derive(Debug, Clone)]
pub struct InitResult {
    pub project_id: ProjectId,
    pub display_name: String,
    /// Whether the store was already there. A pre-existing store keeps its
    /// identity and its secret: SWP never replaces a project secret.
    pub pre_existing: bool,
    /// `"created"` when this run drew the secret, `"kept"` when one was there.
    pub secret_state: &'static str,
    /// `"dpapi"` or `"plain"` — how the key on disk is protected.
    pub secret_scheme: &'static str,
    /// A 40-bit non-secret handle, so a restored `root.key` can be recognised as
    /// the same key without printing it.
    pub secret_handle: String,
    pub permissions_verified: bool,
    pub permissions_detail: String,
    /// `"created"`, `"updated"`, `"already ignored"` or `"not written"`.
    pub gitignore: &'static str,
    /// Paths this run created, store-relative and forward-slashed.
    pub created: Vec<String>,
    /// Whether this run changed the project's display label.
    pub renamed: bool,
    pub measurement: Measurement,
    pub settings: Settings,
}

/// A project that is ready to protect, and what initializing it produced.
pub struct InitOutcome {
    pub session: Session,
    pub result: InitResult,
}

impl Session {
    /// Create — or re-open without changing — a project's store at
    /// `project_root`.
    ///
    /// The directory must exist; nothing here searches for one. What it writes is
    /// `.swp/` and the `.gitignore` entry that keeps the private half out of a
    /// commit, and it modifies no source file — that is a protection run's job.
    pub fn init(project_root: &Path, options: &InitOptions) -> Result<InitOutcome, SwpError> {
        if !project_root.is_dir() {
            return Err(SwpError::usage(format!(
                "{} is not a directory. Pass --project <path> to name the project to \
                 initialize.",
                project_root.display()
            )));
        }
        let existed = Store::exists(project_root);

        let (root, sealed) = SealedSecret::generate()?;
        // On the path where the store already had a key this freshly drawn secret
        // is discarded by `Store::init` — it never was and never becomes the
        // project's secret, and it is dropped below as soon as the answer is read.
        let init = Store::init(project_root, &root)?;
        let store = init.store;
        let mut identity = store.identity()?;

        let mut renamed = false;
        if let Some(raw) = &options.name {
            let name = raw.trim();
            if name.is_empty() || name.chars().any(|c| c.is_control()) || name.len() > 120 {
                return Err(SwpError::usage(
                    "--name must be a short single-line label, at most 120 characters",
                ));
            }
            if identity.display_name != name {
                if existed && !options.force {
                    return Err(SwpError::new(
                        ErrorCode::Usage,
                        format!(
                            "this project already calls itself {:?}. Re-run with --force to name \
                             it {name:?}; reports written before the rename keep the old label, \
                             so the two will not agree",
                            identity.display_name
                        ),
                    ));
                }
                identity.display_name = name.to_string();
                identity.validate()?;
                store.write_identity(&identity)?;
                renamed = true;
            }
        }

        let measurement = measure(&store)?;
        let suggestion = suggest_sites(measurement.files);
        let settings = write_settings(&store, &measurement, suggestion, existed)?;
        // The handle of a key this run did not create comes off the store's own
        // copy, because the freshly drawn one is discarded in that case.
        let (handle, scheme) = if init.pre_existing {
            drop(root);
            let scheme = secret_scheme(&store)?;
            let h = store.load_root().map(|k| k.fingerprint()).map_err(|e| {
                SwpError::new(
                    e.code(),
                    format!(
                        "the store exists but its secret cannot be read: {}",
                        e.message()
                    ),
                )
            })?;
            (h, scheme)
        } else {
            let h = root.fingerprint();
            let s = sealed.scheme.as_str();
            drop(root);
            (h, s)
        };
        // The seal this call drew is the drawn secret in another envelope, and the
        // store has written what it needs: neither survives the call.
        drop(sealed);

        let session = Session::build(store, &Overrides::default())?;
        Ok(InitOutcome {
            session,
            result: InitResult {
                project_id: identity.project_id.clone(),
                display_name: identity.display_name.clone(),
                pre_existing: init.pre_existing,
                secret_state: if init.pre_existing { "kept" } else { "created" },
                secret_scheme: scheme,
                secret_handle: handle,
                permissions_verified: init.permissions.is_verified(),
                permissions_detail: init.permissions.detail().to_string(),
                gitignore: init.gitignore,
                created: init.created.clone(),
                renamed,
                measurement,
                settings,
            },
        })
    }
}

/// Which protection the key on disk carries, without unsealing it.
///
/// This is metadata a caller has a right to see — it says whether the file is
/// protected by the operating system or only by its access list — and reading it
/// is the one reason this touches the envelope at all. The parsed seal is dropped
/// by the end of the call and never unsealed here.
fn secret_scheme(store: &Store) -> Result<&'static str, SwpError> {
    let bytes = std::fs::read(store.root_key_path()).map_err(|e| {
        SwpError::new(
            ErrorCode::SecretUnavailable,
            format!("the store exists but its secret cannot be read: {e}"),
        )
    })?;
    let scheme = SealedSecret::parse_file_bytes(&bytes)?.scheme.as_str();
    drop(bytes);
    Ok(scheme)
}

/// Walk once, cheaply, and count what has an adapter.
///
/// No file is parsed: this measures the tree's shape, not its literals, and a
/// protection run is where the expensive pass happens. The walk is the scanner's
/// own scope, so the count returned here is the count a later scan would report.
///
/// It is also the scanner's *tolerance* of an empty result. Protecting must fail a
/// tree it cannot watermark; initializing must not, because initializing is how
/// you get the `.swp/config.toml` that fixes the problem — and a project whose
/// first commit has no source in it yet is a project that wants a store. The zero
/// count is returned for the caller to report instead (§49).
fn measure(store: &Store) -> Result<Measurement, SwpError> {
    let limits = store.config().map(|c| c.limits).unwrap_or_default();
    let walked = walk::walk_for_scan(store.project_root(), &ProtectConfig::scan_scope(), &limits)?;
    let registry = Registry::standard();
    let mut languages: BTreeMap<String, u32> = BTreeMap::new();
    let mut tops: BTreeMap<String, u32> = BTreeMap::new();
    let mut bytes = 0u64;
    for entry in &walked.files {
        bytes += entry.bytes;
        let Some(adapter) = registry.for_path(Path::new(&entry.rel)) else {
            continue;
        };
        *languages.entry(adapter.name().to_string()).or_insert(0) += 1;
        // A file at the project root is its own target; anything deeper belongs
        // to its first directory, which is the unit `[protect] targets` names.
        let top = match entry.rel.split_once('/') {
            Some((head, _)) => head.to_string(),
            None => ".".to_string(),
        };
        *tops.entry(top).or_insert(0) += 1;
    }
    Ok(Measurement {
        files: languages.values().sum(),
        bytes,
        languages,
        tops,
        skipped: walked.omissions.len() as u32,
    })
}

/// The §9 ladder: how many sites a project of this size should aim at.
///
/// The brief says 10–30 "depending on size and configuration" and forbids a
/// universal constant, so this is a step function over measured file count, with
/// each step's reason:
///
/// - **0–3 files → 4 sites.** The protocol minimum. Below a handful of sites a
///   copy that kept two files holds the whole constellation, so it is the spread,
///   not the count, that carries the evidence — and a three-file project cannot
///   spread further than it has files.
/// - **4–15 → 12.** Enough that losing half the tree loses about half the sites,
///   few enough that the diff a reviewer reads stays readable.
/// - **16–60 → 20.** The brief's normal case: roughly one site per three files.
/// - **61–250 → 32.** A real package. Selection's round-robin puts these into
///   every file with candidates rather than piling them into one.
/// - **251+ → 48.** A large tree. Past this, an extra site adds less surviving
///   evidence per copy than it adds to the diff, which grows linearly.
///
/// The tradeoff runs both ways and is repeated in `docs/USER-GUIDE.md`: more
/// sites is more surviving evidence and a larger visible change to the source;
/// fewer is the opposite. Neither number bounds what a copy can be caught with —
/// the level a scan reaches depends on how many sites *that copy* carries.
pub fn suggest_sites(files: u32) -> u32 {
    let step = match files {
        0..=3 => MIN_TARGET_SITES,
        4..=15 => 12,
        16..=60 => 20,
        61..=250 => 32,
        _ => 48,
    };
    // Six sites per file is as concentrated as a constellation should get: with
    // fewer files than that, the smaller number is the honest suggestion, and a
    // project of two files protected at 48 sites would put 24 sites in each.
    let spread_bound = files.saturating_mul(6).max(MIN_TARGET_SITES);
    step.min(spread_bound)
        .clamp(MIN_TARGET_SITES, MAX_TARGET_SITES)
}

/// Write `[protect]` for a project that has just been initialized; leave an
/// existing config untouched.
fn write_settings(
    store: &Store,
    measured: &Measurement,
    suggestion: u32,
    existed: bool,
) -> Result<Settings, SwpError> {
    let current = store.config()?;
    if existed {
        return Ok(Settings {
            targets: current.protect.targets.clone(),
            target_sites: current.protect.target_sites,
            tag_bits: current.protect.tag_bits,
            embed_strings: current.protect.embed_strings,
            written: false,
            suggestion,
        });
    }
    let cfg = SwpConfig {
        // Whatever the operator already set wins over the defaults this replaces:
        // `[limits]` and `[protect].excludes` may have been edited by hand before
        // `init` was ever run, and silently resetting them would be a surprise.
        limits: current.limits.clone(),
        protect: ProtectConfig {
            excludes: current.protect.excludes.clone(),
            targets: pick_targets(measured),
            target_sites: suggestion,
            ..ProtectConfig::default()
        },
        ..SwpConfig::default()
    };
    cfg.validate()?;
    store.write_config(&cfg)?;
    Ok(Settings {
        targets: cfg.protect.targets.clone(),
        target_sites: cfg.protect.target_sites,
        tag_bits: cfg.protect.tag_bits,
        embed_strings: cfg.protect.embed_strings,
        written: true,
        suggestion,
    })
}

/// The directories that actually hold usable source, busiest first.
///
/// `["src"]` is a guess about layout, and a wrong guess costs a run that protects
/// nothing. Capped at four entries because each target is a directory the operator
/// has to keep in mind, and because a protection run walks each one separately.
fn pick_targets(measured: &Measurement) -> Vec<String> {
    let mut ranked: Vec<(u32, String)> = measured
        .tops
        .iter()
        .map(|(dir, n)| (*n, dir.clone()))
        .collect();
    // Busiest first; ties alphabetically, so the same tree always gets the same
    // config and initializing twice is the same operation.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut out: Vec<String> = ranked.into_iter().take(4).map(|(_, d)| d).collect();
    if out.iter().any(|d| d == ".") {
        // The root covers every other entry, and listing both would double the
        // walk for no added coverage.
        return vec![".".to_string()];
    }
    if out.is_empty() {
        out.push("src".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_monotonic_and_inside_the_protocol_range() {
        let mut last = 0;
        for files in [
            0u32, 1, 3, 4, 8, 15, 16, 40, 60, 61, 200, 250, 251, 5000, 100_000,
        ] {
            let s = suggest_sites(files);
            assert!(
                (MIN_TARGET_SITES..=MAX_TARGET_SITES).contains(&s),
                "{files} → {s}"
            );
            assert!(
                s >= last,
                "{files} suggested {s}, below the smaller tree's {last}"
            );
            last = s;
        }
        // A two-file project does not get a 48-site constellation dumped on it.
        assert_eq!(suggest_sites(2), MIN_TARGET_SITES);
        assert_eq!(suggest_sites(3), MIN_TARGET_SITES);
        assert_eq!(suggest_sites(2), 4);
        assert!(suggest_sites(10) <= 60);
        assert!(suggest_sites(1000) <= 48);
    }

    #[test]
    fn a_root_target_absorbs_the_ones_below_it() {
        let mut tops = BTreeMap::new();
        tops.insert(".".to_string(), 3);
        tops.insert("src".to_string(), 90);
        let m = Measurement {
            files: 93,
            bytes: 0,
            languages: BTreeMap::new(),
            tops,
            skipped: 0,
        };
        assert_eq!(pick_targets(&m), vec![".".to_string()]);
        let mut tops = BTreeMap::new();
        tops.insert("lib".to_string(), 40);
        tops.insert("src".to_string(), 40);
        tops.insert("bin".to_string(), 1);
        tops.insert("docs".to_string(), 1);
        tops.insert("extra".to_string(), 1);
        let m = Measurement {
            files: 83,
            bytes: 0,
            languages: BTreeMap::new(),
            tops,
            skipped: 0,
        };
        // Ties break alphabetically so a second run writes the same file.
        assert_eq!(
            pick_targets(&m),
            vec!["lib", "src", "bin", "docs"],
            "four entries, busiest first"
        );
        let empty = Measurement {
            files: 0,
            bytes: 0,
            languages: BTreeMap::new(),
            tops: BTreeMap::new(),
            skipped: 0,
        };
        assert_eq!(pick_targets(&empty), vec!["src".to_string()]);
    }
}
