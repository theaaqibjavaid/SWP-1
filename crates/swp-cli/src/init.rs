//! `swp init` — become a project with a provenance identity.
//!
//! Two things happen here and both are close to irreversible, which is why this
//! file is longer than the command looks. A 256-bit secret is drawn from the
//! operating system's random source and sealed to this user, and the project's
//! identity is *derived* from it — so the secret is not a credential that can be
//! rotated, it is the root of every location id this project will ever publish.
//! [`Store::init`] refuses to replace one and this command never asks it to.
//!
//! The second thing is measurement. §9 forbids a hard-coded site count, and
//! `.swp/config.toml` is where the number lives, so `init` walks the tree once
//! the way a scanner would and writes a starting figure that [`suggest_sites`]
//! documents. It is a suggestion in the strongest sense available: printed, then
//! written into a file the operator owns, then compared against what the first
//! `swp protect` actually managed to embed.
//!
//! The output is §35's six-part answer — what was generated, what was modified,
//! where private data is stored, what must be backed up, what may be committed,
//! what must never be committed — built from `swp-manifest`'s classification
//! table rather than from a list kept here, so the two cannot disagree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use swp_adapters::Registry;
use swp_core::error::{ErrorCode, SwpError};
use swp_crypto::SealedSecret;
use swp_embedding::walk;
use swp_identity::{
    ProtectConfig, Store, SwpConfig, DEFAULT_TARGET_SITES, MAX_TARGET_SITES, MIN_TARGET_SITES,
};
use swp_manifest::{BACKUP_ARTIFACTS, PRIVATE_ARTIFACTS, PUBLIC_ARTIFACTS};

use crate::args::{Flag, Parsed};
use crate::output::Sink;

/// What the tree holds, measured the way a scan would measure it.
#[derive(Debug, Serialize)]
struct Measurement {
    /// Files with a parser-covered extension.
    files: u32,
    bytes: u64,
    languages: BTreeMap<String, u32>,
    /// Source files per top-level directory, which is what `[protect] targets`
    /// is chosen from.
    tops: BTreeMap<String, u32>,
    skipped: u32,
}

#[derive(Debug, Serialize)]
struct Settings {
    targets: Vec<String>,
    target_sites: u32,
    tag_bits: u8,
    embed_strings: bool,
    /// Whether this run wrote the config, or left the operator's alone.
    written: bool,
    /// What the measurement suggested, whether or not it was applied.
    suggestion: u32,
}

/// `SWP-1-init-v1`: the §35 answer as one document.
#[derive(Debug, Serialize)]
struct InitDocument {
    schema: &'static str,
    protocol: &'static str,
    project_root: String,
    project_id: String,
    display_name: String,
    /// `created` when this run drew the secret, `kept` when one was already there.
    secret: &'static str,
    /// A 40-bit non-secret handle, so a restored `root.key` can be recognised as
    /// the same key without printing it.
    secret_handle: String,
    permissions: String,
    permissions_verified: bool,
    gitignore: &'static str,
    /// What this run modified outside `.swp/`: nothing, and the report says so.
    modified_source: Vec<String>,
    generated: Vec<String>,
    measurement: Measurement,
    settings: Settings,
    commit: &'static [&'static str],
    never_commit: &'static [&'static str],
    back_up: &'static [&'static str],
    next: &'static [&'static str],
}

pub fn run(parsed: &Parsed, cwd: &Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let dir = match parsed.value(Flag::Project) {
        Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
        Some(p) => cwd.join(p),
        None => cwd.to_path_buf(),
    };
    if !dir.is_dir() {
        return Err(SwpError::usage(format!(
            "{} is not a directory. Pass --project <path> to name the project to \
             initialize.",
            dir.display()
        )));
    }
    let existed = Store::exists(&dir);

    let (root, _sealed) = SealedSecret::generate()?;
    let init = Store::init(&dir, &root)?;
    let store = init.store;
    let mut identity = store.identity()?;

    let mut renamed = false;
    if let Some(raw) = parsed.value(Flag::Name) {
        let name = raw.trim();
        if name.is_empty() || name.chars().any(|c| c.is_control()) || name.len() > 120 {
            return Err(SwpError::usage(
                "--name must be a short single-line label, at most 120 characters",
            ));
        }
        if identity.display_name != name {
            if existed && !parsed.has(Flag::Force) {
                return Err(SwpError::new(
                    ErrorCode::Usage,
                    format!(
                        "this project already calls itself {:?}. Re-run with --force to name it \
                         {name:?}; reports written before the rename keep the old label, so the \
                         two will not agree",
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
    // The handle of a key this run did not create comes off the store's own copy,
    // because the freshly drawn one is discarded in that case.
    let handle = if init.pre_existing {
        drop(root);
        store
            .load_root()
            .map(|k| k.fingerprint())
            .map_err(|e| {
                SwpError::new(
                    e.code(),
                    format!("the store exists but its secret cannot be read: {}", e.message()),
                )
            })?
    } else {
        let h = root.fingerprint();
        drop(root);
        h
    };

    let generated = init.created.clone();
    let doc = InitDocument {
        schema: "SWP-1-init-v1",
        protocol: swp_core::SWP_PROTOCOL_NAME,
        project_root: store.project_root().display().to_string(),
        project_id: identity.project_id.to_string(),
        display_name: identity.display_name.clone(),
        secret: if init.pre_existing { "kept" } else { "created" },
        secret_handle: handle,
        permissions: init.permissions.detail().to_string(),
        permissions_verified: init.permissions.is_verified(),
        gitignore: init.gitignore,
        modified_source: Vec::new(),
        generated,
        measurement,
        settings,
        commit: PUBLIC_ARTIFACTS,
        never_commit: PRIVATE_ARTIFACTS,
        back_up: BACKUP_ARTIFACTS,
        next: &["swp generate", "swp protect", "swp verify"],
    };
    if !doc.permissions_verified {
        sink.warn(&format!(
            "root.key's permissions were requested but not confirmed by the operating system: {}",
            doc.permissions
        ));
    }
    if renamed {
        sink.note(&format!("the project is now called {:?}", doc.display_name));
    }
    sink.result(&doc, &text_lines(&doc, renamed))?;
    Ok(0)
}

fn text_lines(d: &InitDocument, renamed: bool) -> Vec<String> {
    let mut out = vec![
        format!("{} — protected at {}", d.project_id, d.project_root),
        format!(
            "  name       {}{}",
            d.display_name,
            if renamed { " (renamed by this run)" } else { "" }
        ),
        format!(
            "  secret     {} · handle {} · permissions {}",
            d.secret,
            d.secret_handle,
            if d.permissions_verified {
                "verified"
            } else {
                "requested, not confirmed"
            }
        ),
        format!("  .gitignore {}", d.gitignore),
        String::new(),
        "What was generated".to_string(),
    ];
    if d.generated.is_empty() {
        out.push("  nothing: every artifact this command writes already existed".to_string());
    } else {
        out.extend(d.generated.iter().map(|p| format!("  {p}")));
    }
    out.extend([
        String::new(),
        "What was modified".to_string(),
        "  your source: nothing. `swp protect` is what edits files.".to_string(),
        String::new(),
        "What this tree holds".to_string(),
    ]);
    let langs = if d.measurement.languages.is_empty() {
        "none of it has a parser".to_string()
    } else {
        d.measurement
            .languages
            .iter()
            .map(|(l, n)| format!("{l} {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    out.push(format!(
        "  {} source file(s) a scanner can use, {} byte(s) read — {}",
        d.measurement.files, d.measurement.bytes, langs
    ));
    if d.measurement.skipped > 0 {
        out.push(format!(
            "  {} file(s) the walk refused or excluded, so they are not in that count",
            d.measurement.skipped
        ));
    }
    out.push(String::new());
    out.push(if d.settings.written {
        "What was configured in .swp/config.toml".to_string()
    } else {
        "What was configured: nothing — your .swp/config.toml was left as it is".to_string()
    });
    out.push(format!(
        "  [protect] targets      {}",
        if d.settings.targets.is_empty() {
            "(none)".to_string()
        } else {
            d.settings.targets.join(", ")
        }
    ));
    out.push(format!(
        "  [protect] target_sites {}",
        d.settings.target_sites
    ));
    if d.settings.written && d.settings.suggestion != DEFAULT_TARGET_SITES {
        out.push(format!("    measured suggestion for a {}-file tree", d.measurement.files));
    }
    out.push(format!("  [protect] tag_bits       {}", d.settings.tag_bits));
    out.push(format!(
        "    a site carries a {}-bit code, so one site is 1-in-{} by chance; that is \
         why a single fragment is never a finding on its own",
        d.settings.tag_bits,
        1u64 << d.settings.tag_bits as u64
    ));
    out.push(format!(
        "  [protect] embed_strings {}",
        d.settings.embed_strings
    ));
    out.extend([
        String::new(),
        "Where the private data lives".to_string(),
    ]);
    out.extend(d.never_commit.iter().map(|p| format!("  {p}")));
    out.extend([
        String::new(),
        "Back these up. Losing them loses every release you have already made.".to_string(),
    ]);
    out.extend(d.back_up.iter().map(|p| format!("  {p}")));
    out.extend([
        String::new(),
        "You may commit".to_string(),
    ]);
    out.extend(d.commit.iter().map(|p| format!("  {p}")));
    out.extend([
        String::new(),
        "You must never commit".to_string(),
    ]);
    out.extend(d.never_commit.iter().map(|p| format!("  {p}")));
    out.extend([
        String::new(),
        "Next".to_string(),
    ]);
    out.extend(d.next.iter().map(|n| format!("  {n}")));
    out.push(String::new());
    out.push(
        "Nothing is protected until `swp protect` runs, and a release cannot be verified \
         without the private data above."
            .to_string(),
    );
    out
}

/// Walk once, cheaply, and count what has an adapter.
///
/// No file is parsed: this measures the tree's shape, not its literals, and
/// `swp protect` is where the expensive pass happens. The walk is the scanner's
/// own scope, so the count printed here is the count a later scan would report.
fn measure(store: &Store) -> Result<Measurement, SwpError> {
    let limits = store.config().map(|c| c.limits).unwrap_or_default();
    let walked = walk::walk(store.project_root(), &ProtectConfig::scan_scope(), &limits)?;
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
    step.min(spread_bound).clamp(MIN_TARGET_SITES, MAX_TARGET_SITES)
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
/// has to keep in mind, and because `swp protect` walks each one separately.
fn pick_targets(measured: &Measurement) -> Vec<String> {
    let mut ranked: Vec<(u32, String)> = measured
        .tops
        .iter()
        .map(|(dir, n)| (*n, dir.clone()))
        .collect();
    // Busiest first; ties alphabetically, so the same tree always gets the same
    // config and `swp init` twice is the same command.
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
        for files in [0u32, 1, 3, 4, 8, 15, 16, 40, 60, 61, 200, 250, 251, 5000, 100_000] {
            let s = suggest_sites(files);
            assert!(
                (MIN_TARGET_SITES..=MAX_TARGET_SITES).contains(&s),
                "{files} → {s}"
            );
            assert!(s >= last, "{files} suggested {s}, below the smaller tree's {last}");
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

    #[test]
    fn init_creates_a_store_that_opens_and_reports_the_same_identity() {
        let dir = Scratch::new("twice");
        dir.write("lib/a.js", "function f(a,b){return a*b+1001;}\n");
        dir.write("src/b.js", "function g(a,b){return a/b+1002;}\n");
        let argv: Vec<String> = vec!["init".into()];
        let parsed = crate::args::parse(&argv).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut sink = crate::output::Sink::new(
            crate::output::Format::Text,
            true,
            &mut out,
            &mut err,
        );
        assert_eq!(run(&parsed, &dir.root, &mut sink).unwrap(), 0);
        let first = String::from_utf8(out).unwrap();
        assert!(first.contains("What was generated"), "{first}");
        assert!(first.contains(".swp/private/root.key"), "{first}");
        assert!(
            first.contains("your source: nothing"),
            "init must say it modified no source: {first}"
        );

        let store = Store::open(&dir.root).unwrap();
        let identity = store.identity().unwrap();
        // The measured tree drove the settings, and both directories held source.
        let cfg = store.config().unwrap();
        assert!(
            cfg.protect.targets.contains(&"src".to_string())
                || cfg.protect.targets.contains(&"lib".to_string())
                || cfg.protect.targets == vec![".".to_string()],
            "{:?}",
            cfg.protect.targets
        );
        assert!(cfg.protect.target_sites >= MIN_TARGET_SITES);
        cfg.validate().unwrap();

        // A second `init` must not draw a second secret.
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let mut sink2 = crate::output::Sink::new(
            crate::output::Format::Text,
            true,
            &mut out2,
            &mut err2,
        );
        run(&parsed, &dir.root, &mut sink2).unwrap();
        let again = Store::open(&dir.root).unwrap();
        assert_eq!(again.identity().unwrap().project_id, identity.project_id);
        let text2 = String::from_utf8(out2).unwrap();
        assert!(text2.contains("secret     kept"), "{text2}");
        assert!(
            text2.contains("nothing: every artifact"),
            "the second run should say it created nothing: {text2}"
        );

        // --name without --force refuses to rename an existing project.
        let mut argv3 = argv.clone();
        argv3.push("--name".into());
        argv3.push("Renamed".into());
        let p3 = crate::args::parse(&argv3).unwrap();
        let mut out3 = Vec::new();
        let mut err3 = Vec::new();
        let mut sink3 = crate::output::Sink::new(
            crate::output::Format::Text,
            true,
            &mut out3,
            &mut err3,
        );
        let e = run(&p3, &dir.root, &mut sink3).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Usage);
        assert!(e.message().contains("--force"), "{e}");
        assert_eq!(
            Store::open(&dir.root)
                .unwrap()
                .identity()
                .unwrap()
                .display_name,
            dir.root.file_name().unwrap().to_string_lossy()
        );

        // …and with --force it renames, leaving the derived identity alone.
        let mut argv4 = argv3.clone();
        argv4.push("--force".into());
        let p4 = crate::args::parse(&argv4).unwrap();
        let mut out4 = Vec::new();
        let mut err4 = Vec::new();
        let mut sink4 = crate::output::Sink::new(
            crate::output::Format::Text,
            true,
            &mut out4,
            &mut err4,
        );
        run(&p4, &dir.root, &mut sink4).unwrap();
        let renamed = Store::open(&dir.root).unwrap().identity().unwrap();
        assert_eq!(renamed.display_name, "Renamed");
        assert_eq!(renamed.project_id, identity.project_id, "a rename moved the id");
    }

    #[test]
    fn a_json_init_answer_carries_the_four_lists_it_owes_the_operator() {
        let dir = Scratch::new("json");
        dir.write("src/a.js", "function f(a,b){return a*b+1001;}\n");
        let argv = vec!["init".into(), "--format".into(), "json".into()];
        let parsed = crate::args::parse(&argv).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut sink = crate::output::Sink::new(
            crate::output::Format::Json,
            true,
            &mut out,
            &mut err,
        );
        run(&parsed, &dir.root, &mut sink).unwrap();
        let text = String::from_utf8(out).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["schema"], "SWP-1-init-v1");
        assert_eq!(doc["protocol"], "SWP-1");
        assert_eq!(doc["secret"], "created");
        assert!(doc["modified_source"].as_array().unwrap().is_empty());
        for field in ["commit", "never_commit", "back_up"] {
            assert!(!doc[field].as_array().unwrap().is_empty(), "{field} is empty");
        }
        assert!(doc["never_commit"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == ".swp/private/root.key"));
        // The handle is a 40-bit base32 label; nothing in the document is a key.
        assert_eq!(doc["secret_handle"].as_str().unwrap().len(), 8);
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("\"key\": \"")
                && !text.contains("root.key\n-----"),
            "the document printed key material"
        );
    }

    /// A scratch project directory, removed when the test ends.
    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "swp-cli-init-{}-{label}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Scratch { root }
        }

        fn write(&self, rel: &str, body: &str) {
            let path = self.root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
