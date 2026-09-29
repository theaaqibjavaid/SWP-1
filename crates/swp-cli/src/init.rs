//! `swp init` — become a project with a provenance identity.
//!
//! Two things happen here and both are close to irreversible, which is why this
//! file is longer than the command looks. A 256-bit secret is drawn from the
//! operating system's random source and sealed to this user, and the project's
//! identity is *derived* from it — so the secret is not a credential that can be
//! rotated, it is the root of every location id this project will ever publish.
//! [`Session::init`](swp_sdk::Session::init) draws that secret and
//! [`Store::init`](swp_identity::Store::init) refuses to replace one; this command
//! never asks it to.
//!
//! The second thing is measurement. §9 forbids a hard-coded site count, and
//! `.swp/config.toml` is where the number lives, so `init` walks the tree once
//! the way a scanner would and writes a starting figure that
//! [`swp_sdk::init::suggest_sites`] documents. It is a suggestion in the strongest
//! sense available: printed, then written into a file the operator owns, then
//! compared against what the first `swp protect` actually managed to embed.
//!
//! The output is §35's six-part answer — what was generated, what was modified,
//! where private data is stored, what must be backed up, what may be committed,
//! what must never be committed — built from `swp-manifest`'s classification
//! table rather than from a list kept here, so the two cannot disagree.

use std::path::{Path, PathBuf};

use serde::Serialize;
use swp_core::error::SwpError;
use swp_identity::DEFAULT_TARGET_SITES;
use swp_manifest::{BACKUP_ARTIFACTS, PRIVATE_ARTIFACTS, PUBLIC_ARTIFACTS};
use swp_sdk::{InitOptions, Measurement, Settings};

use crate::args::{Flag, Parsed};
use crate::output::Sink;

/// What the tree holds, measured the way a scan would measure it, and the
/// `[protect]` section this run left behind — both returned by
/// [`swp_sdk::Session::init`], and serialized here under the field names and
/// order the documented `SWP-1-init-v1` transcript uses.
///
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
    // `init` is the one command that may point at a directory that is not a
    // project yet, so the path is taken as typed and joined to the working
    // directory rather than searched: `swp init` in the wrong place must create a
    // store in the place the operator named, not in the nearest enclosing one.
    let dir = match parsed.value(Flag::Project) {
        Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
        Some(p) => cwd.join(p),
        None => cwd.to_path_buf(),
    };
    let outcome = swp_sdk::Session::init(
        &dir,
        &InitOptions {
            name: parsed.value(Flag::Name).map(|s| s.to_string()),
            force: parsed.has(Flag::Force),
        },
    )?;
    let r = &outcome.result;
    if r.measurement.files == 0 {
        sink.warn(&format!(
            "no file under the default scope has a language adapter, so `swp protect` will \
             refuse this tree. This build parses {}; point [protect] targets at part of it \
             that does, or add an adapter.",
            swp_sdk::capabilities()
                .languages
                .iter()
                .map(|l| l.name)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let doc = InitDocument {
        schema: "SWP-1-init-v1",
        protocol: swp_core::SWP_PROTOCOL_NAME,
        project_root: swp_core::text::display_path(
            &outcome.session.project_root().display().to_string(),
        )
        .to_string(),
        project_id: r.project_id.to_string(),
        display_name: r.display_name.clone(),
        secret: r.secret_state,
        secret_handle: r.secret_handle.clone(),
        permissions: r.permissions_detail.clone(),
        permissions_verified: r.permissions_verified,
        gitignore: r.gitignore,
        modified_source: Vec::new(),
        generated: r.created.clone(),
        measurement: r.measurement.clone(),
        settings: r.settings.clone(),
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
    if r.renamed {
        sink.note(&format!("the project is now called {:?}", doc.display_name));
    }
    sink.result(&doc, &text_lines(&doc, r.renamed))?;
    Ok(0)
}

fn text_lines(d: &InitDocument, renamed: bool) -> Vec<String> {
    let mut out = vec![
        format!("{} — protected at {}", d.project_id, d.project_root),
        format!(
            "  name       {}{}",
            d.display_name,
            if renamed {
                " (renamed by this run)"
            } else {
                ""
            }
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
        out.push(format!(
            "    measured suggestion for a {}-file tree",
            d.measurement.files
        ));
    }
    out.push(format!(
        "  [protect] tag_bits       {}",
        d.settings.tag_bits
    ));
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
    out.extend([String::new(), "Where the private data lives".to_string()]);
    out.extend(d.never_commit.iter().map(|p| format!("  {p}")));
    out.extend([
        String::new(),
        "Back these up. Losing them loses every release you have already made.".to_string(),
    ]);
    out.extend(d.back_up.iter().map(|p| format!("  {p}")));
    out.extend([String::new(), "You may commit".to_string()]);
    out.extend(d.commit.iter().map(|p| format!("  {p}")));
    out.extend([String::new(), "You must never commit".to_string()]);
    out.extend(d.never_commit.iter().map(|p| format!("  {p}")));
    out.extend([String::new(), "Next".to_string()]);
    out.extend(d.next.iter().map(|n| format!("  {n}")));
    out.push(String::new());
    out.push(
        "Nothing is protected until `swp protect` runs, and a release cannot be verified \
         without the private data above."
            .to_string(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use swp_core::error::ErrorCode;
    use swp_identity::{Store, MIN_TARGET_SITES};

    #[test]
    fn init_creates_a_store_that_opens_and_reports_the_same_identity() {
        let dir = Scratch::new("twice");
        dir.write("lib/a.js", "function f(a,b){return a*b+1001;}\n");
        dir.write("src/b.js", "function g(a,b){return a/b+1002;}\n");
        let argv: Vec<String> = vec!["init".into()];
        let parsed = crate::args::parse(&argv).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut sink =
            crate::output::Sink::new(crate::output::Format::Text, true, &mut out, &mut err);
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
        let mut sink2 =
            crate::output::Sink::new(crate::output::Format::Text, true, &mut out2, &mut err2);
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
        let mut sink3 =
            crate::output::Sink::new(crate::output::Format::Text, true, &mut out3, &mut err3);
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
        let mut sink4 =
            crate::output::Sink::new(crate::output::Format::Text, true, &mut out4, &mut err4);
        run(&p4, &dir.root, &mut sink4).unwrap();
        let renamed = Store::open(&dir.root).unwrap().identity().unwrap();
        assert_eq!(renamed.display_name, "Renamed");
        assert_eq!(
            renamed.project_id, identity.project_id,
            "a rename moved the id"
        );
    }

    #[test]
    fn a_json_init_answer_carries_the_four_lists_it_owes_the_operator() {
        let dir = Scratch::new("json");
        dir.write("src/a.js", "function f(a,b){return a*b+1001;}\n");
        let argv = vec!["init".into(), "--format".into(), "json".into()];
        let parsed = crate::args::parse(&argv).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut sink =
            crate::output::Sink::new(crate::output::Format::Json, true, &mut out, &mut err);
        run(&parsed, &dir.root, &mut sink).unwrap();
        let text = String::from_utf8(out).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["schema"], "SWP-1-init-v1");
        assert_eq!(doc["protocol"], "SWP-1");
        assert_eq!(doc["secret"], "created");
        assert!(doc["modified_source"].as_array().unwrap().is_empty());
        for field in ["commit", "never_commit", "back_up"] {
            assert!(
                !doc[field].as_array().unwrap().is_empty(),
                "{field} is empty"
            );
        }
        assert!(doc["never_commit"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == ".swp/private/root.key"));
        // The handle is a 40-bit base32 label; nothing in the document is a key.
        assert_eq!(doc["secret_handle"].as_str().unwrap().len(), 8);
        assert!(
            !text.contains("PRIVATE KEY")
                && !text.contains("\"key\": \"")
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
            let root =
                std::env::temp_dir().join(format!("swp-cli-init-{}-{label}", std::process::id()));
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
