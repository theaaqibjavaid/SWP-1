//! `swp inspect` — what the local store holds, printed for the person who owns it.
//!
//! Every view here is a read of `.swp/`: nothing about a candidate, nothing about
//! a copy, nothing judged. §22's grading and §23's ladder belong to `swp scan`;
//! `inspect` exists because the store *is* the operator's evidence and they are
//! entitled to read it without opening a JSON file in another program.
//!
//! ## The two rules this file keeps
//!
//! * **No secret, ever.** Authentication uses the project's *public* verify key,
//!   so even the manifest views need nothing private beyond the file itself, and
//!   [`Ctx::secret`] is never called here. `swp inspect` can therefore read a
//!   project's whole history on a machine that has the store but not the root key.
//! * **The private views say so, and say what they give away.** `manifest`, `plan`
//!   and `fragments` print the constellation, and each warning names the part of
//!   it that view actually holds: the signed manifest and the plan serialize the
//!   keyed location ids, the fragments view the two literals at each site. That
//!   is precisely what the protocol keeps off a stranger's machine and precisely
//!   what an operator needs when a `verify` answer has to be understood — so it
//!   prints, to the terminal they are standing at, behind a warning that pasting
//!   it into an issue leaks the watermark. A warning that overstated or
//!   understated the leak would teach an operator to ignore the one that matters.
//!
//! Site indexes are array positions: `site 3` is `sites[3]` of that release's
//! manifest, and it is the same number `swp verify` prints for the same site.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use swp_core::error::{ErrorCode, SwpError};
use swp_core::id::ReleaseId;
use swp_core::RadiusKind;
use swp_identity::ReleaseRecord;
use swp_manifest::{PrivateManifest, SiteEntry};

use crate::args::{Flag, Parsed};
use crate::ctx::Ctx;
use crate::output::{self, Sink};

/// The `schema` field every view sets.
const SCHEMA: &str = "SWP-1-inspect-v1";

/// A view's answer: which release it was about, the `data` block, the text lines,
/// and what the text rendering left out.
type Rendering = (Option<ReleaseId>, Value, Vec<String>, Value);

/// The eight things `swp inspect` can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    /// The store as a whole: what exists, and who may see it.
    Store,
    Identity,
    Config,
    Releases,
    Release,
    Manifest,
    Plan,
    Fragments,
}

impl View {
    const ALL: [View; 8] = [
        View::Store,
        View::Identity,
        View::Config,
        View::Releases,
        View::Release,
        View::Manifest,
        View::Plan,
        View::Fragments,
    ];

    fn as_str(self) -> &'static str {
        match self {
            View::Store => "store",
            View::Identity => "identity",
            View::Config => "config",
            View::Releases => "releases",
            View::Release => "release",
            View::Manifest => "manifest",
            View::Plan => "plan",
            View::Fragments => "fragments",
        }
    }

    fn blurb(self) -> &'static str {
        match self {
            View::Store => "every artifact the store holds, and its classification",
            View::Identity => "the public identity, including the verify key",
            View::Config => "the config as it is on disk, not as flags would change it",
            View::Releases => "one line per protected release, oldest first",
            View::Release => "one release record, and whether its private half is present",
            View::Manifest => "the signed site list: keyed addresses and both literals",
            View::Plan => "what a run intended, including every location it refused",
            View::Fragments => "the site table and the refusals, as a human reads them",
        }
    }

    /// Whether this view prints the private constellation, and owes a warning.
    fn is_private(self) -> bool {
        self.private_contents().is_some()
    }

    /// What this view gives away, in the words the warning prints. Not every
    /// private view holds every private field: `fragments` is the view an
    /// operator reads to see a literal, and it carries no location id at all.
    fn private_contents(self) -> Option<&'static str> {
        match self {
            View::Manifest => Some(
                "the signed site list, which is every site's keyed site addresses, its file and \
                 line, and both literals",
            ),
            View::Plan => Some(
                "the intended constellation, which is every planned site's keyed site addresses \
                 and every location the run refused",
            ),
            View::Fragments => Some("every site's literal as it was written and as it now stands"),
            _ => None,
        }
    }

    fn names() -> Vec<&'static str> {
        view_names()
    }

    fn parse(raw: &str) -> Result<View, SwpError> {
        View::ALL
            .iter()
            .find(|v| v.as_str() == raw)
            .copied()
            .ok_or_else(|| {
                SwpError::usage(format!(
                    "there is nothing called {raw:?} to inspect. `swp inspect` shows: {}",
                    View::names().join(", ")
                ))
            })
    }
}

/// The view names exactly as `swp inspect` accepts them. The help text prints this
/// list rather than typing the eight names again, so a ninth view cannot appear
/// in one place and not the other.
pub fn view_names() -> Vec<&'static str> {
    View::ALL.iter().map(|v| v.as_str()).collect()
}

/// The views that print private material, named by the same table the warning
/// uses. `swp inspect --help` prints this list instead of typing the three names
/// again, so a fourth private view cannot be added to the warning and left out of
/// the help page.
pub fn private_view_names() -> Vec<&'static str> {
    View::ALL
        .iter()
        .filter(|v| v.is_private())
        .map(|v| v.as_str())
        .collect()
}

pub fn run(parsed: &Parsed, cwd: &std::path::Path, sink: &mut Sink<'_>) -> Result<i32, SwpError> {
    let view = match parsed.positional.as_slice() {
        [] => View::Store,
        [one] => View::parse(one)?,
        many => {
            return Err(SwpError::usage(format!(
                "inspect takes one thing to look at; {} were given: {}",
                many.len(),
                many.join(", ")
            )))
        }
    };
    let project = Ctx::open(parsed, cwd)?;
    for warning in &project.warnings {
        sink.warn(warning);
    }
    if let Some(contents) = view.private_contents() {
        sink.warn(&format!(
            "this view prints {contents}. It is your own copy of the watermark: do not paste it \
             into an issue, a build log or a document you mean to share.",
        ));
    }
    let limit = output::window(parsed.has(Flag::Full), parsed.number(Flag::Limit)?);
    let (release_id, data, lines, omissions) = match view {
        View::Store => store_view(&project)?,
        View::Identity => identity_view(&project)?,
        View::Config => config_view(&project)?,
        View::Releases => releases_view(&project, limit)?,
        View::Release => release_view(&project, parsed)?,
        View::Manifest => manifest_view(&project, parsed, limit)?,
        View::Plan => plan_view(&project, parsed, limit)?,
        View::Fragments => fragments_view(&project, parsed, limit)?,
    };
    let doc = json!({
        "schema": SCHEMA,
        "view": view.as_str(),
        "project_id": project.identity.project_id.to_string(),
        "display_name": project.identity.display_name,
        // null for the views that are not about one release.
        "release_id": release_id.as_ref().map(|r| r.to_string()),
        // Which repeating lists the text windowed. The JSON document is never shortened.
        "omissions": omissions,
        "data": data,
    });
    sink.result(&doc, &lines)?;
    Ok(0)
}

// --------------------------------------------------------------------------------------
// store
// --------------------------------------------------------------------------------------

fn store_view(project: &Ctx) -> Result<Rendering, SwpError> {
    let s = &project.store;
    let inventory = s.inventory()?;
    let count = |needle: &str| {
        inventory
            .iter()
            .filter(|(p, _)| p.contains(needle))
            .count()
    };
    let data = json!({
        "root": s.project_root().display().to_string(),
        "store": s.relabel(&s.swp_dir()),
        "protocol": project.identity.protocol,
        "canonicalizer_version": project.identity.canonicalizer_version,
        "created_at": project.identity.created_at.to_rfc3339(),
        "root_key": {
            "present": s.root_key_exists(),
            "path": s.relabel(&s.root_key_path()),
        },
        "counts": {
            "releases": count("public/releases/"),
            "private_manifests": count("private/manifests/"),
            "plans": count("private/plans/"),
            "reports": count("private/reports/"),
        },
        "artifacts": inventory
            .iter()
            .map(|(p, public)| json!({ "path": p, "public": public }))
            .collect::<Vec<_>>(),
        "commit": swp_manifest::PUBLIC_ARTIFACTS,
        "never_commit": swp_manifest::PRIVATE_ARTIFACTS,
        "back_up": swp_manifest::BACKUP_ARTIFACTS,
    });
    let mut out = vec![
        format!(
            "store {} — project {}",
            s.relabel(&s.swp_dir()),
            project.identity.project_id
        ),
        format!("  root        {}", s.project_root().display()),
        format!(
            "  secret      {}",
            if s.root_key_exists() {
                format!("present · {}", s.relabel(&s.root_key_path()))
            } else {
                format!(
                    "MISSING — nothing in this store can be verified or scanned without it. \
                     Restore {} from the backup.",
                    s.relabel(&s.root_key_path())
                )
            }
        ),
        format!("  created     {}", project.identity.created_at.to_rfc3339()),
        format!(
            "  protocol    {} · canonicalizer {}",
            project.identity.protocol, project.identity.canonicalizer_version
        ),
        format!(
            "  counts      {} release(s), {} manifest(s), {} plan(s), {} report(s)",
            count("public/releases/"),
            count("private/manifests/"),
            count("private/plans/"),
            count("private/reports/")
        ),
        String::new(),
        format!("  {:<50} {}", "artifact", "may commit"),
    ];
    for (path, public) in &inventory {
        out.push(format!(
            "  {:<50} {}",
            truncate(path, 50),
            if *public { "yes" } else { "never" }
        ));
    }
    out.push(String::new());
    out.push(format!("  {} artifact(s) in the store.", inventory.len()));
    out.push(format!("  back up: {}", swp_manifest::BACKUP_ARTIFACTS.join(", ")));
    out.push(String::new());
    out.push("Views".to_string());
    for v in View::ALL {
        out.push(format!("  {:<11} {}", v.as_str(), v.blurb()));
    }
    Ok((None, data, out, json!({})))
}

// --------------------------------------------------------------------------------------
// identity
// --------------------------------------------------------------------------------------

fn identity_view(project: &Ctx) -> Result<Rendering, SwpError> {
    let i = &project.identity;
    let data = serde_json::to_value(i).map_err(|e| SwpError::internal(format!("identity: {e}")))?;
    // The stored base64 is what gets printed, so decode it first: a file whose
    // key does not parse must not be described as one that verifies anything.
    let key = i.verify_key()?;
    let out = vec![
        format!(
            "identity {}",
            project.store.relabel(&project.store.identity_path())
        ),
        String::new(),
        format!("  project     {}", i.project_id),
        format!("  display     {}", i.display_name),
        format!("  created     {}", i.created_at.to_rfc3339()),
        format!(
            "  protocol    {} · schema {} · canonicalizer {}",
            i.protocol, i.schema, i.canonicalizer_version
        ),
        format!("  generator   {} {}", i.generator.generator, i.generator.swp_version),
        format!(
            "  verify key  {} ({}, {} bytes)",
            i.verification.verify_key_b64,
            i.verification.algorithm,
            key.as_bytes().len()
        ),
        String::new(),
        "  This file is public by design: the verify key authenticates this project's".to_string(),
        "  manifests and release records, and anyone holding it can check them. Nobody".to_string(),
        "  holding it can produce one — the signing key is derived from the root secret and".to_string(),
        "  is never stored. The project id is that same derivation, so changing the display".to_string(),
        "  name here never changes which copies are yours.".to_string(),
    ];
    Ok((None, data, out, json!({})))
}

// --------------------------------------------------------------------------------------
// config
// --------------------------------------------------------------------------------------

fn config_view(project: &Ctx) -> Result<Rendering, SwpError> {
    let cfg = project.stored_config()?;
    let toml = cfg.to_toml();
    let data = json!({
        "path": project.store.relabel(&project.store.config_path()),
        "toml": toml,
        "config": serde_json::to_value(&cfg)
            .map_err(|e| SwpError::internal(format!("config: {e}")))?,
    });
    let mut out = vec![format!(
        "config {}",
        project.store.relabel(&project.store.config_path())
    )];
    out.push(String::new());
    out.extend(toml.lines().map(|l| l.to_string()));
    out.push(String::new());
    out.push("  This is the file as it stands on disk. `--target`, `--sites` and `--bits`".to_string());
    out.push("  change what one protection run uses and never write here, which is why".to_string());
    out.push("  `swp protect` prints the settings a run actually used.".to_string());
    if !project.warnings.is_empty() {
        out.push(String::new());
        out.push("  Applied on top of this file for the current command:".to_string());
        for w in &project.warnings {
            out.push(format!("  · {w}"));
        }
    }
    Ok((None, data, out, json!({})))
}

// --------------------------------------------------------------------------------------
// releases and release
// --------------------------------------------------------------------------------------

fn releases_view(project: &Ctx, limit: usize) -> Result<Rendering, SwpError> {
    let history = project.release_history()?;
    if history.is_empty() {
        return Err(SwpError::new(
            ErrorCode::NotProtected,
            "this project has no releases yet. `swp generate` plans one; `swp protect` makes one.",
        ));
    }
    let rows: Vec<Value> = history
        .iter()
        .map(|r| release_row(project, r))
        .collect::<Result<_, _>>()?;
    let (shown, omitted) = output::head(&rows, limit);
    let mut out = vec![format!(
        "releases — {} of project {}",
        history.len(),
        project.identity.project_id
    )];
    out.push(String::new());
    out.push(format!(
        "  {:<22} {:<22} {:>5} {:>7} {:>4}  {}",
        "release", "created", "sites", "skipped", "bits", "private half"
    ));
    for row in shown {
        out.push(format!(
            "  {:<22} {:<22} {:>5} {:>7} {:>4}  {}",
            row["release_id"].as_str().unwrap_or_default(),
            row["created_at"].as_str().unwrap_or_default(),
            row["watermark"]["sites_embedded"].as_u64().unwrap_or_default(),
            row["watermark"]["sites_skipped"].as_u64().unwrap_or_default(),
            row["watermark"]["tag_bits"].as_u64().unwrap_or_default(),
            private_half(row),
        ));
    }
    if omitted > 0 {
        out.push(format!("  … and {omitted} more; --full lists every one"));
    }
    out.push(String::new());
    out.push(format!(
        "  {} site(s) across {} release(s). A `swp scan` matches a candidate against all of \
         them unless --release or --latest names one.",
        rows.iter()
            .map(|r| r["watermark"]["sites_embedded"].as_u64().unwrap_or_default())
            .sum::<u64>(),
        history.len()
    ));
    out.push("  `swp inspect release --release <id>` reads one record in full.".to_string());
    Ok((
        None,
        json!({ "releases": rows }),
        out,
        json!({ "releases": omitted }),
    ))
}

fn private_half(row: &Value) -> String {
    let m = &row["private_manifest"];
    match (m["present"].as_bool(), m["digest_agrees"].as_bool()) {
        (Some(true), Some(true)) => format!("manifest ({} site(s))", m["sites"].as_u64().unwrap_or(0)),
        (Some(true), _) => "manifest here, digest DISAGREES with the record".to_string(),
        (Some(false), _) => format!(
            "MISSING — restore {}",
            m["path"].as_str().unwrap_or(".swp/private/manifests/")
        ),
        _ => "unknown".to_string(),
    }
}

/// One record, plus the two facts the public half cannot know on its own: that the
/// private manifest is present, and that it hashes to the digest this record
/// published. A restored backup with a half-copied `.swp/` is what that check is
/// for, and it is the failure mode every other error message in this store names.
fn release_row(project: &Ctx, r: &ReleaseRecord) -> Result<Value, SwpError> {
    let id = &r.release_id;
    let mut row =
        serde_json::to_value(r).map_err(|e| SwpError::internal(format!("release record: {e}")))?;
    let manifest_at = project.store.manifest_path(id);
    let plan_at = project.store.plan_path(id);
    let mut manifest = json!({
        "path": project.store.relabel(&manifest_at),
        "present": manifest_at.is_file(),
    });
    if manifest_at.is_file() {
        let bytes = project.store.read_private_manifest(id)?;
        manifest["bytes"] = json!(bytes.len());
        manifest["digest_agrees"] =
            json!(swp_manifest::sha256(&bytes) == r.private_manifest_digest);
        // Reading it authenticates it. A manifest that does not verify under this
        // project's own key is an error to report, not a row to print.
        let m = project.manifest(id)?;
        if &m.release_id != id {
            return Err(mismatch(id, &m));
        }
        manifest["sites"] = json!(m.site_count());
    }
    row["private_manifest"] = manifest;
    row["plan"] = json!({
        "path": project.store.relabel(&plan_at),
        "present": plan_at.is_file(),
    });
    Ok(row)
}

fn release_view(project: &Ctx, parsed: &Parsed) -> Result<Rendering, SwpError> {
    let id = project.one_release(parsed)?;
    let record = project.store.read_release(&id)?;
    let data = release_row(project, &record)?;
    let w = &record.watermark;
    let manifest = &data["private_manifest"];
    let manifest_line = match (
        manifest["present"].as_bool(),
        manifest["digest_agrees"].as_bool(),
    ) {
        (Some(true), Some(true)) => format!(
            "present ({} byte(s)), and it hashes to the digest this record published",
            manifest["bytes"].as_u64().unwrap_or_default()
        ),
        (Some(true), _) => "present, but it does NOT hash to the digest this record published"
            .to_string(),
        _ => format!(
            "missing — restore {}",
            manifest["path"].as_str().unwrap_or_default()
        ),
    };
    let out = vec![
        format!("release {id} of project {}", record.project_id),
        String::new(),
        format!("  created     {}", record.created_at.to_rfc3339()),
        format!(
            "  revision    {}",
            record
                .source_revision
                .as_str()
                .unwrap_or("content — no revision label was given")
        ),
        format!(
            "  watermark   {} embedded · {} refused · {} bit(s) each · ceiling {} site(s)",
            w.sites_embedded, w.sites_skipped, w.tag_bits, w.target_sites
        ),
        format!("  canonical   version {}", w.canonicalizer_version),
        format!(
            "  adapters    {}",
            w.adapters
                .iter()
                .map(|a| format!("{} {} ({})", a.language, a.mode, a.files))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("  form set    {}", w.form_set),
        format!(
            "  fingerprint {} ({})",
            record.fingerprint, record.fingerprint_level
        ),
        format!("  manifest    {manifest_line}"),
        format!("  plan        {}", data["plan"]["path"].as_str().unwrap_or_default()),
        String::new(),
        "  The record is signed and public: `.swp/public/releases/` may be committed, and a".to_string(),
        "  copy of it proves nothing without the private manifest it is the digest of. That".to_string(),
        "  split is deliberate — the record says what was protected, the manifest says where.".to_string(),
        String::new(),
        format!("  `swp inspect fragments --release {id}` reads the site list."),
    ];
    Ok((Some(id), data, out, json!({})))
}

// --------------------------------------------------------------------------------------
// manifest, plan, fragments
// --------------------------------------------------------------------------------------

fn manifest_view(project: &Ctx, parsed: &Parsed, limit: usize) -> Result<Rendering, SwpError> {
    let id = project.one_release(parsed)?;
    let manifest = project.manifest(&id)?;
    if manifest.release_id != id {
        return Err(mismatch(&id, &manifest));
    }
    let data = serde_json::to_value(&manifest)
        .map_err(|e| SwpError::internal(format!("manifest: {e}")))?;
    let (shown, omitted) = output::head(&manifest.sites, limit);
    let mut out = vec![
        format!("manifest {id} — signed, and authenticated against this project's verify key"),
        format!(
            "  path        {}",
            project.store.relabel(&project.store.manifest_path(&id))
        ),
        format!(
            "  sites       {} · {} bit(s) each · canonicalizer {}",
            manifest.site_count(),
            manifest.tag_bits,
            manifest.canonicalizer_version
        ),
        format!(
            "  fingerprint {} ({})",
            manifest.fingerprint, manifest.fingerprint_level
        ),
        format!("  digest      {}", manifest.content_digest()),
        String::new(),
        format!(
            "  {:<5} {:<28} {:<9} {:<10} {:>4}  {}",
            "site", "file:line", "class", "family", "bits", "primary key"
        ),
    ];
    for (i, s) in shown.iter().enumerate() {
        out.push(format!(
            "  {:<5} {:<28} {:<9} {:<10} {:>4}  {}",
            i,
            truncate(&format!("{}:{}", s.file, s.line_hint), 28),
            s.class.as_str(),
            s.family.as_str(),
            s.width,
            primary_kind(s),
        ));
    }
    if omitted > 0 {
        out.push(format!("  … and {omitted} more; --full lists every one"));
    }
    out.push(String::new());
    out.push("  Every site carries four keyed identities: the statement radius and the scope".to_string());
    out.push("  radius, each with local names abstracted and each with them kept. The tag hangs".to_string());
    out.push("  off the `primary` one. `--format json` prints all four, and both literals.".to_string());
    Ok((Some(id), data, out, json!({ "sites": omitted })))
}

fn primary_kind(s: &SiteEntry) -> &'static str {
    match RadiusKind::from_code(s.primary) {
        Ok(k) => k.as_str(),
        // A manifest that got this far authenticated its signature, so an unknown
        // code here is a protocol disagreement rather than corruption; `verify`
        // and `scan` refuse the release outright, and a listing only says so.
        Err(_) => "unknown",
    }
}

fn plan_view(project: &Ctx, parsed: &Parsed, limit: usize) -> Result<Rendering, SwpError> {
    let id = project.one_release(parsed)?;
    let at = project.store.plan_path(&id);
    let bytes = match project.store.read_plan(&id) {
        Ok(b) => b,
        Err(e) if !at.is_file() => {
            return Err(SwpError::new(
                ErrorCode::NotProtected,
                format!(
                    "there is no plan for release {id} at {}. `swp generate` writes one; a \
                     release whose plan was not restored with the rest of .swp/ has only its \
                     manifest.",
                    project.store.relabel(&at)
                ),
            )
            .caused_by(&e))
        }
        Err(e) => return Err(e),
    };
    let plan = swp_embedding::Plan::from_json_bytes(&bytes)?;
    if plan.release_id != id {
        return Err(SwpError::new(
            ErrorCode::ReleaseMismatch,
            format!(
                "the plan filed under {id} describes release {}",
                plan.release_id
            ),
        ));
    }
    let data = serde_json::to_value(&plan).map_err(|e| SwpError::internal(format!("plan: {e}")))?;
    let (shown, omitted) = output::head(&plan.skipped, limit);
    let mut out = vec![
        format!("plan {id} — what this run intended, written before any of it happened"),
        format!("  path        {}", project.store.relabel(&at)),
        format!("  targets     {}", plan.targets.join(", ")),
        format!("  excludes    {}", plan.excludes.join(", ")),
        format!(
            "  asked       {} site(s), ceiling {} · {} planned · {} refused · {} bit(s)",
            plan.requested_sites,
            plan.target_sites,
            plan.sites.len(),
            plan.skipped.len(),
            plan.tag_bits
        ),
        format!(
            "  strings     {}",
            if plan.embed_strings { "enabled" } else { "disabled" }
        ),
        String::new(),
        "What was refused, and why (§11: skipped, never forced)".to_string(),
    ];
    if plan.skipped.is_empty() {
        out.push("  nothing was refused".to_string());
    }
    for s in shown {
        out.push(format!(
            "  {:<22} {:<28} line {:<5} {}",
            s.reason,
            truncate(&s.file, 28),
            s.line_hint,
            truncate(&s.detail, 56)
        ));
    }
    if omitted > 0 {
        out.push(format!("  … and {omitted} more; --full lists every one"));
    }
    if !plan.notes.is_empty() {
        out.push(String::new());
        out.push("Notes".to_string());
        for n in &plan.notes {
            out.push(format!("  · {n}"));
        }
    }
    out.push(String::new());
    out.push(format!("  The {} planned site(s), counted:", plan.sites.len()));
    for (label, groups) in [
        ("class", tally(&plan.sites, |s| s.class.clone())),
        ("family", tally(&plan.sites, |s| s.family.clone())),
        ("adapter", tally(&plan.sites, |s| s.adapter.clone())),
    ] {
        out.push(format!("    by {:<7} {}", label, groups.join(", ")));
    }
    out.push(String::new());
    out.push("  A plan is unsigned: it records an intent, not a claim about the release. The".to_string());
    out.push("  manifest is the signed half — and a plan holds no literal text and no tag, so".to_string());
    out.push("  this is the only place the refusals are written down.".to_string());
    Ok((Some(id), data, out, json!({ "skipped": omitted })))
}

/// Counts of planned sites by one attribute, keyed by the attribute's name so
/// two runs of the same plan print the same lines.
fn tally(
    sites: &[swp_embedding::plan::PlannedSite],
    key: impl Fn(&swp_embedding::plan::PlannedSite) -> String,
) -> Vec<String> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for s in sites {
        *counts.entry(key(s)).or_insert(0) += 1;
    }
    counts
        .iter()
        .map(|(name, n)| format!("{name} {n}"))
        .collect()
}

/// The constellation as a table a person reads: what sits where now, what was
/// there before, and what the run refused to touch. The manifest supplies the
/// first two; only the plan knows the third.
fn fragments_view(project: &Ctx, parsed: &Parsed, limit: usize) -> Result<Rendering, SwpError> {
    let id = project.one_release(parsed)?;
    let manifest = project.manifest(&id)?;
    if manifest.release_id != id {
        return Err(mismatch(&id, &manifest));
    }
    let refused = project
        .store
        .read_plan(&id)
        .ok()
        .and_then(|bytes| swp_embedding::Plan::from_json_bytes(&bytes).ok())
        .map(|plan| plan.skipped)
        .unwrap_or_default();
    let (shown, omitted) = output::head(&manifest.sites, limit);
    let mut out = vec![format!(
        "fragments {id} — {} site(s), {} bit(s) each{}",
        manifest.sites.len(),
        manifest.tag_bits,
        if refused.is_empty() {
            String::new()
        } else {
            format!(", {} candidate(s) refused", refused.len())
        }
    )];
    out.push(String::new());
    out.push(format!(
        "  {:<5} {:<26} {:<10} {:<8} {:>4}  what is written there now",
        "site", "file:line", "family", "class", "bits"
    ));
    for (i, s) in shown.iter().enumerate() {
        out.push(format!(
            "  {:<5} {:<26} {:<10} {:<8} {:>4}  {}",
            i,
            truncate(&format!("{}:{}", s.file, s.line_hint), 26),
            s.family.as_str(),
            s.class.as_str(),
            s.width,
            truncate(&s.rendered, 44)
        ));
    }
    if omitted > 0 {
        out.push(format!("  … and {omitted} more; --full lists every one"));
    }
    out.push(String::new());
    out.push("  The last column is what `swp verify` looks for and what a scan decodes its".to_string());
    out.push("  fragment out of. Its value to anybody else is that it means nothing without".to_string());
    out.push("  this project's root secret — which is why reading it here is safe and".to_string());
    out.push("  publishing it is not.".to_string());
    let data = json!({
        "release_id": id.to_string(),
        "tag_bits": manifest.tag_bits,
        "sites": manifest.sites.iter().enumerate().map(|(i, s)| json!({
            "site": i,
            "file": s.file,
            "line_hint": s.line_hint,
            "language": s.language,
            "adapter": s.adapter,
            "grammar_path": s.grammar_path,
            "class": s.class.as_str(),
            "family": s.family.as_str(),
            "width": s.width,
            "primary": primary_kind(s),
            "original": s.original,
            "rendered": s.rendered,
        })).collect::<Vec<_>>(),
        "refused": refused.iter().map(|s| json!({
            "file": s.file,
            "line_hint": s.line_hint,
            "reason": s.reason,
            "detail": s.detail,
        })).collect::<Vec<_>>(),
    });
    Ok((Some(id), data, out, json!({ "sites": omitted })))
}

fn mismatch(id: &ReleaseId, m: &PrivateManifest) -> SwpError {
    SwpError::new(
        ErrorCode::ReleaseMismatch,
        format!(
            "the manifest filed under {id} is signed as release {}, which is a different \
             constellation",
            m.release_id
        ),
    )
}

/// Count characters so a non-ASCII path cannot land a slice inside a codepoint.
fn truncate(text: &str, width: usize) -> String {
    output::clip(text, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    /// A protected project and the release it published.
    fn protected(command: &str, label: &str) -> (Scratch, String) {
        let dir = Scratch::protected(command, label);
        let doc = dir
            .run(&["inspect", "releases", "--format", "json"])
            .json();
        let release = doc["data"]["releases"][0]["release_id"]
            .as_str()
            .unwrap()
            .to_string();
        (dir, release)
    }

    /// The keyed addresses of one release, read back from the private manifest.
    fn addresses(dir: &Scratch, release: &str) -> Vec<String> {
        let raw = dir.read(&format!(".swp/private/manifests/{release}.json"));
        let doc: Value = serde_json::from_str(&raw).unwrap();
        let mut out = Vec::new();
        for site in doc["sites"].as_array().unwrap() {
            for id in site["locations"].as_array().unwrap() {
                out.push(id.as_str().unwrap_or_default().to_string());
            }
        }
        assert!(out.len() >= 4, "the manifest holds no addresses: {raw}");
        out
    }

    #[test]
    fn every_view_answers_about_a_protected_project() {
        let (dir, release) = protected("inspect", "all-views");
        for view in View::ALL {
            let r = dir.run(&["inspect", view.as_str(), "--format", "json"]);
            assert_eq!(r.code, 0, "{} view failed:
{}{}", view.as_str(), r.out, r.err);
            let doc = r.json();
            assert_eq!(doc["schema"], SCHEMA);
            assert_eq!(doc["view"], view.as_str());
            assert_eq!(doc["project_id"], dir.project_id().as_str());
            assert_ne!(doc["data"], Value::Null, "{} printed no data", view.as_str());
            // The four release-scoped views all name the release they read, and
            // with one release on disk there is exactly one candidate for that.
            if view.is_private() || view == View::Release {
                assert_eq!(doc["release_id"], release.as_str(), "{}", view.as_str());
            }
        }
        // No argument is the store view, which is the answer to "what do I have?".
        let bare = dir.run(&["inspect", "--format", "json"]);
        assert_eq!(bare.json()["view"], "store", "{}", bare.err);
    }

    #[test]
    fn the_private_views_warn_about_exactly_what_each_one_prints() {
        let (dir, release) = protected("inspect", "private-views");
        let ids = addresses(&dir, &release);
        for view in [View::Manifest, View::Plan, View::Fragments] {
            let r = dir.run(&["inspect", view.as_str(), "--format", "json"]);
            assert_eq!(r.code, 0, "{}", r.err);
            assert!(
                r.err.contains("do not paste it into an issue"),
                "{} printed the constellation without saying who may see it:
{}",
                view.as_str(),
                r.err
            );
            // And the warning names what *this* view gives away. `fragments` prints
            // literals and no address, so a warning that promised addresses there
            // would be a statement about output that is not on the screen (§51).
            let names_addresses = r.err.contains("keyed site addresses");
            assert_eq!(
                names_addresses,
                matches!(view, View::Manifest | View::Plan),
                "{}'s warning describes the wrong leak:
{}",
                view.as_str(),
                r.err
            );
        }
        // The two views that serialize a private structure really do carry the ids,
        // in the document a script would pipe into a log.
        for view in [View::Manifest, View::Plan] {
            let r = dir.run(&["inspect", view.as_str(), "--format", "json"]);
            assert!(
                ids.iter().any(|id| r.out.contains(id)),
                "{} warned about addresses and printed none",
                view.as_str()
            );
        }
        // `fragments` is the one that trades an address for a literal: its whole
        // value is showing what the watermark looks like in the source.
        let frags = dir.run(&["inspect", "fragments", "--format", "json"]).json();
        let sites = frags["data"]["sites"].as_array().unwrap();
        assert!(!sites.is_empty(), "the fragments view printed no site");
        assert!(
            sites.iter().all(|s| s["rendered"].as_str().is_some_and(|r| !r.is_empty())),
            "a site arrived without the text at it: {frags:#}"
        );
        assert!(
            sites.iter().all(|s| s["locations"].is_null()),
            "the fragments view started printing keyed addresses; the manifest view is \
             where they belong: {frags:#}"
        );
        // The other five are the views an operator would share. None of them may
        // carry a keyed address, because a leak of those is a leak of the watermark.
        for view in [View::Store, View::Identity, View::Config, View::Releases, View::Release] {
            let r = dir.run(&["inspect", view.as_str(), "--format", "json"]);
            assert_eq!(r.code, 0, "{}", r.err);
            assert!(
                !r.err.contains("do not paste"),
                "{} warned about a leak it did not cause",
                view.as_str()
            );
            for id in &ids {
                assert!(!r.out.contains(id), "{} leaked keyed address {id}", view.as_str());
                assert!(!r.err.contains(id), "{} leaked keyed address {id} on stderr", view.as_str());
            }
        }
    }

    #[test]
    fn inspect_reads_a_store_whose_root_key_is_absent() {
        // The module doc's first rule, stated as the smallest experiment that can
        // falsify it: take the secret away and every view still answers. A store
        // copied to a machine without the key is the normal shape of an audit, and
        // a command that needed the secret would either fail or prompt for one.
        let (dir, _release) = protected("inspect", "no-key");
        let key = dir.root.join(".swp").join("private").join("root.key");
        assert!(key.exists(), "the fixture wrote no root key");
        std::fs::remove_file(&key).unwrap();
        for view in View::ALL {
            let r = dir.run(&["inspect", view.as_str(), "--format", "json"]);
            assert_eq!(
                r.code, 0,
                "{} needed the root key:
{}{}",
                view.as_str(),
                r.out,
                r.err
            );
            assert!(
                !r.out.contains("00000000") && !r.err.contains("secret"),
                "{} looked for a secret it does not need",
                view.as_str()
            );
        }
        let store = dir.run(&["inspect", "store", "--format", "json"]).json();
        assert_eq!(store["data"]["root_key"]["present"], false, "{store:#}");
    }

    #[test]
    fn an_unknown_view_is_refused_by_name_and_lists_the_real_ones() {
        let dir = Scratch::protected("inspect", "bad-view");
        let r = dir.run(&["inspect", "constellation"]);
        assert_eq!(r.code, ErrorCode::Usage.exit_code(), "{}", r.err);
        for name in View::names() {
            assert!(r.err.contains(name), "the refusal omitted {name:?}: {}", r.err);
        }
        // Two arguments are a mistake too, not a second view to merge.
        let two = dir.run(&["inspect", "store", "identity"]);
        assert_eq!(two.code, ErrorCode::Usage.exit_code(), "{}", two.err);
        assert!(two.err.contains("one thing"), "{}", two.err);
    }
}
