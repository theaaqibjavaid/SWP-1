//! A project the suites can protect, mutate and judge — driven through the CLI.
//!
//! Every suite here goes through [`swp_cli::run_in`] rather than calling the
//! library APIs directly. That is a deliberate cost: the crate units already
//! test the pipeline, and what §42 asks for is a matrix over the thing an
//! operator runs, on a tree a person could hold. A measurement of
//! `swp_embedding::protect()` is a measurement of a function; a measurement of
//! `swp protect` is a measurement of the product, and it is the second one the
//! documentation quotes.
//!
//! Three rules keep the suites honest about what they measured:
//!
//! * **A candidate never carries a store.** [`Project::copy_to`] copies sources
//!   and nothing else, because §21's whole point is that the scanner's keys come
//!   from the project doing the scanning. A candidate with its own `.swp/` would
//!   be a second project, not a leak.
//! * **Mutations are named, not improvised.** Each edit in §25 and §26 is one
//!   method, so a documented result points at the code that produced it.
//! * **Nothing is deleted until the process that made it exits.** Directories
//!   holding a root secret go through [`crate::tmp::TempDir::sensitive`], which
//!   complains out loud if cleanup fails.

use std::path::{Path, PathBuf};

use serde_json::Value;
use swp_identity::Store;

use crate::fixtures;
use crate::tmp::TempDir;

/// One protected project: a directory, a `.swp/`, and the release it published.
pub struct Project {
    dir: TempDir,
}

impl Project {
    /// A project of `modules` generated JavaScript modules (§24's partial-copy
    /// ladder needs a tree it can take a tenth of).
    pub fn synthetic(label: &str, modules: usize) -> Self {
        Self::synthetic_variant(label, modules, 0)
    }

    /// [`Self::synthetic`] over one of the generator's other variants: the same
    /// twelve module *shapes*, different names and constants — and, because the
    /// store is created here, a different root key.
    ///
    /// §28's interesting question is not whether two unrelated repositories
    /// collide, but whether two projects that look alike to a human stay apart
    /// for a machine.
    pub fn synthetic_variant(label: &str, modules: usize, variant: usize) -> Self {
        let dir = TempDir::new(label).sensitive();
        fixtures::synthetic_variant(dir.path(), modules, variant);
        let project = Project { dir };
        project.init();
        project
    }

    /// A project whose modules share the generator's constants as well as its
    /// shapes: one team's house style across `modules` files.
    pub fn dense_variant(label: &str, modules: usize, variant: usize) -> Self {
        let dir = TempDir::new(label).sensitive();
        fixtures::synthetic_dense(dir.path(), modules, variant);
        let project = Project { dir };
        project.init();
        project
    }

    /// One of the hand-written language fixtures, already `swp init`-ed.
    pub fn fixture(label: &str, language: &str) -> Self {
        let dir = TempDir::new(label).sensitive();
        match language {
            "javascript" => fixtures::javascript_project(dir.path()),
            "typescript" => fixtures::typescript_project(dir.path()),
            "python" => fixtures::python_project(dir.path()),
            "forms" => fixtures::form_project(dir.path()),
            other => panic!("no {other:?} fixture — the suites name four trees"),
        };
        let project = Project { dir };
        project.init();
        project
    }

    /// [`Self::synthetic`] with `target_sites` raised to the ceiling the config
    /// allows. Site-count experiments need a constellation wider than the
    /// measured suggestion for a small tree.
    pub fn synthetic_wide(label: &str, modules: usize, target_sites: u32) -> Self {
        Self::synthetic_wide_variant(label, modules, target_sites, 0)
    }

    /// [`Self::synthetic_wide`] for one generator variant: same tree shape and
    /// same constellation size, different project. §28 compares these to each
    /// other, which is why the constellation has to be the same size — a
    /// five-site project is not a fair control for a twenty-four-site one.
    pub fn synthetic_wide_variant(
        label: &str,
        modules: usize,
        target_sites: u32,
        variant: usize,
    ) -> Self {
        let project = Self::synthetic_variant(label, modules, variant);
        project.set_config(&wide_config(target_sites));
        project
    }

    /// [`Self::synthetic_wide_variant`] over a [`Self::dense_variant`] tree: the
    /// same constellation, on modules that share their constants as well as their
    /// shapes.
    pub fn dense_wide(label: &str, modules: usize, target_sites: u32, variant: usize) -> Self {
        let project = Self::dense_variant(label, modules, variant);
        project.set_config(&wide_config(target_sites));
        project
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn dir(&self) -> &TempDir {
        &self.dir
    }

    pub fn store(&self) -> Store {
        Store::open(self.root()).expect("this project was never initialized")
    }

    pub fn project_id(&self) -> String {
        self.store().project_id().unwrap().to_string()
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root().join(rel))
            .unwrap_or_else(|e| panic!("{}: {e}", self.dir.child(rel).display()))
    }

    pub fn write(&self, rel: &str, body: &str) {
        self.dir.write(rel, body.as_bytes());
    }

    pub fn remove(&self, rel: &str) {
        let path = self.root().join(rel);
        if path.is_file() {
            std::fs::remove_file(path).unwrap();
        }
    }

    pub fn rename(&self, from: &str, to: &str) {
        let body = self.read(from);
        self.remove(from);
        self.write(to, &body);
    }

    /// Every source path, sorted, `.swp/` excluded.
    pub fn sources(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect(self.root(), self.root(), &mut out);
        out.sort();
        out
    }

    /// Replace `.swp/config.toml` wholesale. The suites use this to pin
    /// `target_sites` where the measured suggestion is smaller than the
    /// experiment needs; a config the test wrote is a config the test can name.
    pub fn set_config(&self, body: &str) {
        self.write(".swp/config.toml", body);
    }

    pub fn run(&self, argv: &[&str]) -> Run {
        Run::of(argv, self.root())
    }

    /// `swp init`, with the assertion every suite repeats.
    fn init(&self) {
        let r = self.run(&["init", "--quiet"]);
        assert_eq!(r.code, 0, "init failed:\n{}{}", r.out, r.err);
    }

    /// `swp protect`, returning the release it published.
    ///
    /// Asserts the run embedded at least one site: a suite that measured a zero
    /// site constellation would report "detection survived" about a watermark
    /// that was never there.
    pub fn protect(&self) -> Release {
        let before = self.sites_before();
        let r = self.run(&["protect"]);
        assert_eq!(r.code, 0, "protect failed:\n{}{}", r.out, r.err);
        let after = self.store().releases().unwrap();
        let fresh = after
            .into_iter()
            .find(|id| !before.contains(id))
            .expect("protect printed success and wrote no release");
        let release = Release::read(self, &fresh.to_string());
        assert!(
            release.sites_embedded > 0,
            "protect embedded nothing into a {}-file tree: {}",
            self.sources().len(),
            r.out
        );
        release
    }

    /// `swp generate`: plans without touching the tree, and returns the plan file.
    pub fn generate(&self) -> Value {
        let r = self.run(&["generate", "--format", "json"]);
        assert_eq!(r.code, 0, "generate failed:\n{}{}", r.out, r.err);
        r.json()
    }

    fn sites_before(&self) -> Vec<swp_core::id::ReleaseId> {
        if Store::exists(self.root()) {
            self.store().releases().unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub fn releases(&self) -> Vec<String> {
        self.store()
            .releases()
            .unwrap_or_default()
            .iter()
            .map(|r| r.to_string())
            .collect()
    }

    pub fn release(&self, id: &str) -> Release {
        Release::read(self, id)
    }

    /// The newest release, which is the one `swp verify` checks by default.
    pub fn latest(&self) -> Release {
        let ids = self.releases();
        assert!(!ids.is_empty(), "this project has no releases");
        Release::read(self, ids.last().unwrap())
    }

    /// `swp verify` on this project's own tree.
    pub fn verify(&self) -> Run {
        self.run(&["verify", "--format", "json"])
    }

    /// `swp scan` of a candidate directory, from this project's point of view.
    pub fn scan(&self, candidate: &Path) -> Verdict {
        let r = self.run(&["scan", &candidate.display().to_string(), "--format", "json"]);
        assert!(
            r.code == 0 || r.code == 1 || r.code == 10,
            "scan of {} ended outside the verdict contract ({}):\n{}{}",
            candidate.display(),
            r.code,
            r.out,
            r.err
        );
        Verdict::of(r)
    }

    /// Copy this project's sources — and only its sources — into a fresh
    /// directory. This is the leaked tree a candidate is: §21 says the scanner
    /// supplies the keys, so a copy that carried `.swp/` would be a different
    /// experiment.
    pub fn copy_to_candidate(&self, label: &str, mut keep: impl FnMut(&str) -> bool) -> Candidate {
        let dir = TempDir::new(label);
        for rel in self.sources() {
            if keep(&rel) {
                let body = self.read(&rel);
                dir.write(&rel, body.as_bytes());
            }
        }
        Candidate { dir }
    }

    /// As [`Self::copy_to_candidate`], keeping the whole tree.
    pub fn copy_whole(&self, label: &str) -> Candidate {
        self.copy_to_candidate(label, |_| true)
    }

    /// A deterministic slice of the tree: the first `num` files of every `den`.
    ///
    /// "25% of the project" has to mean the same 25% in every run and in every
    /// language measured, or the ladder in §24 compares two different trees and
    /// the numbers mean nothing.
    pub fn copy_fraction(&self, label: &str, num: usize, den: usize) -> Candidate {
        let files = self.sources();
        assert!(den >= 1 && num <= den, "not a fraction of a tree");
        // Rounded up, then floored at one file: a copy of nothing is a scan of an
        // empty directory, which is a control and not a data point.
        let want = (files.len() * num).div_ceil(den).clamp(1, files.len());
        let mut kept = 0;
        self.copy_to_candidate(label, |rel| {
            let index = files.iter().position(|f| f == rel).unwrap_or(usize::MAX);
            let take = index % den < num && kept < want;
            kept += usize::from(take);
            take
        })
    }
}

/// A copied tree with no keys of its own: the thing `swp scan` is pointed at.
pub struct Candidate {
    dir: TempDir,
}

impl Candidate {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path().join(rel)).unwrap()
    }

    pub fn write(&self, rel: &str, body: &str) {
        self.dir.write(rel, body.as_bytes());
    }

    pub fn sources(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect(self.path(), self.path(), &mut out);
        out.sort();
        out
    }
}

/// One release of one project, as its own private manifest describes it.
pub struct Release {
    pub id: String,
    pub sites_embedded: u32,
    pub sites_skipped: u32,
    pub tag_bits: u8,
    pub fingerprint: String,
    pub fingerprint_level: String,
    /// Every site's keyed addresses, literals and location, from the signed
    /// private manifest.
    pub sites: Vec<Value>,
}

impl Release {
    fn read(project: &Project, id: &str) -> Self {
        let record = {
            let parsed = swp_core::id::ReleaseId::new(id)
                .unwrap_or_else(|e| panic!("release id {id:?}: {e}"));
            project.store().read_release(&parsed).unwrap()
        };
        let bytes = {
            let parsed = swp_core::id::ReleaseId::new(id).unwrap();
            project.store().read_private_manifest(&parsed).unwrap()
        };
        let manifest: Value = serde_json::from_slice(&bytes).expect("manifest is not JSON");
        Release {
            id: id.to_string(),
            sites_embedded: record.watermark.sites_embedded,
            sites_skipped: record.watermark.sites_skipped,
            tag_bits: record.watermark.tag_bits,
            fingerprint: record.fingerprint.to_string(),
            fingerprint_level: record.fingerprint_level.clone(),
            sites: manifest["sites"].as_array().cloned().unwrap_or_default(),
        }
    }

    /// The distinct files carrying a site, which is what a partial copy removes.
    pub fn files(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sites
            .iter()
            .filter_map(|s| s["file"].as_str().map(str::to_string))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Every site as an attacker holding the manifest would read it: the text in
    /// the file now, and the text that was there before protection.
    ///
    /// Three suites mutate by that pair (§26, §43, §52) and a fourth prints it
    /// (`swp-validate`), which is why it lives here rather than beside one of
    /// them: four copies of the same projection are four chances for a documented
    /// number to stop meaning the same attack.
    pub fn site_texts(&self) -> Vec<crate::transform::SiteText> {
        self.sites
            .iter()
            .filter_map(crate::transform::SiteText::from_manifest)
            .collect()
    }

    /// Every keyed address in this release, as hex text. The suites use it to
    /// prove a public artifact printed none of them.
    pub fn addresses(&self) -> Vec<String> {
        let mut out = Vec::new();
        for site in &self.sites {
            for id in site["locations"].as_array().into_iter().flatten() {
                if let Some(text) = id.as_str() {
                    out.push(text.to_string());
                }
            }
        }
        out
    }
}

/// What one `swp scan` or `swp verify` said, in the fields every suite reads.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub run: Run,
    pub result: String,
    pub level: String,
    pub partial: bool,
    /// The best-matching release's counts, when there was one.
    pub fragments: usize,
    /// The project the best-matching release belongs to, as the report names it.
    /// Attribution is the question §52's fragment-planting attack asks, and the
    /// answer has to be read out of the document rather than assumed from which
    /// store ran the scan.
    pub project_id: String,
    pub files: usize,
    pub exact: usize,
    pub canonical_only: usize,
    pub moved: usize,
    pub stripped: usize,
    pub fingerprint: String,
    /// Files and bytes the scan says it read, from the report's `candidate`
    /// block. A clean verdict over a tree the scanner never opened is not a clean
    /// verdict, so a suite that reports "nothing found" has to be able to say how
    /// much it looked at.
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    /// Spans that reached a tag comparison — the volume the chance bound is set
    /// by, which is why a suite reading only `fragments` can be misled.
    pub probes: u32,
    pub chance: f64,
    pub guarantee: f64,
    /// The tag width the release was embedded at, which is what turns [`Self::probes`]
    /// into a bound.
    pub tag_bits: u8,
}

impl Verdict {
    /// Read a finished `swp scan`/`swp verify` run as a verdict.
    ///
    /// Public because a suite that has to accept a refusal as well as a report
    /// (§45) runs the command itself and sorts the exit code afterwards; the one
    /// in `Project::scan` asserts the code first, which would hide the case.
    pub fn of(run: Run) -> Self {
        let doc = run.json();
        let top = doc["releases"].as_array().and_then(|a| a.first());
        let count = |key: &str| top.and_then(|t| t[key].as_u64()).unwrap_or(0) as usize;
        let real = |key: &str| top.and_then(|t| t[key].as_f64()).unwrap_or(0.0);
        Verdict {
            result: doc["result"].as_str().unwrap_or_default().to_string(),
            level: doc["evidence_level"].as_str().unwrap_or("NONE").to_string(),
            partial: doc["candidate"]["partial"].as_bool().unwrap_or(false),
            files_scanned: doc["candidate"]["files_scanned"].as_u64().unwrap_or(0) as u32,
            bytes_scanned: doc["candidate"]["bytes_scanned"].as_u64().unwrap_or(0),
            fragments: count("fragments"),
            project_id: top
                .and_then(|t| t["project_id"].as_str())
                .unwrap_or("")
                .to_string(),
            files: count("files"),
            exact: count("exact_renderings"),
            canonical_only: count("canonical_only"),
            moved: count("moved"),
            stripped: count("stripped"),
            fingerprint: top
                .and_then(|t| t["fingerprint"].as_str())
                .unwrap_or("absent")
                .to_string(),
            chance: real("chance"),
            guarantee: real("guarantee"),
            tag_bits: top.and_then(|t| t["tag_bits"].as_u64()).unwrap_or(0) as u8,
            probes: top.and_then(|t| t["probes"].as_u64()).unwrap_or(0) as u32,
            run,
        }
    }

    /// The expectation of a coincidental confirmation with *nothing* assumed about
    /// the spans behind [`Self::probes`]: `probes × 2^-width`, so two spans that
    /// present the same statement at the same address count twice.
    ///
    /// The report's own `chance` is tighter — it discounts repeats, on the ground
    /// that spans sharing a keyed address are independent draws — and the two
    /// figures part company exactly where §27's largest corpus lives: a generated
    /// tree with hundreds of copies of one statement. A suite that quotes only the
    /// tight one is quoting an assumption, so the tables here print both and the
    /// documentation can say how much of a verdict the assumption carries. This is
    /// recomputed from the report's numbers rather than read from a field, so the
    /// measurement does not inherit the arithmetic it is checking.
    pub fn union_bound(&self) -> f64 {
        self.probes as f64 * 0.5f64.powi(self.tag_bits as i32)
    }

    /// `PROVENANCE_DETECTED`, i.e. the scan put the finding on the record.
    pub fn detected(&self) -> bool {
        self.result == "PROVENANCE_DETECTED"
    }

    /// The finding's exit code, so a suite can assert the verdict and the code
    /// are the same statement.
    pub fn is_clean(&self) -> bool {
        self.result == "NO_PROVENANCE_DETECTED"
    }
}

/// One command line's whole observable answer.
#[derive(Debug, Clone)]
pub struct Run {
    pub argv: Vec<String>,
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl Run {
    /// Run `swp` with `argv` in `cwd`. The suites drive the in-process entry
    /// point, which is the same function `swp`'s `main` calls; the arguments and
    /// the working directory are all a command takes in from the world.
    pub fn of(argv: &[&str], cwd: &Path) -> Self {
        let owned: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = swp_cli::run_in(&owned, cwd, &mut out, &mut err);
        Run {
            argv: owned,
            code,
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        }
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.out).unwrap_or_else(|e| {
            panic!(
                "`swp {}` printed no JSON document: {e}\n{}",
                self.argv.join(" "),
                self.out
            )
        })
    }

    /// Assert the command succeeded, and return it for further reading.
    pub fn ok(self) -> Self {
        assert_eq!(
            self.code,
            0,
            "`swp {}` exited {}:\n{}{}",
            self.argv.join(" "),
            self.code,
            self.out,
            self.err
        );
        self
    }
}

/// The config the wide trees are protected with.
///
/// The measured suggestion for a twelve-module tree is a smaller constellation
/// than §25's per-file attacks can be read in, so the suites that need one pin
/// it here — and pin it the *same way*, so a "site lost to renaming" in one table
/// and a "site lost to renaming" in another mean the same twenty-four sites.
fn wide_config(target_sites: u32) -> String {
    format!(
        "[protect]\ntargets = [\"src\"]\ntarget_sites = {target_sites}\ntag_bits = 4\nembed_strings \
         = true\n"
    )
}

/// `swp` outside any project: the CLI has no directory of its own to act on, so
/// a suite that only needs a store-less working directory uses this.
pub fn run_in(argv: &[&str], cwd: &Path) -> Run {
    Run::of(argv, cwd)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().map(|n| n == ".swp").unwrap_or(false) {
                continue;
            }
            collect(root, &path, out);
            continue;
        }
        if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The path a suite can hand to `swp scan` for a directory that is not a
/// project at all: an empty one, which is §27's smallest control. The directory
/// is left behind on purpose — the caller removes it — because a `TempDir` that
/// cleaned itself up would take the path with it.
pub fn bare_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("swp1-bare-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&path).expect("cannot create a bare directory");
    path
}
