//! Scratch projects for the command tests: a directory, a run, and its capture.
//!
//! Every command module wants the same three things — a directory that cleans
//! itself up, a project that has been through `init` and `protect`, and a way to
//! read back what the binary printed — so they are in one file rather than
//! rewritten per module. Nothing here is public to the crate outside tests: the
//! point is a temp directory whose name is unique per `(command, label)`, because
//! these run in parallel and two tests sharing one `.swp/` produce a failure that
//! reads like a bug in the store.

use std::path::{Path, PathBuf};

use swp_identity::Store;

/// A temporary project directory, removed when the test ends.
pub struct Scratch {
    pub root: PathBuf,
}

impl Scratch {
    pub fn new(command: &str, label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "swp-cli-{}-{}-{label}",
            command,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Scratch { root }
    }

    pub fn write(&self, rel: &str, body: &str) {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
    }

    pub fn store(&self) -> Store {
        Store::open(&self.root).expect("no .swp/ in this scratch directory")
    }

    pub fn project_id(&self) -> String {
        self.store().identity().unwrap().project_id.to_string()
    }

    /// Project-relative source paths, excluding the store.
    pub fn sources(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect(&self.root, &self.root, &mut out);
        out.sort();
        out
    }

    /// Copy every source file — and deliberately not `.swp/` — into another
    /// directory, which is the shape of a leaked tree.
    pub fn copy_sources_to(&self, dest: &Scratch) {
        for rel in self.sources() {
            let body = self.read(&rel);
            dest.write(&rel, &body);
        }
    }

    /// Every path under `.swp/`, sorted, as project-relative strings. A command
    /// that claims to write nothing has to leave this list alone as much as the
    /// source: the store is where a half-finished run would show up.
    pub fn store_files(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_store(&self.root.join(".swp"), &self.root, &mut out);
        out.sort();
        out
    }

    /// A project with one real release: `swp init`, then `swp protect`.
    ///
    /// The source is ordinary enough to have candidates in every family the
    /// adapters offer, and small enough that a protect run inside a test takes
    /// milliseconds rather than seconds.
    pub fn protected(command: &str, label: &str) -> Self {
        Self::protected_variant(command, label, 0)
    }

    /// As [`Scratch::protected`], from a source that is a different source rather
    /// than a re-watermarked copy of this one.
    pub fn protected_variant(command: &str, label: &str, variant: usize) -> Self {
        let dir = Self::initialized(command, label, variant);
        let protect = dir.run(&["protect"]);
        assert_eq!(
            protect.code, 0,
            "protect failed:\n{}\n{}",
            protect.out, protect.err
        );
        assert!(
            protect.out.contains("site(s)") || protect.out.contains("sites"),
            "protect printed no account of itself:\n{}",
            protect.out
        );
        dir
    }

    /// As [`Scratch::protected_variant`], stopped after `swp init`: the source is
    /// unprotected and the caller gets to run the protection step it is testing.
    ///
    /// Variant `1` is a different source in every way that a site address reads:
    /// its own file names, function and parameter names, constants and file count.
    /// Two projects written from the *same* files are not two unrelated projects —
    /// addresses are keyed over the tree's shape, so identical trees agree on every
    /// address whatever their secrets are — and a test that means "an unrelated
    /// tree" has to say so in the source as well as in the keys.
    pub fn initialized(command: &str, label: &str, variant: usize) -> Self {
        const SHAPES: [(&str, &[&str]); 2] = [
            ("calc", &["src/a.js", "src/b.js", "lib/c.js"]),
            (
                "price",
                &[
                    "src/pricing.js",
                    "src/slug.js",
                    "lib/diff.js",
                    "lib/tokenize.js",
                ],
            ),
        ];
        let (stem, files) = SHAPES[variant % SHAPES.len()];
        let dir = Self::new(command, label);
        for (n, file) in files.iter().enumerate() {
            let mut body = String::new();
            for s in 0..(6 + variant) {
                body.push_str(&format!(
                    "function {stem}_{n}_{s}(amount, rate) {{\n  var step = {};\n  return amount \
                     * rate + step + {};\n}}\n",
                    s + 1 + variant * 3,
                    1000 + s * 17 + n * 3 + variant * 137
                ));
            }
            body.push_str(&format!(
                "var label = \"{stem}-{n}\";\nmodule.exports = {{ label: label }};\n"
            ));
            dir.write(file, &body);
        }
        let init = dir.run(&["init"]);
        assert_eq!(init.code, 0, "init failed: {}", init.err);
        dir
    }

    /// Run one command line with this directory as the working directory.
    pub fn run(&self, argv: &[&str]) -> Run {
        let owned: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = crate::run_in(&owned, &self.root, &mut out, &mut err);
        Run {
            code,
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
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

/// As [`collect`], for the one directory the source walk refuses to enter.
fn collect_store(store: &Path, root: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(store) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_store(&path, root, out);
            continue;
        }
        if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// One command's whole observable answer.
pub struct Run {
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl Run {
    /// stdout as a document. Panics on text mode on purpose: a test that asks for
    /// JSON and gets prose is failing, and the parse error is the report.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.out)
            .unwrap_or_else(|e| panic!("stdout was not one JSON document: {e}\n{}", self.out))
    }
}
