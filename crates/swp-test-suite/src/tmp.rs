//! Temporary directories that clean themselves up.
//!
//! Deliberately not an external dependency: the suites create directories
//! containing a *known secret*, and leaving those behind in `%TEMP%` after a
//! test run would be a small, self-inflicted version of the thing §29 tests
//! against.

use std::fs;
use std::path::{Path, PathBuf};

use swp_core::hex_encode;
use swp_crypto::random_array;

pub struct TempDir {
    path: PathBuf,
    /// Set for directories that held a secret, so a failed cleanup is loud
    /// rather than a file quietly left in a shared temp folder.
    sensitive: bool,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nonce = hex_encode(
            &random_array::<6>()
                .expect("the operating system CSPRNG must be available for test directories"),
        );
        let safe_tag: String = tag
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        path.push(format!("swp1-test-{safe_tag}-{nonce}"));
        fs::create_dir_all(&path).expect("cannot create a temporary directory");
        TempDir {
            path,
            sensitive: false,
        }
    }

    /// Mark this directory as having held key material.
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn child(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    /// Write a file under the directory, creating parent directories.
    pub fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = self.child(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("cannot create parent directories");
        }
        fs::write(&path, bytes).expect("cannot write a fixture file");
        path
    }

    pub fn read(&self, rel: &str) -> Vec<u8> {
        fs::read(self.child(rel)).unwrap_or_default()
    }

    /// Keep the directory after the test, returning its path for inspection.
    /// Used only by the performance suites, which build large trees and are run
    /// deliberately.
    pub fn keep(mut self) -> PathBuf {
        self.sensitive = false;
        self.path.clone()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.sensitive {
            let _ = fs::remove_dir_all(&self.path);
            return;
        }
        if let Err(e) = fs::remove_dir_all(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "SWP-1 TEST WARNING: a directory holding a test secret could not be removed: \
                     {} ({e})",
                    self.path.display()
                );
            }
        }
    }
}
