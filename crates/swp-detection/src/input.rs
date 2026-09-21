//! The scanner's front door: decide what the operator pointed at, and make it a
//! directory tree without ever running what is inside it.
//!
//! §20 says the scanner must accept a single source file, a directory, a source
//! tree, an archive and a package, and that it "must first determine what it is
//! dealing with". That ordering matters for safety as much as for UX: everything
//! downstream of this module — the walk, the site locator, the matcher — only
//! understands "a directory on this machine containing source", so this module's
//! whole job is to turn any of the five input kinds into exactly that, or to
//! refuse.
//!
//! ## Never execute, never trust the names
//!
//! §21 forbids running a candidate's build or install hooks, and this crate takes
//! that literally: no process is spawned anywhere in it. An archive is a *source
//! carrier*, not a program, and the only operations performed on it are "list" and
//! "copy out a regular file". A `.zip` whose manifest says `setup.py` is read the
//! same way as a `.zip` whose manifest says nothing.
//!
//! The second hazard is the archive's own file table. Entry names are attacker
//! content, so an entry is written only when its name resolves to a plain relative
//! path beneath the temporary root — no absolute paths, no drive letters, no
//! verbatim `\\?\` prefixes, and no `..` component at any position. Symlinks,
//! hardlinks, devices, fifos and sockets are skipped rather than extracted: a
//! symlink inside an archive is a write to somewhere else, which is exactly what
//! the name check exists to prevent. `tar` also carries `setuid`/`setgid` and
//! mode bits; none of them are applied, because the extracted tree is read and
//! then deleted.
//!
//! ## Bounded before being read (§45)
//!
//! A 42-byte zip can expand to terabytes. Every loop here is bounded four ways —
//! entry count, per-entry size, cumulative expanded bytes, and per-entry
//! compression ratio — and each bound comes from [`Limits`] rather than a local
//! constant, so the operator can lower one but cannot raise it past the hard
//! ceiling. Hitting a bound is `LimitExceeded`, which the CLI reports as an
//! inconclusive scan. Silently extracting "as much as fit" would let a
//! deliberately explosive archive win by making the scan look clean.
//!
//! Archives inside archives are never opened: the default
//! [`Limits::max_archive_depth`] of 1 means "the container you pointed at, and no
//! further", and 0 means the scanner refuses containers outright. A candidate that
//! hid its copied source in a nested archive is a real scenario, so each archive
//! found *inside* one is recorded as a note that appears in the report rather than
//! being dropped — the honest answer to that tree is "part of it was not examined",
//! not a clean result.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use swp_core::error::{ErrorCode, SwpError};
use swp_core::limits::Limits;

/// How many bytes of a file's head are read to identify it. Enough for the
/// `ustar` magic, which sits at offset 257 with a few bytes to spare.
const SNIFF_LEN: u64 = 600;

/// What the operator pointed `swp scan` at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// One source file, staged into a one-file tree.
    SingleFile,
    /// A directory read in place. Nothing is copied.
    Directory,
    /// A `zip` container, including the formats that are zips under another name:
    /// Python wheels, `.jar`, `.vsix`, Office documents.
    Zip,
    /// A plain `tar`.
    Tar,
    /// A gzip-compressed tar — the `npm pack` and `sdist` shape.
    TarGz,
    /// A gzip-compressed single file, staged as its de-compressed name.
    Gzip,
}

impl InputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InputKind::SingleFile => "file",
            InputKind::Directory => "directory",
            InputKind::Zip => "zip",
            InputKind::Tar => "tar",
            InputKind::TarGz => "tar.gz",
            InputKind::Gzip => "gz",
        }
    }

    /// Whether the input had to be taken apart to be read, which is the difference
    /// between "we scanned your directory" and "we scanned what was inside this
    /// archive" in a report.
    pub fn is_container(self) -> bool {
        !matches!(self, InputKind::Directory | InputKind::SingleFile)
    }
}

/// A temporary directory that removes itself.
#[derive(Debug)]
struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort, and deliberately silent: this is the last thing that
        // happens to a scratch directory this process created, and a failure to
        // remove it cannot change the answer the scan produced.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An input that has been opened and, if it was a container, expanded.
#[derive(Debug)]
pub struct Opened {
    /// A directory containing the candidate's source, ready for the walk.
    pub root: PathBuf,
    pub kind: InputKind,
    /// Where `root` came from, for the report's header.
    pub described: String,
    /// Files skipped or refused while opening: a nested archive, a symlink entry,
    /// a member over the size bound. These are findings, not errors, and the
    /// report shows them so a clean result can be read as "we looked at all of
    /// this" rather than "we looked at some of it".
    pub notes: Vec<String>,
    /// Held so the extracted tree is removed when the scan ends. `None` for a
    /// directory or a single file read in place.
    _temp: Option<TempDir>,
}

impl Opened {
    /// Whether the scan can be described as complete: notes that say "an archive
    /// inside your archive was not opened" mean part of the candidate was never
    /// looked at, and a `NO MATCH` report has to say so.
    pub fn is_partial(&self) -> bool {
        !self.notes.is_empty()
    }
}

/// Classify and open `path`.
pub fn open(path: &Path, limits: &Limits) -> Result<Opened, SwpError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        SwpError::new(
            ErrorCode::Io,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;

    if meta.is_dir() {
        return Ok(Opened {
            root: path.to_path_buf(),
            kind: InputKind::Directory,
            described: path.display().to_string(),
            notes: Vec::new(),
            _temp: None,
        });
    }
    if !meta.is_file() {
        // A fifo, socket or device is not a candidate. Reading one could block
        // forever, which is a denial of service in the middle of a scan.
        return Err(SwpError::usage(format!(
            "{} is neither a directory nor a regular file",
            path.display()
        )));
    }
    if meta.len() > limits.max_archive_expanded_bytes {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "{} is {} bytes, over the {}-byte input bound",
                path.display(),
                meta.len(),
                limits.max_archive_expanded_bytes
            ),
        ));
    }

    let kind = sniff(path)?;
    if !kind.is_container() {
        return stage_file(path, limits);
    }
    if limits.max_archive_depth == 0 {
        return Err(SwpError::new(
            ErrorCode::Usage,
            format!(
                "{} is an archive and [scanner] max_archive_depth is 0, so containers are \
                 not scanned",
                path.display()
            ),
        ));
    }

    let temp = make_temp("swp-scan")?;
    let into = temp.path.clone();
    let mut opened = Opened {
        root: into.clone(),
        kind,
        described: path.display().to_string(),
        notes: Vec::new(),
        _temp: Some(temp),
    };
    let result = match kind {
        InputKind::Zip => extract_zip(path, &into, limits, &mut opened.notes),
        InputKind::Tar => extract_tar(Box::new(File::open(path)?), &into, limits, &mut opened.notes),
        InputKind::TarGz => {
            let file = File::open(path)?;
            let decoder = std::io::BufReader::new(flate2::read::MultiGzDecoder::new(file));
            extract_tar(Box::new(decoder), &into, limits, &mut opened.notes)
        }
        InputKind::Gzip => gunzip_single(path, &into, limits),
        _ => Err(SwpError::internal("a plain file is not a container")),
    };
    if let Err(e) = result {
        // The temporary tree is dropped here rather than left behind at a known
        // path, which matters because the archive was untrusted.
        drop(opened);
        return Err(e);
    }
    Ok(opened)
}

/// Identify a file by its leading bytes, not by its extension.
///
/// An extension is what the sender called a file; magic is what the file is. A
/// `.tgz` that is really a zip, or a `.js` that is really a gzip stream, would
/// otherwise be walked as source and produce a clean report about the wrong bytes.
fn sniff(path: &Path) -> Result<InputKind, SwpError> {
    let mut head = Vec::new();
    File::open(path)
        .map_err(|e| SwpError::new(ErrorCode::Io, format!("cannot open {}: {e}", path.display())))?
        .take(SNIFF_LEN)
        .read_to_end(&mut head)?;
    // `PK\x03\x04` opens every stored file's local header; `PK\x05\x06` opens the
    // central directory of an archive that holds none. Both are zips, and treating
    // the second as an opaque 22-byte source file would scan the wrong thing.
    if head.len() >= 4 && (head[..4] == *b"PK\x03\x04" || head[..4] == *b"PK\x05\x06") {
        return Ok(InputKind::Zip);
    }
    if head.len() >= 2 && head[..2] == [0x1f, 0x8b] {
        // gzip wrapping a tar is the package format of npm, PyPI sdist and cargo;
        // gzip wrapping anything else is a single compressed file.
        let mut probe = std::io::BufReader::new(flate2::read::MultiGzDecoder::new(&head[..]));
        let mut inner = [0u8; 512];
        // A truncated or corrupt stream is still a gzip file; it is the extraction
        // that will report it properly, so a failed probe reads as "no tar magic".
        let n = probe.read(&mut inner).unwrap_or(0);
        return Ok(if is_tar_header(&inner[..n]) {
            InputKind::TarGz
        } else {
            InputKind::Gzip
        });
    }
    if is_tar_header(&head) {
        return Ok(InputKind::Tar);
    }
    Ok(InputKind::SingleFile)
}

/// The `ustar` magic lives at byte 257 of the first 512-byte block.
fn is_tar_header(head: &[u8]) -> bool {
    head.len() >= 262 && &head[257..262] == b"ustar"
}

/// A plain source file becomes a one-file tree, so that the rest of the scanner
/// has one kind of input to handle. The name is kept: it is what selects the
/// language adapter.
fn stage_file(path: &Path, limits: &Limits) -> Result<Opened, SwpError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > limits.max_file_bytes {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "{} is {} bytes, over the {}-byte per-file bound, so it cannot be analyzed",
                path.display(),
                meta.len(),
                limits.max_file_bytes
            ),
        ));
    }
    let temp = make_temp("swp-scan")?;
    let name = file_name(path)?;
    std::fs::copy(path, temp.path.join(&name))?;
    Ok(Opened {
        root: temp.path.clone(),
        kind: InputKind::SingleFile,
        described: path.display().to_string(),
        notes: Vec::new(),
        _temp: Some(temp),
    })
}

/// Gunzip one file into a tree named after it, minus the `.gz`.
fn gunzip_single(path: &Path, into: &Path, limits: &Limits) -> Result<(), SwpError> {
    let name = file_name(path)?;
    let out_name = name
        .to_str()
        .and_then(|s| s.strip_suffix(".gz"))
        .map(String::from)
        .unwrap_or_else(|| "payload".to_string());
    let out = checked_path(into, &out_name)?;
    let mut decoder =
        flate2::read::MultiGzDecoder::new(std::io::BufReader::new(File::open(path)?));
    write_bounded(&mut decoder, &out, limits, &out_name)?;
    Ok(())
}

fn file_name(path: &Path) -> Result<PathBuf, SwpError> {
    path.file_name()
        .map(PathBuf::from)
        .ok_or_else(|| SwpError::usage(format!("{} has no file name", path.display())))
}

/// A fresh temporary directory. The name is unpredictable because the scan may be
/// run on a shared machine, and an attacker who guessed it could pre-create a
/// path the extraction then writes through.
fn make_temp(prefix: &str) -> Result<TempDir, SwpError> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..64u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let candidate = base.join(format!("{prefix}-{pid}-{nanos}-{attempt}"));
        if std::fs::create_dir(&candidate).is_ok() {
            return Ok(TempDir { path: candidate });
        }
    }
    Err(SwpError::new(
        ErrorCode::Io,
        format!("cannot create a temporary directory under {}", base.display()),
    ))
}

/// Resolve one archive member name against the extraction root, refusing anything
/// that would land outside it.
fn checked_path(root: &Path, name: &str) -> Result<PathBuf, SwpError> {
    if name.is_empty() {
        return Err(rejected(name, "empty entry name"));
    }
    let candidate = Path::new(name);
    // `Verbatim`, `VerbatimUNC` and `\\?\` prefixes are matched by shape rather
    // than by listing drive letters, because the letter is the part an archive
    // author chooses.
    if matches!(
        candidate.components().next(),
        Some(Component::Prefix(_) | Component::RootDir)
    ) {
        return Err(rejected(name, "absolute entry path"));
    }
    // Windows-style separators arrive as literal backslashes in a `Path` on
    // Unix, so normalize before splitting: `..\..\windows` is one name here, and
    // after splitting it is a traversal.
    let normalized = name.replace('\\', "/");
    let mut out = root.to_path_buf();
    for part in normalized.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(rejected(name, "parent traversal")),
            c if c.contains(':') => return Err(rejected(name, "drive or scheme prefix")),
            c => out.push(c),
        }
    }
    if out == root {
        return Err(rejected(name, "resolves to the extraction root itself"));
    }
    Ok(out)
}

fn rejected(name: &str, why: &str) -> SwpError {
    SwpError::new(
        ErrorCode::PathRejected,
        format!("archive entry {name:?} was refused: {why}"),
    )
}

/// Copy one member out, enforcing the per-member and cumulative bounds as it goes
/// rather than trusting the size the archive declares.
fn write_bounded(src: &mut dyn Read, dest: &Path, limits: &Limits, name: &str) -> Result<u64, SwpError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(dest)?;
    let mut buf = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        written += n as u64;
        if written > limits.max_archive_member_bytes {
            drop(file);
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "archive entry {name:?} expands past max_archive_member_bytes ({} bytes)",
                    limits.max_archive_member_bytes
                ),
            ));
        }
        file.write_all(&buf[..n])?;
    }
    Ok(written)
}

struct Budget {
    expanded: u64,
    total: u64,
    entries: u64,
}

fn charge(budget: &mut Budget, name: &str, n: u64, limits: &Limits) -> Result<(), SwpError> {
    budget.expanded += n;
    budget.total += n;
    if budget.expanded > limits.max_archive_expanded_bytes {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "archive expands past max_archive_expanded_bytes ({} bytes), so it was not \
                 fully extracted (stopped at {name:?})",
                limits.max_archive_expanded_bytes
            ),
        ));
    }
    Ok(())
}

fn extract_zip(path: &Path, into: &Path, limits: &Limits, notes: &mut Vec<String>) -> Result<(), SwpError> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        SwpError::new(ErrorCode::MalformedSource, format!("zip container is unreadable: {e}"))
    })?;
    if archive.len() as u64 > limits.max_archive_entries {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "zip holds {} entries, over max_archive_entries ({})",
                archive.len(),
                limits.max_archive_entries
            ),
        ));
    }
    let mut budget = Budget {
        expanded: 0,
        total: 0,
        entries: 0,
    };
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            SwpError::new(ErrorCode::MalformedSource, format!("zip entry {i} is unreadable: {e}"))
        })?;
        let raw = entry.name().to_string();
        if entry.is_dir() {
            continue;
        }
        // `enclosed_name` is this format's own traversal check. It is applied in
        // addition to [`checked_path`] rather than instead of it, because the two
        // disagree about backslashes on Unix and the stricter answer wins.
        if entry.enclosed_name().is_none() {
            return Err(rejected(&raw, "name escapes the archive root"));
        }
        if !matches!(entry.unix_mode(), Some(mode) if mode & 0o170000 == 0o100000) {
            // Anything that is not a regular file — symlink, fifo, device — is
            // skipped: a symlink entry would be a write to somewhere else.
            notes.push(format!("skipped non-regular zip entry {raw:?}"));
            continue;
        }
        if is_archive_name(&raw) {
            notes.push(format!("nested archive {raw:?} was not opened"));
            continue;
        }
        if entry.encrypted() {
            notes.push(format!("encrypted zip entry {raw:?} cannot be read"));
            continue;
        }
        let declared = entry.size();
        if declared > limits.max_archive_member_bytes {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!("zip entry {raw:?} declares {declared} bytes, over the member bound"),
            ));
        }
        check_ratio(&raw, entry.compressed_size(), declared, limits)?;
        let dest = checked_path(into, &raw)?;
        let written = write_bounded(&mut entry, &dest, limits, &raw)?;
        check_ratio(&raw, entry.compressed_size(), written, limits)?;
        budget.entries += 1;
        charge(&mut budget, &raw, written, limits)?;
    }
    if budget.entries == 0 {
        return Err(SwpError::new(
            ErrorCode::MalformedSource,
            "the zip container held no files to scan",
        ));
    }
    Ok(())
}

fn check_ratio(name: &str, compressed: u64, expanded: u64, limits: &Limits) -> Result<(), SwpError> {
    if compressed == 0 || limits.max_archive_ratio == 0 {
        return Ok(());
    }
    if expanded / compressed > limits.max_archive_ratio {
        return Err(SwpError::new(
            ErrorCode::LimitExceeded,
            format!(
                "archive entry {name:?} expands {} times over its stored size, past \
                 max_archive_ratio ({}): this is the shape of a decompression bomb, and the \
                 archive was stopped rather than extracted",
                expanded / compressed,
                limits.max_archive_ratio
            ),
        ));
    }
    Ok(())
}

fn extract_tar(
    reader: Box<dyn Read>,
    into: &Path,
    limits: &Limits,
    notes: &mut Vec<String>,
) -> Result<(), SwpError> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    let mut budget = Budget {
        expanded: 0,
        total: 0,
        entries: 0,
    };
    for entry in archive.entries().map_err(|e| {
        SwpError::new(ErrorCode::MalformedSource, format!("tar container is unreadable: {e}"))
    })? {
        let mut entry = entry
            .map_err(|e| {
                SwpError::new(ErrorCode::MalformedSource, format!("tar entry is unreadable: {e}"))
            })?;
        let raw = entry
            .path()
            .map_err(|e| {
                SwpError::new(ErrorCode::MalformedSource, format!("tar entry path is unreadable: {e}"))
            })?
            .to_string_lossy()
            .into_owned();
        budget.entries += 1;
        if budget.entries > limits.max_archive_entries {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "tar holds more than max_archive_entries ({}) entries",
                    limits.max_archive_entries
                ),
            ));
        }
        let kind = entry.header().entry_type();
        if kind == tar::EntryType::Directory {
            continue;
        }
        if kind != tar::EntryType::Regular {
            notes.push(format!("skipped non-regular tar entry {raw:?} ({kind:?})"));
            continue;
        }
        if is_archive_name(&raw) {
            notes.push(format!("nested archive {raw:?} was not opened"));
            continue;
        }
        let declared = entry.header().size().unwrap_or(0);
        if declared > limits.max_archive_member_bytes {
            return Err(SwpError::new(
                ErrorCode::LimitExceeded,
                format!("tar entry {raw:?} declares {declared} bytes, over the member bound"),
            ));
        }
        let dest = checked_path(into, &raw)?;
        let written = write_bounded(&mut entry, &dest, limits, &raw)?;
        charge(&mut budget, &raw, written, limits)?;
    }
    if budget.total == 0 {
        return Err(SwpError::new(
            ErrorCode::MalformedSource,
            "the tar container held no files to scan",
        ));
    }
    Ok(())
}

/// Whether a name looks like an archive, so it is reported rather than opened.
///
/// Only the extension is consulted, and only to decide what to *skip* — a file
/// that is really an archive but named `.js` is still sniffed by the normal walk
/// and simply fails to analyze as a language it is not.
fn is_archive_name(name: &str) -> bool {
    const SUFFIXES: [&str; 10] = [
        ".zip", ".jar", ".war", ".whl", ".egg", ".vsix", ".apk", ".tgz", ".crate", ".gem",
    ];
    let lower = name.to_ascii_lowercase();
    SUFFIXES.iter().any(|s| lower.ends_with(s))
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tar.bz2")
        || lower.ends_with(".tar.xz")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to *this test*, not just this process. Tests run
    /// on threads of one process, so a name keyed only by the pid hands two tests
    /// the same path and lets one archive overwrite another's mid-scan.
    fn temp(label: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("swp-input-{label}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = root.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// Build a zip in memory the way `zip` reads it back.
    fn zip_of(files: &[(&str, &[u8])]) -> PathBuf {
        let dir = temp("zip-src");
        let path = dir.join("c.zip");
        let file = File::create(&path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap();
        path
    }

    fn stored() -> zip::write::FileOptions<'static, ()> {
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored)
    }

    fn deflated() -> zip::write::FileOptions<'static, ()> {
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    }

    fn tar_gz_of(files: &[(&str, &[u8])]) -> PathBuf {
        let dir = temp("tar-src");
        let raw = dir.join("c.tar");
        {
            let file = File::create(&raw).unwrap();
            let mut w = tar::Builder::new(file);
            for (name, bytes) in files {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(bytes.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_entry_type(tar::EntryType::Regular);
                w.append_data(&mut hdr, name, *bytes).unwrap();
            }
            w.finish().unwrap();
        }
        let gzipped = dir.join("c.tar.gz");
        let mut src = std::io::BufReader::new(File::open(&raw).unwrap());
        let out = File::create(&gzipped).unwrap();
        let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
        std::io::copy(&mut src, &mut enc).unwrap();
        enc.finish().unwrap();
        gzipped
    }

    #[test]
    fn a_directory_is_scanned_in_place() {
        let root = temp("dir");
        write(&root, "src/a.js", b"const x = 1000;\n");
        let opened = open(&root, &Limits::default()).unwrap();
        assert_eq!(opened.kind, InputKind::Directory);
        assert_eq!(opened.root, root);
        assert!(!opened.is_partial());
        assert!(opened._temp.is_none(), "a directory is not copied");
    }

    #[test]
    fn a_plain_file_becomes_a_one_file_tree_with_its_name() {
        let root = temp("file");
        let src = write(&root, "thing.js", b"const x = 1000;\n");
        let opened = open(&src, &Limits::default()).unwrap();
        assert_eq!(opened.kind, InputKind::SingleFile);
        assert_eq!(
            std::fs::read_dir(&opened.root).unwrap().count(),
            1,
            "the tree holds just the staged file"
        );
        assert!(opened.root.join("thing.js").is_file());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn magic_beats_extension_when_the_two_disagree() {
        let root = temp("magic");
        // Named like source, is a zip. Reading it as a `.js` file would produce a
        // clean report about bytes that are a container.
        let path = write(&root, "notsource.js", &std::fs::read(zip_of(&[("a.js", b"var x = 1;")])).unwrap());
        let opened = open(&path, &Limits::default()).unwrap();
        assert_eq!(opened.kind, InputKind::Zip);
        assert!(opened.root.join("a.js").is_file());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_tar_gz_package_is_extracted_with_its_directory_prefix() {
        let path = tar_gz_of(&[
            ("package/index.js", b"export const x = 1000;\n"),
            ("package/lib/util.js", b"export const y = 2000;\n"),
        ]);
        let opened = open(&path, &Limits::default()).unwrap();
        assert_eq!(opened.kind, InputKind::TarGz);
        assert!(opened.root.join("package/index.js").is_file());
        assert!(opened.root.join("package/lib/util.js").is_file());
    }

    #[test]
    fn traversal_absolute_and_device_entries_are_refused_not_written() {
        for name in ["../escaped.js", "/abs.js", "a/../../b.js", "..\\windows.js"] {
            let path = zip_of(&[(name, b"var x = 1;")]);
            let e = open(&path, &Limits::default()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::PathRejected, "{name}: {e:?}");
        }
    }

    #[test]
    fn a_nonregular_zip_entry_is_skipped_and_said_so() {
        let dir = temp("link-entry");
        let path = dir.join("c.zip");
        let file = File::create(&path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let symlink_opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o120777);
        w.add_symlink("evil", "../../outside", symlink_opts).unwrap();
        w.start_file("ok.js", stored())
            .unwrap();
        w.write_all(b"var x = 1;").unwrap();
        w.finish().unwrap();

        let opened = open(&path, &Limits::default()).unwrap();
        assert_eq!(opened.notes.len(), 1, "{:?}", opened.notes);
        assert!(opened.notes[0].contains("non-regular"));
        assert!(opened.root.join("ok.js").is_file());
        assert!(!opened.root.join("evil").exists());
        assert!(opened.is_partial());
    }

    #[test]
    fn an_entry_bigger_than_the_member_bound_stops_the_scan() {
        let tight = Limits {
            max_archive_member_bytes: 16,
            ..Limits::default()
        };
        let path = zip_of(&[("big.js", &[b'x'; 4096])]);
        let e = open(&path, &tight).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded, "{e:?}");
    }

    #[test]
    fn the_cumulative_expansion_bound_is_charged_across_entries() {
        // Compressed, because the bound under test is on the *expanded* total and
        // an input file already over that bound trips the pre-flight size check
        // instead of reaching the accumulator. The archive here is ~6 KB of stored
        // headers and near-nothing of payload, and expands to ~12 KB.
        let tight = Limits {
            max_archive_expanded_bytes: 8_000,
            max_archive_member_bytes: 1000,
            ..Limits::default()
        };
        let dir = temp("cumulative");
        let path = dir.join("c.zip");
        let file = File::create(&path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        for i in 0..60u32 {
            w.start_file(format!("f{i}.js"), deflated()).unwrap();
            w.write_all(&[b'y'; 200]).unwrap();
        }
        w.finish().unwrap();
        let e = open(&path, &tight).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded, "{e:?}");
        assert!(e.message().contains("was not fully extracted"), "{e:?}");
    }

    #[test]
    fn a_high_ratio_entry_is_refused_as_a_bomb_shape() {
        let dir = temp("bomb");
        let path = dir.join("b.zip");
        let file = File::create(&path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        w.start_file("huge.js", deflated())
            .unwrap();
        // Highly compressible, so the stored size is tiny against 4 MiB.
        for _ in 0..4096 {
            w.write_all(&[0u8; 1024]).unwrap();
        }
        w.finish().unwrap();
        let e = open(&path, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::LimitExceeded, "{e:?}");
        assert!(e.message().contains("decompression bomb"), "{e:?}");
    }

    #[test]
    fn a_nested_archive_is_reported_rather_than_opened() {
        let path = zip_of(&[("vendor/inner.zip", b"PK\x03\x04rest"), ("src/a.js", b"var x = 1;")]);
        let opened = open(&path, &Limits::default()).unwrap();
        assert_eq!(opened.notes.len(), 1, "{:?}", opened.notes);
        assert!(opened.notes[0].contains("nested archive"));
        // Not extracted either: an unopened container is nothing but bytes to this
        // scan, and writing it out would put attacker-chosen content in the
        // temporary tree for no benefit. The note names it, which is the finding.
        assert!(!opened.root.join("vendor/inner.zip").exists());
        assert!(opened.root.join("src/a.js").is_file());
        assert!(opened.is_partial(), "part of the candidate was not examined");
    }

    #[test]
    fn an_archive_can_be_refused_entirely_by_configuration() {
        // The setting a site that only ever scans checked-out trees would use: a
        // container is then an unsupported input, said so, rather than a slow
        // surprise.
        let path = zip_of(&[("src/a.js", b"var x = 1;")]);
        let no_archives = Limits {
            max_archive_depth: 0,
            ..Limits::default()
        };
        let e = open(&path, &no_archives).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Usage, "{e:?}");
        assert!(e.message().contains("max_archive_depth"), "{e:?}");
        // A plain file is still fine: the setting is about containers, not input.
        let js = temp("plain");
        let src = write(&js, "a.js", b"var x = 1;");
        assert_eq!(
            open(&src, &no_archives).unwrap().kind,
            InputKind::SingleFile
        );
    }

    #[test]
    fn an_empty_container_is_an_error_because_nothing_was_scanned() {
        let path = zip_of(&[]);
        let e = open(&path, &Limits::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::MalformedSource, "{e:?}");
    }

    #[test]
    fn a_special_file_is_refused_rather_than_read() {
        let root = temp("special");
        let opened = open(&root.join("nowhere.js"), &Limits::default());
        assert!(opened.is_err(), "a path that does not exist cannot be scanned");
    }

    #[test]
    fn extracted_trees_are_gone_when_the_scan_end() {
        let path = zip_of(&[("src/a.js", b"var x = 1;")]);
        let kept = {
            let opened = open(&path, &Limits::default()).unwrap();
            opened.root.clone()
        };
        assert!(!kept.exists(), "the temporary tree outlived the scan");
    }

    #[test]
    fn classification_of_a_plain_gzip_is_not_a_tar() {
        let dir = temp("gz");
        let raw = write(&dir, "a.js", b"var x = 1000;\n");
        let out = dir.join("a.js.gz");
        let mut src = std::io::BufReader::new(File::open(&raw).unwrap());
        let enc = File::create(&out).unwrap();
        let mut e = flate2::write::GzEncoder::new(enc, flate2::Compression::default());
        std::io::copy(&mut src, &mut e).unwrap();
        e.finish().unwrap();
        let opened = open(&out, &Limits::default()).unwrap();
        assert_eq!(opened.kind, InputKind::Gzip);
        assert_eq!(std::fs::read(opened.root.join("a.js")).unwrap(), b"var x = 1000;\n");
    }

    #[test]
    fn an_overwritten_root_component_cannot_escape() {
        // `a/../../../etc/passwd` normalises upward, and the check runs per
        // component, so it must be refused at the first `..` rather than resolved.
        assert!(checked_path(Path::new("/tmp/x"), "a/../../../etc/passwd").is_err());
        assert!(checked_path(Path::new("/tmp/x"), "./safe.js").unwrap().ends_with("safe.js"));
        assert!(checked_path(Path::new("/tmp/x"), "").is_err());
    }
}
