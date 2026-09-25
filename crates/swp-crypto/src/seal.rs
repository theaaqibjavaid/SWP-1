//! Secret sealing and file permissions.
//!
//! Two layers, and they protect against different things:
//!
//! * On Windows the secret is sealed with DPAPI (user scope), so the bytes on
//!   disk are unreadable to any other account and to the same account on a
//!   different machine.
//! * Independently, the file's access control list is tightened to the current
//!   user and then **read back and verified**. A permission change that could
//!   not be confirmed is reported as unverified, never silently accepted —
//!   `std::fs` permission calls on Windows are a well-known way to believe you
//!   hardened a file you did not harden.
//!
//! The honest limit, stated in docs/SECURITY.md: anything running as you can
//! read the secret. DPAPI does not change that; it changes what a stolen backup
//! or another account on the machine can do with the file.

use std::path::Path;

use base64::Engine as _;

use swp_core::error::{ErrorCode, SwpError};
use swp_core::text::decode_utf8_strict;

use crate::random;
use crate::secret::{RootSecret, SecretBytes};
use crate::ROOT_SECRET_LEN;

const ENVELOPE_HEADER: &str = "swp1-secret-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Windows Data Protection API, user scope.
    Dpapi,
    /// Stored as the raw key, protected only by file permissions. Used on
    /// non-Windows platforms and when explicitly requested for portability.
    Plain,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Dpapi => "dpapi",
            Scheme::Plain => "plain",
        }
    }
    pub fn parse(s: &str) -> Result<Self, SwpError> {
        match s {
            "dpapi" => Ok(Scheme::Dpapi),
            "plain" => Ok(Scheme::Plain),
            other => Err(SwpError::new(
                ErrorCode::SecretUnavailable,
                format!("unknown secret scheme {other:?}"),
            )),
        }
    }
}

/// A sealed root secret, ready to be written to `.swp/private/root.key`.
///
/// The payload is deliberately a `SecretBytes`: under `Scheme::Plain` these
/// bytes *are* the root secret, so a derived `Debug` or `Clone` would leak it
/// into a panic message, a log line or an unzeroized heap copy. Not `Clone`
/// for that reason.
pub struct SealedSecret {
    pub scheme: Scheme,
    payload: SecretBytes,
}

impl std::fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSecret")
            .field("scheme", &self.scheme)
            .field("payload", &self.payload)
            .finish()
    }
}

impl SealedSecret {
    /// Seal a freshly generated root secret.
    pub fn generate() -> Result<(RootSecret, SealedSecret), SwpError> {
        let bytes = random::random_array::<ROOT_SECRET_LEN>()?;
        let root = RootSecret::from_bytes(&bytes)?;
        let sealed = SealedSecret::seal(&root)?;
        Ok((root, sealed))
    }

    pub fn seal(root: &RootSecret) -> Result<Self, SwpError> {
        #[cfg(windows)]
        {
            if plain_requested() {
                return Ok(SealedSecret {
                    scheme: Scheme::Plain,
                    payload: SecretBytes::from_slice(root.as_slice()),
                });
            }
            let payload = dpapi_protect(root.as_slice())?;
            Ok(SealedSecret {
                scheme: Scheme::Dpapi,
                payload: SecretBytes::from_vec(payload),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(SealedSecret {
                scheme: Scheme::Plain,
                payload: SecretBytes::from_slice(root.as_slice()),
            })
        }
    }

    pub fn unseal(&self) -> Result<RootSecret, SwpError> {
        let bytes = match self.scheme {
            Scheme::Plain => SecretBytes::from_slice(self.payload.as_slice()),
            Scheme::Dpapi => {
                #[cfg(windows)]
                {
                    SecretBytes::from_vec(dpapi_unprotect(self.payload.as_slice())?)
                }
                #[cfg(not(windows))]
                {
                    return Err(SwpError::new(
                        ErrorCode::SecretUnavailable,
                        "this secret was sealed with Windows DPAPI and can only be opened on \
                         Windows, by the same user account, on the same machine",
                    ));
                }
            }
        };
        let root = RootSecret::from_bytes(bytes.as_slice()).map_err(|e| {
            e.caused_by(if self.scheme == Scheme::Plain {
                "the sealed file holds a payload that is not a root secret; it is truncated or corrupt"
            } else {
                "DPAPI returned a payload that is not a root secret; the file is corrupt"
            })
        })?;
        drop(bytes);
        Ok(root)
    }

    /// The exact bytes of `root.key`.
    pub fn to_file_bytes(&self) -> Vec<u8> {
        let body = base64::engine::general_purpose::STANDARD.encode(self.payload.as_slice());
        format!(
            "{ENVELOPE_HEADER}\nscheme: {}\npayload: {body}\n",
            self.scheme.as_str()
        )
        .into_bytes()
    }

    pub fn parse_file_bytes(bytes: &[u8]) -> Result<Self, SwpError> {
        let text = decode_utf8_strict(bytes).ok_or_else(|| {
            SwpError::new(
                ErrorCode::SecretUnavailable,
                "secret file is not valid UTF-8",
            )
        })?;
        let mut scheme: Option<Scheme> = None;
        let mut payload: Option<String> = None;
        for (i, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if i == 0 {
                if line != ENVELOPE_HEADER {
                    return Err(SwpError::new(
                        ErrorCode::SecretUnavailable,
                        format!("unrecognized secret file format (expected {ENVELOPE_HEADER:?})"),
                    ));
                }
                continue;
            }
            let (k, v) = line.split_once(": ").ok_or_else(|| {
                SwpError::new(
                    ErrorCode::SecretUnavailable,
                    format!("malformed line {} in secret file", i + 1),
                )
            })?;
            match k {
                "scheme" => scheme = Some(Scheme::parse(v)?),
                "payload" => payload = Some(v.to_string()),
                other => {
                    return Err(SwpError::new(
                        ErrorCode::SecretUnavailable,
                        format!("unexpected field {other:?} in secret file"),
                    ))
                }
            }
        }
        let scheme = scheme.ok_or_else(|| {
            SwpError::new(ErrorCode::SecretUnavailable, "secret file has no scheme")
        })?;
        let payload = payload.ok_or_else(|| {
            SwpError::new(ErrorCode::SecretUnavailable, "secret file has no payload")
        })?;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload.trim())
            .map_err(|e| {
                SwpError::new(
                    ErrorCode::SecretUnavailable,
                    format!("secret payload is not base64: {e}"),
                )
            })?;
        Ok(SealedSecret {
            scheme,
            payload: SecretBytes::from_vec(payload),
        })
    }
}

/// Set `SWP_SECRET_PLAIN=1` to skip DPAPI (backup tooling, containers, CI).
/// The file then contains the key itself, protected only by its ACL.
pub fn plain_requested() -> bool {
    matches!(
        std::env::var("SWP_SECRET_PLAIN").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Outcome of an attempt to restrict access to a secret file. Reported to the
/// user verbatim; never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionOutcome {
    /// Permissions were set and confirmed by reading them back.
    Verified(String),
    /// Set, but confirmation could not be parsed. Treated as a warning.
    Unverified(String),
    /// Nothing was changed (unsupported platform or the tool is missing).
    Unavailable(String),
}

impl PermissionOutcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, PermissionOutcome::Verified(_))
    }
    pub fn detail(&self) -> &str {
        match self {
            PermissionOutcome::Verified(s) | PermissionOutcome::Unverified(s) => s,
            PermissionOutcome::Unavailable(s) => s,
        }
    }
}

/// Restrict `path` to the current user and verify it.
pub fn harden_permissions(path: &Path) -> PermissionOutcome {
    #[cfg(windows)]
    {
        harden_windows(path)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => match std::fs::metadata(path) {
                Ok(m) if m.permissions().mode() & 0o777 == 0o600 => {
                    PermissionOutcome::Verified("owner read/write only (0600)".into())
                }
                Ok(m) => PermissionOutcome::Unverified(format!(
                    "requested 0600 but the file reports {:o}",
                    m.permissions().mode() & 0o777
                )),
                Err(e) => PermissionOutcome::Unverified(e.to_string()),
            },
            Err(e) => PermissionOutcome::Unavailable(e.to_string()),
        }
    }
}

#[cfg(windows)]
fn harden_windows(path: &Path) -> PermissionOutcome {
    let user = match windows_user_name() {
        Some(u) => u,
        None => {
            return PermissionOutcome::Unavailable("cannot determine the current user name".into())
        }
    };
    let path_s = path.to_string_lossy().to_string();
    let grant = format!("{user}:F");
    let applied = run(
        "icacls",
        &[
            path_s.as_str(),
            "/inheritance:r",
            "/grant:r",
            grant.as_str(),
        ],
    );
    let after = match applied {
        Ok(_) => icacls(path),
        Err(e) => return PermissionOutcome::Unavailable(e.to_string()),
    };
    match after {
        Ok(text) => {
            let has_grant = text.to_lowercase().contains(&user.to_lowercase());
            let still_inherited = text.lines().any(|l| l.contains("(I)"));
            if has_grant && !still_inherited {
                PermissionOutcome::Verified(format!("ACL limited to {user}"))
            } else if has_grant {
                PermissionOutcome::Unverified(
                    "the file still shows inherited access entries; other accounts on this \
                     machine may be able to read it (DPAPI keeps the contents unreadable to \
                     them, but review the ACL with `icacls`)"
                        .into(),
                )
            } else {
                PermissionOutcome::Unverified("could not confirm the new ACL".into())
            }
        }
        Err(e) => PermissionOutcome::Unverified(format!("could not read back the ACL: {e}")),
    }
}

#[cfg(windows)]
fn icacls(path: &Path) -> Result<String, IcaclsError> {
    let p = path.to_string_lossy().to_string();
    run("icacls", &[p.as_str()])
}

/// Why an `icacls` invocation came back with nothing usable.
///
/// A machine that cannot start the process and a process that started and refused
/// the change are different failures, and what the operator does next differs
/// between them. They used to arrive at the call site as one `io::Error`, so the
/// one sentence printed for both was "icacls failed to run" — and when `icacls`
/// exited non-zero without writing anything, both streams `run` captures were
/// empty and the message ended in a colon with nothing after it.
#[cfg(windows)]
enum IcaclsError {
    /// Windows never ran the program. The operating system's own error is kept
    /// verbatim, code included when it has one: `os error 1450` is a loaded
    /// machine, `os error 5` is a policy, and neither is a broken ACL.
    Spawn(std::io::Error),
    /// The program ran and did not succeed. `text` is whatever it wrote to either
    /// stream, which may be nothing. `code` is `None` when the child was
    /// terminated rather than exited, which is a third failure mode again.
    Refused { code: Option<i32>, text: String },
}

#[cfg(windows)]
impl std::fmt::Display for IcaclsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcaclsError::Spawn(e) => write!(f, "could not start icacls: {e}"),
            IcaclsError::Refused { code, text } => {
                let ran = match code {
                    Some(code) => format!("icacls exited with status {code}"),
                    None => "icacls was terminated without an exit status".to_string(),
                };
                let text = text.trim();
                if text.is_empty() {
                    write!(f, "{ran} without reporting a reason")
                } else {
                    write!(f, "{ran}: {text}")
                }
            }
        }
    }
}

#[cfg(windows)]
fn windows_user_name() -> Option<String> {
    let user = std::env::var("USERNAME").ok()?;
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() && !domain.eq_ignore_ascii_case(&user) => {
            Some(format!("{domain}\\{user}"))
        }
        _ => Some(user),
    }
}

#[cfg(windows)]
fn run(program: &str, args: &[&str]) -> Result<String, IcaclsError> {
    use std::process::Command;
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(IcaclsError::Spawn)?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        return Err(IcaclsError::Refused {
            code: out.status.code(),
            text,
        });
    }
    Ok(text)
}

#[cfg(windows)]
mod dpapi {
    use core::ffi::c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            pdata_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            pdata_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            pdata_in: *const DataBlob,
            psz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            pdata_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h: *mut c_void) -> *mut c_void;
    }

    fn blob(bytes: &mut [u8]) -> DataBlob {
        DataBlob {
            cb_data: bytes.len() as u32,
            pb_data: bytes.as_mut_ptr(),
        }
    }

    /// SAFETY: standard DPAPI calls with well-formed blobs. The `0x1` both calls
    /// pass is `CRYPTPROTECT_PROMPT_ON_STRONGPASSWORD`, and the prompt struct is
    /// `NULL` in each, so there is nothing for it to prompt with: no UI is
    /// possible on a headless run. (`CryptProtectData` has no
    /// `CRYPTPROTECT_UI_FORBIDDEN` — that flag belongs to the message-encryption
    /// API — so passing NULL with the prompt flag is the way to say the same
    /// thing.)
    pub fn protect(input: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut src = input.to_vec();
        let mut in_blob = blob(&mut src);
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: core::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &mut in_blob as *mut DataBlob as *const DataBlob,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                0x1,
                &mut out_blob,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let out = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(out)
    }

    pub fn unprotect(input: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut src = input.to_vec();
        let mut in_blob = blob(&mut src);
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: core::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &mut in_blob as *mut DataBlob as *const DataBlob,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                0x1,
                &mut out_blob,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let out = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(out)
    }
}

#[cfg(windows)]
fn dpapi_protect(bytes: &[u8]) -> Result<Vec<u8>, SwpError> {
    dpapi::protect(bytes).map_err(|e| {
        SwpError::new(
            ErrorCode::SecretUnavailable,
            format!("DPAPI refused to protect the root secret: {e}"),
        )
    })
}

#[cfg(windows)]
fn dpapi_unprotect(bytes: &[u8]) -> Result<Vec<u8>, SwpError> {
    dpapi::unprotect(bytes).map_err(|e| {
        SwpError::new(
            ErrorCode::SecretUnavailable,
            format!(
                "DPAPI could not open the root secret ({e}). It was sealed for a different \
                 Windows account or a different machine; recover it from the export you made \
                 when it was created"
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("swp-crypto-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn seal_unseal_round_trips_through_the_file_format() {
        let (root, sealed) = SealedSecret::generate().unwrap();
        let bytes = sealed.to_file_bytes();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("swp1-secret-v1\n"));
        let parsed = SealedSecret::parse_file_bytes(&bytes).unwrap();
        assert_eq!(parsed.scheme, sealed.scheme);
        let reopened = parsed.unseal().unwrap();
        assert_eq!(
            crate::derive::derive_key(&root, crate::derive::Domain::Project, &[b"x"])
                .as_slice()
                .to_vec(),
            crate::derive::derive_key(&reopened, crate::derive::Domain::Project, &[b"x"])
                .as_slice()
                .to_vec(),
            "unsealed secret does not behave like the original"
        );
    }

    #[test]
    fn dpapi_payload_does_not_contain_the_key() {
        let (root, sealed) = SealedSecret::generate().unwrap();
        if sealed.scheme != Scheme::Dpapi {
            return; // plain mode requested; the assertion below would not apply
        }
        let file = sealed.to_file_bytes();
        // The raw key bytes must not appear anywhere in the stored envelope.
        assert!(!file.windows(32).any(|w| w == root.as_slice()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(root.as_slice());
        assert!(!String::from_utf8_lossy(&file).contains(&b64));
    }

    #[test]
    fn debug_printing_a_sealed_secret_cannot_leak_the_key() {
        // Plain mode stores the key itself in `payload`, so a derived `Debug`
        // would put the root secret into any log line, panic message or test
        // snapshot that formats the value. This is the §29 guard for that path.
        let key = [0x42u8; ROOT_SECRET_LEN];
        let root = RootSecret::from_bytes(&key).unwrap();
        let sealed = SealedSecret::seal(&root).unwrap();
        let rendered = format!("{sealed:?}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
        assert!(
            !rendered.contains("4242"),
            "raw key bytes leaked through Debug: {rendered}"
        );
        assert!(!rendered.contains(&swp_core::hex_encode(key.as_slice())));
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        assert!(!rendered.contains(&b64), "base64 key leaked: {rendered}");
        let root_rendered = format!("{root:?}");
        assert!(
            !root_rendered.contains("4242"),
            "RootSecret Debug leaked: {root_rendered}"
        );
    }

    #[test]
    fn envelope_parser_rejects_junk() {
        assert!(SealedSecret::parse_file_bytes(b"not a secret file").is_err());
        assert!(
            SealedSecret::parse_file_bytes(b"swp1-secret-v1\nscheme: magic\npayload: AAA\n")
                .is_err()
        );
        assert!(SealedSecret::parse_file_bytes(b"swp1-secret-v1\nscheme: plain\n").is_err());
        assert!(SealedSecret::parse_file_bytes(&[0xff, 0xfe, 0xfd]).is_err());
        let ok = SealedSecret::parse_file_bytes(
            b"swp1-secret-v1\nscheme: plain\npayload: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
        )
        .unwrap();
        assert_eq!(ok.scheme, Scheme::Plain);
        assert!(ok.unseal().is_ok());
    }

    #[test]
    fn a_truncated_payload_is_reported_as_corrupt_not_short() {
        let bad = SealedSecret {
            scheme: Scheme::Plain,
            payload: SecretBytes::from_vec(vec![1, 2, 3]),
        };
        let e = bad.unseal().unwrap_err();
        assert!(e.render().contains("corrupt"));
    }

    #[test]
    fn permission_hardening_reports_what_it_found() {
        let d = dir("perms");
        let f = d.join("root.key");
        std::fs::write(&f, b"placeholder").unwrap();
        let outcome = harden_permissions(&f);
        // Whatever the platform, the call must classify itself and never panic.
        assert!(!outcome.detail().is_empty(), "empty permission report");
        println!("permission outcome: {outcome:?}");
    }

    // The three modes that used to reach the operator as one sentence, one test
    // each. The last is the reported failure: a child that exits non-zero without
    // writing anything left `run` with no text at all, so the caller printed
    // "icacls failed to run:" with nothing after the colon.
    #[cfg(windows)]
    #[test]
    fn a_program_that_never_started_is_named_as_a_start_failure() {
        let e = run("icacls-that-does-not-exist", &[]).unwrap_err();
        assert!(
            matches!(e, IcaclsError::Spawn(_)),
            "a missing program was classified as {e}"
        );
        let text = e.to_string();
        assert!(text.starts_with("could not start icacls"), "{text}");
        // The operating system's own words are carried through untouched, which
        // is the difference between "check your PATH" and "check the policy".
        assert!(
            text.len() > "could not start icacls: ".len(),
            "the OS error was dropped: {text}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_refusal_keeps_the_status_and_the_reason_icacls_gave() {
        let missing = dir("refused").join("no-such-key.file");
        let e = run("icacls", &[missing.to_string_lossy().as_ref()]).unwrap_err();
        let IcaclsError::Refused { code, text } = &e else {
            panic!("icacls answered this and it was classified as a start failure: {e}");
        };
        assert!(
            matches!(code, Some(c) if c != &0),
            "a refusal with no non-zero status: {e}"
        );
        assert!(!text.trim().is_empty(), "the reason was lost: {e}");
        assert!(e.to_string().contains("exited with status"), "{e}");
        assert!(
            !e.to_string().contains("could not start"),
            "a refusal read as a start failure: {e}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_child_that_says_nothing_says_that_it_said_nothing() {
        // `cmd /c exit 3` is the deterministic form of the reported failure: it
        // runs, it fails, and it writes to neither stream.
        let e = run("cmd.exe", &["/c", "exit", "3"]).unwrap_err();
        let IcaclsError::Refused { code, text } = &e else {
            panic!("a silent exit was classified as a start failure: {e}");
        };
        assert_eq!(*code, Some(3));
        assert!(text.trim().is_empty(), "the child spoke after all: {text}");
        assert!(
            e.to_string().contains("without reporting a reason"),
            "the message was left blank where a diagnosis belongs: {e}"
        );
    }
}
