use std::fmt;

/// Machine-readable error identifiers. These are part of the protocol: they
/// appear in JSON reports as `error_code` and are stable across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// No adapter can analyze this language.
    UnsupportedLanguage,
    /// A manifest could not be read, parsed, version-checked or validated.
    InvalidManifest,
    /// A watermark artifact was found but is structurally not a valid SWP-1 fragment set.
    InvalidWatermark,
    /// The root secret is missing, unreadable, or sealed for a different user/machine.
    SecretUnavailable,
    /// Source could not be decoded or is not source at all.
    MalformedSource,
    /// The language adapter's parser failed on otherwise valid-looking input.
    ParserFailure,
    /// An embedding was requested at a location whose safety preconditions fail.
    UnsafeEmbedding,
    /// An artifact declares a protocol/schema version this build cannot verify.
    ProtocolVersionUnsupported,
    /// Evidence exists but does not reach the threshold for the requested assertion.
    InsufficientEvidence,
    /// A resource limit was reached; the result is partial, not negative.
    LimitExceeded,
    /// The requested project has not been protected yet.
    NotProtected,
    /// The project is protected but the current tree no longer matches a release.
    ReleaseMismatch,
    /// Protection found no location that passes the safety preconditions.
    NoSafeLocations,
    /// A path in an archive or an input was refused as unsafe to write or read.
    PathRejected,
    /// Usage error from the command line.
    Usage,
    /// Filesystem or process failure.
    Io,
    /// Anything not covered above.
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnsupportedLanguage => "UNSUPPORTED_LANGUAGE",
            ErrorCode::InvalidManifest => "INVALID_MANIFEST",
            ErrorCode::InvalidWatermark => "INVALID_WATERMARK",
            ErrorCode::SecretUnavailable => "SECRET_UNAVAILABLE",
            ErrorCode::MalformedSource => "MALFORMED_SOURCE",
            ErrorCode::ParserFailure => "PARSER_FAILURE",
            ErrorCode::UnsafeEmbedding => "UNSAFE_EMBEDDING",
            ErrorCode::ProtocolVersionUnsupported => "PROTOCOL_VERSION_UNSUPPORTED",
            ErrorCode::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
            ErrorCode::LimitExceeded => "LIMIT_REACHED",
            ErrorCode::NotProtected => "NOT_PROTECTED",
            ErrorCode::ReleaseMismatch => "RELEASE_MISMATCH",
            ErrorCode::NoSafeLocations => "NO_SAFE_LOCATIONS",
            ErrorCode::PathRejected => "PATH_REJECTED",
            ErrorCode::Usage => "USAGE",
            ErrorCode::Io => "IO_ERROR",
            ErrorCode::Internal => "INTERNAL_ERROR",
        }
    }

    /// Every code, so tests can assert exhaustively that none of the three
    /// per-code tables was left missing an entry when a code was added.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::UnsupportedLanguage,
        ErrorCode::InvalidManifest,
        ErrorCode::InvalidWatermark,
        ErrorCode::SecretUnavailable,
        ErrorCode::MalformedSource,
        ErrorCode::ParserFailure,
        ErrorCode::UnsafeEmbedding,
        ErrorCode::ProtocolVersionUnsupported,
        ErrorCode::InsufficientEvidence,
        ErrorCode::LimitExceeded,
        ErrorCode::NotProtected,
        ErrorCode::ReleaseMismatch,
        ErrorCode::NoSafeLocations,
        ErrorCode::PathRejected,
        ErrorCode::Usage,
        ErrorCode::Io,
        ErrorCode::Internal,
    ];

    /// What the user should do next. Every CLI error path surfaces this string;
    /// the brief requires errors to be actionable, not merely descriptive.
    pub fn next_step(self) -> &'static str {
        match self {
            ErrorCode::UnsupportedLanguage => {
                "The grammar this adapter compiles in could not be installed into the parser, so \
                 no file of this language can be read. This is a property of the build rather \
                 than of your project: check `swp --version`, and if it persists report the \
                 language and platform. To protect a language no adapter claims, see \
                 docs/LANGUAGE-ADAPTERS.md."
            }
            ErrorCode::InvalidManifest => {
                "Re-run with --release <id> naming an intact release under .swp/public/releases/. If the file is genuinely corrupt, restore it from your provenance backup; a manifest cannot be regenerated without the root secret."
            }
            ErrorCode::InvalidWatermark => {
                "The candidate contains an SWP-1 shaped artifact that fails validation. Treat it as unverified: report it, and re-check the project's release records with `swp inspect manifest`."
            }
            ErrorCode::SecretUnavailable => {
                "Watermark verification needs the root secret. Check .swp/private/root.key exists and is readable, and that you are running as the same Windows account that created it (the secret is sealed per-user). Recovery from backup is documented in docs/GETTING-STARTED.md."
            }
            ErrorCode::MalformedSource => {
                "The file is not decodable text or is truncated. SWP-1 will not guess at it: it is \
                 listed under the report's omissions, and a scan that could not examine it says \
                 so rather than reporting a clean result."
            }
            ErrorCode::ParserFailure => {
                "The language parser gave up on this file, which is a result about the parser and \
                 the file together, not a statement that the file is innocent. Re-run on the \
                 files around it; if one file always fails, that file is the thing to look at."
            }
            ErrorCode::UnsafeEmbedding => {
                "This location was refused because a rewrite there could change program behavior. \
                 Run `swp inspect plan --release <id>` for the recorded reason, and aim \
                 [protect].targets at more files if the constellation came out too small — a \
                 smaller constellation is the correct outcome, not one to force."
            }
            ErrorCode::ProtocolVersionUnsupported => {
                "Do not read this as a non-match. Install a build of SWP-1 that declares support for the artifact's protocol version, or verify it with the generator version recorded in its release record."
            }
            ErrorCode::InsufficientEvidence => {
                "No assertion is possible from the observed evidence. `swp report` lists which evidence types were present; a wider scan scope or more protected fragments on the next release may suffice."
            }
            ErrorCode::LimitExceeded => {
                "The scan or protection stopped at a configured resource limit and is PARTIAL, not negative. Raise the relevant key in .swp/config.toml under [limits] and re-run, or narrow the input path."
            }
            ErrorCode::NotProtected => {
                "Run `swp init` then `swp protect` in the project first."
            }
            ErrorCode::ReleaseMismatch => {
                "The protected tree has changed since this release. Run `swp protect` to record a new release, or `swp verify --release <id>` to list the fragments that were lost."
            }
            ErrorCode::NoSafeLocations => {
                "Every candidate location failed a safety precondition, so nothing was embedded and \
                 the source is unchanged. Run `swp generate` to see what was offered and what was \
                 refused, widen [protect].targets to more files, or turn [protect] embed_strings \
                 on if it is off. A tree with no safe location is a real answer, not a failure to \
                 work around."
            }
            ErrorCode::PathRejected => {
                "An input path escaped the extraction directory, was absolute, or traversed a symlink. The archive or tree was refused rather than partially extracted; re-run on a source you produced yourself if you believe the check is too strict."
            }
            ErrorCode::Usage => "Re-run with --help to see accepted arguments.",
            ErrorCode::Io => {
                "Check that the path exists, is not locked by another process, and that you have write permission."
            }
            ErrorCode::Internal => {
                "This is a defect in SWP-1: an invariant the code believed held did not. Report \
                 the message and the command that printed it; include no secret file, and no \
                 more of your source than the one file the `at:` line names."
            }
        }
    }

    /// Process exit code. Distinct codes let scripts branch on outcome without
    /// parsing text.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorCode::Usage => 2,
            ErrorCode::SecretUnavailable => 3,
            ErrorCode::NotProtected => 4,
            ErrorCode::InvalidManifest | ErrorCode::ReleaseMismatch => 5,
            ErrorCode::ProtocolVersionUnsupported => 6,
            ErrorCode::LimitExceeded => 7,
            ErrorCode::UnsupportedLanguage => 8,
            ErrorCode::InvalidWatermark => 9,
            ErrorCode::InsufficientEvidence => 10,
            ErrorCode::UnsafeEmbedding => 11,
            ErrorCode::MalformedSource => 12,
            ErrorCode::ParserFailure => 13,
            ErrorCode::Io => 14,
            ErrorCode::NoSafeLocations => 15,
            ErrorCode::PathRejected => 16,
            ErrorCode::Internal => 70,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The single error type used across every SWP-1 crate.
#[derive(Debug, thiserror::Error)]
pub struct SwpFailure {
    pub code: ErrorCode,
    pub message: String,
    /// Path associated with the failure, when one exists. Never contains
    /// secret material.
    pub path: Option<String>,
}

impl fmt::Display for SwpFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) => write!(f, "{}: {} (at {})", self.code, self.message, p),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

/// Error type with an optional cause chain flattened into the message.
#[derive(Debug)]
pub struct SwpError {
    pub failure: SwpFailure,
    pub cause: Option<String>,
    /// Advice that replaces [`ErrorCode::next_step`] for this one failure.
    ///
    /// The table is keyed by code, and a code can have more than one cause worth
    /// acting on: `NO_SAFE_LOCATIONS` means either "every candidate literal failed
    /// a safety precondition" or "nothing here is source at all", and telling
    /// someone to raise `target_sites` when their tree holds no JavaScript,
    /// TypeScript or Python is a dead end printed as a next step.
    pub next: Option<String>,
}

impl SwpError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        SwpError {
            failure: SwpFailure {
                code,
                message: message.into(),
                path: None,
            },
            cause: None,
            next: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.failure.path = Some(path.into());
        self
    }

    pub fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    /// The step to tell this caller to take, which is the code's unless the site
    /// that raised the error knew better.
    pub fn next_step(&self) -> &str {
        self.next
            .as_deref()
            .unwrap_or_else(|| self.failure.code.next_step())
    }

    pub fn caused_by(mut self, cause: impl std::fmt::Display) -> Self {
        self.cause = Some(cause.to_string());
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.failure.code
    }

    pub fn message(&self) -> &str {
        &self.failure.message
    }

    pub fn path(&self) -> Option<&str> {
        self.failure.path.as_deref()
    }

    /// Single-line human rendering: the error, why, and what to do next.
    pub fn render(&self) -> String {
        let mut s = format!("{} — {}", self.failure.code, self.failure.message);
        if let Some(c) = &self.cause {
            s.push_str(&format!("\n  caused by: {c}"));
        }
        s.push_str(&format!("\n  next step: {}", self.next_step()));
        s
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Usage, msg)
    }
    pub fn io(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Io, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
    pub fn invalid_manifest(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidManifest, msg)
    }
    pub fn unsupported_version(found: u16, supported: u16) -> Self {
        Self::new(
            ErrorCode::ProtocolVersionUnsupported,
            format!("artifact declares protocol/schema version {found}; this build supports {supported}"),
        )
    }
}

impl fmt::Display for SwpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.failure)
    }
}

impl std::error::Error for SwpError {}

impl From<std::io::Error> for SwpError {
    fn from(e: std::io::Error) -> Self {
        Self::io(e.to_string()).caused_by(e)
    }
}

impl From<serde_json::Error> for SwpError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(ErrorCode::InvalidManifest, e.to_string()).caused_by(e)
    }
}

pub type SwpResult<T> = Result<T, SwpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_hint_and_unique_exit_code_except_shared() {
        // Iterated over ErrorCode::ALL, so adding a code without guidance or a
        // distinct exit status fails here rather than in a user's shell.
        assert!(
            ErrorCode::ALL.len() >= 17,
            "the code table and ALL must agree"
        );
        let mut by_code: std::collections::BTreeMap<i32, Vec<&'static str>> =
            std::collections::BTreeMap::new();
        for c in ErrorCode::ALL {
            assert!(!c.next_step().is_empty(), "{c:?} has no guidance");
            assert_ne!(c.exit_code(), 0, "{c:?} must not exit 0");
            assert!(!c.as_str().is_empty());
            assert!(
                c.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{c:?} wire name must be SCREAMING_SNAKE"
            );
            by_code.entry(c.exit_code()).or_default().push(c.as_str());
        }
        for (code, names) in &by_code {
            match names.len() {
                1 => {}
                // The one intentional sharing: an unreadable manifest and a
                // manifest that does not match the tree are the same operator
                // problem, and scripts should not have to handle them apart.
                2 if *names == vec!["INVALID_MANIFEST", "RELEASE_MISMATCH"] => {}
                other => panic!("exit code {code} claimed by {other:?}"),
            }
        }
        // Distinct codes must have distinct wire names.
        let names: std::collections::BTreeSet<_> =
            ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ErrorCode::ALL.len());
    }

    #[test]
    fn rendering_keeps_the_actionable_hint() {
        let e = SwpError::new(ErrorCode::SecretUnavailable, "root.key missing");
        let r = e.render();
        assert!(r.contains("SECRET_UNAVAILABLE"));
        assert!(r.contains("next step:"));
        assert!(r.contains("root secret"));
    }
}
