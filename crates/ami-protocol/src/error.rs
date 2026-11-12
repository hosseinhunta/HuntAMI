//! Structured, credential-safe error types.
//!
//! Every variant carries machine-readable context (byte counts, indices,
//! offending *names*) but never raw secret values. `Display`/`Debug` output is
//! deliberately built from escaped previews so a malformed `Password:` line or
//! an oversized binary frame cannot dump credentials or unbounded junk into
//! logs.

use std::fmt;

/// Result alias used throughout the protocol crate.
pub type Result<T, E = AmiError> = std::result::Result<T, E>;

/// The unified error type for codec, validation, and encoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmiError {
    /// The initial `Asterisk Call Manager/<version>` greeting line is
    /// structurally invalid (missing prefix, wrong shape, bad terminator).
    InvalidGreeting {
        /// Escaped, length-limited preview of the rejected line.
        preview: String,
    },
    /// A header line inside a message could not be parsed (e.g. no colon).
    MalformedHeader {
        /// Zero-based index of the offending field within the message.
        index: usize,
        /// Escaped, length-limited preview of the offending line.
        preview: String,
    },
    /// A configured resource limit was exceeded while accumulating data.
    SizeLimitExceeded {
        /// Which limit fired.
        limit: LimitKind,
        /// Observed byte (or count) value at the moment of failure.
        observed: u64,
        /// Configured maximum.
        max: u64,
    },
    /// The stream framing requires behavior this client intentionally does
    /// not implement (for example an unknown `Follows` variant that would
    /// need out-of-band knowledge to terminate safely). Fail-closed.
    UnsupportedFraming {
        /// Stable identifier of the unsupported construct.
        kind: &'static str,
        /// Escaped preview of the triggering header, when available.
        preview: String,
    },
    /// A field name or value contained bytes forbidden on the wire
    /// (CR/LF injection, NUL, non-UTF-8 where required) or an invalid name.
    InvalidFieldEncoding {
        /// What specifically was wrong.
        reason: FieldEncodingReason,
        /// Escaped preview of the offending bytes.
        preview: String,
    },
    /// EOF arrived in the middle of a greeting, header line, message, or
    /// command-output block. Carries enough context to diagnose truncation.
    Truncated {
        /// What was being read when EOF hit.
        stage: TruncationStage,
        /// Bytes accumulated so far in the incomplete structure.
        partial_bytes: u64,
    },
    /// An outgoing message failed semantic validation before encoding.
    Validation {
        /// Machine-readable rule identifier (stable across releases).
        rule: &'static str,
        /// Human-readable detail. Never contains secret values.
        detail: String,
    },
}

/// Which configured limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Greeting line length.
    Greeting,
    /// Single header line length.
    Line,
    /// Header count per message.
    HeaderCount,
    /// Total bytes of one message's header block.
    Message,
    /// Bytes in one command-output (`Output:`/frame) block.
    CommandOutput,
    /// Bytes currently buffered by the decoder overall.
    BufferedTotal,
}

impl LimitKind {
    /// Stable short name, useful in metrics/log keys.
    pub fn as_str(self) -> &'static str {
        match self {
            LimitKind::Greeting => "greeting_bytes",
            LimitKind::Line => "line_bytes",
            LimitKind::HeaderCount => "header_count",
            LimitKind::Message => "message_bytes",
            LimitKind::CommandOutput => "command_output_bytes",
            LimitKind::BufferedTotal => "buffered_total_bytes",
        }
    }
}

/// Reasons a field failed encoding validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldEncodingReason {
    /// Name or value contained CR or LF (header-injection attempt).
    CrLfInjection,
    /// Name or value contained NUL.
    NullByte,
    /// Name is empty.
    EmptyName,
    /// Name contained a colon (would corrupt first-colon splitting).
    ColonInName,
    /// Data required UTF-8 but was not valid UTF-8.
    InvalidUtf8,
}

/// Where an unexpected EOF occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationStage {
    /// Partway through the greeting line.
    Greeting,
    /// Partway through a header line.
    HeaderLine,
    /// Headers were seen but the blank terminator line never arrived.
    MessageTerminator,
    /// Inside a command-output block whose terminating blank line is missing.
    CommandOutput,
}

impl fmt::Display for AmiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmiError::InvalidGreeting { preview } => {
                write!(f, "invalid AMI greeting line: {preview}")
            }
            AmiError::MalformedHeader { index, preview } => {
                write!(f, "malformed header at field {index}: {preview}")
            }
            AmiError::SizeLimitExceeded { limit, observed, max } => write!(
                f,
                "{} limit exceeded: {observed} > {max}",
                limit.as_str()
            ),
            AmiError::UnsupportedFraming { kind, preview } => {
                write!(f, "unsupported framing ({kind}): {preview}")
            }
            AmiError::InvalidFieldEncoding { reason, preview } => {
                write!(f, "invalid field encoding ({reason:?}): {preview}")
            }
            AmiError::Truncated { stage, partial_bytes } => {
                write!(f, "unexpected EOF during {stage:?} after {partial_bytes} bytes")
            }
            AmiError::Validation { rule, detail } => {
                write!(f, "validation failed [{rule}]: {detail}")
            }
        }
    }
}

impl std::error::Error for AmiError {}

impl AmiError {
    /// True when the error means "more input may fix this" — i.e. it is a
    /// *retryable* condition for an incremental decoder rather than a fatal
    /// protocol violation. Only [`AmiError::Truncated`] at EOF qualifies and
    /// only the caller observing real EOF can act on it; internally the
    /// decoder uses [`NeedMore`](crate::decoder::DecodeStep) instead.
    pub fn is_eof_truncation(&self) -> bool {
        matches!(self, AmiError::Truncated { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_never_includes_raw_secret_values() {
        // Previews are produced via fields::write_escaped which strips control
        // chars; ensure an error built with an escaped preview renders safely.
        let e = AmiError::InvalidGreeting { preview: "\"Asterisk\\x00garbage\"".into() };
        let s = e.to_string();
        assert!(!s.contains('\0'));
        assert!(s.contains("\\x00"));
    }

    #[test]
    fn size_limit_display_names_the_limit() {
        let e = AmiError::SizeLimitExceeded {
            limit: LimitKind::CommandOutput,
            observed: 10,
            max: 5,
        };
        assert_eq!(e.to_string(), "command_output_bytes limit exceeded: 10 > 5");
    }

    #[test]
    fn truncation_predicate() {
        let e = AmiError::Truncated { stage: TruncationStage::Greeting, partial_bytes: 3 };
        assert!(e.is_eof_truncation());
        let other = AmiError::MalformedHeader { index: 0, preview: "x".into() };
        assert!(!other.is_eof_truncation());
    }
}
