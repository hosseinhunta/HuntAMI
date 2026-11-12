//! Configurable resource limits enforced **while accumulating**, not after.
//!
//! Defaults are chosen generously relative to what Asterisk itself emits
//! (Asterisk's own receive buffer is 1024 bytes per line and it caps headers
//! at 512 per message — see `main/manager.c` in the pinned sources listed in
//! `fixtures/compatibility.toml`) but stay small enough that a hostile peer
//! cannot make us buffer unbounded data.

/// Immutable set of decoder/encoder resource limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes of the greeting line, including its CRLF terminator.
    pub greeting_bytes: usize,
    /// Maximum bytes of any single header line, excluding the terminator.
    pub line_bytes: usize,
    /// Maximum number of header lines per message.
    pub header_count: usize,
    /// Maximum total bytes of one message's header block (all lines plus
    /// terminators, excluding command-output frames).
    pub message_bytes: usize,
    /// Maximum bytes in one command-output block (the `Output:` frame region
    /// following a `Follows: yes` response), including terminators.
    pub command_output_bytes: usize,
    /// Maximum bytes the decoder may hold in its internal buffer at any time
    /// across all pending structures (partial line + complete-but-unconsumed
    /// messages). This bounds retained backing allocations.
    pub buffered_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Asterisk greeting is ~30 bytes; 512 is ample headroom.
            greeting_bytes: 512,
            // Asterisk reads 1024-byte lines; allow 4 KiB for long
            // CallerIDName / URI values.
            line_bytes: 4096,
            // Asterisk allows 512 headers per message.
            header_count: 512,
            // 512 headers x up to 4 KiB is pathological; cap the block at
            // 256 KiB which comfortably exceeds realistic large events.
            message_bytes: 256 * 1024,
            // Command output can be large (core show settings etc.); 8 MiB
            // is generous yet bounded.
            command_output_bytes: 8 * 1024 * 1024,
            // Hard ceiling on everything buffered at once.
            buffered_total_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Everything at half the default sizes — handy for tests exercising the
    /// limit paths without allocating megabytes.
    pub fn tiny() -> Self {
        Self {
            greeting_bytes: 32,
            line_bytes: 24,
            header_count: 4,
            message_bytes: 96,
            command_output_bytes: 64,
            buffered_total_bytes: 128,
        }
    }

    /// Sanity check: reject nonsensical configurations early. Any zero
    /// `header_count` or a `line_bytes` larger than `message_bytes` would
    /// deadlock the parser, so we refuse them.
    pub fn validate(&self) -> Result<(), crate::AmiError> {
        use crate::error::{AmiError, LimitKind};
        if self.header_count == 0 {
            return Err(AmiError::Validation {
                rule: "limits.header_count_nonzero",
                detail: "header_count must be at least 1".into(),
            });
        }
        if self.line_bytes > self.message_bytes {
            return Err(AmiError::Validation {
                rule: "limits.line_le_message",
                detail: format!(
                    "line_bytes ({}) must be <= message_bytes ({})",
                    self.line_bytes, self.message_bytes
                ),
            });
        }
        if self.message_bytes > self.buffered_total_bytes {
            return Err(AmiError::SizeLimitExceeded {
                limit: LimitKind::BufferedTotal,
                observed: self.message_bytes as u64,
                max: self.buffered_total_bytes as u64,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_self_consistent() {
        assert!(Limits::default().validate().is_ok());
        assert!(Limits::tiny().validate().is_ok());
    }

    #[test]
    fn rejects_line_larger_than_message() {
        let l = Limits { line_bytes: 100, message_bytes: 50, ..Default::default() };
        let e = l.validate().unwrap_err();
        assert!(matches!(e, crate::AmiError::Validation { rule: "limits.line_le_message", .. }));
    }

    #[test]
    fn rejects_zero_header_count() {
        let l = Limits { header_count: 0, ..Default::default() };
        assert!(l.validate().is_err());
    }

    #[test]
    fn rejects_message_larger_than_buffer() {
        let l = Limits { message_bytes: 1 << 20, buffered_total_bytes: 1024, ..Default::default() };
        assert!(l.validate().is_err());
    }
}
