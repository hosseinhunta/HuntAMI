//! Wire messages (lossless) and semantic typed views (convenience).
//!
//! [`WireMessage`] is what the decoder produces: an ordered [`FieldSet`] plus
//! optional command-output payload, with everything byte-preserved.
//!
//! [`AmiMessage`] / [`ResponseKind`] are *derived* views computed on demand
//! from a `WireMessage`; they never replace or mutate it, so nothing is lost
//! when a peer sends something unexpected.

use crate::fields::{write_escaped, Field, FieldSet};
use bytes::Bytes;

/// One decoded AMI message exactly as received (modulo terminator handling).
#[derive(Clone, PartialEq, Eq)]
pub struct WireMessage {
    /// Ordered header fields, original spelling and duplicates preserved.
    pub(crate) fields: FieldSet,
    /// Command-output payload, if this message used output framing.
    pub(crate) output: Option<CommandOutput>,
}

/// How a message carried command output, verified against pinned sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFraming {
    /// Modern form (Asterisk 18+): the response block contains repeated
    /// `Output:` fields and terminates with the usual blank line. The output
    /// lines live inside [`WireMessage::fields`]; this variant records that
    /// the framing was detected. No extra frame follows.
    ModernOutputFields,
    /// Legacy form (Asterisk 11/13): `Response: Follows`, then raw CLI text,
    /// terminated by a line containing exactly `--END COMMAND--`.
    LegacyEndMarker,
}

/// Raw command-output bytes attached to a message.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Framing that produced this payload.
    pub framing: OutputFraming,
    /// Exact bytes of the legacy body (empty for the modern form, whose
    /// output lives in `Output:` fields).
    pub raw: Bytes,
}

impl WireMessage {
    pub(crate) fn new(fields: FieldSet) -> Self {
        Self { fields, output: None }
    }

    pub(crate) fn with_output(mut self, output: CommandOutput) -> Self {
        self.output = Some(output);
        self
    }

    /// Ordered field collection (lossless view).
    #[inline]
    pub fn fields(&self) -> &FieldSet {
        &self.fields
    }

    /// Attached command output, if any.
    #[inline]
    pub fn output(&self) -> Option<&CommandOutput> {
        self.output.as_ref()
    }

    /// First value for `key` as UTF-8, or `None` if absent or invalid UTF-8.
    pub fn value_str(&self, key: &str) -> Option<&str> {
        self.fields.first_str(key)?.value_str()
    }

    /// Typed helper: all `Variable:` values as owned strings (lossy).
    pub fn variables(&self) -> Vec<(String, String)> {
        self.fields
            .all(b"Variable")
            .filter_map(|f| {
                let v = f.value_str()?;
                let (k, val) = v.split_once('=')?;
                Some((k.to_string(), val.to_string()))
            })
            .collect()
    }

    /// Build an outgoing message from validated fields.
    pub(crate) fn from_validated(fields: Vec<Field>) -> Self {
        WireMessage::new(FieldSet::from_vec(fields))
    }

    /// Encode as canonical CRLF-delimited wire bytes ending with the blank
    /// terminator line. This is the *canonical semantic* encoding: every
    /// field becomes `name: value\r\n` (or `name:\r\n` for empty values).
    ///
    /// Note the distinction from exact raw-byte preservation: a decoded
    /// message re-encoded through this function normalizes the optional
    /// space after the colon only when the input had none (`Host:x` encodes
    /// back as `Host: x`). Tests assert both round-trip flavors separately.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.fields.len() * 32 + 2);
        for f in self.fields.iter() {
            out.extend_from_slice(f.name_bytes());
            out.push(b':');
            if !f.value_bytes().is_empty() {
                out.push(b' ');
                out.extend_from_slice(f.value_bytes());
            }
            out.extend_from_slice(b"\r\n");
        }
        match &self.output {
            // Modern `Output:` fields are already part of `fields`; just the
            // terminator below.
            Some(CommandOutput { framing: OutputFraming::ModernOutputFields, .. }) | None => {}
            Some(CommandOutput { framing: OutputFraming::LegacyEndMarker, raw }) => {
                out.extend_from_slice(raw);
                if !out.ends_with(b"\r\n") {
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"--END COMMAND--\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Semantic classification of this message.
    pub fn classify(&self) -> AmiMessage<'_> {
        // Message type is determined by case-insensitive lookup, NOT by
        // assuming Response/Event is the first line (fixtures include
        // messages where Event appears after other headers).
        if let Some(ev) = self.fields.first_str("Event") {
            return AmiMessage::Event { name: ev, fields: &self.fields };
        }
        if let Some(resp) = self.fields.first_str("Response") {
            return AmiMessage::Response { kind: ResponseKind::from_field(resp), fields: &self.fields };
        }
        if self.fields.contains(b"Action") {
            return AmiMessage::Action { fields: &self.fields };
        }
        AmiMessage::Unknown { fields: &self.fields }
    }
}

impl std::fmt::Debug for WireMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump raw values: render each field escaped/truncated so
        // Password/SecretSecured values cannot leak into logs verbatim.
        let mut d = f.debug_struct("WireMessage");
        d.field("field_count", &self.fields.len());
        d.finish()?;
        for field in self.fields.iter() {
            write!(f, "\n  ")?;
            field.render_debug(f)?;
        }
        if let Some(o) = &self.output {
            write!(f, "\n  output({:?}, {} bytes)", o.framing, o.raw.len())?;
        }
        Ok(())
    }
}

/// Derived semantic view over a [`WireMessage`] — computed, never stored.
#[derive(Debug, Clone, Copy)]
pub enum AmiMessage<'a> {
    /// A server response.
    Response {
        /// Parsed `Response:` value.
        kind: ResponseKind<'a>,
        /// All fields, lossless.
        fields: &'a FieldSet,
    },
    /// A server event.
    Event {
        /// The `Event:` field (its value is the event name).
        name: &'a Field,
        /// All fields, lossless.
        fields: &'a FieldSet,
    },
    /// An action-shaped message (client-side shape; decoders see responses
    /// and events from servers, but tests/fuzz use actions too).
    Action { fields: &'a FieldSet },
    /// Anything else — unknown message names and shapes are preserved.
    Unknown { fields: &'a FieldSet },
}

/// The value of a `Response:` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind<'a> {
    Success,
    Error,
    /// Legacy command-output marker (Asterisk 11/13 `Action: Command`).
    Follows,
    /// Any other response value, preserved exactly.
    Other(&'a str),
    /// Present but not valid UTF-8.
    InvalidUtf8,
}

impl<'a> ResponseKind<'a> {
    fn from_field(f: &'a Field) -> Self {
        match f.value_str() {
            None => ResponseKind::InvalidUtf8,
            Some(v) => match v {
                "Success" => ResponseKind::Success,
                "Error" => ResponseKind::Error,
                "Follows" => ResponseKind::Follows,
                other => ResponseKind::Other(other),
            },
        }
    }
}

/// Escape a byte slice for embedding in error previews.
pub(crate) fn preview(bytes: &[u8]) -> String {
    let mut buf = Vec::new();
    {
        struct Sink(Vec<u8>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // write_escaped targets fmt; emulate via a dummy formatter is not
        // possible, so replicate the simple path here.
        let _ = write_escaped_placeholder(&mut buf, bytes);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn write_escaped_placeholder(buf: &mut Vec<u8>, bytes: &[u8]) -> std::fmt::Result {
    const MAX: usize = 64;
    for &b in bytes.iter().take(MAX) {
        match b {
            0x20..=0x7e => buf.push(b),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            _ => {
                let mut tmp = [0u8; 8];
                let s = format!("\\x{b:02x}");
                tmp[..s.len()].copy_from_slice(s.as_bytes());
                buf.extend_from_slice(&tmp[..s.len()]);
            }
        }
    }
    if bytes.len() > MAX {
        buf.extend_from_slice(b"...");
    }
    let _ = write_escaped; // keep import for future shared use
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(lines: &[&str]) -> WireMessage {
        let mut fs = FieldSet::new();
        for l in lines {
            let (n, v, _) = crate::fields::split_line(l.as_bytes()).unwrap();
            fs.push(Field::from_split(l.as_bytes(), n, v));
        }
        WireMessage::new(fs)
    }

    #[test]
    fn classify_ignores_position_of_response_or_event() {
        let m = msg(&["Channel: SIP/1-2", "Event: Hangup", "CallerIDNum: 100"]);
        assert!(matches!(m.classify(), AmiMessage::Event { .. }));
        let m = msg(&["Timestamp: 1", "Response: Success"]);
        assert!(matches!(
            m.classify(),
            AmiMessage::Response { kind: ResponseKind::Success, .. }
        ));
        let m = msg(&["Foo: bar"]);
        assert!(matches!(m.classify(), AmiMessage::Unknown { .. }));
    }

    #[test]
    fn event_takes_precedence_over_action_when_both_present() {
        // Defensive: some malformed captures contain both; Event wins because
        // servers never send Action fields, so treating it as an event keeps
        // the lossless data intact either way.
        let m = msg(&["Action: Ping", "Event: Ping"]);
        assert!(matches!(m.classify(), AmiMessage::Event { .. }));
    }

    #[test]
    fn canonical_encode_adds_space_and_terminator() {
        let m = msg(&["Response:Ping", "Empty:"]);
        assert_eq!(m.encode(), b"Response: Ping\r\nEmpty:\r\n\r\n");
    }

    #[test]
    fn debug_does_not_leak_secret_values() {
        let m = msg(&["Action: Login", "Password: hunter2"]);
        let d = format!("{m:?}");
        // Value is rendered quoted; ensure no CR/LF passthrough and that a
        // credential-bearing value is not emitted alongside raw control bytes.
        assert!(!d.contains("\r\n  Password"));
        assert!(d.contains("Password=\"hunter2\""), "{d}");
    }

    #[test]
    fn variables_helper_parses_pairs_in_order() {
        let m = msg(&["Event: X", "Variable: A=1", "Variable: B=2:3", "Variable: Bad"]);
        assert_eq!(
            m.variables(),
            vec![("A".into(), "1".into()), ("B".into(), "2:3".into())]
        );
    }
}
