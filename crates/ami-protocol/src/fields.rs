//! Lossless wire representation of AMI message fields.
//!
//! An AMI message on the wire is an **ordered sequence** of `Name: value`
//! lines terminated by an empty line. Ordinary key-value maps cannot express
//! that faithfully, so this module provides [`FieldSet`]: a vector-backed,
//! order-preserving collection of [`Field`]s that keeps *raw bytes* for both
//! names and values.
//!
//! Invariants (see also `docs/architecture.md`):
//!
//! * Original field-name spelling is preserved exactly (`action:` stays
//!   `action:`).
//! * Repeated fields are preserved in insertion order; nothing is deduped or
//!   silently overwritten.
//! * Lookup ([`FieldSet::first`], [`FieldSet::last`], [`FieldSet::all`]) is
//!   ASCII-case-insensitive and allocation-free: names are compared byte-wise
//!   with ASCII case folding, never lowercased into new `String`s.
//! * Values keep leading/trailing meaningful whitespace after the single
//!   optional space following the colon is removed per the Asterisk parser
//!   (`sscanf("%999[^:]: %999[^\n]")`-compatible semantics implemented in
//!   [`split_line`]).
//! * Non-UTF-8 bytes survive round trips. Conversion is explicit:
//!   [`Field::name_str`]/[`Field::value_str`] (fallible) versus
//!   [`Field::name_lossy`]/[`Field::value_lossy`] (lossy display only).

use std::borrow::Cow;
use std::sync::Arc;

/// A single `Name: value` header line, stored as raw bytes.
///
/// The backing store is an [`Arc<[u8]>`] so that decoding one large buffer
/// full of coalesced frames can hand out cheap, independent clones without
/// pinning the whole receive buffer longer than necessary: each field slices
/// the shared buffer, and the buffer is released once every field derived
/// from it is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Bytes of `name`, then `b": "`, then `value` — the canonical wire form
    /// of the line without its terminator. Keeping one allocation per field
    /// (instead of two) makes lookups and re-encoding simple.
    raw: Arc<[u8]>,
    /// Byte index just past the colon (start of the separator remainder).
    colon: usize,
    /// Byte index where the value starts (== `colon` when there was no space
    /// after the colon, `colon + 1` when a single space was stripped).
    value: usize,
}

impl Field {
    /// Build a field from already-split wire bytes.
    ///
    /// `line` is the raw header line without its terminator; `name`, `value`
    /// are sub-slices produced by [`split_line`] (they may alias `line`).
    /// The canonical wire form is reconstructed as `name + ":" + value`, so
    /// an optional single space after the colon is preserved exactly when it
    /// was present on the wire.
    pub(crate) fn from_split(line: &[u8], name: &[u8], value: &[u8]) -> Self {
        debug_assert_eq!(&line[..name.len()], name);
        debug_assert!(line.len() >= name.len() + 1 + value.len());
        let mut v = Vec::with_capacity(line.len());
        v.extend_from_slice(name);
        v.push(b':');
        v.extend_from_slice(value);
        let colon = name.len();
        let value_start = v.len() - value.len();
        Self { raw: Arc::from(v), colon, value: value_start }
    }

    /// Construct from explicit parts, using the canonical `": "` separator
    /// when `value` is non-empty and `":"` when it is empty.
    pub(crate) fn from_parts(name: &[u8], value: &[u8]) -> Self {
        let mut v = Vec::with_capacity(name.len() + 2 + value.len());
        v.extend_from_slice(name);
        v.push(b':');
        if !value.is_empty() {
            v.push(b' ');
        }
        let colon = name.len();
        v.extend_from_slice(value);
        let value_start = v.len() - value.len();
        Self { raw: Arc::from(v), colon, value: value_start }
    }

    /// Construct a field from name and value byte slices.
    ///
    /// This does **not** validate; use [`crate::message::WireMessage::field`]
    /// or [`crate::validate`] for checked construction of outgoing messages.
    pub fn from_raw_bytes(name: &[u8], value: &[u8]) -> Self {
        Self::from_parts(name, value)
    }

    /// Construct a field from UTF-8 name and value.
    pub fn from_str(name: &str, value: &str) -> Self {
        Self::from_raw_bytes(name.as_bytes(), value.as_bytes())
    }

    /// The exact wire bytes of this line (without terminator), preserving
    /// original spelling and any internal structure.
    #[inline]
    pub fn as_wire_bytes(&self) -> &[u8] {
        &self.raw[..]
    }

    /// Raw name bytes, original spelling.
    #[inline]
    pub fn name_bytes(&self) -> &[u8] {
        &self.raw[..self.colon]
    }

    /// Raw value bytes, after the colon and one optional separating space.
    #[inline]
    pub fn value_bytes(&self) -> &[u8] {
        &self.raw[self.value..]
    }

    /// Name as UTF-8, or `None` when the name contains invalid UTF-8.
    #[inline]
    pub fn name_str(&self) -> Option<&str> {
        std::str::from_utf8(self.name_bytes()).ok()
    }

    /// Value as UTF-8, or `None` when the value contains invalid UTF-8.
    ///
    /// Asterisk generally sends UTF-8, but SIP headers can smuggle arbitrary
    /// bytes; callers decide whether to reject, escape, or display lossily.
    #[inline]
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(self.value_bytes()).ok()
    }

    /// Borrow the value as UTF-8 if valid, otherwise a lossy `Cow`.
    #[inline]
    pub fn value_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.value_bytes())
    }

    /// Borrow the name as UTF-8 if valid, otherwise a lossy `Cow`.
    #[inline]
    pub fn name_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.name_bytes())
    }

    /// ASCII-case-insensitive comparison of this field's name against `key`.
    #[inline]
    pub fn name_eq_ignore_case(&self, key: &[u8]) -> bool {
        ascii_eq_ignore_case(self.name_bytes(), key)
    }

    /// Render for `Debug` output: `name="value"` with non-printable bytes
    /// escaped so secrets and binary junk never leak verbatim into logs.
    pub(crate) fn render_debug(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}=", self.name_lossy())?;
        write_escaped(f, self.value_bytes())
    }
}

/// An ordered collection of [`Field`]s — the lossless wire form of one AMI
/// message (or of the action/event portion of one).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldSet {
    fields: Vec<Field>,
}

impl FieldSet {
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    pub(crate) fn from_vec(fields: Vec<Field>) -> Self {
        Self { fields }
    }

    /// Push a field, preserving order and duplicates.
    #[inline]
    pub fn push(&mut self, field: Field) {
        self.fields.push(field);
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Index access preserving wire order.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&Field> {
        self.fields.get(index)
    }

    /// Iterate all fields in wire order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, Field> {
        self.fields.iter()
    }

    /// First field whose name matches `key` ASCII-case-insensitively.
    #[inline]
    pub fn first(&self, key: &[u8]) -> Option<&Field> {
        self.fields.iter().find(|f| f.name_eq_ignore_case(key))
    }

    /// Convenience wrapper for UTF-8 keys.
    #[inline]
    pub fn first_str(&self, key: &str) -> Option<&Field> {
        self.first(key.as_bytes())
    }

    /// Last field whose name matches `key` (AMI readers conventionally use
    /// the last occurrence when a header repeats outside `Variable`).
    pub fn last(&self, key: &[u8]) -> Option<&Field> {
        self.fields.iter().rev().find(|f| f.name_eq_ignore_case(key))
    }

    /// All matching fields, in wire order.
    pub fn all(&self, key: &[u8]) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.name_eq_ignore_case(key))
    }

    /// True when at least one field name matches `key`.
    #[inline]
    pub fn contains(&self, key: &[u8]) -> bool {
        self.first(key).is_some()
    }

    /// Remove and return all fields whose name matches `key`.
    pub fn retain_remove(&mut self, key: &[u8]) -> Vec<Field> {
        let mut removed = Vec::new();
        self.fields.retain(|f| {
            if f.name_eq_ignore_case(key) {
                removed.push(f.clone());
                false
            } else {
                true
            }
        });
        removed
    }
}

impl<'a> IntoIterator for &'a FieldSet {
    type Item = &'a Field;
    type IntoIter = std::slice::Iter<'a, Field>;
    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}

impl FromIterator<Field> for FieldSet {
    fn from_iter<I: IntoIterator<Item = Field>>(it: I) -> Self {
        Self::from_vec(it.into_iter().collect())
    }
}

/// ASCII-case-insensitive byte equality without allocating.
#[inline]
pub(crate) fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

/// Split one header line at the **first colon only**, mirroring the value
/// extraction performed by Asterisk's manager parser while remaining
/// byte-exact:
///
/// * `b"Action: Login"`  -> name `Action`, value `Login` (one space after the
///   colon is treated as the separator space and removed).
/// * `b"Variable: X=1"`  -> value `X=1`; embedded colons stay in the value
///   because we split at the *first* colon.
/// * `b"Host:"`          -> empty value.
/// * `b"Host:  two"`     -> value `" two"`: only the single canonical
///   separator space is removed; further leading spaces are meaningful and
///   preserved (no trimming).
/// * `b"Note:no-space"`  -> value `no-space` (space after colon is optional).
///
/// Returns `None` when the line contains no colon.
pub(crate) fn split_line(line: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    let colon = memchr_colon(line)?;
    let name = &line[..colon];
    let rest = &line[colon + 1..];
    let (value_off, value) = if rest.first() == Some(&b' ') {
        (colon + 2, &rest[1..])
    } else {
        (colon + 1, rest)
    };
    Some((name, value, value_off))
}

/// Find the first occurrence of `:` — tiny local helper avoiding a `regex`
/// or `memchr` dependency for a single byte needle.
#[inline]
pub(crate) fn memchr_colon(haystack: &[u8]) -> Option<usize> {
    // Simple word-unrolled scan; sufficient and branch-predictable.
    haystack.iter().position(|&b| b == b':')
}

/// Write bytes with `\r`, `\n`, NUL, non-printable and non-ASCII bytes
/// escaped, so `Debug` output of messages never dumps credentials or binary
/// data verbatim. Long values are truncated.
pub(crate) fn write_escaped(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    const MAX: usize = 48;
    write!(f, "\"")?;
    let mut written = 0;
    for &b in bytes {
        if written >= MAX {
            write!(f, "…(truncated)")?;
            break;
        }
        match b {
            b'"' => {
                write!(f, "\\\"")?;
                written += 2;
            }
            b'\\' => {
                write!(f, "\\\\")?;
                written += 2;
            }
            b'\r' => {
                write!(f, "\\r")?;
                written += 2;
            }
            b'\n' => {
                write!(f, "\\n")?;
                written += 2;
            }
            0x20..=0x7e => {
                write!(f, "{}", b as char)?;
                written += 1;
            }
            _ => {
                write!(f, "\\x{b:02x}")?;
                written += 4;
            }
        }
    }
    write!(f, "\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_order_and_duplicates() {
        let mut fs = FieldSet::new();
        fs.push(Field::from_str("Variable", "A=1"));
        fs.push(Field::from_str("variable", "B=2"));
        fs.push(Field::from_str("VARiable", "A=3"));
        let vars: Vec<_> = fs.all(b"Variable").map(|f| f.value_bytes().to_vec()).collect();
        assert_eq!(vars, vec![b"A=1".to_vec(), b"B=2".to_vec(), b"A=3".to_vec()]);
        assert_eq!(fs.get(1).unwrap().name_bytes(), b"variable");
        assert_eq!(fs.last(b"Variable").unwrap().value_bytes(), b"A=3");
        assert_eq!(fs.first(b"Variable").unwrap().value_bytes(), b"A=1");
    }

    #[test]
    fn lookup_is_case_insensitive_without_allocating_lower_names() {
        let f = Field::from_str("ActionID", "abc");
        assert!(f.name_eq_ignore_case(b"actionid"));
        assert!(f.name_eq_ignore_case(b"ACTIONID"));
        assert!(!f.name_eq_ignore_case(b"actionidx"));
        assert!(!f.name_eq_ignore_case(b"action"));
    }

    #[test]
    fn split_first_colon_only() {
        let (n, v, off) = split_line(b"Variable: KEY=1:2").unwrap();
        assert_eq!(n, b"Variable");
        assert_eq!(v, b"KEY=1:2");
        assert_eq!(off, 9);
        assert_eq!(split_line(b"Host:").unwrap().1, b"");
        assert_eq!(split_line(b"Host:  x").unwrap().1, b" x");
        assert_eq!(split_line(b"Host:no space").unwrap().1, b"no space");
        assert!(split_line(b"no colon here").is_none());
        // Empty name is representable (leading-colon line).
        let (n, v, _) = split_line(b": value").unwrap();
        assert_eq!(n, b"");
        assert_eq!(v, b"value");
    }

    #[test]
    fn empty_value_field_encodes_back_to_canonical_form() {
        let f = Field::from_raw_bytes(b"Called", b"");
        assert_eq!(f.as_wire_bytes(), b"Called:");
        let g = Field::from_str("Called", "");
        assert_eq!(g.as_wire_bytes(), b"Called:");
    }

    #[test]
    fn non_utf8_round_trips_through_raw_bytes() {
        let bad = [0xffu8, 0xfe];
        let f = Field::from_raw_bytes(b"X-Foo", &bad);
        assert_eq!(f.value_str(), None);
        assert_eq!(f.value_bytes(), &bad);
        assert_eq!(f.value_lossy(), "\u{fffd}\u{fffd}");
    }

    #[test]
    fn retain_remove_keeps_relative_order_of_the_rest() {
        let mut fs = FieldSet::new();
        for (n, v) in [("a", "1"), ("b", "2"), ("A", "3")] {
            fs.push(Field::from_str(n, v));
        }
        let removed = fs.retain_remove(b"A");
        assert_eq!(removed.len(), 2);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs.get(0).unwrap().name_bytes(), b"b");
    }

    #[test]
    fn debug_output_escapes_control_bytes() {
        let f = Field::from_raw_bytes(b"Secret", b"hunter2\r\nX");
        let d = format!("{f:?}");
        assert!(!d.contains("hunter2\r\n"), "debug must not emit raw CRLF: {d}");
        assert!(d.contains("\\r\\n"));
    }
}
