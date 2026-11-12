//! Outgoing-message validation and canonical encoding.
//!
//! Rules (verified against the pinned Asterisk sources listed in
//! `fixtures/compatibility.toml`):
//!
//! * Field names must be non-empty, contain no CR, LF, `:`, or NUL, and be
//!   valid UTF-8.
//! * Field values must contain no CR or LF (header-injection prevention) and
//!   no NUL. They must be valid UTF-8 for an outgoing action.
//! * An action carries at most one `Action:` field and at most one
//!   `ActionID:` field; a non-empty `Action:` name is required.
//! * Duplicate fields are preserved, never merged or overwritten — except
//!   that this module *refuses* to build a message that would silently
//!   duplicate `Action`/`ActionID`.

use crate::error::{AmiError, FieldEncodingReason};
use crate::fields::{ascii_eq_ignore_case, Field, FieldSet};
use crate::message::WireMessage;

/// Validate a single field name's bytes for transmission.
pub fn validate_name(name: &[u8]) -> Result<(), AmiError> {
    if name.is_empty() {
        return Err(AmiError::InvalidFieldEncoding {
            reason: FieldEncodingReason::EmptyName,
            preview: String::new(),
        });
    }
    check_forbidden(name, true)?;
    if std::str::from_utf8(name).is_err() {
        return Err(AmiError::InvalidFieldEncoding {
            reason: FieldEncodingReason::InvalidUtf8,
            preview: crate::decoder::preview_bytes(name),
        });
    }
    Ok(())
}

/// Validate a single field value's bytes for transmission.
pub fn validate_value(value: &[u8]) -> Result<(), AmiError> {
    check_forbidden(value, false)?;
    if std::str::from_utf8(value).is_err() {
        return Err(AmiError::InvalidFieldEncoding {
            reason: FieldEncodingReason::InvalidUtf8,
            preview: crate::decoder::preview_bytes(value),
        });
    }
    Ok(())
}

fn check_forbidden(bytes: &[u8], name: bool) -> Result<(), AmiError> {
    for &b in bytes {
        let reason = match b {
            b'\r' | b'\n' => FieldEncodingReason::CrLfInjection,
            0 => FieldEncodingReason::NullByte,
            b':' if name => FieldEncodingReason::ColonInName,
            _ => continue,
        };
        // Preview only the offending byte position context, never the whole
        // secret-bearing value verbatim beyond the escape truncation.
        return Err(AmiError::InvalidFieldEncoding {
            reason,
            preview: crate::decoder::preview_bytes(bytes),
        });
    }
    Ok(())
}

/// A builder for outgoing AMI actions with validated, order-preserving
/// fields. Constructed via [`OutgoingAction::new`].
#[derive(Debug, Clone)]
pub struct OutgoingAction {
    fields: Vec<Field>,
}

impl OutgoingAction {
    /// Begin an action named `action` (validated immediately).
    pub fn new(action: &str) -> Result<Self, AmiError> {
        validate_name(action.as_bytes())?;
        if action.is_empty() {
            return Err(AmiError::Validation {
                rule: "action.name_nonempty",
                detail: "action name must not be empty".into(),
            });
        }
        Ok(Self { fields: vec![Field::from_str("Action", action)] })
    }

    /// Append a validated field. Duplicates such as `Variable` are kept in
    /// the order given; `Action` and `ActionID` may appear only once.
    pub fn field(mut self, name: &str, value: &str) -> Result<Self, AmiError> {
        self.try_field(name, value)?;
        Ok(self)
    }

    /// Fallible in-place variant used by builders that need error recovery.
    pub fn try_field(&mut self, name: &str, value: &str) -> Result<(), AmiError> {
        validate_name(name.as_bytes())?;
        validate_value(value.as_bytes())?;
        let n = name.as_bytes();
        if ascii_eq_ignore_case(n, b"Action") && self.has(b"Action") {
            return Err(AmiError::Validation {
                rule: "action.cardinality_action",
                detail: "an outgoing action may carry exactly one Action field".into(),
            });
        }
        if ascii_eq_ignore_case(n, b"ActionID") && self.has(b"ActionID") {
            return Err(AmiError::Validation {
                rule: "action.cardinality_actionid",
                detail: "an outgoing action may carry exactly one ActionID field".into(),
            });
        }
        self.fields.push(Field::from_str(name, value));
        Ok(())
    }

    /// Set the `ActionID`, replacing any previously set one *only when asked
    /// explicitly* (this is the caller overwriting their own value, which is
    /// allowed; server-supplied fields are never touched here).
    pub fn action_id(mut self, id: &str) -> Result<Self, AmiError> {
        let existing = self.has(b"ActionID");
        validate_value(id.as_bytes())?;
        if existing {
            self.fields.retain(|f| !f.name_eq_ignore_case(b"ActionID"));
        }
        self.fields.insert(1.min(self.fields.len()), Field::from_str("ActionID", id));
        Ok(self)
    }

    fn has(&self, key: &[u8]) -> bool {
        self.fields.iter().any(|f| f.name_eq_ignore_case(key))
    }

    /// Number of fields so far.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// True when only the `Action` line exists.
    pub fn is_empty(&self) -> bool {
        self.fields.len() <= 1
    }

    /// Validate cardinality and freeze into a [`WireMessage`].
    pub fn build(self) -> Result<WireMessage, AmiError> {
        // Action already validated at construction; re-check uniqueness.
        let actions = self.fields.iter().filter(|f| f.name_eq_ignore_case(b"Action")).count();
        if actions != 1 {
            return Err(AmiError::Validation {
                rule: "action.cardinality_action",
                detail: format!("expected exactly 1 Action field, found {actions}"),
            });
        }
        let ids = self.fields.iter().filter(|f| f.name_eq_ignore_case(b"ActionID")).count();
        if ids > 1 {
            return Err(AmiError::Validation {
                rule: "action.cardinality_actionid",
                detail: format!("expected at most 1 ActionID field, found {ids}"),
            });
        }
        Ok(WireMessage::from_validated(self.fields))
    }
}

/// Validate an arbitrary field set as an outgoing message (used by tests
/// and by callers who built `FieldSet`s directly).
pub fn validate_outgoing(fields: &FieldSet) -> Result<(), AmiError> {
    for f in fields.iter() {
        validate_name(f.name_bytes())?;
        validate_value(f.value_bytes())?;
    }
    let actions = fields.all(b"Action").count();
    if actions > 1 {
        return Err(AmiError::Validation {
            rule: "action.cardinality_action",
            detail: format!("found {actions} Action fields"),
        });
    }
    let ids = fields.all(b"ActionID").count();
    if ids > 1 {
        return Err(AmiError::Validation {
            rule: "action.cardinality_actionid",
            detail: format!("found {ids} ActionID fields"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_crlf_injection_in_values() {
        let a = OutgoingAction::new("Ping").unwrap();
        let err = a.field("Data", "ok\r\nAction: Fake").unwrap_err();
        assert!(matches!(
            err,
            AmiError::InvalidFieldEncoding { reason: FieldEncodingReason::CrLfInjection, .. }
        ));
    }

    #[test]
    fn rejects_colon_and_empty_names() {
        let a = OutgoingAction::new("Ping").unwrap();
        assert!(matches!(
            a.field("Bad:Name", "v").unwrap_err(),
            AmiError::InvalidFieldEncoding { reason: FieldEncodingReason::ColonInName, .. }
        ));
        let a = OutgoingAction::new("Ping").unwrap();
        assert!(matches!(
            a.field("", "v").unwrap_err(),
            AmiError::InvalidFieldEncoding { reason: FieldEncodingReason::EmptyName, .. }
        ));
    }

    #[test]
    fn preserves_duplicate_variables_rejects_duplicate_actionid() {
        let a = OutgoingAction::new("Login")
            .unwrap()
            .field("Variable", "A=1")
            .unwrap()
            .field("Variable", "B=2")
            .unwrap();
        let m = a.build().unwrap();
        assert_eq!(m.variables().len(), 2);

        let a = OutgoingAction::new("Login").unwrap().field("ActionID", "x").unwrap();
        assert!(a.field("ActionID", "y").is_err());
    }

    #[test]
    fn action_id_setter_replaces_own_value_only() {
        let a = OutgoingAction::new("Ping")
            .unwrap()
            .action_id("first")
            .unwrap()
            .action_id("second")
            .unwrap();
        let m = a.build().unwrap();
        assert_eq!(m.fields().all(b"ActionID").count(), 1);
        assert_eq!(m.value_str("ActionID").unwrap(), "second");
    }

    #[test]
    fn rejects_non_utf8_outgoing_value() {
        let a = OutgoingAction::new("X").unwrap();
        assert!(matches!(
            a.try_field_bad_bytes(b"Note", b"\xff\xfe"),
            Err(AmiError::InvalidFieldEncoding { reason: FieldEncodingReason::InvalidUtf8, .. })
        ));
    }

    impl OutgoingAction {
        fn try_field_bad_bytes(&self, name: &[u8], value: &[u8]) -> Result<(), AmiError> {
            validate_name(name)?;
            validate_value(value)
        }
    }
}
