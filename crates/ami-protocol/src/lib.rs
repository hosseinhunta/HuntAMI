//! Runtime-independent AMI wire layer: lossless messages, incremental
//! codec, validation, resource limits, and structured errors.
//!
//! See `docs/architecture.md` for the invariants this crate enforces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod decoder;
pub mod error;
pub mod fields;
pub mod limits;
pub mod message;
pub mod validate;

pub use decoder::{DecodeStep, Decoder};
pub use error::{AmiError, FieldEncodingReason, LimitKind, Result, TruncationStage};
pub use fields::{Field, FieldSet};
pub use limits::Limits;
pub use message::{AmiMessage, CommandOutput, OutputFraming, ResponseKind, WireMessage};
