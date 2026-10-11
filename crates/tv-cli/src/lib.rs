#![forbid(unsafe_code)]
//! Bounded transport only. This crate does not yet provide a verifier CLI.

use std::io::{self, Read};
use thiserror::Error;
use tv_core::input::{InputError, UntrustedJson, parse_untrusted};

/// Source-independent transport failure. The future CLI must classify stdin.
#[derive(Debug, Error)]
pub enum ReadInputError {
    /// No underlying I/O error text is exposed, since it may contain content.
    #[error("CannotRead")]
    CannotRead(io::ErrorKind),
    #[error(transparent)]
    Input(#[from] InputError),
}

/// Read and parse one bounded, untrusted JSON document.
///
/// # Errors
/// Returns a content-free I/O or input-rule failure.
pub fn read_untrusted(reader: impl Read) -> Result<UntrustedJson, ReadInputError> {
    // A fixed bound on the reader, not metadata or a post-read size check.
    let mut bounded = reader.take(4_000_001);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| ReadInputError::CannotRead(error.kind()))?;
    parse_untrusted(&bytes).map_err(Into::into)
}
