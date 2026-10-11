//! G3–G5 input boundary. Parsed values never acquire verification status.

use serde::Deserializer as _;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// Maximum serialized input size, in bytes.
pub const MAX_INPUT_BYTES: usize = 4_000_000;
/// Maximum number of nested JSON containers.
pub const MAX_DEPTH: usize = 64;

/// Parsing never establishes authenticity or field semantics.
pub struct UntrustedJson {
    source: String,
}

impl UntrustedJson {
    /// Borrow the original, still-untrusted text without canonicalizing numbers.
    #[must_use]
    pub fn as_untrusted_str(&self) -> &str {
        &self.source
    }
}

impl fmt::Debug for UntrustedJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UntrustedJson { source: [redacted] }")
    }
}

/// Content-free failure categories for this parsing stage only.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InputError {
    #[error("InputTooLarge")]
    InputTooLarge,
    #[error("NotUtf8")]
    NotUtf8,
    #[error("ByteOrderMark")]
    ByteOrderMark,
    #[error("JsonSyntax")]
    JsonSyntax,
    #[error("DuplicateKey at {path}")]
    DuplicateKey { path: String },
    #[error("LoneSurrogate at {path}")]
    LoneSurrogate { path: String },
    #[error("TooDeep")]
    TooDeep,
}

/// Parse one strict JSON document, leaving every value untrusted.
///
/// # Errors
/// Returns an input-rule failure without including document contents.
pub fn parse_untrusted(bytes: &[u8]) -> Result<UntrustedJson, InputError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(InputError::InputTooLarge);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| InputError::NotUtf8)?;
    if source.starts_with('\u{feff}') {
        return Err(InputError::ByteOrderMark);
    }
    check_depth(bytes)?;
    // RawValue validates a complete JSON value without converting any number.
    let raw: &RawValue = serde_json::from_str(source).map_err(|_| InputError::JsonSyntax)?;
    check_objects(raw.get(), "$")?;
    Ok(UntrustedJson {
        source: source.to_owned(),
    })
}

// This scan bounds recursion before invoking serde. It is not a JSON decoder:
// mismatched delimiters and malformed escapes are rejected by serde afterward.
fn check_depth(bytes: &[u8]) -> Result<(), InputError> {
    let mut depth = 0_u8;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth = depth.saturating_add(1);
                    if usize::from(depth) > MAX_DEPTH {
                        return Err(InputError::TooDeep);
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

fn check_objects(source: &str, path: &str) -> Result<(), InputError> {
    let mut failure = None;
    let visitor = ContainerVisitor {
        failure: &mut failure,
        path,
    };
    let mut decoder = serde_json::Deserializer::from_str(source);
    let result = match source.as_bytes().first() {
        Some(b'{') => decoder.deserialize_map(visitor),
        Some(b'[') => decoder.deserialize_seq(visitor),
        // RawValue validated syntax, but permits lone surrogate escapes.
        // Rust String decoding is the additional Unicode-scalar check.
        Some(b'"') => {
            return serde_json::from_str::<String>(source)
                .map(|_| ())
                .map_err(|_| InputError::LoneSurrogate {
                    path: path.to_owned(),
                });
        }
        _ => return Ok(()),
    };
    result.map_err(|_| failure.unwrap_or(InputError::JsonSyntax))
}

struct ContainerVisitor<'a> {
    failure: &'a mut Option<InputError>,
    path: &'a str,
}

impl<'de> Visitor<'de> for ContainerVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON container")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut names = BTreeSet::new();
        let mut member = 0_usize;
        loop {
            let key_path = format!("{}.member[{member}].name", self.path);
            let name = map.next_key::<String>().inspect_err(|_| {
                *self.failure = Some(InputError::LoneSurrogate {
                    path: key_path.clone(),
                });
            })?;
            let Some(name) = name else { break };
            if !names.insert(name) {
                *self.failure = Some(InputError::DuplicateKey { path: key_path });
                return Err(A::Error::custom("input rule failed"));
            }
            let value: &RawValue = map.next_value()?;
            check_objects(
                value.get(),
                &format!("{}.member[{member}].value", self.path),
            )
            .map_err(|error| {
                *self.failure = Some(error);
                A::Error::custom("input rule failed")
            })?;
            // Input byte cap makes usize overflow unreachable on supported hosts.
            member = member.saturating_add(1);
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut index = 0_usize;
        while let Some(value) = sequence.next_element::<&RawValue>()? {
            check_objects(value.get(), &format!("{}[{index}]", self.path)).map_err(|error| {
                *self.failure = Some(error);
                A::Error::custom("input rule failed")
            })?;
            index = index.saturating_add(1);
        }
        Ok(())
    }
}
