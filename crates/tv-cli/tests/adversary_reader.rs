#![forbid(unsafe_code)]

use std::io::{self, Read};
use tv_cli::{ReadInputError, read_untrusted};
use tv_core::input::{InputError, MAX_INPUT_BYTES};

struct NeverEof {
    consumed: usize,
    chunk: usize,
}

impl Read for NeverEof {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.chunk);
        let output = buffer.get_mut(..count).ok_or(io::ErrorKind::InvalidInput)?;
        output.fill(b' ');
        self.consumed += count;
        Ok(count)
    }
}

#[test]
fn reader_that_never_reaches_eof_stops_at_cap_plus_one() {
    let mut cases = 0;
    for chunk in [1, 4093, usize::MAX] {
        let mut reader = NeverEof { consumed: 0, chunk };
        assert!(matches!(
            read_untrusted(&mut reader),
            Err(ReadInputError::Input(InputError::InputTooLarge))
        ));
        assert_eq!(reader.consumed, 4_000_001);
        cases += 1;
    }
    assert_eq!(cases, 3);
}

struct InterruptedChunks {
    bytes: &'static [u8],
    interrupt_next: bool,
    interruptions: usize,
}

impl Read for InterruptedChunks {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            self.interruptions += 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt_next = true;
        let count = buffer.len().min(1);
        self.bytes
            .read(buffer.get_mut(..count).ok_or(io::ErrorKind::InvalidInput)?)
    }
}

#[test]
fn repeated_interruption_between_utf8_bytes_preserves_the_complete_document()
-> Result<(), ReadInputError> {
    let source = "{\"é😀\":\"日本語\"}";
    let mut reader = InterruptedChunks {
        bytes: source.as_bytes(),
        interrupt_next: true,
        interruptions: 0,
    };
    assert_eq!(read_untrusted(&mut reader)?.as_untrusted_str(), source);
    assert_eq!(reader.interruptions, source.len() + 1);
    Ok(())
}

struct FailAfterPrefix {
    bytes: Vec<u8>,
    sent: usize,
    failures: usize,
    kind: io::ErrorKind,
}

impl Read for FailAfterPrefix {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.sent == self.bytes.len() {
            self.failures += 1;
            return Err(io::Error::new(self.kind, "private-read-error-987654321"));
        }
        let remaining = self
            .bytes
            .get(self.sent..)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let count = remaining.len().min(buffer.len());
        let output = buffer.get_mut(..count).ok_or(io::ErrorKind::InvalidInput)?;
        output.copy_from_slice(remaining.get(..count).ok_or(io::ErrorKind::InvalidInput)?);
        self.sent += count;
        Ok(count)
    }
}

#[test]
fn io_failure_after_a_complete_json_value_is_not_mistaken_for_eof() {
    let mut executed = 0;
    for kind in [
        io::ErrorKind::Other,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::TimedOut,
        io::ErrorKind::UnexpectedEof,
    ] {
        let mut reader = FailAfterPrefix {
            bytes: b"{}".to_vec(),
            sent: 0,
            failures: 0,
            kind,
        };
        let result = read_untrusted(&mut reader);
        assert!(matches!(result, Err(ReadInputError::CannotRead(actual)) if actual == kind));
        assert_eq!(reader.failures, 1);
        if let Err(error) = result {
            assert!(!error.to_string().contains("private-read-error"));
            assert!(!format!("{error:?}").contains("987654321"));
        }
        executed += 1;
    }
    assert_eq!(executed, 5);
}

#[test]
fn exact_cap_still_requires_eof_but_cap_plus_one_stops_before_further_io() {
    let mut exact = FailAfterPrefix {
        bytes: format!("null{}", " ".repeat(MAX_INPUT_BYTES - 4)).into_bytes(),
        sent: 0,
        failures: 0,
        kind: io::ErrorKind::Other,
    };
    assert!(matches!(
        read_untrusted(&mut exact),
        Err(ReadInputError::CannotRead(io::ErrorKind::Other))
    ));
    assert_eq!(exact.sent, 4_000_000);
    assert_eq!(exact.failures, 1);
    exact.bytes.push(b' ');
    exact.sent = 0;
    exact.failures = 0;
    assert!(matches!(
        read_untrusted(&mut exact),
        Err(ReadInputError::Input(InputError::InputTooLarge))
    ));
    assert_eq!(exact.sent, 4_000_001);
    assert_eq!(exact.failures, 0);
}

#[test]
fn transport_enforces_the_same_parser_rules_after_successful_read() {
    for (source, error) in [
        (
            br#"{"a":0,"\u0061":1}"#.as_slice(),
            InputError::DuplicateKey {
                path: "$.member[1].name".into(),
            },
        ),
        (
            br#"["\ud800"]"#.as_slice(),
            InputError::LoneSurrogate {
                path: "$[0]".into(),
            },
        ),
        (b"{} []".as_slice(), InputError::JsonSyntax),
        (b"\xef\xbb\xbf{}".as_slice(), InputError::ByteOrderMark),
        (b"\xff".as_slice(), InputError::NotUtf8),
    ] {
        assert!(
            matches!(read_untrusted(source), Err(ReadInputError::Input(actual)) if actual == error)
        );
    }
    assert!(read_untrusted(b"{\"ok\":true}".as_slice()).is_ok());
}
