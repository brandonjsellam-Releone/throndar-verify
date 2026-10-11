#![forbid(unsafe_code)]

use std::io::{self, Cursor, Read};
use tv_cli::{ReadInputError, read_untrusted};
use tv_core::input::{InputError, MAX_INPUT_BYTES, UntrustedJson};

#[test]
fn reads_valid_chunked_input_until_eof() {
    struct Chunked(Cursor<Vec<u8>>);
    impl Read for Chunked {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let chunk = buffer.len().min(1);
            self.0
                .read(buffer.get_mut(..chunk).ok_or(io::ErrorKind::InvalidInput)?)
        }
    }
    let source = "{\"utf8\":\"é😀\"}";
    let parsed = read_untrusted(Chunked(Cursor::new(source.as_bytes().to_vec())));
    assert!(parsed.is_ok());
    assert_eq!(
        parsed.ok().as_ref().map(UntrustedJson::as_untrusted_str),
        Some(source)
    );
}

#[test]
fn reader_consumes_at_most_cap_plus_one() {
    let mut reader = Cursor::new(vec![b' '; MAX_INPUT_BYTES + 20_000]);
    assert!(matches!(
        read_untrusted(&mut reader),
        Err(ReadInputError::Input(InputError::InputTooLarge))
    ));
    assert_eq!(reader.position(), 4_000_001);
}

#[test]
fn exact_cap_can_succeed_and_empty_reader_fails() {
    let source = format!("\"{}\"", "a".repeat(MAX_INPUT_BYTES - 2));
    assert!(read_untrusted(source.as_bytes()).is_ok());
    assert!(matches!(
        read_untrusted(io::empty()),
        Err(ReadInputError::Input(InputError::JsonSyntax))
    ));
}

#[test]
fn read_failure_after_valid_prefix_never_accepts_partial_input() {
    struct Failing {
        emitted: bool,
    }
    impl Read for Failing {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                return Err(io::Error::other("PRIVATE-IO-DETAIL"));
            }
            self.emitted = true;
            let out = buffer.get_mut(..2).ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(b"{}");
            Ok(2)
        }
    }
    let result = read_untrusted(Failing { emitted: false });
    assert!(matches!(
        result,
        Err(ReadInputError::CannotRead(io::ErrorKind::Other))
    ));
    assert!(!format!("{result:?}").contains("PRIVATE-IO-DETAIL"));
}

#[test]
fn interrupted_read_retries_without_losing_data() {
    struct Interrupted {
        once: bool,
        bytes: Cursor<Vec<u8>>,
    }
    impl Read for Interrupted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.once {
                self.once = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.bytes.read(buffer)
        }
    }
    assert!(
        read_untrusted(Interrupted {
            once: false,
            bytes: Cursor::new(b"{}".to_vec())
        })
        .is_ok()
    );
}
