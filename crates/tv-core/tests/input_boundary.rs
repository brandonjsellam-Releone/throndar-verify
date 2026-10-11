#![forbid(unsafe_code)]

use tv_core::input::{InputError, MAX_DEPTH, MAX_INPUT_BYTES, UntrustedJson, parse_untrusted};

fn rejects(bytes: &[u8], expected: InputError) {
    assert_eq!(parse_untrusted(bytes).err(), Some(expected));
}

#[test]
fn preserves_valid_json_as_untrusted_source() {
    let cases = [
        r#"{"answer":"naïve — 日本語 😀","v":1}"#,
        r#"{"pair":"\uD83D\uDE00","slash":"\\","quote":"\""}"#,
        r#"{"a":{"same":1},"b":{"same":2},"":null}"#,
        r"[true,false,null,0,-0,1.0,1e400,-123456789012345678901234567890]",
        " \t\r\n{\"x\":2}\n",
        "null",
        "true",
        "\"text\"",
        "[]",
        "{}",
    ];
    let mut executed = 0;
    for source in cases {
        let parsed = parse_untrusted(source.as_bytes());
        assert!(parsed.is_ok(), "positive case {executed} failed");
        assert_eq!(
            parsed.ok().as_ref().map(UntrustedJson::as_untrusted_str),
            Some(source)
        );
        executed += 1;
    }
    assert_eq!(executed, 10, "all positive input vectors must execute");
}

#[test]
fn rejects_duplicate_decoded_keys_at_every_depth() {
    let cases = [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"x":[{"a":null,"a":null}]}"#,
        r#"{"😀":1,"\ud83d\ude00":2}"#,
        r#"{"":1,"":2}"#,
        r#"{"x":{"y":{"z":1,"z":2}}}"#,
    ];
    let mut executed = 0;
    for source in cases {
        assert!(matches!(
            parse_untrusted(source.as_bytes()),
            Err(InputError::DuplicateKey { .. })
        ));
        executed += 1;
    }
    assert_eq!(executed, 6);
}

#[test]
fn rejects_lone_surrogates_in_values_and_names() {
    let cases = [
        r#""\ud800""#,
        r#""\udfff""#,
        r#"["\ud800x"]"#,
        r#"{"\ud800":1}"#,
        r#"{"x":{"y":"\udc00"}}"#,
        r#""\ud800\u0041""#,
        r#""\ud800\ud800""#,
    ];
    for source in cases {
        assert!(matches!(
            parse_untrusted(source.as_bytes()),
            Err(InputError::LoneSurrogate { .. })
        ));
    }
}

#[test]
fn rejects_invalid_utf8_without_lossy_substitution() {
    for source in [
        b"\"\xff\"".as_slice(),
        b"\"\xc0\xaf\"",
        b"\"\xed\xa0\x80\"",
        b"\"\xf0\x9f\"",
        b"\x80",
    ] {
        rejects(source, InputError::NotUtf8);
    }
}

#[test]
fn leading_bom_is_refused_but_bom_in_string_is_data() {
    rejects("\u{feff}{}".as_bytes(), InputError::ByteOrderMark);
    assert!(parse_untrusted("\"\u{feff}\"".as_bytes()).is_ok());
}

#[test]
#[expect(
    clippy::literal_string_with_formatting_args,
    reason = "malformed JSON corpus contains a literal unquoted property"
)]
fn exactly_one_complete_document_is_required() {
    for source in [
        "",
        " ",
        "{}{}",
        "null true",
        "[1,]",
        "{\"a\":}",
        "[",
        "\"",
        "NaN",
        "Infinity",
        "01",
        "+1",
        "1.",
        "1e",
        "/*x*/{}",
        "{a:1}",
        "\"\\x41\"",
        "\"\n\"",
    ] {
        rejects(source.as_bytes(), InputError::JsonSyntax);
    }
}

#[test]
fn container_depth_64_succeeds_and_65_fails() {
    let exact = format!("{}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    assert!(parse_untrusted(exact.as_bytes()).is_ok());
    let over = format!("[{exact}]");
    rejects(over.as_bytes(), InputError::TooDeep);
    rejects("[".repeat(100_000).as_bytes(), InputError::TooDeep);
}

#[test]
fn object_and_mixed_containers_count_toward_depth() {
    let exact = format!("{}0{}", "{\"a\":".repeat(64), "}".repeat(64));
    assert!(parse_untrusted(exact.as_bytes()).is_ok());
    rejects(format!("[{exact}]").as_bytes(), InputError::TooDeep);
}

#[test]
fn many_shallow_siblings_do_not_accumulate_nesting_depth() {
    let array = format!("[{}]", vec![r#"{"items":[]}"#; 200].join(","));
    assert!(parse_untrusted(array.as_bytes()).is_ok());
    let members = (0..200)
        .map(|index| format!("\"field{index}\":{{}}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_untrusted(format!("{{{members}}}").as_bytes()).is_ok());
}

#[test]
fn delimiters_inside_strings_do_not_count_as_containers() {
    let source = format!(
        "{{\"x\":\"{}\\\"{}\\\\\"}}",
        "[".repeat(500),
        "}".repeat(500)
    );
    assert!(parse_untrusted(source.as_bytes()).is_ok());
}

#[test]
fn exact_byte_cap_is_inclusive() {
    let exact = format!("\"{}\"", "a".repeat(MAX_INPUT_BYTES - 2));
    assert!(parse_untrusted(exact.as_bytes()).is_ok());
    rejects(format!("{exact} ").as_bytes(), InputError::InputTooLarge);
}

#[test]
fn cap_counts_utf8_bytes_not_characters() {
    let exact = format!("\"{}\"", "é".repeat((MAX_INPUT_BYTES - 2) / 2));
    assert_eq!(exact.len(), MAX_INPUT_BYTES);
    assert!(parse_untrusted(exact.as_bytes()).is_ok());
    rejects(format!("{exact} ").as_bytes(), InputError::InputTooLarge);
}

#[test]
fn diagnostics_never_echo_private_input_or_duplicate_names() {
    let marker = "PRIVATE-AUDIT-MARKER";
    let input = format!("{{\"{marker}\":1,\"{marker}\":2}}");
    let error = parse_untrusted(input.as_bytes()).err();
    assert_eq!(
        error,
        Some(InputError::DuplicateKey {
            path: "$.member[1].name".into()
        })
    );
    assert!(!format!("{error:?}").contains(marker));
    let parsed = parse_untrusted(format!("\"{marker}\"").as_bytes());
    assert!(parsed.is_ok());
    assert!(!format!("{parsed:?}").contains(marker));
}

#[test]
fn error_paths_locate_structure_without_exposing_names() {
    assert_eq!(
        parse_untrusted(br#"{"private":[{"private":"\ud800"}]}"#).err(),
        Some(InputError::LoneSurrogate {
            path: "$.member[0].value[0].member[0].value".into()
        })
    );
    assert_eq!(
        parse_untrusted(br#"{"x":{"\ud800":1}}"#).err(),
        Some(InputError::LoneSurrogate {
            path: "$.member[0].value.member[0].name".into()
        })
    );
}

#[test]
fn serde_internal_token_names_are_ordinary_names() {
    for source in [
        r#"{"$serde_json::private::Number":"not a number"}"#,
        r#"{"$serde_json::private::RawValue":"{\"a\":1,\"a\":2}"}"#,
    ] {
        assert!(parse_untrusted(source.as_bytes()).is_ok());
    }
}
