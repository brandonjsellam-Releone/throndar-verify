#![forbid(unsafe_code)]

use tv_core::input::{InputError, MAX_INPUT_BYTES, parse_untrusted};

#[test]
fn escaped_equivalent_duplicates_fail_even_at_the_last_permitted_level() {
    let pairs = [
        (r#""a""#, r#""\u0061""#),
        (r#""/""#, r#""\/""#),
        (r#""\n""#, r#""\u000a""#),
        (r#""\t""#, r#""\u0009""#),
        (r#""\\""#, r#""\u005c""#),
        (r#""\"""#, r#""\u0022""#),
        (r#""😀""#, r#""\uD83D\uDE00""#),
        (r#""é""#, r#""\u00E9""#),
    ];
    let mut executed = 0;
    for depth in [1, 8, 64] {
        for (first, second) in pairs {
            let source = format!(
                "{}{{{first}:0,{second}:1}}{}",
                "[".repeat(depth - 1),
                "]".repeat(depth - 1)
            );
            assert!(
                matches!(
                    parse_untrusted(source.as_bytes()),
                    Err(InputError::DuplicateKey { .. })
                ),
                "duplicate pair {executed} at depth {depth} was not classified"
            );
            executed += 1;
        }
    }
    assert_eq!(executed, 24);
}

#[test]
fn scalar_distinct_names_and_sibling_names_are_not_false_duplicates() -> Result<(), InputError> {
    let cases = [
        r#"{"é":0,"e\u0301":1}"#,
        r#"{"A":0,"a":1}"#,
        r#"{"\u0000":0,"":1}"#,
        r#"[{"name":0},{"\u006eame":1}]"#,
        r#"{"left":{"x":0},"right":{"x":1}}"#,
    ];
    let mut executed = 0;
    for source in cases {
        assert_eq!(
            parse_untrusted(source.as_bytes())?.as_untrusted_str(),
            source
        );
        executed += 1;
    }
    assert_eq!(executed, 5);
    Ok(())
}

#[test]
fn all_lone_surrogate_escapes_fail_in_both_name_and_value_positions() {
    let mut executed = 0;
    for codepoint in 0xd800_u32..=0xdfff {
        let value = format!(r#"{{"private":[0,"prefix\u{codepoint:04x}suffix"]}}"#);
        let name = format!(r#"[{{"prefix\u{codepoint:04x}suffix":0}}]"#);
        for source in [value, name] {
            assert!(
                matches!(
                    parse_untrusted(source.as_bytes()),
                    Err(InputError::LoneSurrogate { .. })
                ),
                "surrogate U+{codepoint:04X} must be classified"
            );
            executed += 1;
        }
    }
    assert_eq!(executed, 4096);
}

#[test]
fn valid_surrogate_pairs_cover_both_halves_without_false_refusal() -> Result<(), InputError> {
    let mut executed = 0;
    for high in 0xd800_u32..=0xdbff {
        let source = format!(r#""\u{high:04x}\udc00""#);
        assert_eq!(
            parse_untrusted(source.as_bytes())?.as_untrusted_str(),
            source
        );
        executed += 1;
    }
    for low in 0xdc00_u32..=0xdfff {
        let source = format!(r#"{{"\ud800\u{low:04x}":true}}"#);
        assert_eq!(
            parse_untrusted(source.as_bytes())?.as_untrusted_str(),
            source
        );
        executed += 1;
    }
    assert_eq!(executed, 2048);
    Ok(())
}

#[test]
fn alternating_containers_have_an_exact_64_container_limit() -> Result<(), InputError> {
    let mut exact = "null".to_owned();
    for depth in 1..=64 {
        exact = if depth % 2 == 0 {
            format!("{{\"safe\":{exact}}}")
        } else {
            format!("[{exact}]")
        };
        assert_eq!(parse_untrusted(exact.as_bytes())?.as_untrusted_str(), exact);
    }
    assert_eq!(
        parse_untrusted(format!("[{exact}]").as_bytes()).err(),
        Some(InputError::TooDeep)
    );
    Ok(())
}

#[test]
fn escaped_quote_and_backslash_parity_does_not_confuse_depth_scan() -> Result<(), InputError> {
    let strings = [
        r#""\\[{}]""#,
        r#""\\\"[{}]""#,
        r#""\u0022[{}]""#,
        r#""\"\\[{}]""#,
    ];
    let mut executed = 0;
    for string in strings {
        let source = format!("{}{string}{}", "[".repeat(64), "]".repeat(64));
        assert_eq!(
            parse_untrusted(source.as_bytes())?.as_untrusted_str(),
            source
        );
        executed += 1;
    }
    assert_eq!(executed, 4);
    Ok(())
}

#[test]
fn huge_number_tokens_are_preserved_without_numeric_conversion() -> Result<(), InputError> {
    let source = format!(
        " \n[-0,-0.0,1E+000009,1e-999999999999999999999,{},0.{}] \t",
        "9".repeat(100_000),
        "1".repeat(100_000)
    );
    assert_eq!(
        parse_untrusted(source.as_bytes())?.as_untrusted_str(),
        source
    );
    Ok(())
}

#[test]
fn complete_value_does_not_hide_any_trailing_token_or_non_json_whitespace() {
    let mut executed = 0;
    for prefix in ["{}", "[]", "0", "null", "\"x\""] {
        for suffix in [
            "{}", "[]", "false", "x", "\0", "\u{b}", "\u{c}", "\u{a0}", "\u{feff}",
        ] {
            assert_eq!(
                parse_untrusted(format!("{prefix} {suffix}").as_bytes()).err(),
                Some(InputError::JsonSyntax),
                "trailing vector {executed}"
            );
            executed += 1;
        }
    }
    assert_eq!(executed, 45);
}

#[test]
fn all_single_bytes_have_only_the_ten_expected_valid_documents() {
    let mut accepted = 0;
    for byte in 0_u8..=255 {
        let result = parse_untrusted(&[byte]);
        assert_eq!(result.is_ok(), byte.is_ascii_digit(), "byte {byte}");
        accepted += usize::from(result.is_ok());
    }
    assert_eq!(accepted, 10);
}

#[test]
fn syntax_incomplete_unicode_and_invalid_utf8_are_distinguished() {
    let syntax = [
        br#""\u123""#.as_slice(),
        br#""\uZ000""#,
        br#""\ud800\q""#,
        br#"{"\u123":0}"#,
    ];
    for bytes in syntax {
        assert_eq!(parse_untrusted(bytes).err(), Some(InputError::JsonSyntax));
    }
    for bytes in [
        b"\"\xed\xbf\xbf\"".as_slice(),
        b"\"\xf4\x90\x80\x80\"",
        b"\"\xc1\xbf\"",
        b"\"\xf0\x80\x80\x80\"",
    ] {
        assert_eq!(parse_untrusted(bytes).err(), Some(InputError::NotUtf8));
    }
}

#[test]
fn whitespace_is_included_in_the_size_cap_and_cannot_hide_a_suffix() -> Result<(), InputError> {
    let exact = format!("null{}", " ".repeat(MAX_INPUT_BYTES - 4));
    assert_eq!(exact.len(), 4_000_000);
    assert_eq!(parse_untrusted(exact.as_bytes())?.as_untrusted_str(), exact);
    assert_eq!(
        parse_untrusted(format!("{exact} ").as_bytes()).err(),
        Some(InputError::InputTooLarge)
    );
    assert_eq!(
        parse_untrusted(format!("{exact}x").as_bytes()).err(),
        Some(InputError::InputTooLarge)
    );
    Ok(())
}

#[test]
fn parser_error_display_debug_and_success_debug_do_not_echo_markers() -> Result<(), InputError> {
    let marker = "private-marker-987654321";
    let cases = [
        format!(r#"[{{"{marker}":0,"{marker}":1}}]"#),
        format!(r#"{{"{marker}":"{marker}\ud800"}}"#),
        format!(r#"{{"{marker}\udfff":0}}"#),
        format!(r#"{{"{marker}":}}"#),
        format!("\u{feff}{{\"{marker}\":0}}"),
    ];
    let mut executed = 0;
    for source in cases {
        let result = parse_untrusted(source.as_bytes());
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(!error.to_string().contains(marker));
            assert!(!format!("{error:?}").contains(marker));
            assert!(!error.to_string().contains("987654321"));
            executed += 1;
        }
    }
    assert_eq!(executed, 5);
    let accepted = parse_untrusted(format!(r#"{{"secret":"{marker}"}}"#).as_bytes())?;
    assert!(!format!("{accepted:?}").contains(marker));
    assert!(accepted.as_untrusted_str().contains(marker));
    Ok(())
}
