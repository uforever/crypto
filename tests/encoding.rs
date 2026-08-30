//! Tests for the encoding operations (hex, Base64) and ROT13.

use crypto::base64::{alphabet, FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::enums::Case;
use crypto::hex::{FromHex, ToHex};
use crypto::operation::Operation;
use crypto::rot13::Rot13;

/// Runs the operation and returns the raw output bytes.
fn run(op: &dyn Operation, input: &[u8]) -> Vec<u8> {
    op.run(input).expect("operation should not fail").to_vec()
}

#[test]
fn to_hex_default_is_lowercase_and_unseparated() {
    let op = ToHex::default();
    assert_eq!(run(&op, b"Hello"), b"48656c6c6f");
}

#[test]
fn to_hex_custom_separator_prefix_and_case() {
    let op = ToHex::new(" ", "\\x", Case::Upper);
    assert_eq!(run(&op, b"Hello"), b"\\x48 \\x65 \\x6C \\x6C \\x6F");
}

#[test]
fn from_hex_default_parses_contiguous_hex() {
    let op = FromHex::default();
    assert_eq!(run(&op, b"48656c6c6f"), b"Hello");
}

#[test]
fn from_hex_custom_separator_and_prefix() {
    let op = FromHex::new(", ", "0x");
    assert_eq!(run(&op, b"0x48, 0x65, 0x6c, 0x6c, 0x6f"), b"Hello");
}

#[test]
fn from_hex_rejects_invalid_characters() {
    let op = FromHex::default();
    assert!(op.run(b"zz").is_err());
}

#[test]
fn hex_roundtrip() {
    let to_hex = ToHex::default();
    let from_hex = FromHex::default();
    let input = b"\x00\x01\xfe\xff arbitrary bytes";

    let encoded = to_hex.run(input).unwrap();
    let decoded = from_hex.run(&encoded).unwrap();
    assert_eq!(decoded.to_vec(), input.to_vec());
}

#[test]
fn to_base64_standard_alphabet() {
    let op = ToBase64::default();
    let cases = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    for (input, expected) in cases {
        assert_eq!(
            String::from_utf8(run(&op, input.as_bytes())).unwrap(),
            expected,
            "input: {input:?}"
        );
    }
}

#[test]
fn from_base64_standard_alphabet() {
    let op = FromBase64::default();
    let cases = [
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg==", "foob"),
        ("Zm9vYmE=", "fooba"),
        ("Zm9vYmFy", "foobar"),
    ];

    for (input, expected) in cases {
        assert_eq!(
            run(&op, input.as_bytes()),
            expected.as_bytes(),
            "input: {input:?}"
        );
    }
}

#[test]
fn base64_roundtrip_across_lengths() {
    let to_base64 = ToBase64::default();
    let from_base64 = FromBase64::default();

    for len in 0..=32usize {
        let input: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37).wrapping_add(1)).collect();
        let encoded = to_base64.run(&input).unwrap();
        let decoded = from_base64.run(&encoded).unwrap();
        assert_eq!(decoded.to_vec(), input, "length: {len}");
    }
}

#[test]
fn base64_url_safe_alphabet_has_no_padding() {
    let op = ToBase64::new(alphabet::URL_SAFE);
    let encoded = run(&op, b"Hello");
    assert_eq!(String::from_utf8(encoded).unwrap(), "SGVsbG8");
}

#[test]
fn base64_rejects_invalid_characters() {
    let op = FromBase64::default();
    assert!(op.run(b"Zm9v!").is_err());
}

#[test]
fn rot13_default_shifts_by_thirteen() {
    let op = Rot13::default();
    assert_eq!(
        String::from_utf8(run(&op, b"Hello, World!")).unwrap(),
        "Uryyb, Jbeyq!"
    );
}

#[test]
fn rot13_twice_returns_the_original_text() {
    let op = Rot13::default();
    let input = b"The Quick Brown Fox, 42!";

    let once = op.run(input).unwrap();
    let twice = op.run(&once).unwrap();
    assert_eq!(twice.to_vec(), input.to_vec());
}

#[test]
fn rot13_zero_shift_is_identity() {
    let op = Rot13::new(0);
    assert_eq!(run(&op, b"unchanged, 123!"), b"unchanged, 123!");
}

#[test]
fn rot13_custom_shift() {
    // Shift 1: 'a' -> 'b', 'z' wraps to 'a'.
    let op = Rot13::new(1);
    assert_eq!(
        String::from_utf8(run(&op, b"az AZ !?")).unwrap(),
        "ba BA !?"
    );
}

#[test]
fn display_renders_utf8_and_debug_renders_hex() {
    let bytes = Bytes::new(b"Hello".as_ref());
    assert_eq!(format!("{bytes}"), "Hello");
    assert_eq!(format!("{bytes:?}"), "48656c6c6f");

    let binary = Bytes::new([0xff, 0x00].as_ref());
    assert_eq!(format!("{binary:?}"), "ff00");
}
