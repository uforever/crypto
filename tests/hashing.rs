//! Known-answer tests for the hashing operations, using public test
//! vectors (RFC 1321, FIPS 180, GB/T 32905, RFC 2104 style examples).

use crypto::hmac::Hmac;
use crypto::md5::Md5;
use crypto::operation::Operation;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha256, Sha512};
use crypto::sm3::Sm3;

const FOX: &str = "The quick brown fox jumps over the lazy dog";

/// Runs the operation and renders the output as lowercase hex
/// (`Bytes` implements `Debug` as a hex string).
fn hex_of(op: &dyn Operation, input: &[u8]) -> String {
    let output = op.run(input).expect("hashing should not fail");
    format!("{output:?}")
}

#[test]
fn md5_known_vectors() {
    let cases = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("123456", "e10adc3949ba59abbe56e057f20f883e"),
        (FOX, "9e107d9d372bb6826bd81d3542a419d6"),
    ];

    for (input, expected) in cases {
        assert_eq!(hex_of(&Md5, input.as_bytes()), expected, "input: {input:?}");
    }
}

#[test]
fn sha1_known_vectors() {
    let cases = [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (FOX, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
    ];

    for (input, expected) in cases {
        assert_eq!(hex_of(&Sha1::default(), input.as_bytes()), expected);
    }
}

#[test]
fn sha1_zero_rounds_falls_back_to_default() {
    // `Sha1::new(0)` is documented to fall back to the standard 80 rounds.
    assert_eq!(
        hex_of(&Sha1::new(0), b"abc"),
        hex_of(&Sha1::default(), b"abc")
    );
}

#[test]
fn sha256_known_vectors() {
    let cases = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            FOX,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(hex_of(&Sha256, input.as_bytes()), expected, "input: {input:?}");
    }
}

#[test]
fn sha512_known_vectors() {
    let cases = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ];

    for (input, expected) in cases {
        let expected = expected.split_whitespace().collect::<String>();
        assert_eq!(hex_of(&Sha512, input.as_bytes()), expected, "input: {input:?}");
    }
}

#[test]
fn sm3_known_vectors() {
    // Vectors from GB/T 32905-2016.
    let cases = [
        (
            "abc",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        ),
        (
            "",
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        ),
        (
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(hex_of(&Sm3, input.as_bytes()), expected, "input: {input:?}");
    }
}

#[test]
fn hmac_md5_known_vector() {
    let op = Hmac::<Md5>::new(b"key");
    assert_eq!(hex_of(&op, FOX.as_bytes()), "80070713463e7749b90c2dc24911e275");
}

#[test]
fn hmac_sha1_known_vector() {
    let op = Hmac::<Sha1>::new(b"key");
    assert_eq!(
        hex_of(&op, FOX.as_bytes()),
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    );
}

#[test]
fn hmac_sha256_known_vector() {
    let op = Hmac::<Sha256>::new(b"key");
    assert_eq!(
        hex_of(&op, FOX.as_bytes()),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
}

#[test]
fn hmac_sha256_supports_keys_longer_than_block_size() {
    // RFC 4231 test case 6: the key (0xaa repeated 131 times) exceeds the
    // 64-byte block size and must be hashed before use.
    let op = Hmac::<Sha256>::new(&[0xaa; 131]);
    assert_eq!(
        hex_of(
            &op,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}
