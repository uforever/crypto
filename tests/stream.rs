//! Tests for the stream cipher (RC4) and XXTEA.

use crypto::bytes::Bytes;
use crypto::operation::Operation;
use crypto::rc4::Rc4;
use crypto::tea::{XxteaDecrypt, XxteaEncrypt};

/// Renders bytes as lowercase hex (`Bytes` implements `Debug` as hex).
fn hex(bytes: &Bytes) -> String {
    format!("{bytes:?}")
}

#[test]
fn rc4_known_vectors() {
    // Classic RC4 test vectors.
    let cases = [
        ("Key", "Plaintext", "bbf316e8d940af0ad3"),
        ("Wiki", "pedia", "1021bf0420"),
        ("Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"),
    ];

    for (key, plaintext, expected) in cases {
        let op = Rc4::new(key.as_bytes());
        let ciphertext = op.run(plaintext.as_bytes()).unwrap();
        assert_eq!(hex(&ciphertext), expected, "key: {key:?}");
    }
}

#[test]
fn rc4_is_self_inverting() {
    let op = Rc4::new(b"symmetric");
    let plaintext = b"RC4 is a stream cipher";

    let ciphertext = op.run(plaintext).unwrap();
    let recovered = op.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn xxtea_roundtrip_with_length() {
    let key = b"0123456789abcdef";

    for plaintext in [
        &b"x"[..],
        b"abcd",
        b"Hello, XXTEA!",
        b"0123456789abcdef0123456789abcdef",
    ] {
        let encrypt = XxteaEncrypt::new(key, true);
        let decrypt = XxteaDecrypt::new(key, true);

        let ciphertext = encrypt.run(plaintext).unwrap();
        let recovered = decrypt.run(&ciphertext).unwrap();
        assert_eq!(recovered.to_vec(), plaintext.to_vec());
    }
}

#[test]
fn xxtea_roundtrip_without_length() {
    // Without the embedded length the plaintext is restored up to the
    // 4-byte aligned block size.
    let key = b"0123456789abcdef";
    let plaintext = b"Hello, XXTEA!"; // 13 bytes -> padded to 16

    let encrypt = XxteaEncrypt::new(key, false);
    let decrypt = XxteaDecrypt::new(key, false);

    let ciphertext = encrypt.run(plaintext).unwrap();
    assert_eq!(ciphertext.len(), 16);

    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.len(), 16);
    assert_eq!(&recovered[..13], plaintext);
}

#[test]
fn xxtea_uses_only_the_first_16_key_bytes() {
    let base_key = b"0123456789abcdef";
    // Extra key bytes must not change the result.
    let longer_key = b"0123456789abcdefXYZ";

    let plaintext = b"key truncation!";
    let a = XxteaEncrypt::new(base_key, true).run(plaintext).unwrap();
    let b = XxteaEncrypt::new(longer_key, true).run(plaintext).unwrap();

    assert_eq!(a.to_vec(), b.to_vec());
}

#[test]
fn xxtea_decrypt_rejects_wrong_key() {
    let plaintext = b"secret message!";

    let ciphertext = XxteaEncrypt::new(b"correct-key-1234", true)
        .run(plaintext)
        .unwrap();
    let recovered = XxteaDecrypt::new(b"wrong--key-1234", true)
        .run(&ciphertext)
        .unwrap();

    assert_ne!(recovered.to_vec(), plaintext.to_vec());
}
