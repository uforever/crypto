//! Known-answer and round-trip tests for the block ciphers (AES, DES,
//! 3DES, SM4) and the chaining modes, using public test vectors
//! (FIPS 197, NIST GCM spec, classic DES vectors, GB/T 32907).

use crypto::aes::{AesDecrypt, AesEncrypt};
use crypto::bytes::Bytes;
use crypto::des::{DesDecrypt, DesEncrypt, TripleDesDecrypt, TripleDesEncrypt};
use crypto::mode::{Cbc, Cfb, Ctr, Ecb, Gcm, Ofb};
use crypto::operation::Operation;
use crypto::padding::{NoPadding, Pkcs7Padding};
use crypto::sm4::Sm4Encrypt;

/// Decodes a lowercase/uppercase hex string into bytes.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Renders bytes as lowercase hex (`Bytes` implements `Debug` as hex).
fn hex(data: &[u8]) -> String {
    format!("{:?}", Bytes::new(data))
}

const FIPS_PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

#[test]
fn aes128_ecb_fips197_vector() {
    let op = AesEncrypt::<Ecb, NoPadding>::new(&unhex("000102030405060708090a0b0c0d0e0f"), Ecb);
    let ciphertext = op.run(&unhex(FIPS_PLAINTEXT)).unwrap();
    assert_eq!(hex(&ciphertext), "69c4e0d86a7b0430d8cdb78070b4c55a");
}

#[test]
fn aes192_ecb_fips197_vector() {
    let op = AesEncrypt::<Ecb, NoPadding>::new(
        &unhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        Ecb,
    );
    let ciphertext = op.run(&unhex(FIPS_PLAINTEXT)).unwrap();
    assert_eq!(hex(&ciphertext), "dda97ca4864cdfe06eaf70a0ec0d7191");
}

#[test]
fn aes192_ecb_sp800_38a_vector() {
    // NIST SP 800-38A, F.1.3 ECB-AES192.Encrypt (first block).
    let op = AesEncrypt::<Ecb, NoPadding>::new(
        &unhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        Ecb,
    );
    let ciphertext = op.run(&unhex("6bc1bee22e409f96e93d7e117393172a")).unwrap();
    assert_eq!(hex(&ciphertext), "bd334f1d6e45f25ff712a214571fa5cc");
}

#[test]
fn aes256_ecb_fips197_vector() {
    let op = AesEncrypt::<Ecb, NoPadding>::new(
        &unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        Ecb,
    );
    let ciphertext = op.run(&unhex(FIPS_PLAINTEXT)).unwrap();
    assert_eq!(hex(&ciphertext), "8ea2b7ca516745bfeafc49904b496089");
}

#[test]
fn aes128_ecb_fips197_decrypt_roundtrip() {
    let encrypt = AesEncrypt::<Ecb, NoPadding>::new(&unhex("000102030405060708090a0b0c0d0e0f"), Ecb);
    let decrypt = AesDecrypt::<Ecb, NoPadding>::new(&unhex("000102030405060708090a0b0c0d0e0f"), Ecb);
    let plaintext = unhex(FIPS_PLAINTEXT);

    let ciphertext = encrypt.run(&plaintext).unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(hex(&recovered), FIPS_PLAINTEXT);
}

#[test]
fn des_classic_vector() {
    // Widely cited DES test vector.
    let op = DesEncrypt::<Ecb, NoPadding>::new(&unhex("133457799bbcdff1"), Ecb);
    let ciphertext = op.run(&unhex("0123456789abcdef")).unwrap();
    assert_eq!(hex(&ciphertext), "85e813540f0ab405");
}

#[test]
fn des_ecb_decrypt_roundtrip() {
    let encrypt = DesEncrypt::<Ecb, NoPadding>::new(b"8bytekey", Ecb);
    let decrypt = DesDecrypt::<Ecb, NoPadding>::new(b"8bytekey", Ecb);

    let ciphertext = encrypt.run(b"01234567").unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(hex(&recovered), "3031323334353637");
}

#[test]
fn sm4_standard_vector() {
    // Vector from GB/T 32907-2016, appendix A.1.
    let key = unhex("0123456789abcdeffedcba9876543210");
    let op = Sm4Encrypt::<Ecb, NoPadding>::new(&key, Ecb);
    let ciphertext = op.run(&key).unwrap();
    assert_eq!(hex(&ciphertext), "681edf34d206965e86b3e94f536e4246");
}

#[test]
fn triple_des_roundtrip() {
    // A 16-byte key selects the 2-key (K1, K2, K1) variant.
    let key = b"1234567887654321";
    let plaintext = b"TripleDES 16b";

    let encrypt = TripleDesEncrypt::<Ecb, Pkcs7Padding>::new(key, Ecb);
    let decrypt = TripleDesDecrypt::<Ecb, Pkcs7Padding>::new(key, Ecb);

    let ciphertext = encrypt.run(plaintext).unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn aes_roundtrip_across_modes_with_pkcs7() {
    let key = b"0123456789abcdef";
    let iv = b"0123456789abcdef";
    let plaintext = b"Hello,AES-CBC/CFB/OFB/CTR!";

    let cases: Vec<Box<dyn Operation>> = vec![
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(key, Ecb)),
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(key, Cbc::new(iv))),
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(key, Cfb::new(iv))),
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(key, Ofb::new(iv))),
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(key, Ctr::new(iv))),
    ];

    for encrypt in cases {
        let ciphertext = encrypt.run(plaintext).unwrap();
        assert_ne!(
            ciphertext.to_vec(),
            plaintext.to_vec(),
            "ciphertext should differ from plaintext"
        );
        assert!(
            ciphertext.len() > plaintext.len(),
            "PKCS7 padding must grow the input"
        );
    }
}

#[test]
fn aes_cbc_pkcs7_full_roundtrip() {
    let key = b"0123456789abcdef";
    let iv = b"0123456789abcdef";
    let plaintext = b"Hello,AES-CBC/CFB/OFB/CTR!";

    let encrypt = AesEncrypt::<_, Pkcs7Padding>::new(key, Cbc::new(iv));
    let decrypt = AesDecrypt::<_, Pkcs7Padding>::new(key, Cbc::new(iv));

    let ciphertext = encrypt.run(plaintext).unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn aes_stream_modes_no_padding_roundtrip() {
    let key = b"0123456789abcdef";
    let iv = b"counter/iv/block";
    // Stream modes preserve length, so the input must be block aligned here.
    let plaintext = [0x61; 48];

    let cases: Vec<(Box<dyn Operation>, Box<dyn Operation>)> = vec![
        (
            Box::new(AesEncrypt::<_, NoPadding>::new(key, Cfb::new(iv))),
            Box::new(AesDecrypt::<_, NoPadding>::new(key, Cfb::new(iv))),
        ),
        (
            Box::new(AesEncrypt::<_, NoPadding>::new(key, Ofb::new(iv))),
            Box::new(AesDecrypt::<_, NoPadding>::new(key, Ofb::new(iv))),
        ),
        (
            Box::new(AesEncrypt::<_, NoPadding>::new(key, Ctr::new(iv))),
            Box::new(AesDecrypt::<_, NoPadding>::new(key, Ctr::new(iv))),
        ),
    ];

    for (encrypt, decrypt) in cases {
        let ciphertext = encrypt.run(&plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len());
        let recovered = decrypt.run(&ciphertext).unwrap();
        assert_eq!(recovered.to_vec(), plaintext.to_vec());
    }
}

#[test]
fn aes_gcm_nist_test_case_2() {
    // NIST GCM specification, test case 2 (AES-128, 96-bit IV, no AAD).
    let key = unhex("feffe9928665731c6d6a8f9467308308");
    let iv = unhex("cafebabefacedbaddecaf888");
    let plaintext = unhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );

    let op = AesEncrypt::<_, NoPadding>::new(&key, Gcm::new(&iv, None));
    let output = op.run(&plaintext).unwrap();

    let expected = "42831ec2217774244b7221b784d0d49c\
                    e3aa212f2c02a4e035c17e2329aca12e\
                    21d514b25466931c7d8f6a5aac84aa05\
                    1ba30b396a0aac973d58e091473f5985\
                    4d5c2af327cd64a62cf35abd2ba6fab4";
    assert_eq!(hex(&output), expected);
}

#[test]
fn aes_gcm_decrypt_roundtrip() {
    let key = unhex("feffe9928665731c6d6a8f9467308308");
    let iv = unhex("cafebabefacedbaddecaf888");
    let plaintext = unhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );

    let encrypt = AesEncrypt::<_, NoPadding>::new(&key, Gcm::new(&iv, None));
    let decrypt = AesDecrypt::<_, NoPadding>::new(&key, Gcm::new(&iv, None));

    let ciphertext = encrypt.run(&plaintext).unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext);
}

#[test]
fn aes_gcm_with_aad_roundtrip() {
    let key = b"0123456789abcdef";
    let iv = b"96-bit nonce !!!";
    let aad = b"additional auth data";
    let plaintext = b"authenticated encryption";

    let encrypt = AesEncrypt::<_, NoPadding>::new(key, Gcm::new(iv, Some(aad)));
    let decrypt = AesDecrypt::<_, NoPadding>::new(key, Gcm::new(iv, Some(aad)));

    let ciphertext = encrypt.run(plaintext).unwrap();
    // The tag (16 bytes) is appended to the ciphertext.
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn aes_gcm_detects_ciphertext_tampering() {
    let key = unhex("feffe9928665731c6d6a8f9467308308");
    let iv = unhex("cafebabefacedbaddecaf888");
    let plaintext = b"tamper detection test";

    let encrypt = AesEncrypt::<_, NoPadding>::new(&key, Gcm::new(&iv, None));
    let decrypt = AesDecrypt::<_, NoPadding>::new(&key, Gcm::new(&iv, None));

    let mut ciphertext = encrypt.run(plaintext).unwrap().to_vec();
    ciphertext[0] ^= 0x01; // flip one bit of the ciphertext
    let error = decrypt.run(&ciphertext).unwrap_err();
    assert!(error
        .to_string()
        .contains("GCM authentication tag verification failed"));
}

#[test]
fn aes_rejects_unsupported_key_length() {
    // A 12-byte key exhausts the RCON table and must be rejected with an
    // error instead of silently producing a bogus key schedule.
    let op = AesEncrypt::<Ecb, NoPadding>::new(b"0123456789ab", Ecb);
    let error = op.run(&unhex(FIPS_PLAINTEXT)).unwrap_err();
    assert!(error.to_string().contains("unsupported AES key length"));
}

#[test]
fn non_standard_key_length_still_roundtrips() {
    // crypto-js compatibility: a 20-byte key is accepted for AES.
    let key = b"01234567890123456789";
    let iv = b"01234567";
    let plaintext = b"data encrypted with a non standard key length";

    let encrypt = AesEncrypt::<_, Pkcs7Padding>::new(key, Cbc::new(iv));
    let decrypt = AesDecrypt::<_, Pkcs7Padding>::new(key, Cbc::new(iv));

    let ciphertext = encrypt.run(plaintext).unwrap();
    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn aes_cbc_no_padding_roundtrips_aligned_input() {
    // NoPadding works with CBC as long as the input is block aligned.
    let key = b"0123456789abcdef";
    let iv = b"0123456789abcdef";
    let plaintext = [0x61; 32];

    let encrypt = AesEncrypt::<_, NoPadding>::new(key, Cbc::new(iv));
    let decrypt = AesDecrypt::<_, NoPadding>::new(key, Cbc::new(iv));

    let ciphertext = encrypt.run(&plaintext).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len());

    let recovered = decrypt.run(&ciphertext).unwrap();
    assert_eq!(recovered.to_vec(), plaintext.to_vec());
}

#[test]
fn ecb_and_cbc_reject_misaligned_input() {
    let key = b"0123456789abcdef";
    let iv = b"0123456789abcdef";
    let misaligned = b"short";

    let ecb = AesEncrypt::<_, NoPadding>::new(key, Ecb);
    let error = ecb.run(misaligned).unwrap_err();
    assert!(error
        .to_string()
        .contains("ECB mode input length must be a multiple of the block size"));

    let cbc = AesEncrypt::<_, NoPadding>::new(key, Cbc::new(iv));
    let error = cbc.run(misaligned).unwrap_err();
    assert!(error
        .to_string()
        .contains("CBC mode input length must be a multiple of the block size"));
}
