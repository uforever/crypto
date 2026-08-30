//! Round-trip and known-answer tests for the padding schemes.

use crypto::enums::{BlockSize, Endian};
use crypto::padding::{BitPadding, NoPadding, Padding, Pkcs7Padding, ZeroPadding};

#[test]
fn pkcs7_pads_a_full_block_for_aligned_input() {
    let padding = Pkcs7Padding::new(BlockSize::Bytes16);

    // Empty input -> one full block of 0x10.
    assert_eq!(padding.pad(b""), vec![0x10; 16]);
    // 16 bytes of input -> another full block of 0x10.
    assert_eq!(padding.pad(&[0x00; 16]).len(), 32);
}

#[test]
fn pkcs7_pad_length_matches_missing_bytes() {
    let padding = Pkcs7Padding::new(BlockSize::Bytes16);
    let data = [b'A'; 13];

    let padded = padding.pad(&data);
    assert_eq!(padded.len(), 16);
    assert_eq!(&padded[..13], &data);
    assert_eq!(&padded[13..], &[0x03; 3]);
}

#[test]
fn pkcs7_unpad_restores_the_original_data() {
    let padding = Pkcs7Padding::new(BlockSize::Bytes16);
    let padded = padding.pad(b"Hello, padding!");

    assert_eq!(padding.unpad(&padded).unwrap(), b"Hello, padding!");
}

#[test]
fn pkcs7_roundtrip_across_lengths() {
    let padding = Pkcs7Padding::new(BlockSize::Bytes16);

    for len in 0..=33usize {
        let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_add(1)).collect();
        let padded = padding.pad(&data);
        assert_eq!(
            padded.len(),
            (len / 16 + 1) * 16,
            "padded length mismatch for {len}"
        );
        assert_eq!(
            padding.unpad(&padded).unwrap(),
            data,
            "roundtrip failed for {len}"
        );
    }
}

#[test]
fn zero_padding_appends_zeros_to_the_block_boundary() {
    let padding = ZeroPadding::new(BlockSize::Bytes16);
    let padded = padding.pad(b"0123456789"); // 10 bytes

    assert_eq!(padded.len(), 16);
    assert_eq!(&padded[10..], &[0x00; 6]);
    assert_eq!(padding.unpad(&padded).unwrap(), b"0123456789");
}

#[test]
fn zero_padding_roundtrip_for_nonzero_ending_data() {
    let padding = ZeroPadding::new(BlockSize::Bytes16);

    // Zero padding is not reversible when the data itself ends in zeros;
    // verify the supported case where it does not.
    for len in 1..=32usize {
        let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(7).wrapping_add(1)).collect();
        let padded = padding.pad(&data);
        assert_eq!(
            padding.unpad(&padded).unwrap(),
            data,
            "roundtrip failed for {len}"
        );
    }
}

#[test]
fn no_padding_is_the_identity() {
    let padding = NoPadding::new(BlockSize::Bytes16);
    let data = b"unchanged";

    assert_eq!(padding.pad(data), data.to_vec());
    assert_eq!(padding.unpad(data).unwrap(), data.to_vec());
}

#[test]
fn bit_padding_matches_the_md5_layout() {
    // MD5-style padding: 64-byte blocks, big-endian bit length in the last
    // 8 bytes, 0x80 separator.
    let padding = BitPadding::new(BlockSize::Bytes64, Endian::Big);
    let padded = padding.pad(b"abc");

    assert_eq!(padded.len(), 64);
    assert_eq!(padded[0], b'a');
    assert_eq!(padded[3], 0x80);
    // "abc" is 3 bytes = 24 bits, matching the classic MD5("abc") padding.
    assert_eq!(&padded[56..], &24u64.to_be_bytes());
    assert_eq!(padding.unpad(&padded).unwrap(), b"abc");
}

#[test]
fn bit_padding_minimal_block() {
    // 56 bytes of input need one extra block: 56 + 0x80 + zeros + 8 > 64.
    let padding = BitPadding::new(BlockSize::Bytes64, Endian::Big);
    let padded = padding.pad(&[0x61; 56]);

    assert_eq!(padded.len(), 128);
    assert_eq!(padding.unpad(&padded).unwrap(), [0x61; 56]);
}

#[test]
fn bit_padding_roundtrip_little_endian() {
    let padding = BitPadding::new(BlockSize::Bytes16, Endian::Little);

    for len in 0..=17usize {
        let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_add(3)).collect();
        let padded = padding.pad(&data);
        assert_eq!(
            padded.len() % 16,
            0,
            "padded length must be a block multiple for {len}"
        );
        assert_eq!(
            padding.unpad(&padded).unwrap(),
            data,
            "roundtrip failed for {len}"
        );
    }
}

#[test]
fn pkcs7_unpad_rejects_invalid_padding() {
    let padding = Pkcs7Padding::new(BlockSize::Bytes16);

    // The final byte encodes the padding length, so it must be in 1..=16.
    let mut bad_range = vec![b'A'; 16];
    bad_range[15] = 0x00;
    assert!(padding.unpad(&bad_range).is_err());
    bad_range[15] = 0x11;
    assert!(padding.unpad(&bad_range).is_err());

    // Every padding byte must repeat the padding length.
    let mut inconsistent = vec![b'A'; 13];
    inconsistent.extend_from_slice(&[0x03, 0x03, 0x02]);
    assert!(padding.unpad(&inconsistent).is_err());
}
