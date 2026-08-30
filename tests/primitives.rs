//! Unit-style tests for the `Bytes` / `Bits` primitives.

use crypto::bits::Bits;
use crypto::bytes::Bytes;
use crypto::enums::Bit::{One, Zero};

#[test]
fn bytes_debug_is_lowercase_hex() {
    let bytes = Bytes::new([0x0f, 0xa0, 0xff].as_ref());
    assert_eq!(format!("{bytes:?}"), "0fa0ff");
}

#[test]
fn bytes_display_prefers_utf8_and_falls_back_to_hex() {
    let text = Bytes::new(b"Hello".as_ref());
    assert_eq!(format!("{text}"), "Hello");

    // 0xff is never valid in UTF-8, so Display falls back to hex. (Note:
    // some non-ASCII byte pairs such as [0xde, 0xad] are valid UTF-8 and
    // render as their code point instead.)
    let binary = Bytes::new([0xff, 0xfe].as_ref());
    assert_eq!(format!("{binary}"), "fffe");
}

#[test]
fn bytes_xor_is_cyclic_over_the_right_hand_side() {
    let data = Bytes::new([0x01, 0x02, 0x03, 0x04].as_ref());
    let key = Bytes::new([0x10].as_ref());

    assert_eq!(format!("{:?}", data.xor(&key)), "11121314");
}

#[test]
fn bytes_inc_wraps_around() {
    let mut bytes = Bytes::new([0xff, 0xff].as_ref());
    bytes.inc();
    assert_eq!(format!("{bytes:?}"), "0000");

    let mut bytes = Bytes::new([0x00, 0x0f].as_ref());
    bytes.inc();
    assert_eq!(format!("{bytes:?}"), "0010");
}

#[test]
fn bytes_inc32_only_touches_the_last_four_bytes() {
    let mut data = vec![0x01; 16];
    data[12..].fill(0xff);

    let mut bytes = Bytes::new(data);
    bytes.inc32();

    assert_eq!(format!("{bytes:?}"), "01010101010101010101010100000000");
}

#[test]
fn bytes_align_pads_on_the_left() {
    let bytes = Bytes::new([0x01].as_ref());
    assert_eq!(format!("{:?}", bytes.align(4, 0x00)), "00000001");

    // Existing bytes are preserved when the target length is reached.
    assert_eq!(format!("{:?}", bytes.align(1, 0x00)), "01");
}

#[test]
fn bytes_permutation_selects_by_index_and_defaults_to_zero() {
    let bytes = Bytes::new([0x0a, 0x0b, 0x0c].as_ref());
    assert_eq!(format!("{:?}", bytes.permutation(&[2, 0, 1])), "0c0a0b");
    // Out-of-range indexes yield zero bytes.
    assert_eq!(format!("{:?}", bytes.permutation(&[0, 9])), "0a00");
}

#[test]
fn bits_from_bytes_expands_msb_first() {
    let bits = Bits::from(&[0b1010_0001][..]);
    assert_eq!(bits.len(), 8);
    let expected = [One, Zero, One, Zero, Zero, Zero, Zero, One];
    assert!(bits.iter().copied().eq(expected));
}

#[test]
fn bits_to_usize_reads_big_endian() {
    let bits = Bits::from(&[0xff][..]);
    assert_eq!(bits.to_usize(), 0xff);

    let empty = Bits::default();
    assert_eq!(empty.to_usize(), 0);
}

#[test]
fn bits_bytes_roundtrip() {
    let data = [0x00, 0x7f, 0x80, 0xff];
    let bits = Bits::from(&data[..]);
    let bytes = bits.to_bytes();
    assert_eq!(bytes.to_vec(), data.to_vec());
}

#[test]
fn bits_inc_wraps_around() {
    let mut bits = Bits::from(&[0xff][..]);
    bits.inc();
    assert!(bits.iter().all(|&b| b == Zero));
}

#[test]
fn bits_align_pads_on_the_left() {
    let bits = Bits::from(&[0x01][..]); // 00000001
    let aligned = bits.align(16, Zero);

    assert_eq!(aligned.len(), 16);
    assert_eq!(aligned.to_usize(), 1);
}

#[test]
fn bits_xor_is_cyclic() {
    let a = Bits::from(&[0b1111_0000][..]);
    let b = Bits::from(&[0b0000_1111][..]);

    let xored = a.xor(&b);
    assert_eq!(xored.to_usize(), 0xff);
}

#[test]
fn bytes_to_bits_is_equivalent_to_bits_from_bytes() {
    let data = [0x12, 0x34, 0x56];
    let via_bytes = Bytes::new(&data[..]).to_bits();
    let direct = Bits::from(&data[..]);

    assert!(via_bytes.iter().copied().eq(direct.iter().copied()));
}
