use crypto::bytes::Bytes;
use crypto::enums::{BlockSize, Endian};
use crypto::padding::{BitPadding, Padding as _, Pkcs7Padding, ZeroPadding};
use crypto::types::Result;

fn main() -> Result<()> {
    let padding_input = Bytes::new("123456".as_bytes());
    println!("{:?}", padding_input.as_ref());

    // Bit Padding
    println!("---- ---- Bit Padding ---- ----");
    let bit_padding_1 = BitPadding::new(BlockSize::Bytes32, Endian::Big);
    let bit_padding_2 = BitPadding::new(BlockSize::Bytes128, Endian::Little);
    let result1 = bit_padding_1.pad(&padding_input);
    println!("{:?}", result1);
    let result2 = bit_padding_2.pad(&result1);
    println!("{:?}", result2);
    let result3 = bit_padding_2.unpad(&result2);
    println!("{:?}", result3);
    let result4 = bit_padding_1.unpad(&result3);
    println!("{:?}", result4);
    println!("---- ---- ---- ---- ----");
    println!();

    // PKCS#7 Padding
    println!("---- ---- PKCS#7 Padding ---- ----");
    let pkcs7_padding = Pkcs7Padding::new(BlockSize::Bytes16);
    let result5 = pkcs7_padding.pad(&padding_input);
    println!("{:?}", result5);
    let result6 = pkcs7_padding.unpad(&result5);
    println!("{:?}", result6);
    println!("---- ---- ----");
    println!();

    // Zero Padding
    println!("---- ---- Zero Padding ---- ----");
    let zero_padding = ZeroPadding::new(BlockSize::Bytes16);
    let result7 = zero_padding.pad(&padding_input);
    println!("{:?}", result7);
    let result8 = zero_padding.unpad(&result7);
    println!("{:?}", result8);
    println!("---- ---- ----");
    println!();

    Ok(())
}
