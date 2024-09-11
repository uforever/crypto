use std::str::FromStr;

use crypto::bytes::Bytes;
use crypto::enums::{BlockSize, Endian};
use crypto::padding::{BitPadding, Padding as _};
use crypto::types::Result;

fn main() -> Result<()> {
    // Bit Padding
    println!("---- ---- Bit Padding ---- ----");
    let bit_padding_input = Bytes::from_str("123456")?;
    let bit_padding_1 = BitPadding::new(BlockSize::Bytes32, Endian::Big);
    let bit_padding_2 = BitPadding::new(BlockSize::Bytes128, Endian::Little);
    let result1 = bit_padding_1.pad(&bit_padding_input);
    println!("{:?}", result1);
    let result2 = bit_padding_2.pad(&result1);
    println!("{:?}", result2);
    let result3 = bit_padding_2.unpad(&result2);
    println!("{:?}", result3);
    let result4 = bit_padding_1.unpad(&result3);
    println!("{:?}", result4);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
