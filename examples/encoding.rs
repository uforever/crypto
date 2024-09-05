use std::borrow::Cow;

use crypto::base64::{alphabet, FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::hex::{FromHex, ToHex};
use crypto::recipe::Recipe;

fn main() -> anyhow::Result<()> {
    // bytes
    println!("---- ---- Bytes ---- ----");
    let arr_data: &[u8] = &[0x48, 0x65, 0x6c, 0x6c, 0x6f];
    let vec_data: Vec<u8> = vec![1, 2, 3, 4];
    let boxed_data: Box<[u8]> = Box::new([5, 6, 7, 8]);
    let cow_data: Cow<[u8]> = Cow::from(vec![9, 10, 11, 12]);

    let bytes1 = Bytes::new(arr_data);
    let bytes2 = Bytes::new(vec_data);
    let bytes3 = Bytes::new(boxed_data);
    let bytes4 = Bytes::new(cow_data);

    let string_data = String::from("foo");
    let str_data = "bar";

    let bytes5 = Bytes::from(string_data);
    let bytes6 = Bytes::from(str_data);
    let bytes7 = Bytes::default();

    println!("{}", bytes1);
    println!("{:?}", bytes2);
    println!("{:?}", bytes3);
    println!("{:?}", bytes4);
    println!("{}", bytes5);
    println!("{}", bytes6);
    println!("{}", bytes7);
    println!("---- ---- ---- ---- ----");
    println!();

    // hex
    println!("---- ---- Hex ---- ----");
    let from_hex_input = Bytes::from("0x48, 0x65, 0x6c, 0x6c, 0x6f");
    let from_hex_op = FromHex::new(", ", "0x");
    //println!("{:?}", from_hex_op);
    let recipe1 = Recipe::new(vec![from_hex_op]);
    let from_hex_output = recipe1.bake(from_hex_input)?;
    println!("{}", from_hex_output);

    let to_hex_input = Bytes::from("Hello");
    //let to_hex_op = ToHex::default();
    let to_hex_op = ToHex::new(" ", "\\x", true);
    //println!("{:?}", to_hex_op);
    let recipe2 = Recipe::new(vec![to_hex_op]);
    let to_hex_output = recipe2.bake(to_hex_input)?;
    println!("{}", to_hex_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // base64
    println!("---- ---- Base64 ---- ----");
    let from_base64_input = Bytes::from("SGVsbG8=");
    let from_base64_op = FromBase64 {
        strict_mode: true,
        ..Default::default()
    };
    //println!("{:?}", from_base64_op);
    //let from_base64_input = Bytes::from("5'9XE'm");
    //let from_base64_op = FromBase64::new(alphabet::BIN_HEX, false);
    let recipe4 = Recipe::new(vec![from_base64_op]);
    let from_base64_output = recipe4.bake(from_base64_input)?;
    println!("{}", from_base64_output);

    let to_base64_input = Bytes::from("Hello");
    //let to_base64_op = ToBase64::default();
    let to_base64_op = ToBase64::new(alphabet::BIN_HEX);
    //println!("{:?}", to_base64_op);
    let recipe3 = Recipe::new(vec![to_base64_op]);
    let to_base64_output = recipe3.bake(to_base64_input)?;
    println!("{}", to_base64_output);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
