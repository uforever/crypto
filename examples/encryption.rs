use std::str::FromStr;

use crypto::base64::{FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::des::{DesDecrypt, DesEncrypt};
use crypto::padding::Pkcs7Padding;
use crypto::rc4::Rc4;
use crypto::recipe::Recipe;
use crypto::types::Result;

fn main() -> Result<()> {
    // RC4
    println!("---- ---- RC4 ---- ----");
    let rc4_input = Bytes::from_str("Hello")?;
    //let rc4_op = RC4::default();
    let rc4_op = Rc4::new(Bytes::from_str("CRYPTO")?);
    //println!("{:?}", rc4_op);
    let recipe1 = Recipe::new(vec![Box::new(rc4_op)]);
    let rc4_output1 = recipe1.bake(&rc4_input)?;
    println!("{:?}", rc4_output1);
    let rc4_output2 = recipe1.bake(&rc4_output1)?;
    println!("{}", rc4_output2);
    println!("---- ---- ---- ---- ----");
    println!();

    // DES
    println!("---- ---- DES ---- ----");
    let des_input = Bytes::from_str("Hello, World!")?;
    //let des_op = DesEncrypt::new(Bytes::from("123"));
    let des_encrypt = DesEncrypt::<Pkcs7Padding>::new(Bytes::from_str("12345678")?);
    let to_base64_op = ToBase64::default();
    let recipe2 = Recipe::new(vec![Box::new(des_encrypt), Box::new(to_base64_op)]);
    let des_encrypt_result = recipe2.bake(&des_input)?;
    println!("{}", des_encrypt_result);

    let des_decrypt = DesDecrypt::<Pkcs7Padding>::new(Bytes::from_str("12345678")?);
    let from_base64_op = FromBase64::default();
    let recipe3 = Recipe::new(vec![Box::new(from_base64_op), Box::new(des_decrypt)]);
    let des_decrypt_result = recipe3.bake(&des_encrypt_result)?;
    println!("{}", des_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
