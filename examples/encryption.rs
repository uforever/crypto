use crypto::base64::ToBase64;
use crypto::bytes::Bytes;
use crypto::des::DesEncrypt;
use crypto::padding::Pkcs7Padding;
use crypto::rc4::Rc4;
use crypto::recipe::Recipe;
use crypto::types::Result;
use std::str::FromStr;

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
    let des_op = DesEncrypt::<Pkcs7Padding>::new(Bytes::from_str("12345678")?);
    let to_base64_op = ToBase64::default();
    let recipe2 = Recipe::new(vec![Box::new(des_op), Box::new(to_base64_op)]);
    let des_output = recipe2.bake(&des_input)?;
    println!("{}", des_output);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
