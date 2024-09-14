use std::str::FromStr;

use crypto::aes::{AesDecrypt, AesEncrypt};
use crypto::base64::{FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::des::{DesDecrypt, DesEncrypt, TripleDesDecrypt, TripleDesEncrypt};
use crypto::mode::{Cbc, Ecb};
use crypto::padding::{Pkcs7Padding, ZeroPadding};
use crypto::rc4::Rc4;
use crypto::recipe::Recipe;
use crypto::types::Result;

fn main() -> Result<()> {
    // RC4
    println!("---- ---- RC4 ---- ----");
    let rc4_input = Bytes::from_str("Hello")?;
    //let rc4_op = RC4::default();
    let rc4_op = Rc4::new(&Bytes::from_str("CRYPTO")?);
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

    let des_ecb_key = Bytes::from_str("12345678")?;
    let des_ecb_encrypt = DesEncrypt::<Ecb, ZeroPadding>::new(&des_ecb_key, Ecb);
    let recipe2 = Recipe::new(vec![
        Box::new(des_ecb_encrypt),
        Box::new(ToBase64::default()),
    ]);
    let des_ecb_encrypt_result = recipe2.bake(&des_input)?;
    println!("{}", des_ecb_encrypt_result);

    let des_ecb_decrypt = DesDecrypt::<_, ZeroPadding>::new(&des_ecb_key, Ecb);
    let recipe3 = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(des_ecb_decrypt),
    ]);
    let des_ecb_decrypt_result = recipe3.bake(&des_ecb_encrypt_result)?;
    println!("{}", des_ecb_decrypt_result);

    let des_cbc_key = Bytes::from_str("321")?;
    let des_cbc_iv = Bytes::from_str("123")?;
    let des_cbc_encrypt = DesEncrypt::<_, Pkcs7Padding>::new(&des_cbc_key, Cbc::new(&des_cbc_iv));
    let recipe4 = Recipe::new(vec![
        Box::new(des_cbc_encrypt),
        Box::new(ToBase64::default()),
    ]);
    let des_cbc_encrypt_result = recipe4.bake(&des_input)?;
    println!("{}", des_cbc_encrypt_result);

    let des_cbc_decrypt = DesDecrypt::<_, Pkcs7Padding>::new(&des_cbc_key, Cbc::new(&des_cbc_iv));
    let recipe5 = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(des_cbc_decrypt),
    ]);
    let des_cbc_decrypt_result = recipe5.bake(&des_cbc_encrypt_result)?;
    println!("{}", des_cbc_decrypt_result);

    let triple_des_key = Bytes::from_str("1234567887654321")?;
    let triple_des_iv = Bytes::from_str("00009999")?;
    let triple_des_encrypt =
        TripleDesEncrypt::<_, Pkcs7Padding>::new(&triple_des_key, Cbc::new(&triple_des_iv));
    let recipe6 = Recipe::new(vec![
        Box::new(triple_des_encrypt),
        Box::new(ToBase64::default()),
    ]);
    let triple_des_encrypt_result = recipe6.bake(&des_input)?;
    println!("{}", triple_des_encrypt_result);

    let triple_des_decrypt =
        TripleDesDecrypt::<_, Pkcs7Padding>::new(&triple_des_key, Cbc::new(&triple_des_iv));
    let recipe7 = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(triple_des_decrypt),
    ]);
    let triple_des_decrypt_result = recipe7.bake(&triple_des_encrypt_result)?;
    println!("{}", triple_des_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    // AES
    println!("---- ---- AES ---- ----");
    let aes_input = Bytes::from_str("FooBar")?;
    let aes_key = Bytes::from_str("01234567890123456789")?;
    let aes_iv = Bytes::from_str("01234567")?;
    let aes_op = AesEncrypt::<_, Pkcs7Padding>::new(&aes_key, Cbc::new(&aes_iv));
    let recipe8 = Recipe::new(vec![Box::new(aes_op), Box::new(ToBase64::default())]);
    let aes_output = recipe8.bake(&aes_input)?;
    println!("{:}", aes_output);

    let aes_decrypt = AesDecrypt::<_, Pkcs7Padding>::new(&aes_key, Cbc::new(&aes_iv));
    let recipe9 = Recipe::new(vec![Box::new(FromBase64::default()), Box::new(aes_decrypt)]);
    let aes_decrypt_result = recipe9.bake(&aes_output)?;
    println!("{:}", aes_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
