use crypto::aes::{AesDecrypt, AesEncrypt};
use crypto::base64::{FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::des::{DesDecrypt, DesEncrypt, TripleDesDecrypt, TripleDesEncrypt};
use crypto::mode::{Cbc, Ecb};
use crypto::padding::{Pkcs7Padding, ZeroPadding};
use crypto::rc4::Rc4;
use crypto::recipe::Recipe;
use crypto::sm4::{Sm4Decrypt, Sm4Encrypt};
use crypto::tea::{XxteaDecrypt, XxteaEncrypt};
use crypto::types::Result;

fn main() -> Result<()> {
    // RC4
    println!("---- ---- RC4 ---- ----");
    let rc4_input = Bytes::new(b"Hello".as_ref());
    //let rc4_op = RC4::default();
    let rc4_op = Rc4::new(&Bytes::new("CRYPTO".as_bytes()));
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
    let des_input = Bytes::new(b"Hello, World!".as_ref());

    let des_ecb_key = Bytes::new("12345678".as_bytes());
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

    let des_cbc_key = Bytes::new("321".as_bytes());
    let des_cbc_iv = Bytes::new("123".as_bytes());
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

    let triple_des_key = Bytes::new("1234567887654321".as_bytes());
    let triple_des_iv = Bytes::new("00009999".as_bytes());
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
    let aes_input = Bytes::new("FooBar".as_bytes());
    let aes_key = Bytes::new("01234567890123456789".as_bytes());
    let aes_iv = Bytes::new("01234567".as_bytes());
    let aes_op = AesEncrypt::<_, Pkcs7Padding>::new(&aes_key, Cbc::new(&aes_iv));
    let recipe8 = Recipe::new(vec![Box::new(aes_op), Box::new(ToBase64::default())]);
    let aes_output = recipe8.bake(&aes_input)?;
    println!("{}", aes_output);

    let aes_decrypt = AesDecrypt::<_, Pkcs7Padding>::new(&aes_key, Cbc::new(&aes_iv));
    let recipe9 = Recipe::new(vec![Box::new(FromBase64::default()), Box::new(aes_decrypt)]);
    let aes_decrypt_result = recipe9.bake(&aes_output)?;
    println!("{}", aes_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    // TEA
    println!("---- ---- TEA ---- ----");
    let xxtea_input = Bytes::new([1, 0, 0, 0, 2, 0, 0].as_ref());
    let xxtea_key = Bytes::new([2, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0].as_ref());
    let xxtea_encrypt = XxteaEncrypt::new(&xxtea_key, false);
    let recipe10 = Recipe::new(vec![Box::new(xxtea_encrypt)]);
    let xxtea_output = recipe10.bake(&xxtea_input)?;
    println!("{}", xxtea_output);

    let xxtea_decrypt = XxteaDecrypt::new(&xxtea_key, false);
    let recipe11 = Recipe::new(vec![Box::new(xxtea_decrypt)]);
    let xxtea_decrypt_result = recipe11.bake(&xxtea_output)?;
    println!("{:?}", xxtea_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    // SM4
    println!("---- ---- SM4 ---- ----");
    let sm4_input = Bytes::new(
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08,
        ]
        .as_ref(),
    );
    let sm4_key = Bytes::new(
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
        .as_ref(),
    );
    let sm4_iv = Bytes::new(
        [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ]
        .as_ref(),
    );

    let sm4_encrypt = Sm4Encrypt::<_, Pkcs7Padding>::new(&sm4_key, Cbc::new(&sm4_iv));
    let recipe12 = Recipe::new(vec![Box::new(sm4_encrypt)]);
    let sm4_output = recipe12.bake(&sm4_input)?;
    println!("{}", sm4_output);

    let sm4_decrypt = Sm4Decrypt::<_, Pkcs7Padding>::new(&sm4_key, Cbc::new(&sm4_iv));
    let recipe13 = Recipe::new(vec![Box::new(sm4_decrypt)]);
    let sm4_decrypt_result = recipe13.bake(&sm4_output)?;
    println!("{:?}", sm4_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
