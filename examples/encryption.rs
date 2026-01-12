use crypto::aes::{AesDecrypt, AesEncrypt};
use crypto::base64::{FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::des::{DesDecrypt, DesEncrypt, TripleDesDecrypt, TripleDesEncrypt};
use crypto::hex::{FromHex, ToHex};
use crypto::mode::{Cbc, Cfb, Ctr, Ecb, Gcm, Ofb};
use crypto::padding::{NoPadding, Pkcs7Padding, ZeroPadding};
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
    let des_input = Bytes::new(b"Hello, World!Hello, World!Hello, World!".as_ref());

    let des_ecb_key = Bytes::new("12345678".as_bytes());
    let des_ecb_encrypt = DesEncrypt::<Ecb, ZeroPadding>::new(&des_ecb_key, Ecb);
    let recipe2 = Recipe::new(vec![
        Box::new(des_ecb_encrypt),
        Box::new(ToBase64::default()),
    ]);
    let des_ecb_encrypt_result = recipe2.bake(&des_input)?;
    println!("{}", des_ecb_encrypt_result);

    let des_ecb_decrypt = DesDecrypt::<Ecb, ZeroPadding>::new(&des_ecb_key, Ecb);
    let recipe3 = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(des_ecb_decrypt),
    ]);
    let des_ecb_decrypt_result = recipe3.bake(&des_ecb_encrypt_result)?;
    println!("{}", des_ecb_decrypt_result);

    let des_cfb_iv = Bytes::new("87654321".as_bytes());
    let des_cfb_encrypt = DesEncrypt::<_, NoPadding>::new(&des_ecb_key, Cfb::new(&des_cfb_iv));
    let recipe_cfbencrypt =
        Recipe::new(vec![Box::new(des_cfb_encrypt), Box::new(ToHex::default())]);
    let des_cfb_encrypt_result = recipe_cfbencrypt.bake(&des_input)?;
    println!("{}", des_cfb_encrypt_result);
    let des_cfb_decrypt = DesDecrypt::<_, NoPadding>::new(&des_ecb_key, Cfb::new(&des_cfb_iv));
    let recipe_cfbdecrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(des_cfb_decrypt),
    ]);
    let des_cfb_decrypt_result = recipe_cfbdecrypt.bake(&des_cfb_encrypt_result)?;
    println!("{}", des_cfb_decrypt_result);

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

    let triple_des_ofb_encrypt =
        TripleDesEncrypt::<_, NoPadding>::new(&triple_des_key, Ofb::new(&triple_des_iv));
    let recipe_ofb_3des_encrypt = Recipe::new(vec![
        Box::new(triple_des_ofb_encrypt),
        Box::new(ToHex::default()),
    ]);
    let triple_des_ofb_encrypt_result = recipe_ofb_3des_encrypt.bake(&des_input)?;
    println!("{}", triple_des_ofb_encrypt_result);
    let triple_des_ofb_decrypt =
        TripleDesDecrypt::<_, NoPadding>::new(&triple_des_key, Ofb::new(&triple_des_iv));
    let recipe_ofb_3des_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(triple_des_ofb_decrypt),
    ]);
    let triple_des_ofb_decrypt_result =
        recipe_ofb_3des_decrypt.bake(&triple_des_ofb_encrypt_result)?;
    println!("{}", triple_des_ofb_decrypt_result);

    let triple_des_ctr_encrypt =
        TripleDesEncrypt::<_, NoPadding>::new(&triple_des_key, Ctr::new(&triple_des_iv));
    let recipe_ctr_3des_encrypt = Recipe::new(vec![
        Box::new(triple_des_ctr_encrypt),
        Box::new(ToHex::default()),
    ]);
    let triple_des_ctr_encrypt_result = recipe_ctr_3des_encrypt.bake(&des_input)?;
    println!("{}", triple_des_ctr_encrypt_result);
    let triple_des_ctr_decrypt =
        TripleDesDecrypt::<_, NoPadding>::new(&triple_des_key, Ctr::new(&triple_des_iv));
    let recipe_ctr_3des_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(triple_des_ctr_decrypt),
    ]);
    let triple_des_ctr_decrypt_result =
        recipe_ctr_3des_decrypt.bake(&triple_des_ctr_encrypt_result)?;
    println!("{}", triple_des_ctr_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    // AES
    println!("---- ---- AES ---- ----");
    let aes_input = Bytes::new(
        "FooBar Lorem ipsum dolor sit amet ex cupidatat culpa ullamco et eiusmod eu".as_bytes(),
    );
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

    let aes_cfb_key = Bytes::new("FooBar Lorem ipsum dolor sit ame".as_bytes());
    let aes_cfb_iv = Bytes::new("co et eiusmod eu".as_bytes());
    let aes_cfb_encrypt = AesEncrypt::<_, NoPadding>::new(&aes_cfb_key, Cfb::new(&aes_cfb_iv));
    let recipe_cfb_aes = Recipe::new(vec![Box::new(aes_cfb_encrypt), Box::new(ToHex::default())]);
    let aes_cfb_output = recipe_cfb_aes.bake(&aes_input)?;
    println!("{}", aes_cfb_output);
    let aes_cfb_decrypt = AesDecrypt::<_, NoPadding>::new(&aes_cfb_key, Cfb::new(&aes_cfb_iv));
    let recipe_cfb_aes_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(aes_cfb_decrypt),
    ]);
    let aes_cfb_decrypt_result = recipe_cfb_aes_decrypt.bake(&aes_cfb_output)?;
    println!("{}", aes_cfb_decrypt_result);

    let aes_ctr_encrypt = AesEncrypt::<_, NoPadding>::new(&aes_cfb_key, Ctr::new(&aes_cfb_iv));
    let recipe_ctr_aes = Recipe::new(vec![Box::new(aes_ctr_encrypt), Box::new(ToHex::default())]);
    let aes_ctr_output = recipe_ctr_aes.bake(&aes_input)?;
    println!("{}", aes_ctr_output);
    let aes_ctr_decrypt = AesDecrypt::<_, NoPadding>::new(&aes_cfb_key, Ctr::new(&aes_cfb_iv));
    let recipe_ctr_aes_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(aes_ctr_decrypt),
    ]);
    let aes_ctr_decrypt_result = recipe_ctr_aes_decrypt.bake(&aes_ctr_output)?;
    println!("{}", aes_ctr_decrypt_result);

    let aes_gcm_iv = Bytes::new("co et eiusmod euABCD".as_bytes());
    let aes_gcm_aad = Bytes::new(b"Additional Auth Data".as_ref());
    let aes_gcm_encrypt =
        AesEncrypt::<_, NoPadding>::new(&aes_cfb_key, Gcm::new(&aes_gcm_iv, Some(&aes_gcm_aad)));
    let recipe_gcm_aes = Recipe::new(vec![Box::new(aes_gcm_encrypt), Box::new(ToHex::default())]);
    let aes_gcm_output = recipe_gcm_aes.bake(&aes_input)?;
    println!("{}", aes_gcm_output);
    let aes_gcm_decrypt =
        AesDecrypt::<_, NoPadding>::new(&aes_cfb_key, Gcm::new(&aes_gcm_iv, Some(&aes_gcm_aad)));
    let recipe_gcm_aes_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(aes_gcm_decrypt),
    ]);

    /*
    let mut fake_gcm_output = aes_gcm_output.to_vec();
    // 篡改最后一个字节，模拟标签验证失败
    let last_index = fake_gcm_output.len() - 1;
    fake_gcm_output[last_index] ^= 0x01;
    let aes_gcm_decrypt_result = recipe_gcm_aes_decrypt.bake(&fake_gcm_output)?;
    */
    let aes_gcm_decrypt_result = recipe_gcm_aes_decrypt.bake(&aes_gcm_output)?;
    println!("{}", aes_gcm_decrypt_result);
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

    let sm4_ofb_input = Bytes::new(b"Hello, SM4 More Mode!Hello, SM4 More Mode!".as_ref());
    let sm4_ofb_key = Bytes::new(b"Sixteen byte key".as_ref());
    let sm4_ofb_iv = Bytes::new(b"InitialVector123".as_ref());
    let sm4_ofb_encrypt = Sm4Encrypt::<_, NoPadding>::new(&sm4_ofb_key, Ofb::new(&sm4_ofb_iv));
    let recipe_sm4_ofb = Recipe::new(vec![Box::new(sm4_ofb_encrypt), Box::new(ToHex::default())]);
    let sm4_ofb_output = recipe_sm4_ofb.bake(&sm4_ofb_input)?;
    println!("{}", sm4_ofb_output);
    let sm4_ofb_decrypt = Sm4Decrypt::<_, NoPadding>::new(&sm4_ofb_key, Ofb::new(&sm4_ofb_iv));
    let recipe_sm4_ofb_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(sm4_ofb_decrypt),
    ]);
    let sm4_ofb_decrypt_result = recipe_sm4_ofb_decrypt.bake(&sm4_ofb_output)?;
    println!("{}", sm4_ofb_decrypt_result);

    let sm4_ctr_iv = Bytes::new(
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ]
        .as_ref(),
    );
    let sm4_ctr_encrypt = Sm4Encrypt::<_, NoPadding>::new(&sm4_ofb_key, Ctr::new(&sm4_ctr_iv));
    let recipe_sm4_ctr = Recipe::new(vec![Box::new(sm4_ctr_encrypt), Box::new(ToHex::default())]);
    let sm4_ctr_output = recipe_sm4_ctr.bake(&sm4_ofb_input)?;
    println!("{}", sm4_ctr_output);
    let sm4_ctr_decrypt = Sm4Decrypt::<_, NoPadding>::new(&sm4_ofb_key, Ctr::new(&sm4_ctr_iv));
    let recipe_sm4_ctr_decrypt = Recipe::new(vec![
        Box::new(FromHex::default()),
        Box::new(sm4_ctr_decrypt),
    ]);
    let sm4_ctr_decrypt_result = recipe_sm4_ctr_decrypt.bake(&sm4_ctr_output)?;
    println!("{}", sm4_ctr_decrypt_result);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
