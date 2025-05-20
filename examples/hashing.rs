use crypto::base64::ToBase64;
use crypto::bytes::Bytes;
use crypto::hmac::Hmac;
use crypto::md5::Md5;
use crypto::recipe::Recipe;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use crypto::sm3::Sm3;
use crypto::types::Result;

fn main() -> Result<()> {
    // MD5
    println!("---- ---- MD5 ---- ----");
    //let md5_input = Bytes::default();
    let md5_input = Bytes::new(b"123456".as_ref());
    let recipe1 = Recipe::new(vec![Box::new(Md5)]);
    let md5_output = recipe1.bake(&md5_input)?;
    println!("{:?}", md5_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // SHA1
    println!("---- ---- SHA1 ---- ----");
    let sha1_input = Bytes::new("123456".as_bytes());
    let sha1_op = Sha1::default();
    //println!("{:?}", sha1_op);
    let recipe2 = Recipe::new(vec![Box::new(sha1_op)]);
    let sha1_output = recipe2.bake(&sha1_input)?;
    println!("{:?}", sha1_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // SHA2
    println!("---- ---- SHA2 ---- ----");
    let sha256_input = Bytes::default();
    let recipe3 = Recipe::new(vec![Box::new(Sha256)]);
    let sha256_output = recipe3.bake(&sha256_input)?;
    println!("{:?}", sha256_output);
    let sha512_input = Bytes::new("123456".as_bytes());
    let recipe4 = Recipe::new(vec![Box::new(Sha512)]);
    let sha512_output = recipe4.bake(&sha512_input)?;
    println!("{:?}", sha512_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // HMAC
    println!("---- ---- HMAC ---- ----");
    let hmac_input = Bytes::new("Hello, world!".as_bytes());
    let hmac_key = Bytes::new("123456".as_bytes());
    let hmac_op = Hmac::<Sha512>::new(&hmac_key);
    //println!("{:?}", hmac_op);
    let to_base64_op = ToBase64::default();
    let recipe5 = Recipe::new(vec![Box::new(hmac_op), Box::new(to_base64_op)]);
    let hmac_output = recipe5.bake(&hmac_input)?;
    println!("{}", hmac_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // SM3
    println!("---- ---- SM3 ---- ----");
    let sm3_input = Bytes::new("12233344445555500000".as_bytes());
    let recipe6 = Recipe::new(vec![Box::new(Sm3)]);
    let sm3_output = recipe6.bake(&sm3_input)?;
    println!("{:?}", sm3_output);

    let sm3_hmac_input = Bytes::new("3334444".as_bytes());
    let sm3_hmac_key = Bytes::new(vec![
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);
    let sm3_hmac_op = Hmac::<Sm3>::new(&sm3_hmac_key);
    let recipe7 = Recipe::new(vec![Box::new(sm3_hmac_op)]);
    let sm3_hmac_output = recipe7.bake(&sm3_hmac_input)?;
    println!("{:?}", sm3_hmac_output);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
