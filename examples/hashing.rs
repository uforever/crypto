use crypto::bytes::Bytes;
use crypto::hmac::Hmac;
use crypto::md5::Md5;
use crypto::recipe::Recipe;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use crypto::types::Result;
use std::str::FromStr;

fn main() -> Result<()> {
    // MD5
    println!("---- ---- MD5 ---- ----");
    //let md5_input = Bytes::default();
    let md5_input = Bytes::from_str("123456")?;
    let recipe1 = Recipe::new(vec![Md5]);
    let md5_output = recipe1.bake(&md5_input)?;
    println!("{:?}", md5_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // SHA1
    println!("---- ---- SHA1 ---- ----");
    let sha1_input = Bytes::from_str("123456")?;
    let sha1_op = Sha1::default();
    //println!("{:?}", sha1_op);
    let recipe2 = Recipe::new(vec![sha1_op]);
    let sha1_output = recipe2.bake(&sha1_input)?;
    println!("{:?}", sha1_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // SHA2
    println!("---- ---- SHA2 ---- ----");
    let sha256_input = Bytes::default();
    let recipe3 = Recipe::new(vec![Sha256]);
    let sha256_output = recipe3.bake(&sha256_input)?;
    println!("{:?}", sha256_output);
    let sha512_input = Bytes::from_str("123456")?;
    let recipe4 = Recipe::new(vec![Sha512]);
    let sha512_output = recipe4.bake(&sha512_input)?;
    println!("{:?}", sha512_output);
    println!("---- ---- ---- ---- ----");
    println!();

    // HMAC
    println!("---- ---- HMAC ---- ----");
    let hmac_input = Bytes::from_str("Hello, world!")?;
    let hmac_key = Bytes::from_str("5d939b5d53749fdead9f86bfff5f6f4bc831f4eb5b80f3f123a761f786f0e265296b0c6865233939c7610e271b45553ebf1b2a1bf7d38af6931161a82e64dad600")?;
    let hmac_op = Hmac::<Sha512>::new(hmac_key);
    //println!("{:?}", hmac_op);
    let recipe5 = Recipe::new(vec![hmac_op]);
    let hmac_output = recipe5.bake(&hmac_input)?;
    println!("{:?}", hmac_output);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
