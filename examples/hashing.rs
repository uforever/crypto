use crypto::bytes::Bytes;
use crypto::md5::MD5;
use crypto::recipe::Recipe;
use crypto::sha1::SHA1;
use crypto::sha256::SHA256;
use crypto::sha512::SHA512;

fn main() -> anyhow::Result<()> {
    // MD5
    //let md5_input = Bytes::default();
    let md5_input = Bytes::from("123456");
    let recipe1 = Recipe::new(vec![MD5]);
    let md5_output = recipe1.bake(md5_input)?;
    println!("{:?}", md5_output);

    // SHA1
    let sha1_input = Bytes::from("123456");
    let sha1_op = SHA1::default();
    let recipe2 = Recipe::new(vec![sha1_op]);
    let sha1_output = recipe2.bake(sha1_input)?;
    println!("{:?}", sha1_output);

    // SHA2
    let sha256_input = Bytes::default();
    let recipe3 = Recipe::new(vec![SHA256]);
    let sha256_output = recipe3.bake(sha256_input)?;
    println!("{:?}", sha256_output);
    let sha512_input = Bytes::from("123456");
    let recipe4 = Recipe::new(vec![SHA512]);
    let sha512_output = recipe4.bake(sha512_input)?;
    println!("{:?}", sha512_output);

    Ok(())
}
