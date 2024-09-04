use crypto::bytes::Bytes;
use crypto::md5::MD5;
use crypto::recipe::Recipe;
use crypto::sha1::SHA1;

fn main() -> anyhow::Result<()> {
    // MD5
    //let md5_input = Bytes::default();
    let md5_input = Bytes::from("123456");
    let md5_op = MD5 {};
    let recipe1 = Recipe::new(vec![md5_op]);
    let md5_output = recipe1.bake(md5_input)?;
    println!("{:?}", md5_output);

    // SHA1
    let sha1_input = Bytes::from("123456");
    let sha1_op = SHA1::default();
    let recipe2 = Recipe::new(vec![sha1_op]);
    let sha1_output = recipe2.bake(sha1_input)?;
    println!("{:?}", sha1_output);
    Ok(())
}
