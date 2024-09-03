use crypto::bytes::Bytes;
use crypto::md5::MD5;
use crypto::recipe::Recipe;

fn main() -> anyhow::Result<()> {
    // MD5
    //let md5_input = Bytes::from("Litt1eQ");
    let md5_input = Bytes::default();
    let md5_op = MD5 {};
    let recipe1 = Recipe::new(vec![md5_op]);
    let md5_output = recipe1.bake(md5_input)?;
    println!("{:?}", md5_output);

    Ok(())
}
