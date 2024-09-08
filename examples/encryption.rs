use crypto::bytes::Bytes;
use crypto::rc4::RC4;
use crypto::recipe::Recipe;
use crypto::types::Result;

fn main() -> Result<()> {
    // RC4
    println!("---- ---- RC4 ---- ----");
    let rc4_input = Bytes::from("Hello");
    //let rc4_op = RC4::default();
    let rc4_op = RC4::new(Bytes::from("CRYPTO"));
    //println!("{:?}", rc4_op);
    let recipe1 = Recipe::new(vec![rc4_op]);
    let rc4_output1 = recipe1.bake(&rc4_input)?;
    println!("{:?}", rc4_output1);
    let rc4_output2 = recipe1.bake(&rc4_output1)?;
    println!("{}", rc4_output2);
    println!("---- ---- ---- ---- ----");
    println!();

    Ok(())
}
