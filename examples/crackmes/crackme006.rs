use crypto::bytes::Bytes;
use crypto::recipe::Recipe;
use crypto::tea::XxteaDecrypt;
use crypto::types::Result;

fn main() -> Result<()> {
    // read message.txt.enc as input
    let input_filename = "message.txt.enc";
    // write to passwd.txt
    let output_filename = "passwd.txt";
    let content = std::fs::read(input_filename)?;
    let input_bytes = Bytes::new(content);
    let xxtea_key = Bytes::new(
        [
            0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32,
            0x54, 0x76,
        ]
        .as_ref(),
    );
    let xxtea_decrypt = XxteaDecrypt::new(xxtea_key, false);
    let recipe = Recipe::new(vec![Box::new(xxtea_decrypt)]);
    let output_bytes = recipe.bake(&input_bytes)?;
    std::fs::write(output_filename, output_bytes.as_ref())?;

    Ok(())
}
