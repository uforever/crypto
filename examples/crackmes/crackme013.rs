use std::env;

use crypto::aes::{
    inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows, sub_bytes,
};
use crypto::bytes::Bytes;
use crypto::hex::FromHex;
use crypto::recipe::Recipe;
use crypto::types::Result;

// implements the aesdec instruction
fn aesdec(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = inv_shift_rows(state);
    let result = inv_sub_bytes(&result);

    // note: this is not the inverse of the aesenc instruction
    // the order of the following two operations is reversed compared with the usual decryption flow
    let result = inv_mix_columns(&result);
    result.xor(&Bytes::new(round_key))
}

// implements the inverse of the aesdec instruction
fn inv_aesdec(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = Bytes::new(state).xor(&Bytes::new(round_key));
    let result = mix_columns(&result);
    let result = sub_bytes(&result);
    shift_rows(&result)
}

// implements the aesenc instruction
fn aesenc(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = shift_rows(state);
    let result = sub_bytes(&result);
    let result = mix_columns(&result);
    result.xor(&Bytes::new(round_key))
}

fn inv_aesenc(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = Bytes::new(state).xor(&Bytes::new(round_key));
    let result = inv_mix_columns(&result);
    let result = inv_sub_bytes(&result);
    inv_shift_rows(&result)
}

// crackme013.exe inv_aesenc 195cc88ecb14338ec91429c224ed656d 39012176971dd0a8d0e9bfd1c4506fa1
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("len: {}", args.len());
        println!("Usage: {} <aes_instru> <state> <round_key>", args[0]);
        return Err("Invalid arguments".into());
    }

    let aes_instru = args[1].as_str();
    let state = Bytes::new(args[2].as_bytes());
    let round_key = Bytes::new(args[3].as_bytes());

    let from_hex_op = FromHex::default();
    let from_hex_recipe = Recipe::new(vec![Box::new(from_hex_op)]);
    let state_bytes = from_hex_recipe.bake(&state)?;
    let round_key_bytes = from_hex_recipe.bake(&round_key)?;

    let result = match aes_instru {
        "aesdec" => aesdec(&state_bytes, &round_key_bytes),
        "inv_aesdec" => inv_aesdec(&state_bytes, &round_key_bytes),
        "aesenc" => aesenc(&state_bytes, &round_key_bytes),
        "inv_aesenc" => inv_aesenc(&state_bytes, &round_key_bytes),
        _ => return Err("Invalid aes_instru".into()),
    };

    println!("{:?}", result);

    Ok(())
}
