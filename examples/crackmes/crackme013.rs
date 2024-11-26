use std::env;

use crypto::aes::{
    inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows, sub_bytes,
};
use crypto::bytes::Bytes;
use crypto::hex::{FromHex, ToHex};
use crypto::recipe::Recipe;
use crypto::types::Result;

// 实现aesdec指令
fn aesdec(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = inv_shift_rows(state);
    let result = inv_sub_bytes(&result);

    // 注意这里并不是aesenc指令的逆操作
    // 下面两个操作的顺序和常规解密过程相反
    let result = inv_mix_columns(&result);
    result.xor(&Bytes::new(round_key))
}

// 实现aesdec指令的逆操作
fn inv_aesdec(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = Bytes::new(state).xor(&Bytes::new(round_key));
    let result = mix_columns(&result);
    let result = sub_bytes(&result);
    shift_rows(&result)
}

// 实现aesenc指令
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

    let to_hex_op = ToHex::default();
    let to_hex_recipe = Recipe::new(vec![Box::new(to_hex_op)]);
    let result_str = to_hex_recipe.bake(&result)?;
    println!("{}", result_str);

    Ok(())
}
