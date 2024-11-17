use std::io::{self, Write};

use crypto::bytes::Bytes;
use crypto::enums::Case;
use crypto::hex::ToHex;
use crypto::recipe::Recipe;
use crypto::rot13::Rot13;
use crypto::types::Result;

fn main() -> Result<()> {
    print!("Input name: ");
    io::stdout().flush()?;

    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username_bytes = Bytes::new(username.trim().as_bytes());
    let username_len = username_bytes.len();

    // 获取输入长度len 作为循环变量u32的从初始值
    // 循环len次 每次 * 0x19660D + 0x3C6EF35F 取后32位 溢出的部分忽略
    // mod 0x5E 后 再加 0x21
    let mut reg_value: u32 = username_len as u32;
    let mut result1 = vec![];
    for _ in 0..username_len {
        reg_value = reg_value.wrapping_mul(0x19660D).wrapping_add(0x3C6EF35F); // 溢出的部分忽略掉
        result1.push((reg_value % 0x5E) as u8 + 0x21);
    }

    // 这时得到一个ASCII字节序列
    // 进行ToHex变换
    // 再进行一次凯撒密码 位移为12
    let to_hex_op = ToHex::new("", "", Case::Upper);
    let rot12_op = Rot13::new(12);
    let recipe = Recipe::new(vec![Box::new(to_hex_op), Box::new(rot12_op)]);
    let result2 = recipe.bake(&Bytes::new(result1))?;

    // 每四位为一组 中间加'-'
    let serial_key = result2
        .chunks(4)
        .map(|chunk| chunk.iter().map(|&b| b as char).collect::<String>())
        .collect::<Vec<String>>()
        .join("-");

    println!("Serial key: {}", serial_key);
    Ok(())
}
