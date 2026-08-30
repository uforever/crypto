use std::io::{self, Write};

use crypto::bytes::Bytes;
use crypto::types::Result;

fn main() -> Result<()> {
    print!("Input username: ");
    io::stdout().flush()?;
    // the key is extracted from the program
    let key = [
        0x5F, 0x72, 0x20, 0x3C, 0x28, 0x29, 0x3C, 0x31, 0x2D, 0x5A, 0x32, 0x5B, 0x6C, 0x35, 0x2C,
        0x5E,
    ];
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username_bytes = Bytes::new(username.trim().as_bytes());
    let username_len = username_bytes.len();
    // take the max of the 16-byte key length and the username length; the shorter one is used cyclically
    // xor the two and map the result to characters A-Z via modulo
    // the final reg code is 16 characters long
    let mut reg_code: Vec<u8> = Vec::with_capacity(16);
    reg_code.extend_from_slice(&key);
    let max = 16.max(username_len);
    for i in 0..max {
        let key_index = i % 16;
        let username_index = i % username_len;
        let c = (reg_code[key_index] ^ username_bytes[username_index]) % 25 + 65;
        reg_code[key_index] = c;
    }
    // group every four bytes, joined by '-'
    let reg_code_str = reg_code
        .chunks(4)
        .map(|chunk| chunk.iter().map(|&byte| byte as char).collect::<String>())
        .collect::<Vec<String>>()
        .join("-");
    println!("Reg code: {}", reg_code_str);
    Ok(())
}
