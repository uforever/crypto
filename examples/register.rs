use std::io::{self, Write};

use crypto::base64::ToBase64;
use crypto::bytes::Bytes;
use crypto::recipe::Recipe;
use crypto::types::Result;

fn main() -> Result<()> {
    // 提示用户输入
    print!("Input: ");
    io::stdout().flush().unwrap(); // 确保提示信息立即显示
    let s_box = [
        0x69, 0xbf, 0x45, 0x32, 0xe0, 0xb2, 0x67, 0x4d, 0x9d, 0xbc, 0x86, 0xb7, 0x54, 0x6f, 0xc4,
        0x95, 0x10, 0x46, 0x57, 0xf4, 0x56, 0xf2, 0x96, 0xe4, 0x8f, 0xb9, 0x03, 0xda, 0x8b, 0x00,
        0x3f, 0x5f, 0xca, 0x15, 0x07, 0xd5, 0x98, 0x1c, 0x64, 0x24, 0x3c, 0x43, 0x2d, 0xf0, 0xdb,
        0xf8, 0x42, 0x66, 0xc0, 0x1d, 0x77, 0x9e, 0xa4, 0xad, 0x44, 0x1e, 0xae, 0x14, 0x21, 0xe6,
        0x59, 0x93, 0x6c, 0x51, 0x40, 0xff, 0x78, 0x47, 0xd1, 0x6e, 0x23, 0x11, 0x5a, 0x18, 0x94,
        0xba, 0x6d, 0x31, 0xc9, 0xcc, 0x9f, 0x29, 0xe2, 0xbb, 0x87, 0x4e, 0x09, 0x83, 0x52, 0x92,
        0x65, 0xc6, 0x26, 0x49, 0x8d, 0xeb, 0xf9, 0x91, 0x3d, 0xc3, 0x0e, 0xab, 0x35, 0x62, 0x2b,
        0x90, 0x48, 0x1a, 0xb0, 0x16, 0x2e, 0xaf, 0xd4, 0xdc, 0xb4, 0x28, 0x1b, 0x41, 0x53, 0x13,
        0x9c, 0x02, 0x39, 0xa2, 0x4b, 0x0a, 0xfc, 0x63, 0x2a, 0x36, 0x73, 0x7c, 0xdf, 0xed, 0x7d,
        0x70, 0xa5, 0x81, 0x05, 0xd7, 0x2f, 0x99, 0x27, 0xc8, 0x7f, 0x80, 0xcf, 0xfa, 0xe3, 0x7a,
        0x84, 0xf5, 0xe5, 0x4c, 0xd6, 0xc1, 0xb8, 0x19, 0xce, 0xac, 0x75, 0x9b, 0x37, 0x34, 0x50,
        0x38, 0x25, 0x0b, 0x60, 0xc5, 0x8c, 0x6b, 0x0c, 0x3a, 0x08, 0x30, 0xef, 0x89, 0x61, 0x71,
        0xfd, 0xb3, 0x4a, 0xb1, 0x55, 0x04, 0xa9, 0x97, 0x88, 0xde, 0xd3, 0x58, 0x6a, 0x01, 0xfe,
        0x12, 0x3b, 0xea, 0x0d, 0xc2, 0xf6, 0xbe, 0x76, 0xbd, 0x7e, 0x82, 0x0f, 0xd2, 0xd0, 0xaa,
        0x72, 0xa0, 0xfb, 0xd8, 0x68, 0xa7, 0xa3, 0x3e, 0x74, 0x5b, 0xe8, 0x2c, 0xa1, 0x33, 0xb6,
        0xf7, 0xc7, 0x85, 0x8e, 0xa6, 0xd9, 0x5d, 0xec, 0xe7, 0x17, 0x4f, 0x1f, 0xb5, 0xf3, 0xe1,
        0xcb, 0x79, 0x7b, 0x22, 0x9a, 0xa8, 0xdd, 0xe9, 0xf1, 0x8a, 0xee, 0xcd, 0x5e, 0x5c, 0x06,
        0x20,
    ];

    let special_key: [u8; 200] = [
        0x9e, 0x68, 0x27, 0x6b, 0xe7, 0x24, 0xe4, 0xf7, 0xa7, 0x0c, 0x7c, 0xb3, 0xc1, 0x07, 0xdc,
        0xbf, 0xfb, 0xb2, 0xd9, 0xe9, 0x45, 0x81, 0xc1, 0x5c, 0x2e, 0xca, 0x77, 0xb6, 0x1e, 0x0a,
        0x28, 0x5c, 0xcf, 0x59, 0xc4, 0xe4, 0xb3, 0xc8, 0x59, 0xff, 0x8f, 0xb6, 0xdc, 0xed, 0xf8,
        0x27, 0xc3, 0xe7, 0xa1, 0xb6, 0x1f, 0xa9, 0x76, 0x0f, 0x2a, 0x7b, 0xed, 0x4a, 0x0b, 0xa9,
        0xc3, 0xba, 0xc3, 0xcd, 0x5c, 0x18, 0x18, 0x56, 0x4d, 0xf4, 0xda, 0xad, 0x7a, 0x47, 0x5f,
        0x48, 0x75, 0xeb, 0x84, 0xc8, 0x06, 0xa9, 0xd3, 0xbe, 0xee, 0xf1, 0xb3, 0x8e, 0x3c, 0x40,
        0x0d, 0x36, 0x17, 0xde, 0xe2, 0x67, 0xde, 0x29, 0xef, 0xdf, 0xae, 0xa9, 0xa5, 0xf8, 0x74,
        0x9f, 0x94, 0x5c, 0x4a, 0x1d, 0x92, 0x04, 0xe2, 0xb2, 0xe4, 0x79, 0x2e, 0xb3, 0xad, 0x03,
        0xec, 0x81, 0xae, 0x54, 0xe6, 0xe4, 0xa7, 0x91, 0xbd, 0x84, 0xff, 0xf1, 0xf8, 0x28, 0x0c,
        0x1b, 0xe6, 0x8b, 0x4f, 0x40, 0x97, 0x38, 0xa0, 0x89, 0xce, 0x71, 0x22, 0xd3, 0x9b, 0xba,
        0x56, 0x86, 0xc7, 0x0c, 0x28, 0xb8, 0x91, 0x89, 0x83, 0x09, 0x6a, 0x07, 0x23, 0x32, 0x1c,
        0x2d, 0x4b, 0xc8, 0xbe, 0x9d, 0x67, 0xf2, 0x1d, 0xb2, 0x96, 0xf7, 0x51, 0x5d, 0x24, 0x09,
        0x65, 0xf5, 0xcb, 0x7b, 0x89, 0xe8, 0xa9, 0xdf, 0xa1, 0xa6, 0xc4, 0xc5, 0x1c, 0x1e, 0xb1,
        0x54, 0x08, 0x15, 0x25, 0xbd,
    ];

    // 创建一个字符串变量来存储输入
    let mut input = String::new();
    let length = special_key.len();

    // 读取标准输入
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            // 去掉输入字符串末尾的换行符
            let input = input.trim();
            let input_bytes = Bytes::new(input.as_bytes());

            let mut output: Vec<u8> = Vec::with_capacity(input.len());

            for i in 0..input_bytes.len() {
                output.push(s_box[input_bytes[i] as usize]);
            }

            for j in 0..output.len() {
                output[j] ^= special_key[j % length];
            }

            let output_bytes = Bytes::new(output);
            let to_base64_op = ToBase64::default();
            let recipe = Recipe::new(vec![Box::new(to_base64_op)]);
            let to_base64_output = recipe.bake(&output_bytes)?;
            println!("Output: {}", to_base64_output);
        }
        Err(e) => {
            eprintln!("Err: {}", e);
        }
    }

    Ok(())
}
