use crypto::aes::{
    inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows, sub_bytes,
};
use crypto::bytes::Bytes;
use crypto::types::Result;

// 实现aesdec指令
#[allow(dead_code)]
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
#[allow(dead_code)]
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

fn main() -> Result<()> {
    let xmm0_1st = [
        0x19, 0x5c, 0xc8, 0x8e, 0xcb, 0xd4, 0x33, 0x8e, 0xc9, 0x14, 0x29, 0xc2, 0x24, 0xed, 0x65,
        0x6d,
    ];
    let xmm1_1st = [
        0x39, 0x01, 0x21, 0x76, 0x97, 0x1d, 0xd0, 0xa8, 0xd0, 0xe9, 0xbf, 0xd1, 0xc4, 0x50, 0x6f,
        0xa1,
    ];

    let password_1st = inv_aesdec(xmm0_1st.as_ref(), xmm1_1st.as_ref());
    println!("{}", password_1st);

    let xmm0_2nd = [
        0x59, 0x1b, 0x25, 0xd8, 0xfe, 0x16, 0x87, 0x42, 0x82, 0x66, 0xc5, 0xbb, 0x95, 0x53, 0xcc,
        0x0d,
    ];
    let xmm1_2nd = [
        0xba, 0xa0, 0x72, 0xa5, 0x9f, 0x75, 0x19, 0xe1, 0x34, 0x4d, 0x1c, 0xf1, 0x86, 0x42, 0x24,
        0x42,
    ];

    let password_2nd = inv_aesenc(xmm0_2nd.as_ref(), xmm1_2nd.as_ref());
    println!("{}", password_2nd);

    let xmm0_3rd = [
        0x15, 0x19, 0x7f, 0x7f, 0xf6, 0x06, 0xc9, 0xd0, 0x9d, 0xf4, 0x83, 0x08, 0x47, 0xd9, 0xfe,
        0xd3,
    ];
    let xmm1_3rd = [
        0x8d, 0x25, 0x96, 0x08, 0x37, 0xdd, 0x5f, 0x24, 0xa3, 0x4a, 0x09, 0x2a, 0xe2, 0x4e, 0xc9,
        0x84,
    ];

    let password_3rd = inv_aesdec(xmm0_3rd.as_ref(), xmm1_3rd.as_ref());
    println!("{}", password_3rd);

    let xmm0_4th = [
        0x63, 0x8a, 0xdc, 0xa0, 0xaf, 0x8c, 0x72, 0x72, 0x6e, 0x06, 0xfa, 0x9e, 0xb7, 0x37, 0xc2,
        0x81,
    ];
    let xmm1_4th = [
        0x88, 0x6d, 0x62, 0x52, 0x4f, 0xe7, 0xcf, 0x3f, 0xab, 0x64, 0xe4, 0x11, 0xcf, 0x5b, 0x4e,
        0xbd,
    ];

    let password_4th = inv_aesdec(xmm0_4th.as_ref(), xmm1_4th.as_ref());
    println!("{}", password_4th);

    Ok(())
}
