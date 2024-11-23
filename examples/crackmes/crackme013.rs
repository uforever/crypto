use crypto::aes::{
    inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows, sub_bytes,
};
use crypto::bytes::Bytes;
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

fn aesenc(state: &[u8], round_key: &[u8]) -> Bytes {
    let result = shift_rows(state);
    let result = sub_bytes(&result);
    let result = mix_columns(&result);
    result.xor(&Bytes::new(round_key))
}

fn main() -> Result<()> {
    let result_xmm2 = [
        0x61, 0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64,
        0x64,
    ];
    let key_xmm1 = [
        0x39, 0x01, 0x21, 0x76, 0x97, 0x1d, 0xd0, 0xa8, 0xd0, 0xe9, 0xbf, 0xd1, 0xc4, 0x50, 0x6f,
        0xa1,
    ];
    let input_xmm0 = [
        0x19, 0x5c, 0xc8, 0x8e, 0xcb, 0xd4, 0x33, 0x8e, 0xc9, 0x14, 0x29, 0xc2, 0x24, 0xed, 0x65,
        0x6d,
    ];
    let plaintext_xmm2 = aesdec(result_xmm2.as_ref(), key_xmm1.as_ref());
    let password = inv_aesdec(input_xmm0.as_ref(), key_xmm1.as_ref());
    let aesenc_result = aesenc(input_xmm0.as_ref(), key_xmm1.as_ref());

    println!("{:?}", plaintext_xmm2);
    println!("{}", password);
    println!("{}", aesenc_result);

    Ok(())
}
