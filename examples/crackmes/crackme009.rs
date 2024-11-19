use std::time::{SystemTime, UNIX_EPOCH};

use crypto::bytes::Bytes;
use crypto::types::Result;

const FLOOR: u128 = 0x20;
const CEIL: u128 = 0x7E;

// 根据给定的sum和count生成count个随机字节
// 每个字节的范围为[FLOOR, CEIL]
fn gen_bytes(sum: u128, count: u128) -> Result<Vec<u8>> {
    if count == 1 {
        return Ok(vec![sum as u8]);
    }

    // 计算当前字符的可选范围
    let rest_sum_min = FLOOR * (count - 1);
    let rest_sum_max = CEIL * (count - 1);

    let mut floor = sum.saturating_sub(rest_sum_max);
    let mut ceil = sum.saturating_sub(rest_sum_min);

    if floor > CEIL {
        return Err("sum is too small".into());
    }
    if ceil < FLOOR {
        return Err("sum is too large".into());
    }

    if floor < FLOOR {
        floor = FLOOR;
    }
    if ceil > CEIL {
        ceil = CEIL;
    }

    // 随机生成单个字节
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let random_u128 = now.as_nanos() % (ceil - floor + 1) + floor;
    // 递归调用
    let rest_sum = sum - random_u128;
    let rest_count = count - 1;
    let random_byte = random_u128 as u8;
    let rest_bytes = gen_bytes(rest_sum, rest_count)?;
    let mut bytes = vec![random_byte];
    bytes.extend(rest_bytes);
    Ok(bytes)
}

fn main() -> Result<()> {
    let mut key: Vec<u8> = Vec::with_capacity(16);

    key.extend(gen_bytes(262, 4)?);
    key.extend(gen_bytes(273, 4)?);
    key.extend(gen_bytes(262, 4)?);
    key.extend(gen_bytes(273, 4)?);

    println!("{}", Bytes::new(key));
    Ok(())
}
