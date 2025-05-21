use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::tea::{xxtea_mx, DELTA};
use crate::types::Result;

#[derive(Debug)]
pub struct XxteaDecrypt {
    pub key: Bytes,
    pub include_length: bool,
}

impl XxteaDecrypt {
    pub fn new(key: &[u8], include_length: bool) -> Self {
        Self {
            key: Bytes::new(key),
            include_length,
        }
    }
}

impl Operation for XxteaDecrypt {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // 处理输入数据
        // 长度不是4的倍数 需要补齐
        let mut input = input.to_vec();
        let length = input.len();
        if length % 4 != 0 {
            let padding_length = 4 - length % 4;
            let padding = vec![0u8; padding_length];
            input.extend(padding);
        }

        // key 只取前16字节 如果key长度小于16 则用0填充
        let mut key_bytes = self.key.to_vec();
        if key_bytes.len() < 16 {
            key_bytes.extend(vec![0u8; 16 - key_bytes.len()]);
        } else {
            key_bytes.truncate(16);
        }

        // key转为u32数组
        let key = key_bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>();

        // 4字节一组 转为u32数组 进行加密
        let mut v = input
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>();

        let n = v.len();
        if n == 0 {
            return Ok(Bytes::default());
        }

        let rounds = 6 + 52 / n;
        let mut sum = (rounds as u32).wrapping_mul(DELTA);
        let mut e: usize;
        let mut y = v[0];
        let mut z: u32;
        for _ in 0..rounds {
            e = (sum as usize >> 2) & 3;
            // for (p=n-1; p>0; p--)
            for p in (1..n).rev() {
                z = v[p - 1];
                v[p] = v[p].wrapping_sub(xxtea_mx(z, y, sum, &key, p, e));
                y = v[p];
            }
            z = v[n - 1];
            v[0] = v[0].wrapping_sub(xxtea_mx(z, y, sum, &key, 0, e));
            y = v[0];
            sum = sum.wrapping_sub(DELTA);
        }

        // 加密结果转为字节数组
        let mut output = v
            .iter()
            .flat_map(|&v| v.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();

        if self.include_length {
            let original_length = v[n - 1];
            output.truncate(original_length as usize);
        }

        Ok(Bytes::new(output))
    }
}
