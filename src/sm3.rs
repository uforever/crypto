use crate::bytes::Bytes;
use crate::enums::{BlockSize, Endian};
use crate::operation::{Hashing, Operation};
use crate::padding::{BitPadding, Padding as _};
use crate::types::Result;

// 块大小 512 bits
const BLOCK_SIZE: BlockSize = BlockSize::Bytes64;

// 初始化向量
const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

// 迭代压缩过程中使用到的一些函数

fn tj(j: usize) -> u32 {
    if j < 16 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

fn ffj(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

fn ggj(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

#[derive(Debug, Default)]
pub struct Sm3;

impl Operation for Sm3 {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // 填充
        let padded_data = BitPadding::new(BLOCK_SIZE, Endian::Big).pad(input);

        let mut a0 = IV[0];
        let mut b0 = IV[1];
        let mut c0 = IV[2];
        let mut d0 = IV[3];
        let mut e0 = IV[4];
        let mut f0 = IV[5];
        let mut g0 = IV[6];
        let mut h0 = IV[7];

        for chunk in padded_data.chunks(64) {
            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;
            let mut e = e0;
            let mut f = f0;
            let mut g = g0;
            let mut h = h0;

            // 扩展
            // 每块512比特 分为16个32位的字
            // 16组扩展成68组
            // 68组扩展成132组
            let mut w = [0u32; 132];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into()?);
            }
            for i in 16..68 {
                w[i] = p1(w[i - 16] ^ w[i - 9] ^ (w[i - 3].rotate_left(15)))
                    ^ (w[i - 13].rotate_left(7))
                    ^ w[i - 6];
            }
            for i in 68..132 {
                w[i] = w[i - 68] ^ w[i - 64];
            }

            // 迭代压缩
            for j in 0..64 {
                let ss1 = a
                    .rotate_left(12)
                    .wrapping_add(e)
                    .wrapping_add(tj(j).rotate_left(j as u32 % 32))
                    .rotate_left(7);
                let ss2 = ss1 ^ (a.rotate_left(12));
                let tt1 = ffj(j, a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(ss2)
                    .wrapping_add(w[j + 68]);
                let tt2 = ggj(j, e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(ss1)
                    .wrapping_add(w[j]);

                d = c;
                c = b.rotate_left(9);
                b = a;
                a = tt1;
                h = g;
                g = f.rotate_left(19);
                f = e;
                e = p0(tt2);
            }

            a0 ^= a;
            b0 ^= b;
            c0 ^= c;
            d0 ^= d;
            e0 ^= e;
            f0 ^= f;
            g0 ^= g;
            h0 ^= h;
        }

        Ok(Bytes::new(
            [
                a0.to_be_bytes(),
                b0.to_be_bytes(),
                c0.to_be_bytes(),
                d0.to_be_bytes(),
                e0.to_be_bytes(),
                f0.to_be_bytes(),
                g0.to_be_bytes(),
                h0.to_be_bytes(),
            ]
            .concat(),
        ))
    }
}

impl Hashing for Sm3 {
    fn block_size(&self) -> BlockSize {
        BLOCK_SIZE
    }
}
