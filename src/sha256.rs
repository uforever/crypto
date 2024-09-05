use crate::bytes::Bytes;
use crate::operation::{Hashing, Operation};

// 前8个质数2..19的平方根的分数部分的前32位
const A: u32 = 0x6a09e667;
const B: u32 = 0xbb67ae85;
const C: u32 = 0x3c6ef372;
const D: u32 = 0xa54ff53a;
const E: u32 = 0x510e527f;
const F: u32 = 0x9b05688c;
const G: u32 = 0x1f83d9ab;
const H: u32 = 0x5be0cd19;

// 前64个质数2..311的立方根分数部分的前32位
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Default)]
pub struct SHA256;

fn padding(data: &[u8]) -> Vec<u8> {
    let mut padded_data = Vec::from(data);
    let original_len: u64 = data.len() as u64 * 8;
    padded_data.push(0x80);

    //while (padded_data.len() * 8) % 512 != 448 {
    // 8 bytes for original length
    while padded_data.len() % 64 != 56 {
        padded_data.push(0);
    }

    padded_data.extend_from_slice(&original_len.to_be_bytes());
    padded_data
}

impl Operation for SHA256 {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
        let padded_data = padding(&input);

        let mut a0 = A;
        let mut b0 = B;
        let mut c0 = C;
        let mut d0 = D;
        let mut e0 = E;
        let mut f0 = F;
        let mut g0 = G;
        let mut h0 = H;

        for chunk in padded_data.chunks(64) {
            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;
            let mut e = e0;
            let mut f = f0;
            let mut g = g0;
            let mut h = h0;

            let mut words: Vec<u32> = vec![];

            for i in 0..64 {
                let word = if i < 16 {
                    u32::from_be_bytes([
                        chunk[i * 4],
                        chunk[i * 4 + 1],
                        chunk[i * 4 + 2],
                        chunk[i * 4 + 3],
                    ])
                } else {
                    words[i - 16]
                        .wrapping_add(
                            words[i - 15].rotate_right(7)
                                ^ words[i - 15].rotate_right(18)
                                ^ words[i - 15] >> 3,
                        )
                        .wrapping_add(words[i - 7])
                        .wrapping_add(
                            words[i - 2].rotate_right(17)
                                ^ words[i - 2].rotate_right(19)
                                ^ words[i - 2] >> 10,
                        )
                };

                words.push(word);

                let temp1 = h
                    .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                    .wrapping_add((e & f) ^ ((!e) & g))
                    .wrapping_add(K[i])
                    .wrapping_add(word);
                let temp2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                    .wrapping_add((a & b) ^ (a & c) ^ (b & c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
            e0 = e0.wrapping_add(e);
            f0 = f0.wrapping_add(f);
            g0 = g0.wrapping_add(g);
            h0 = h0.wrapping_add(h);
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

impl Hashing for SHA256 {
    fn block_size(&self) -> usize {
        64
    }
    fn output_size(&self) -> usize {
        32
    }
}
