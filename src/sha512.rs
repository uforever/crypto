use crate::bytes::Bytes;
use crate::operation::{BlockSize, Hashing, Operation};
use crate::padding::{BitPadding, Endian, Padding as _};

const BLOCK_SIZE: BlockSize = BlockSize::Bytes128;

// 前8个质数2..19的平方根的分数部分的前64位
const A: u64 = 0x6a09e667f3bcc908;
const B: u64 = 0xbb67ae8584caa73b;
const C: u64 = 0x3c6ef372fe94f82b;
const D: u64 = 0xa54ff53a5f1d36f1;
const E: u64 = 0x510e527fade682d1;
const F: u64 = 0x9b05688c2b3e6c1f;
const G: u64 = 0x1f83d9abfb41bd6b;
const H: u64 = 0x5be0cd19137e2179;

// 前80个质数2..409的立方根分数部分的前64位
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Debug, Default)]
pub struct SHA512;

impl Operation for SHA512 {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes> {
        let padded_data = BitPadding::new(BLOCK_SIZE, Endian::Big).pad(input);

        let mut a0 = A;
        let mut b0 = B;
        let mut c0 = C;
        let mut d0 = D;
        let mut e0 = E;
        let mut f0 = F;
        let mut g0 = G;
        let mut h0 = H;

        for chunk in padded_data.chunks(128) {
            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;
            let mut e = e0;
            let mut f = f0;
            let mut g = g0;
            let mut h = h0;

            let mut words: Vec<u64> = vec![];

            for i in 0..80 {
                let word = if i < 16 {
                    u64::from_be_bytes([
                        chunk[i * 8],
                        chunk[i * 8 + 1],
                        chunk[i * 8 + 2],
                        chunk[i * 8 + 3],
                        chunk[i * 8 + 4],
                        chunk[i * 8 + 5],
                        chunk[i * 8 + 6],
                        chunk[i * 8 + 7],
                    ])
                } else {
                    words[i - 16]
                        .wrapping_add(
                            words[i - 15].rotate_right(1)
                                ^ words[i - 15].rotate_right(8)
                                ^ words[i - 15] >> 7,
                        )
                        .wrapping_add(words[i - 7])
                        .wrapping_add(
                            words[i - 2].rotate_right(19)
                                ^ words[i - 2].rotate_right(61)
                                ^ words[i - 2] >> 6,
                        )
                };

                words.push(word);

                let temp1 = h
                    .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
                    .wrapping_add((e & f) ^ ((!e) & g))
                    .wrapping_add(K[i])
                    .wrapping_add(word);
                let temp2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
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

impl Hashing for SHA512 {
    fn block_size(&self) -> BlockSize {
        BLOCK_SIZE
    }

    //fn output_size(&self) -> usize {
    //    64
    //}
}
