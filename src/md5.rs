use crate::bytes::Bytes;
use crate::operation::{BlockSize, Hashing, Operation};
use crate::padding::{BitPadding, Endian, Padding as _};

const BLOCK_SIZE: BlockSize = BlockSize::Bytes64;

//const INIT_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
const A: u32 = 0x67452301;
const B: u32 = 0xefcdab89;
const C: u32 = 0x98badcfe;
const D: u32 = 0x10325476;

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// std::array::from_fn(|i| (((i + 1) as f64).sin().abs() * 2.0_f64.powi(32)) as u32);
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Debug, Default)]
pub struct MD5;

impl Operation for MD5 {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes> {
        let padded_data = BitPadding::new(BLOCK_SIZE, Endian::Little).pad(input);

        let mut a0 = A;
        let mut b0 = B;
        let mut c0 = C;
        let mut d0 = D;

        for chunk in padded_data.chunks(64) {
            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;

            for i in 0..64 {
                let mut f: u32;
                let g: u32;

                if i < 16 {
                    f = (b & c) | (!b & d);
                    g = i;
                } else if i < 32 {
                    f = (d & b) | (!d & c);
                    g = (5 * i + 1) % 16;
                } else if i < 48 {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) % 16;
                } else {
                    f = c ^ (b | !d);
                    g = (7 * i) % 16;
                }

                let g = g as usize;
                let i = i as usize;
                let message: [u8; 4] = [
                    chunk[4 * g],
                    chunk[4 * g + 1],
                    chunk[4 * g + 2],
                    chunk[4 * g + 3],
                ];
                f = f
                    .wrapping_add(a)
                    .wrapping_add(K[i])
                    .wrapping_add(u32::from_le_bytes(message));
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f.rotate_left(S[i]));
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }

        Ok(Bytes::new(
            [
                a0.to_le_bytes(),
                b0.to_le_bytes(),
                c0.to_le_bytes(),
                d0.to_le_bytes(),
            ]
            .concat(),
        ))
    }
}

impl Hashing for MD5 {
    fn block_size(&self) -> BlockSize {
        BLOCK_SIZE
    }

    //fn output_size(&self) -> usize {
    //    16
    //}
}
