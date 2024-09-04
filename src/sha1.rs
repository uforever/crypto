use crate::bytes::Bytes;
use crate::operation::Operation;

const A: u32 = 0x67452301;
const B: u32 = 0xEFCDAB89;
const C: u32 = 0x98BADCFE;
const D: u32 = 0x10325476;
const E: u32 = 0xC3D2E1F0;

pub struct SHA1 {
    pub rounds: usize,
}

impl Default for SHA1 {
    fn default() -> Self {
        SHA1 { rounds: 80 }
    }
}

impl SHA1 {
    pub fn new(rounds: usize) -> SHA1 {
        if rounds == 0 {
            return SHA1 { rounds: 80 };
        }

        SHA1 { rounds }
    }
}

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

impl Operation for SHA1 {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
        let padded_data = padding(&input);

        let mut a0 = A;
        let mut b0 = B;
        let mut c0 = C;
        let mut d0 = D;
        let mut e0 = E;

        for chunk in padded_data.chunks(64) {
            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;
            let mut e = e0;

            let mut words: Vec<u32> = vec![];

            for i in 0..self.rounds {
                let word = if i < 16 {
                    u32::from_be_bytes([
                        chunk[i * 4],
                        chunk[i * 4 + 1],
                        chunk[i * 4 + 2],
                        chunk[i * 4 + 3],
                    ])
                } else {
                    (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1)
                };

                words.push(word);

                let temp = if i < 20 {
                    a.rotate_left(5)
                        .wrapping_add((b & c) | (!b & d))
                        .wrapping_add(e)
                        .wrapping_add(0x5A827999)
                        .wrapping_add(word)
                } else if i < 40 {
                    a.rotate_left(5)
                        .wrapping_add(b ^ c ^ d)
                        .wrapping_add(e)
                        .wrapping_add(0x6ED9EBA1)
                        .wrapping_add(word)
                } else if i < 60 {
                    a.rotate_left(5)
                        .wrapping_add((b & c) | (b & d) | (c & d))
                        .wrapping_add(e)
                        .wrapping_add(0x8F1BBCDC)
                        .wrapping_add(word)
                } else if i < 80 {
                    a.rotate_left(5)
                        .wrapping_add(b ^ c ^ d)
                        .wrapping_add(e)
                        .wrapping_add(0xCA62C1D6)
                        .wrapping_add(word)
                } else {
                    b ^ c ^ d
                };

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
            e0 = e0.wrapping_add(e);
        }

        Ok(Bytes::new(
            [
                a0.to_be_bytes(),
                b0.to_be_bytes(),
                c0.to_be_bytes(),
                d0.to_be_bytes(),
                e0.to_be_bytes(),
            ]
            .concat(),
        ))
    }
}