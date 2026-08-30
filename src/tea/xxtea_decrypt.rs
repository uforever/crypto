use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::tea::{xxtea_mx, DELTA};
use crate::types::Result;

/// XXTEA decryption over 32-bit little-endian words.
#[derive(Debug)]
pub struct XxteaDecrypt {
    pub key: Bytes,
    pub include_length: bool,
}

impl XxteaDecrypt {
    /// Creates an XXTEA decryptor with a 16-byte key.
    pub fn new(key: &[u8], include_length: bool) -> Self {
        Self {
            key: Bytes::new(key),
            include_length,
        }
    }
}

impl Operation for XxteaDecrypt {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // handle the input data
        // pad it if the length is not a multiple of 4
        let mut input = input.to_vec();
        let length = input.len();
        if !length.is_multiple_of(4) {
            let padding_length = 4 - length % 4;
            let padding = vec![0u8; padding_length];
            input.extend(padding);
        }

        // use only the first 16 bytes of the key; zero-pad if the key is shorter than 16
        let mut key_bytes = self.key.to_vec();
        if key_bytes.len() < 16 {
            key_bytes.extend(vec![0u8; 16 - key_bytes.len()]);
        } else {
            key_bytes.truncate(16);
        }

        // convert the key to a u32 array
        let key = key_bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>();

        // convert the input into a u32 array in 4-byte groups for decryption
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

        // convert the decryption result into a byte array
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
