use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::tea::{xxtea_mx, DELTA};
use crate::types::Result;

/// XXTEA encryption over 32-bit little-endian words.
#[derive(Debug)]
pub struct XxteaEncrypt {
    pub key: Bytes,
    pub include_length: bool, // common implementations append a 32-bit length block after the input
}

impl XxteaEncrypt {
    /// Creates an XXTEA encryptor with a 16-byte key.
    pub fn new(key: &[u8], include_length: bool) -> Self {
        Self {
            key: Bytes::new(key),
            include_length,
        }
    }
}

impl Operation for XxteaEncrypt {
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
        // if include_length is enabled, append the length information after the input data
        if self.include_length {
            // length to u32 little-endian
            let length_bytes = (length as u32).to_le_bytes();
            input.extend_from_slice(&length_bytes);
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

        // convert the input into a u32 array in 4-byte groups for encryption
        let mut v = input
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>();

        let n = v.len();
        if n == 0 {
            return Ok(Bytes::default());
        }

        let rounds = 6 + 52 / n;
        let mut sum = 0u32;
        let mut e: usize;
        let mut y: u32;
        let mut z = v[n - 1];
        for _ in 0..rounds {
            sum = sum.wrapping_add(DELTA);
            e = (sum as usize >> 2) & 3;
            for p in 0..n - 1 {
                y = v[p + 1];
                v[p] = v[p].wrapping_add(xxtea_mx(z, y, sum, &key, p, e));
                z = v[p];
            }
            y = v[0];
            v[n - 1] = v[n - 1].wrapping_add(xxtea_mx(z, y, sum, &key, n - 1, e));
            z = v[n - 1];
        }

        // convert the encryption result into a byte array
        let output = v
            .iter()
            .flat_map(|&v| v.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();

        Ok(Bytes::new(output))
    }
}
