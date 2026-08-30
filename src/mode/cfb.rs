use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// Cipher Feedback (CFB) mode
// encryption is not parallelizable while decryption is parallelizable
// supports no padding
/// Cipher feedback (CFB) mode: re-encrypts the previous ciphertext block to
/// produce the keystream, so decryption parallelizes while encryption cannot.
#[derive(Clone, Debug)]
pub struct Cfb {
    pub iv: Bytes,
}

impl Cfb {
    /// Creates a CFB mode with the given initialization vector.
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: Bytes::new(iv) }
    }
}

impl Mode for Cfb {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();
        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            let plain: Bits = block.xor(&block_encrypt(&vector));
            // the previous ciphertext block becomes the next vector
            vector = block;
            output.extend_from_slice(&plain.to_bytes());
        }

        Ok(Bytes::new(output))
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();

        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            // the ciphertext becomes the next vector
            vector = block.xor(&block_encrypt(&vector));
            output.extend_from_slice(&vector.to_bytes());
        }

        Ok(Bytes::new(output))
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            output.extend_from_slice(&block.xor(&block_encrypt(&vector)));
            // the previous ciphertext block becomes the next vector
            vector = block;
        }
        Ok(Bytes::new(output))
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            // the ciphertext becomes the next vector
            vector = block.xor(&block_encrypt(&vector));
            output.extend_from_slice(&vector);
        }
        Ok(Bytes::new(output))
    }
}
