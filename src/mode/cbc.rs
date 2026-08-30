use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// Cipher Block Chaining (CBC) mode
// encryption is not parallelizable while decryption is parallelizable
// input length must be a multiple of the block size (must be ensured when using NoPadding)
#[derive(Clone, Debug)]
pub struct Cbc {
    pub iv: Bytes,
}

impl Cbc {
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: Bytes::new(iv) }
    }
}

impl Mode for Cbc {
    // decryption uses the round keys in reverse order
    fn uses_decrypt_direction(&self) -> bool {
        true
    }

    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();
        if !input.len().is_multiple_of(block_size) {
            return Err("CBC mode input length must be a multiple of the block size".into());
        }

        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            let decrypted_block = block_decrypt(&block);
            let plain = decrypted_block.xor(&vector).to_bytes();
            vector = block;
            output.extend_from_slice(&plain);
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
        if !input.len().is_multiple_of(block_size) {
            return Err("CBC mode input length must be a multiple of the block size".into());
        }

        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            vector = block_encrypt(&block.xor(&vector));
            output.extend_from_slice(&vector.to_bytes());
        }

        Ok(Bytes::new(output))
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        let block_size: usize = block_size.into();
        if !input.len().is_multiple_of(block_size) {
            return Err("CBC mode input length must be a multiple of the block size".into());
        }

        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let decrypted_block = block_decrypt(chunk);
            let plain = decrypted_block.xor(&vector);
            vector = Bytes::new(chunk);
            output.extend_from_slice(&plain);
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
        if !input.len().is_multiple_of(block_size) {
            return Err("CBC mode input length must be a multiple of the block size".into());
        }

        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            vector = block_encrypt(&block.xor(&vector));
            output.extend_from_slice(&vector);
        }
        Ok(Bytes::new(output))
    }
}
