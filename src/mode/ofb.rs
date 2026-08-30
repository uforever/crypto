use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// Output Feedback (OFB) mode
// neither encryption nor decryption is parallelizable
// supports no padding
/// Output feedback (OFB) mode: turns the block cipher into a synchronous
/// keystream generator, so encryption and decryption are the same operation.
#[derive(Clone, Debug)]
pub struct Ofb {
    pub iv: Bytes,
}

impl Ofb {
    /// Creates an OFB mode with the given initialization vector.
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: Bytes::new(iv) }
    }

    fn bits_crypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_crypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            // the vector keeps being updated
            vector = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&vector).to_bytes());
        }

        Bytes::new(output)
    }

    fn bytes_crypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_crypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            // the vector keeps being updated
            vector = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&vector));
        }
        Bytes::new(output)
    }
}

impl Mode for Ofb {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        Ok(self.bits_crypt(input, block_size, block_encrypt))
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        Ok(self.bits_crypt(input, block_size, block_encrypt))
    }

    // encryption and decryption are identical
    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        Ok(self.bytes_crypt(input, block_size, block_encrypt))
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        Ok(self.bytes_crypt(input, block_size, block_encrypt))
    }
}
