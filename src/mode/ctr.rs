use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// Counter (CTR) mode
// both encryption and decryption are parallelizable
// supports no padding
/// Counter (CTR) mode: encrypts an incrementing counter to form a keystream,
/// supporting parallel encryption and decryption.
#[derive(Clone, Debug)]
pub struct Ctr {
    pub iv: Bytes,
}

// counter increment follows the CyberChef implementation (only the last 32 bits are incremented)
impl Ctr {
    /// Creates a CTR mode with the given initialization vector (counter).
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
            let block_key = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&block_key).to_bytes());
            // the counter keeps incrementing
            vector.inc32();
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
            let block_key = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&block_key));
            // the counter keeps incrementing
            vector.inc32();
        }
        Bytes::new(output)
    }
}

impl Mode for Ctr {
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
