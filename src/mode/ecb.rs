use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// Electronic Codebook (ECB)
// both encryption and decryption are parallelizable
// input length must be a multiple of the block size (must be ensured when using NoPadding)
#[derive(Clone, Copy, Debug)]
pub struct Ecb;

fn bits_crypt(
    input: &[u8],
    block_size: BlockSize,
    block_crypt: impl Fn(&[Bit]) -> Bits,
) -> Result<Bytes> {
    let block_size: usize = block_size.into();
    if !input.len().is_multiple_of(block_size) {
        return Err("ECB mode input length must be a multiple of the block size".into());
    }

    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(block_size) {
        let block: Bits = chunk.into();

        output.extend_from_slice(&block_crypt(&block).to_bytes());
    }

    Ok(Bytes::new(output))
}

fn bytes_crypt(
    input: &[u8],
    block_size: BlockSize,
    block_crypt: impl Fn(&[u8]) -> Bytes,
) -> Result<Bytes> {
    let block_size: usize = block_size.into();
    if !input.len().is_multiple_of(block_size) {
        return Err("ECB mode input length must be a multiple of the block size".into());
    }

    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(block_size) {
        let block: Bytes = Bytes::new(chunk);
        output.extend_from_slice(&block_crypt(&block));
    }
    Ok(Bytes::new(output))
}

impl Mode for Ecb {
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
        bits_crypt(input, block_size, block_decrypt)
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        bits_crypt(input, block_size, block_encrypt)
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        bytes_crypt(input, block_size, block_decrypt)
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        bytes_crypt(input, block_size, block_encrypt)
    }
}
