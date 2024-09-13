use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;

#[derive(Clone, Copy, Debug)]
pub struct Ecb;

fn bits_crypt(input: &[u8], block_size: BlockSize, block_crypt: impl Fn(&[Bit]) -> Bits) -> Bytes {
    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(block_size.into()) {
        let block: Bits = chunk.into();

        output.extend_from_slice(&block_crypt(&block).to_bytes());
    }

    Bytes::new(output)
}

fn bytes_crypt(input: &[u8], block_size: BlockSize, block_crypt: impl Fn(&[u8]) -> Bytes) -> Bytes {
    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(block_size.into()) {
        let block: Bytes = Bytes::new(chunk);
        output.extend_from_slice(&block_crypt(&block));
    }
    Bytes::new(output)
}

impl Mode for Ecb {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        bits_crypt(input, block_size, block_decrypt)
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        bits_crypt(input, block_size, block_encrypt)
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        bytes_crypt(input, block_size, block_decrypt)
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        bytes_crypt(input, block_size, block_encrypt)
    }
}
