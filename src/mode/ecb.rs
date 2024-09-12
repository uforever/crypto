use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;

#[derive(Clone, Copy, Debug)]
pub struct Ecb;

fn crypt(input: &[u8], block_size: BlockSize, block_crypt: impl Fn(&[Bit]) -> Bits) -> Bytes {
    let length = input.len();
    let mut output = Vec::with_capacity(length);
    for chunk in input.chunks(block_size.into()) {
        let block: Bits = chunk.into();

        output.extend_from_slice(&block_crypt(&block).to_bytes());
    }

    Bytes::new(output)
}

impl Mode for Ecb {
    fn decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        crypt(input, block_size, block_decrypt)
    }

    fn encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        crypt(input, block_size, block_encrypt)
    }
}
