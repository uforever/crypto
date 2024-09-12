use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::BlockSize;
use crate::mode::Mode;

#[derive(Clone, Copy, Debug)]
pub struct Ecb;

fn crypt(input: &[u8], block_size: BlockSize, block_crypt: impl Fn(Bits) -> Bits) -> Bytes {
    let length = input.len();
    let mut output = Vec::with_capacity(length);
    for chunk in input.chunks(block_size.into()) {
        let block: Bits = chunk.into();

        output.extend_from_slice(&Bytes::from(block_crypt(block)));
    }

    Bytes::new(output)
}

impl Mode for Ecb {
    fn decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes {
        crypt(input, block_size, block_decrypt)
    }

    fn encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes {
        crypt(input, block_size, block_encrypt)
    }
}
