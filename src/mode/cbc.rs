use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::BlockSize;
use crate::mode::Mode;

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
    fn decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes {
        todo!()
    }

    fn encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes {
        todo!()
    }
}
