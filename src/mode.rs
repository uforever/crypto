use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::BlockSize;

use std::fmt::Debug;

mod cbc;
mod ecb;

pub use cbc::Cbc;
pub use ecb::Ecb;

pub trait Mode: Debug {
    fn decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes;

    fn encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(Bits) -> Bits,
    ) -> Bytes;
}
