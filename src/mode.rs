use std::fmt::Debug;

use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};

mod cbc;
mod ecb;

pub use cbc::Cbc;
pub use ecb::Ecb;

pub trait Mode: Clone + Debug {
    fn decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes;

    fn encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes;
}
