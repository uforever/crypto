use std::fmt::Debug;

use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};

mod cbc;
mod cfb;
mod ctr;
mod ecb;
mod gcm;
mod ofb;

pub use cbc::Cbc;
pub use cfb::Cfb;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::Gcm;
pub use ofb::Ofb;

pub trait Mode: Clone + Debug {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes;

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes;

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes;

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes;
}
