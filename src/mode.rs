use std::fmt::Debug;

use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::types::Result;

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

/// A block cipher mode of operation built around a raw block cipher function.
pub trait Mode: Clone + Debug {
    /// Whether decryption walks the round keys in reverse order.
    // direct-decrypt modes such as ECB/CBC must reverse the round key order and return true
    // stream modes such as CFB/OFB/CTR/GCM reuse the forward encryption function; the default returns false
    fn uses_decrypt_direction(&self) -> bool {
        false
    }

    /// Decrypts bit-oriented input block by block.
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes>;

    /// Encrypts bit-oriented input block by block.
    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes>;

    /// Decrypts byte-oriented input block by block.
    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_decrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes>;

    /// Encrypts byte-oriented input block by block.
    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes>;
}
